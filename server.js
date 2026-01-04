import express from "express";
import fs from "fs/promises";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const app = express();

app.use(express.json({ limit: "10mb" }));

// =========================
// Config
// =========================
const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || "";
const OPENSCAD_BIN = process.env.OPENSCAD_BIN || "openscad";
const OPENSCAD_TIMEOUT_MS = Number(process.env.OPENSCAD_TIMEOUT_MS || 120000);

const LIB_DIR = process.env.OPENSCAD_LIB_DIR || "/opt/openscad-libs";
const ENABLED_DIR = path.join(LIB_DIR, "_enabled");
const LIB_DB_PATH = process.env.OPENSCAD_LIB_DB_PATH || path.join(LIB_DIR, ".libdb.json");

const SERVICE_NAME = process.env.SERVICE_NAME || "OpenSCAD Render Service";
const EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL || ""; // optional

// =========================
// Auth
// =========================
function authOk(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  return h === `Bearer ${TOKEN}`;
}

// allow ?token=... for the dashboard + events
function authOkOrQueryToken(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  if (h === `Bearer ${TOKEN}`) return true;
  if ((req.query?.token || "") === TOKEN) return true;
  return false;
}

// =========================
// Small utils
// =========================
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function exists(p) {
  try { await fs.stat(p); return true; } catch { return false; }
}

async function ensureDir(p) {
  await fs.mkdir(p, { recursive: true });
}

async function rmrf(p) {
  await fs.rm(p, { recursive: true, force: true });
}

// Dir copy (Node 16+ has fs.cp)
async function copyDir(src, dest) {
  await ensureDir(path.dirname(dest));
  if (typeof fs.cp === "function") {
    await fs.cp(src, dest, { recursive: true });
    return;
  }
  const entries = await fs.readdir(src, { withFileTypes: true });
  await ensureDir(dest);
  for (const e of entries) {
    const from = path.join(src, e.name);
    const to = path.join(dest, e.name);
    if (e.isDirectory()) await copyDir(from, to);
    else await fs.copyFile(from, to);
  }
}

async function sha256Hex(buf) {
  const { createHash } = await import("crypto");
  return createHash("sha256").update(buf).digest("hex");
}

// =========================
// Live events + log buffer
// =========================
const MAX_LOG = 250;
const logBuffer = [];
const sseClients = new Set();

function pushLog(type, message, data = null) {
  const entry = {
    ts: new Date().toISOString(),
    type,
    message,
    data
  };
  logBuffer.push(entry);
  while (logBuffer.length > MAX_LOG) logBuffer.shift();

  // broadcast to SSE clients
  const payload = `event: log\ndata: ${JSON.stringify(entry)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch {}
  }
}

function pushState(db) {
  const entry = { ts: new Date().toISOString(), db };
  const payload = `event: state\ndata: ${JSON.stringify(entry)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch {}
  }
}

// =========================
// Library DB
// =========================
async function readLibDb() {
  try {
    const raw = await fs.readFile(LIB_DB_PATH, "utf8");
    const db = JSON.parse(raw);
    if (!db || typeof db !== "object") throw new Error("Invalid DB");
    if (!db.libraries) db.libraries = {};
    return db;
  } catch {
    return { libraries: {} };
  }
}

async function writeLibDb(db) {
  await ensureDir(path.dirname(LIB_DB_PATH));
  await fs.writeFile(LIB_DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

async function rebuildEnabledDir() {
  await ensureDir(LIB_DIR);
  await rmrf(ENABLED_DIR);
  await ensureDir(ENABLED_DIR);

  const db = await readLibDb();
  const libs = Object.values(db.libraries || {});
  for (const l of libs) {
    const enabled = (l.enabled !== false); // default true
    if (!enabled) continue;

    const src = path.join(LIB_DIR, l.id);
    const dest = path.join(ENABLED_DIR, l.id);

    if (!(await exists(src))) continue;

    // Try symlink; if it fails, copy
    try {
      await fs.symlink(src, dest, "dir");
    } catch {
      await copyDir(src, dest);
    }
  }
}

// =========================
// Download + extract helpers
// =========================
function isGithubRepoUrl(u) {
  try {
    const url = new URL(u);
    return url.hostname === "github.com";
  } catch {
    return false;
  }
}

function parseGithubOwnerRepo(u) {
  const url = new URL(u);
  const parts = url.pathname.replace(/^\/+/, "").split("/");
  const owner = parts[0];
  const repo = (parts[1] || "").replace(/\.git$/, "");
  if (!owner || !repo) return null;
  return { owner, repo };
}

async function githubCodeloadUrl(repoUrl, ref) {
  const pr = parseGithubOwnerRepo(repoUrl);
  if (!pr) throw new Error("Invalid GitHub repo URL");
  const { owner, repo } = pr;

  const headUrl = `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${encodeURIComponent(ref)}`;
  const tagUrl  = `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/tags/${encodeURIComponent(ref)}`;

  const r1 = await fetch(headUrl, { method: "HEAD" });
  if (r1.ok) return headUrl;

  const r2 = await fetch(tagUrl, { method: "HEAD" });
  if (r2.ok) return tagUrl;

  return headUrl;
}

async function downloadToBuffer(url) {
  const resp = await fetch(url, { redirect: "follow" });
  if (!resp.ok) throw new Error(`Download failed ${resp.status} from ${url}`);
  const ab = await resp.arrayBuffer();
  return Buffer.from(ab);
}

async function extractTarGz(archivePath, destDir) {
  await ensureDir(destDir);
  try {
    await execFileAsync("tar", ["-xzf", archivePath, "-C", destDir], { timeout: 120000 });
  } catch (e) {
    const msg = e?.stderr || e?.stdout || e?.message || String(e);
    throw new Error(`Extract failed: ${msg}`);
  }
}

async function listTopLevelDirs(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return entries.filter((e) => e.isDirectory()).map((e) => e.name);
}

async function installOneLibrary(lib) {
  const {
    id,
    url,
    ref = null,
    rootFolder = null,
    version = null,
    sha256 = null,
    enabled = true
  } = lib || {};

  if (!id || typeof id !== "string") throw new Error("Library missing id");
  if (!url || typeof url !== "string") throw new Error(`Library ${id} missing url`);

  await ensureDir(LIB_DIR);

  let usedUrl = url;
  if (isGithubRepoUrl(url)) {
    const refToUse = ref || "master";
    usedUrl = await githubCodeloadUrl(url, refToUse);
  }

  pushLog("library.download.start", `Downloading ${id}`, { url, usedUrl });

  const buf = await downloadToBuffer(usedUrl);
  const gotSha = await sha256Hex(buf);

  if (sha256 && String(sha256).toLowerCase() !== gotSha.toLowerCase()) {
    throw new Error(`SHA256 mismatch for ${id}. expected=${sha256} got=${gotSha}`);
  }

  const jobId = crypto.randomBytes(6).toString("hex");
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${id}-${jobId}-`));
  const archivePath = path.join(tmpDir, "lib.tar.gz");
  const extractDir = path.join(tmpDir, "extract");

  await fs.writeFile(archivePath, buf);
  await extractTarGz(archivePath, extractDir);

  let rf = rootFolder;
  if (!rf) {
    const tops = await listTopLevelDirs(extractDir);
    if (tops.length === 1) rf = tops[0];
  }
  if (!rf) {
    const tops = await listTopLevelDirs(extractDir);
    throw new Error(`Could not auto-detect rootFolder. Top-level dirs: ${tops.join(", ") || "(none)"}`);
  }

  const rfPath = path.join(extractDir, rf);
  if (!(await exists(rfPath))) {
    throw new Error(`Could not find rootFolder "${rf}" inside extracted archive`);
  }

  const dest = path.join(LIB_DIR, id);
  await rmrf(dest);
  await copyDir(rfPath, dest);

  const db = await readLibDb();
  db.libraries[id] = {
    id,
    version,
    url,
    usedUrl,
    sha256: gotSha,
    rootFolder: rf,
    enabled: enabled !== false,
    installedAt: db.libraries[id]?.installedAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastError: null
  };
  await writeLibDb(db);
  await rebuildEnabledDir();

  await rmrf(tmpDir);

  pushLog("library.install.ok", `Installed ${id}`, { id, enabled: enabled !== false, rootFolder: rf, sha256: gotSha.slice(0, 16) + "…" });
  pushState(db);
  return db.libraries[id];
}

async function removeLibraries(ids) {
  const db = await readLibDb();
  const removed = [];
  for (const id of ids) {
    if (!id) continue;
    await rmrf(path.join(LIB_DIR, id));
    delete db.libraries[id];
    removed.push(id);
    pushLog("library.remove", `Removed ${id}`, { id });
  }
  await writeLibDb(db);
  await rebuildEnabledDir();
  pushState(db);
  return removed;
}

async function setEnabled(id, enabled) {
  const db = await readLibDb();
  if (!db.libraries[id]) {
    db.libraries[id] = { id };
  }
  db.libraries[id].enabled = enabled === true;
  db.libraries[id].updatedAt = new Date().toISOString();
  await writeLibDb(db);
  await rebuildEnabledDir();
  pushLog("library.toggle", `${enabled ? "Enabled" : "Disabled"} ${id}`, { id, enabled });
  pushState(db);
  return db.libraries[id];
}

// =========================
// Routes
// =========================
app.get("/health", (_req, res) => res.status(200).send("ok"));

// Root: serve the dashboard (no more "Cannot GET /")
app.get("/", (req, res) => {
  // Keep token support on root page
  const q = TOKEN ? `?token=${encodeURIComponent(req.query?.token || "")}` : "";
  return res.redirect(`/libraries${q}`);
});

// Live event stream (SSE)
app.get("/events", async (req, res) => {
  if (!authOkOrQueryToken(req)) return res.status(401).end("Unauthorized");

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  sseClients.add(res);

  // Send initial snapshot
  const db = await readLibDb();
  res.write(`event: state\ndata: ${JSON.stringify({ ts: new Date().toISOString(), db })}\n\n`);
  for (const entry of logBuffer.slice(-50)) {
    res.write(`event: log\ndata: ${JSON.stringify(entry)}\n\n`);
  }

  const ping = setInterval(() => {
    try { res.write(`event: ping\ndata: ${Date.now()}\n\n`); } catch {}
  }, 15000);

  req.on("close", () => {
    clearInterval(ping);
    sseClients.delete(res);
  });
});

// Render STL
app.post("/render", async (req, res) => {
  let dir = null;
  const started = Date.now();
  try {
    if (!authOk(req)) return res.status(401).json({ error: "Unauthorized" });

    const { code, format } = req.body || {};
    if (typeof code !== "string" || !code.trim()) {
      return res.status(400).json({ error: "Missing code" });
    }
    if ((format || "stl") !== "stl") {
      return res.status(400).json({ error: "Only format=stl is supported" });
    }

    pushLog("render.start", "Render requested", { bytes: code.length });

    const jobId = crypto.randomBytes(6).toString("hex");
    dir = await fs.mkdtemp(path.join(os.tmpdir(), `scad-${jobId}-`));
    const inFile = path.join(dir, "input.scad");
    const outFile = path.join(dir, "output.stl");

    await fs.writeFile(inFile, code, "utf8");

    // Use only enabled libs
    const env = { ...process.env };
    const existing = env.OPENSCADPATH || "";
    env.OPENSCADPATH = existing
      ? `${ENABLED_DIR}${path.delimiter}${existing}`
      : `${ENABLED_DIR}`;

    // No --enable=manifold (your openscad build rejects it)
    await execFileAsync(
      OPENSCAD_BIN,
      ["-o", outFile, inFile],
      { timeout: OPENSCAD_TIMEOUT_MS, env }
    );

    const stl = await fs.readFile(outFile);
    const ms = Date.now() - started;

    pushLog("render.ok", "Render completed", { ms, bytes: stl.length });

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(stl);
  } catch (e) {
    const msg =
      e?.stderr?.toString?.() ||
      e?.stdout?.toString?.() ||
      e?.message ||
      String(e);

    pushLog("render.err", "Render failed", { error: msg });

    return res.status(500).json({ error: msg });
  } finally {
    if (dir) await rmrf(dir);
  }
});

// Sync libraries (install/update + enable flags + optional removals)
app.post("/libraries/sync", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const { libraries, removeIds } = req.body || {};
    pushLog("sync.start", "Library sync request received", {
      librariesCount: Array.isArray(libraries) ? libraries.length : 0,
      removeCount: Array.isArray(removeIds) ? removeIds.length : 0
    });

    const installed = [];
    const errors = [];

    if (Array.isArray(removeIds) && removeIds.length) {
      await removeLibraries(removeIds);
    }

    if (!Array.isArray(libraries) || libraries.length === 0) {
      const db = await readLibDb();
      pushState(db);
      return res.json({ ok: true, installed, errors, db });
    }

    for (const lib of libraries) {
      try {
        const rec = await installOneLibrary(lib);
        installed.push(rec);
      } catch (err) {
        const id = lib?.id || "(unknown)";
        const message = String(err?.message || err);

        const db = await readLibDb();
        db.libraries[id] = {
          ...(db.libraries[id] || {}),
          id,
          url: lib?.url || db.libraries[id]?.url || null,
          usedUrl: db.libraries[id]?.usedUrl || null,
          version: lib?.version ?? db.libraries[id]?.version ?? null,
          rootFolder: lib?.rootFolder ?? db.libraries[id]?.rootFolder ?? null,
          enabled: lib?.enabled ?? db.libraries[id]?.enabled ?? true,
          updatedAt: new Date().toISOString(),
          lastError: message
        };
        await writeLibDb(db);
        await rebuildEnabledDir();
        pushLog("library.install.err", `Failed ${id}`, { error: message });
        pushState(db);

        errors.push({ id, error: message });
      }
    }

    const db = await readLibDb();
    pushLog("sync.done", "Library sync finished", { ok: errors.length === 0, installed: installed.length, errors: errors.length });
    pushState(db);

    return res.json({ ok: errors.length === 0, installed, errors, db });
  } catch (e) {
    pushLog("sync.err", "Library sync crashed", { error: String(e?.message || e) });
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Toggle enable/disable (simple)
app.post("/libraries/toggle", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });
    const { id, enabled } = req.body || {};
    if (!id) return res.status(400).json({ ok: false, error: "Missing id" });

    const rec = await setEnabled(id, enabled === true);
    const db = await readLibDb();
    return res.json({ ok: true, library: rec, db });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Remove libraries
app.post("/libraries/remove", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });
    const { ids } = req.body || {};
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ ok: false, error: "Body must include ids: []" });
    }
    const removed = await removeLibraries(ids);
    const db = await readLibDb();
    return res.json({ ok: true, removed, db });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Status JSON
app.get("/libraries/status", async (req, res) => {
  try {
    if (!authOkOrQueryToken(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const db = await readLibDb();
    const libs = Object.values(db.libraries || {}).sort((a, b) =>
      String(a.id || "").localeCompare(String(b.id || ""))
    );

    return res.json({
      ok: true,
      count: libs.length,
      libDir: LIB_DIR,
      enabledDir: ENABLED_DIR,
      dbPath: LIB_DB_PATH,
      libraries: libs,
      recentLogs: logBuffer.slice(-50)
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Dashboard HTML (mobile-friendly + live updates)
app.get("/libraries", async (req, res) => {
  try {
    if (!authOkOrQueryToken(req)) {
      return res
        .status(401)
        .type("html")
        .send(`<h2>Unauthorized</h2><p>Open <code>/libraries?token=YOUR_TOKEN</code> or send an Authorization header.</p>`);
    }

    const tokenParam = TOKEN ? `?token=${encodeURIComponent(req.query?.token || "")}` : "";
    const eventsUrl = `/events${tokenParam}`;
    const statusUrl = `/libraries/status${tokenParam}`;

    return res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(SERVICE_NAME)} - Libraries</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
           background:#0b1020; color:#e5e7eb; }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 14px; }
    .card { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);
            border-radius: 14px; padding: 14px; box-shadow: 0 10px 30px rgba(0,0,0,0.25); }
    h1 { font-size: 18px; margin: 0 0 6px; }
    .meta { display:flex; gap:10px; flex-wrap:wrap; font-size: 12px; color:#a5b4fc; margin-bottom: 10px; }
    .pill { background: rgba(99,102,241,0.18); border: 1px solid rgba(99,102,241,0.35);
            padding: 4px 8px; border-radius: 999px; }
    .grid { display:grid; grid-template-columns: 1.2fr 0.8fr; gap: 12px; }
    table { width:100%; border-collapse: collapse; overflow:hidden; border-radius: 12px; }
    th, td { text-align:left; padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.10); font-size: 13px; vertical-align: top; }
    th { color:#c7d2fe; font-weight: 600; position: sticky; top: 0; background: rgba(11,16,32,0.95); }
    .ok { color:#34d399; font-weight: 700; }
    .bad { color:#fb7185; font-weight: 700; }
    .muted { color:#94a3b8; font-size: 12px; }
    .url { word-break: break-all; }
    .row { display:flex; gap:12px; flex-wrap:wrap; align-items:center; justify-content:space-between; margin-bottom: 10px; }
    button { background:#6366f1; border:none; color:white; padding:10px 12px; border-radius: 10px; font-weight: 700; cursor:pointer; }
    button:active { transform: translateY(1px); }
    .log { height: 420px; overflow:auto; border-radius: 12px; border:1px solid rgba(255,255,255,0.12); background: rgba(0,0,0,0.25); padding: 10px; }
    .logline { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New";
               font-size: 12px; line-height: 1.35; margin: 0 0 8px; }
    .logtype { color:#93c5fd; }
    .logts { color:#a7f3d0; }
    .divider { height: 1px; background: rgba(255,255,255,0.10); margin: 10px 0; }
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr; }
      .log { height: 320px; }
    }
    @media (max-width: 720px) {
      th:nth-child(5), td:nth-child(5),
      th:nth-child(6), td:nth-child(6) { display:none; }
      th, td { padding: 8px; font-size: 12px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="row">
        <div>
          <h1>${escapeHtml(SERVICE_NAME)} — Library Sync Dashboard</h1>
          <div class="meta">
            <span class="pill">External: ${escapeHtml(EXTERNAL_URL || "—")}</span>
            <span class="pill">LIB_DIR: ${escapeHtml(LIB_DIR)}</span>
            <span class="pill">ENABLED: ${escapeHtml(ENABLED_DIR)}</span>
            <span class="pill" id="count">Loading…</span>
            <span class="pill" id="live">Live: connecting…</span>
          </div>
        </div>
        <div><button onclick="refresh()">Refresh</button></div>
      </div>

      <div class="grid">
        <div>
          <table>
            <thead>
              <tr>
                <th style="width: 150px;">Library</th>
                <th>Status</th>
                <th>Enabled</th>
                <th>Installed</th>
                <th>Root Folder</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody id="tbody">
              <tr><td colspan="6" class="muted">Loading…</td></tr>
            </tbody>
          </table>
        </div>

        <div>
          <div class="muted" style="margin-bottom:6px">Live logs (updates when server receives POSTs)</div>
          <div class="log" id="log"></div>
          <div class="divider"></div>
          <div class="muted">
            Tip: keep this open while you press Enable/Disable in Base44 — you’ll see each action here.
          </div>
        </div>
      </div>
    </div>
  </div>

<script>
  const statusUrl = "${statusUrl}";
  const eventsUrl = "${eventsUrl}";
  let lastDb = null;

  function esc(s) {
    return String(s || "")
      .replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")
      .replaceAll('"',"&quot;").replaceAll("'","&#039;");
  }

  function fmtDate(s) {
    if (!s) return "—";
    const d = new Date(s);
    return isNaN(d.getTime()) ? String(s) : d.toLocaleString();
  }

  function renderDb(db) {
    lastDb = db;
    const libs = Object.values((db && db.libraries) || {}).sort((a,b)=>String(a.id||"").localeCompare(String(b.id||"")));

    document.getElementById("count").textContent = libs.length + " libraries";

    const rows = libs.map(l => {
      const installed = !!l.installedAt;
      const status = installed ? '<span class="ok">Installed</span>' : '<span class="bad">Missing</span>';
      const enabled = (l.enabled !== false) ? '<span class="ok">Yes</span>' : '<span class="bad">No</span>';
      const err = l.lastError ? ('<div class="bad muted" style="margin-top:4px;">' + esc(l.lastError) + '</div>') : '';
      const src = esc(l.usedUrl || l.url || "—");

      return \`
        <tr>
          <td><strong>\${esc(l.id || "")}</strong><div class="muted">\${esc(l.version || "")}</div></td>
          <td>\${status}\${err}</td>
          <td>\${enabled}</td>
          <td class="muted">\${esc(fmtDate(l.updatedAt || l.installedAt))}</td>
          <td class="muted">\${esc(l.rootFolder || "—")}</td>
          <td class="url muted">\${src}</td>
        </tr>
      \`;
    }).join("");

    document.getElementById("tbody").innerHTML =
      rows || '<tr><td colspan="6" class="muted">No libraries installed yet.</td></tr>';
  }

  function appendLog(entry) {
    const el = document.getElementById("log");
    const line = document.createElement("div");
    line.className = "logline";
    line.innerHTML =
      '<span class="logts">' + esc(entry.ts) + '</span> ' +
      '<span class="logtype">[' + esc(entry.type) + ']</span> ' +
      esc(entry.message) +
      (entry.data ? (' <span class="muted">' + esc(JSON.stringify(entry.data)) + '</span>') : '');
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
  }

  async function refresh() {
    const res = await fetch(statusUrl, { cache: "no-store" });
    const data = await res.json();
    if (data.ok) {
      renderDb({ libraries: Object.fromEntries((data.libraries||[]).map(l => [l.id, l])) });
      // preload logs if empty
      if ((data.recentLogs||[]).length && document.getElementById("log").children.length === 0) {
        for (const e of data.recentLogs) appendLog(e);
      }
    } else {
      document.getElementById("tbody").innerHTML =
        '<tr><td colspan="6" class="bad">Failed to load: ' + esc(data.error || "Unknown") + '</td></tr>';
    }
  }

  // SSE live updates
  function connectSse() {
    const live = document.getElementById("live");
    try {
      const es = new EventSource(eventsUrl);
      live.textContent = "Live: connected";

      es.addEventListener("state", (ev) => {
        const payload = JSON.parse(ev.data);
        renderDb(payload.db);
      });

      es.addEventListener("log", (ev) => {
        appendLog(JSON.parse(ev.data));
      });

      es.addEventListener("error", () => {
        live.textContent = "Live: disconnected (retrying…)";
      });

      return es;
    } catch (e) {
      live.textContent = "Live: unavailable (polling)";
      return null;
    }
  }

  refresh();
  connectSse();

  // fallback polling (in case proxies block SSE)
  setInterval(refresh, 10000);
</script>
</body>
</html>`);
  } catch (e) {
    return res.status(500).type("html").send(`<pre>${escapeHtml(String(e?.message || e))}</pre>`);
  }
});

// =========================
// Boot
// =========================
const port = process.env.PORT || 3000;
app.listen(port, async () => {
  await ensureDir(LIB_DIR);
  await rebuildEnabledDir();

  console.log(`${SERVICE_NAME} running on :${port}`);
  console.log(`LIB_DIR=${LIB_DIR}`);
  console.log(`ENABLED_DIR=${ENABLED_DIR}`);
  console.log(`DB=${LIB_DB_PATH}`);

  pushLog("server.start", "Server started", { port, LIB_DIR, ENABLED_DIR, DB: LIB_DB_PATH });
});
