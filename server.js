import express from "express";
import fs from "fs/promises";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const app = express();

// IMPORTANT for cookies behind Render/HTTPS proxy
app.set("trust proxy", 1);

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

// =========================
// Cookie auth helpers
// =========================
function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const [k, ...rest] = part.trim().split("=");
    if (!k) return;
    out[k] = decodeURIComponent(rest.join("=") || "");
  });
  return out;
}

function cookieAuthOk(req) {
  if (!TOKEN) return true;
  const c = parseCookies(req);
  return c.os_token === TOKEN;
}

function bearerAuthOk(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  return h === `Bearer ${TOKEN}`;
}

// For dashboard GET routes (browser loads): allow cookie or ?token or bearer
function dashboardAuthOk(req) {
  if (!TOKEN) return true;
  if (cookieAuthOk(req)) return true;
  if (bearerAuthOk(req)) return true;
  if ((req.query?.token || "") === TOKEN) return true; // optional fallback
  return false;
}

// For POST routes: require bearer (keep these protected from browser CSRF)
function apiAuthOk(req) {
  return bearerAuthOk(req);
}

// =========================
// Utils
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

// Node 16+ fs.cp exists; otherwise fallback copy
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
// Live log + SSE
// =========================
const MAX_LOG = 300;
const logBuffer = [];
const sseClients = new Set();

function pushLog(type, message, data = null) {
  const entry = { ts: new Date().toISOString(), type, message, data };
  logBuffer.push(entry);
  while (logBuffer.length > MAX_LOG) logBuffer.shift();

  const payload = `event: log\ndata: ${JSON.stringify(entry)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch {}
  }
}

function pushState(db) {
  const payload = `event: state\ndata: ${JSON.stringify({ ts: new Date().toISOString(), db })}\n\n`;
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
    const enabled = (l.enabled !== false);
    if (!enabled) continue;

    const src = path.join(LIB_DIR, l.id);
    const dest = path.join(ENABLED_DIR, l.id);
    if (!(await exists(src))) continue;

    // Prefer symlink; fall back to copy
    try {
      await fs.symlink(src, dest, "dir");
    } catch {
      await copyDir(src, dest);
    }
  }
}

// =========================
// Download + extract
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

  // try heads first, then tags
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
  await execFileAsync("tar", ["-xzf", archivePath, "-C", destDir], { timeout: 120000 });
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
    enabled = true,

    // optional fields for your “admin-like” UI
    name = null,
    description = null,
    keywords = null
  } = lib || {};

  if (!id || typeof id !== "string") throw new Error("Library missing id");
  if (!url || typeof url !== "string") throw new Error(`Library ${id} missing url`);

  await ensureDir(LIB_DIR);

  let usedUrl = url;
  if (isGithubRepoUrl(url)) {
    const refToUse = ref || "master";
    usedUrl = await githubCodeloadUrl(url, refToUse);
  }

  pushLog("library.download.start", `Downloading ${id}`, { usedUrl });

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
  const now = new Date().toISOString();

  db.libraries[id] = {
    // required core
    id,
    url,
    usedUrl,
    ref: ref || null,
    version,
    rootFolder: rf,
    sha256: gotSha,
    enabled: enabled !== false,

    // admin-ish metadata (optional)
    name: name || db.libraries[id]?.name || null,
    description: description || db.libraries[id]?.description || null,
    keywords: Array.isArray(keywords) ? keywords : (db.libraries[id]?.keywords || null),

    installedAt: db.libraries[id]?.installedAt || now,
    updatedAt: now,
    lastError: null
  };

  await writeLibDb(db);
  await rebuildEnabledDir();
  await rmrf(tmpDir);

  pushLog("library.install.ok", `Installed ${id}`, { enabled: db.libraries[id].enabled, rootFolder: rf });
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

// Root -> dashboard
app.get("/", (req, res) => res.redirect("/libraries"));

// Login page (sets cookie)
app.get("/login", (req, res) => {
  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(SERVICE_NAME)} - Login</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial; background:#0b1020; color:#e5e7eb; }
    .wrap { max-width: 520px; margin: 0 auto; padding: 18px; }
    .card { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);
            border-radius: 14px; padding: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.25); }
    h1 { font-size: 18px; margin: 0 0 8px; }
    p { color:#94a3b8; font-size: 13px; line-height: 1.4; margin: 0 0 12px; }
    input { width: 100%; padding: 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.14);
            background: rgba(0,0,0,0.25); color: #e5e7eb; font-size: 14px; }
    button { margin-top: 10px; width: 100%; background:#6366f1; border:none; color:white;
             padding:12px; border-radius: 12px; font-weight: 800; cursor:pointer; }
    .muted { margin-top: 10px; font-size: 12px; color:#94a3b8; }
    code { color:#a5b4fc; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>${escapeHtml(SERVICE_NAME)} — Dashboard Login</h1>
      <p>Enter your <code>OPENSCAD_RENDER_TOKEN</code> once. We store it in a secure cookie so you can view the live dashboard without URL tokens.</p>
      <form method="POST" action="/login">
        <input name="token" type="password" placeholder="Render token" autocomplete="current-password" />
        <button type="submit">Sign in</button>
      </form>
      <div class="muted">If you don’t set <code>OPENSCAD_RENDER_TOKEN</code>, login is not required.</div>
    </div>
  </div>
</body>
</html>`;
  res.type("html").send(html);
});

// need urlencoded for login
app.use(express.urlencoded({ extended: false }));

app.post("/login", (req, res) => {
  if (!TOKEN) return res.redirect("/libraries");
  const t = (req.body?.token || "").trim();
  if (t !== TOKEN) {
    return res.status(401).type("html").send(`<p style="font-family:system-ui;color:#fff;background:#0b1020;padding:20px">
      Wrong token. <a href="/login" style="color:#a5b4fc">Try again</a>.
    </p>`);
  }

  const isSecure = req.secure || (req.headers["x-forwarded-proto"] === "https");
  const cookie = [
    `os_token=${encodeURIComponent(TOKEN)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    isSecure ? "Secure" : ""
  ].filter(Boolean).join("; ");

  res.setHeader("Set-Cookie", cookie);
  pushLog("dashboard.login", "Dashboard login success");
  res.redirect("/libraries");
});

app.get("/logout", (_req, res) => {
  res.setHeader("Set-Cookie", "os_token=; Path=/; Max-Age=0; SameSite=Lax");
  res.redirect("/login");
});

// SSE live updates
app.get("/events", async (req, res) => {
  if (!dashboardAuthOk(req)) return res.status(401).end("Unauthorized");

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  sseClients.add(res);

  const db = await readLibDb();
  res.write(`event: state\ndata: ${JSON.stringify({ ts: new Date().toISOString(), db })}\n\n`);
  for (const entry of logBuffer.slice(-60)) {
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
    if (!apiAuthOk(req)) return res.status(401).json({ error: "Unauthorized" });

    const { code, format } = req.body || {};
    if (typeof code !== "string" || !code.trim()) return res.status(400).json({ error: "Missing code" });
    if ((format || "stl") !== "stl") return res.status(400).json({ error: "Only format=stl is supported" });

    pushLog("render.start", "Render requested", { bytes: code.length });

    const jobId = crypto.randomBytes(6).toString("hex");
    dir = await fs.mkdtemp(path.join(os.tmpdir(), `scad-${jobId}-`));
    const inFile = path.join(dir, "input.scad");
    const outFile = path.join(dir, "output.stl");
    await fs.writeFile(inFile, code, "utf8");

    // IMPORTANT: only enabled libs
    const env = { ...process.env };
    const existing = env.OPENSCADPATH || "";
    env.OPENSCADPATH = existing
      ? `${ENABLED_DIR}${path.delimiter}${existing}`
      : `${ENABLED_DIR}`;

    await execFileAsync(
      OPENSCAD_BIN,
      ["-o", outFile, inFile],
      { timeout: OPENSCAD_TIMEOUT_MS, env }
    );

    const stl = await fs.readFile(outFile);
    pushLog("render.ok", "Render completed", { ms: Date.now() - started, bytes: stl.length });

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

// Sync libraries (install/update + optional remove)
app.post("/libraries/sync", async (req, res) => {
  try {
    if (!apiAuthOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const { libraries, removeIds } = req.body || {};
    pushLog("sync.start", "Library sync request", {
      librariesCount: Array.isArray(libraries) ? libraries.length : 0,
      removeCount: Array.isArray(removeIds) ? removeIds.length : 0
    });

    const installed = [];
    const errors = [];

    if (Array.isArray(removeIds) && removeIds.length) {
      await removeLibraries(removeIds);
    }

    if (Array.isArray(libraries)) {
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
            ref: lib?.ref ?? db.libraries[id]?.ref ?? null,
            enabled: lib?.enabled ?? db.libraries[id]?.enabled ?? true,
            name: lib?.name ?? db.libraries[id]?.name ?? null,
            description: lib?.description ?? db.libraries[id]?.description ?? null,
            keywords: Array.isArray(lib?.keywords) ? lib.keywords : (db.libraries[id]?.keywords ?? null),
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

// Toggle enable/disable
app.post("/libraries/toggle", async (req, res) => {
  try {
    if (!apiAuthOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });
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
    if (!apiAuthOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });
    const { ids } = req.body || {};
    if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ ok: false, error: "Body must include ids: []" });

    const removed = await removeLibraries(ids);
    const db = await readLibDb();
    return res.json({ ok: true, removed, db });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Status JSON (dashboard fetch uses cookie auth)
app.get("/libraries/status", async (req, res) => {
  try {
    if (!dashboardAuthOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });

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
      recentLogs: logBuffer.slice(-80)
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Dashboard HTML (admin-like cards + search + live log)
app.get("/libraries", async (req, res) => {
  if (!dashboardAuthOk(req)) return res.redirect("/login");

  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(SERVICE_NAME)} - Libraries</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial; background:#0b1020; color:#e5e7eb; }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 16px; }
    .top { display:flex; align-items:center; justify-content:space-between; gap: 12px; flex-wrap:wrap; }
    h1 { font-size: 22px; margin: 0; letter-spacing: 0.2px; }
    .sub { color:#94a3b8; font-size: 13px; margin-top: 4px; }
    .btn { background:#6366f1; border:none; color:white; padding:10px 12px; border-radius: 10px; font-weight: 800; cursor:pointer; }
    .btn.secondary { background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.14); }
    .row { display:flex; gap: 12px; align-items:center; flex-wrap:wrap; margin-top: 14px; }
    .search { flex: 1; min-width: 220px; }
    input[type="search"] { width:100%; padding: 12px 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.14);
                          background: rgba(0,0,0,0.25); color:#e5e7eb; font-size: 14px; }
    .grid { display:grid; grid-template-columns: 1.6fr 1fr; gap: 14px; margin-top: 14px; }
    .panel { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);
             border-radius: 14px; padding: 14px; box-shadow: 0 10px 30px rgba(0,0,0,0.25); }
    .card { background: rgba(255,255,255,0.06); border: 1px solid rgba(99,102,241,0.35);
            border-radius: 16px; padding: 14px; margin-bottom: 12px; }
    .cardTop { display:flex; justify-content:space-between; gap: 10px; align-items:flex-start; }
    .title { display:flex; gap: 10px; align-items:flex-start; }
    .icon { width: 28px; height: 28px; border-radius: 10px; background: rgba(99,102,241,0.18);
            border: 1px solid rgba(99,102,241,0.35); display:flex; align-items:center; justify-content:center; }
    .name { font-weight: 900; font-size: 16px; }
    .desc { color:#cbd5e1; font-size: 13px; margin-top: 2px; line-height: 1.3; }
    .badge { padding: 4px 10px; border-radius: 999px; font-weight: 900; font-size: 12px; }
    .badge.ok { background: rgba(52,211,153,0.16); border: 1px solid rgba(52,211,153,0.35); color:#34d399; }
    .badge.off { background: rgba(251,113,133,0.14); border: 1px solid rgba(251,113,133,0.35); color:#fb7185; }
    .meta { margin-top: 10px; display:grid; gap: 6px; }
    .label { color:#94a3b8; font-size: 12px; }
    .chips { display:flex; flex-wrap:wrap; gap: 6px; margin-top: 6px; }
    .chip { font-size: 12px; color:#cbd5e1; background: rgba(255,255,255,0.06);
            border:1px solid rgba(255,255,255,0.10); padding: 3px 8px; border-radius: 999px; }
    .url { word-break: break-all; color:#94a3b8; font-size: 12px; margin-top: 6px; }
    .err { margin-top: 8px; color:#fb7185; font-size: 12px; }
    .log { height: 520px; overflow:auto; border-radius: 12px; border:1px solid rgba(255,255,255,0.12); background: rgba(0,0,0,0.25); padding: 10px; }
    .logline { font-family: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New"; font-size: 12px; margin: 0 0 8px; line-height: 1.35; }
    .ts { color:#a7f3d0; }
    .ty { color:#93c5fd; }
    .live { color:#a5b4fc; font-size: 12px; }
    @media (max-width: 940px) { .grid { grid-template-columns: 1fr; } .log { height: 320px; } }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>${escapeHtml(SERVICE_NAME)} — Library Monitor</h1>
        <div class="sub">Live view of installed/enabled libraries + sync/render logs.</div>
      </div>
      <div style="display:flex; gap:10px; align-items:center;">
        <span class="live" id="live">Live: connecting…</span>
        <button class="btn secondary" onclick="location.href='/logout'">Logout</button>
        <button class="btn" onclick="refresh()">Refresh</button>
      </div>
    </div>

    <div class="row">
      <div class="search"><input id="q" type="search" placeholder="Search libraries…" oninput="render()" /></div>
      <div class="live" id="count">Loading…</div>
    </div>

    <div class="grid">
      <div class="panel">
        <div id="cards"></div>
      </div>

      <div class="panel">
        <div class="label" style="margin-bottom:8px">Live Logs (updates when server receives POSTs)</div>
        <div class="log" id="log"></div>
      </div>
    </div>
  </div>

<script>
  const statusUrl = "/libraries/status";
  const eventsUrl = "/events";
  let db = null;

  function esc(s){ return String(s||"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;"); }
  function fmtDate(s){ if(!s) return "—"; const d=new Date(s); return isNaN(d)? String(s) : d.toLocaleString(); }

  function render(){
    if(!db){ return; }
    const q = (document.getElementById("q").value || "").toLowerCase().trim();
    const libs = Object.values(db.libraries || {}).sort((a,b)=>String(a.id||"").localeCompare(String(b.id||"")));

    const filtered = libs.filter(l => {
      const hay = [
        l.id, l.name, l.description,
        Array.isArray(l.keywords) ? l.keywords.join(" ") : ""
      ].join(" ").toLowerCase();
      return !q || hay.includes(q);
    });

    document.getElementById("count").textContent = filtered.length + " of " + libs.length + " libraries";

    const cards = filtered.map(l => {
      const enabled = (l.enabled !== false);
      const title = l.name || l.id;
      const desc = l.description || "—";
      const kws = Array.isArray(l.keywords) ? l.keywords : [];
      const last = l.updatedAt || l.installedAt;
      const url = l.usedUrl || l.url || "—";
      const err = l.lastError ? ('<div class="err">Last error: ' + esc(l.lastError) + '</div>') : "";

      return \`
        <div class="card">
          <div class="cardTop">
            <div class="title">
              <div class="icon">⬢</div>
              <div>
                <div class="name">\${esc(title)}</div>
                <div class="desc">\${esc(desc)}</div>
                <div class="url">\${esc(url)}</div>
              </div>
            </div>
            <div>
              <span class="badge \${enabled ? "ok" : "off"}">\${enabled ? "Enabled" : "Disabled"}</span>
            </div>
          </div>

          <div class="meta">
            <div class="label">Keywords:</div>
            <div class="chips">
              \${kws.length ? kws.map(k => '<span class="chip">'+esc(k)+'</span>').join("") : '<span class="chip">—</span>'}
            </div>
            <div class="label" style="margin-top:8px">Last Sync: \${esc(fmtDate(last))}</div>
            \${err}
          </div>
        </div>
      \`;
    }).join("");

    document.getElementById("cards").innerHTML = cards || '<div class="label">No libraries found.</div>';
  }

  function appendLog(entry){
    const el = document.getElementById("log");
    const line = document.createElement("div");
    line.className = "logline";
    line.innerHTML =
      '<span class="ts">' + esc(entry.ts) + '</span> ' +
      '<span class="ty">[' + esc(entry.type) + ']</span> ' +
      esc(entry.message) +
      (entry.data ? (' <span style="color:#94a3b8">' + esc(JSON.stringify(entry.data)) + '</span>') : '');
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
  }

  async function refresh(){
    const res = await fetch(statusUrl, { cache:"no-store", credentials:"same-origin" });
    const data = await res.json();
    if(!data.ok){
      document.getElementById("cards").innerHTML = '<div class="err">Failed: ' + esc(data.error || "Unknown") + '</div>';
      return;
    }
    db = { libraries: Object.fromEntries((data.libraries||[]).map(l => [l.id, l])) };
    render();

    // preload logs once
    const logEl = document.getElementById("log");
    if(logEl.children.length === 0 && (data.recentLogs||[]).length){
      for(const e of data.recentLogs) appendLog(e);
    }
  }

  function connectSse(){
    const live = document.getElementById("live");
    try{
      const es = new EventSource(eventsUrl);
      live.textContent = "Live: connected";

      es.addEventListener("state", (ev) => {
        const payload = JSON.parse(ev.data);
        db = payload.db;
        render();
      });

      es.addEventListener("log", (ev) => {
        appendLog(JSON.parse(ev.data));
      });

      es.addEventListener("error", () => {
        live.textContent = "Live: disconnected (retrying…)";
      });
      return es;
    }catch(e){
      live.textContent = "Live: unavailable (polling)";
      return null;
    }
  }

  refresh();
  connectSse();
  setInterval(refresh, 12000);
</script>
</body>
</html>`);
});

// =========================
// Boot
// =========================
const port = process.env.PORT || 3000;
app.listen(port, async () => {
  await ensureDir(LIB_DIR);
  await rebuildEnabledDir();
  pushLog("server.start", "Server started", { port, LIB_DIR, ENABLED_DIR, DB: LIB_DB_PATH });
  console.log(`${SERVICE_NAME} running on :${port}`);
});
