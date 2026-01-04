import express from "express";
import fs from "fs/promises";
import { createWriteStream, existsSync } from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const app = express();

app.use(express.json({ limit: "10mb" }));

/**
 * ENV
 */
const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || ""; // bearer token
const PORT = Number(process.env.PORT || 3000);

// Library storage
const LIB_ROOT = process.env.OPENSCAD_LIB_DIR || "/opt/openscad-libs";
const LIB_SRC_DIR = path.join(LIB_ROOT, "src");       // extracted libs go here
const LIB_ENABLED_DIR = path.join(LIB_ROOT, "enabled"); // symlinks named by id live here
const DB_PATH = process.env.OPENSCAD_LIB_DB || path.join(LIB_ROOT, "libdb.json");

// Limits
const MAX_ARCHIVE_BYTES = Number(process.env.OPENSCAD_MAX_ARCHIVE_BYTES || 80 * 1024 * 1024); // 80MB
const OPENSCAD_TIMEOUT_MS = Number(process.env.OPENSCAD_TIMEOUT_MS || 120_000);

// In-memory log + SSE clients
const LOG_MAX = 500;
const logs = [];
const sseClients = new Set();

/**
 * Small logger that also pushes to dashboard/SSE
 */
function log(tag, msg, obj) {
  const line =
    `${new Date().toISOString()} [${tag}] ${msg}` +
    (obj ? ` ${JSON.stringify(obj)}` : "");
  logs.push(line);
  while (logs.length > LOG_MAX) logs.shift();

  // broadcast
  for (const res of sseClients) {
    try {
      res.write(`event: log\ndata: ${JSON.stringify({ line })}\n\n`);
    } catch {}
  }
  // also console
  console.log(line);
}

function safeJson(res, status, payload) {
  res.status(status).setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  return res.send(JSON.stringify(payload));
}

/**
 * AUTH (Bearer OR cookie OR ?token=)
 */
function getTokenFromCookie(req) {
  const cookie = req.headers.cookie || "";
  const m = cookie.match(/(?:^|;\s*)osrt=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}
function getTokenFromReq(req) {
  const h = req.headers.authorization || "";
  if (h.startsWith("Bearer ")) return h.slice("Bearer ".length).trim();

  const c = getTokenFromCookie(req);
  if (c) return c.trim();

  const q = req.query?.token;
  if (typeof q === "string") return q.trim();

  return "";
}
function authOk(req) {
  if (!TOKEN) return true; // no token configured => open
  return getTokenFromReq(req) === TOKEN;
}
function requireAuth(req, res, next) {
  if (authOk(req)) return next();
  res.status(401).setHeader("Content-Type", "text/plain");
  return res.send('Unauthorized\n\nOpen "/?token=YOUR_TOKEN" once to login (cookie), or send Authorization: Bearer YOUR_TOKEN');
}

/**
 * DB
 */
async function ensureDirs() {
  await fs.mkdir(LIB_ROOT, { recursive: true });
  await fs.mkdir(LIB_SRC_DIR, { recursive: true });
  await fs.mkdir(LIB_ENABLED_DIR, { recursive: true });
}

async function readDb() {
  try {
    const txt = await fs.readFile(DB_PATH, "utf8");
    const parsed = JSON.parse(txt);
    if (!parsed || typeof parsed !== "object") throw new Error("bad db");
    if (!parsed.libraries) parsed.libraries = {};
    return parsed;
  } catch {
    return { libraries: {} };
  }
}

async function writeDb(db) {
  await fs.mkdir(path.dirname(DB_PATH), { recursive: true });
  await fs.writeFile(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

/**
 * Download helpers
 */
function isGithubRepoUrl(u) {
  return /^https:\/\/github\.com\/[^/]+\/[^/]+\/?$/.test(u);
}

function githubToCodeloadTarball(repoUrl, ref) {
  // repoUrl: https://github.com/owner/repo
  const m = repoUrl.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/?$/);
  if (!m) return null;
  const owner = m[1];
  const repo = m[2];
  const normalizedRef =
    ref && ref.startsWith("refs/")
      ? ref
      : `refs/heads/${ref || "master"}`;

  return `https://codeload.github.com/${owner}/${repo}/tar.gz/${normalizedRef}`;
}

async function downloadToFile(url, outFile) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`Download failed ${res.status} from ${url}`);
  const reader = res.body?.getReader?.();
  if (!reader) throw new Error("No response body stream");

  await fs.mkdir(path.dirname(outFile), { recursive: true });
  const ws = createWriteStream(outFile);

  const hash = crypto.createHash("sha256");
  let bytes = 0;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    bytes += value.length;
    if (bytes > MAX_ARCHIVE_BYTES) {
      ws.destroy();
      throw new Error(`Archive too large (> ${MAX_ARCHIVE_BYTES} bytes)`);
    }
    hash.update(value);
    ws.write(value);
  }
  ws.end();

  await new Promise((resolve, reject) => {
    ws.on("finish", resolve);
    ws.on("error", reject);
  });

  return { sha256: hash.digest("hex"), bytes };
}

async function execOk(bin, args, opts = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      timeout: opts.timeout ?? 120000,
      maxBuffer: opts.maxBuffer ?? 20 * 1024 * 1024,
      env: opts.env ?? process.env,
      cwd: opts.cwd,
    });
    return { ok: true, stdout, stderr };
  } catch (e) {
    const stdout = e?.stdout || "";
    const stderr = e?.stderr || "";
    const msg = e?.message || String(e);
    return { ok: false, msg, stdout, stderr };
  }
}

async function rmrf(p) {
  await fs.rm(p, { recursive: true, force: true });
}

async function moveDir(src, dst) {
  await fs.mkdir(path.dirname(dst), { recursive: true });
  try {
    await fs.rename(src, dst);
  } catch {
    // cross-device fallback: copy then delete
    await fs.cp(src, dst, { recursive: true });
    await rmrf(src);
  }
}

async function listTopFolders(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return entries.filter(e => e.isDirectory()).map(e => e.name);
}

/**
 * Install logic:
 * - Accept github repo URL + ref OR direct tar.gz URL
 * - Extract into LIB_SRC_DIR/<id>/<rootFolder>
 * - Create symlink LIB_ENABLED_DIR/<id> -> extracted folder if enabled
 */
async function installOrUpdateLibrary(db, lib) {
  const id = String(lib.id || "").trim();
  if (!id) throw new Error("Library missing id");

  const enabled = lib.enabled !== false; // default true
  const ref = lib.ref ? String(lib.ref).trim() : "master";

  const url = String(lib.url || "").trim();
  if (!url) throw new Error(`Library ${id} missing url`);

  // Build download URL
  let usedUrl = url;
  if (isGithubRepoUrl(url)) {
    usedUrl = githubToCodeloadTarball(url, ref);
  }

  const jobId = crypto.randomBytes(6).toString("hex");
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${id}-${jobId}-`));
  const archiveFile = path.join(tmpDir, "archive.tgz");
  const extractDir = path.join(tmpDir, "extract");

  await fs.mkdir(extractDir, { recursive: true });

  log("library.download.start", `Downloading ${id}`, { usedUrl });

  const { sha256, bytes } = await downloadToFile(usedUrl, archiveFile);

  // Optional hash verification
  if (lib.sha256 && String(lib.sha256).trim()) {
    const expected = String(lib.sha256).trim().toLowerCase();
    if (expected !== sha256) {
      throw new Error(`SHA256 mismatch for ${id} (expected ${expected}, got ${sha256})`);
    }
  }

  // Extract (tar must exist on server)
  const tarRes = await execOk("tar", ["-xzf", archiveFile, "-C", extractDir], { timeout: 120000 });
  if (!tarRes.ok) {
    throw new Error(`Extract failed for ${id}: ${tarRes.msg}\n${tarRes.stderr}`);
  }

  // Determine root folder
  const tops = await listTopFolders(extractDir);
  if (!tops.length) throw new Error(`No folders found after extracting ${id}`);

  const rootFolder = lib.rootFolder ? String(lib.rootFolder).trim() : tops[0];
  if (!tops.includes(rootFolder)) {
    throw new Error(`Could not find rootFolder "${rootFolder}" inside extracted archive (top folders: ${tops.join(", ")})`);
  }

  // Destination layout: /opt/openscad-libs/src/<id>/<rootFolder>
  const idDir = path.join(LIB_SRC_DIR, id);
  await rmrf(idDir);
  await fs.mkdir(idDir, { recursive: true });

  const extractedPath = path.join(extractDir, rootFolder);
  const destPath = path.join(idDir, rootFolder);

  await moveDir(extractedPath, destPath);

  // Enable/disable via symlink
  const linkPath = path.join(LIB_ENABLED_DIR, id);
  await fs.rm(linkPath, { force: true }).catch(() => {});
  if (enabled) {
    // symlink name == library id
    await fs.symlink(destPath, linkPath, "dir");
  }

  const now = new Date().toISOString();
  db.libraries[id] = {
    ...(db.libraries[id] || {}),
    id,
    url,
    usedUrl,
    ref,
    version: lib.version ?? null,
    rootFolder,
    sha256,
    bytes,
    enabled,
    name: lib.name ?? db.libraries[id]?.name ?? null,
    description: lib.description ?? db.libraries[id]?.description ?? null,
    keywords: lib.keywords ?? db.libraries[id]?.keywords ?? null,
    installedAt: db.libraries[id]?.installedAt ?? now,
    updatedAt: now,
    lastError: null,
  };

  await writeDb(db);

  log("library.install.ok", `Installed ${id}`, { enabled, rootFolder, sha256: sha256.slice(0, 12) });

  // Broadcast status update
  for (const res of sseClients) {
    try {
      res.write(`event: status\ndata: ${JSON.stringify({ libraries: db.libraries })}\n\n`);
    } catch {}
  }

  await rmrf(tmpDir);

  return db.libraries[id];
}

/**
 * ROUTES
 */
app.get("/health", (_req, res) => res.status(200).send("ok"));

/**
 * Dashboard (cookie login)
 * - Visit once with /?token=YOUR_TOKEN
 * - Cookie is set, future visits no token needed
 */
app.get("/", (req, res, next) => {
  const t = (req.query?.token || "").toString().trim();
  if (TOKEN && t && t === TOKEN) {
    res.setHeader(
      "Set-Cookie",
      `osrt=${encodeURIComponent(t)}; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=Lax; Secure`
    );
    log("dashboard.login", "Dashboard login success");
  }
  next();
}, requireAuth, async (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  return res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>OpenSCAD Render — Library Monitor</title>
  <style>
    body { margin:0; font-family: ui-sans-serif,system-ui, -apple-system, Segoe UI, Roboto; background:#0b0b16; color:#e9e9ff;}
    .wrap { max-width:1100px; margin:0 auto; padding:24px; }
    .top { display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;}
    h1 { margin:0; font-size:22px; letter-spacing:.2px;}
    .sub { margin-top:6px; color:#b8b8dd; font-size:13px;}
    .row { display:grid; grid-template-columns: 1fr 1.2fr; gap:14px; margin-top:16px;}
    @media (max-width: 900px){ .row { grid-template-columns: 1fr; } }
    .card { background: rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.10); border-radius:16px; padding:14px; }
    .search { width:100%; padding:12px 14px; border-radius:999px; border:1px solid rgba(255,255,255,.15); background:rgba(0,0,0,.25); color:#fff; outline:none;}
    .pill { display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px; font-size:12px; border:1px solid rgba(255,255,255,.15); background:rgba(255,255,255,.06);}
    .pill.ok { background:rgba(34,197,94,.15); border-color:rgba(34,197,94,.25); color:#bff7cd;}
    .pill.bad { background:rgba(239,68,68,.15); border-color:rgba(239,68,68,.25); color:#ffd0d0;}
    .btn { padding:9px 12px; border-radius:10px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.08); color:#fff; cursor:pointer;}
    .btn.primary { background:rgba(124,58,237,.45); border-color:rgba(124,58,237,.6);}
    .lib { display:flex; gap:12px; align-items:flex-start; padding:10px; border-radius:14px; border:1px solid rgba(255,255,255,.10); background:rgba(0,0,0,.15); margin-top:10px;}
    .lib h3 { margin:0; font-size:15px;}
    .lib .meta { color:#b8b8dd; font-size:12px; margin-top:6px; word-break:break-all;}
    .small { font-size:12px; color:#b8b8dd; }
    .err { color:#ffb4b4; font-size:12px; margin-top:6px; white-space:pre-wrap; }
    .logs { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas; font-size:12px; line-height:1.45; height:520px; overflow:auto; white-space:pre-wrap; background:rgba(0,0,0,.30); padding:12px; border-radius:14px; border:1px solid rgba(255,255,255,.10); }
    .bar { display:flex; align-items:center; gap:10px; }
    .right { display:flex; gap:8px; align-items:center; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>OpenSCAD Render Service — Library Monitor</h1>
        <div class="sub">Live view of installed/enabled libraries + sync/render logs.</div>
      </div>
      <div class="right">
        <span id="live" class="pill">Live: connecting…</span>
        <button class="btn" id="logout">Logout</button>
        <button class="btn primary" id="refresh">Refresh</button>
      </div>
    </div>

    <div style="margin-top:14px" class="bar">
      <input id="q" class="search" placeholder="Search libraries…" />
      <div class="small"><span id="count">0</span> libraries</div>
    </div>

    <div class="row">
      <div class="card">
        <div id="libs"></div>
      </div>

      <div class="card">
        <div class="small" style="margin-bottom:8px">Live Logs (updates when server receives POSTs)</div>
        <div id="logbox" class="logs"></div>
      </div>
    </div>
  </div>

<script>
  const libsEl = document.getElementById("libs");
  const logbox = document.getElementById("logbox");
  const q = document.getElementById("q");
  const countEl = document.getElementById("count");
  const liveEl = document.getElementById("live");

  let state = { libraries: {} };

  function pill(text, ok) {
    return '<span class="pill ' + (ok ? 'ok' : 'bad') + '">' + text + '</span>';
  }

  function renderLibs() {
    const term = (q.value || "").toLowerCase().trim();
    const items = Object.values(state.libraries || {});
    const filtered = items.filter(x => {
      const blob = [
        x.id, x.name, x.description, (x.keywords||[]).join(","), x.url
      ].join(" ").toLowerCase();
      return blob.includes(term);
    });
    countEl.textContent = filtered.length;

    if (!filtered.length) {
      libsEl.innerHTML = '<div class="small">No libraries found.</div>';
      return;
    }

    libsEl.innerHTML = filtered
      .sort((a,b)=>a.id.localeCompare(b.id))
      .map(lib => {
        const status = lib.enabled ? pill("Enabled", true) : pill("Disabled", false);
        const name = lib.name || lib.id;
        const last = lib.updatedAt ? new Date(lib.updatedAt).toLocaleString() : "—";
        const err = lib.lastError ? '<div class="err">Error: ' + lib.lastError + '</div>' : '';
        return (
          '<div class="lib">' +
            '<div style="flex:1">' +
              '<div style="display:flex; justify-content:space-between; gap:10px; align-items:center;">' +
                '<h3>' + name + '</h3>' +
                status +
              '</div>' +
              '<div class="meta">' + (lib.usedUrl || lib.url || "") + '</div>' +
              '<div class="small">Last Sync: ' + last + '</div>' +
              err +
            '</div>' +
          '</div>'
        );
      })
      .join("");
  }

  async function refresh() {
    const r = await fetch("/api/status", { credentials: "include" });
    if (!r.ok) {
      logbox.textContent = "Unauthorized. Open /?token=YOUR_TOKEN once.";
      return;
    }
    const data = await r.json();
    state = data.db || { libraries: {} };
    renderLibs();
    // initial logs
    if (Array.isArray(data.logs)) {
      logbox.textContent = data.logs.join("\\n");
      logbox.scrollTop = logbox.scrollHeight;
    }
  }

  q.addEventListener("input", renderLibs);
  document.getElementById("refresh").onclick = refresh;

  document.getElementById("logout").onclick = async () => {
    await fetch("/logout", { method: "POST", credentials: "include" });
    location.reload();
  };

  // SSE for logs + status
  const es = new EventSource("/events", { withCredentials: true });

  es.onopen = () => {
    liveEl.textContent = "Live: connected";
    liveEl.className = "pill ok";
  };
  es.onerror = () => {
    liveEl.textContent = "Live: disconnected";
    liveEl.className = "pill bad";
  };

  es.addEventListener("log", (e) => {
    try {
      const { line } = JSON.parse(e.data);
      logbox.textContent += (logbox.textContent ? "\\n" : "") + line;
      logbox.scrollTop = logbox.scrollHeight;
    } catch {}
  });

  es.addEventListener("status", (e) => {
    try {
      const payload = JSON.parse(e.data);
      state.libraries = payload.libraries || {};
      renderLibs();
    } catch {}
  });

  refresh();
</script>
</body>
</html>`);
});

app.post("/logout", async (_req, res) => {
  res.setHeader("Set-Cookie", `osrt=; Path=/; Max-Age=0; SameSite=Lax; Secure`);
  return res.status(200).send("ok");
});

/**
 * SSE events for live logs/status
 */
app.get("/events", requireAuth, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  sseClients.add(res);
  res.write(`event: log\ndata: ${JSON.stringify({ line: `${new Date().toISOString()} [sse] connected` })}\n\n`);

  req.on("close", () => {
    sseClients.delete(res);
  });
});

/**
 * Status endpoint (dashboard uses this)
 */
app.get("/api/status", requireAuth, async (_req, res) => {
  const db = await readDb();
  return safeJson(res, 200, {
    ok: true,
    db,
    logs: logs.slice(-250),
    env: { port: PORT, LIB_ROOT, LIB_ENABLED_DIR, DB_PATH },
  });
});

/**
 * Library sync:
 * POST /libraries/sync
 * Body:
 * {
 *   "libraries": [
 *     { id, url, ref, enabled, rootFolder?, sha256?, name?, description?, keywords? }
 *   ]
 * }
 */
app.post("/libraries/sync", requireAuth, async (req, res) => {
  const body = req.body || {};
  const libs = Array.isArray(body.libraries) ? body.libraries : [];

  log("library.sync.start", "Library sync request", { librariesCount: libs.length });

  if (!libs.length) {
    return safeJson(res, 400, { ok: false, error: "Missing libraries[]" });
  }

  const db = await readDb();
  const installed = [];
  const errors = [];

  for (const lib of libs) {
    try {
      const record = await installOrUpdateLibrary(db, lib);
      installed.push(record);
    } catch (e) {
      const id = lib?.id || "(unknown)";
      const msg = String(e?.message || e);
      errors.push({ id, error: msg });
      db.libraries[id] = {
        ...(db.libraries[id] || {}),
        id,
        url: lib?.url ?? db.libraries[id]?.url ?? null,
        ref: lib?.ref ?? db.libraries[id]?.ref ?? null,
        enabled: lib?.enabled !== false,
        updatedAt: new Date().toISOString(),
        lastError: msg,
      };
      await writeDb(db);
      log("library.install.err", `Install failed ${id}`, { error: msg });
    }
  }

  log("sync.done", "Library sync finished", { ok: errors.length === 0, installed: installed.length, errors: errors.length });

  // broadcast final status
  for (const r of sseClients) {
    try {
      r.write(`event: status\ndata: ${JSON.stringify({ libraries: db.libraries })}\n\n`);
    } catch {}
  }

  return safeJson(res, 200, { ok: errors.length === 0, installed, errors, db });
});

/**
 * Render endpoint:
 * POST /render
 * { format:"stl", code:"...scad..." }
 */
app.post("/render", requireAuth, async (req, res) => {
  try {
    const { code, format } = req.body || {};
    if (typeof code !== "string" || !code.trim()) {
      return safeJson(res, 400, { error: "Missing code" });
    }
    if ((format || "stl") !== "stl") {
      return safeJson(res, 400, { error: "Only format=stl is supported" });
    }

    log("render.start", "Render requested", { bytes: Buffer.byteLength(code, "utf8") });

    const jobId = crypto.randomBytes(6).toString("hex");
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), `scad-${jobId}-`));
    const inFile = path.join(dir, "input.scad");
    const outFile = path.join(dir, "output.stl");

    await fs.writeFile(inFile, code, "utf8");

    // Make enabled libraries available to OpenSCAD via OPENSCADPATH
    const env = { ...process.env };
    const existing = env.OPENSCADPATH ? String(env.OPENSCADPATH) : "";
    env.OPENSCADPATH = existing
      ? `${LIB_ENABLED_DIR}${path.delimiter}${existing}`
      : `${LIB_ENABLED_DIR}`;

    const r = await execOk("openscad", ["-o", outFile, inFile], {
      timeout: OPENSCAD_TIMEOUT_MS,
      env,
    });

    if (!r.ok) {
      // Return real stderr so you can debug (no more blank)
      log("render.err", "Render failed", { error: r.msg });
      await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
      return safeJson(res, 500, {
        error: "OpenSCAD render failed",
        message: r.msg,
        stderr: r.stderr,
        stdout: r.stdout,
      });
    }

    const stl = await fs.readFile(outFile);
    await fs.rm(dir, { recursive: true, force: true }).catch(() => {});

    log("render.ok", "Render completed", { bytes: stl.length });

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(stl);
  } catch (e) {
    log("render.err", "Render exception", { error: String(e?.message || e) });
    return safeJson(res, 500, { error: String(e?.message || e) });
  }
});

/**
 * Start
 */
(async () => {
  await ensureDirs();
  const db = await readDb();
  await writeDb(db);

  log("server.start", "Server started", { port: PORT, LIB_ROOT, LIB_ENABLED_DIR, DB_PATH });

  app.listen(PORT, () => {
    console.log(`OpenSCAD render service running on :${PORT}`);
  });
})();
