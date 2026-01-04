import express from "express";
import fs from "fs/promises";
import fsSync from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const app = express();

app.use(express.json({ limit: "15mb" }));

/**
 * ENV
 */
const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || "";
const PORT = Number(process.env.PORT || 3000);
const OPENSCAD_BIN = process.env.OPENSCAD_BIN || "openscad";

// Where libs + DB live
const LIB_DIR = process.env.OPENSCAD_LIB_DIR || "/opt/openscad-libs";
const ENABLED_DIR = path.join(LIB_DIR, "_enabled");     // symlinks used by OpenSCAD include path
const INSTALL_DIR = path.join(LIB_DIR, "_installed");   // extracted archives
const DB_PATH = process.env.OPENSCAD_LIB_DB || path.join(LIB_DIR, "libdb.json");

// Limits
const MAX_LIB_BYTES = Number(process.env.OPENSCAD_MAX_LIB_BYTES || 250 * 1024 * 1024); // 250MB
const RENDER_TIMEOUT_MS = Number(process.env.OPENSCAD_RENDER_TIMEOUT_MS || 120000);
const MAX_CONCURRENT_RENDERS = Number(process.env.OPENSCAD_MAX_CONCURRENT || 2);

// Optional CORS (only if you need browser calls from your Base44 frontend directly)
const CORS_ORIGIN = process.env.CORS_ORIGIN || "";

/**
 * Basic CORS (optional)
 */
if (CORS_ORIGIN) {
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", CORS_ORIGIN);
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });
}

/**
 * Auth helpers
 */
function getTokenFromReq(req) {
  const h = req.headers.authorization || "";
  if (h.startsWith("Bearer ")) return h.slice("Bearer ".length).trim();
  if (req.query && typeof req.query.token === "string") return req.query.token.trim();
  return "";
}
function authOk(req) {
  if (!TOKEN) return true;
  return getTokenFromReq(req) === TOKEN;
}
function requireAuth(req, res, next) {
  if (!authOk(req)) {
    return res
      .status(401)
      .send("Unauthorized\n\nOpen /?token=YOUR_TOKEN or send an Authorization header.");
  }
  next();
}

/**
 * Logging + SSE
 */
const LOG_RING_MAX = 500;
const logRing = [];
const sseClients = new Set();

function pushLog(tag, message, meta = null) {
  const line = {
    ts: new Date().toISOString(),
    tag,
    message,
    meta,
  };
  logRing.push(line);
  if (logRing.length > LOG_RING_MAX) logRing.shift();

  // broadcast to SSE clients
  const payload = `event: log\ndata: ${JSON.stringify(line)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch (_) {}
  }
}

function pushStateUpdate(db) {
  const payload = `event: state\ndata: ${JSON.stringify({ ts: new Date().toISOString(), db })}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch (_) {}
  }
}

/**
 * DB
 */
let db = { libraries: {} };

async function ensureDirs() {
  await fs.mkdir(LIB_DIR, { recursive: true });
  await fs.mkdir(ENABLED_DIR, { recursive: true });
  await fs.mkdir(INSTALL_DIR, { recursive: true });
}

async function loadDb() {
  try {
    const txt = await fs.readFile(DB_PATH, "utf8");
    db = JSON.parse(txt);
    if (!db || typeof db !== "object") db = { libraries: {} };
    if (!db.libraries || typeof db.libraries !== "object") db.libraries = {};
  } catch (_) {
    db = { libraries: {} };
  }
}

async function saveDb() {
  await fs.writeFile(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

/**
 * Symlink enabled libs into ENABLED_DIR/<id> so users can:
 *   use <MCAD/involute_gears.scad>;
 */
async function rebuildEnabledSymlinks() {
  await fs.mkdir(ENABLED_DIR, { recursive: true });

  // remove existing symlinks/dirs in ENABLED_DIR
  const entries = await fs.readdir(ENABLED_DIR).catch(() => []);
  for (const e of entries) {
    await fs.rm(path.join(ENABLED_DIR, e), { recursive: true, force: true }).catch(() => {});
  }

  for (const [id, lib] of Object.entries(db.libraries)) {
    if (!lib.enabled) continue;
    if (!lib.installPath) continue;
    const linkPath = path.join(ENABLED_DIR, id);
    try {
      await fs.symlink(lib.installPath, linkPath, "junction");
    } catch (e) {
      pushLog("library.symlink.err", `Failed to symlink ${id}`, { error: String(e?.message || e) });
      db.libraries[id].lastError = `Symlink failed: ${String(e?.message || e)}`;
    }
  }
  await saveDb();
}

/**
 * Download helpers
 */
function isLikelyGitHubRepoUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname === "github.com" && u.pathname.split("/").filter(Boolean).length >= 2;
  } catch {
    return false;
  }
}

function parseGitHubOwnerRepo(url) {
  const u = new URL(url);
  const parts = u.pathname.split("/").filter(Boolean);
  const owner = parts[0];
  let repo = parts[1] || "";
  repo = repo.replace(/\.git$/i, "");
  return { owner, repo };
}

function pickGitHubArchiveUrl(repoUrl, ref) {
  const { owner, repo } = parseGitHubOwnerRepo(repoUrl);

  // Try heads first; if it 404s we’ll retry as tags during download.
  const r = (ref && String(ref).trim()) ? String(ref).trim() : "master";
  const heads = `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${encodeURIComponent(r)}`;
  const tags  = `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/tags/${encodeURIComponent(r)}`;
  return { heads, tags, ref: r };
}

async function downloadToFile(url, outPath) {
  const resp = await fetch(url, { redirect: "follow" });
  if (!resp.ok) {
    throw new Error(`Download failed ${resp.status} from ${url}`);
  }
  const contentLength = Number(resp.headers.get("content-length") || "0");
  if (contentLength && contentLength > MAX_LIB_BYTES) {
    throw new Error(`Download too large (${contentLength} bytes)`);
  }

  const arr = new Uint8Array(await resp.arrayBuffer());
  if (arr.byteLength > MAX_LIB_BYTES) {
    throw new Error(`Download too large (${arr.byteLength} bytes)`);
  }

  await fs.writeFile(outPath, arr);
  return arr.byteLength;
}

async function sha256File(filePath) {
  const buf = await fs.readFile(filePath);
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function tarTopFolder(archivePath) {
  const { stdout } = await execFileAsync("tar", ["-tzf", archivePath], { timeout: 60000 });
  const lines = stdout.split("\n").map(s => s.trim()).filter(Boolean);
  if (!lines.length) throw new Error("Archive appears empty");
  const first = lines[0];
  const top = first.split("/")[0];
  return top;
}

async function tarExtract(archivePath, destDir) {
  await fs.mkdir(destDir, { recursive: true });
  await execFileAsync("tar", ["-xzf", archivePath, "-C", destDir], { timeout: 120000 });
}

/**
 * Install/Update one library
 */
async function installLibrary(spec) {
  const id = String(spec.id || "").trim();
  if (!id) throw new Error("Library missing id");

  const url = String(spec.url || "").trim();
  if (!url) throw new Error(`Library ${id} missing url`);

  const enabled = (spec.enabled === undefined) ? true : !!spec.enabled;
  const ref = spec.ref ? String(spec.ref).trim() : null;
  const rootFolderOverride = spec.rootFolder ? String(spec.rootFolder).trim() : null;
  const expectedSha = spec.sha256 ? String(spec.sha256).trim().toLowerCase() : null;

  // Determine actual download URL
  let usedUrl = url;
  let tagFallbackUrl = null;

  if (isLikelyGitHubRepoUrl(url)) {
    const { heads, tags, ref: r } = pickGitHubArchiveUrl(url, ref);
    usedUrl = heads;
    tagFallbackUrl = tags;
    pushLog("library.download.start", `Downloading ${id}`, { usedUrl, ref: r });
  } else {
    pushLog("library.download.start", `Downloading ${id}`, { usedUrl });
  }

  const jobId = crypto.randomBytes(6).toString("hex");
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${id}-${jobId}-`));
  const archivePath = path.join(tmpDir, `${id}.tar.gz`);

  let downloadedFrom = usedUrl;
  try {
    try {
      await downloadToFile(usedUrl, archivePath);
    } catch (e) {
      // If it was a GitHub repo and heads failed, try tags automatically
      if (tagFallbackUrl) {
        pushLog("library.download.retry", `Retrying ${id} as tag`, { usedUrl: tagFallbackUrl });
        await downloadToFile(tagFallbackUrl, archivePath);
        downloadedFrom = tagFallbackUrl;
      } else {
        throw e;
      }
    }

    const actualSha = await sha256File(archivePath);
    if (expectedSha && expectedSha !== actualSha) {
      throw new Error(`SHA256 mismatch for ${id}. Expected ${expectedSha}, got ${actualSha}`);
    }

    // Figure out root folder
    const topFolder = await tarTopFolder(archivePath);
    const rootFolder = rootFolderOverride || topFolder;

    // Verify rootFolder exists in archive listing (cheap check)
    // (we’ll just ensure it matches top folder or is within it)
    if (rootFolderOverride && rootFolderOverride !== topFolder) {
      // allow nested, but must start with topFolder
      if (!rootFolderOverride.startsWith(topFolder)) {
        throw new Error(`Could not find rootFolder "${rootFolderOverride}" inside extracted archive (top folder is "${topFolder}")`);
      }
    }

    // Extract into INSTALL_DIR/<id>/<sha>/
    const libBase = path.join(INSTALL_DIR, id, actualSha);
    await fs.rm(libBase, { recursive: true, force: true }).catch(() => {});
    await fs.mkdir(libBase, { recursive: true });

    await tarExtract(archivePath, libBase);

    const installPath = path.join(libBase, rootFolder);
    if (!fsSync.existsSync(installPath)) {
      throw new Error(`Install path not found after extract: ${installPath}`);
    }

    const now = new Date().toISOString();

    db.libraries[id] = {
      id,
      url,
      usedUrl: downloadedFrom,
      ref: ref || null,
      version: spec.version ? String(spec.version) : null,
      rootFolder,
      sha256: actualSha,
      enabled,
      name: spec.name ? String(spec.name) : (db.libraries[id]?.name ?? null),
      description: spec.description ? String(spec.description) : (db.libraries[id]?.description ?? null),
      keywords: Array.isArray(spec.keywords) ? spec.keywords : (db.libraries[id]?.keywords ?? null),
      installPath,
      installedAt: db.libraries[id]?.installedAt || now,
      updatedAt: now,
      lastError: null,
    };

    pushLog("library.install.ok", `Installed ${id}`, { enabled, rootFolder, sha256: actualSha });
    await saveDb();
    await rebuildEnabledSymlinks();
    pushStateUpdate(db);

    return db.libraries[id];
  } catch (e) {
    const msg = String(e?.message || e);
    pushLog("library.install.err", `Failed ${id}`, { error: msg });

    const now = new Date().toISOString();
    db.libraries[id] = {
      ...(db.libraries[id] || { id }),
      id,
      url,
      usedUrl,
      ref: ref || null,
      version: spec.version ? String(spec.version) : (db.libraries[id]?.version ?? null),
      enabled,
      updatedAt: now,
      lastError: msg,
    };
    await saveDb();
    pushStateUpdate(db);

    throw e;
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Enable/Disable/Delete helpers
 */
async function setEnabled(id, enabled) {
  if (!db.libraries[id]) throw new Error(`Library not found: ${id}`);
  db.libraries[id].enabled = !!enabled;
  db.libraries[id].updatedAt = new Date().toISOString();
  db.libraries[id].lastError = null;
  await saveDb();
  await rebuildEnabledSymlinks();
  pushLog("library.enabled", `${enabled ? "Enabled" : "Disabled"} ${id}`);
  pushStateUpdate(db);
  return db.libraries[id];
}
async function deleteLibrary(id) {
  const lib = db.libraries[id];
  if (!lib) return;
  delete db.libraries[id];
  await saveDb();

  // remove enabled link and installed files
  await fs.rm(path.join(ENABLED_DIR, id), { recursive: true, force: true }).catch(() => {});
  await fs.rm(path.join(INSTALL_DIR, id), { recursive: true, force: true }).catch(() => {});
  pushLog("library.delete", `Deleted ${id}`);
  pushStateUpdate(db);
}

/**
 * Simple render concurrency limiter
 */
let inFlight = 0;
const waiters = [];
async function acquireRenderSlot() {
  if (inFlight < MAX_CONCURRENT_RENDERS) {
    inFlight += 1;
    return;
  }
  await new Promise(resolve => waiters.push(resolve));
  inFlight += 1;
}
function releaseRenderSlot() {
  inFlight = Math.max(0, inFlight - 1);
  const next = waiters.shift();
  if (next) next();
}

/**
 * Routes
 */
app.get("/health", (_req, res) => res.status(200).send("ok"));

/**
 * SSE events for dashboard
 */
app.get("/events", requireAuth, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  // initial state + logs
  res.write(`event: state\ndata: ${JSON.stringify({ ts: new Date().toISOString(), db })}\n\n`);
  for (const l of logRing) {
    res.write(`event: log\ndata: ${JSON.stringify(l)}\n\n`);
  }

  sseClients.add(res);
  req.on("close", () => sseClients.delete(res));
});

/**
 * Return installed libs (server truth)
 */
app.get("/libraries", requireAuth, async (_req, res) => {
  const libs = Object.values(db.libraries || {});
  res.json({ ok: true, libraries: libs });
});

/**
 * Install/update libs.
 * Body:
 * { libraries: [{id,url,ref,rootFolder,sha256,version,enabled,name,description,keywords}], removeMissing?: boolean }
 */
app.post("/libraries/sync", requireAuth, async (req, res) => {
  try {
    const libraries = Array.isArray(req.body?.libraries) ? req.body.libraries : [];
    const removeMissing = !!req.body?.removeMissing;

    pushLog("sync.start", "Library sync request", { librariesCount: libraries.length, removeMissing });

    const installed = [];
    const errors = [];

    const incomingIds = new Set(libraries.map(l => String(l?.id || "").trim()).filter(Boolean));

    for (const spec of libraries) {
      try {
        const lib = await installLibrary(spec);
        installed.push(lib);
      } catch (e) {
        errors.push({ id: spec?.id, error: String(e?.message || e) });
      }
    }

    if (removeMissing) {
      // disable anything not in incoming list
      for (const id of Object.keys(db.libraries)) {
        if (!incomingIds.has(id)) {
          await setEnabled(id, false).catch(() => {});
        }
      }
    }

    pushLog("sync.done", "Library sync finished", { ok: errors.length === 0, installed: installed.length, errors: errors.length });
    pushStateUpdate(db);

    res.json({ ok: errors.length === 0, installed, errors, db });
  } catch (e) {
    pushLog("sync.err", "Library sync failed", { error: String(e?.message || e) });
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post("/libraries/:id/enable", requireAuth, async (req, res) => {
  try {
    const lib = await setEnabled(req.params.id, true);
    res.json({ ok: true, library: lib });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post("/libraries/:id/disable", requireAuth, async (req, res) => {
  try {
    const lib = await setEnabled(req.params.id, false);
    res.json({ ok: true, library: lib });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e?.message || e) });
  }
});

app.delete("/libraries/:id", requireAuth, async (req, res) => {
  try {
    await deleteLibrary(req.params.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e?.message || e) });
  }
});

/**
 * Render endpoint
 * Body: { code: "...", format: "stl" }
 */
app.post("/render", requireAuth, async (req, res) => {
  await acquireRenderSlot();
  const start = Date.now();

  try {
    const { code, format } = req.body || {};
    if (typeof code !== "string" || !code.trim()) {
      return res.status(400).json({ error: "Missing code" });
    }
    if ((format || "stl") !== "stl") {
      return res.status(400).json({ error: "Only format=stl is supported" });
    }

    pushLog("render.start", "Render requested", { bytes: Buffer.byteLength(code, "utf8") });

    const jobId = crypto.randomBytes(6).toString("hex");
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), `scad-${jobId}-`));
    const inFile = path.join(dir, "input.scad");
    const outFile = path.join(dir, "output.stl");

    await fs.writeFile(inFile, code, "utf8");

    // IMPORTANT: No --enable=manifold (your OpenSCAD doesn’t support it)
    // Provide library include path via OPENSCADPATH pointing at ENABLED_DIR which contains symlinks:
    //   ENABLED_DIR/MCAD -> .../MCAD-master
    // so user can `use <MCAD/involute_gears.scad>;`
    const env = {
      ...process.env,
      OPENSCADPATH: ENABLED_DIR,
    };

    // Use binstl to keep STL smaller and faster
    const args = [
      "-o", outFile,
      "--export-format", "binstl",
      inFile
    ];

    let stdout = "";
    let stderr = "";
    try {
      const r = await execFileAsync(OPENSCAD_BIN, args, { timeout: RENDER_TIMEOUT_MS, env });
      stdout = r.stdout || "";
      stderr = r.stderr || "";
    } catch (e) {
      stdout = e?.stdout || "";
      stderr = e?.stderr || "";
      // Return stderr so you can see why OpenSCAD failed (missing module, include path, syntax, etc.)
      const errMsg = `OpenSCAD failed.\n\nSTDERR:\n${stderr}\n\nSTDOUT:\n${stdout}`;
      pushLog("render.err", "Render failed", { error: errMsg.slice(0, 2000) });
      return res.status(500).json({ error: errMsg });
    }

    const stl = await fs.readFile(outFile);
    const ms = Date.now() - start;

    pushLog("render.ok", "Render completed", { ms, bytes: stl.length });

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(stl);
  } finally {
    releaseRenderSlot();
  }
});

/**
 * Dashboard UI (root)
 */
app.get("/", requireAuth, async (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>OpenSCAD Render Service — Library Monitor</title>
<style>
  :root{
    --bg:#0b0b16; --panel:#151528; --panel2:#111125;
    --border:#27274a; --text:#eaeaff; --muted:#a7a7c7;
    --good:#2dd4bf; --bad:#fb7185; --chip:#1d1d36;
    --accent:#7c3aed;
  }
  *{box-sizing:border-box}
  body{
    margin:0;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
    background: radial-gradient(1200px 600px at 10% 10%, #1b1440 0%, rgba(27,20,64,0) 60%),
                radial-gradient(900px 500px at 90% 20%, #23123b 0%, rgba(35,18,59,0) 55%),
                var(--bg);
    color:var(--text);
  }
  header{
    padding:22px 26px 10px;
    display:flex; align-items:center; justify-content:space-between;
    gap:12px;
  }
  h1{margin:0; font-size:22px; letter-spacing:.2px}
  .sub{color:var(--muted); font-size:13px; margin-top:4px}
  .topRight{display:flex; gap:10px; align-items:center}
  .pill{padding:7px 10px; background:rgba(255,255,255,.06); border:1px solid var(--border); border-radius:999px; color:var(--muted); font-size:12px}
  .btn{
    cursor:pointer;
    padding:10px 12px;
    border-radius:10px;
    border:1px solid var(--border);
    background:rgba(255,255,255,.06);
    color:var(--text);
    font-weight:600;
  }
  .btn.primary{background:linear-gradient(135deg, var(--accent), #5b21b6); border-color:transparent}
  .wrap{padding:0 26px 26px}
  .searchRow{display:flex; gap:12px; align-items:center; margin:10px 0 14px}
  input{
    width:100%;
    padding:12px 14px;
    border-radius:12px;
    border:1px solid var(--border);
    background:rgba(0,0,0,.25);
    color:var(--text);
    outline:none;
  }
  .grid{
    display:grid;
    grid-template-columns: 360px 1fr;
    gap:14px;
  }
  @media (max-width: 980px){
    .grid{grid-template-columns:1fr}
  }
  .panel{
    background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
    border:1px solid var(--border);
    border-radius:16px;
    overflow:hidden;
  }
  .panelHead{
    padding:12px 14px;
    border-bottom:1px solid var(--border);
    display:flex; justify-content:space-between; align-items:center;
  }
  .panelTitle{font-weight:800}
  .count{color:var(--muted); font-size:12px}
  .list{padding:12px; display:flex; flex-direction:column; gap:10px; max-height:60vh; overflow:auto}
  .card{
    border:1px solid var(--border);
    border-radius:14px;
    padding:12px;
    background:rgba(0,0,0,.18);
  }
  .row{display:flex; justify-content:space-between; gap:10px; align-items:center}
  .id{font-weight:900; letter-spacing:.3px}
  .tag{
    font-size:12px;
    padding:4px 10px;
    border-radius:999px;
    border:1px solid var(--border);
    background:rgba(255,255,255,.06);
  }
  .tag.good{border-color:rgba(45,212,191,.35); color:var(--good)}
  .tag.bad{border-color:rgba(251,113,133,.35); color:var(--bad)}
  .url{color:var(--muted); font-size:12px; word-break:break-all; margin-top:8px}
  .meta{display:flex; gap:8px; flex-wrap:wrap; margin-top:10px}
  .chip{background:rgba(255,255,255,.05); border:1px solid var(--border); padding:4px 8px; border-radius:999px; font-size:12px; color:var(--muted)}
  .logs{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New";
    font-size:12px;
    padding:12px;
    max-height:60vh;
    overflow:auto;
    white-space:pre-wrap;
  }
  .logline{margin:0 0 8px}
  .logts{color:#86efac}
  .logtag{color:#93c5fd}
  .logmsg{color:#eaeaff}
  .logmeta{color:var(--muted)}
</style>
</head>
<body>
<header>
  <div>
    <h1>OpenSCAD Render Service — Library Monitor</h1>
    <div class="sub">Live view of installed/enabled libraries + sync/render logs.</div>
  </div>
  <div class="topRight">
    <div class="pill" id="livePill">Live: connecting…</div>
    <button class="btn" onclick="logout()">Logout</button>
    <button class="btn primary" onclick="refreshState()">Refresh</button>
  </div>
</header>

<div class="wrap">
  <div class="searchRow">
    <input id="search" placeholder="Search libraries…" oninput="render()" />
    <div class="count" id="count">0 of 0 libraries</div>
  </div>

  <div class="grid">
    <div class="panel">
      <div class="panelHead">
        <div class="panelTitle">Libraries</div>
        <div class="count" id="libCountSmall">—</div>
      </div>
      <div class="list" id="libs"></div>
    </div>

    <div class="panel">
      <div class="panelHead">
        <div class="panelTitle">Live Logs <span class="count">(updates when server receives POSTs)</span></div>
      </div>
      <div class="logs" id="logs"></div>
    </div>
  </div>
</div>

<script>
  const token = new URLSearchParams(location.search).get("token");
  function logout(){
    // simplest: drop query token
    location.href = "/?token=";
  }
  function authedUrl(p){
    const u = new URL(p, location.origin);
    if (token) u.searchParams.set("token", token);
    return u.toString();
  }

  let state = { libraries: {} };
  let logs = [];

  function fmtDate(iso){
    if(!iso) return "—";
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
  }

  function render(){
    const q = (document.getElementById("search").value || "").toLowerCase().trim();
    const libsEl = document.getElementById("libs");
    libsEl.innerHTML = "";

    const all = Object.values(state.libraries || {});
    const filtered = all.filter(l => {
      const hay = (l.id + " " + (l.name||"") + " " + (l.description||"") + " " + (l.url||"") + " " + (l.usedUrl||"")).toLowerCase();
      return !q || hay.includes(q);
    });

    document.getElementById("count").textContent = filtered.length + " of " + all.length + " libraries";
    document.getElementById("libCountSmall").textContent = all.length + " total";

    if(!filtered.length){
      libsEl.innerHTML = '<div class="card" style="color:var(--muted)">No libraries found.</div>';
      return;
    }

    for(const l of filtered){
      const enabled = !!l.enabled;
      const ok = enabled && !l.lastError;
      const statusClass = ok ? "good" : "bad";
      const statusText = enabled ? (l.lastError ? "Error" : "Enabled") : "Disabled";

      const keywords = Array.isArray(l.keywords) ? l.keywords : [];
      const kwChips = keywords.slice(0, 8).map(k => '<span class="chip">'+k+'</span>').join("");

      const err = l.lastError ? ('<div class="url" style="color:var(--bad);margin-top:10px">Last error: '+escapeHtml(l.lastError)+'</div>') : "";

      const card = document.createElement("div");
      card.className = "card";
      card.innerHTML = \`
        <div class="row">
          <div class="id">\${escapeHtml(l.id)}</div>
          <div class="tag \${statusClass}">\${statusText}</div>
        </div>
        <div class="url">\${escapeHtml(l.usedUrl || l.url || "")}</div>
        <div class="meta">
          <span class="chip">Root: \${escapeHtml(l.rootFolder || "—")}</span>
          <span class="chip">SHA: \${escapeHtml((l.sha256||"").slice(0,10) || "—")}</span>
          <span class="chip">Last Sync: \${escapeHtml(fmtDate(l.updatedAt || l.installedAt))}</span>
        </div>
        \${kwChips ? ('<div class="meta" style="margin-top:8px">'+kwChips+'</div>') : ""}
        \${err}
      \`;
      libsEl.appendChild(card);
    }
  }

  function renderLogs(){
    const el = document.getElementById("logs");
    el.innerHTML = logs.map(l => {
      const meta = l.meta ? " " + escapeHtml(JSON.stringify(l.meta)) : "";
      return '<div class="logline"><span class="logts">'+escapeHtml(l.ts)+'</span> <span class="logtag">['+escapeHtml(l.tag)+']</span> <span class="logmsg">'+escapeHtml(l.message)+'</span><span class="logmeta">'+meta+'</span></div>';
    }).join("");
    el.scrollTop = el.scrollHeight;
  }

  function escapeHtml(s){
    return String(s||"").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;', "'":'&#39;'}[c]));
  }

  async function refreshState(){
    const r = await fetch(authedUrl("/libraries"));
    const j = await r.json();
    if(j && j.ok){
      state = { libraries: Object.fromEntries((j.libraries||[]).map(l => [l.id, l])) };
      render();
    }
  }

  // SSE
  const livePill = document.getElementById("livePill");
  const ev = new EventSource(authedUrl("/events"));
  ev.addEventListener("open", () => { livePill.textContent = "Live: connected"; });
  ev.addEventListener("error", () => { livePill.textContent = "Live: disconnected"; });

  ev.addEventListener("state", (e) => {
    try {
      const payload = JSON.parse(e.data);
      state = payload.db || state;
      render();
    } catch {}
  });

  ev.addEventListener("log", (e) => {
    try {
      const line = JSON.parse(e.data);
      logs.push(line);
      if (logs.length > 400) logs.shift();
      renderLogs();
    } catch {}
  });

  // initial pull
  refreshState().then(() => renderLogs());
</script>
</body>
</html>`);
});

/**
 * Startup
 */
(async () => {
  await ensureDirs();
  await loadDb();
  await rebuildEnabledSymlinks();

  pushLog("server.start", "Server started", {
    port: PORT,
    LIB_DIR,
    ENABLED_DIR,
    DB_PATH,
    OPENSCAD_BIN,
    MAX_CONCURRENT_RENDERS
  });

  app.listen(PORT, () => {
    console.log(`OpenSCAD render service running on :${PORT}`);
  });
})();
