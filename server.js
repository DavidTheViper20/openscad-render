import express from "express";
import fs from "fs/promises";
import fsSync from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import { pipeline } from "stream/promises";
import { Transform, Readable } from "stream";

const execFileAsync = promisify(execFile);
const app = express();

// ------------------------
// Config
// ------------------------
app.set("trust proxy", 1);
app.use(express.json({ limit: "10mb" }));

const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || "";

// IMPORTANT for free Render: use /tmp (writable) and expect it to wipe on restarts
const LIB_ROOT = process.env.OPENSCAD_LIB_DIR || "/tmp/openscad-libs";
const STORE_DIR = path.join(LIB_ROOT, "_store");
const ENABLED_DIR = path.join(LIB_ROOT, "enabled");
const DB_PATH = path.join(LIB_ROOT, "libdb.json");

// Optional: auto-sync source (recommended so you never manually sync again)
const AUTOSYNC_URL = process.env.OPENSCAD_AUTOSYNC_URL || "";
const AUTOSYNC_TOKEN = process.env.OPENSCAD_AUTOSYNC_TOKEN || ""; // if your manifest endpoint needs auth
const AUTOSYNC_INTERVAL_MS = Number(process.env.OPENSCAD_AUTOSYNC_INTERVAL_MS || "300000"); // 5 min default

// Limits
const MAX_LOG_LINES = 600;
const MAX_LIB_DOWNLOAD_MB = Number(process.env.OPENSCAD_MAX_LIB_MB || "200"); // safety
const MAX_LIB_BYTES = MAX_LIB_DOWNLOAD_MB * 1024 * 1024;

// ------------------------
// Small helpers
// ------------------------
function nowIso() {
  return new Date().toISOString();
}

const logs = [];
const sseClients = new Set();

function pushLog(tag, msg, data) {
  const line =
    `${nowIso()} [${tag}] ${msg}` + (data ? ` ${JSON.stringify(data)}` : "");
  logs.push(line);
  while (logs.length > MAX_LOG_LINES) logs.shift();

  // Broadcast to SSE
  for (const res of sseClients) {
    try {
      res.write(`event: log\ndata: ${JSON.stringify({ line })}\n\n`);
    } catch {
      // ignore
    }
  }
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  const parts = cookieHeader.split(";");
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function reqToken(req) {
  // 1) Authorization header
  const h = req.headers.authorization || "";
  if (h.startsWith("Bearer ")) return h.slice("Bearer ".length).trim();

  // 2) Query token (needed for EventSource)
  if (typeof req.query.token === "string" && req.query.token.trim())
    return req.query.token.trim();

  // 3) Cookie
  const cookies = parseCookies(req.headers.cookie || "");
  if (cookies.auth_token) return cookies.auth_token;

  return "";
}

function authOk(req) {
  if (!TOKEN) return true; // if you haven't set a token, everything is open
  const t = reqToken(req);
  return !!t && t === TOKEN;
}

function requireAuth(req, res, next) {
  if (!authOk(req)) {
    return res.status(401).send(
      `Unauthorized\n\nOpen "/?token=YOUR_TOKEN" once to login (saved in browser), or send Authorization: Bearer YOUR_TOKEN`
    );
  }
  next();
}

async function ensureDirs() {
  await fs.mkdir(LIB_ROOT, { recursive: true });
  await fs.mkdir(STORE_DIR, { recursive: true });
  await fs.mkdir(ENABLED_DIR, { recursive: true });
}

async function loadDb() {
  try {
    const raw = await fs.readFile(DB_PATH, "utf8");
    const db = JSON.parse(raw);
    if (!db || typeof db !== "object") return { libraries: {} };
    if (!db.libraries || typeof db.libraries !== "object") db.libraries = {};
    return db;
  } catch {
    return { libraries: {} };
  }
}

async function saveDb(db) {
  try {
    await fs.writeFile(DB_PATH, JSON.stringify(db, null, 2), "utf8");
  } catch (e) {
    pushLog("db.err", "Failed to write DB (continuing)", {
      error: String(e?.message || e),
    });
  }
}

let DB = { libraries: {} };

// ------------------------
// GitHub URL normalization
// ------------------------
function looksLikeGithubRepo(url) {
  return /^https:\/\/github\.com\/[^/]+\/[^/]+\/?$/.test(url.trim());
}

function githubCodeload(url, ref) {
  const m = url.trim().match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/?$/);
  if (!m) return null;
  const owner = m[1];
  const repo = m[2];
  const safeRef = (ref || "master").trim();
  return {
    heads: `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${encodeURIComponent(
      safeRef
    )}`,
    tags: `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/tags/${encodeURIComponent(
      safeRef
    )}`,
  };
}

// ✅ NEW: Convert GitHub "archive zip" links to codeload tarballs (so tar -xzf works)
function githubZipToCodeloadTar(url) {
  // https://github.com/OWNER/REPO/archive/refs/heads/REF.zip
  // https://github.com/OWNER/REPO/archive/refs/tags/V1.2.3.zip
  const m = url
    .trim()
    .match(
      /^https:\/\/github\.com\/([^/]+)\/([^/]+)\/archive\/refs\/(heads|tags)\/([^/]+)\.zip$/
    );
  if (!m) return null;
  const owner = m[1];
  const repo = m[2];
  const kind = m[3];
  const ref = m[4];
  return `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/${kind}/${encodeURIComponent(
    ref
  )}`;
}

async function downloadToFile(url, destPath) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`Download failed ${res.status} from ${url}`);

  const len = Number(res.headers.get("content-length") || "0");
  if (len && len > MAX_LIB_BYTES) {
    throw new Error(
      `Download too large (${len} bytes) > limit ${MAX_LIB_BYTES}`
    );
  }

  await fs.mkdir(path.dirname(destPath), { recursive: true });
  const fileStream = fsSync.createWriteStream(destPath);

  let total = 0;

  if (!res.body) throw new Error("No response body");

  // Convert WHATWG stream -> Node stream (more reliable on Render)
  const nodeReadable = Readable.fromWeb(res.body);

  const limiter = new Transform({
    transform(chunk, _enc, cb) {
      total += chunk.length;
      if (total > MAX_LIB_BYTES) {
        cb(new Error(`Download exceeded limit ${MAX_LIB_BYTES} bytes`));
        return;
      }
      cb(null, chunk);
    },
  });

  await pipeline(nodeReadable, limiter, fileStream);

  return { bytes: total };
}

async function sha256File(filePath) {
  const h = crypto.createHash("sha256");
  const s = fsSync.createReadStream(filePath);
  await new Promise((resolve, reject) => {
    s.on("data", (d) => h.update(d));
    s.on("end", resolve);
    s.on("error", reject);
  });
  return h.digest("hex");
}

async function listDirNames(p) {
  try {
    const entries = await fs.readdir(p, { withFileTypes: true });
    return entries.map((e) => ({ name: e.name, isDir: e.isDirectory() }));
  } catch {
    return [];
  }
}

async function safeRm(p) {
  try {
    await fs.rm(p, { recursive: true, force: true });
  } catch {
    // ignore
  }
}

async function safeSymlink(target, linkPath) {
  await safeRm(linkPath);
  await fs.symlink(target, linkPath, "dir");
}

// ------------------------
// Library install logic
// ------------------------
async function installOneLibrary(lib) {
  const id = String(lib.id || "").trim();
  if (!id) throw new Error("Missing library id");

  const ref = String(lib.ref || "master").trim();
  const url = String(lib.url || "").trim();
  if (!url) throw new Error(`Library ${id}: missing url`);

  // Determine which URL we actually download
  let usedUrl = url;

  // ✅ If it’s a GitHub archive zip URL, convert it
  const zipTar = githubZipToCodeloadTar(url);
  if (zipTar) {
    usedUrl = zipTar;
  } else if (looksLikeGithubRepo(url)) {
    // ✅ If it's a GitHub repo URL, convert to codeload tarball
    const u = githubCodeload(url, ref);
    usedUrl = u.heads; // prefer heads first
  } else {
    // If someone put a non-GitHub ZIP, we can't extract with tar.
    if (usedUrl.endsWith(".zip")) {
      throw new Error(
        `Library ${id}: .zip URLs are not supported unless it's a GitHub archive URL. Use https://github.com/OWNER/REPO or a .tar.gz URL.`
      );
    }
  }

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${id}-`));
  const tgzPath = path.join(tmpDir, "lib.tar.gz");

  pushLog("library.download.start", `Downloading ${id}`, { usedUrl, ref });

  let downloaded;
  try {
    downloaded = await downloadToFile(usedUrl, tgzPath);
  } catch (e) {
    // If GitHub repo heads failed, try tags as fallback
    if (looksLikeGithubRepo(url)) {
      const u = githubCodeload(url, ref);
      usedUrl = u.tags;
      downloaded = await downloadToFile(usedUrl, tgzPath);
    } else {
      throw e;
    }
  }

  const sha = await sha256File(tgzPath);
  if (lib.sha256 && String(lib.sha256).trim() && String(lib.sha256).trim() !== sha) {
    throw new Error(
      `Library ${id}: sha256 mismatch (expected ${lib.sha256}, got ${sha})`
    );
  }

  // Extract into STORE_DIR/<id> (replace existing)
  const storePath = path.join(STORE_DIR, id);
  await safeRm(storePath);
  await fs.mkdir(storePath, { recursive: true });

  // extract tar.gz
  await execFileAsync("tar", ["-xzf", tgzPath, "-C", storePath], {
    timeout: 180000,
  });

  // Determine extracted "top folder"
  const entries = await listDirNames(storePath);
  const dirs = entries.filter((e) => e.isDir).map((e) => e.name);
  const topFolder = dirs.length === 1 ? dirs[0] : null;

  const desiredRootFolder = (lib.rootFolder ?? "").toString().trim();
  let finalTarget = storePath;

  if (desiredRootFolder) {
    const candidate = path.join(storePath, desiredRootFolder);
    if (fsSync.existsSync(candidate) && fsSync.statSync(candidate).isDirectory()) {
      finalTarget = candidate;
    } else {
      pushLog("library.rootFolder.warn", `rootFolder not found for ${id}, falling back`, {
        desiredRootFolder,
        topFolder,
      });
      if (topFolder) finalTarget = path.join(storePath, topFolder);
    }
  } else {
    if (topFolder) finalTarget = path.join(storePath, topFolder);
  }

  // enable/disable
  const enabled = lib.enabled !== false;

  const enabledLink = path.join(ENABLED_DIR, id);
  if (enabled) {
    await safeSymlink(finalTarget, enabledLink);
  } else {
    await safeRm(enabledLink);
  }

  // store a nicer “actualRootFolder”
  const rel = path.relative(storePath, finalTarget);
  const actualRootFolder = rel && rel !== "" && !rel.startsWith("..") ? rel : null;

  const rec = {
    id,
    url,
    usedUrl,
    ref,
    version: lib.version ?? null,
    rootFolder: desiredRootFolder || actualRootFolder || topFolder || null,
    sha256: sha,
    enabled,
    name: lib.name ?? null,
    description: lib.description ?? null,
    keywords: lib.keywords ?? null,
    installedAt: nowIso(),
    updatedAt: nowIso(),
    lastError: null,
  };

  DB.libraries[id] = { ...(DB.libraries[id] || {}), ...rec };

  pushLog("library.install.ok", `Installed ${id}`, {
    bytes: downloaded?.bytes,
    sha256: sha,
    enabled,
    linkedTo: enabled ? finalTarget : "(disabled)",
  });

  await saveDb(DB);
  return rec;
}

async function applyLibraries(payload, { disableMissing = false } = {}) {
  const libs = Array.isArray(payload?.libraries) ? payload.libraries : [];
  const results = [];
  const errors = [];
  const desiredIds = new Set();

  for (const l of libs) {
    try {
      const id = String(l.id || "").trim();
      if (!id) throw new Error("Library missing id");
      desiredIds.add(id);

      const rec = await installOneLibrary(l);
      results.push(rec);
    } catch (e) {
      const err = String(e?.message || e);
      errors.push({ id: l?.id || null, error: err });

      if (l?.id) {
        const lid = String(l.id);
        DB.libraries[lid] = {
          ...(DB.libraries[lid] || {}),
          id: lid,
          url: l?.url || null,
          ref: l?.ref || null,
          enabled: false,
          updatedAt: nowIso(),
          lastError: err,
        };
      }
      pushLog("library.install.err", `Install failed`, { id: l?.id || null, error: err });
    }
  }

  if (disableMissing) {
    for (const id of Object.keys(DB.libraries)) {
      if (!desiredIds.has(id)) {
        DB.libraries[id].enabled = false;
        DB.libraries[id].updatedAt = nowIso();
        // remove link so OpenSCADPATH doesn't see it
        await safeRm(path.join(ENABLED_DIR, id));
      }
    }
  }

  await saveDb(DB);
  return { installed: results, errors };
}

// ------------------------
// Auto-sync (no disk -> recover after restarts automatically)
// ------------------------
async function autoSyncOnce() {
  if (!AUTOSYNC_URL) return;

  try {
    pushLog("autosync.start", "Fetching manifest", { url: AUTOSYNC_URL });
    const res = await fetch(AUTOSYNC_URL, {
      headers: AUTOSYNC_TOKEN ? { Authorization: `Bearer ${AUTOSYNC_TOKEN}` } : {},
    });
    if (!res.ok) throw new Error(`Manifest fetch failed ${res.status}`);
    const manifest = await res.json();

    const libraries = Array.isArray(manifest) ? manifest : manifest?.libraries;
    if (!Array.isArray(libraries)) throw new Error(`Manifest invalid: expected libraries[]`);

    pushLog("autosync.apply", "Applying manifest", { count: libraries.length });
    await applyLibraries({ libraries }, { disableMissing: true });
    pushLog("autosync.ok", "Auto-sync complete", { count: libraries.length });
  } catch (e) {
    pushLog("autosync.err", "Auto-sync failed", { error: String(e?.message || e) });
  }
}

// ------------------------
// Routes: Health + Render
// ------------------------
app.get("/health", (_req, res) => res.status(200).send("ok"));

app.post("/render", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ error: "Unauthorized" });

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

    // Set OPENSCADPATH to enabled libs so `use <LIB/...>` resolves.
    const env = {
      ...process.env,
      OPENSCADPATH: ENABLED_DIR,
    };

    try {
      await execFileAsync("openscad", ["-o", outFile, inFile], {
        timeout: 180000,
        env,
      });
    } catch (e) {
      const stdout = e?.stdout || "";
      const stderr = e?.stderr || e?.message || "";
      pushLog("render.err", "Render failed", {
        error: String(stderr || stdout || e?.message || e),
      });
      return res.status(500).json({
        error: "OpenSCAD render failed",
        details: String(stderr || stdout || e?.message || e),
      });
    }

    const stl = await fs.readFile(outFile);
    pushLog("render.ok", "Render completed", { bytes: stl.length });

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(stl);
  } catch (e) {
    pushLog("render.err", "Render crashed", { error: String(e?.message || e) });
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

// ------------------------
// Routes: Library Sync API
// ------------------------
app.post("/libraries/sync", requireAuth, async (req, res) => {
  pushLog("sync.start", "Library sync request", {
    librariesCount: Array.isArray(req.body?.libraries) ? req.body.libraries.length : 0,
  });

  const { installed, errors } = await applyLibraries(req.body, { disableMissing: false });

  pushLog("sync.done", "Library sync finished", {
    ok: errors.length === 0,
    installed: installed.length,
    errors: errors.length,
  });

  return res.json({ ok: errors.length === 0, installed, errors, db: DB });
});

// Apply = sets enabled exactly to payload (disableMissing=true is the default)
app.post("/libraries/apply", requireAuth, async (req, res) => {
  const disableMissing = req.body?.disableMissing !== false;

  pushLog("apply.start", "Library apply request", {
    librariesCount: Array.isArray(req.body?.libraries) ? req.body.libraries.length : 0,
    disableMissing,
  });

  const { installed, errors } = await applyLibraries(req.body, { disableMissing });

  pushLog("apply.done", "Library apply finished", {
    ok: errors.length === 0,
    installed: installed.length,
    errors: errors.length,
  });

  return res.json({ ok: errors.length === 0, installed, errors, db: DB });
});

app.get("/api/status", requireAuth, async (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.json({
    ok: true,
    db: DB,
    logs,
    env: {
      port: Number(process.env.PORT || 3000),
      LIB_ROOT,
      ENABLED_DIR,
      DB_PATH,
      AUTOSYNC_URL: AUTOSYNC_URL ? "(set)" : "",
    },
  });
});

// SSE stream (EventSource can't send headers -> accept ?token=)
app.get("/api/stream", async (req, res) => {
  if (!authOk(req)) return res.status(401).send("Unauthorized");

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  res.write(`event: hello\ndata: ${JSON.stringify({ ok: true })}\n\n`);
  sseClients.add(res);

  req.on("close", () => sseClients.delete(res));
});

// ------------------------
// Dashboard (token remembered)
// ------------------------
function dashboardHtml() {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>OpenSCAD Render Service — Library Monitor</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system; background: radial-gradient(1200px 800px at 20% 10%, #1b1b4a 0%, #07071a 55%, #050515 100%); color:#eaeaf2; }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 22px; }
    .top { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    h1 { font-size: 22px; margin:0; letter-spacing:.2px; }
    .sub { margin-top:6px; color:#a8a8c7; font-size: 13px; }
    .row { display:flex; gap:16px; margin-top:18px; }
    @media (max-width: 900px) { .row { flex-direction: column; } }
    .card { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.10); border-radius: 16px; padding: 14px; box-shadow: 0 10px 40px rgba(0,0,0,0.35); }
    .left { flex: 1; min-height: 520px; }
    .right { width: 440px; }
    @media (max-width: 900px) { .right { width: auto; } }
    .pill { display:inline-flex; align-items:center; gap:8px; padding: 6px 10px; border-radius: 999px; font-size: 12px; background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.10); }
    .btn { cursor:pointer; padding: 8px 12px; border-radius: 10px; border:1px solid rgba(255,255,255,0.14); background: rgba(255,255,255,0.08); color:#fff; }
    .btn.primary { background: linear-gradient(135deg,#7c3aed,#a855f7); border: none; }
    .btn:disabled { opacity:.5; cursor:not-allowed; }
    .toolbar { display:flex; align-items:center; gap:10px; }
    input[type="text"], input[type="password"] { width:100%; padding: 10px 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.14); background: rgba(0,0,0,0.25); color:#fff; outline:none; }
    .grid { display:grid; grid-template-columns: 1fr; gap: 12px; margin-top: 12px; }
    .lib { padding: 12px; border-radius: 14px; background: rgba(0,0,0,0.18); border: 1px solid rgba(255,255,255,0.10); }
    .libTop { display:flex; align-items:center; justify-content:space-between; gap:10px; }
    .libId { font-weight: 700; letter-spacing:.3px; }
    .tag { font-size: 11px; padding: 4px 8px; border-radius: 999px; }
    .tag.on { background: rgba(34,197,94,.18); border:1px solid rgba(34,197,94,.35); color:#9ef7c0; }
    .tag.off { background: rgba(148,163,184,.14); border:1px solid rgba(148,163,184,.30); color:#cbd5e1; }
    .muted { color:#b7b7d6; font-size: 12px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }
    .logbox { height: 520px; overflow:auto; background: rgba(0,0,0,0.28); border:1px solid rgba(255,255,255,0.12); border-radius: 14px; padding: 10px; }
    .login { position: fixed; inset: 0; display:none; align-items:center; justify-content:center; background: rgba(0,0,0,0.55); }
    .login .panel { width: 420px; max-width: calc(100% - 28px); }
    .hr { height:1px; background: rgba(255,255,255,0.10); margin: 10px 0; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>OpenSCAD Render Service — Library Monitor</h1>
        <div class="sub">Live view of installed/enabled libraries + sync/render logs. (Free Render: libs re-download after restarts)</div>
      </div>
      <div class="toolbar">
        <span class="pill" id="live">Live: connecting…</span>
        <button class="btn" id="logout">Logout</button>
        <button class="btn primary" id="refresh">Refresh</button>
      </div>
    </div>

    <div class="row">
      <div class="card left">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">
          <input id="search" type="text" placeholder="Search libraries…"/>
          <div class="muted" id="count">0 libraries</div>
        </div>
        <div class="grid" id="libs"></div>
      </div>

      <div class="card right">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <div style="font-weight:700;">Live Logs <span class="muted">(updates on POSTs)</span></div>
        </div>
        <div class="hr"></div>
        <div class="logbox mono" id="logbox"></div>
      </div>
    </div>
  </div>

  <div class="login" id="login">
    <div class="card panel">
      <div style="font-weight:800;font-size:18px;">Enter Render Token</div>
      <div class="muted" style="margin-top:6px;">Stored in your browser (localStorage). You won’t be asked again.</div>
      <div style="margin-top:12px;">
        <input id="tokenInput" type="password" placeholder="Paste OPENSCAD_RENDER_TOKEN"/>
      </div>
      <div style="display:flex;gap:10px;margin-top:12px;">
        <button class="btn primary" id="saveToken">Save</button>
        <button class="btn" id="cancelToken">Cancel</button>
      </div>
      <div class="muted" style="margin-top:10px;">Tip: open <span class="mono">/?token=YOUR_TOKEN</span> once.</div>
    </div>
  </div>

<script>
  const qs = new URLSearchParams(location.search);
  const urlToken = qs.get('token');
  if (urlToken) {
    localStorage.setItem('render_token', urlToken);
    qs.delete('token');
    const clean = location.pathname + (qs.toString() ? '?' + qs.toString() : '');
    history.replaceState({}, '', clean);
  }

  const loginEl = document.getElementById('login');
  const tokenInput = document.getElementById('tokenInput');
  const saveTokenBtn = document.getElementById('saveToken');
  const cancelTokenBtn = document.getElementById('cancelToken');

  function getToken() { return localStorage.getItem('render_token') || ''; }
  function showLogin() { loginEl.style.display = 'flex'; tokenInput.value = ''; tokenInput.focus(); }
  function hideLogin() { loginEl.style.display = 'none'; }

  saveTokenBtn.onclick = () => {
    const t = tokenInput.value.trim();
    if (!t) return;
    localStorage.setItem('render_token', t);
    hideLogin();
    boot();
  };
  cancelTokenBtn.onclick = () => hideLogin();

  document.getElementById('logout').onclick = () => {
    localStorage.removeItem('render_token');
    location.reload();
  };

  document.getElementById('refresh').onclick = () => boot();

  const logbox = document.getElementById('logbox');
  const libsEl = document.getElementById('libs');
  const countEl = document.getElementById('count');
  const liveEl = document.getElementById('live');
  const searchEl = document.getElementById('search');

  let statusCache = null;

  function appendLog(line) {
    const atBottom = (logbox.scrollTop + logbox.clientHeight) >= (logbox.scrollHeight - 12);
    const div = document.createElement('div');
    div.textContent = line;
    logbox.appendChild(div);
    while (logbox.childNodes.length > 600) logbox.removeChild(logbox.firstChild);
    if (atBottom) logbox.scrollTop = logbox.scrollHeight;
  }

  function renderLibraries() {
    const q = (searchEl.value || '').toLowerCase();
    const libs = (statusCache?.db?.libraries) || {};
    const list = Object.values(libs)
      .filter(x => !q || (x.id || '').toLowerCase().includes(q) || (x.url||'').toLowerCase().includes(q));

    countEl.textContent = list.length + ' of ' + Object.keys(libs).length + ' libraries';
    libsEl.innerHTML = '';

    if (!list.length) {
      const empty = document.createElement('div');
      empty.className = 'muted';
      empty.textContent = 'No libraries found.';
      libsEl.appendChild(empty);
      return;
    }

    for (const lib of list.sort((a,b) => (a.id||'').localeCompare(b.id||''))) {
      const box = document.createElement('div');
      box.className = 'lib';
      box.innerHTML = \`
        <div class="libTop">
          <div class="libId">\${lib.id || '(no id)'}</div>
          <span class="tag \${lib.enabled ? 'on' : 'off'}">\${lib.enabled ? 'Enabled' : 'Disabled'}</span>
        </div>
        <div class="muted" style="margin-top:6px;word-break:break-all;">\${lib.usedUrl || lib.url || ''}</div>
        <div class="muted" style="margin-top:6px;">Last Sync: \${lib.updatedAt ? new Date(lib.updatedAt).toLocaleString() : '—'}</div>
        \${lib.lastError ? '<div class="muted" style="margin-top:6px;color:#fca5a5;">Error: ' + lib.lastError + '</div>' : ''}
      \`;
      libsEl.appendChild(box);
    }
  }

  searchEl.addEventListener('input', () => renderLibraries());

  async function fetchStatus() {
    const t = getToken();
    const r = await fetch('/api/status', {
      headers: t ? { 'Authorization': 'Bearer ' + t } : {}
    });
    if (r.status === 401) throw new Error('unauthorized');
    return await r.json();
  }

  function connectSSE() {
    const t = getToken();
    if (!t) return;

    const es = new EventSource('/api/stream?token=' + encodeURIComponent(t));
    liveEl.textContent = 'Live: connecting…';

    es.addEventListener('hello', () => {
      liveEl.textContent = 'Live: connected';
    });

    es.addEventListener('log', (ev) => {
      try {
        const data = JSON.parse(ev.data);
        appendLog(data.line);
      } catch {}
    });

    es.onerror = () => {
      liveEl.textContent = 'Live: disconnected';
    };
  }

  async function boot() {
    const t = getToken();
    if (!t && ${TOKEN ? "true" : "false"}) { showLogin(); return; }
    hideLogin();

    try {
      statusCache = await fetchStatus();
      logbox.innerHTML = '';
      (statusCache.logs || []).forEach(appendLog);
      renderLibraries();
      connectSSE();
      liveEl.textContent = 'Live: connected';
    } catch (e) {
      if (String(e.message).includes('unauthorized')) {
        showLogin();
      } else {
        appendLog(new Date().toISOString() + ' [ui.err] ' + (e.message || String(e)));
      }
    }
  }

  boot();
</script>
</body>
</html>`;
}

app.get("/", async (req, res) => {
  // If they provided ?token= and it matches, set a cookie too (nice-to-have)
  if (TOKEN && typeof req.query.token === "string" && req.query.token === TOKEN) {
    res.setHeader(
      "Set-Cookie",
      `auth_token=${encodeURIComponent(TOKEN)}; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=Lax; Secure`
    );
  }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).send(dashboardHtml());
});

// ------------------------
// Boot
// ------------------------
async function main() {
  await ensureDirs();
  DB = await loadDb();

  pushLog("server.start", "Server started", {
    port: Number(process.env.PORT || 3000),
    LIB_ROOT,
    ENABLED_DIR,
    DB_PATH,
  });

  // Auto-sync on boot (critical for free instances)
  await autoSyncOnce();

  // Periodic auto-sync while awake
  if (AUTOSYNC_URL) {
    setInterval(() => autoSyncOnce().catch(() => {}), AUTOSYNC_INTERVAL_MS).unref?.();
  }

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`OpenSCAD render service running on :${port}`);
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
