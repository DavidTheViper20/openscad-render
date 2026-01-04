// server.js (ESM)
// OpenSCAD Render Service + Library Sync + Live Dashboard
// Adds: per-library delete button (with confirm), mobile-friendly token modal,
// color-coded “explanation” under each log, and log view filters (raw / both / explain)

import express from "express";
import fs from "fs/promises";
import fsSync from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import { pipeline } from "stream/promises";
import { Transform } from "stream";

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
const AUTOSYNC_TOKEN = process.env.OPENSCAD_AUTOSYNC_TOKEN || "";
const AUTOSYNC_INTERVAL_MS = Number(process.env.OPENSCAD_AUTOSYNC_INTERVAL_MS || "300000");

// Limits
const MAX_LOG_LINES = 800;
const MAX_LIB_DOWNLOAD_MB = Number(process.env.OPENSCAD_MAX_LIB_MB || "200");
const MAX_LIB_BYTES = MAX_LIB_DOWNLOAD_MB * 1024 * 1024;

// ------------------------
// Helpers: time, auth, SSE, logs
// ------------------------
function nowIso() {
  return new Date().toISOString();
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
  if (typeof req.query.token === "string" && req.query.token.trim()) return req.query.token.trim();

  // 3) Cookie
  const cookies = parseCookies(req.headers.cookie || "");
  if (cookies.auth_token) return cookies.auth_token;

  return "";
}

function authOk(req) {
  if (!TOKEN) return true;
  const t = reqToken(req);
  return !!t && t === TOKEN;
}

function requireAuth(req, res, next) {
  if (!authOk(req)) {
    return res
      .status(401)
      .send(
        `Unauthorized\n\nOpen "/?token=YOUR_TOKEN" once to login (saved in browser), or send Authorization: Bearer YOUR_TOKEN`
      );
  }
  next();
}

// SSE
const sseClients = new Set();

function sseBroadcast(event, payload) {
  const data = JSON.stringify(payload);
  for (const res of sseClients) {
    try {
      res.write(`event: ${event}\ndata: ${data}\n\n`);
    } catch {
      // ignore
    }
  }
}

// Logs (structured)
const logEntries = [];

function explainLog(tag, msg, data) {
  // Level by tag pattern
  let level = "info";
  if (tag.includes(".err") || tag === "render.err") level = "error";
  else if (tag.includes(".warn")) level = "warn";

  // Tiny explanation mapping
  const map = {
    "server.start": "Server booted. Ready to render & sync libraries.",
    "render.start": "Starting an OpenSCAD render job.",
    "render.ok": "Render finished. Returning STL bytes.",
    "render.err": "Render failed. OpenSCAD returned an error.",
    "sync.start": "Sync request received from your website/admin.",
    "sync.done": "Sync request completed.",
    "apply.start": "Applying full library set (optionally disabling missing).",
    "apply.done": "Apply completed.",
    "autosync.start": "Auto-sync: fetching your manifest.",
    "autosync.apply": "Auto-sync: installing/updating libraries from manifest.",
    "autosync.ok": "Auto-sync finished successfully.",
    "autosync.err": "Auto-sync failed (manifest fetch or install error).",
    "db.err": "Couldn’t persist DB file; continuing with in-memory state.",
    "library.download.start": "Downloading library archive.",
    "library.install.ok": "Library extracted and linked. Usable via use <LIB/...>.",
    "library.install.err": "Library install failed; it will be marked disabled.",
    "library.rootFolder.warn": "Requested rootFolder missing; using fallback folder.",
    "library.delete.start": "Deleting library from server (store + enabled link + DB).",
    "library.delete.ok": "Library deleted.",
    "library.delete.err": "Delete failed (see details).",
  };

  let explain = map[tag] || "Update received.";
  // Add small dynamic hint for some events
  if (tag === "library.install.ok" && data?.id) explain = `Installed “${data.id}”. Now available to renders.`;
  if (tag === "library.install.err" && data?.id) explain = `Failed installing “${data.id}”. It will not be available to renders.`;
  if (tag === "library.delete.ok" && data?.id) explain = `Deleted “${data.id}” from the server.`;

  return { level, explain };
}

function pushLog(tag, msg, data) {
  const { level, explain } = explainLog(tag, msg, data);
  const entry = {
    ts: nowIso(),
    tag,
    msg,
    data: data ?? null,
    level,   // info | warn | error
    explain, // tiny human explanation
  };
  entry.line = `${entry.ts} [${tag}] ${msg}` + (data ? ` ${JSON.stringify(data)}` : "");

  logEntries.push(entry);
  while (logEntries.length > MAX_LOG_LINES) logEntries.shift();

  sseBroadcast("log", entry);
}

function broadcastLibraries(DB) {
  sseBroadcast("libraries", { libraries: DB.libraries, at: nowIso() });
}

// ------------------------
// FS/DB helpers
// ------------------------
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
    pushLog("db.err", "Failed to write DB (continuing)", { error: String(e?.message || e) });
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

async function listDirNames(p) {
  try {
    const entries = await fs.readdir(p, { withFileTypes: true });
    return entries.map((e) => ({ name: e.name, isDir: e.isDirectory() }));
  } catch {
    return [];
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
    heads: `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${encodeURIComponent(safeRef)}`,
    tags: `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/tags/${encodeURIComponent(safeRef)}`,
  };
}

// ------------------------
// Download helpers
// ------------------------
async function downloadToFile(url, destPath) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`Download failed ${res.status} from ${url}`);

  const len = Number(res.headers.get("content-length") || "0");
  if (len && len > MAX_LIB_BYTES) {
    throw new Error(`Download too large (${len} bytes) > limit ${MAX_LIB_BYTES}`);
  }

  await fs.mkdir(path.dirname(destPath), { recursive: true });
  const fileStream = fsSync.createWriteStream(destPath);

  let total = 0;
  const reader = res.body;
  if (!reader) throw new Error("No response body");

  await pipeline(
    reader,
    new Transform({
      transform(chunk, _enc, cb) {
        total += chunk.length;
        if (total > MAX_LIB_BYTES) {
          cb(new Error(`Download exceeded limit ${MAX_LIB_BYTES} bytes`));
          return;
        }
        cb(null, chunk);
      },
    }),
    fileStream
  );

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

// ------------------------
// Enable/disable handling
// ------------------------
async function setLibraryEnabled(id, finalTarget, enabled) {
  const linkPath = path.join(ENABLED_DIR, id);
  if (enabled) {
    await safeSymlink(finalTarget, linkPath);
  } else {
    await safeRm(linkPath);
  }
}

// ------------------------
// Library install logic
// ------------------------
async function installOneLibrary(lib) {
  const id = String(lib.id || "").trim();
  if (!id) throw new Error("Missing library id");

  const ref = String(lib.ref || "master").trim();
  const wantEnabled = lib.enabled !== false;

  let url = String(lib.url || "").trim();
  if (!url) throw new Error(`Library ${id}: missing url`);

  let usedUrl = url;
  if (looksLikeGithubRepo(url)) {
    const u = githubCodeload(url, ref);
    usedUrl = u.heads;
  }

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${id}-`));
  const tgzPath = path.join(tmpDir, "lib.tar.gz");

  pushLog("library.download.start", `Downloading ${id}`, { id, usedUrl, ref });

  let downloaded;
  try {
    downloaded = await downloadToFile(usedUrl, tgzPath);
  } catch (e) {
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
    throw new Error(`Library ${id}: sha256 mismatch (expected ${lib.sha256}, got ${sha})`);
  }

  const storePath = path.join(STORE_DIR, id);
  await safeRm(storePath);
  await fs.mkdir(storePath, { recursive: true });

  await execFileAsync("tar", ["-xzf", tgzPath, "-C", storePath], { timeout: 180000 });

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
        id,
        desiredRootFolder,
        topFolder,
      });
      if (topFolder) finalTarget = path.join(storePath, topFolder);
    }
  } else {
    if (topFolder) finalTarget = path.join(storePath, topFolder);
  }

  await setLibraryEnabled(id, finalTarget, wantEnabled);

  const rec = {
    id,
    url,
    usedUrl,
    ref,
    version: lib.version ?? null,
    rootFolder: desiredRootFolder || topFolder || null,
    sha256: sha,
    enabled: wantEnabled,
    name: lib.name ?? null,
    description: lib.description ?? null,
    keywords: lib.keywords ?? null,
    installedAt: nowIso(),
    updatedAt: nowIso(),
    lastError: null,
  };

  DB.libraries[id] = { ...(DB.libraries[id] || {}), ...rec };

  pushLog("library.install.ok", `Installed ${id}`, {
    id,
    bytes: downloaded?.bytes,
    sha256: sha,
    enabled: wantEnabled,
    linkedTo: wantEnabled ? finalTarget : "(disabled)",
  });

  await saveDb(DB);
  broadcastLibraries(DB);

  return rec;
}

async function applyLibraries(payload, { disableMissing = false } = {}) {
  const libs = Array.isArray(payload?.libraries) ? payload.libraries : [];
  const results = [];
  const errors = [];
  const desiredIds = new Set();

  for (const l of libs) {
    const id = String(l?.id || "").trim();
    if (id) desiredIds.add(id);

    try {
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
          usedUrl: DB.libraries[lid]?.usedUrl || null,
          ref: l?.ref || null,
          enabled: false,
          updatedAt: nowIso(),
          lastError: err,
        };
        await safeRm(path.join(ENABLED_DIR, lid));
      }

      pushLog("library.install.err", `Install failed`, { id: l?.id || null, error: err });
      await saveDb(DB);
      broadcastLibraries(DB);
    }
  }

  if (disableMissing) {
    for (const id of Object.keys(DB.libraries)) {
      if (!desiredIds.has(id)) {
        DB.libraries[id].enabled = false;
        DB.libraries[id].updatedAt = nowIso();
        await safeRm(path.join(ENABLED_DIR, id));
      }
    }
    await saveDb(DB);
    broadcastLibraries(DB);
  }

  return { installed: results, errors };
}

async function deleteLibrary(id) {
  const libId = String(id || "").trim();
  if (!libId) throw new Error("Missing id");
  pushLog("library.delete.start", `Deleting ${libId}`, { id: libId });

  // remove enabled link + store content + DB record
  await safeRm(path.join(ENABLED_DIR, libId));
  await safeRm(path.join(STORE_DIR, libId));
  delete DB.libraries[libId];

  await saveDb(DB);
  pushLog("library.delete.ok", `Deleted ${libId}`, { id: libId });
  broadcastLibraries(DB);
}

// ------------------------
// Auto-sync
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

    const env = { ...process.env, OPENSCADPATH: ENABLED_DIR };

    try {
      await execFileAsync("openscad", ["-o", outFile, inFile], {
        timeout: 180000,
        env,
      });
    } catch (e) {
      const stderr = e?.stderr || e?.message || "";
      pushLog("render.err", "Render failed", { error: String(stderr) });
      return res.status(500).json({
        error: "OpenSCAD render failed",
        details: String(stderr),
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

  broadcastLibraries(DB);
  return res.json({ ok: errors.length === 0, installed, errors, db: DB });
});

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

  broadcastLibraries(DB);
  return res.json({ ok: errors.length === 0, installed, errors, db: DB });
});

// NEW: delete library fully from render (store + enabled symlink + DB)
app.post("/libraries/delete", requireAuth, async (req, res) => {
  try {
    const id = String(req.body?.id || "").trim();
    if (!id) return res.status(400).json({ ok: false, error: "Missing id" });

    if (!DB.libraries[id]) {
      // If not present, still ensure folders are gone (idempotent)
      await safeRm(path.join(ENABLED_DIR, id));
      await safeRm(path.join(STORE_DIR, id));
      return res.json({ ok: true, deleted: id, existed: false, db: DB });
    }

    await deleteLibrary(id);
    return res.json({ ok: true, deleted: id, existed: true, db: DB });
  } catch (e) {
    pushLog("library.delete.err", "Delete failed", { error: String(e?.message || e) });
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Status (structured logs + db)
app.get("/api/status", requireAuth, async (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.json({
    ok: true,
    db: DB,
    logs: logEntries, // structured
    env: {
      port: Number(process.env.PORT || 3000),
      LIB_ROOT,
      ENABLED_DIR,
      DB_PATH,
      AUTOSYNC_URL: AUTOSYNC_URL ? "(set)" : "",
    },
  });
});

// Libraries-only endpoint (for your Admin “Refresh Status”)
app.get("/api/libraries", requireAuth, async (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.json({ ok: true, libraries: DB.libraries });
});

// SSE stream (EventSource can't send headers -> accept ?token=)
app.get("/api/stream", async (req, res) => {
  if (!authOk(req)) return res.status(401).send("Unauthorized");

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  res.write(`event: hello\ndata: ${JSON.stringify({ ok: true, at: nowIso() })}\n\n`);
  res.write(
    `event: libraries\ndata: ${JSON.stringify({ libraries: DB.libraries, at: nowIso() })}\n\n`
  );

  sseClients.add(res);
  req.on("close", () => sseClients.delete(res));
});

// ------------------------
// Dashboard UI
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
    body {
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system;
      background: radial-gradient(1200px 800px at 20% 10%, #1b1b4a 0%, #07071a 55%, #050515 100%);
      color:#eaeaf2;
    }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 22px; }
    .top { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    h1 { font-size: 22px; margin:0; letter-spacing:.2px; }
    .sub { margin-top:6px; color:#a8a8c7; font-size: 13px; }
    .row { display:flex; gap:16px; margin-top:18px; }
    @media (max-width: 900px) { .row { flex-direction: column; } }
    .card {
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: 16px;
      padding: 14px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.35);
    }
    .left { flex: 1; min-height: 520px; }
    .right { width: 440px; }
    @media (max-width: 900px) { .right { width: auto; } }
    .pill {
      display:inline-flex; align-items:center; gap:8px;
      padding: 6px 10px; border-radius: 999px; font-size: 12px;
      background: rgba(255,255,255,0.07);
      border: 1px solid rgba(255,255,255,0.10);
      white-space: nowrap;
    }
    .btn {
      cursor:pointer;
      padding: 8px 12px; border-radius: 10px;
      border:1px solid rgba(255,255,255,0.14);
      background: rgba(255,255,255,0.08);
      color:#fff;
      white-space: nowrap;
    }
    .btn.primary { background: linear-gradient(135deg,#7c3aed,#a855f7); border: none; }
    .btn:disabled { opacity:.5; cursor:not-allowed; }
    .toolbar { display:flex; align-items:center; gap:10px; flex-wrap: wrap; }
    input[type="text"], input[type="password"] {
      width:100%;
      box-sizing: border-box;
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.14);
      background: rgba(0,0,0,0.25);
      color:#fff;
      outline:none;
    }
    .grid { display:grid; grid-template-columns: 1fr; gap: 12px; margin-top: 12px; }
    .lib {
      padding: 12px; border-radius: 14px;
      background: rgba(0,0,0,0.18);
      border: 1px solid rgba(255,255,255,0.10);
    }
    .libTop { display:flex; align-items:center; justify-content:space-between; gap:10px; }
    .libId { font-weight: 700; letter-spacing:.3px; }
    .tag { font-size: 11px; padding: 4px 8px; border-radius: 999px; }
    .tag.on { background: rgba(34,197,94,.18); border:1px solid rgba(34,197,94,.35); color:#9ef7c0; }
    .tag.off { background: rgba(148,163,184,.14); border:1px solid rgba(148,163,184,.30); color:#cbd5e1; }
    .muted { color:#b7b7d6; font-size: 12px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }
    .logbox {
      height: 520px; overflow:auto;
      background: rgba(0,0,0,0.28);
      border:1px solid rgba(255,255,255,0.12);
      border-radius: 14px;
      padding: 10px;
    }
    .logRow { padding: 8px 8px; border-bottom: 1px solid rgba(255,255,255,0.08); }
    .logLine { white-space: pre-wrap; word-break: break-word; }
    .logExplain { margin-top: 4px; font-size: 11px; }
    .logExplain.info { color: #86efac; }   /* green */
    .logExplain.warn { color: #fde047; }   /* yellow */
    .logExplain.error { color: #fca5a5; }  /* red */
    .hr { height:1px; background: rgba(255,255,255,0.10); margin: 10px 0; }

    /* Mobile-friendly token modal */
    .login {
      position: fixed; inset: 0;
      display:none; align-items:center; justify-content:center;
      background: rgba(0,0,0,0.55);
      padding: 14px;
      box-sizing: border-box;
    }
    .login .panel {
      width: min(420px, calc(100vw - 28px));
      max-width: 100%;
    }
    .login .panel .rowBtns { display:flex; gap:10px; margin-top: 12px; flex-wrap: wrap; }
    .login .panel .rowBtns .btn { flex: 1 1 140px; }

    .iconBtn {
      display:inline-flex; align-items:center; justify-content:center;
      width: 34px; height: 34px;
      border-radius: 10px;
      border:1px solid rgba(255,255,255,0.14);
      background: rgba(255,255,255,0.08);
      cursor:pointer;
    }
    .iconBtn.danger:hover { border-color: rgba(239,68,68,0.55); }
    .iconBtn svg { width: 16px; height: 16px; opacity: .95; }
    .filters { display:flex; gap:8px; flex-wrap: wrap; }
    .chip {
      cursor:pointer;
      padding: 6px 10px;
      border-radius: 999px;
      border:1px solid rgba(255,255,255,0.14);
      background: rgba(255,255,255,0.08);
      font-size: 12px;
      user-select: none;
    }
    .chip.active { background: rgba(124,58,237,0.35); border-color: rgba(124,58,237,0.55); }
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
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px; flex-wrap: wrap;">
          <div style="flex: 1 1 260px;">
            <input id="search" type="text" placeholder="Search libraries…"/>
          </div>
          <div class="muted" id="count">0 libraries</div>
        </div>
        <div class="grid" id="libs"></div>
      </div>

      <div class="card right">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px; flex-wrap: wrap;">
          <div style="font-weight:700;">Live Logs <span class="muted">(updates on POSTs)</span></div>
          <div class="filters">
            <div class="chip active" data-mode="both" id="modeBoth">Both</div>
            <div class="chip" data-mode="raw" id="modeRaw">Raw</div>
            <div class="chip" data-mode="explain" id="modeExplain">Explain</div>
          </div>
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
      <div class="rowBtns">
        <button class="btn primary" id="saveToken">Save</button>
        <button class="btn" id="cancelToken">Cancel</button>
      </div>
      <div class="muted" style="margin-top:10px;">Tip: you can also open <span class="mono">/?token=YOUR_TOKEN</span> once.</div>
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

  // Log view mode
  let logMode = 'both';
  const modeBoth = document.getElementById('modeBoth');
  const modeRaw = document.getElementById('modeRaw');
  const modeExplain = document.getElementById('modeExplain');
  function setMode(m) {
    logMode = m;
    modeBoth.classList.toggle('active', m === 'both');
    modeRaw.classList.toggle('active', m === 'raw');
    modeExplain.classList.toggle('active', m === 'explain');
    // re-render from cache
    renderLogsFromCache();
  }
  modeBoth.onclick = () => setMode('both');
  modeRaw.onclick = () => setMode('raw');
  modeExplain.onclick = () => setMode('explain');

  const logbox = document.getElementById('logbox');
  const libsEl = document.getElementById('libs');
  const countEl = document.getElementById('count');
  const liveEl = document.getElementById('live');
  const searchEl = document.getElementById('search');

  let statusCache = { db: { libraries: {} }, logs: [] };
  let es = null;

  function trashIconSvg() {
    return \`
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
           stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M3 6h18"></path>
        <path d="M8 6V4h8v2"></path>
        <path d="M19 6l-1 14H6L5 6"></path>
        <path d="M10 11v6"></path>
        <path d="M14 11v6"></path>
      </svg>\`;
  }

  function renderLibraries() {
    const q = (searchEl.value || '').toLowerCase();
    const libs = (statusCache?.db?.libraries) || {};
    const all = Object.values(libs);
    const list = all.filter(x =>
      !q ||
      (x.id || '').toLowerCase().includes(q) ||
      (x.url || '').toLowerCase().includes(q) ||
      (x.usedUrl || '').toLowerCase().includes(q)
    );

    countEl.textContent = list.length + ' of ' + all.length + ' libraries';
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

      const top = document.createElement('div');
      top.className = 'libTop';

      const left = document.createElement('div');
      left.style.display = 'flex';
      left.style.alignItems = 'center';
      left.style.gap = '10px';

      const idEl = document.createElement('div');
      idEl.className = 'libId';
      idEl.textContent = lib.id || '(no id)';

      const tag = document.createElement('span');
      tag.className = 'tag ' + (lib.enabled ? 'on' : 'off');
      tag.textContent = lib.enabled ? 'Enabled' : 'Disabled';

      left.appendChild(idEl);
      left.appendChild(tag);

      const right = document.createElement('div');
      right.style.display = 'flex';
      right.style.alignItems = 'center';
      right.style.gap = '8px';

      // Delete button (always available)
      const delBtn = document.createElement('button');
      delBtn.className = 'iconBtn danger';
      delBtn.title = 'Delete library from server';
      delBtn.innerHTML = trashIconSvg();
      delBtn.onclick = async (ev) => {
        ev.preventDefault();
        ev.stopPropagation();

        const ok = confirm(\`Delete "\${lib.id}" from render server?\\n\\nThis removes it from the server UI + storage.\`);
        if (!ok) return;

        try {
          delBtn.disabled = true;
          await deleteLibraryFromServer(lib.id);
        } finally {
          delBtn.disabled = false;
        }
      };

      right.appendChild(delBtn);

      top.appendChild(left);
      top.appendChild(right);

      const urlEl = document.createElement('div');
      urlEl.className = 'muted';
      urlEl.style.marginTop = '6px';
      urlEl.style.wordBreak = 'break-all';
      urlEl.textContent = lib.usedUrl || lib.url || '';

      const timeEl = document.createElement('div');
      timeEl.className = 'muted';
      timeEl.style.marginTop = '6px';
      timeEl.textContent = 'Last Sync: ' + (lib.updatedAt ? new Date(lib.updatedAt).toLocaleString() : '—');

      box.appendChild(top);
      box.appendChild(urlEl);
      box.appendChild(timeEl);

      if (lib.lastError) {
        const errEl = document.createElement('div');
        errEl.className = 'muted';
        errEl.style.marginTop = '6px';
        errEl.style.color = '#fca5a5';
        errEl.textContent = 'Error: ' + lib.lastError;
        box.appendChild(errEl);
      }

      libsEl.appendChild(box);
    }
  }

  searchEl.addEventListener('input', () => renderLibraries());

  function clearLogbox() {
    logbox.innerHTML = '';
  }

  function renderOneLog(entry) {
    const row = document.createElement('div');
    row.className = 'logRow';

    // raw line
    if (logMode === 'raw' || logMode === 'both') {
      const line = document.createElement('div');
      line.className = 'logLine';
      line.textContent = entry.line || '';
      row.appendChild(line);
    }

    // explanation
    if (logMode === 'explain' || logMode === 'both') {
      const ex = document.createElement('div');
      ex.className = 'logExplain ' + (entry.level || 'info');
      ex.textContent = entry.explain || '';
      row.appendChild(ex);
    }

    return row;
  }

  function appendLog(entry) {
    const atBottom = (logbox.scrollTop + logbox.clientHeight) >= (logbox.scrollHeight - 12);
    logbox.appendChild(renderOneLog(entry));
    while (logbox.childNodes.length > 800) logbox.removeChild(logbox.firstChild);
    if (atBottom) logbox.scrollTop = logbox.scrollHeight;
  }

  function renderLogsFromCache() {
    clearLogbox();
    for (const e of (statusCache.logs || [])) appendLog(e);
  }

  async function fetchStatus() {
    const t = getToken();
    const r = await fetch('/api/status', {
      headers: t ? { 'Authorization': 'Bearer ' + t } : {}
    });
    if (r.status === 401) throw new Error('unauthorized');
    return await r.json();
  }

  async function deleteLibraryFromServer(id) {
    const t = getToken();
    const r = await fetch('/libraries/delete', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(t ? { 'Authorization': 'Bearer ' + t } : {})
      },
      body: JSON.stringify({ id })
    });

    if (r.status === 401) throw new Error('unauthorized');
    const data = await r.json();
    if (!data.ok) throw new Error(data.error || 'Delete failed');

    // If SSE is connected, it will also update, but do a quick local update too:
    statusCache.db = data.db || statusCache.db;
    renderLibraries();
  }

  function connectSSE() {
    const t = getToken();
    if (!t) return;

    try { if (es) es.close(); } catch {}
    es = new EventSource('/api/stream?token=' + encodeURIComponent(t));
    liveEl.textContent = 'Live: connecting…';

    es.addEventListener('hello', () => {
      liveEl.textContent = 'Live: connected';
    });

    es.addEventListener('log', (ev) => {
      try {
        const entry = JSON.parse(ev.data);
        // keep a small cache
        statusCache.logs = statusCache.logs || [];
        statusCache.logs.push(entry);
        while (statusCache.logs.length > 800) statusCache.logs.shift();
        appendLog(entry);
      } catch {}
    });

    es.addEventListener('libraries', (ev) => {
      try {
        const data = JSON.parse(ev.data);
        statusCache.db.libraries = data.libraries || {};
        renderLibraries();
      } catch {}
    });

    es.onerror = () => {
      liveEl.textContent = 'Live: disconnected';
    };
  }

  async function boot() {
    const t = getToken();
    const tokenRequired = ${TOKEN ? "true" : "false"};
    if (!t && tokenRequired) { showLogin(); return; }
    hideLogin();

    try {
      const s = await fetchStatus();
      statusCache = s || statusCache;

      renderLogsFromCache();
      renderLibraries();

      connectSSE();
      liveEl.textContent = 'Live: connected';
    } catch (e) {
      if (String(e.message).includes('unauthorized')) {
        showLogin();
      } else {
        // synthesize a UI error entry
        const entry = {
          ts: new Date().toISOString(),
          tag: 'ui.err',
          msg: e.message || String(e),
          data: null,
          level: 'error',
          explain: 'Dashboard error while loading status.',
          line: new Date().toISOString() + ' [ui.err] ' + (e.message || String(e)),
        };
        statusCache.logs = statusCache.logs || [];
        statusCache.logs.push(entry);
        renderLogsFromCache();
      }
    }
  }

  boot();
</script>
</body>
</html>`;
}

// Always serve UI; it will ask for token once (stored in browser)
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
