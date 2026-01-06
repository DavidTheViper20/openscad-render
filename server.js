// server.js (drop-in, full file)
// - Renders OpenSCAD -> STL
// - Syncs OpenSCAD libraries from GitHub (repo URL / archive URL) or direct .zip/.tar.gz/.tgz
// - Dashboard UI: live logs (with colored explanations + filters), refresh, delete w/ confirm
// - Free Render compatible: stores libs + db in /tmp (wiped on restarts); optional autosync supported

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

// Free Render: /tmp is writable but ephemeral (wipes on restarts)
const LIB_ROOT = process.env.OPENSCAD_LIB_DIR || "/tmp/openscad-libs";
const STORE_DIR = path.join(LIB_ROOT, "_store");
const ENABLED_DIR = path.join(LIB_ROOT, "enabled");
const DB_PATH = path.join(LIB_ROOT, "libdb.json");

// Optional: auto-sync source (recommended so you never manually sync again)
const AUTOSYNC_URL = process.env.OPENSCAD_AUTOSYNC_URL || "";
const AUTOSYNC_TOKEN = process.env.OPENSCAD_AUTOSYNC_TOKEN || ""; // if your manifest endpoint needs auth
const AUTOSYNC_INTERVAL_MS = Number(process.env.OPENSCAD_AUTOSYNC_INTERVAL_MS || "300000"); // 5 min default

// Limits
const MAX_LOG_ITEMS = 900;
const MAX_LIB_DOWNLOAD_MB = Number(process.env.OPENSCAD_MAX_LIB_MB || "250");
const MAX_LIB_BYTES = MAX_LIB_DOWNLOAD_MB * 1024 * 1024;

// ------------------------
// Logging + SSE
// ------------------------
function nowIso() {
  return new Date().toISOString();
}

const logs = []; // structured log objects
const sseClients = new Set();

function classifyLevel(tag) {
  const t = String(tag || "");
  if (t.includes(".err") || t.includes("error")) return "error";
  if (t.includes(".warn") || t.includes("warn")) return "warn";
  return "info";
}

function explainFor(tag, msg, data) {
  const t = String(tag || "");
  const id = data?.id ? `“${data.id}”` : "";
  if (t === "server.start") return { level: "info", text: "Server booted. Ready to render & sync libraries." };
  if (t === "sync.start") return { level: "info", text: "Sync request received from your website/admin." };
  if (t === "sync.done") return { level: "info", text: "Sync request completed." };
  if (t === "apply.start") return { level: "info", text: "Apply request received (set enabled/disabled state)." };
  if (t === "apply.done") return { level: "info", text: "Apply request completed." };
  if (t === "library.download.start") return { level: "info", text: `Downloading library archive ${id}.` };
  if (t === "library.rootFolder.warn") return { level: "warn", text: `rootFolder not found for ${id}; using best fallback folder.` };
  if (t === "library.install.ok") return { level: "info", text: `Installed ${id}. Now available to renders.` };
  if (t === "library.install.err") return { level: "error", text: `Failed installing ${id}. It will not be available to renders.` };
  if (t === "library.delete.ok") return { level: "info", text: `Deleted ${id} from the render server.` };
  if (t === "library.delete.err") return { level: "error", text: `Failed deleting ${id}.` };
  if (t === "render.start") return { level: "info", text: "Render requested. OpenSCAD is generating an STL." };
  if (t === "render.ok") return { level: "info", text: "Render completed successfully." };
  if (t === "render.err") return { level: "error", text: "Render failed. Check the OpenSCAD error output." };
  if (t === "autosync.start") return { level: "info", text: "Auto-sync: fetching library manifest from your website." };
  if (t === "autosync.apply") return { level: "info", text: "Auto-sync: applying manifest to render server." };
  if (t === "autosync.ok") return { level: "info", text: "Auto-sync complete." };
  if (t === "autosync.err") return { level: "error", text: "Auto-sync failed (manifest fetch or apply error)." };
  if (t === "db.err") return { level: "warn", text: "Warning: could not write DB to disk. (Will still work until restart.)" };
  return null;
}

function pushLog(tag, msg, data) {
  const ts = nowIso();
  const level = classifyLevel(tag);
  const explain = explainFor(tag, msg, data);

  const entry = {
    ts,
    level,
    tag,
    msg,
    data: data ?? null,
    rawLine: `${ts} [${tag}] ${msg}` + (data ? ` ${JSON.stringify(data)}` : ""),
    explain: explain?.text ?? null,
    explainLevel: explain?.level ?? null,
  };

  logs.push(entry);
  while (logs.length > MAX_LOG_ITEMS) logs.shift();

  // Broadcast to SSE
  for (const res of sseClients) {
    try {
      res.write(`event: log\ndata: ${JSON.stringify(entry)}\n\n`);
    } catch {
      // ignore
    }
  }
}

function broadcastStatus() {
  const payload = { ts: nowIso() };
  for (const res of sseClients) {
    try {
      res.write(`event: status\ndata: ${JSON.stringify(payload)}\n\n`);
    } catch {
      // ignore
    }
  }
}

// ------------------------
// Auth helpers
// ------------------------
function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
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
  if (!TOKEN) return true; // open if no token set
  const t = reqToken(req);
  return !!t && t === TOKEN;
}

function requireAuth(req, res, next) {
  if (!authOk(req)) {
    return res
      .status(401)
      .send(`Unauthorized\n\nOpen "/?token=YOUR_TOKEN" once to login (saved in browser), or send Authorization: Bearer YOUR_TOKEN`);
  }
  next();
}

// ------------------------
// FS + DB helpers
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
    return entries.map((e) => ({ name: e.name, isDir: e.isDirectory(), isSym: e.isSymbolicLink() }));
  } catch {
    return [];
  }
}

async function readMagic(filePath, n = 4) {
  const fh = await fs.open(filePath, "r");
  try {
    const buf = Buffer.alloc(n);
    const { bytesRead } = await fh.read(buf, 0, n, 0);
    return buf.slice(0, bytesRead);
  } finally {
    await fh.close();
  }
}

function detectArchiveTypeFromMagic(buf) {
  // ZIP: PK..
  if (buf.length >= 2 && buf[0] === 0x50 && buf[1] === 0x4b) return "zip";
  // GZIP: 1F 8B
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) return "tgz";
  return "unknown";
}

function detectArchiveTypeFromUrl(url) {
  const u = String(url || "").toLowerCase();
  if (u.endsWith(".zip")) return "zip";
  if (u.endsWith(".tar.gz") || u.endsWith(".tgz")) return "tgz";
  return "unknown";
}

const cmdCache = new Map();
async function hasCmd(cmd) {
  if (cmdCache.has(cmd)) return cmdCache.get(cmd);
  try {
    await execFileAsync("sh", ["-lc", `command -v ${cmd} >/dev/null 2>&1`], { timeout: 5000 });
    cmdCache.set(cmd, true);
    return true;
  } catch {
    cmdCache.set(cmd, false);
    return false;
  }
}

// ------------------------
// Download helpers
// ------------------------
class ByteLimitTransform extends Transform {
  constructor(limitBytes) {
    super();
    this.limitBytes = limitBytes;
    this.total = 0;
  }
  _transform(chunk, _enc, cb) {
    this.total += chunk.length;
    if (this.total > this.limitBytes) {
      cb(new Error(`Download exceeded limit ${this.limitBytes} bytes`));
      return;
    }
    cb(null, chunk);
  }
}

async function downloadToFile(url, destPath) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`Download failed ${res.status} from ${url}`);

  const len = Number(res.headers.get("content-length") || "0");
  if (len && len > MAX_LIB_BYTES) {
    throw new Error(`Download too large (${len} bytes) > limit ${MAX_LIB_BYTES}`);
  }

  const contentType = res.headers.get("content-type") || "";
  await fs.mkdir(path.dirname(destPath), { recursive: true });

  const fileStream = fsSync.createWriteStream(destPath);
  const reader = res.body;
  if (!reader) throw new Error("No response body");

  const limiter = new ByteLimitTransform(MAX_LIB_BYTES);
  await pipeline(reader, limiter, fileStream);

  return { bytes: limiter.total, contentType };
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
// GitHub URL normalization
// ------------------------
function parseGithubOwnerRepo(url) {
  const m = String(url || "").trim().match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)(\/.*)?$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2].replace(/\.git$/, ""), rest: m[3] || "" };
}

function normalizeGithubUrlToCodeload(url, refHint) {
  // Accept:
  // - https://github.com/OWNER/REPO
  // - https://github.com/OWNER/REPO/archive/refs/heads/master.zip
  // - https://github.com/OWNER/REPO/archive/refs/tags/v1.2.3.zip
  // - https://github.com/OWNER/REPO/tree/master
  const p = parseGithubOwnerRepo(url);
  if (!p) return null;

  let ref = (refHint || "master").trim();
  let kind = "heads"; // "heads" or "tags"

  const rest = p.rest || "";
  const mHeads = rest.match(/\/archive\/refs\/heads\/([^/]+)\.(zip|tar\.gz|tgz)$/i);
  const mTags = rest.match(/\/archive\/refs\/tags\/([^/]+)\.(zip|tar\.gz|tgz)$/i);
  const mTree = rest.match(/\/tree\/([^/]+)\/?$/i);

  if (mHeads) {
    kind = "heads";
    ref = decodeURIComponent(mHeads[1]);
  } else if (mTags) {
    kind = "tags";
    ref = decodeURIComponent(mTags[1]);
  } else if (mTree) {
    kind = "heads";
    ref = decodeURIComponent(mTree[1]);
  }

  const encodedRef = encodeURIComponent(ref);
  const usedUrl = `https://codeload.github.com/${p.owner}/${p.repo}/tar.gz/refs/${kind}/${encodedRef}`;

  return { usedUrl, ref, kind };
}

// ------------------------
// Archive extraction (ZIP or TGZ)
// ------------------------
async function extractArchive(archivePath, destDir, archiveType) {
  // archiveType: "zip" | "tgz" | "unknown"
  await fs.mkdir(destDir, { recursive: true });

  if (archiveType === "zip") {
    // Prefer bsdtar if present, then unzip
    const haveBsdtar = await hasCmd("bsdtar");
    if (haveBsdtar) {
      await execFileAsync("bsdtar", ["-xf", archivePath, "-C", destDir], { timeout: 180000 });
      return;
    }
    const haveUnzip = await hasCmd("unzip");
    if (haveUnzip) {
      await execFileAsync("unzip", ["-q", archivePath, "-d", destDir], { timeout: 180000 });
      return;
    }
    throw new Error("ZIP archive received but neither 'bsdtar' nor 'unzip' is available on the server. Use a GitHub repo URL (recommended) or a .tar.gz URL.");
  }

  // Default: assume gzip tarball
  await execFileAsync("tar", ["-xzf", archivePath, "-C", destDir], { timeout: 180000 });
}

// ------------------------
// Library state + install
// ------------------------
let DB = { libraries: {} };

async function setEnabledSymlink(id, targetPath, enabled) {
  const linkPath = path.join(ENABLED_DIR, id);
  if (!enabled) {
    await safeRm(linkPath);
    return;
  }
  await safeSymlink(targetPath, linkPath);
}

async function computeRuntimeEnabledIds() {
  const entries = await listDirNames(ENABLED_DIR);
  // treat both symlinks and real dirs as enabled entries
  return entries.filter((e) => e.isDir || e.isSym).map((e) => e.name);
}

async function installOneLibrary(lib) {
  const id = String(lib.id || "").trim();
  if (!id) throw new Error("Missing library id");

  const enabled = lib.enabled !== false; // default true
  const refHint = String(lib.ref || "master").trim();
  const url = String(lib.url || "").trim();
  if (!url) throw new Error(`Library ${id}: missing url`);

  // Normalize GitHub URLs to codeload tar.gz (best), even if user pasted archive.zip
  let usedUrl = url;
  let ref = refHint;
  const ghNorm = normalizeGithubUrlToCodeload(url, refHint);
  if (ghNorm) {
    usedUrl = ghNorm.usedUrl;
    ref = ghNorm.ref;
  }

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${id}-`));
  const archivePath = path.join(tmpDir, "lib.archive");

  pushLog("library.download.start", `Downloading ${id}`, { id, usedUrl, ref });

  let downloaded;
  try {
    downloaded = await downloadToFile(usedUrl, archivePath);
  } catch (e) {
    // If original url was not github, and we failed, just throw
    throw e;
  }

  const sha = await sha256File(archivePath);
  const expectedSha = String(lib.sha256 || "").trim();
  if (expectedSha && expectedSha !== sha) {
    throw new Error(`Library ${id}: sha256 mismatch (expected ${expectedSha}, got ${sha})`);
  }

  // Detect archive type robustly (URL hint + magic bytes)
  const urlHintType = detectArchiveTypeFromUrl(usedUrl);
  const magic = await readMagic(archivePath, 4);
  const magicType = detectArchiveTypeFromMagic(magic);
  const archiveType = magicType !== "unknown" ? magicType : urlHintType;

  // Extract into STORE_DIR/<id> (replace existing)
  const storePath = path.join(STORE_DIR, id);
  await safeRm(storePath);
  await fs.mkdir(storePath, { recursive: true });

  try {
    await extractArchive(archivePath, storePath, archiveType);
  } catch (e) {
    // Helpful, explicit error
    throw new Error(
      `Extract failed (${archiveType}). ${String(e?.stderr || e?.message || e)}`
    );
  }

  // Determine extracted top folder
  const entries = await listDirNames(storePath);
  const dirs = entries.filter((e) => e.isDir).map((e) => e.name);
  const topFolder = dirs.length === 1 ? dirs[0] : null;

  // rootFolder handling
  const desiredRootFolder = String(lib.rootFolder ?? "").trim();
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
  } else if (topFolder) {
    finalTarget = path.join(storePath, topFolder);
  }

  await setEnabledSymlink(id, finalTarget, enabled);

  const prev = DB.libraries[id] || {};
  const rec = {
    id,
    url,
    usedUrl,
    ref,
    version: lib.version ?? prev.version ?? null,
    rootFolder: desiredRootFolder || topFolder || null,
    sha256: sha,
    enabled,
    name: lib.name ?? prev.name ?? null,
    description: lib.description ?? prev.description ?? null,
    keywords: lib.keywords ?? prev.keywords ?? null,
    targetPath: finalTarget,
    installedAt: prev.installedAt || nowIso(),
    updatedAt: nowIso(),
    lastError: null,
  };

  DB.libraries[id] = rec;

  pushLog("library.install.ok", `Installed ${id}`, {
    id,
    bytes: downloaded?.bytes,
    sha256: sha,
    enabled,
    linkedTo: finalTarget,
  });

  await saveDb(DB);
  broadcastStatus();
  return rec;
}

async function applyLibraries(payload, { disableMissing = false } = {}) {
  const libs = Array.isArray(payload?.libraries) ? payload.libraries : [];
  const results = [];
  const errors = [];
  const desiredIds = new Set();

  for (const l of libs) {
    const id = String(l?.id || "").trim();
    if (!id) {
      errors.push({ id: null, error: "Library missing id" });
      continue;
    }
    desiredIds.add(id);

    try {
      const rec = await installOneLibrary(l);
      // enable/disable based on payload
      const enabled = l.enabled !== false;
      rec.enabled = enabled;
      rec.updatedAt = nowIso();
      DB.libraries[id] = { ...DB.libraries[id], ...rec };

      // ensure symlink matches enabled flag
      await setEnabledSymlink(id, rec.targetPath || path.join(STORE_DIR, id), enabled);

      results.push(DB.libraries[id]);
    } catch (e) {
      const err = String(e?.message || e);
      errors.push({ id, error: err });

      DB.libraries[id] = {
        ...(DB.libraries[id] || {}),
        id,
        url: l?.url || null,
        usedUrl: l?.usedUrl || null,
        ref: l?.ref || null,
        enabled: false,
        updatedAt: nowIso(),
        lastError: err,
      };

      pushLog("library.install.err", `Install failed`, { id, error: err });
      await saveDb(DB);
      broadcastStatus();
    }
  }

  if (disableMissing) {
    for (const id of Object.keys(DB.libraries)) {
      if (!desiredIds.has(id)) {
        DB.libraries[id].enabled = false;
        DB.libraries[id].updatedAt = nowIso();
        await setEnabledSymlink(id, "", false);
      }
    }
    await saveDb(DB);
    broadcastStatus();
  }

  return { installed: results, errors };
}

async function deleteLibrary(id) {
  const libId = String(id || "").trim();
  if (!libId) throw new Error("Missing id");

  const enabledLink = path.join(ENABLED_DIR, libId);
  const storePath = path.join(STORE_DIR, libId);

  await safeRm(enabledLink);
  await safeRm(storePath);

  // remove from DB
  const existed = !!DB.libraries[libId];
  delete DB.libraries[libId];

  await saveDb(DB);
  pushLog("library.delete.ok", `Deleted ${libId}`, { id: libId, existed });
  broadcastStatus();
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
    if (!Array.isArray(libraries)) throw new Error("Manifest invalid: expected libraries[]");

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
    if (typeof code !== "string" || !code.trim()) return res.status(400).json({ error: "Missing code" });
    if ((format || "stl") !== "stl") return res.status(400).json({ error: "Only format=stl is supported" });

    pushLog("render.start", "Render requested", { bytes: Buffer.byteLength(code, "utf8") });

    const jobId = crypto.randomBytes(6).toString("hex");
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), `scad-${jobId}-`));
    const inFile = path.join(dir, "input.scad");
    const outFile = path.join(dir, "output.stl");
    await fs.writeFile(inFile, code, "utf8");

    const env = { ...process.env, OPENSCADPATH: ENABLED_DIR };

    try {
      await execFileAsync("openscad", ["-o", outFile, inFile], { timeout: 180000, env });
    } catch (e) {
      const details = String(e?.stderr || e?.stdout || e?.message || e);
      pushLog("render.err", "Render failed", { error: details.slice(0, 2000) });
      return res.status(500).json({ error: "OpenSCAD render failed", details });
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

// Apply = sets enabled exactly to payload (disableMissing=true by default)
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

app.post("/libraries/delete", requireAuth, async (req, res) => {
  const id = String(req.body?.id || "").trim();
  if (!id) return res.status(400).json({ ok: false, error: "Missing id" });

  try {
    await deleteLibrary(id);
    return res.json({ ok: true });
  } catch (e) {
    const err = String(e?.message || e);
    pushLog("library.delete.err", "Delete failed", { id, error: err });
    return res.status(500).json({ ok: false, error: err });
  }
});

// ------------------------
// Routes: Status + SSE stream
// ------------------------
app.get("/api/status", requireAuth, async (_req, res) => {
  // Merge DB with runtime enabled directory (in case of partial state)
  const enabledIds = new Set(await computeRuntimeEnabledIds());
  const libs = { ...(DB?.libraries || {}) };

  // Mark enabled based on runtime symlink presence if DB missing
  for (const id of enabledIds) {
    if (!libs[id]) libs[id] = { id, enabled: true, updatedAt: nowIso(), installedAt: null, lastError: null };
    if (libs[id]?.enabled === undefined) libs[id].enabled = true;
  }

  res.setHeader("Cache-Control", "no-store");
  return res.json({
    ok: true,
    db: { libraries: libs },
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
// Dashboard UI
// ------------------------
function dashboardHtml() {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>OpenSCAD Render — Monitor</title>
  <style>
    :root { color-scheme: dark; }
    body {
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system;
      background: radial-gradient(1200px 800px at 20% 10%, #1b1b4a 0%, #07071a 55%, #050515 100%);
      color:#eaeaf2;
    }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 18px; }
    .top { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    h1 { font-size: 20px; margin:0; letter-spacing:.2px; }
    .sub { margin-top:6px; color:#a8a8c7; font-size: 13px; line-height: 1.3; }
    .row { display:flex; gap:14px; margin-top:14px; }
    @media (max-width: 900px) { .row { flex-direction: column; } }
    .card {
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: 16px;
      padding: 12px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.35);
    }
    .left { flex: 1; min-height: 520px; }
    .right { width: 440px; }
    @media (max-width: 900px) { .right { width: auto; } }

    .pill { display:inline-flex; align-items:center; gap:8px; padding: 6px 10px; border-radius: 999px; font-size: 12px;
      background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.10); }
    .toolbar { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    .btn { cursor:pointer; padding: 8px 12px; border-radius: 10px; border:1px solid rgba(255,255,255,0.14); background: rgba(255,255,255,0.08); color:#fff; }
    .btn.primary { background: linear-gradient(135deg,#7c3aed,#a855f7); border: none; }
    .btn.danger { background: rgba(239,68,68,.15); border:1px solid rgba(239,68,68,.35); }
    .btn:disabled { opacity:.5; cursor:not-allowed; }

    input[type="text"], input[type="password"], select {
      width:100%; padding: 10px 12px; border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.14);
      background: rgba(0,0,0,0.25); color:#fff; outline:none;
      box-sizing: border-box;
    }

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
    .hr { height:1px; background: rgba(255,255,255,0.10); margin: 10px 0; }

    /* Explanation colors */
    .explain { font-size: 12px; margin-top: 4px; }
    .explain.info { color: #86efac; }   /* green */
    .explain.warn { color: #fde68a; }   /* yellow */
    .explain.error { color: #fca5a5; }  /* red */
    .rawline { color: #eaeaf2; }

    /* Mobile-friendly login modal */
    .login { position: fixed; inset: 0; display:none; align-items:center; justify-content:center; background: rgba(0,0,0,0.55); padding: 14px; }
    .login .panel { width: min(460px, 100%); max-height: 90vh; overflow:auto; }
    .login .row { display:flex; gap:10px; margin-top: 12px; flex-wrap:wrap; }
    .login .row .btn { flex: 1; min-width: 140px; }
    .tiny { font-size: 11px; color:#a8a8c7; line-height:1.35; }
    a { color:#c4b5fd; text-decoration:none; }
    .iconbtn { cursor:pointer; border:none; background:transparent; color:#fff; padding: 6px 8px; border-radius: 10px; }
    .iconbtn:hover { background: rgba(255,255,255,0.08); }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>OpenSCAD Render Service — Monitor</h1>
        <div class="sub">
          Live view of installed/enabled libraries + sync/render logs.<br/>
          <span class="tiny">Free Render note: /tmp resets on restarts → libraries must be re-synced (auto-sync recommended).</span>
        </div>
      </div>
      <div class="toolbar">
        <span class="pill" id="live">Live: connecting…</span>
        <button class="btn" id="logout">Logout</button>
        <button class="btn primary" id="refresh">Refresh</button>
      </div>
    </div>

    <div class="row">
      <div class="card left">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
          <div style="flex:1; min-width: 220px;">
            <input id="search" type="text" placeholder="Search libraries…"/>
          </div>
          <div class="muted" id="count">0 libraries</div>
        </div>
        <div class="grid" id="libs"></div>
      </div>

      <div class="card right">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
          <div style="font-weight:700;">Logs</div>
          <div style="display:flex; gap:10px; align-items:center;">
            <select id="logMode" style="width: 200px;">
              <option value="both">Raw + Explanation</option>
              <option value="raw">Raw only</option>
              <option value="explain">Explanation only</option>
            </select>
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
      <div class="muted" style="margin-top:6px;">Stored in your browser. You won’t be asked again.</div>
      <div style="margin-top:12px;">
        <input id="tokenInput" type="password" placeholder="Paste OPENSCAD_RENDER_TOKEN"/>
      </div>
      <div class="row">
        <button class="btn primary" id="saveToken">Save</button>
        <button class="btn" id="cancelToken">Cancel</button>
      </div>
      <div class="tiny" style="margin-top:10px;">Tip: you can also open <span class="mono">/?token=YOUR_TOKEN</span> once.</div>
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
  const logModeEl = document.getElementById('logMode');

  let statusCache = null;
  let es = null;

  function scrollToBottomIfNeeded(el, atBottom) {
    if (atBottom) el.scrollTop = el.scrollHeight;
  }

  function renderLogEntry(entry) {
    const mode = logModeEl.value;
    const wrapper = document.createElement('div');
    wrapper.style.marginBottom = '10px';

    if (mode === 'raw' || mode === 'both') {
      const raw = document.createElement('div');
      raw.className = 'rawline';
      raw.textContent = entry.rawLine || '';
      wrapper.appendChild(raw);
    }
    if ((mode === 'explain' || mode === 'both') && entry.explain) {
      const ex = document.createElement('div');
      ex.className = 'explain ' + (entry.explainLevel || 'info');
      ex.textContent = entry.explain;
      wrapper.appendChild(ex);
    }

    return wrapper;
  }

  function setLogs(allLogs) {
    const atBottom = (logbox.scrollTop + logbox.clientHeight) >= (logbox.scrollHeight - 12);
    logbox.innerHTML = '';
    (allLogs || []).forEach((e) => logbox.appendChild(renderLogEntry(e)));
    scrollToBottomIfNeeded(logbox, atBottom);
  }

  function appendLog(entry) {
    const atBottom = (logbox.scrollTop + logbox.clientHeight) >= (logbox.scrollHeight - 12);
    logbox.appendChild(renderLogEntry(entry));
    while (logbox.childNodes.length > 900) logbox.removeChild(logbox.firstChild);
    scrollToBottomIfNeeded(logbox, atBottom);
  }

  function renderLibraries() {
    const q = (searchEl.value || '').toLowerCase();
    const libsObj = (statusCache?.db?.libraries) || {};
    const list = Object.values(libsObj)
      .filter(x => !q || (x.id || '').toLowerCase().includes(q) || (x.url||'').toLowerCase().includes(q) || (x.usedUrl||'').toLowerCase().includes(q));

    countEl.textContent = list.length + ' of ' + Object.keys(libsObj).length + ' libraries';
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

      const used = (lib.usedUrl || lib.url || '');
      const updated = lib.updatedAt ? new Date(lib.updatedAt).toLocaleString() : '—';

      box.innerHTML = \`
        <div class="libTop">
          <div class="libId">\${lib.id || '(no id)'}</div>
          <div style="display:flex;align-items:center;gap:8px;">
            <span class="tag \${lib.enabled ? 'on' : 'off'}">\${lib.enabled ? 'Enabled' : 'Disabled'}</span>
            <button class="iconbtn" title="Delete from render server" data-del="\${lib.id}">🗑️</button>
          </div>
        </div>
        <div class="muted" style="margin-top:6px;word-break:break-all;">\${used}</div>
        <div class="muted" style="margin-top:6px;">Last Update: \${updated}</div>
        \${lib.lastError ? '<div class="muted" style="margin-top:6px;color:#fca5a5;">Error: ' + lib.lastError + '</div>' : ''}
      \`;

      libsEl.appendChild(box);
    }

    // wire delete buttons
    libsEl.querySelectorAll('[data-del]').forEach(btn => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-del');
        if (!id) return;
        const ok = confirm('Delete "' + id + '" from the render server?\\n\\nThis removes it from the render UI and deletes its files in /tmp.');
        if (!ok) return;
        try {
          await deleteLibrary(id);
          await boot();
        } catch (e) {
          alert('Delete failed: ' + (e.message || String(e)));
        }
      };
    });
  }

  searchEl.addEventListener('input', () => renderLibraries());
  logModeEl.addEventListener('change', () => setLogs(statusCache?.logs || []));

  async function fetchStatus() {
    const t = getToken();
    const r = await fetch('/api/status', { headers: t ? { 'Authorization': 'Bearer ' + t } : {} });
    if (r.status === 401) throw new Error('unauthorized');
    return await r.json();
  }

  async function deleteLibrary(id) {
    const t = getToken();
    const r = await fetch('/libraries/delete', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(t ? { 'Authorization': 'Bearer ' + t } : {})
      },
      body: JSON.stringify({ id })
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
    return j;
  }

  function connectSSE() {
    const t = getToken();
    if (!t) return;

    try {
      if (es) { try { es.close(); } catch {} }
      es = new EventSource('/api/stream?token=' + encodeURIComponent(t));
      liveEl.textContent = 'Live: connecting…';

      es.addEventListener('hello', () => {
        liveEl.textContent = 'Live: connected';
      });

      es.addEventListener('log', (ev) => {
        try {
          const entry = JSON.parse(ev.data);
          appendLog(entry);
        } catch {}
      });

      // When libraries change, server sends status -> refresh lists automatically
      es.addEventListener('status', () => {
        // quick refresh without clearing logs
        refreshStatusNoClear();
      });

      es.onerror = () => {
        liveEl.textContent = 'Live: disconnected';
      };
    } catch {
      liveEl.textContent = 'Live: disconnected';
    }
  }

  async function refreshStatusNoClear() {
    try {
      const next = await fetchStatus();
      statusCache = next;
      renderLibraries();
      // Don't blow away logbox; we already append live logs.
    } catch {}
  }

  async function boot() {
    const t = getToken();
    const tokenRequired = ${TOKEN ? "true" : "false"};
    if (!t && tokenRequired) { showLogin(); return; }
    hideLogin();

    try {
      statusCache = await fetchStatus();
      setLogs(statusCache.logs || []);
      renderLibraries();
      connectSSE();
      liveEl.textContent = 'Live: connected';
    } catch (e) {
      if (String(e.message).includes('unauthorized')) showLogin();
      else alert('UI error: ' + (e.message || String(e)));
    }
  }

  boot();
</script>
</body>
</html>`;
}

// Always serve UI (even if unauth); UI will ask for token once.
app.get("/", async (req, res) => {
  // If they provided ?token= and it matches, set a cookie too
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
