import express from "express";
import fs from "fs/promises";
import fssync from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import { pipeline } from "stream/promises";

const execFileAsync = promisify(execFile);
const app = express();

app.use(express.json({ limit: "25mb" }));

// -------------------- CONFIG --------------------
const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || "";
const LIB_DIR = process.env.OPENSCAD_LIB_DIR || "/opt/openscad-libs";
const INSTALL_DB = path.join(LIB_DIR, ".installed.json");
const DOWNLOAD_TIMEOUT_MS = Number(process.env.OPENSCAD_LIB_DOWNLOAD_TIMEOUT_MS || 120000);
const OPENSCAD_TIMEOUT_MS = Number(process.env.OPENSCAD_TIMEOUT_MS || 120000);

// If you want to restrict where downloads can come from:
const ALLOWED_LIB_HOSTS = (process.env.OPENSCAD_ALLOWED_LIB_HOSTS || "github.com,codeload.github.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// -------------------- AUTH --------------------
function authOk(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  return h === `Bearer ${TOKEN}`;
}
function requireAuth(req, res) {
  if (!authOk(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

// -------------------- UTIL --------------------
async function ensureDir(p) {
  await fs.mkdir(p, { recursive: true });
}

async function fileExists(p) {
  try {
    await fs.stat(p);
    return true;
  } catch {
    return false;
  }
}

function sha256Buffer(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  await new Promise((resolve, reject) => {
    const s = fssync.createReadStream(filePath);
    s.on("data", (d) => hash.update(d));
    s.on("end", resolve);
    s.on("error", reject);
  });
  return hash.digest("hex");
}

function isProbablyGitHubRepoUrl(u) {
  try {
    const url = new URL(u);
    return url.hostname === "github.com" && url.pathname.split("/").filter(Boolean).length >= 2;
  } catch {
    return false;
  }
}

function toGitHubTarballCandidates(repoUrl, ref) {
  // Accept:
  //  - https://github.com/org/repo
  //  - https://github.com/org/repo/tree/<ref>
  // Build candidates that usually work:
  //  - https://codeload.github.com/org/repo/tar.gz/<ref>
  //  - https://github.com/org/repo/archive/refs/heads/<ref>.tar.gz
  // We’ll try main/master if ref not provided.
  const u = new URL(repoUrl);
  const parts = u.pathname.split("/").filter(Boolean);
  const org = parts[0];
  const repo = parts[1];

  let refGuess = ref;
  // If URL includes /tree/<ref>
  const treeIdx = parts.indexOf("tree");
  if (!refGuess && treeIdx !== -1 && parts[treeIdx + 1]) refGuess = parts[treeIdx + 1];

  const refsToTry = refGuess ? [refGuess] : ["main", "master", "HEAD"];

  const candidates = [];
  for (const r of refsToTry) {
    candidates.push(`https://codeload.github.com/${org}/${repo}/tar.gz/${r}`);
    if (r !== "HEAD") {
      candidates.push(`https://github.com/${org}/${repo}/archive/refs/heads/${r}.tar.gz`);
      candidates.push(`https://github.com/${org}/${repo}/archive/refs/tags/${r}.tar.gz`);
    }
  }
  return candidates;
}

function assertAllowedHost(downloadUrl) {
  const u = new URL(downloadUrl);
  if (!ALLOWED_LIB_HOSTS.includes(u.hostname)) {
    throw new Error(
      `Library host not allowed: ${u.hostname}. Set OPENSCAD_ALLOWED_LIB_HOSTS to include it.`
    );
  }
}

// Download to file (streaming)
async function downloadToFile(url, outFile) {
  assertAllowedHost(url);

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), DOWNLOAD_TIMEOUT_MS);

  try {
    const resp = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "OpenSCAD-Render-LibSync/1.0",
        "Accept": "application/octet-stream,*/*",
      },
    });

    if (!resp.ok) {
      throw new Error(`Download failed ${resp.status} from ${url}`);
    }
    await ensureDir(path.dirname(outFile));
    const fileStream = fssync.createWriteStream(outFile);
    await pipeline(resp.body, fileStream);
    return { ok: true, url };
  } finally {
    clearTimeout(t);
  }
}

async function extractTgz(archiveFile, extractDir) {
  await ensureDir(extractDir);
  // Use system tar (present on most Linux images incl. Render)
  await execFileAsync("tar", ["-xzf", archiveFile, "-C", extractDir], { timeout: 120000 });
}

// Find a folder within extracted content that matches rootFolder
async function resolveExtractedRoot(extractDir, rootFolder) {
  const top = await fs.readdir(extractDir, { withFileTypes: true });
  const topDirs = top.filter((d) => d.isDirectory()).map((d) => d.name);

  if (rootFolder) {
    // Common case: <repo>-<ref>/<rootFolder>
    for (const td of topDirs) {
      const candidate = path.join(extractDir, td, rootFolder);
      if (await fileExists(candidate)) return candidate;
    }
    // Or rootFolder at top-level
    const direct = path.join(extractDir, rootFolder);
    if (await fileExists(direct)) return direct;

    // Or it might be nested deeper; do a shallow search (2 levels)
    for (const td of topDirs) {
      const inner = await fs.readdir(path.join(extractDir, td), { withFileTypes: true });
      for (const ent of inner) {
        if (ent.isDirectory() && ent.name === rootFolder) {
          return path.join(extractDir, td, ent.name);
        }
      }
    }

    throw new Error(`Could not find rootFolder "${rootFolder}" inside extracted archive`);
  }

  // If no rootFolder specified:
  // If only one top-level dir, use it
  if (topDirs.length === 1) return path.join(extractDir, topDirs[0]);

  // Otherwise: pick the first dir that contains .scad files (one level down)
  for (const td of topDirs) {
    const p = path.join(extractDir, td);
    const inner = await fs.readdir(p, { withFileTypes: true });
    if (inner.some((x) => x.isFile() && x.name.toLowerCase().endsWith(".scad"))) return p;
  }

  throw new Error("Could not determine library root folder automatically; please set rootFolder");
}

async function loadInstalled() {
  try {
    const txt = await fs.readFile(INSTALL_DB, "utf8");
    return JSON.parse(txt);
  } catch {
    return { libraries: {} };
  }
}

async function saveInstalled(db) {
  await ensureDir(LIB_DIR);
  await fs.writeFile(INSTALL_DB, JSON.stringify(db, null, 2), "utf8");
}

// Install/Update a library
// Descriptor shape:
// {
//   id: "gears",
//   version: "optional",
//   url: "https://...tgz OR https://github.com/org/repo",
//   ref: "main|master|tag (optional for github)",
//   sha256: "optional",
//   rootFolder: "MCAD" (optional but recommended for repo bundles)
// }
const installLocks = new Map();

async function installLibrary(desc) {
  if (!desc?.id) throw new Error("Library missing id");
  if (!desc?.url) throw new Error(`Library ${desc.id} missing url`);

  // Simple in-process lock to prevent concurrent installs of same lib
  if (installLocks.has(desc.id)) return installLocks.get(desc.id);

  const p = (async () => {
    await ensureDir(LIB_DIR);
    const db = await loadInstalled();
    const existing = db.libraries?.[desc.id];

    // If already installed with same version+sha256, skip
    if (
      existing &&
      desc.version &&
      existing.version === desc.version &&
      (!desc.sha256 || existing.sha256 === desc.sha256)
    ) {
      return existing;
    }

    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${desc.id}-`));
    const archiveFile = path.join(tmpDir, "lib.tgz");
    const extractDir = path.join(tmpDir, "extract");
    const finalDir = path.join(LIB_DIR, desc.id);
    const metaDir = path.join(finalDir, ".meta");

    // Download (supports GitHub repo URL by converting to tarball URLs)
    let usedUrl = desc.url;
    if (isProbablyGitHubRepoUrl(desc.url) && !desc.url.toLowerCase().endsWith(".tgz") && !desc.url.toLowerCase().endsWith(".tar.gz")) {
      const candidates = toGitHubTarballCandidates(desc.url, desc.ref);
      let ok = false;
      let lastErr = null;
      for (const c of candidates) {
        try {
          await downloadToFile(c, archiveFile);
          usedUrl = c;
          ok = true;
          break;
        } catch (e) {
          lastErr = e;
        }
      }
      if (!ok) throw lastErr || new Error("Failed to download GitHub tarball");
    } else {
      await downloadToFile(desc.url, archiveFile);
    }

    // Verify sha if provided
    const gotSha = await sha256File(archiveFile);
    if (desc.sha256 && desc.sha256.toLowerCase() !== gotSha.toLowerCase()) {
      throw new Error(`SHA256 mismatch for ${desc.id}. expected=${desc.sha256} got=${gotSha}`);
    }

    // Extract
    await extractTgz(archiveFile, extractDir);
    const rootPath = await resolveExtractedRoot(extractDir, desc.rootFolder);

    // Replace install atomically-ish
    await fs.rm(finalDir, { recursive: true, force: true });
    await ensureDir(finalDir);
    await fs.cp(rootPath, finalDir, { recursive: true });

    // Write meta
    await ensureDir(metaDir);
    const meta = {
      id: desc.id,
      version: desc.version || null,
      url: desc.url,
      usedUrl,
      sha256: gotSha,
      rootFolder: desc.rootFolder || null,
      installedAt: new Date().toISOString(),
    };
    await fs.writeFile(path.join(metaDir, "installed.json"), JSON.stringify(meta, null, 2), "utf8");

    db.libraries = db.libraries || {};
    db.libraries[desc.id] = meta;
    await saveInstalled(db);

    return meta;
  })().finally(() => {
    installLocks.delete(desc.id);
  });

  installLocks.set(desc.id, p);
  return p;
}

async function ensureLibraries(libraries) {
  // libraries can be:
  // - ["gears","threads"] (must already be installed)
  // - [{id,url,rootFolder,...}, ...] (will install/ensure)
  const db = await loadInstalled();
  const missing = [];

  for (const lib of libraries || []) {
    if (typeof lib === "string") {
      if (!db.libraries?.[lib]) missing.push(lib);
    } else if (lib && typeof lib === "object") {
      await installLibrary(lib);
    }
  }

  if (missing.length) {
    throw new Error(
      `Missing libraries on render server: ${missing.join(", ")}. Call POST /libraries/sync first or pass full descriptors.`
    );
  }
}

async function symlinkRequestedLibsIntoJob(jobDir, libraries) {
  // For installed libs, we symlink jobDir/<something> so OpenSCAD finds `use <MCAD/...>` relative to input.scad dir.
  // Strategy:
  // - If the library has rootFolder, create jobDir/<rootFolder> -> LIB_DIR/<id>
  // - Otherwise, create jobDir/<id> -> LIB_DIR/<id>
  const db = await loadInstalled();

  for (const lib of libraries || []) {
    const id = typeof lib === "string" ? lib : lib.id;
    if (!id) continue;
    const meta = db.libraries?.[id];
    if (!meta) continue;

    // If they specified rootFolder, link that name (e.g. "MCAD") to the installed directory.
    // Otherwise link by id.
    const linkName = meta.rootFolder || id;
    const linkPath = path.join(jobDir, linkName);

    // Remove if exists
    await fs.rm(linkPath, { recursive: true, force: true });
    // Create symlink
    await fs.symlink(path.join(LIB_DIR, id), linkPath, "dir");
  }
}

// -------------------- ROUTES --------------------
app.get("/health", async (_req, res) => {
  await ensureDir(LIB_DIR);
  res.status(200).send("ok");
});

// List installed libs
app.get("/libraries", async (req, res) => {
  if (!requireAuth(req, res)) return;
  const db = await loadInstalled();
  res.status(200).json(db);
});

// Sync/install libs
app.post("/libraries/sync", async (req, res) => {
  try {
    if (!requireAuth(req, res)) return;

    const { libraries } = req.body || {};
    if (!Array.isArray(libraries) || libraries.length === 0) {
      return res.status(400).json({ error: "Body must include { libraries: [...] }" });
    }

    const results = [];
    for (const lib of libraries) {
      if (!lib?.id || !lib?.url) {
        return res.status(400).json({ error: "Each library must include at least {id, url}" });
      }
      const meta = await installLibrary(lib);
      results.push(meta);
    }

    const db = await loadInstalled();
    return res.status(200).json({ ok: true, installed: results, db });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Render STL
app.post("/render", async (req, res) => {
  try {
    if (!requireAuth(req, res)) return;

    const { code, format, libraries = [] } = req.body || {};
    if (typeof code !== "string" || !code.trim()) {
      return res.status(400).json({ error: "Missing code" });
    }
    if ((format || "stl") !== "stl") {
      return res.status(400).json({ error: "Only format=stl is supported" });
    }

    // Ensure libraries are available (install if descriptors provided)
    await ensureLibraries(libraries);

    const jobId = crypto.randomBytes(6).toString("hex");
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), `scad-${jobId}-`));
    const inFile = path.join(dir, "input.scad");
    const outFile = path.join(dir, "output.stl");

    // Make requested libraries available relative to input.scad
    await symlinkRequestedLibsIntoJob(dir, libraries);

    await fs.writeFile(inFile, code, "utf8");

    // Render
    // You can add OpenSCAD flags here if you want:
    // --enable=manifold can help robustness on some builds
    await execFileAsync("openscad", ["-o", outFile, "--enable=manifold", inFile], {
      timeout: OPENSCAD_TIMEOUT_MS,
    });

    const stl = await fs.readFile(outFile);

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(stl);
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, async () => {
  await ensureDir(LIB_DIR);
  console.log(`OpenSCAD render service running on :${port}`);
  console.log(`LIB_DIR=${LIB_DIR}`);
});
