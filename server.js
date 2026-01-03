// server.js
// Drop-in OpenSCAD render service + library sync (GitHub tarballs) + stable include paths.
//
// What this gives you:
// - POST /render  { code, format:"stl" }  -> returns STL bytes (or JSON error with stderr)
// - POST /libraries/sync { libraries:[{id,url,ref,rootFolder}] } -> downloads + installs libs
// - GET  /libraries/list -> shows installed libs
// - Uses a stable include path: <LIB_ID/...> (not MCAD-master/...)
//   Example in your SCAD:  use <MCAD/involute_gears.scad>;
//
// ENV you should set on Render:
// - OPENSCAD_RENDER_TOKEN=... (optional, but recommended)
// - OPENSCAD_LIB_DIR=/opt/openscad-libs (default)
// - OPENSCAD_BIN=openscad (default)
// - OPENSCAD_TIMEOUT_MS=120000 (default)
// - OPENSCAD_MIN_STL_BYTES=200 (default)

import express from "express";
import fs from "fs/promises";
import fssync from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const app = express();

app.use(express.json({ limit: "15mb" }));

const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || "";
const LIB_DIR = process.env.OPENSCAD_LIB_DIR || "/opt/openscad-libs";
const LIB_DB_PATH = path.join(LIB_DIR, ".libraries.json");
const OPENSCAD_BIN = process.env.OPENSCAD_BIN || "openscad";
const TIMEOUT_MS = Number(process.env.OPENSCAD_TIMEOUT_MS || 120000);
const MIN_STL_BYTES = Number(process.env.OPENSCAD_MIN_STL_BYTES || 200);

function authOk(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  return h === `Bearer ${TOKEN}`;
}

function safeId(id) {
  return String(id || "")
    .trim()
    .replace(/[^a-zA-Z0-9_\-]/g, "_")
    .slice(0, 64);
}

async function ensureLibDir() {
  await fs.mkdir(LIB_DIR, { recursive: true });
}

async function loadLibDb() {
  await ensureLibDir();
  try {
    const raw = await fs.readFile(LIB_DB_PATH, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return { libraries: {} };
    if (!parsed.libraries) parsed.libraries = {};
    return parsed;
  } catch {
    return { libraries: {} };
  }
}

async function saveLibDb(db) {
  await ensureLibDir();
  await fs.writeFile(LIB_DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

// If user provides a GitHub repo URL like https://github.com/openscad/MCAD,
// and a ref like "master" or "main", we convert to codeload tarball automatically.
function resolveDownloadUrl(url, ref) {
  const u = String(url || "").trim();
  const r = String(ref || "").trim() || "master";

  // If they already provided a direct tar.gz/.tgz, use it as-is.
  if (u.endsWith(".tar.gz") || u.endsWith(".tgz")) return u;

  // GitHub repo URL -> codeload tarball.
  const m = u.match(/^https?:\/\/github\.com\/([^\/]+)\/([^\/#?]+)(?:\.git)?\/?$/i);
  if (m) {
    const owner = m[1];
    const repo = m[2];
    // Heads by default. (Tags are possible too, but heads covers 99% of your use.)
    return `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${encodeURIComponent(r)}`;
  }

  // Otherwise treat as a direct URL.
  return u;
}

async function downloadToFile(url, filePath) {
  const resp = await fetch(url, { redirect: "follow" });
  if (!resp.ok) {
    throw new Error(`Download failed ${resp.status} from ${url}`);
  }
  const buf = Buffer.from(await resp.arrayBuffer());
  await fs.writeFile(filePath, buf);
  return { bytes: buf.length };
}

async function pathExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function installLibrary({ id, url, ref, rootFolder }) {
  const libId = safeId(id);
  if (!libId) throw new Error("Library id is required");

  const usedUrl = resolveDownloadUrl(url, ref);
  if (!usedUrl) throw new Error(`Library "${libId}" missing url`);

  const jobId = crypto.randomBytes(6).toString("hex");
  const workDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${jobId}-`));
  const archivePath = path.join(workDir, "lib.tar.gz");
  const extractDir = path.join(workDir, "extract");

  await fs.mkdir(extractDir, { recursive: true });
  const dl = await downloadToFile(usedUrl, archivePath);

  // Extract
  // (Render Linux images have tar. If yours doesn’t, install it or switch to a node tar library.)
  await execFileAsync("tar", ["-xzf", archivePath, "-C", extractDir], { timeout: 120000 });

  // rootFolder: if provided, that folder must exist inside extracted tree.
  // If not provided, we auto-detect the single top-level folder.
  let rootPath = extractDir;

  if (rootFolder && String(rootFolder).trim()) {
    const rf = String(rootFolder).trim();
    const candidate = path.join(extractDir, rf);
    if (!(await pathExists(candidate))) {
      // Give a helpful error by listing top-level directories.
      const top = await fs.readdir(extractDir).catch(() => []);
      throw new Error(`Could not find rootFolder "${rf}" inside extracted archive. Top-level: ${top.join(", ")}`);
    }
    rootPath = candidate;
  } else {
    const top = (await fs.readdir(extractDir).catch(() => [])).filter(Boolean);
    if (top.length === 1 && await pathExists(path.join(extractDir, top[0]))) {
      rootPath = path.join(extractDir, top[0]);
    } else {
      // multiple roots -> require rootFolder
      throw new Error(`Archive has multiple root entries (${top.join(", ")}). Provide rootFolder.`);
    }
  }

  // Install to stable path: /opt/openscad-libs/<LIB_ID>/...
  const targetDir = path.join(LIB_DIR, libId);
  await ensureLibDir();
  await fs.rm(targetDir, { recursive: true, force: true });
  await fs.mkdir(targetDir, { recursive: true });

  // Copy extracted root content into targetDir
  // If rootPath is the library folder itself, we want its contents.
  const entries = await fs.readdir(rootPath);
  for (const name of entries) {
    await fs.cp(path.join(rootPath, name), path.join(targetDir, name), { recursive: true });
  }

  // Optional sha256 (nice to store, not required)
  let sha256 = null;
  try {
    const cryptoMod = await import("crypto");
    const hash = cryptoMod.createHash("sha256");
    hash.update(await fs.readFile(archivePath));
    sha256 = hash.digest("hex");
  } catch {
    // ignore
  }

  return {
    id: libId,
    version: null,
    url: String(url || ""),
    usedUrl,
    sha256,
    rootFolder: String(rootFolder || ""),
    installedAt: new Date().toISOString(),
    bytes: dl.bytes
  };
}

async function runOpenSCADToSTL(code, inFile, outFile) {
  await ensureLibDir();

  const env = {
    ...process.env,
    // Helps OpenSCAD resolve use/include
    OPENSCADPATH: LIB_DIR
  };

  // IMPORTANT: -I adds include search path so `use <MCAD/...>` works.
  const args = [
    "-I", LIB_DIR,
    "-o", outFile,
    inFile
  ];

  const { stdout, stderr } = await execFileAsync(OPENSCAD_BIN, args, {
    timeout: TIMEOUT_MS,
    env
  });

  // Validate output
  const st = await fs.stat(outFile).catch(() => null);
  if (!st || st.size < MIN_STL_BYTES) {
    const errPreview = String(stderr || "").slice(0, 4000);
    throw new Error(`OpenSCAD produced empty/invalid STL (size=${st?.size ?? 0}). stderr: ${errPreview}`);
  }

  return { stdout, stderr, bytes: st.size };
}

app.get("/health", async (_req, res) => {
  await ensureLibDir();
  res.status(200).send("ok");
});

// List installed libs (debug)
app.get("/libraries/list", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });
    const db = await loadLibDb();
    return res.json({ ok: true, libraries: db.libraries || {} });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Sync/install libs
app.post("/libraries/sync", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const { libraries } = req.body || {};
    if (!Array.isArray(libraries) || libraries.length === 0) {
      return res.status(400).json({ ok: false, error: "Missing libraries[]" });
    }

    const db = await loadLibDb();
    const installed = [];

    for (const lib of libraries) {
      const meta = await installLibrary(lib);
      db.libraries[meta.id] = meta;
      installed.push(meta);
    }

    await saveLibDb(db);
    return res.json({ ok: true, installed, db });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Render SCAD -> STL
app.post("/render", async (req, res) => {
  let dir = null;
  try {
    if (!authOk(req)) return res.status(401).json({ error: "Unauthorized" });

    const { code, format } = req.body || {};
    if (typeof code !== "string" || !code.trim()) {
      return res.status(400).json({ error: "Missing code" });
    }
    if ((format || "stl") !== "stl") {
      return res.status(400).json({ error: "Only format=stl is supported" });
    }

    const jobId = crypto.randomBytes(6).toString("hex");
    dir = await fs.mkdtemp(path.join(os.tmpdir(), `scad-${jobId}-`));
    const inFile = path.join(dir, "input.scad");
    const outFile = path.join(dir, "output.stl");

    await fs.writeFile(inFile, code, "utf8");

    const result = await runOpenSCADToSTL(code, inFile, outFile);

    const stl = await fs.readFile(outFile);

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    // Optional debug headers
    res.setHeader("X-STL-Bytes", String(result.bytes));

    return res.status(200).send(stl);
  } catch (e) {
    // Return stderr to help you diagnose missing include/module issues.
    return res.status(500).json({ error: String(e?.message || e) });
  } finally {
    if (dir) {
      // Best-effort cleanup
      try {
        await fs.rm(dir, { recursive: true, force: true });
      } catch {}
    }
  }
});

const port = process.env.PORT || 3000;
app.listen(port, async () => {
  await ensureLibDir();
  console.log(`OpenSCAD render service running on :${port}`);
  console.log(`LIB_DIR=${LIB_DIR}`);
  console.log(`TOKEN_AUTH=${TOKEN ? "enabled" : "disabled"}`);
});
