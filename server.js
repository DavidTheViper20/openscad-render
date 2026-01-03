import express from "express";
import fsp from "fs/promises";
import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import { pipeline } from "stream/promises";
import { Readable, Transform } from "stream";

const execFileAsync = promisify(execFile);
const app = express();

app.use(express.json({ limit: "10mb" }));

// =====================
// Auth
// =====================
const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || "";
function authOk(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  return h === `Bearer ${TOKEN}`;
}

app.get("/health", (_req, res) => res.status(200).send("ok"));

// =====================
// Library install config
// =====================

// Where libraries are installed on the render server
const LIB_DIR = process.env.OPENSCAD_LIB_DIR || "/opt/openscad-libs";

// Optional: JSON manifest (recommended) so you can change libs without code changes.
// Format example:
// {
//   "gears_mcad": {"version":"1.0.0","url":"https://.../mcad-1.0.0.tgz","sha256":"...","rootFolder":"MCAD"},
//   "threads": {"version":"2.1.0","url":"https://.../threads-2.1.0.tgz","sha256":"...","rootFolder":"threads"}
// }
function loadManifest() {
  const env = process.env.OPENSCAD_LIB_MANIFEST_JSON;
  if (env && env.trim()) {
    try {
      return JSON.parse(env);
    } catch (e) {
      console.warn("OPENSCAD_LIB_MANIFEST_JSON is not valid JSON:", e?.message || e);
    }
  }

  // Fallback example manifest (replace via env var in production)
  return {
    // Example only. Use OPENSCAD_LIB_MANIFEST_JSON for real values.
    // gears_mcad: {
    //   version: "1.0.0",
    //   url: "https://your-cdn.com/openscad-libs/mcad-1.0.0.tgz",
    //   sha256: "PUT_SHA256_HERE",
    //   rootFolder: "MCAD"
    // }
  };
}

function normalizeLibs(libs) {
  if (!libs) return [];
  if (Array.isArray(libs)) return libs.map(String);
  return [];
}

async function ensureDir(p) {
  await fsp.mkdir(p, { recursive: true });
}

function installedMetaPath(libId) {
  return path.join(LIB_DIR, `${libId}.installed.json`);
}

function lockPath(libId) {
  return path.join(LIB_DIR, `${libId}.lock`);
}

async function readInstalledMeta(libId) {
  try {
    const raw = await fsp.readFile(installedMetaPath(libId), "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function writeInstalledMeta(libId, meta) {
  await fsp.writeFile(installedMetaPath(libId), JSON.stringify(meta, null, 2), "utf8");
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function withLibLock(libId, fn) {
  await ensureDir(LIB_DIR);
  const lp = lockPath(libId);

  const deadline = Date.now() + 60_000; // 60s
  while (true) {
    try {
      const handle = await fsp.open(lp, "wx");
      try {
        return await fn();
      } finally {
        await handle.close().catch(() => {});
        await fsp.unlink(lp).catch(() => {});
      }
    } catch (e) {
      if (e?.code !== "EEXIST") throw e;
      if (Date.now() > deadline) throw new Error(`Timeout waiting for lock for ${libId}`);
      await sleep(250 + Math.floor(Math.random() * 250));
    }
  }
}

async function downloadToFile(url, destPath, expectedSha256) {
  const resp = await fetch(url, { redirect: "follow" });
  if (!resp.ok) throw new Error(`Download failed ${resp.status} from ${url}`);

  const hash = crypto.createHash("sha256");
  const hasher = new Transform({
    transform(chunk, _enc, cb) {
      hash.update(chunk);
      cb(null, chunk);
    },
  });

  await pipeline(
    Readable.fromWeb(resp.body),
    hasher,
    fs.createWriteStream(destPath)
  );

  const digest = hash.digest("hex");
  if (expectedSha256 && expectedSha256 !== digest) {
    throw new Error(`SHA256 mismatch. Expected ${expectedSha256}, got ${digest}`);
  }
  return digest;
}

async function extractArchive(archivePath, destDir) {
  // Supports .tgz/.tar.gz via tar (recommended).
  // Supports .zip via unzip if installed.
  const lower = archivePath.toLowerCase();

  await ensureDir(destDir);

  if (lower.endsWith(".tgz") || lower.endsWith(".tar.gz")) {
    await execFileAsync("tar", ["-xzf", archivePath, "-C", destDir], { timeout: 120000 });
    return;
  }

  if (lower.endsWith(".zip")) {
    // Requires `unzip` installed on the render server.
    await execFileAsync("unzip", ["-q", archivePath, "-d", destDir], { timeout: 120000 });
    return;
  }

  throw new Error(`Unsupported archive type for ${archivePath}. Use .tgz/.tar.gz (recommended) or .zip (requires unzip).`);
}

async function safeRemove(p) {
  await fsp.rm(p, { recursive: true, force: true }).catch(() => {});
}

async function pathExists(p) {
  try {
    await fsp.stat(p);
    return true;
  } catch {
    return false;
  }
}

async function ensureLibraryInstalled(libId, { force = false } = {}) {
  const manifest = loadManifest();
  const spec = manifest[libId];
  if (!spec) throw new Error(`Unknown library id: ${libId}`);
  if (!spec.url || !spec.rootFolder) throw new Error(`Library ${libId} missing url/rootFolder in manifest`);

  const targetFolder = path.join(LIB_DIR, spec.rootFolder);

  return await withLibLock(libId, async () => {
    await ensureDir(LIB_DIR);

    const meta = await readInstalledMeta(libId);
    const folderOk = await pathExists(targetFolder);

    if (!force && meta && folderOk && meta.version === spec.version) {
      return { libId, status: "already", version: meta.version, rootFolder: spec.rootFolder };
    }

    // Install / reinstall
    const tmpBase = await fsp.mkdtemp(path.join(os.tmpdir(), `lib-${libId}-`));
    const archivePath = path.join(tmpBase, "lib_archive");

    try {
      // Pick extension from URL so extractor knows what to do
      const urlLower = spec.url.toLowerCase();
      const ext =
        urlLower.endsWith(".tar.gz") ? ".tar.gz" :
        urlLower.endsWith(".tgz") ? ".tgz" :
        urlLower.endsWith(".zip") ? ".zip" :
        "";

      const archiveWithExt = archivePath + ext;

      const sha = await downloadToFile(spec.url, archiveWithExt, spec.sha256);

      const extractedDir = path.join(tmpBase, "extracted");
      await extractArchive(archiveWithExt, extractedDir);

      const extractedRoot = path.join(extractedDir, spec.rootFolder);
      if (!(await pathExists(extractedRoot))) {
        // Helpful debug: list top-level dirs
        const items = await fsp.readdir(extractedDir).catch(() => []);
        throw new Error(
          `Archive did not contain expected rootFolder "${spec.rootFolder}". Found: ${items.join(", ")}`
        );
      }

      // Replace existing
      await safeRemove(targetFolder);

      // Copy to target (rename can fail across devices)
      await fsp.cp(extractedRoot, targetFolder, { recursive: true });

      await writeInstalledMeta(libId, {
        libId,
        version: spec.version,
        rootFolder: spec.rootFolder,
        sha256: sha,
        installedAt: new Date().toISOString(),
        sourceUrl: spec.url,
      });

      return { libId, status: "installed", version: spec.version, rootFolder: spec.rootFolder };
    } finally {
      await safeRemove(tmpBase);
    }
  });
}

// =====================
// Library endpoints
// =====================

app.get("/libraries/status", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ error: "Unauthorized" });

    const manifest = loadManifest();
    await ensureDir(LIB_DIR);

    const result = {};
    for (const [id, spec] of Object.entries(manifest)) {
      const meta = await readInstalledMeta(id);
      const folderOk = spec?.rootFolder ? await pathExists(path.join(LIB_DIR, spec.rootFolder)) : false;
      result[id] = {
        manifest: { version: spec.version, rootFolder: spec.rootFolder, hasUrl: !!spec.url },
        installed: !!meta && folderOk,
        installedMeta: meta || null,
      };
    }

    return res.json({ ok: true, libDir: LIB_DIR, status: result });
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

app.post("/libraries/sync", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ error: "Unauthorized" });

    const libs = normalizeLibs(req.body?.libs);
    const force = !!req.body?.force;

    if (!libs.length) {
      return res.status(400).json({ error: "libs[] is required" });
    }

    const installed = [];
    const already = [];
    for (const id of libs) {
      const r = await ensureLibraryInstalled(id, { force });
      if (r.status === "installed") installed.push(id);
      else already.push(id);
    }

    return res.json({ ok: true, installed, already });
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

// =====================
// Render endpoint
// =====================

app.post("/render", async (req, res) => {
  const jobId = crypto.randomBytes(6).toString("hex");
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), `scad-${jobId}-`));

  try {
    if (!authOk(req)) return res.status(401).json({ error: "Unauthorized" });

    const { code, format } = req.body || {};
    const libs = normalizeLibs(req.body?.libs);

    if (typeof code !== "string" || !code.trim()) {
      return res.status(400).json({ error: "Missing code" });
    }
    if ((format || "stl") !== "stl") {
      return res.status(400).json({ error: "Only format=stl is supported" });
    }

    // Ensure requested libs installed
    if (libs.length) {
      for (const id of libs) await ensureLibraryInstalled(id, { force: false });
    }

    const inFile = path.join(dir, "input.scad");
    const outFile = path.join(dir, "output.stl");

    await fsp.writeFile(inFile, code, "utf8");

    // Add library include path so SCAD can: use <MCAD/involute_gears.scad>;
    // NOTE: -I adds a library search path.
    const args = [];
    args.push("-o", outFile);

    // Optional: enables manifold backend if installed OpenSCAD supports it
    // (If your OpenSCAD build doesn't support, remove this line.)
    args.push("--enable=manifold");

    // Library search path
    args.push("-I", LIB_DIR);

    args.push(inFile);

    await execFileAsync("openscad", args, { timeout: 120000 });

    const stl = await fsp.readFile(outFile);

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(stl);
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  } finally {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`OpenSCAD render service running on :${port}`));
