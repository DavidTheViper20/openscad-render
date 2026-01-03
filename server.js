import express from "express";
import fs from "fs/promises";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const app = express();

app.use(express.json({ limit: "20mb" }));

// ===== Env =====
const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || "";
const OPENSCAD_BIN = process.env.OPENSCAD_BIN || "openscad";
const LIB_DIR = process.env.OPENSCAD_LIB_DIR || "/opt/openscad-libs";
const TIMEOUT_MS = Number(process.env.OPENSCAD_TIMEOUT_MS || 120000);
const MIN_VALID_STL_BYTES = Number(process.env.MIN_VALID_STL_BYTES || 200);
const LIB_DB_PATH = path.join(LIB_DIR, "libraries.json");

// ===== Helpers =====
function authOk(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  return h === `Bearer ${TOKEN}`;
}

async function ensureLibDir() {
  await fs.mkdir(LIB_DIR, { recursive: true });
  try {
    await fs.access(LIB_DB_PATH);
  } catch {
    await fs.writeFile(LIB_DB_PATH, JSON.stringify({ libraries: {} }, null, 2), "utf8");
  }
}

async function readLibDb() {
  await ensureLibDir();
  const raw = await fs.readFile(LIB_DB_PATH, "utf8");
  try {
    return JSON.parse(raw);
  } catch {
    return { libraries: {} };
  }
}

async function writeLibDb(db) {
  await ensureLibDir();
  const tmp = `${LIB_DB_PATH}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(db, null, 2), "utf8");
  await fs.rename(tmp, LIB_DB_PATH);
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function isProbablyJson(buf) {
  const s = buf.slice(0, 2).toString("utf8");
  return s.startsWith("{") || s.startsWith("[");
}

function resolveGitHubTarballUrl(repoUrl, ref) {
  // repoUrl like: https://github.com/openscad/MCAD
  // Use codeload, not github archive pages (more reliable).
  const m = String(repoUrl).match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git|\/)?$/i);
  if (!m) return null;
  const owner = m[1];
  const repo = m[2];
  const safeRef = ref || "master";
  return `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${safeRef}`;
}

async function downloadToBuffer(url) {
  const resp = await fetch(url, { redirect: "follow" });
  if (!resp.ok) {
    throw new Error(`Download failed ${resp.status} from ${url}`);
  }
  const arr = new Uint8Array(await resp.arrayBuffer());
  return Buffer.from(arr);
}

async function pathExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function safeRm(p) {
  try {
    await fs.rm(p, { recursive: true, force: true });
  } catch {}
}

async function ensureSymlink(linkPath, targetPath) {
  // Remove existing link/dir, then symlink.
  await safeRm(linkPath);
  await fs.symlink(targetPath, linkPath);
}

async function extractTarGzToDir(tarGzPath, outDir) {
  await fs.mkdir(outDir, { recursive: true });
  // tar should exist on linux (Render)
  await execFileAsync("tar", ["-xzf", tarGzPath, "-C", outDir], { timeout: 120000 });
}

async function inferRootFolder(extractDir) {
  const items = await fs.readdir(extractDir, { withFileTypes: true });
  const dirs = items.filter((d) => d.isDirectory()).map((d) => d.name);
  if (dirs.length === 1) return dirs[0];
  return null;
}

let librarySyncLock = Promise.resolve();
function withSyncLock(fn) {
  const run = librarySyncLock.then(fn, fn);
  librarySyncLock = run.then(() => {}, () => {});
  return run;
}

// ===== Routes =====
app.get("/health", async (_req, res) => {
  await ensureLibDir();
  res.status(200).send("ok");
});

app.get("/libraries", async (req, res) => {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });
  const db = await readLibDb();
  return res.json({ ok: true, libraries: db.libraries || {} });
});

app.post("/libraries/sync", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });
    await ensureLibDir();

    const libs = req.body?.libraries;
    if (!Array.isArray(libs) || libs.length === 0) {
      return res.status(400).json({ ok: false, error: "Missing libraries[]" });
    }

    const result = await withSyncLock(async () => {
      const db = await readLibDb();
      db.libraries ||= {};

      const installed = [];

      for (const lib of libs) {
        const id = String(lib?.id || "").trim();
        if (!id) throw new Error("Each library needs id");

        const url = String(lib?.url || "").trim();
        if (!url) throw new Error(`Library ${id} missing url`);

        const ref = String(lib?.ref || "").trim() || "master";

        // Accept either a direct tarball URL, or a GitHub repo URL.
        let usedUrl = url;
        if (!/\.(tgz|tar\.gz)$/i.test(url)) {
          const gh = resolveGitHubTarballUrl(url, ref);
          if (!gh) throw new Error(`Library ${id}: url must be .tgz/.tar.gz or a GitHub repo URL`);
          usedUrl = gh;
        }

        // Download
        const tarBuf = await downloadToBuffer(usedUrl);
        const tarHash = sha256(tarBuf);

        // Extract into temp
        const tmpExtract = path.join(LIB_DIR, `__extract_${id}_${Date.now()}_${crypto.randomBytes(3).toString("hex")}`);
        await fs.mkdir(tmpExtract, { recursive: true });

        const tarPath = path.join(tmpExtract, "lib.tar.gz");
        await fs.writeFile(tarPath, tarBuf);

        await extractTarGzToDir(tarPath, tmpExtract);

        // Determine rootFolder inside extracted archive
        const rootFolder = String(lib?.rootFolder || "").trim() || (await inferRootFolder(tmpExtract));
        if (!rootFolder) {
          await safeRm(tmpExtract);
          throw new Error(`Could not infer rootFolder for ${id}. Provide rootFolder explicitly.`);
        }

        const rootPath = path.join(tmpExtract, rootFolder);
        if (!(await pathExists(rootPath))) {
          await safeRm(tmpExtract);
          throw new Error(`Could not find rootFolder "${rootFolder}" inside extracted archive`);
        }

        // Move root folder into LIB_DIR as a versioned folder
        // Keep the extracted folder name as-is (e.g. MCAD-master).
        const finalRootPath = path.join(LIB_DIR, rootFolder);
        await safeRm(finalRootPath);
        await fs.rename(rootPath, finalRootPath);

        // Clean temp
        await safeRm(tmpExtract);

        // Create stable alias so code can do: use <MCAD/...>
        // Alias folder name is the library id.
        const aliasPath = path.join(LIB_DIR, id);
        await ensureSymlink(aliasPath, finalRootPath);

        const meta = {
          id,
          version: lib?.version || null,
          url,
          usedUrl,
          sha256: tarHash,
          rootFolder,
          installedAt: new Date().toISOString(),
        };

        db.libraries[id] = meta;
        installed.push(meta);
      }

      await writeLibDb(db);
      return { installed, db };
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

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

    await ensureLibDir();

    const jobId = crypto.randomBytes(6).toString("hex");
    dir = await fs.mkdtemp(path.join(os.tmpdir(), `scad-${jobId}-`));
    const inFile = path.join(dir, "input.scad");
    const outFile = path.join(dir, "output.stl");

    await fs.writeFile(inFile, code, "utf8");

    // IMPORTANT:
    // - Do NOT pass --enable=manifold (your OpenSCAD doesn't support it)
    // - Use OPENSCADPATH so: use <MCAD/...> works
    const env = {
      ...process.env,
      OPENSCADPATH: LIB_DIR,
    };

    // OpenSCAD CLI: openscad -o output.stl input.scad
    await execFileAsync(OPENSCAD_BIN, ["-o", outFile, inFile], {
      timeout: TIMEOUT_MS,
      env,
    });

    const stl = await fs.readFile(outFile);

    // Guard: don’t return JSON disguised as STL
    if (!stl || stl.length < MIN_VALID_STL_BYTES || isProbablyJson(stl)) {
      return res.status(500).json({
        error: "STL export produced invalid/empty output. Check OpenSCAD code and library paths.",
        details: `bytes=${stl?.length || 0}`,
      });
    }

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(stl);
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  } finally {
    if (dir) {
      try { await fs.rm(dir, { recursive: true, force: true }); } catch {}
    }
  }
});

// ===== Start =====
const port = process.env.PORT || 3000;
app.listen(port, async () => {
  await ensureLibDir();
  console.log(`OpenSCAD render service running on :${port}`);
  console.log(`LIB_DIR=${LIB_DIR}`);
});
