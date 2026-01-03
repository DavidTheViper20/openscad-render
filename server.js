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

// ===== Config =====
const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || "";
const LIB_DIR = process.env.OPENSCAD_LIB_DIR || "/opt/openscad-libs";
const LIB_DB_FILE = process.env.OPENSCAD_LIB_DB_FILE || path.join(LIB_DIR, "_installed.json");

// Optional allowlist for security (comma-separated hostnames)
// Default allows GitHub + codeload.
const ALLOWED_HOSTS = (process.env.OPENSCAD_LIB_ALLOWED_HOSTS || "github.com,codeload.github.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function authOk(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  return h === `Bearer ${TOKEN}`;
}

async function ensureDir(p) {
  await fs.mkdir(p, { recursive: true });
}

async function readDb() {
  try {
    const txt = await fs.readFile(LIB_DB_FILE, "utf8");
    return JSON.parse(txt);
  } catch {
    return { libraries: {} };
  }
}

async function writeDb(db) {
  await ensureDir(path.dirname(LIB_DB_FILE));
  await fs.writeFile(LIB_DB_FILE, JSON.stringify(db, null, 2), "utf8");
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function urlHost(u) {
  try {
    return new URL(u).hostname;
  } catch {
    return "";
  }
}

function assertAllowedUrl(u) {
  const host = urlHost(u);
  if (!host) throw new Error(`Invalid URL: ${u}`);
  if (!ALLOWED_HOSTS.includes(host)) {
    throw new Error(`URL host not allowed: ${host}. Allowed: ${ALLOWED_HOSTS.join(", ")}`);
  }
}

// If user supplies https://github.com/org/repo, build codeload tarball URLs.
// We try a few patterns for ref because branch/tag can differ.
function expandGithubTarballUrls(repoUrl, ref) {
  const m = repoUrl.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/?$/);
  if (!m) return [repoUrl]; // not a plain repo URL, use as-is
  const owner = m[1];
  const repo = m[2].replace(/\.git$/, "");
  const base = `https://codeload.github.com/${owner}/${repo}/tar.gz/`;

  if (!ref || !ref.trim()) {
    // No ref provided → GitHub default branch is unknown; user should set ref.
    // Still try "master" then "main".
    return [`${base}refs/heads/master`, `${base}refs/heads/main`];
  }

  const r = ref.trim();

  // If they already passed a "refs/..." string, respect it.
  if (r.startsWith("refs/")) return [`${base}${r}`];

  // Try as branch, then tag, then raw ref (covers commits sometimes).
  return [
    `${base}refs/heads/${r}`,
    `${base}refs/tags/${r}`,
    `${base}${r}`,
  ];
}

async function downloadFirstWorking(urls) {
  let lastErr = "";
  for (const u of urls) {
    assertAllowedUrl(u);
    const resp = await fetch(u, { redirect: "follow" });
    if (!resp.ok) {
      lastErr = `HTTP ${resp.status} from ${u}`;
      continue;
    }
    const ab = await resp.arrayBuffer();
    const buf = Buffer.from(ab);
    return { usedUrl: u, buf };
  }
  throw new Error(`Download failed. Last error: ${lastErr}`);
}

async function listTopLevelDirs(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return entries.filter((e) => e.isDirectory()).map((e) => e.name);
}

async function rmForce(p) {
  await fs.rm(p, { recursive: true, force: true });
}

async function moveDir(src, dst) {
  await rmForce(dst);
  try {
    await fs.rename(src, dst);
  } catch {
    // cross-device fallback
    await fs.cp(src, dst, { recursive: true });
    await rmForce(src);
  }
}

async function installLibrary(lib) {
  // lib: {id, url, ref?, rootFolder?, sha256?, version?}
  const { id, url, ref, rootFolder, sha256, version } = lib || {};
  if (!id || typeof id !== "string") throw new Error("Library missing id");
  if (!url || typeof url !== "string") throw new Error(`Library ${id} missing url`);

  await ensureDir(LIB_DIR);

  const expanded = expandGithubTarballUrls(url, ref);
  const { usedUrl, buf } = await downloadFirstWorking(expanded);

  const gotSha = sha256Hex(buf);
  if (sha256 && String(sha256).trim() && gotSha !== String(sha256).trim().toLowerCase()) {
    throw new Error(`SHA256 mismatch for ${id}. expected=${sha256} got=${gotSha}`);
  }

  const jobId = crypto.randomBytes(6).toString("hex");
  const workDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${jobId}-`));
  const archivePath = path.join(workDir, "lib.tar.gz");
  const extractDir = path.join(workDir, "extract");
  await ensureDir(extractDir);

  await fs.writeFile(archivePath, buf);

  // Extract (tar is the simplest + reliable on linux hosts)
  await execFileAsync("tar", ["-xzf", archivePath, "-C", extractDir], { timeout: 120000 });

  // Choose root folder
  let root = rootFolder && String(rootFolder).trim() ? String(rootFolder).trim() : null;
  if (root) {
    const p = path.join(extractDir, root);
    try {
      const st = await fs.stat(p);
      if (!st.isDirectory()) throw new Error();
    } catch {
      throw new Error(`Could not find rootFolder "${root}" inside extracted archive`);
    }
  } else {
    const tops = await listTopLevelDirs(extractDir);
    if (tops.length === 1) root = tops[0];
    else if (tops.length > 1) {
      // pick the one most likely to be the project folder (heuristic)
      root = tops.find((x) => x.toLowerCase().includes(id.toLowerCase())) || tops[0];
    } else {
      throw new Error("Archive extraction produced no top-level folders");
    }
  }

  // Install into stable folder: LIB_DIR/id
  const srcFolder = path.join(extractDir, root);
  const dstFolder = path.join(LIB_DIR, id);

  await moveDir(srcFolder, dstFolder);
  await rmForce(workDir);

  return {
    id,
    version: version || null,
    url,
    usedUrl,
    sha256: gotSha,
    rootFolder: root,
    installedAt: new Date().toISOString(),
    installPath: dstFolder,
  };
}

// ===== Routes =====
app.get("/health", (_req, res) => res.status(200).send("ok"));

app.get("/libraries", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });
    const db = await readDb();
    res.json({ ok: true, db, libDir: LIB_DIR, allowedHosts: ALLOWED_HOSTS });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Sync/install libraries (call this from Base44 server-side)
app.post("/libraries/sync", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const { libraries } = req.body || {};
    if (!Array.isArray(libraries) || libraries.length === 0) {
      return res.status(400).json({ ok: false, error: "Body must include libraries: []" });
    }

    const db = await readDb();
    const installed = [];

    for (const lib of libraries) {
      const meta = await installLibrary(lib);
      db.libraries[meta.id] = meta;
      installed.push(meta);
    }

    await writeDb(db);

    return res.json({ ok: true, installed, db });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Render OpenSCAD code to STL
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

    // Ensure OpenSCAD can find libs
    const env = {
      ...process.env,
      OPENSCADPATH: LIB_DIR,
    };

    // Export binary STL (smaller, faster)
    // If your OpenSCAD doesn't support binstl, change to "asciistl" or remove --export-format.
    const args = ["--export-format", "binstl", "-o", outFile, inFile];

    const { stdout, stderr } = await execFileAsync("openscad", args, {
      timeout: 120000,
      env,
      cwd: dir,
      maxBuffer: 10 * 1024 * 1024,
    });

    // Validate output exists and isn't tiny
    const st = await fs.stat(outFile);
    if (!st || st.size < 200) {
      return res.status(500).json({
        error: "STL output was empty/suspiciously small",
        details: { size: st?.size || 0, stdout, stderr },
      });
    }

    const stl = await fs.readFile(outFile);

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(stl);
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  } finally {
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, async () => {
  await ensureDir(LIB_DIR);
  console.log(`OpenSCAD render service running on :${port}`);
  console.log(`LIB_DIR=${LIB_DIR}`);
  console.log(`ALLOWED_HOSTS=${ALLOWED_HOSTS.join(",")}`);
});
