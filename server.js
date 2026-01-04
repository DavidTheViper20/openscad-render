import express from "express";
import fs from "fs/promises";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const app = express();

app.use(express.json({ limit: "10mb" }));

// =========================
// Config
// =========================
const TOKEN = process.env.OPENSCAD_RENDER_TOKEN || "";
const OPENSCAD_BIN = process.env.OPENSCAD_BIN || "openscad";
const OPENSCAD_TIMEOUT_MS = Number(process.env.OPENSCAD_TIMEOUT_MS || 120000);

const LIB_DIR = process.env.OPENSCAD_LIB_DIR || "/opt/openscad-libs";
const LIB_DB_PATH = process.env.OPENSCAD_LIB_DB_PATH || path.join(LIB_DIR, ".libdb.json");

// Optional: set for nicer display on /libraries
const RENDER_EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL || "";

// =========================
// Auth helpers
// =========================
function authOk(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  return h === `Bearer ${TOKEN}`;
}

// Browser-friendly: allow ?token=... for /libraries screen
function authOkOrQueryToken(req) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || "";
  if (h === `Bearer ${TOKEN}`) return true;
  if ((req.query?.token || "") === TOKEN) return true;
  return false;
}

// =========================
// Small utils
// =========================
function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function sha256Hex(buf) {
  const { createHash } = await import("crypto");
  return createHash("sha256").update(buf).digest("hex");
}

async function rmrf(p) {
  await fs.rm(p, { recursive: true, force: true });
}

async function ensureDir(p) {
  await fs.mkdir(p, { recursive: true });
}

async function exists(p) {
  try {
    await fs.stat(p);
    return true;
  } catch {
    return false;
  }
}

// Prefer fs.cp if available (Node 16+)
async function copyDir(src, dest) {
  await ensureDir(path.dirname(dest));
  if (typeof fs.cp === "function") {
    await fs.cp(src, dest, { recursive: true });
    return;
  }
  // fallback manual copy
  const entries = await fs.readdir(src, { withFileTypes: true });
  await ensureDir(dest);
  for (const e of entries) {
    const from = path.join(src, e.name);
    const to = path.join(dest, e.name);
    if (e.isDirectory()) await copyDir(from, to);
    else await fs.copyFile(from, to);
  }
}

// =========================
// Library DB
// =========================
async function readLibDb() {
  try {
    const raw = await fs.readFile(LIB_DB_PATH, "utf8");
    const db = JSON.parse(raw);
    if (!db || typeof db !== "object") throw new Error("Invalid DB");
    if (!db.libraries) db.libraries = {};
    return db;
  } catch {
    return { libraries: {} };
  }
}

async function writeLibDb(db) {
  await ensureDir(path.dirname(LIB_DB_PATH));
  await fs.writeFile(LIB_DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

// =========================
// Download + Extract
// =========================
function isGithubRepoUrl(u) {
  try {
    const url = new URL(u);
    return url.hostname === "github.com";
  } catch {
    return false;
  }
}

function parseGithubOwnerRepo(u) {
  const url = new URL(u);
  const parts = url.pathname.replace(/^\/+/, "").split("/");
  const owner = parts[0];
  const repo = (parts[1] || "").replace(/\.git$/, "");
  if (!owner || !repo) return null;
  return { owner, repo };
}

// Build a codeload URL for a github repo + ref
async function githubCodeloadUrl(repoUrl, ref) {
  const pr = parseGithubOwnerRepo(repoUrl);
  if (!pr) throw new Error("Invalid GitHub repo URL");
  const { owner, repo } = pr;

  // Try heads first, then tags (because we can’t know)
  const headUrl = `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${encodeURIComponent(ref)}`;
  const tagUrl = `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/tags/${encodeURIComponent(ref)}`;

  // HEAD check
  const r1 = await fetch(headUrl, { method: "HEAD" });
  if (r1.ok) return headUrl;

  const r2 = await fetch(tagUrl, { method: "HEAD" });
  if (r2.ok) return tagUrl;

  // If both fail, return headUrl so the error is at least deterministic
  return headUrl;
}

async function downloadToBuffer(url) {
  const resp = await fetch(url, { redirect: "follow" });
  if (!resp.ok) {
    throw new Error(`Download failed ${resp.status} from ${url}`);
  }
  const ab = await resp.arrayBuffer();
  return Buffer.from(ab);
}

async function extractTarGz(archivePath, destDir) {
  await ensureDir(destDir);
  try {
    await execFileAsync("tar", ["-xzf", archivePath, "-C", destDir], { timeout: 120000 });
  } catch (e) {
    const msg = e?.stderr || e?.stdout || e?.message || String(e);
    throw new Error(`Extract failed: ${msg}`);
  }
}

async function listTopLevelDirs(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return entries.filter((e) => e.isDirectory()).map((e) => e.name);
}

async function installOneLibrary(lib) {
  const {
    id,
    url,
    ref = null,
    rootFolder = null,
    version = null,
    sha256 = null
  } = lib || {};

  if (!id || typeof id !== "string") throw new Error("Library missing id");
  if (!url || typeof url !== "string") throw new Error(`Library ${id} missing url`);

  await ensureDir(LIB_DIR);

  // Build the actual download URL
  let usedUrl = url;
  if (isGithubRepoUrl(url)) {
    const refToUse = ref || "master";
    usedUrl = await githubCodeloadUrl(url, refToUse);
  }

  // Download
  const buf = await downloadToBuffer(usedUrl);
  const gotSha = await sha256Hex(buf);

  if (sha256 && String(sha256).toLowerCase() !== gotSha.toLowerCase()) {
    throw new Error(`SHA256 mismatch for ${id}. expected=${sha256} got=${gotSha}`);
  }

  // Temp workspace
  const jobId = crypto.randomBytes(6).toString("hex");
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `lib-${id}-${jobId}-`));
  const archivePath = path.join(tmpDir, "lib.tar.gz");
  const extractDir = path.join(tmpDir, "extract");

  await fs.writeFile(archivePath, buf);
  await extractTarGz(archivePath, extractDir);

  // Find root folder
  let rf = rootFolder;
  if (!rf) {
    const tops = await listTopLevelDirs(extractDir);
    if (tops.length === 1) rf = tops[0];
  }
  if (!rf) {
    const tops = await listTopLevelDirs(extractDir);
    throw new Error(`Could not auto-detect rootFolder. Top-level dirs: ${tops.join(", ") || "(none)"}`);
  }

  const rfPath = path.join(extractDir, rf);
  if (!(await exists(rfPath))) {
    throw new Error(`Could not find rootFolder "${rf}" inside extracted archive`);
  }

  // Install to LIB_DIR/<id>/...
  const dest = path.join(LIB_DIR, id);
  await rmrf(dest);
  await copyDir(rfPath, dest);

  // Record DB
  const db = await readLibDb();
  db.libraries[id] = {
    id,
    version,
    url,
    usedUrl,
    sha256: gotSha,
    rootFolder: rf,
    installedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastError: null
  };
  await writeLibDb(db);

  // Cleanup temp (best-effort)
  await rmrf(tmpDir);

  return db.libraries[id];
}

// =========================
// Routes
// =========================
app.get("/health", (_req, res) => res.status(200).send("ok"));

// ---- Render STL ----
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

    // IMPORTANT: add library path via OPENSCADPATH so "use <MCAD/...>" works
    const env = { ...process.env };
    const existing = env.OPENSCADPATH || "";
    env.OPENSCADPATH = existing
      ? `${LIB_DIR}${path.delimiter}${existing}`
      : `${LIB_DIR}`;

    // NOTE: do NOT pass --enable=manifold (your OpenSCAD build doesn’t support it)
    await execFileAsync(
      OPENSCAD_BIN,
      ["-o", outFile, inFile],
      { timeout: OPENSCAD_TIMEOUT_MS, env }
    );

    const stl = await fs.readFile(outFile);

    res.setHeader("Content-Type", "application/sla");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(stl);
  } catch (e) {
    // If execFile failed, include stderr if available
    const msg =
      e?.stderr?.toString?.() ||
      e?.stdout?.toString?.() ||
      e?.message ||
      String(e);

    return res.status(500).json({ error: msg });
  } finally {
    if (dir) await rmrf(dir);
  }
});

// ---- Sync libraries (downloads/extracts into OPENSCAD_LIB_DIR) ----
app.post("/libraries/sync", async (req, res) => {
  try {
    if (!authOk(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const { libraries } = req.body || {};
    if (!Array.isArray(libraries) || libraries.length === 0) {
      return res.status(400).json({ ok: false, error: "Body must include libraries: []" });
    }

    const installed = [];
    const errors = [];

    // Install sequentially to keep logs simple
    for (const lib of libraries) {
      try {
        const rec = await installOneLibrary(lib);
        installed.push(rec);
      } catch (err) {
        const id = lib?.id || "(unknown)";
        const message = String(err?.message || err);

        // Store lastError in DB
        const db = await readLibDb();
        db.libraries[id] = {
          ...(db.libraries[id] || {}),
          id,
          url: lib?.url || db.libraries[id]?.url || null,
          usedUrl: db.libraries[id]?.usedUrl || null,
          version: lib?.version ?? db.libraries[id]?.version ?? null,
          rootFolder: lib?.rootFolder ?? db.libraries[id]?.rootFolder ?? null,
          sha256: db.libraries[id]?.sha256 ?? null,
          updatedAt: new Date().toISOString(),
          lastError: message
        };
        await writeLibDb(db);

        errors.push({ id, error: message });
      }
    }

    const db = await readLibDb();
    return res.json({
      ok: errors.length === 0,
      installed,
      errors,
      db
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// ---- Status JSON ----
app.get("/libraries/status", async (req, res) => {
  try {
    if (!authOkOrQueryToken(req)) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const db = await readLibDb();
    const libs = Object.values(db.libraries || {}).sort((a, b) =>
      String(a.id || "").localeCompare(String(b.id || ""))
    );

    return res.json({
      ok: true,
      count: libs.length,
      dbPath: LIB_DB_PATH,
      libDir: LIB_DIR,
      libraries: libs
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// ---- Simple mobile-friendly status page ----
app.get("/libraries", async (req, res) => {
  try {
    if (!authOkOrQueryToken(req)) {
      return res
        .status(401)
        .type("html")
        .send(`<h2>Unauthorized</h2><p>Open <code>/libraries?token=YOUR_TOKEN</code> or send an Authorization header.</p>`);
    }

    const tokenParam = TOKEN ? `?token=${encodeURIComponent(req.query?.token || "")}` : "";
    return res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenSCAD Library Status</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
           background:#0b1020; color:#e5e7eb; }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 16px; }
    .card { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);
            border-radius: 14px; padding: 14px; box-shadow: 0 10px 30px rgba(0,0,0,0.25); }
    h1 { font-size: 18px; margin: 0 0 8px; }
    .meta { display:flex; gap:10px; flex-wrap:wrap; font-size: 12px; color:#a5b4fc; margin-bottom: 10px; }
    .pill { background: rgba(99,102,241,0.18); border: 1px solid rgba(99,102,241,0.35);
            padding: 4px 8px; border-radius: 999px; }
    table { width:100%; border-collapse: collapse; overflow:hidden; border-radius: 12px; }
    th, td { text-align:left; padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.10); font-size: 13px; vertical-align: top; }
    th { color:#c7d2fe; font-weight: 600; position: sticky; top: 0; background: rgba(11,16,32,0.95); }
    .ok { color:#34d399; font-weight: 600; }
    .bad { color:#fb7185; font-weight: 600; }
    .muted { color:#94a3b8; font-size: 12px; }
    .url { word-break: break-all; }
    .row { display:flex; gap:12px; flex-wrap:wrap; align-items:center; justify-content:space-between; margin-bottom: 10px; }
    button { background:#6366f1; border:none; color:white; padding:10px 12px; border-radius: 10px; font-weight: 600; cursor:pointer; }
    button:active { transform: translateY(1px); }
    @media (max-width: 720px) {
      th:nth-child(4), td:nth-child(4),
      th:nth-child(5), td:nth-child(5) { display:none; }
      th, td { padding: 8px; font-size: 12px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="row">
        <div>
          <h1>OpenSCAD Library Status</h1>
          <div class="meta">
            <span class="pill">Render: ${escapeHtml(RENDER_EXTERNAL_URL) || "—"}</span>
            <span class="pill">LIB_DIR: ${escapeHtml(LIB_DIR)}</span>
            <span class="pill">DB: ${escapeHtml(LIB_DB_PATH)}</span>
            <span class="pill" id="count">Loading…</span>
            <span class="pill" id="updated">—</span>
          </div>
        </div>
        <div><button onclick="load()">Refresh</button></div>
      </div>

      <table>
        <thead>
          <tr>
            <th style="width: 160px;">Library</th>
            <th>Status</th>
            <th>Installed At</th>
            <th>Root Folder</th>
            <th>SHA256</th>
            <th>Source URL</th>
          </tr>
        </thead>
        <tbody id="tbody">
          <tr><td colspan="6" class="muted">Loading…</td></tr>
        </tbody>
      </table>

      <p class="muted" style="margin-top:10px">
        Auto-refreshes every 5 seconds.
      </p>
    </div>
  </div>

<script>
  const statusUrl = "/libraries/status${tokenParam}";
  function fmtDate(s) {
    if (!s) return "—";
    const d = new Date(s);
    return isNaN(d.getTime()) ? String(s) : d.toLocaleString();
  }
  function esc(s) {
    return String(s || "")
      .replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")
      .replaceAll('"',"&quot;").replaceAll("'","&#039;");
  }

  async function load() {
    try {
      const res = await fetch(statusUrl, { cache: "no-store" });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "Failed");

      document.getElementById("count").textContent = \`\${data.count} libraries\`;
      document.getElementById("updated").textContent = "Updated: " + new Date().toLocaleTimeString();

      const rows = (data.libraries || []).map(l => {
        const installed = !!l.installedAt;
        const status = installed ? '<span class="ok">Installed</span>' : '<span class="bad">Missing</span>';
        const err = l.lastError ? ('<div class="bad muted" style="margin-top:4px;">' + esc(l.lastError) + '</div>') : '';
        const shaShort = l.sha256 ? (String(l.sha256).slice(0, 16) + "…") : "—";
        return \`
          <tr>
            <td><strong>\${esc(l.id || "")}</strong><div class="muted">\${esc(l.version || "")}</div></td>
            <td>\${status}\${err}</td>
            <td>\${esc(fmtDate(l.installedAt))}</td>
            <td>\${esc(l.rootFolder || "—")}</td>
            <td class="muted">\${esc(shaShort)}</td>
            <td class="url muted">\${esc(l.usedUrl || l.url || "—")}</td>
          </tr>
        \`;
      }).join("");

      document.getElementById("tbody").innerHTML =
        rows || '<tr><td colspan="6" class="muted">No libraries installed yet.</td></tr>';
    } catch (e) {
      document.getElementById("tbody").innerHTML =
        '<tr><td colspan="6" class="bad">Failed to load: ' + esc(String(e.message || e)) + '</td></tr>';
    }
  }

  load();
  setInterval(load, 5000);
</script>
</body>
</html>`);
  } catch (e) {
    return res.status(500).type("html").send(`<pre>${escapeHtml(String(e?.message || e))}</pre>`);
  }
});

// =========================
// Start
// =========================
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`OpenSCAD render service running on :${port}`);
  console.log(`LIB_DIR=${LIB_DIR}`);
  console.log(`LIB_DB_PATH=${LIB_DB_PATH}`);
});
