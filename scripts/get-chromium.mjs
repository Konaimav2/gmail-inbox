#!/usr/bin/env node
// get-chromium: vendor a project-local Chromium into .chromium/ (gitignored) so the
// login batch needs no system chrome package — only VNC/Xvfb stay external.
// Downloads the stable chrome-for-testing linux64 build (~160MB), extracts with
// `unzip` (fallback: python3 zipfile), verifies --version.
// Usage: node scripts/get-chromium.mjs [--force]
import { execFileSync, spawnSync } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, chmodSync, rmSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEST = join(ROOT, ".chromium");
const BIN = join(DEST, "chrome-linux64", "chrome");
const API = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";
const MAX_BYTES = 300 * 1024 * 1024;

const log = (s) => console.log(`[${new Date().toISOString().slice(11, 19)}] ${s}`);
const sh = (c, a = []) => spawnSync(c, a, { encoding: "utf8" });

if (existsSync(BIN) && !process.argv.includes("--force")) {
  try {
    const v = execFileSync(BIN, ["--version"], { encoding: "utf8" }).trim();
    log(`local chromium OK: ${BIN} (${v}) — pass --force to re-download`);
    process.exit(0);
  } catch { log("local binary broken — re-downloading..."); }
}
log("resolving stable chrome-for-testing build...");
const meta = await (await fetch(API)).json();
const stable = meta?.channels?.Stable;
const dl = stable?.downloads?.chrome?.find((d) => d.platform === "linux64");
if (!dl?.url) { log("!! could not resolve download URL"); process.exit(1); }
log(`stable ${stable.version}: ${dl.url}`);
mkdirSync(DEST, { recursive: true, mode: 0o700 });
const zip = join(DEST, "chrome-linux64.zip");
log("downloading (~160MB)...");
{
  const res = await fetch(dl.url);
  if (!res.ok) { log(`!! download http ${res.status}`); process.exit(1); }
  const total = +(res.headers.get("content-length") || 0);
  if (total > MAX_BYTES) { log(`!! archive too big (${total})`); process.exit(1); }
  await new Promise((res2, rej) => {
    const f = createWriteStream(zip, { mode: 0o600 });
    let n = 0;
    (async () => {
      try {
        for await (const c of res.body) {
          n += c.length;
          if (n > MAX_BYTES) throw new Error("archive too big");
          if (!f.write(c)) await new Promise((r) => f.once("drain", r));
        }
        f.end(() => res2());
      } catch (e) { try { f.destroy(); } catch {} rej(e); }
    })();
    f.on("error", rej);
  });
  log(`saved ${(statSync(zip).size / 1048576).toFixed(1)}MB`);
}
log("extracting...");
let ok = false;
if (sh("unzip", ["-q", "-o", zip, "-d", DEST]).status === 0) ok = true;
else {
  log("unzip missing — trying python3 zipfile...");
  ok = sh("python3", ["-c", `import zipfile;zipfile.ZipFile(${JSON.stringify(zip)}).extractall(${JSON.stringify(DEST)})`]).status === 0;
}
if (!ok || !existsSync(BIN)) { log("!! extraction failed"); process.exit(1); }
rmSync(zip);
chmodSync(BIN, 0o755);
const ver = execFileSync(BIN, ["--version"], { encoding: "utf8" }).trim();
log(`done: ${BIN} (${ver}) — run-batch picks it up automatically (or CHROME_BIN=...)`);
