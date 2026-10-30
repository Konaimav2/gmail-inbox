#!/usr/bin/env node
// run-batch: semi-auto Gmail login batch from list.txt (email|password|2fa token optional)
// Flow: setup VNC+Chromium -> count accounts -> loop: login, handle challenge (phone-tap / passkey / code / selfie-home-phone skips), save cookies, next.
// VNC/Xvfb exist ONLY for run-batch interactive challenges (QR/captcha/phone-tap human assist).
// Mail fetch never spawns a browser (it is HTTP elsewhere); VNC stack is batch-only.
import { execSync, spawnSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import { readdirSync as fsReaddir } from "node:fs";
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync, rmSync, appendFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runLogPath, appendLine, shotPath, ensureDir } from "./lib/runlog.mjs";

process.umask(0o077);
const maskSecret = (s) => String(s || "").slice(0, 2) + "****";
const maskCode = (s) => String(s || "").slice(0, 2) + "****";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// Browser binary order: $CHROME_BIN > project-local .chromium/ (scripts/get-chromium.mjs,
// no system package needed) > system chrome > agent-browser cache.
// Local-first so the batch is self-contained (only VNC/Xvfb remain external) and the
// binary + flags are managed in one place (baseChromeArgs + $CHROME_ARGS).
const LOCAL_CHROME = join(ROOT, ".chromium");
const CHROME_CANDIDATES = [
  process.env.CHROME_BIN || "",
  join(LOCAL_CHROME, "chrome-real", "opt", "google", "chrome", "chrome"), // real stable (get-chromium default)
  join(LOCAL_CHROME, "chrome-linux64", "chrome"), // chrome-for-testing (--testing)
  join(LOCAL_CHROME, "chrome-linux", "chrome"),
  join(LOCAL_CHROME, "chrome"),
  "/root/.agent-browser/browsers/chrome-150.0.7871.46/chrome",
  "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "/usr/bin/chromium-browser",
].filter(Boolean);
const CHROME = (() => {
  for (const c of CHROME_CANDIDATES) {
    try { const p = spawnSync("bash", ["-c", `command -v '${c}'`], { encoding: "utf8" }).stdout.trim(); if (p) return p; } catch {}
    if (existsSync(c)) return c;
  }
  return "chromium";
})();
// Lightweight ladder: low-memory flags for both headful and headless Chrome, plus
// component/feature trims so the vendored binary stays lean. $CHROME_ARGS (space-
// separated) appends operator tweaks without editing the script.
// NOTE: images stay ENABLED — disabling them breaks reCAPTCHA widgets and QR codes.
const LOWMEM_ARGS = ["--disable-dev-shm-usage", "--disable-gpu"];
const LEAN_ARGS = ["--disable-component-update", "--disable-sync", "--no-default-browser-check", "--disable-features=Translate,MediaRouter,OptimizationHints", "--disable-blink-features=AutomationControlled"];
const EXTRA_ARGS = (process.env.CHROME_ARGS || "").split(/\s+/).filter(Boolean);
// Detect chrome-headless-shell binary (sibling of CHROME candidates) for --no-vnc runs; fallback to headless Chrome.
const CHROME_HEADLESS_SHELL = (() => {
  try { const p = spawnSync("bash", ["-c", `command -v 'chrome-headless-shell'`], { encoding: "utf8" }).stdout.trim(); if (p && existsSync(p)) return p; } catch {}
  try { const s = join(dirname(CHROME), "chrome-headless-shell"); if (existsSync(s)) return s; } catch {}
  for (const c of CHROME_CANDIDATES) {
    try { if (String(c).includes("/")) { const s = join(dirname(String(c)), "chrome-headless-shell"); if (existsSync(s)) return s; } } catch {}
  }
  return null;
})();
const chromeBinary = (headless) => (headless && CHROME_HEADLESS_SHELL ? CHROME_HEADLESS_SHELL : CHROME);
function baseChromeArgsRaw(headless) {
  const a = [`--user-data-dir=${PROFILE}`, "--no-sandbox", "--no-first-run", "--disable-background-networking", "--window-size=1366,900", "--remote-debugging-port=9222", ...LOWMEM_ARGS, ...LEAN_ARGS, ...EXTRA_ARGS];
  if (headless) a.push("--headless=new");
  a.push("about:blank");
  return a;
}
// P2-1 one browser per batch: periodic hard restart cadence (Google 8-account session cap).
// Reuse the single Chrome across accounts; hard-restart only on CDP-unreachable, proxy switch,
// or every BROWSER_RESTART_EVERY accounts (default 8, env override).
const BROWSER_RESTART_EVERY = Math.max(1, parseInt(process.env.BROWSER_RESTART_EVERY || "1", 10) || 8);
let CURRENT_PROXY = null; // proxy the live browser was started with (null = direct)
let ACCOUNTS_SINCE_RESTART = 0;
let BROWSER_STARTED = false;
const PROFILE_BASE = join(ROOT, ".chrome-profiles");
let PROFILE = join(ROOT, ".chrome-profile");
let CURRENT_EMAIL = null;
function profileFor(email) {
  return join(PROFILE_BASE, String(email || "default").toLowerCase().replace(/[^a-z0-9._-]/g, "_"));
}
const COOKIE_DIR = join(ROOT, "cookies");
import { buildTodo } from "./lib/todo.mjs";
const LIST_FILE = join(ROOT, "list.txt");
const LOGGED_FILE = join(ROOT, "logged.txt");
const RUN_LOGGED = new Set();
const VERIFY_WAIT_MS = Number(process.env.VERIFY_WAIT_MS || 30000);
const FAILED_FILE = join(ROOT, "failed.txt");
// VNC password: read from .env (VNC_PASSWORD), auto-generate + persist if missing
const ENV_FILE = join(ROOT, ".env");
function loadEnv() {
  const o = {};
  try { for (const l of readFileSync(ENV_FILE, "utf8").split("\n")) { const m = l.match(/^([A-Z0-9_]+)=(.*)$/); if (m) o[m[1]] = m[2]; } } catch {}
  return o;
}
function ensureVncPass() {
  const env = loadEnv();
  if (env.VNC_PASSWORD) return env.VNC_PASSWORD;
  const gen = "vnc" + crypto.randomBytes(8).toString("hex"); // random, not in examples
  try {
    let s = existsSync(ENV_FILE) ? readFileSync(ENV_FILE, "utf8") : "";
    if (!/^VNC_PASSWORD=/m.test(s)) { if (s && !s.endsWith("\n")) s += "\n"; s += `VNC_PASSWORD=${gen}\n`; }
    else s = s.replace(/^VNC_PASSWORD=.*$/m, `VNC_PASSWORD=${gen}`);
    writeFileSync(ENV_FILE, s, { mode: 0o600 });
  } catch {}
  return gen;
}
const VNCPASS = ensureVncPass(); // random per-install; never logged
function markFailed(email, reason, pw = "", tok = "") {
  void captureFailArtifacts(shotPath(ROOT, email, String(reason || "fail"))).catch(() => { });
  try {
    const cur = existsSync(FAILED_FILE) ? readFileSync(FAILED_FILE, "utf8") : "";
    const lines = cur.split("\n").filter((l) => !l.startsWith(email + "|"));
    // Per spec: From list.txt (email|pass|2fa) -> Success loggedmail(email|pass|2fa), Failed failed.txt(email|pass|2fa|reason)
    // Preserve full credential so account can be retried with the same 2FA token.
    const safeReason = String(reason ?? "").replace(/\|/g, " ");
    lines.push(pw ? `${email}|${pw}|${tok || ""}|${safeReason}` : `${email}|${safeReason}`);
    writeFileSync(FAILED_FILE, lines.join("\n") + "\n", { mode: 0o600 });
  } catch {}
}
function clearFailed(email) {
  try {
    const cur = existsSync(FAILED_FILE) ? readFileSync(FAILED_FILE, "utf8") : "";
    writeFileSync(FAILED_FILE, cur.split("\n").filter((l) => !l.startsWith(email + "|")).join("\n"), { mode: 0o600 });
  } catch {}
}
function parseLine(l) {
  const s = String(l == null ? "" : l).trim();
  const idx = s.indexOf("|");
  if (idx <= 0) return null;
  const email = s.slice(0, idx).trim();
  const parts = s.slice(idx + 1).split("|");
  while (parts.length && parts[parts.length - 1].trim() === "") parts.pop();
  const norm = (x) => String(x).replace(/\s+/g, "");
  const isTok = (x) => /^\d{1,8}$/.test(norm(x));
  const isB32 = (x) => /^[A-Z2-7]{16,}$/.test(norm(x).toUpperCase());
  const tail = () => parts[parts.length - 1];
  let reason = "";
  if (parts.length >= 3) {
    const last = tail().trim(), prev = parts[parts.length - 2].trim();
    if (last && !isTok(last) && !isB32(last) && (/\s/.test(last) || isTok(prev))) reason = parts.pop().trim();
  }
  let tok = "";
  if (parts.length >= 2 && isTok(tail())) tok = norm(parts.pop());
  let base32 = "";
  if (parts.length >= 2 && isB32(tail())) base32 = norm(parts.pop()).toUpperCase();
  const pw = parts.join("|").trim();
  if (!pw) return { email, pw: "", tok, reason, base32, secret: base32, bad: true };
  return { email, pw, tok, reason, base32, secret: base32 };
}
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";
// minimal cookie-jar fetch (mirrors server): follows redirects + applies Set-Cookie
async function fetchWithJar(cookies, url) {
  const rank = (c) => [c.domain.split(".").length, c.path ? c.path.length : 0, c.domain.startsWith(".") ? 0 : 1];
  const hdr = (jar) => {
    const best = new Map();
    for (const c of jar) { if (!c.domain || c.domain.indexOf("google.com") < 0) continue; if (!best.has(c.name) || rank(c) > rank(best.get(c.name))) best.set(c.name, c); }
    return [...best.values()].filter((c) => c.name !== "NID" && c.name !== "AEC").map((c) => `${c.name}=${c.value}`).join("; ");
  };
  let jar = [...cookies], cur = url;
  for (let hop = 0; hop < 6; hop++) {
    const res = await fetch(cur, { headers: { "User-Agent": UA, Cookie: hdr(jar) }, redirect: "manual" });
    for (const sc of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) {
      const [pair] = sc.split(";"); const eq = pair.indexOf("="); if (eq < 1) continue;
      const name = pair.slice(0, eq).trim(), value = pair.slice(eq + 1).trim();
      const dm = (sc.match(/Domain=([^;]+)/i) || [])[1] || "google.com";
      const pth = (sc.match(/Path=([^;]+)/i) || [])[1] || "/";
      const existing = jar.find((c) => c.name === name);
      // skip session-killers in-memory too: a cleared SID mid-chain would fake a dead verdict
      if (/^(SID|SSID|__Secure-1PSID|__Secure-3PSID|SAPISID|APISID|HSID|SSID)$/.test(name) && value.length < 20) continue;
      if (existing) existing.value = value; else if (value) jar.push({ name, value, domain: dm, path: pth, secure: /Secure/i.test(sc), expires: -1 });
    }
    if (res.status >= 300 && res.status < 400) { const loc = res.headers.get("location"); if (!loc) return { status: res.status, body: "" }; cur = new URL(loc, cur).toString(); continue; }
    return { status: res.status, body: await res.text(), jar };
  }
  return { status: 599, body: "" };
}
// true session check: simls payload present = actually signed in
async function cookieValidPath(f) {
  try {
    if (!existsSync(f)) return false;
    const ck = JSON.parse(readFileSync(f, "utf8"));
    const jar = (Array.isArray(ck) ? ck : []).filter((c) => c && c.name).map((c) => `${c.name}=${c.value}`).join("; ");
    if (!jar) return false;
    const r = await fetch("https://mail.google.com/mail/u/0/feed/atom/", {
      headers: { Cookie: jar, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36" },
      redirect: "manual",
    });
    if (r.status !== 200) return false;
    return /<feed|<entry/i.test(await r.text());
  } catch { return false; }
}
async function cookieValidDurable(email) {
  let ok = await cookieValid(email);
  for (let k = 0; k < 2 && !ok; k++) {
    try { await saveCookies(email); log("-> cookie re-export #" + (k + 1)); } catch {}
    await sleep(3000);
    ok = await cookieValid(email);
  }
  return ok;
}
async function cookieValid(email) {
  const cf = join(COOKIE_DIR, email.replace(/[@.]/g, "_") + ".json");
  for (let i = 0; i < 3; i++) {
    try { if (await cookieValidPath(cf)) return true; } catch {}
    if (i < 2) await sleep(5000);
  }
  return false;
}
async function gmailHumanWarmup() {
  const curUrl = (await evalJs("location.href")) || "";
  if (!/mail\.google\.com/.test(curUrl)) {
    log("-> warmup: buka Gmail dulu sebelum simpan cookie");
    await send("Page.navigate", { url: "https://mail.google.com/mail/u/0/#inbox" });
  }
  let ready = false;
  for (let i = 0; i < 25; i++) {
    await sleep(800);
    ready = !!(await evalJs("!!document.querySelector('[role=\"main\"], [gh=\"tl\"], table.F, [aria-label*=\"Inbox\"]')"));
    if (ready) break;
  }
  log(`-> warmup: Gmail ${ready ? "siap" : "(belum terkonfirmasi)"}`);
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: 620, y: 420 });
  await sleep(450);
  await send("Input.dispatchMouseEvent", { type: "mouseWheel", x: 620, y: 420, deltaX: 0, deltaY: 240 });
  await sleep(600);
  const navRaw = await evalJs(`(() => {
    const cands = [...document.querySelectorAll('a[href*="#inbox"], a[href*="inbox"], [role="link"]')]
      .filter((x) => /inbox|kotak masuk/i.test((x.innerText || x.getAttribute("aria-label") || "")))
      .filter((x) => { const r = x.getBoundingClientRect(); return r.width > 20 && r.height > 10; });
    if (!cands.length) return "";
    const el = cands[0]; const r = el.getBoundingClientRect();
    return JSON.stringify({ x: Math.round(r.x + r.width / 2), y: Math.round(r.y + r.height / 2), t: (el.innerText || el.getAttribute("aria-label") || "").trim().slice(0, 18) });
  })()`);
  if (navRaw) {
    const nv = JSON.parse(navRaw);
    await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: nv.x, y: nv.y });
    await sleep(160);
    await send("Input.dispatchMouseEvent", { type: "mousePressed", x: nv.x, y: nv.y, button: "left", clickCount: 1 });
    await sleep(80);
    await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: nv.x, y: nv.y, button: "left", clickCount: 1 });
    log(`-> warmup: klik menu "${nv.t}" @${nv.x},${nv.y}`);
  } else {
    log("!! warmup: menu Inbox nggak ketemu (lanjut save)");
  }
  await sleep(2600);
  await send("Input.dispatchMouseEvent", { type: "mouseWheel", x: 620, y: 460, deltaX: 0, deltaY: 180 });
  await sleep(1300);
  const warmUrl = (await evalJs("location.href")) || "";
  const atGmail = /mail\.google\.com\/mail/.test(warmUrl);
  log(`-> warmup: ${atGmail ? "Gmail kebuka" : "masih di " + warmUrl.slice(0, 60)}`);
}

async function atomStrict(email) {
  try {
    const f = join(COOKIE_DIR, String(email).toLowerCase().replace(/@/g, "_").replace(/\./g, "_") + ".json");
    if (!existsSync(f)) return false;
    const ck = JSON.parse(readFileSync(f, "utf8"));
    const jar = (Array.isArray(ck) ? ck : []).filter((c) => c && c.name).map((c) => `${c.name}=${c.value}`).join("; ");
    if (!jar) return false;
    const r = await fetch("https://mail.google.com/mail/u/0/feed/atom/", {
      headers: { Cookie: jar, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36" },
      redirect: "manual",
    });
    if (r.status !== 200) return false;
    const b = await r.text();
    return /<feed|<entry/i.test(b);
  } catch { return false; }
}

async function demoteDeadLogged() {
  try {
    if (!existsSync(LOGGED_FILE)) return;
    const lines = readFileSync(LOGGED_FILE, "utf8").split("\n").map((l) => l.trim()).filter(Boolean);
    if (!lines.length) return;
    const keep = [];
    let demoted = 0;
    for (const e of lines) {
      let ok = await atomStrict(e);
      if (!ok) { await new Promise((r) => setTimeout(r, 1500)); ok = await atomStrict(e); }
      if (ok) keep.push(e);
      else { markFailed(e, "cookie-dead"); demoted++; log(`-> demote ${e}: cookie mati -> failed.txt`); }
    }
    if (demoted) {
      writeFileSync(LOGGED_FILE, keep.length ? keep.join("\n") + "\n" : "");
      log(`-> demoted ${demoted} akun dari logged.txt (cookie 401)`);
    }
  } catch (e) { log("!! demote error: " + ((e && e.message) || e)); }
}
async function reconcileFailed() {
  try {
    for (const l of (existsSync(FAILED_FILE) ? readFileSync(FAILED_FILE, "utf8") : "").split("\n").filter(Boolean)) {
      const p = parseLine(l); if (!p) continue;
      if (await cookieValid(p.email)) {
        const lg = existsSync(LOGGED_FILE) ? readFileSync(LOGGED_FILE, "utf8") : "";
        if (!lg.split("\n").some((x) => { const f = x.split("|")[0].trim().toLowerCase(); return f === p.email.toLowerCase(); })) appendFileSync(LOGGED_FILE, `${p.email}|${p.pw}|${p.tok || ""}\n`, { mode: 0o600 });
        clearFailed(p.email);
      }
    }
    log("reconciled valid cookies");
  } catch {}
}
const DISPLAY = ":99";
const CDP = "http://127.0.0.1:9222";
const SHOTS_DIR = ensureDir(join(ROOT, "screenshots"));
const OUT = process.env.RUN_LOG || runLogPath(ROOT, "run-batch");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
mkdirSync(COOKIE_DIR, { recursive: true, mode: 0o700 });
const ts = () => new Date().toISOString().slice(11, 19); // HH:MM:SS (UTC) on every line
const log = (s) => { const line = `[${ts()}] ${s}`; console.log(line); try { appendFileSync(OUT, line + "\n", { mode: 0o600 }); } catch {} };
log(`=== run-batch start ${new Date().toISOString()} ===`);
log(`-> log file: ${OUT}`);
log(`-> shots dir: ${SHOTS_DIR}`);
const sh = (cmd, opts = {}) => { try { return spawnSync("bash", ["-c", cmd], { encoding: "utf8", ...opts }).stdout.trim(); } catch { return ""; } };
const UID = sh("id -u") || String(process.getuid?.() ?? "");

// ------------------------------------------------ setup
log("-> Checking dependencies....");
let missing = [];
if (!existsSync(CHROME)) missing.push("chromium");
if (!sh("which x11vnc")) missing.push("x11vnc");
// websockify: resolve real binary path (venv/global), spawn by resolved path (not bare name)
const WEBSOCKIFY = (() => {
  const c = [
    sh("command -v websockify || true"),
    "/usr/local/lib/hermes-agent/venv/bin/websockify",
    "/usr/bin/websockify",
    "/usr/local/bin/websockify",
  ].map((x) => x && x.trim()).filter(Boolean);
  for (const p of c) if (existsSync(p)) return p;
  // maybe it's a python module: `python -m websockify`
  const py = sh("command -v python3 || true");
  if (py && existsSync(py)) {
    const probe = `${py} -m websockify --help 2>/dev/null`;
    if (sh(probe + " && echo WSOK").includes("WSOK")) return `${py} -m websockify`;
  }
  return null;
})();
if (!WEBSOCKIFY) missing.push("websockify");
if (!existsSync("/opt/noVNC")) missing.push("noVNC");
if (missing.length) {
  log(`-> Installing missing dependencies.... (${missing.join(", ")})`);
  if (missing.includes("x11vnc")) { log(sh("apt-get install -y x11vnc 2>&1 | tail -1")); }
  if (missing.includes("websockify")) { log(sh("pip install --break-system-packages -q websockify 2>&1 | tail -1")); }
  if (missing.includes("noVNC")) { log(sh("git clone --depth 1 https://github.com/novnc/noVNC /opt/noVNC 2>&1 | tail -1")); sh("ln -sf vnc.html /opt/noVNC/index.html"); }
  if (missing.includes("chromium")) { log("!! chromium missing, cannot proceed"); process.exit(1); }
}
const VNC_BIND = (loadEnv().VNC_BIND || "127.0.0.1"); // configurable via .env
const VNC_PORT = String(loadEnv().VNC_PORT || "6080"); // noVNC/websockify port, configurable via .env
if (!["127.0.0.1", "localhost", "::1"].includes(VNC_BIND)) log(`!! VNC_BIND=${VNC_BIND} is non-loopback — no TLS on :${VNC_PORT}, use SSH tunnel`);
// ensure /opt/noVNC/index.html -> vnc.html for convenience (http://ip:${VNC_PORT}/ serves viewer directly)
try { sh("ln -sf vnc.html /opt/noVNC/index.html"); } catch {}
log("-> Setting up VNC and Chromium....");
const NO_VNC_FLAG = process.argv.slice(2).includes("--no-vnc");
// --xvfb: headful Chrome under Xvfb WITHOUT the VNC viewer (no x11vnc/websockify).
// Renders like a real desktop browser (far less "insecure browser" flagging than
// --headless=new) while needing no viewer and no human. Phone-tap + TOTP still work.
const XVFB_FLAG = process.argv.slice(2).includes("--xvfb") || !!process.env.XVFB_ONLY;
const USE_SECURITY_CODE = process.argv.slice(2).includes("--security-code") || !!process.env.USE_SECURITY_CODE;
if (!NO_VNC_FLAG && !XVFB_FLAG) {
  log("-> Mode: VNC headful (default — watch + assist in the viewer; --xvfb/--no-vnc opt out)");
  sh(`pkill -u ${UID} -f "[X]vfb ${DISPLAY}" ; pkill -u ${UID} -f "[r]emote-debugging-port=9222" ; pkill -u ${UID} -f "[x]11vnc -display ${DISPLAY}" ; pkill -u ${UID} -f "[w]ebsockify ${VNC_PORT}" ; pkill -u ${UID} -f "[c]hromium-browser --no-sandbox" ; sleep 1`);
} else {
  log("-> --no-vnc: VNC/Xvfb disabled (headless Chrome only)");
}
// ---- VM / machine preflight: fail fast with a clear reason instead of crashing mid-batch ----
function preflight() {
  const problems = [];
  // 1. display: headful Chrome + VNC need an X server (Xvfb)
  if (!sh("which Xvfb") && !sh("which Xorg")) problems.push("no Xvfb/Xorg (cannot run headful Chrome/VNC)");
  // 2. shared memory / sandbox: Chrome in containers often needs /dev/shm or --no-sandbox
  const shm = sh("df -k /dev/shm 2>/dev/null | awk 'NR==2{print $4}'");
  if (shm && +shm < 1024 * 64) problems.push("low /dev/shm (" + shm + "KB) — Chrome may crash; mount shm or pass --disable-dev-shm-usage");
  // 3. memory: VNC+Chrome+Xvfb want ~1GB free (override via BATCH_MIN_RAM_MB;
  // swap-backed boxes can safely go lower — Chrome is the only big consumer)
  const minRamKB = Math.max(256 * 1024, parseInt(process.env.BATCH_MIN_RAM_MB || "", 10) * 1024 || 1024 * 1024);
  const memKB = sh("free -k | awk 'NR==2{print $7}'"); // available
  if (memKB && +memKB < minRamKB) problems.push("low free RAM (" + Math.round(memKB / 1024) + "MB) — need ~" + Math.round(minRamKB / 1024) + "MB+ (or set BATCH_MIN_RAM_MB)");
  // 4. CPU virt flags: not required (software GL works) but warn if machine likely can't handle it
  const cpu = sh("grep -c '^flags' /proc/cpuinfo");
  // 5. writable profile dir
  try { sh(`mkdir -p ${PROFILE} && touch ${PROFILE}/.wtest && rm -f ${PROFILE}/.wtest`); }
  catch { problems.push("cannot write Chrome profile dir " + PROFILE); }
  // 6. network reachability for the login host
  const net = sh("curl -s -o /dev/null -w '%{http_code}' -m 8 https://accounts.google.com 2>/dev/null");
  if (net !== "200" && net !== "302" && net !== "301") problems.push("cannot reach accounts.google.com (http " + (net || "timeout") + ")");
  return problems;
}
const pf = preflight();
if (pf.length) {
  log("!! Preflight FAILED — this machine cannot run the login batch:");
  for (const p of pf) log("    - " + p);
  log("   Resolve the above, or run on a machine/VM with a display, ~1GB+ RAM and network to Google.");
  process.exit(1);
} else {
  log("-> Preflight OK (display, shm, RAM, profile, network).");
}
const KEEP_PROFILE_SESSION = !process.argv.includes("--fresh-profile");
if (KEEP_PROFILE_SESSION) log("-> profile session DIPERTAHANKAN (Cookies + Local Storage; device continuity)");
else sh(`rm -rf ${PROFILE}/Default/Cookies* 2>/dev/null; true`);
const SPAWNED = [];
const detach = (cmd, args) => { const c = spawn(cmd, args, { detached: true, env: { ...process.env, DISPLAY }, stdio: ["ignore", "ignore", "ignore"] }); try { SPAWNED.push(c); } catch {} c.unref(); return c; };
if (!NO_VNC_FLAG) {
  detach("Xvfb", [DISPLAY, "-screen", "0", "1366x900x24", "-ac"]);
  await sleep(1500);
  detach(chromeBinary(false), baseChromeArgs(false));
  BROWSER_STARTED = true; CURRENT_PROXY = null; ACCOUNTS_SINCE_RESTART = 0;
  log(`-> Chrome binary/mode: ${chromeBinary(false)} (headful Chrome + low-mem flags)`);
  await sleep(2500);
  // x11vnc password via -passwdfile (0600 temp file, deleted after spawn) — never on cmdline
  const vncPassFile = join(ROOT, `.x11vnc-passwd-${process.pid}-${crypto.randomBytes(4).toString("hex")}`);
  try { writeFileSync(vncPassFile, VNCPASS + "\n", { mode: 0o600 }); } catch {}
  detach("x11vnc", ["-display", DISPLAY, "-localhost", "-forever", "-shared", "-noxdamage", "-passwdfile", vncPassFile, "-rfbport", "5900", "-bg", "-o", "/tmp/batch-x11vnc.log"]);
  await sleep(1500);
  try { unlinkSync(vncPassFile); } catch {}
  // WebSocket tunnel + noVNC web UI for human assistance (QR/captcha/phone).
  // --web=/opt/noVNC serves ONLY noVNC's own files (vnc.html, js, css) — NOT project files.
  // websockify may resolve to "python3 -m websockify" or a bare binary; detach expects (cmd, args)
  const [wsCmd, ...wsPre] = String(WEBSOCKIFY).split(" ");
  detach(wsCmd, [...wsPre, `--web=/opt/noVNC`, `${VNC_BIND}:${VNC_PORT}`, `localhost:5900`]);
  log(`-> VNC ready: http://${VNC_BIND}:${VNC_PORT}/  (password in .env VNC_PASSWORD)`);
  log("-> VNC stack is batch-only; mail fetch never spawns a browser");
} else if (XVFB_FLAG) {
  log("-> --xvfb: headful Chrome under Xvfb, no VNC viewer (human-like rendering, phone-tap/TOTP still work)...");
  detach("Xvfb", [DISPLAY, "-screen", "0", "1366x900x24", "-ac"]);
  await sleep(1500);
  detach(chromeBinary(false), baseChromeArgs(false));
  BROWSER_STARTED = true; CURRENT_PROXY = null; ACCOUNTS_SINCE_RESTART = 0;
  log(`-> Chrome binary/mode: ${chromeBinary(false)} (headful Xvfb, no VNC + low-mem flags)`);
  log("-> VNC stack is batch-only; mail fetch never spawns a browser");
  await sleep(2500);
} else {
  log("-> --no-vnc: skipping Xvfb/VNC, starting headless Chromium...");
  detach(chromeBinary(true), baseChromeArgs(true));
  BROWSER_STARTED = true; CURRENT_PROXY = null; ACCOUNTS_SINCE_RESTART = 0;
  log(`-> Chrome binary/mode: ${chromeBinary(true)} (${CHROME_HEADLESS_SHELL ? "chrome-headless-shell headless" : "headless Chrome fallback"} + low-mem flags)`);
  log("-> VNC stack is batch-only; mail fetch never spawns a browser");
  await sleep(2500);
}
// wait CDP
(async () => { for (let i = 0; i < 30; i++) { try { const t = await (await fetch(`${CDP}/json`)).json(); if (t.length) break; } catch {} await sleep(1000); } })();

// ------------------------------------------------ count accounts
log("-> Counting accounts....");
const lines = readFileSync(LIST_FILE, "utf8").split("\n").map((l) => l.trim()).filter(Boolean);
const accounts = [];
for (const l of lines) {
  const parsed = parseLine(l);
  if (!parsed || !parsed.pw) { markFailed(l.slice(0, 40), "bad format"); continue; }
  const email = parsed.email, pw = parsed.pw, tok = parsed.tok, secret = parsed.base32 || parsed.secret || "";
  if (parsed.base32) {
    try {
      const cur = existsSync(SECRETS_FILE) ? readFileSync(SECRETS_FILE, "utf8") : "";
      const known = cur.split("\n").some((row) => row.split("|")[0].trim() === email);
      if (!known) writeFileSync(SECRETS_FILE, cur + (cur && !cur.endsWith("\n") ? "\n" : "") + email + "|" + parsed.base32 + "\n");
    } catch (e) { }
  }
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) && pw) accounts.push({ email, pw, tok, secret });
  else markFailed(email || l.slice(0, 40), "bad format");
}
const invalid = lines.length - accounts.length;
log(`-> Find ${accounts.length} valid and ${invalid} invalid format! Setting the loop to ${accounts.length}....`);
    backupState("run");
await reconcileFailed();

// ------------------------------------------------ cdp helpers
let ws, send, sendS, pageTarget;
const oopif = new Map();
// stealth bundle: hide the automation signals Google's "browser may not be secure"
// verdict keys on. Injected before ANY page script via addScriptToEvaluateOnNewDocument.
// Paired with --disable-blink-features=AutomationControlled in baseChromeArgs.
const STEALTH = `(() => {
try {
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  window.chrome = window.chrome || {};
  window.chrome.runtime = window.chrome.runtime || {};
  window.chrome.app = window.chrome.app || { isInstalled: false };
  window.chrome.csi = window.chrome.csi || function () {};
  const mime = (type, suffixes, desc) => ({ type, suffixes, description: desc, enabledPlugin: null });
  const plug = (name, desc, mimes) => { const p = { name, description: desc, filename: 'internal-' + name.replace(/\\s/g, '') + '.so', length: mimes.length }; mimes.forEach((m, i) => { p[i] = m; m.enabledPlugin = p; }); return p; };
  const pdfMimes = [mime('application/pdf', 'pdf', 'Portable Document Format'), mime('text/pdf', 'pdf', 'Portable Document Format')];
  const plugins = [plug('Chrome PDF Viewer', 'Portable Document Format', pdfMimes), plug('Chromium PDF Viewer', 'Portable Document Format', pdfMimes)];
  Object.defineProperty(navigator, 'plugins', { get: () => plugins });
  Object.defineProperty(navigator, 'mimeTypes', { get: () => pdfMimes });
  Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
  Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
  Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
  const _query = (window.Permissions && window.Permissions.prototype.query) || null;
  if (_query) window.Permissions.prototype.query = function (p) {
    if (p && p.name === 'notifications') return Promise.resolve({ state: 'default', onchange: null });
    return _query.apply(this, arguments);
  };
  const _cpt = window.HTMLVideoElement && window.HTMLVideoElement.prototype.canPlayType;
  if (_cpt) window.HTMLVideoElement.prototype.canPlayType = function (t) {
    if (t && /mp4|avc1/.test(t)) return 'probably';
    return _cpt.apply(this, arguments);
  };
  try {
    Object.defineProperty(window, 'outerWidth', { get: () => window.innerWidth });
    Object.defineProperty(window, 'outerHeight', { get: () => window.innerHeight });
  } catch {}
  try {
    const _gp = window.WebGLRenderingContext && window.WebGLRenderingContext.prototype.getParameter;
    if (_gp) window.WebGLRenderingContext.prototype.getParameter = function (p) {
      if (p === 37445) return 'Intel Inc.';
      if (p === 37446) return 'Intel Iris OpenGL Engine';
      return _gp.apply(this, arguments);
    };
  } catch {}
} catch {}
})();`;
async function connectCDP() {
  for (let i = 0; i < 30; i++) {
    try {
      const targets = await (await fetch(`${CDP}/json`)).json();
      const pages = targets.filter((t) => t.type === "page" && /^https?:/.test(t.url) && !/workspace\.google\.com/.test(t.url));
      // close all other page tabs so we drive exactly one visible tab
      const keep = pages[0] || targets.find((t) => t.type === "page");
      if (!keep) throw 0;
      for (const t of targets.filter((x) => x.type === "page" && x.id !== keep.id)) {
        fetch(`${CDP}/json/close/${t.id}`).catch(() => {});
      }
      await sleep(800);
      pageTarget = keep;
      ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
      await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error("ws")); });
      let id = 0; const pending = new Map();
      oopif.clear();
      globalThis.__autoAttached = false;
      globalThis.__autoAttached = false;
      ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.method === "Target.attachedToTarget" && m.params) { oopif.set(m.params.sessionId, m.params.targetInfo || {}); } if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
      send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
      sendS = (method, params = {}, sessionId) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });
      await send("Page.enable"); await send("Runtime.enable"); await send("Network.enable");
      // normalize UA: --headless=new advertises "HeadlessChrome" in the UA string —
      // an instant automation tell. Rewrite to the stock desktop token.
      try {
        const uaR = await send("Runtime.evaluate", { expression: "navigator.userAgent", returnByValue: true });
        const ua = uaR?.result?.result?.value || "";
        if (/HeadlessChrome/i.test(ua)) await send("Network.setUserAgentOverride", { userAgent: ua.replace(/HeadlessChrome/g, "Chrome") });
      } catch {}
      await send("Page.addScriptToEvaluateOnNewDocument", { source: STEALTH });
      return;
    } catch { await sleep(1000); }
  }
  throw new Error("cdp unreachable");
}
async function evalJs(expr) {
  const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
  if (r.result?.exceptionDetails) return null;
  return r.result?.result?.value;
}
async function state() {
  const j = await evalJs(`(() => ({ url: location.href, title: document.title, inputs: [...document.querySelectorAll('input')].filter(i=>i.offsetParent!==null).map(i=>i.type+':'+(i.name||i.id)), text: document.body.innerText.slice(0, 20000), buttons: [...document.querySelectorAll('button,[role=button]')].map(b=>(b.innerText||'').trim()).filter(t=>t&&t.length<60) }))()`);
  return j || { url: "", title: "", text: "", buttons: [], inputs: [] };
}
async function setInput(sel, value) {
  // React-compatible value setter + events
  return await evalJs(`(() => { const el=document.querySelector(${JSON.stringify(sel)}); if(!el) return false; const setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set; setter.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); el.focus(); return true; })()`);
}
async function submitForm() {
  return await evalJs(`(() => { const f=document.querySelector('form'); if(!f) return false; if(f.requestSubmit) f.requestSubmit(); else f.submit(); return true; })()`);
}
async function typeChars(sel, value) {
  // human-paced keystrokes via CDP so React registers the value
  const focused = await evalJs(`(() => { const el=document.querySelector(${JSON.stringify(sel)}); if(!el) return false; el.focus(); el.click(); el.value=''; return true; })()`);
  if (!focused) return false;
  await sleep(400); // fixed
  for (const ch of value) {
    await send("Input.insertText", { text: ch });
    await sleep(40); // fixed keystroke pacing
  }
  await sleep(600); // fixed
  return true;
}
async function realClick(elExpr) {
  // trusted pointer event: Google material buttons IGNORE el.click(); CDP mouse works
  const c = await evalJs(`(() => { const el=${elExpr}; if(!el||el.offsetParent===null) return null; const b=el.getBoundingClientRect(); return {x:b.x+b.width/2, y:b.y+b.height/2}; })()`);
  if (!c) return false;
  await send("Input.dispatchMouseEvent", { type: "mousePressed", x: c.x, y: c.y, button: "left", clickCount: 1 });
  await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: c.x, y: c.y, button: "left", clickCount: 1 });
  return true;
}

// ── Audio reCAPTCHA auto-solver (VNC becomes OPTIONAL) ──
// Mirrors webshare's proven flow: find audio iframe/button -> trusted click ->
// extract mp3 -> transcribe via sibling audio-solver.py -> type answer -> verify.
// Returns true if the grecaptcha token appears (captcha solved), else false (caller can waitHuman).
async function findCaptchaTargets() {
  const raw = await evalJs(`(() => {
    const hits = [];
    const add = (el, kind, prio) => {
      if (!el || !el.getBoundingClientRect) return;
      const r = el.getBoundingClientRect();
      if (r.width < 20 || r.height < 20) return;
      const cs = getComputedStyle(el);
      if (cs.visibility === "hidden" || cs.display === "none" || parseFloat(cs.opacity) < 0.15) return;
      if (el.closest('[aria-hidden="true"]')) return;
      if (r.bottom < 0 || r.top > innerHeight || r.right < 0 || r.left > innerWidth) return;
      hits.push({ kind, prio, x: r.x, y: r.y, w: r.width, h: r.height, off: r.x > innerWidth * 0.58 ? 1 : 0 });
    };
    document.querySelectorAll("div[data-sitekey], div.g-recaptcha, div.h-captcha").forEach((el) => add(el, "sitekey", 0));
    document.querySelectorAll("iframe").forEach((el) => {
      const src = el.src || "";
      if (/bframe/i.test(src)) return;
      if (/recaptcha|hcaptcha/i.test(src)) return add(el, /anchor|checkbox/i.test(src) ? "anchor" : "iframe", 1);
      if (el.title && /captcha/i.test(el.title)) return add(el, "title", 2);
      if ((el.className || "").toString().match(/captcha|turnstile/i)) return add(el, "class", 3);
    });
    hits.sort((a, b) => (a.prio - b.prio) || (a.off - b.off) || (a.w * a.h - b.w * b.h));
    return JSON.stringify(hits.slice(0, 6));
  })()`);
  try { return JSON.parse(raw || "[]"); } catch { return []; }
}


const GRID_MODEL = process.env.CAPTCHA_VISION_MODEL || "deepseek-v4.1-flash";
const GRID_BASE = process.env.ROUTER9_BASE || "https://api.openai.com/v1";

function routerKey() {
  if (process.env.ROUTER9_API_KEY) return process.env.ROUTER9_API_KEY;
  if (process.env.OPENAI_API_KEY) return process.env.OPENAI_API_KEY;
  try {
    for (const line of readFileSync(join(ROOT, ".env"), "utf8").split("\n")) {
      const m = /^\s*ROUTER9_API_KEY\s*=\s*(.+?)\s*$/.exec(line);
      if (m) return m[1].replace(/^["']|["']$/g, "");
    }
  } catch {}
  return "";
}

async function bframeSession() {
  return oopif.size ? [...oopif.keys()] : null;
}

async function waitTilesLoaded(sid, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    let ok = false;
    try {
      const r = await sendS("Runtime.evaluate", { returnByValue: true, expression: `(() => { const im = [...document.querySelectorAll('[class*="rc-image-tile"]')]; const imgs = im.filter((x) => x.tagName === "IMG"); if (!imgs.length) return false; return imgs.every((x) => x.complete && x.naturalWidth > 0); })()` }, sid);
      ok = !!(r && r.result && r.result.result ? r.result.result.value : false);
    } catch {}
    if (ok) return true;
    await sleep(600);
  }
  return false;
}

async function gridState() {
  const EXPR = `(() => { const t = document.querySelector('[class*="rc-imageselect-table"]'); if (!t) return ""; const d = document.querySelector('[class*="rc-imageselect-desc"]'); const tiles = [...document.querySelectorAll('[class*="rc-imageselect-tile"]')].map((e) => { const b = e.getBoundingClientRect(); return { x: Math.round(b.x), y: Math.round(b.y), w: Math.round(b.width), h: Math.round(b.height) }; }); return JSON.stringify({ desc: d ? d.innerText : "", tiles, vw: document.documentElement.clientWidth, vh: document.documentElement.clientHeight }); })()`;
  for (const [sid, info] of oopif) {
    let v = "";
    try {
      const r = await sendS("Runtime.evaluate", { returnByValue: true, expression: EXPR }, sid);
      v = r && r.result && r.result.result ? r.result.result.value : "";
    } catch { continue; }
    if (!v) continue;
    const st = JSON.parse(v);
    st.sid = sid;
    st.url = (info && info.url) || "";
    st.frame = null;
    try {
      const raw = await evalJs(`(() => { const list = [...document.querySelectorAll("iframe")].filter((f) => (f.src || "").indexOf("bframe") >= 0); for (const f of list) { f.style.setProperty("position","fixed","important"); f.style.setProperty("left","0","important"); f.style.setProperty("top","0","important"); f.style.setProperty("width","400px","important"); f.style.setProperty("height","580px","important"); f.style.setProperty("z-index","2147483647","important"); f.style.setProperty("visibility","visible","important"); f.style.setProperty("opacity","1","important"); } const b = list.map((f) => { const r = f.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; }).filter((r) => r.w >= 300 && r.h >= 300); return JSON.stringify({ n: list.length, best: b[0] || null }); })()`);
      const parsed = raw ? JSON.parse(raw) : null;
      st.frame = parsed && parsed.best ? parsed.best : null;
      st.ifrN = parsed ? parsed.n : 0;
    } catch {}
    await waitTilesLoaded(sid, 15000);
    await sleep(250);
    return st;
  }
  return null;
}

async function shotClip(st, x, y, w, h) {
  if (!st.frame || !st.vw) return "";
  const sx = st.frame.w / st.vw;
  const sy = st.frame.h / st.vh;
  for (let k = 0; k < 3; k++) {
    try {
      const r = await send("Page.captureScreenshot", { format: "jpeg", quality: 88, clip: { x: st.frame.x + x * sx, y: st.frame.y + y * sy, width: w * sx, height: h * sy, scale: 2 } });
      const d = (r && r.result && r.result.data) || "";
      if (d && Buffer.from(d, "base64").length > 1500) return d;
    } catch {}
    await sleep(700);
  }
  return "";
}

async function clickTile(st, idx) {
  try {
    const r = await sendS("Runtime.evaluate", { returnByValue: true, expression: `(() => { const e = document.querySelectorAll('[class*="rc-imageselect-tile"]')[${idx}]; if (!e) return "no-el"; e.click(); const sel = [...document.querySelectorAll('[class*="rc-imageselect-tile"]')].filter((x) => /selected/i.test(x.className) || x.getAttribute("aria-checked") === "true").length; return "ok:" + sel; })()` }, st.sid);
    return (r && r.result && r.result.result ? r.result.result.value : "err") || "err";
  } catch { return "err"; }
}

async function visionYesNo(b64, target) {
  const key = routerKey();
  if (!key || !b64) return null;
  const body = { model: GRID_MODEL, max_tokens: 4, temperature: 0, messages: [{ role: "user", content: [
    { type: "text", text: `Does this photo show ${target}? Answer yes or no.` },
    { type: "image_url", image_url: { url: "data:image/jpeg;base64," + b64 } },
  ] }] };
  try {
    const res = await fetch(GRID_BASE + "/chat/completions", { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await res.json();
    const txt = String((j && j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || "").trim().toLowerCase();
    if (/^yes\b/.test(txt)) return true;
    if (/^no\b/.test(txt)) return false;
    return null;
  } catch { return null; }
}

async function visionDescribe(b64) {
  const key = routerKey();
  if (!key || !b64) return "";
  const body = {
    model: GRID_MODEL,
    max_tokens: 24,
    temperature: 0,
    messages: [{ role: "user", content: [
      { type: "text", text: "List the main objects in this photo, comma-separated, max 5 words. Reply NONE if blank." },
      { type: "image_url", image_url: { url: "data:image/jpeg;base64," + b64 } },
    ] }],
  };
  try {
    const res = await fetch(GRID_BASE + "/chat/completions", { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await res.json();
    return String((j && j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || "").replace(/\s+/g, " ").trim();
  } catch { return ""; }
}

function targetKeywords(target) {
  const t = String(target || "").toLowerCase().replace(/^(a|an|the)\s+/, "").trim();
  const map = {
    "fire hydrant": ["hydrant"], "fire hydrants": ["hydrant"],
    "traffic light": ["traffic light", "traffic signal", "signal"],
    "traffic lights": ["traffic light", "traffic signal", "signal"],
    bicycle: ["bicycle", "bike", "cyclist"], bicycles: ["bicycle", "bike", "cyclist"],
    motorcycle: ["motorcycle", "motorbike", "scooter"], motorcycles: ["motorcycle", "motorbike", "scooter"],
    bus: ["bus"], buses: ["bus"], car: ["car", "vehicle"], cars: ["car", "vehicle"],
    crosswalk: ["crosswalk", "zebra", "crossing"], "palm tree": ["palm"], "palm trees": ["palm"],
    stairs: ["stair", "step"], chimney: ["chimney"], "parking meter": ["parking meter"],
  };
  if (map[t]) return map[t];
  const sing = t.replace(/s$/, "");
  return [...new Set([t, sing, t + "s"])].filter(Boolean);
}

function descMatches(desc, target) {
  const d = String(desc || "").toLowerCase().trim();
  if (!d || d === "none") return false;
  return targetKeywords(target).some((k) => d.includes(k.toLowerCase()));
}

async function captchaSolveGrid(rounds = 3) {
  const waitGrid = async (tries) => {
    for (let i = 0; i < tries; i++) { const s = await gridState(); if (s) return s; await sleep(1200); }
    return null;
  };
  let st = await waitGrid(15);
  if (!st) { log(`-> grid: table nggak muncul (oopif=${oopif.size})`); return false; }
  for (let round = 1; round <= rounds; round++) {
    if (round > 1) { st = await waitGrid(10); if (!st) { log("-> grid: ronde selesai, grid hilang"); return true; } }
    const clean = String(st.desc || "").replace(/\s+/g, " ").replace(/if there are none.*$/i, "").replace(/click verify.*$/i, "").trim();
    const wm = /with\s+(.+)$/i.exec(clean);
    const target = (wm ? wm[1] : clean).replace(/[.,;]+$/, "").trim();
    log(`-> grid r${round}: "${target.slice(0, 30)}" (${st.tiles.length} tile, ifr=${st.ifrN}, frame=${st.frame ? "ok" : "NULL"})`);
    try { const fresh = await gridState(); if (fresh && fresh.frame) { st.frame = fresh.frame; st.vw = fresh.vw || st.vw; st.vh = fresh.vh || st.vh; } } catch {}
    const picks = [];
    for (let i = 0; i < st.tiles.length; i++) {
      const tl = st.tiles[i];
      const b64 = await shotClip(st, tl.x, tl.y, tl.w, tl.h);
      if (!b64) { log(`-> grid: tile ${i} screenshot gagal`); continue; }
      let hit = await visionYesNo(b64, target);
      let tag = hit === true ? "YES" : hit === false ? "no" : "?";
      if (hit === null) {
        const dsc = await visionDescribe(b64);
        hit = descMatches(dsc, target);
        tag = `?${dsc.slice(0, 26)}`;
      }
      log(`-> grid: tile ${i} ${hit ? "MATCH" : "-"} (${tag})`);
      if (hit) picks.push(i);
    }
    log(`-> grid: pilih ${picks.length}/${st.tiles.length} [${picks.join(",")}]`);
    if (!picks.length) { log("-> grid: nggak ada tile cocok — batal"); return false; }
    for (const i of picks) { const cr = await clickTile(st, i); await sleep(180); if (i === picks[picks.length - 1]) log(`-> grid: klik ${picks.length} tile (${cr})`); }
    await sleep(350);
    try {
      const vr = await sendS("Runtime.evaluate", { returnByValue: true, expression: `(() => { const b = document.querySelector('#recaptcha-verify-button'); if (!b) return "no-btn"; b.click(); return "ok"; })()` }, st.sid);
      log("-> grid: verify " + ((vr && vr.result && vr.result.result ? vr.result.result.value : "?") || "?"));
    } catch {}
    for (let w = 0; w < 6; w++) {
      await sleep(1200);
      let tok = "";
      try { tok = await evalJs(`(() => { const t = document.querySelector('textarea[name="g-recaptcha-response"], input[name="g-recaptcha-response"]'); return t ? String(t.value || "") : ""; })()`); } catch {}
      if (tok && String(tok).length > 20) { log(`-> grid: SOLVED (token ${String(tok).length} char)`); return true; }
      if (!(await gridState())) { log("-> grid: grid hilang, nunggu token"); return true; }
      try {
        const er = await sendS("Runtime.evaluate", { returnByValue: true, expression: `(() => { const e = document.querySelector('.rc-imageselect-incorrect-response'); return e ? String(e.innerText || "").slice(0, 60) : ""; })()` }, st.sid);
        const ev = (er && er.result && er.result.result ? er.result.result.value : "") || "";
        if (ev) log(`-> grid: google: "${ev}"`);
      } catch {}
    }
    log("-> grid: ronde berikutnya");
  }
  return false;
}

async function ensureAutoAttach() {
  if (globalThis.__autoAttached) return;
  globalThis.__autoAttached = true;
  try { await send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }); } catch {}
}

async function captchaChallengeCount() {
  let n = 0;
  try {
    n = Number(await evalJs(`[...document.querySelectorAll('iframe[src*="bframe"]')].filter(f => { const r = f.getBoundingClientRect(); const cs = getComputedStyle(f); return r.width > 100 && r.height > 100 && r.top > -50 && r.top < innerHeight && r.bottom > 0 && cs.visibility !== "hidden" && cs.display !== "none" && Number(cs.opacity || 1) > 0.05; }).length`)) || 0;
  } catch {}
  if (n) return n;
  for (const [sid, info] of oopif.entries()) {
    if (!/bframe/i.test(info.url || "")) continue;
    try {
      const r = await sendS("Runtime.evaluate", { returnByValue: true, expression: `(() => { const el = document.querySelector('#rc-imageselect, .rc-imageselect-table, .rc-audiochallenge-response, #audio-response, .rc-audiochallenge'); if (!el) return 0; const b = el.getBoundingClientRect(); return b.width > 100 && b.height > 80 ? 1 : 0; })()` }, sid);
      if (Number(r && r.result && r.result.result ? r.result.result.value : 0) === 1) return 1;
    } catch {}
  }
  return 0;
}

async function captchaOopifPoint() {
  await ensureAutoAttach();
  await sleep(500);
  const list = [...oopif.entries()].filter(([, info]) => /recaptcha|hcaptcha/i.test(info.url || "") && !/bframe/i.test(info.url || ""));
  for (const [sid, info] of list) {
    let v = null;
    try {
      const ev = await sendS("Runtime.evaluate", {
        returnByValue: true,
        expression: `(() => { const el = document.querySelector("#recaptcha-anchor") || document.querySelector(".recaptcha-checkbox"); if (!el) return ""; const r = el.getBoundingClientRect(); const d = document.documentElement; const cs = getComputedStyle(el); return JSON.stringify({ x: r.x + r.width / 2, y: r.y + r.height / 2, w: r.width, h: r.height, vw: d.clientWidth, vh: d.clientHeight, vis: cs.visibility !== "hidden" && cs.display !== "none" }); })()`,
      }, sid);
      v = (ev && ev.result && ev.result.result ? ev.result.result : {}).value;
    } catch {}
    if (!v) continue;
    let inner = null;
    try { inner = JSON.parse(v); } catch { continue; }
    if (!inner || !inner.vw || !inner.vh) continue;
    let irect = null;
    try {
      const raw = await evalJs(`(() => { const u = ${JSON.stringify(info.url)}; const f = [...document.querySelectorAll("iframe")].find((x) => (x.src || "") === u); if (!f) return ""; const b = f.getBoundingClientRect(); return JSON.stringify({ x: b.x, y: b.y, w: b.width, h: b.height }); })()`);
      if (raw) irect = JSON.parse(raw);
    } catch {}
    if (!irect || irect.w < 50 || irect.h < 40) continue;
    const sx = irect.w / inner.vw;
    const sy = irect.h / inner.vh;
    const pt = { x: Math.round(irect.x + inner.x * sx), y: Math.round(irect.y + inner.y * sy) };
    let hit = "?";
    try {
      hit = await evalJs(`(() => { const el = document.elementFromPoint(${pt.x}, ${pt.y}); if (!el) return "null"; const t = el.tagName.toLowerCase(); return t + (el.id ? "#" + el.id : "") + (el.className && typeof el.className === "string" ? "." + el.className.split(" ")[0] : "") + (el.src ? " src=" + String(el.src).slice(0, 40) : ""); })()`);
    } catch {}
    log(`-> captcha: OOPIF anchor ${pt.x},${pt.y} (iframe ${Math.round(irect.w)}x${Math.round(irect.h)} vis=${inner.vis ? 1 : 0}) hit=${String(hit).slice(0, 70)}`);
    return { x: pt.x, y: pt.y, fw: Math.round(irect.w), fh: Math.round(irect.h) };
  }
  return null;
}

async function captchaCheckboxPoint(retries = 6) {
  let domReady = false;
  for (let attempt = 0; attempt < retries; attempt++) {
    const seen = [];
    let usable = [];
    try {
      if (!domReady) { try { await send("DOM.enable"); domReady = true; } catch {} }
      let vp = { w: 0, h: 0 };
      try {
        const vr = await send("Runtime.evaluate", { expression: "JSON.stringify({ w: innerWidth, h: innerHeight })", returnByValue: true });
        const vraw = (vr && vr.result && vr.result.result ? vr.result.result : vr && vr.result ? vr.result : {}).value;
        if (vraw) vp = JSON.parse(vraw);
      } catch {}
      const tree = await send("Page.getFrameTree");
      const flat = [];
      const walk = (n) => { if (!n) return; flat.push(n.frame); for (const c of n.childFrames || []) walk(c); };
      walk((tree && tree.result ? tree.result : tree || {}).frameTree);
      const dbg = [];
      const mainId = flat.length ? flat[0].id : null;
      const cands = flat.filter((f) => f.id !== mainId && !/bframe/i.test(f.url || ""));
      for (const fr of cands) {
        let world = null;
        try { world = await send("Page.createIsolatedWorld", { frameId: fr.id, worldName: "capworld" }); } catch { continue; }
        const ctx = (world && world.result ? world.result : world || {}).executionContextId;
        if (!ctx) continue;
        let ev = null;
        try {
          ev = await send("Runtime.evaluate", {
            contextId: ctx,
            returnByValue: true,
            expression: `(() => { const el = document.querySelector("#recaptcha-anchor") || document.querySelector(".recaptcha-checkbox"); if (!el) return ""; const r = el.getBoundingClientRect(); const d = document.documentElement; const cs = getComputedStyle(el); return JSON.stringify({ x: r.x + r.width / 2, y: r.y + r.height / 2, w: r.width, h: r.height, vw: d.clientWidth, vh: d.clientHeight, vis: r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && cs.display !== "none" }); })()`,
          });
        } catch { continue; }
        const v = (ev && ev.result && ev.result.result ? ev.result.result : ev && ev.result ? ev.result : {}).value;
        if (!v) { dbg.push(`none:${(fr.url || "blank").slice(0, 48)}`); continue; }
        let inner = null;
        try { inner = JSON.parse(v); } catch { continue; }
        if (!inner || !inner.vw || !inner.vh || !inner.w || !inner.h) continue;
        let frect = null;
        try {
          const owner = await send("DOM.getFrameOwner", { frameId: fr.id });
          const bn = (owner && owner.result ? owner.result : owner || {}).backendNodeId;
          if (bn) {
            const box = await send("DOM.getBoxModel", { backendNodeId: bn });
            const q = (box && box.result ? box.result : box || {}).model ? ((box.result || box).model.border) : null;
            if (q && q.length >= 8) {
              const x0 = Math.min(q[0], q[2], q[4], q[6]);
              const y0 = Math.min(q[1], q[3], q[5], q[7]);
              const w0 = Math.max(q[0], q[2], q[4], q[6]) - x0;
              const h0 = Math.max(q[1], q[3], q[5], q[7]) - y0;
              if (w0 > 20 && h0 > 20) frect = { x: x0, y: y0, w: w0, h: h0 };
            }
          }
        } catch {}
        if (!frect) continue;
        const sx = frect.w / inner.vw;
        const sy = frect.h / inner.vh;
        const inView = frect.x + frect.w > 0 && frect.y + frect.h > 0 && frect.x < vp.w && frect.y < vp.h;
        const pt = {
          x: Math.round(frect.x + inner.x * sx),
          y: Math.round(frect.y + inner.y * sy),
          vis: inner.vis !== false,
          inView,
          fw: Math.round(frect.w),
          fh: Math.round(frect.h),
        };
        seen.push(`${pt.x},${pt.y} ${pt.fw}x${pt.fh} vis=${pt.vis ? 1 : 0} inView=${inView ? 1 : 0}`);
        if (pt.vis && inView && frect.w >= 50 && frect.h >= 40) usable.push(pt);
      }
      if (!usable.length && !seen.length) {
        const oo = await captchaOopifPoint();
        if (oo) return oo;
      }
      if (usable.length) {
        usable.sort((a, b) => a.y - b.y || a.x - b.x);
        const best = usable[0];
        log(`-> captcha: presisi ${best.x},${best.y} (frame ${best.fw}x${best.fh}, kandidat ${usable.length}/${seen.length}) [${seen.join(" | ")}]`);
        return { x: best.x, y: best.y };
      }
      if (seen.length) log(`-> captcha: ${seen.length} anchor ketemu tapi nggak kelihatan: [${seen.join(" | ")}]`);
      else log(`-> captcha: anchor belum ada (frames=${flat.length}) [${dbg.join(" | ")}]`);
    } catch (err) {
      log(`!! captcha: ukur presisi gagal: ${(err && err.message) || err}`);
    }
    if (attempt < retries - 1) await sleep(800);
  }
  return null;
}

async function captchaOopifClick() {
  const anchors = [...oopif.entries()].filter(([, info]) => /anchor/i.test(info.url || ""));
  for (const [asid] of anchors) {
    try {
      const r = await sendS("Runtime.evaluate", {
        returnByValue: true,
        expression: `(() => { const el = document.querySelector("#recaptcha-anchor") || document.querySelector(".recaptcha-checkbox"); if (!el) return "no-el"; if (el.getAttribute("aria-checked") === "true") return "already"; el.click(); return "clicked"; })()`,
      }, asid);
      const v = r && r.result && r.result.result ? r.result.result.value : null;
      if (v === "clicked" || v === "already") { log(`-> captcha: JS click OOPIF anchor -> ${v}`); return true; }
    } catch {}
  }
  return false;
}

async function clickCaptchaCheckbox() {
  const bf = captchaChallengeCount;
  await ensureAutoAttach();
  await sleep(900);
  if (await captchaOopifClick()) {
    for (let k = 0; k < 12; k++) {
      await sleep(1500);
      let tok = "";
      try { tok = await evalJs(`(() => { const t = document.querySelector('textarea[name="g-recaptcha-response"], input[name="g-recaptcha-response"]'); return t ? String(t.value || "") : ""; })()`); } catch {}
      if (tok && String(tok).length > 20) { log("-> captcha: solved via JS click (token)"); return true; }
      let hp = false;
      try { hp = !!(await evalJs(`!!document.querySelector('input[type="password"]')`)); } catch {}
      if (hp) { log("-> captcha: solved via JS click (password field)"); return true; }
      if (await gridState()) {
        log("-> captcha: grid kebuka — solver jalan");
        if (await captchaSolveGrid(3)) return true;
      }
    }
  }
  let before = 0;
  for (let i = 0; i < 30; i++) {
    before = await bf();
    if (before > 0) break;
    let tk0 = "";
    try { tk0 = await evalJs(`(() => { const t = document.querySelector('textarea[name="g-recaptcha-response"], input[name="g-recaptcha-response"]'); return t ? String(t.value || "") : ""; })()`); } catch {}
    if (tk0 && String(tk0).length > 20) { log("-> captcha: token udah kebentuk sebelum klik — solved"); return true; }
    let hasPw = false;
    try { hasPw = !!(await evalJs(`!!document.querySelector('input[type="password"]')`)); } catch {}
    if (hasPw) { log("-> captcha: password field udah muncul — captcha lewat"); return true; }
    await sleep(2000);
  }
  if (before > 0) { log(`-> captcha: challenge udah kebuka duluan (bframe=${before}) — skip klik, langsung solve`); return true; }
  let targets = [];
  for (let i = 0; i < 8 && !targets.length; i++) { targets = await findCaptchaTargets(); if (!targets.length) await sleep(400); }
  if (!targets.length) { log("!! captcha: widget tidak ketemu"); return false; }
  const pick = await captchaCheckboxPoint();
  if (pick) log(`-> captcha: ukur presisi ok, checkbox @${Math.round(pick.x)},${Math.round(pick.y)} (frame ${Math.round(pick.fw)}x${Math.round(pick.fh)})`);
  else log("-> captcha: presisi nggak tersedia, pakai rasio widget (h*0.36 / h*0.5)");
  let vpz = { w: 0, h: 0 };
  try { vpz = JSON.parse(await evalJs("JSON.stringify({ w: innerWidth, h: innerHeight })")) || vpz; } catch {}
  for (const t of targets.slice(0, 3)) {
    if (vpz.w && (t.x + t.w <= 0 || t.y + t.h <= 0 || t.x >= vpz.w || t.y >= vpz.h)) { log(`-> captcha: skip ${t.kind} @${Math.round(t.x)},${Math.round(t.y)} (di luar viewport)`); continue; }
    const cx = Math.round(pick ? pick.x : t.x + t.h * 0.36);
    const cy = Math.round(pick ? pick.y : t.y + t.h * 0.5);
    log(`-> captcha: klik ${t.kind} ${Math.round(t.w)}x${Math.round(t.h)} @${cx},${cy}`);
    await realClick(cx, cy);
    let now = before;
    for (let k = 0; k < 4; k++) { await sleep(1800); now = await bf(); if (now > before) break; }
    if (now > before) { log(`-> captcha: challenge aktif (bframe ${before}->${now})`); return true; }
    let capTok = "";
    try { capTok = await evalJs(`(() => { const t = document.querySelector('textarea[name="g-recaptcha-response"], input[name="g-recaptcha-response"]'); return t ? String(t.value || "") : ""; })()`); } catch {}
    if (capTok && String(capTok).length > 20) { log(`-> captcha: token kebentuk (${String(capTok).length} char) — captcha SOLVED`); return true; }
    if (!/recaptcha|challenge|verify/i.test(String(await evalJs("location.href")))) { log("-> captcha: halaman lanjut (lolos)"); return true; }
    log("-> captcha: klik belum ngefek, coba kandidat berikutnya");
  }
  return false;
}

async function solveAudioCaptcha(timeoutMs = 60000) {
  const t0 = Date.now();
  // Find reCAPTCHA frames (classic v2 AND enterprise) via CDP frame tree —
  // cross-origin reCAPTCHA iframes BLOCK contentDocument, so we evaluate INSIDE the
  // frame using Page.createIsolatedWorld (works across origins, no taint).

async function captchaFrame() {
    const tree = (await send("Page.getFrameTree").catch(() => null))?.result?.frameTree;
    const walk = (n) => { let out = n.url ? [n] : []; (n.childFrames || []).forEach(c => out = out.concat(walk(c))); return out; };
    const all = tree ? walk(tree) : [];
    return all.find(fr => (fr.url || "").includes("recaptcha") && (/anchor/.test(fr.url) || /bframe/.test(fr.url) || /imageframe/.test(fr.url))) || null;
  }
  // evaluate JS inside a specific frame (bypasses cross-origin restriction)
  async function evalInFrame(frameId, expr) {
    try {
      const w = await send("Page.createIsolatedWorld", { frameId, grantUniveralAccess: false, worldName: "th-solver" });
      const ctx = w.result?.executionContextId;
      if (!ctx) return null;
      const r = await send("Runtime.evaluate", { expression: expr, contextId: ctx, returnByValue: true, awaitPromise: true });
      return r.result?.result?.value ?? null;
    } catch { return null; }
  }
  // helper: run expr in the frame that currently has the audio/challenge content
  const runInCaptchaFrame = async (expr) => {
    const fr = await captchaFrame();
    if (!fr) return null;
    return await evalInFrame(fr.id, expr);
  };
  // 1. switch challenge to audio: find the [title~=audio] control inside ANY recaptcha frame
  const audioClick = await runInCaptchaFrame(`(() => {
    const b = [...document.querySelectorAll('button,[role=button]')].find(x => /audio/i.test((x.title||'')+' '+(x.getAttribute('aria-label')||'')+' '+(x.className||'')));
    if (b) { b.click(); return 'clicked'; }
    return null;
  })()`);
  if (audioClick === "clicked") { log("-> Audio auto-solve: audio switch clicked (in-frame, cross-origin safe)."); await sleep(2500); }
  else log("-> Audio auto-solve: audio control not found in frame.");

  // 2. extract the audio src from the challenge frame
  const src = await runInCaptchaFrame(`(() => {
    const a = document.getElementById('audio-source'); if (a && a.src) return a.src;
    const au = document.querySelector('audio'); if (au) return au.currentSrc || au.src || '';
    const s = document.querySelector('audio source'); if (s) return s.src || '';
    return '';
  })()`);
  if (!src) { log("-> Audio auto-solve: no audio source found."); return false; }
  log("-> Audio auto-solve: got audio source.");

  // transcribe via sibling Python helper (proven pipeline)
  const { execFileSync } = await import("node:child_process");
  let answer = "";
  try {
    const solverPy = process.env.AUDIO_SOLVER_PY || "python3";
    const solverPath = join(ROOT, "scripts/audio-solver.py");
    const out = execFileSync(solverPy,
      [solverPath], { input: JSON.stringify({ audio_url: src }), encoding: "utf8", timeout: 40000, stdio: ["pipe","pipe","pipe"] });
    const parsed = JSON.parse(out.trim().split("\n").pop());
    if (parsed.ok && parsed.answer) { answer = parsed.answer; }
    else log("-> Audio auto-solve: transcription failed: " + (parsed.error || "?"));
  } catch (e) { log("-> Audio auto-solve: python helper error: " + String(e).slice(0,80)); return false; }
  if (!answer) return false;
  log(`-> Audio auto-solve: heard "${maskCode(answer)}"`);

  // type + verify inside the challenge frame (cross-origin safe)
  await runInCaptchaFrame(`(() => {
    const i = document.getElementById('audio-response');
    if (!i) return false;
    const s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
    s.call(i, ${JSON.stringify(answer)});
    i.dispatchEvent(new Event('input',{bubbles:true}));
    const v = document.getElementById('recaptcha-verify-button');
    if (v) v.click();
    return true;
  })()`);
  // confirm token appeared
  const deadline = t0 + timeoutMs;
  while (Date.now() < deadline) {
    await sleep(3000);
    // token may live in the anchor frame (cross-origin) OR the main page — check both
    let tok = await evalJs(`(() => { try { const g=window.grecaptcha; if(g&&g.getResponse&&g.getResponse()) return g.getResponse(); } catch(e){} const inp=document.querySelector('textarea[name="g-recaptcha-response"]'); return inp?inp.value:''; })()`).catch(() => "");
    if (!tok) tok = (await runInCaptchaFrame(`(() => { try { const g=window.grecaptcha; if(g&&g.getResponse&&g.getResponse()) return g.getResponse(); } catch(e){} return ''; })()`)) || "";
    if (tok) { log("-> Audio auto-solve: SOLVED (token obtained)."); return true; }
  }
  log("-> Audio auto-solve: submitted but no token — will fall back to human.");
  return false;
}
// wait for a human to assist (QR scan, captcha solve, phone tap) in VNC.
// mode "any"   (phone-tap / verify-it's-you): any page change counts as progress/solved.
// mode "gmail" (QR / captcha / manual verify): must actually reach Gmail (success) before
//   continuing — clicking the QR option alone is NOT success. Long window so the human has
//   time to scan/solve. Polls every 4s; returns true only on the right outcome.
async function waitHuman(email, label, mode = "any", timeoutMs = 90000) {
  log(`-> ${label}: waiting up to ${Math.round(timeoutMs / 1000)}s for human assistance in VNC (QR/captcha/phone)...`);
  const t0 = Date.now();
  let lastUrl = await evalJs("location.href") || "";
  while (Date.now() - t0 < timeoutMs) {
    await sleep(4000);
    const u = await evalJs("location.href") || "";
    const T = (await evalJs("document.body.innerText") || "").slice(0, 400);
    // real success: reached Gmail inbox — must STICK for a second poll (Google
    // often bounces mail URL back to the verification wall; a single sighting
    // is a false "resolved" that wastes a full 90s human-wait cycle).
    if (/\/mail\.google\.com\/mail/.test(u)) {
      await sleep(4000);
      const u2 = await evalJs("location.href") || "";
      if (/\/mail\.google\.com\/mail/.test(u2)) { log(`-> ${label}: reached Gmail (confirmed) — resolved`); return true; }
      log(`-> ${label}: Gmail sighting bounced back to challenge — still waiting...`);
      lastUrl = u2;
      continue;
    }
    // still on a verification/QR/captcha screen? keep waiting (not done yet)
    if (/QR|scan|security code|Enter the code|verify|Captcha|captcha|I'?m not a robot/i.test(T) && !/\/mail\.google/.test(u)) {
      continue;
    }
    // any other page change
    if (u !== lastUrl) {
      if (mode === "any") { log(`-> ${label}: page changed — continuing flow`); return true; }
      // mode "gmail": keep waiting until we actually reach mail
      lastUrl = u;
    }
  }
  log(`-> ${label}: no completion after ${Math.round(timeoutMs / 1000)}s — skipping account`);
  return false;
}
async function clickNext() {
  // wait until the enabled Next button exists, then trusted click
  for (let i = 0; i < 40; i++) {
    const r = await realClick(`[...document.querySelectorAll('button,[role=button],input[type=submit]')].find(x=>((x.innerText||x.value||'').trim()==='Next')&&x.offsetParent!==null&&!x.disabled)`);
    if (r) return true;
    await sleep(500);
  }
  return false;
}
async function clickText(txt, quiet = false) {
  const t = String(txt).trim().toLowerCase();
  const raw = await evalJs(`(() => {
    const want = ${JSON.stringify(t)};
    const label = (x) => ((x.innerText || x.value || x.getAttribute("aria-label") || "") + "").trim().toLowerCase().replace(/\\s+/g, " ");
    const els = [...document.querySelectorAll("button,[role=button],a,[role=link],input[type=button],input[type=submit]")]
      .filter((x) => {
        if (label(x) !== want) return false;
        const r = x.getBoundingClientRect();
        if (r.width < 8 || r.height < 8) return false;
        const st = getComputedStyle(x);
        if (st.visibility === "hidden" || st.display === "none" || st.pointerEvents === "none" || Number(st.opacity) < 0.3) return false;
        return r.bottom > 0 && r.top < innerHeight + 200;
      });
    if (!els.length) return "";
    els.sort((a, b) => {
      const rank = (x) => (/^(BUTTON|A|INPUT)$/.test(x.tagName) ? 0 : x.getAttribute("role") === "button" ? 1 : 2);
      const d = rank(a) - rank(b);
      if (d) return d;
      const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
      return ra.width * ra.height - rb.width * rb.height;
    });
    const el = els[0];
    el.scrollIntoView({ block: "center", inline: "center" });
    const r = el.getBoundingClientRect();
    return JSON.stringify({ x: Math.round(r.x + r.width / 2), y: Math.round(r.y + r.height / 2), tag: el.tagName });
  })()`);
  if (!raw) { if (!quiet) log(`!! klik "${t}": elemen nggak ketemu`); return false; }
  let p;
  try { p = JSON.parse(raw); } catch { return false; }
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: p.x, y: p.y });
  await sleep(120);
  await send("Input.dispatchMouseEvent", { type: "mousePressed", x: p.x, y: p.y, button: "left", clickCount: 1 });
  await sleep(70);
  await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: p.x, y: p.y, button: "left", clickCount: 1 });
  log(`-> klik "${t}" @${p.x},${p.y} (${p.tag})`);
  return true;
}
async function saveCookies(email) {
  const { result } = await send("Network.getAllCookies");
  const cookies = (result?.cookies || []).filter((c) => c.domain.includes("google.com"));
  if (!cookies.some((c) => ["SID", "SSID", "__Secure-1PSID"].includes(c.name) && c.value.length > 20)) return false;
  writeFileSync(join(COOKIE_DIR, email.replace(/[@.]/g, "_") + ".json"), JSON.stringify(cookies, null, 2), { mode: 0o600 });
  return true;
}
const SS_DIR = join(ROOT, "screenshots");
mkdirSync(SS_DIR, { recursive: true, mode: 0o700 });
async function captureFailArtifacts(pngPath) {
  if (!pngPath) return null;
  let ok = false;
  try {
    const shot = await send("Page.captureScreenshot", { format: "png" });
    writeFileSync(pngPath, Buffer.from(shot.data, "base64"));
    ok = true;
  } catch (e) {
    log(`-> shot gagal: ${e && e.message ? e.message : e}`);
  }
  try {
    const r = await send("Runtime.evaluate", { expression: "document.documentElement.outerHTML", returnByValue: true });
    const html = r && r.result && r.result.value ? String(r.result.value) : "";
    if (html) writeFileSync(pngPath.replace(/\.png$/, ".html"), html.slice(0, 3000000), { mode: 0o600 });
  } catch (e) { }
  if (ok) log(`-> ss: ${pngPath}`);
  return ok ? pngPath : null;
}

async function screenshot(email) {
  const file = join(SS_DIR, `fail-${email.replace(/[@.]/g,"_")}.png`);
  try { const s = await send("Page.captureScreenshot", { format: "png" }); writeFileSync(file, Buffer.from(s.result.data, "base64"), { mode: 0o600 }); log("-> Screenshot saved: " + file); return true; } catch { return false; }
}

// ── QR-to-terminal: extract the Google QR image, downsample in-page via canvas,
//    render as scannable unicode half-block ASCII in the terminal. ──
// QR codes are images inside the sign-in challenge; canvas.getImageData works in
// the SAME origin (accounts.google.com), so no cross-origin taint issue.
// Returns the ASCII art string (or null if no QR found).
async function renderQrToTerminal() {
  // 1. locate the QR <img> (Google renders it as img[src*=chart.googleapis] or data: PNG)
  const info = await evalJs(`(() => {
    const imgs = [...document.querySelectorAll('img')].filter(i => {
      const s = (i.src || '');
      return /chart\.googleapis|data:image\/(png|jpeg)/.test(s) && (i.width > 50);
    });
    if (!imgs.length) return null;
    const img = imgs[imgs.length - 1]; // newest = the current QR
    return { src: img.src, w: img.naturalWidth || img.width, h: img.naturalHeight || img.height };
  })()`).catch(() => null);
  if (!info) { log("-> No QR image element found on page."); return null; }
  log(`-> QR image found (${info.w}x${info.h}). Rendering to terminal...`);

  // 2. draw it to a canvas at fixed grid (37x37 → half-block = 74 cols terminal),
  //    sample luminance → binary matrix
  const matrix = await evalJs(`(async () => {
    const img = new Image();
    img.src = ${JSON.stringify(info.src)};
    await new Promise((res, rej) => { img.onload = res; img.onerror = rej; });
    const N = 37; // QR version-agnostic grid
    const c = document.createElement('canvas'); c.width = N; c.height = N;
    const ctx = c.getContext('2d');
    ctx.drawImage(img, 0, 0, N, N);
    const d = ctx.getImageData(0, 0, N, N).data;
    // threshold: QR modules are black/white; pick midpoint of extremes
    let min = 255, max = 0;
    for (let i = 0; i < d.length; i += 4) { const v = 0.3*d[i]+0.59*d[i+1]+0.11*d[i+2]; min = Math.min(min, v); max = Math.max(max, v); }
    const mid = (min + max) / 2;
    const rows = [];
    for (let y = 0; y < N; y++) { let r = ''; for (let x = 0; x < N; x++) { r += (0.3*d[(y*N+x)*4]+0.59*d[(y*N+x)*4+1]+0.11*d[(y*N+x)*4+2]) < mid ? '1' : '0'; } rows.push(r); }
    return rows;
  })()`).catch(() => null);
  if (!matrix) { log("-> Failed to decode QR pixels."); return null; }

  // 3. render half-block ASCII: two vertical pixels per character (▀ top, ▄ bottom, █ both, ' ' none)
  const N = matrix.length;
  const lines = [];
  for (let y = 0; y < N; y += 2) {
    let line = "";
    const top = matrix[y];
    const bot = (y + 1 < N) ? matrix[y + 1] : "0".repeat(N);
    for (let x = 0; x < N; x++) {
      const a = top[x] === "1", b = bot[x] === "1";
      line += a && b ? "█" : a ? "▀" : b ? "▄" : " ";
    }
    lines.push(line);
  }
  const art = lines.join("\n");
  log("\n" + art + "\n", "info");
  log("-> Scan the QR above with your phone to complete sign-in. (QR also saved as screenshot)", "arr");
  return art;
}
// extract the tap-code (number) from challenge text
function extractCode(text) {
  // Google prompt: short number sits on its own line right above "Check your <phone>"
  let m = text.match(/(\d{1,6})\s*\n\s*Check your/);
  if (m) return m[1];
  // from the sentence: "then tap 71 on your phone"
  m = text.match(/then tap (\d{1,6}) on your phone/);
  if (m) return m[1];
  // fallback: any standalone 5-8 digit token (SMS-style codes)
  m = text.match(/(^|\s)(\d{5,8})(\s|$)/);
  return m ? m[2] : null;
}
const MAILRE = /^https:\/\/mail\.google\.com\/mail/;

// ---- TOTP auto-fill (local RFC 6238 only) ----
// store per-account authenticator secrets in a plaintext file (email|secret),
// fetched from the 2FA-setup screen (or provided by the user).
const SECRETS_FILE = join(ROOT, ".2fa-secrets"); // email|base32-secret
function getSecret(email) {
  try {
    if (!existsSync(SECRETS_FILE)) return null;
    for (const l of readFileSync(SECRETS_FILE, "utf8").split("\n")) {
      const [e, s] = l.split("|");
      if (e === email && s && s.trim()) return s.trim().replace(/\s+/g, "");
    }
  } catch {}
  return null;
}
async function fetch2FA(email) {
  const secret = getSecret(email);
  if (!secret) return null;
  // compute TOTP locally (RFC 6238 / HMAC-SHA1, 30s step, 6 digits) — offline, always works
  try {
    const { createHmac } = await import("node:crypto");
    const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const key = secret.toUpperCase().replace(/=+$/g, "");
    let bits = "";
    for (const ch of key) { const v = base32.indexOf(ch); if (v < 0) throw new Error("bad base32"); bits += v.toString(2).padStart(5, "0"); }
    while (bits.length % 8) bits += "0";
    const bytes = []; for (let i = 0; i < bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    const counter = Math.floor(Date.now() / 1000 / 30);
    const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
    const h = createHmac("sha1", Buffer.from(bytes)).update(buf).digest();
    const off = h[h.length - 1] & 0xf;
    const code = ((h.readUInt32BE(off) & 0x7fffffff) % 1000000).toString().padStart(6, "0");
    return { code, source: "local TOTP (RFC 6238)" };
  } catch {}
  return null;
}
// when the authenticator setup screen shows a key, persist it so future logins auto-fill
function saveSecretFromScreen(email, key) {
  try {
    const norm = key.replace(/\s+/g, "").toUpperCase();
    const cur = existsSync(SECRETS_FILE) ? readFileSync(SECRETS_FILE, "utf8") : "";
    const others = cur.split("\n").filter((l) => l && !l.startsWith(email + "|"));
    others.push(`${email}|${norm}`);
    writeFileSync(SECRETS_FILE, others.join("\n") + "\n", { mode: 0o600 });
    return norm;
  } catch { return null; }
}

// P1-1 opt-in security-code shortcut (tap-notification stays DEFAULT).
// When USE_SECURITY_CODE is set (--security-code flag or env), the Verify-it's-you
// branch clicks "Try another way" FIRST, then picks in order:
//   Get a security code|security code on your phone -> Text message|SMS
//   -> existing TOTP autofill -> tap-number relay as LAST fallback.
async function trySecurityCodeMethod() {
  const sec = await evalJs(`(() => {
    const opts=[...document.querySelectorAll('button,[role=button],a,li,div')];
    const re=/Get a security code|security code on your phone/i;
    const el=opts.find(x=>re.test((x.innerText||'').trim()) && (x.innerText||'').trim().length<80);
    if(el){el.click();return true;} return false;
  })()`).catch(() => false);
  if (sec) { log("-> Selected security-code method"); await sleep(2500); return true; }
  const sms = await evalJs(`(() => {
    const opts=[...document.querySelectorAll('button,[role=button],a,li,div')];
    const re=/Text message|\\bSMS\\b/i;
    const el=opts.find(x=>re.test((x.innerText||'').trim()) && (x.innerText||'').trim().length<80);
    if(el){el.click();return true;} return false;
  })()`).catch(() => false);
  if (sms) { log("-> Selected Text message/SMS method"); await sleep(2500); return true; }
  return false;
}
async function tryTotpAutofill(email, tok) {
  const stNow = await state().catch(() => null);
  if (!stNow) return false;
  const codeInput = (stNow.inputs || []).find((x) => x.includes("tel") || x.includes("code"));
  if (!codeInput) return false;
  const sel = codeInput.includes("tel") ? `input[type=tel]` : `input[type=text]`;
  if (tok) { log("-> Using provided 2FA token"); await setInput(sel, tok); await sleep(300); await clickNext(); await sleep(1500);
  try { const pt = String(await evalJs("document.body.innerText.replace(/\n+/g, ' ').slice(0, 140)")); const pu = String(await evalJs("location.pathname")); log(`-> password submit: path=${pu.slice(0, 40)} txt="${pt.slice(0, 70)}"`); } catch {} return true; }
  const auto = await fetch2FA(email);
  if (auto) { log(`-> Auto-filled code from ${auto.source}`); await setInput(sel, auto.code); await sleep(300); await clickNext(); await sleep(2000); return true; }
  return false;
}

// ------------------------------------------------ main loop
// success path: save cookies + record to loggedmail
async function finishLogin(email, pw, tok) {
  try { RUN_LOGGED.add(email); } catch {}
  await sleep(4000);
  const st = await state();
  if (!MAILRE.test(st.url)) { log("-> bounced after submit (not signed in): " + (st.url || "--").slice(0, 70)); return false; }
  try { await gmailHumanWarmup(); } catch {}
  log("-> Login complete, saving cookies....");
  const ok = await saveCookies(email);
  if (ok) {
    if (await cookieValidDurable(email)) { log("-> Done! (session verified)"); clearFailed(email); try { const LGF = LOGGED_FILE; const cur = existsSync(LGF) ? readFileSync(LGF, "utf8") : ""; if (!cur.split("\n").some((l) => l.startsWith(email + "|"))) appendFileSync(LGF, `${email}|${pw}|${tok || ""}\n`, { mode: 0o600 }); } catch {} }
    else { try { const pt = String(await evalJs("document.body.innerText.replace(/\\n+/g, \" \").slice(0, 160)")); const pu = String(await evalJs("location.pathname")); log(`-> login gagal: path=${pu.slice(0, 40)} txt="${pt.slice(0, 90)}"`); } catch {} log("-> Cookie invalid after login (verification skipped) — marked failed"); markFailed(email, "session invalid", pw, tok); }
  } else log("-> Failed to save cookies (no session).");
  return ok;
}
function purgeProfileCaches(dir, depth = 0) {
  const cacheNames = new Set(["Cache", "Code Cache", "GPUCache", "ShaderCache", "GrShaderCache", "DawnGraphiteCache", "DawnWebGPUCache", "CacheStorage", "Service Worker"]);
  let ents = [];
  try { ents = fsReaddir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    const p = join(dir, e.name);
    if (e.isSymbolicLink()) { try { unlinkSync(p); } catch { try { rmSync(p, { force: true }); } catch {} } continue; }
    if (e.isDirectory()) {
      if (cacheNames.has(e.name)) { try { rmSync(p, { recursive: true, force: true }); } catch {} continue; }
      if (depth < 2) purgeProfileCaches(p, depth + 1);
    }
  }
}

async function restoreCookiesFor(email) {
  const f = join(COOKIE_DIR, email.replace(/[@.]/g, "_") + ".json");
  if (!existsSync(f)) { log(`-> cookie file ${email} nggak ada, andalkan profile`); return 0; }
  let arr = [];
  try { arr = JSON.parse(readFileSync(f, "utf8")); } catch { return 0; }
  if (!Array.isArray(arr) || !arr.length) return 0;
  await send("Network.enable", {});
  let n = 0;
  for (const c of arr) {
    if (!c || !c.name || !c.domain) continue;
    const p = { name: c.name, value: String(c.value ?? ""), domain: c.domain, path: c.path || "/", secure: !!c.secure, httpOnly: !!c.httpOnly, sourceScheme: c.sourceScheme || "Secure", sourcePort: c.sourcePort || 443 };
    if (c.priority) p.priority = c.priority;
    if (!c.session && c.expires) p.expires = Math.floor(c.expires);
    if (/^(lax|strict|none)$/i.test(String(c.sameSite || ""))) p.sameSite = String(c.sameSite);
    try { const r = await send("Network.setCookie", p); if (r?.result?.success) n++; } catch {}
  }
  log(`-> cookies restored ${n}/${arr.length} (${email})`);
  return n;
}

async function cookieLoginProbe(email, acc) {
  globalThis.__probePicked = false;
  const n = await restoreCookiesFor(email);
  await send("Page.navigate", { url: "https://accounts.google.com/" });
  await sleep(2500);
  const local = email.split("@")[0].toLowerCase();
  const picked = await evalJs(`(() => { const t = ${JSON.stringify(local)}; const els = [...document.querySelectorAll('div[data-identifier], div[role="link"], li, a')]; const hit = els.find((e) => ((e.getAttribute("data-identifier") || "") + " " + (e.textContent || "")).toLowerCase().includes(t)); if (!hit) return ""; hit.click(); return "ok"; })()`);
  globalThis.__probePicked = picked === "ok";
  if (picked === "ok") log(`-> profile ketemu: ${email} ada di chooser, diklik (relogin profile, bukan device baru)`);
  {
    const t0 = String(await evalJs(`(document.body ? document.body.innerText : "").slice(0, 200)`));
    if (/logged out|signed out/i.test(t0)) log(`-> ${email}: akun dikenali profile tapi sesi Google LOGGED OUT -> butuh password sekali (email nggak usah diketik ulang)`);
  }
  if (picked !== "ok") { log(`-> chooser kosong: ${email} belum terdaftar di profile -> login penuh (isi email)`); return false; }
  await sleep(2000);
  await send("Page.navigate", { url: "https://mail.google.com/mail/u/0/#inbox" });
  for (let i = 0; i < 8; i++) {
    await sleep(1200);
    const u = String(await evalJs("location.href"));
    if (/mail\.google\.com\/mail\/u\/\d+/.test(u)) {
      const st = JSON.parse(String(await evalJs(`JSON.stringify({ pw: !!document.querySelector('input[type="password"]'), signout: !!document.querySelector('a[href*="SignOutOptions"]'), bad: /verify it.s you|logged out|signed out|sign in|masuk/i.test((document.body ? document.body.innerText : "").slice(0, 300)) })`)) || "{}");
      if (st.signout && !st.pw && !st.bad) {
        log(`-> cookie login OK: ${email} langsung masuk Gmail, password nggak dipakai (nggak bikin device baru)`);
        await finishLogin(email, acc.pass || acc.password || "", "");
        return true;
      }
    }
    if (/accounts\.google\.com|servicelogin/.test(u)) { log(`-> cookie ${email} mati (redirect signin), lanjut password`); return false; }
  }
  log(`-> cookie ${email}: probe timeout, lanjut password`);
  return false;
}

async function loginOne(acc) {
  const _em = acc.email || acc.user || String(acc);
  try { if (await cookieLoginProbe(_em, acc)) return true; } catch (e) { log("!! cookie probe: " + ((e && e.message) || e)); }
  const { email, pw, tok } = acc;
  log(`-> Logging in account ${email}....`);
  if (!globalThis.__probePicked) {
    if (KEEP_PROFILE_SESSION) {
      const _restored = await restoreCookiesFor(email).catch(() => 0);
      log(`-> session restore: ${_restored} cookie (${_restored ? "chooser path, tanpa password" : "nggak ada cookie, login penuh"})`);
    } else {
      await send("Network.clearBrowserCookies").catch(() => {});
    }
  }
  // kill any residual session so the identifier page is clean
  await send("Page.navigate", { url: "https://accounts.google.com/Logout" });
  await sleep(2500);
  await clickText("Sign out", true);
  await sleep(2000);
  await send("Page.navigate", { url: "https://accounts.google.com/AddSession?continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&hl=en" });
  await sleep(3500);
  // if account chooser is open, jump to "Use another account"
  const chooser = await evalJs(`(() => { const t=document.body.innerText||''; return /Use another account/i.test(t) ? true : false; })()`).catch(() => false);
  if (chooser) { await clickText("Use another account"); await sleep(2000); }
  // chooser resume: our signed-out account tile may already be listed (cookie relogin
  // lands here). Clicking it jumps straight to the password screen — same as a
  // returning user, no identifier typing needed. Pick the DEEPEST tile containing
  // our email + "signed out" (Google nests avatar/text spans; parent clicks bubble).
  let resumed = false;
  try {
    resumed = await realClick(`[...document.querySelectorAll('li,[role=option],button,a,div')].filter(x=>{const t=(x.innerText||'').toLowerCase();return t.includes(${JSON.stringify(email.toLowerCase())}) && /signed\\s*out/.test(t);}).sort((a,b)=>(a.innerText||'').length-(b.innerText||'').length)[0]`);
    if (resumed) { log("-> Account tile found — resuming session (skipping email entry)...."); await sleep(2500); }
  } catch { resumed = false; }
  // email
  for (let i = 0; i < 24 && !resumed; i++) { const s = await state(); if (s.inputs.some((x) => x.includes("email") || x.includes("identifier"))) break; await sleep(500); }
  // (resume skips straight to the password wait below)
  if (!resumed) {
    const hasIdField = await evalJs(`!!document.querySelector('input[name=identifier], #identifierId')`);
    if (!hasIdField) log("-> identifier nggak ada (akun udah kepilih dari profile) — skip isi email");
    const cur = await evalJs(`(() => { const el=document.querySelector('input[name=identifier], #identifierId, input[type=email]'); return el?el.value:''; })()`).catch(() => "");
    if (hasIdField && cur !== email) { await typeChars('input[name=identifier], #identifierId, input[type=email]', email); }
    await clickNext();
  }
  // wait for password field, detect invalid email or captcha
  let pwField = false;
  for (let i = 0; i < 30; i++) {
    const s = await state();
    // Invalid email detection
    if (/Couldn't find your Google Account|couldn't find|no account found|This account doesn.t exist/i.test(s.text + " " + s.title)) {
      log(`-> Invalid email: ${email} — skipping.`);
      markFailed(email, "invalid email", pw, tok);
      return false;
    }
    if (s.inputs.some((x) => x.includes("password"))) { pwField = true; break; }
    if (/reCAPTCHA|I'?m not a robot|Verify you are human|not a robot/i.test(s.text + " " + s.title)) {
    log("-> captcha: klik checkbox DULU (mouse asli, ukur presisi)");
    const capOk = await clickCaptchaCheckbox();
    let capBf = Number(await captchaChallengeCount());
    if (capBf === 0) {
      log("-> captcha: tidak ada challenge gambar" + (capOk ? " (lolos)" : " (cek manual di VNC)"));
    } else {
      log(`-> captcha: challenge gambar aktif (bframe=${capBf}), baru coba audio solver...`);
      try { await solveAudioCaptcha(); } catch (e) { log("!! audio solver: " + ((e && e.message) || e)); }
      capBf = Number(await evalJs(`[...document.querySelectorAll('iframe[src*="bframe"]')].filter(f => { const r = f.getBoundingClientRect(); return r.width > 50 && r.height > 50 && r.bottom > 0 && r.top < innerHeight; }).length`)) || 0;
      if (capBf === 0) log("-> captcha: audio solver berhasil");
      else log("-> captcha: audio gagal, coba grid solver...");
      if (await captchaSolveGrid(3)) log("-> captcha: grid beres (token/grid hilang)");
      else log("-> captcha: grid gagal, HUMAN di VNC — jangan interrupt");
    }
    // checkbox first: a direct click usually mints the token without audio fallback
      try { await evalJs(`(() => { const cb=document.querySelector('.recaptcha-checkbox-border,[role=checkbox]'); if(cb){cb.click();return true;} return false; })()`); } catch (e) { }
      await sleep(2200);
      let grecaptchaToken = "";
      let captchaResolved = false;
      const captchaTimeout = Date.now() + 180000;
    while (Date.now() < captchaTimeout) {
        await sleep(2500);
        // Poll for grecaptcha token (webshare approach) — confirms real solve
        try {
          grecaptchaToken = await evalJs(`(() => { try { const t = document.querySelector('textarea[name="g-recaptcha-response"], input[name="g-recaptcha-response"]'); if (t && t.value && t.value.length > 20) return t.value; const gr = window.grecaptcha && (window.grecaptcha.enterprise || window.grecaptcha); if (!gr || !gr.getResponse) return ""; return gr.getResponse() || ""; } catch (e) { return ""; } })()`);
        } catch (e) { grecaptchaToken = ""; }
        const st = await state();
        // captcha solved = token present OR captcha text gone + advanced
        if (grecaptchaToken) {
          captchaResolved = true;
          log("-> Grecaptcha token obtained — captcha SOLVED (webshare method).");
          break;
        }
        if (!/reCAPTCHA|I'?m not a robot|Verify you are human|not a robot/i.test(st.text + " " + st.title)) {
          if (st.inputs.some((x) => x.includes("password")) || /password/i.test(st.text)) {
            captchaResolved = true;
            log("-> Captcha solved! Password field detected.");
            break;
          }
          log("-> Captcha text gone, page advanced.");
          captchaResolved = true;
          break;
        }
      }
      if (!captchaResolved) {
        await screenshot(email);
        log("-> Captcha not solved after 180s, skipping.");
        return false;
      }
      // Reset the outer loop to re-evaluate current state
      i = 0; continue;
    }
    await sleep(1000);
  }
  const s2 = await state();
  // If there's no password field, Google recognized the device and skipped straight to a
  // challenge (e.g. "Verify it's you"). Don't give up — fall into the outcome-poll loop below,
  // which handles phone-tap codes, QR, and human-assist waits.
  if (!s2.inputs.some((x) => x.includes("password"))) {
    log("-> No password field (device recognized / direct challenge); page: " + (s2.title || s2.url || "").slice(0, 90));
    // set the poll loop's starting state so it doesn't loop on the stale password page
    const t0 = Date.now();
    let findingLogged = false, codeLogged = false, lastUnknown = null, lastUnknownAt = 0;
    let humanWaits = 0;
    const MAX_WAITS = NO_VNC_FLAG ? 1 : 3; // headless: no eyes — one wait max
    let actedOn = null, actedAt = 0;
    const acted = async (url) => { if (actedOn === url && Date.now() - actedAt < 25000) return true; actedOn = url; actedAt = Date.now(); await sleep(2000); return false; };
    // re-enter the same polling logic below by looping here
    const challengeLoop = async () => {
      while (Date.now() - t0 < 300000) {
        await sleep(2500);
        const st = await state();
        if (MAILRE.test(st.url)) { return await finishLogin(email, pw, tok); }
        const T = st.text + " " + st.title;
        if (/Verify it's you|Check your/i.test(T)) {
          if (!findingLogged) { log(`-> Finding text "Verify it's you" and "Passkey" and getting the code`); findingLogged = true; log(`-> Verify path: ${USE_SECURITY_CODE ? "security-code (opt-in)" : "tap-notification (default)"}`); }
          if (USE_SECURITY_CODE) {
            if (await clickText("Try another way")) await sleep(2500);
            if (await trySecurityCodeMethod()) { await tryTotpAutofill(email, tok); continue; }
            if (await tryTotpAutofill(email, tok)) continue;
            // LAST fallback: tap-number relay below
          }
          const st2 = await state();
          const code = extractCode(st2.text);
          if (code && !codeLogged) { log(`-> Code found! Click ${code} on your phone. Waiting....`); codeLogged = true; }
          else if (!code) { log("-> No text match, continuing...."); }
          continue;
        }
        if (/Verifikasi info|verify your info|phone verification|QR code|scan the QR/i.test(T)) {
          log("-> Manual phone/QR verification detected");
          await renderQrToTerminal();   // print the QR as ASCII for phone scanning
          const ok = await waitHuman(email, "QR/phone verification", "gmail");
          if (ok) continue;
          markFailed(email, "manual-verify", pw, tok); return false;
        }
        if (/reCAPTCHA|I'?m not a robot|Verify you are human|not a robot/i.test(T)) {
          log("-> reCAPTCHA detected; attempting auto-solve...");
          const clicked = await evalJs(`(() => { const cb=document.querySelector('.recaptcha-checkbox-border,[role=checkbox]'); if(cb){cb.click();return true;} return false; })()`);
          if (clicked) { log("-> Clicked reCAPTCHA, waiting 5s..."); await sleep(5000); continue; }
          await sleep(4000); continue;
        }
        if (/This browser or app may not be secure|Sign in blocked|Access blocked|Account disabled|Couldn.t sign you in/i.test(T)) {
          // wall: try to clear it (realClick) and resync state before manual verify
          try { await realClick(`[...document.querySelectorAll('button,a,[role=button]')].filter((x) => /continue|learn more|i understand|got it|next/i.test((x.innerText||'').trim()) && x.offsetParent !== null).slice(0, 1)`); await sleep(2500); await state(); } catch (e) { }
          if (NO_VNC_FLAG) { log("-> Insecure-browser wall headless — needs headed VNC run; marking failed"); markFailed(email, "insecure-browser", pw, tok); return false; }
          log("-> Security flag / access blocked — waiting for human (may unlock in VNC)");
          const ok = await waitHuman(email, "blocked screen", "gmail");
          if (ok) continue;
          markFailed(email, "blocked", pw, tok); return false;
        }
        const uk = (st.title || st.url || "").slice(0, 120);
        if (lastUnknown === uk && Date.now() - lastUnknownAt > 60000) {
          log("-> Stuck on unknown screen >60s; waiting for human assistance...");
          const ok = await waitHuman(email, "unknown screen", "gmail");
          if (ok) {
            // waitHuman confirmed a STICKY Gmail page (double-poll), but re-verify:
            // if we're not in the inbox right now, the session bounced again.
            const v = await state();
            if (!MAILRE.test(v.url)) {
              log("-> Assist resolved then bounced back to verification — counting as stuck...");
              humanWaits++;
              if (humanWaits >= MAX_WAITS) {
                log("-> Unknown screen persists after 3 human waits — marking failed (no infinite loop).");
                await screenshot(email); // capture the wall for later eyes-on review
                markFailed(email, "persistent-unknown", pw, tok); return false;
              }
              lastUnknown = ""; lastUnknownAt = Date.now(); continue;
            }
            humanWaits++;
            if (humanWaits >= MAX_WAITS) {
              log("-> Unknown screen persists after 3 human waits — marking failed (no infinite loop).");
              await screenshot(email); // capture the wall for later eyes-on review
              markFailed(email, "persistent-unknown", pw, tok); return false;
            }
            lastUnknown = ""; lastUnknownAt = Date.now(); continue;
          }
          markFailed(email, "timeout (" + uk.slice(0, 30) + ")", pw, tok); return false;
        }
        if (lastUnknown !== uk) { lastUnknown = uk; lastUnknownAt = Date.now(); }
      }
    };
    return await challengeLoop();
  }
  log(`-> Inserting password....`);
  let __pwSeen = false;
  for (let i = 0; i < 10 && !__pwSeen; i++) {
    __pwSeen = !!(await evalJs(`(() => !!document.querySelector('input[type=password], input[name=Passwd], input[autocomplete="current-password"]'))()`).catch(() => false));
    if (!__pwSeen) await sleep(400);
  }
  if (!__pwSeen) { await screenshot(email).catch(() => {}); log("-> field password nggak muncul — abort akun ini (nggak klik buta)"); throw new Error("password field tidak ada"); }
  const __pwMarked = await evalJs(`(() => { const els=[...document.querySelectorAll('input[type=password], input[name=Passwd], input[autocomplete="current-password"]')]; const v=els.find(e=>e.offsetParent!==null && !e.disabled) || els[0]; if(!v) return false; v.setAttribute('data-kuli-pw','1'); v.focus(); v.click(); return true; })()`).catch(() => false);
  if (!__pwMarked) { log("-> nggak ada input password yang bisa difokusin — abort"); throw new Error("password field tidak bisa difokus"); }
  await typeChars('[data-kuli-pw="1"]', pw);
  let filled = Number(await evalJs(`(() => { const f = document.querySelector('[data-kuli-pw="1"], input[type=password], input[name=Passwd], input[autocomplete="current-password"]'); return f ? f.value.length : 0; })()`));
  if (!filled) {
    try {
      await evalJs(`(() => { const f = document.querySelector('input[type=password]'); if (f) { f.focus(); f.click(); } })()`);
      await send("Input.insertText", { text: pw });
    } catch {}
    filled = Number(await evalJs(`(() => { const f = document.querySelector('[data-kuli-pw="1"], input[type=password], input[name=Passwd], input[autocomplete="current-password"]'); return f ? f.value.length : 0; })()`));
  }
  log(`-> password terisi: ${filled} char`);
  if (!filled) { await screenshot(email).catch(() => {}); log("-> password MASIH kosong — abort akun ini, nggak klik Next"); throw new Error("password kosong"); }
  await clickNext();
  await sleep(3000); // fixed post-submit delay
  // Quick wrong-password / invalid-creds check right after submit (don't wait 300s for it)
  {
    const stq = await state();
    const Tq = stq.text + " " + stq.title;
    if (/Wrong password|password was incorrect|couldn't sign you in|Try again or click Forgot password/i.test(Tq)) {
      log(`-> Wrong password for ${email} — skipping.`);
      markFailed(email, "bad creds", pw, tok);
      return false;
    }
  }
  // outcome poll
  const t0 = Date.now();
  let findingLogged = false;
  let codeLogged = false;
  let lastUnknown = null;
  let lastUnknownAt = 0;
  let unknownWaits = 0; // cap human assists here too (mirror of challengeLoop)
  const MAX_WAITS2 = NO_VNC_FLAG ? 1 : 3; // headless: no eyes — one wait max
  let actedOn = null;   // url of the last auto-skip action
  let actedAt = 0;
  const acted = async (url) => { if (actedOn === url && Date.now() - actedAt < 25000) return true; actedOn = url; actedAt = Date.now(); await sleep(2000); return false; };
  while (Date.now() - t0 < 300000) {
    await sleep(2500);
    const st = await state();
    if (MAILRE.test(st.url)) {
      return await finishLogin(email, pw, tok);
    }
    const T = st.text + " " + st.title;
    // 2FA AUTHENTICATOR SETUP screen: "Open your authenticator app" + a setup key.
    // Not a one-time code yet — show the key / wait for manual entry in VNC.
    if (/Open your authenticator app|and this key|space's don't matter|spaces don.t matter|authenticator app/i.test(T) && !/verification code/i.test(T)) {
      const keyMatch = T.match(/([a-z0-9]{4}(?: [a-z0-9]{4})+)/i);
      if (keyMatch) {
        log(`-> Authenticator setup key found: ${maskSecret(keyMatch[1])}`);
        const saved = saveSecretFromScreen(email, keyMatch[1]);
        log(saved ? "-> Saved 2FA secret; future logins auto-fill via local TOTP" : "-> Could not save 2FA secret");
        // try to auto-complete right away: fetch code and type it if a code field is present
        const auto = await fetch2FA(email);
        const stNow = await state();
        const codeInput = stNow.inputs.find((x) => x.includes("tel") || x.includes("code"));
        if (auto && codeInput) {
          const sel = codeInput ? `input[type=tel]` : `input[type=text]`;
          log(`-> Auto-filled code from ${auto.source}: ${maskCode(auto.code)}`);
          await setInput(sel, auto.code); await sleep(300); await submitForm(); await sleep(1500);
  try { const pt = String(await evalJs("document.body.innerText.replace(/\n+/g, ' ').slice(0, 150)")); const pu2 = String(await evalJs("location.pathname")); log(`-> setelah password: ${pu2.slice(0, 42)} | "${pt.slice(0, 70)}"`); } catch {} continue;
        }
        log("-> Waiting for manual 2FA code entry in VNC (or a 2FA token via CLI)...");
      } else {
        log("-> Authenticator setup screen detected; waiting for manual handling in VNC...");
      }
      await sleep(3000);
      continue;
    }
    if (/Verify it's you|Check your/i.test(T)) {
      if (!findingLogged) { log('-> Finding text "Verify it\'s you" and "Passkey" and getting the code'); findingLogged = true; log(`-> Verify path: ${USE_SECURITY_CODE ? "security-code (opt-in)" : "tap-notification (default)"}`); }
      if (USE_SECURITY_CODE) {
        if (await clickText("Try another way")) await sleep(2500);
        if (await trySecurityCodeMethod()) { await tryTotpAutofill(email, tok); continue; }
        if (await tryTotpAutofill(email, tok)) continue;
        // LAST fallback: tap-number relay below
      }
      // Prefer the phone/SMS option over a recovery-email code. If the current
      // screen is the email-code path (an "Enter code" field + recovery-email text),
      // switch to "Try another way" and pick the phone/SMS method so we can relay it.
      const isEmailCode = /email with a verification code|recovery email|Enter code/i.test(T) && /Try another way/i.test(T);
      if (isEmailCode) {
        log("-> Email-code challenge; switching to phone/SMS method");
        if (await clickText("Try another way")) await sleep(2500);
        // pick a phone/SMS/text option
        const picked = await evalJs(`(() => {
          const opts=[...document.querySelectorAll('button,[role=button],a,li,div')];
          const re=/Text message|Get a security code|verification code on your phone|\\+[0-9]{1,3}([\\s-]?[0-9]){6,}|Send a code|\\bSMS\\b|Get a verification code/i;
          const el=opts.find(x=>re.test((x.innerText||'').trim()) && (x.innerText||'').trim().length<80);
          if(el){el.click();return true;} return false;
        })()`);
        if (picked) { log("-> Selected phone/SMS verification"); await sleep(2500); }
        else { log("-> Could not find a phone option; trying 'Try another way' once more"); await clickText("Try another way"); await sleep(2500); }
      }
      if (/Passkey/i.test(T)) {
        // passkey path: try another way -> tap yes on phone
        if (await clickText("Try another way")) { await sleep(2500); }
        await evalJs(`(() => { const b=[...document.querySelectorAll('button,[role=button],a')].find(x=>/Tap Yes on your phone/i.test(x.innerText||'')); if(b){b.click();return true;} return false; })()`);
        await sleep(2000);
      }
      const st2 = await state();
      const code = extractCode(st2.text);
      if (code && !codeLogged) { log(`-> Code found! Click ${code} on your phone. Waiting....`); codeLogged = true; }
      else if (!code) { log("-> No text match, continuing...."); }
      continue;
    }
    if (/Set a home address|Home address|personalize your experiences/i.test(T)) { if (await acted(st.url)) continue; log("-> Wizard detected; clicking Skip"); await clickText("Skip"); continue; }
    // 2-Step Verification method chooser: pick "Google Authenticator app" so the base32
    // TOTP auto-fill can complete it. Must come BEFORE the phone/recovery branches.
    // ONLY fires on the actual chooser URL (/challenge/selection) — the TOTP screen also
    // shows "2-Step Verification" text but must fall through to the code-fill branch.
    if (/\/challenge\/selection/.test(st.url) && /Google Authenticator|verification code from the Google Authenticator/i.test(T)) {
      if (await acted(st.url)) continue;
      log("-> 2-Step Verification chooser; clicking Google Authenticator app");
      // settle so coordinates are stable, then trusted-click the nested <a>/link.
      // Retry until the URL actually advances to /challenge/totp.
      let navigated = false;
      for (let attempt = 0; attempt < 5 && !navigated; attempt++) {
        await sleep(1500);
        const target = await evalJs(`(() => {
          // ONLY <li> / [role=option] — the outer container is a DIV and must NOT match.
          const opts=[...document.querySelectorAll('li, [role="option"]')].filter(x=>/Google Authenticator|verification code from the Google Authenticator/i.test((x.innerText||'').trim()) && x.offsetParent!==null && (x.innerText||'').trim().length < 120);
          if(!opts.length) return null;
          const li=opts[0];
          const a=li.querySelector('a,[role="link"],[jsaction],button') || li;
          const b=(a||li).getBoundingClientRect();
          return {x:b.x+b.width/2, y:b.y+b.height/2, h:b.height};
        })()`);
        if (target && target.x != null) {
          await send("Input.dispatchMouseEvent", { type: "mousePressed", x: target.x, y: target.y, button: "left", clickCount: 1 });
          await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: target.x, y: target.y, button: "left", clickCount: 1 });
          await sleep(2500);
          const u = await evalJs("location.href") || "";
          if (/\/challenge\/totp/.test(u)) { log(`-> Navigated to TOTP challenge (attempt ${attempt+1})`); navigated = true; }
          else if (attempt === 4) log("-> Click did not navigate; giving up");
        } else { log("-> Authenticator option not found; giving up"); break; }
      }
      if (!navigated) {
        log("-> Could not reach TOTP screen; skipping");
      }
      continue;
    }
    if (/Enter phone|Add a recovery phone|recovery email|Make sure you can always sign in/i.test(T)) { log('-> Checking for "Take selfie", "Home", or "Phone number"'); if (await acted(st.url)) continue; const cn = await clickText("Cancel") || await clickText("not now"); if (cn) log("-> Found! Clicking cancel"); continue; }
    if (/Selfie/i.test(T)) { log('-> Checking for "Take selfie", "Home", or "Phone number"'); if (await acted(st.url)) { log("-> Selfie screen: clicked once, waiting 25s…"); } else { log("-> Found! Clicking not now (manual ok in VNC if video selfie)"); await clickText("not now") || await clickText("Skip") || await clickText("Done") || await clickText("No thanks"); } continue; }
    if (/Enter your phone number|Phone number/i.test(T) && !/Phone number:/i.test(T)) { log('-> Checking for "Take selfie", "Home", or "Phone number"'); log("-> Found! Clicking cancel"); await clickText("cancel") || await clickText("Skip") || await clickText("Not now"); await sleep(1500); continue; }
    if (/^Home|Home\b/i.test(st.title || "") || /Save your password|Welcome/i.test(T)) { const cn = await clickText("not now") || await clickText("Skip") || await clickText("Done") || await clickText("No thanks"); if (cn) { log("-> Found! Clicking skip/not now"); } await sleep(1500); continue; }
    // post-verification onboarding wizard catch-all: any screen with Skip/Done/Not now/Later
    if (/recovery|protect your account|google one|set up|profile|personalize|recovery phone|recovery email|add.*phone|add.*email/i.test(T) && /Skip|Done|Not now|Later|No thanks|I.lld do this later/i.test(T)) {
      if (await acted(st.url)) continue;
      log("-> Post-verification onboarding wizard; clicking skip...");
      await clickText("Skip") || await clickText("Not now") || await clickText("Done") || await clickText("No thanks") || await clickText("I'll do this later");
      await sleep(1500);
      continue;
    }
    if (/Enter the code|Enter code|one-time-code|verification code|Enter security code|Get a code to sign in|g\.co\/sc/i.test(T)) {
      // g.co/sc "Get a code to sign in" screen: "Try another way" -> "Authenticator app" leads to TOTP.
      // IMPORTANT: do NOT auto-fill TOTP here — this screen wants a g.co/sc web code. Only
      // navigate toward the authenticator screen, then continue (fresh state next loop).
      if (/Get a code to sign in|g\.co\/sc/i.test(T)) {
        log("-> g.co/sc screen detected; switching to authenticator method");
        if (await clickText("Try another way")) { await sleep(2500); }
        // pick the authenticator option (click the nested <a>/role=link — the real navigable)
        const picked = await realClick(`(() => {
          const opts=[...document.querySelectorAll('li, [role="option"]')].filter(x=>/authenticator app|verification code from your authenticator|Enter code from your authenticator|Google Authenticator/i.test((x.innerText||'').trim()) && x.offsetParent!==null && (x.innerText||'').trim().length < 120);
          if(!opts.length) return null;
          const li=opts[0];
          const a=li.querySelector('a,[role="link"],[jsaction],button') || li;
          return a;
        })()`);
        if (picked) { log("-> Selected authenticator app; waiting for TOTP screen"); await sleep(3000); }
        else { log("-> Could not find authenticator option, trying 'Try another way' once more"); await clickText("Try another way"); await sleep(2500); }
        continue; // re-loop: fresh state() will see the TOTP screen, then the code fill below fires
      }
      // genuine TOTP / one-time-code entry screen
      const codeInput = st.inputs.find((x) => x.includes("tel") || x.includes("code"));
      if (tok) { log("-> Using provided 2FA token"); const sel = codeInput ? `input[type=tel]` : `input[type=text]`; await setInput(sel, tok); await sleep(300); await clickNext(); await sleep(1500); continue; }
      // auto-fill from local TOTP if a secret is stored for this account
      const auto = await fetch2FA(email);
      if (auto && codeInput) {
        const sel = codeInput ? `input[type=tel]` : `input[type=text]`;
        log(`-> Auto-filled code from ${auto.source}: ${maskCode(auto.code)}`);
        await setInput(sel, auto.code); await sleep(300); await clickNext(); await sleep(2000); continue;
      }
      log("-> No text match, continuing...."); continue;
    }
    if (/password was incorrect|couldn't sign you in|couldn't find your google account|Wrong password/i.test(T)) { log("-> Wrong password detected, skipping."); markFailed(email, "bad creds", pw, tok); return false; }
    if (/reCAPTCHA|I'?m not a robot|Verify you are human|not a robot/i.test(T)) {
      // try clicking the reCAPTCHA checkbox + alternative methods before giving up
      log("-> reCAPTCHA detected; attempting auto-solve...");
      const clicked = await evalJs(`(() => {
        const cb = document.querySelector('.recaptcha-checkbox-border, iframe[src*=recaptcha], [role=checkbox]') ||
                   [...document.querySelectorAll('*')].find(x=>x.classList.contains('recaptcha-checkbox-border'));
        if(cb){cb.click();return true;}
        return false;
      })()`);
      if (clicked) { log("-> Clicked reCAPTCHA checkbox, waiting 5s..."); await sleep(5000); continue; }
      // try "Try another way" -> phone/email instead
      log("-> reCAPTCHA checkbox not found; trying alternate method...");
      await sleep(4000);
      continue;
    }
    if (/Verifikasi info|verify your info|phone verification|QR code|scan the QR/i.test(T)) {
      log("-> Manual phone/QR verification detected");
      const ok = await waitHuman(email, "QR/phone verification", "gmail");
      if (ok) continue;               // reached Gmail — keep going
      markFailed(email, "manual-verify", pw, tok); return false;
    }
    if (/This browser or app may not be secure|Sign in blocked|Access blocked|Account disabled|Couldn.t sign you in/i.test(T)) {
      // wall: try to clear it (realClick) and resync state before manual verify
      try { await realClick(`[...document.querySelectorAll('button,a,[role=button]')].filter((x) => /continue|learn more|i understand|got it|next/i.test((x.innerText||'').trim()) && x.offsetParent !== null).slice(0, 1)`); await sleep(2500); await state(); } catch (e) { }
      // Headless browsers get this wall purely for being automated — no human tap
      // can fix it. Fail fast with a precise reason instead of burning 3×90s waits.
      if (NO_VNC_FLAG) { log("-> Insecure-browser wall headless — needs headed VNC run; marking failed"); markFailed(email, "insecure-browser", pw, tok); return false; }
      log("-> Security flag / access blocked — waiting for human (may unlock in VNC)");
      const ok = await waitHuman(email, "blocked screen", "gmail");
      if (ok) continue;
      markFailed(email, "blocked", pw, tok); return false;
    }
    if (/Your account is at risk|unusual sign-in|Confirm you're not a robot|suspicious|high risk/i.test(T)) {
      if (NO_VNC_FLAG) { log("-> Risk/robot challenge headless — needs eyes in VNC; marking failed"); markFailed(email, "risk/robot", pw, tok); return false; }
      log("-> Risk/robot challenge — waiting for human (may solve captcha in VNC)");
      const ok = await waitHuman(email, "risk/robot", "gmail");
      if (ok) continue;
      markFailed(email, "risk/robot", pw, tok); return false;
    }
    const uk = (st.title || st.url || "").slice(0, 120);
    if (/verify|confirm your identity|security check|activity|2[- ]step|challenge/i.test(T)) {
      if (lastUnknown !== uk) log("-> Verification page found (no auto-handler); waiting in VNC…");
      lastUnknown = uk; lastUnknownAt = Date.now();
    } else if (lastUnknown !== uk) {
      log("-> Checking for verification page....");
      log("-> No verification page, continuing....");
      lastUnknown = uk; lastUnknownAt = Date.now();
    } else if (Date.now() - lastUnknownAt > 60000) {
      // unknown screen stuck: give a human time in VNC (QR / captcha / phone tap) to fix it,
      // then if still not resolved, skip.
      log("-> Stuck on unknown screen >60s; waiting for human assistance in VNC...");
      const ok = await waitHuman(email, "unknown screen", "gmail");
      if (ok) {
        const v = await state();
        if (!MAILRE.test(v.url)) log("-> Assist resolved then bounced back to verification — counting as stuck...");
        if (++unknownWaits >= MAX_WAITS2) { markFailed(email, "persistent-unknown", pw, tok); break; }
        lastUnknown = ""; lastUnknownAt = Date.now(); continue;
      }
      markFailed(email, "timeout (" + uk.slice(0, 30) + ")", pw, tok); break;
    }
  }
  await screenshot(email);
  return false;
}

async function hardChromeReset() {
  try {
    sh(`pkill -9 -u ${UID} -f "chrome-real" || true`);
    sh(`pkill -9 -u ${UID} -f "remote-debugging-port" || true`);
  } catch {}
  await sleep(700);
    for (const d of [PROFILE_BASE, join(ROOT, ".chrome-profile")]) purgeProfileCaches(d);
    log("-> chrome soft reset: cache dibuang, identitas device (Cookies/Preferences) DIKEEP");
  try { sh("rm -rf /tmp/.org.chromium.Chromium.* 2>/dev/null || true"); } catch {}
  BROWSER_STARTED = false;
  log("-> chrome hard reset: proses mati, cache dibuang, PROFILE (Cookies/Preferences) DIKEEP");
}

async function resetBrowser(proxy) {
  // P2-1 hard restart ONLY (off the per-account hot path): pkill + fresh profile.
  // Hot path reuses the single browser; this runs on CDP-unreachable, proxy switch,
  // or every BROWSER_RESTART_EVERY accounts (Google 8-account session cap).
  sh(`pkill -u ${UID} -f "[r]emote-debugging-port=9222" ; sleep 1 ; rm -rf ${PROFILE}`);
  const headless = NO_VNC_FLAG && !XVFB_FLAG; // --xvfb runs headful under Xvfb
  const args = baseChromeArgs(headless);
  if (proxy) {
    // route login Chrome through the proxy; keep localhost (CDP) unproxied
    args.splice(args.length - 1, 0, `--proxy-server=${proxy}`, "--proxy-bypass-list=<-loopback>");
    log(`-> Using proxy: ${proxy.replace(/\/\/[^@:]+:[^@]+@/, "//***@")} (creds hidden)`);
    if (/\/\/[^/]*@/.test(proxy)) log("!! proxy credentials remain visible in Chrome cmdline via ps; prefer credential-less proxy or local forwarder");
  }
  detach(chromeBinary(headless), args);
  CURRENT_PROXY = proxy || null;
  ACCOUNTS_SINCE_RESTART = 0;
  BROWSER_STARTED = true;
  for (let i = 0; i < 30; i++) { try { const t = await (await fetch(`${CDP}/json`)).json(); if (t.some((x) => x.type === "page")) break; } catch {} await sleep(1000); }
  await connectCDP();
}

async function cdpAlive() {
  try {
    const t = await (await fetch(`${CDP}/json`, { signal: AbortSignal.timeout(5000) })).json();
    return Array.isArray(t);
  } catch { return false; }
}

// P2-1 one browser per batch: reuse the single Chrome across accounts.
// Per-account isolation = Network.clearBrowserCookies (loginOne) + fresh CDP target + P1-2 refreshWithCookies.
// Returns "reused" or "restarted"; throws on CDP failure so the P1-3 retry helper can hard-restart.
async function ensureBrowser(wantedProxy) {
  const wantProfile = profileFor(CUR_ACC);
  const prevProfile = PROFILE;
  const needsProfileSwitch = BROWSER_STARTED && wantProfile !== PROFILE;
  if (needsProfileSwitch) log(`-> rotating Chrome profile (device isolation) -> ${wantProfile.split("/").pop()}`);
  PROFILE = wantProfile;
  try { mkdirSync(PROFILE, { recursive: true }); } catch {}
  const want = wantedProxy || null;
  const needsPeriodic = BROWSER_STARTED && ACCOUNTS_SINCE_RESTART >= BROWSER_RESTART_EVERY;
  const needsProxySwitch = BROWSER_STARTED && (want !== CURRENT_PROXY);
  if (needsPeriodic) log(`-> Periodic browser restart every ${BROWSER_RESTART_EVERY} accounts (session cap)`);
  if (needsProxySwitch) log("-> Proxy switch detected; hard-restarting browser");
  if (BROWSER_STARTED && !needsPeriodic && !needsProxySwitch && !needsProfileSwitch && await cdpAlive()) {
    try {
      try { await fetch(`${CDP}/json/new?about:blank`); } catch {}
      await connectCDP();
      return "reused";
    } catch (e) {
      log("-> Reuse target failed, falling through to hard restart: " + String(e && e.message || e).slice(0, 100));
    }
  }
  await resetBrowser(want);
  if (prevProfile && prevProfile !== PROFILE) { try { rmSync(prevProfile, { recursive: true, force: true }); } catch {} }
  return "restarted";
}

async function isDone(acc) {
  const cfile = join(COOKIE_DIR, acc.email.replace(/[@.]/g, "_") + ".json");
  // self-heal: main file gone but a quarantined copy validates (false quarantine)?
  // Validate the copy IN PLACE — restore only on a VALID verdict, never on failure.
  try {
    const bad = join(COOKIE_DIR, "invalid", acc.email.replace(/[@.]/g, "_") + ".json");
    if (!existsSync(cfile) && existsSync(bad) && await cookieValidPath(bad)) {
      renameSync(bad, cfile);
      log(`-> Healed ${acc.email} (false quarantine) — skipping login.`);
      return true;
    }
  } catch {}
  if (existsSync(cfile)) {
    // fresh cookie files were verified moments ago (this or a parallel run) —
    // trust them without re-probing (a throttled probe false-negatives and would
    // quarantine a good cookie, causing exactly the dupe re-login it prevents).
    try {
      const ageMs = Date.now() - statSync(cfile).mtimeMs;
      const freshMs = Math.max(1, parseInt(process.env.BATCH_FRESH_MINUTES || "15", 10) || 15) * 60000;
      if (ageMs < freshMs) { log(`-> Skipping ${acc.email} (fresh cookies, ${Math.round(ageMs / 1000)}s old).`); return true; }
    } catch {}
    if (await cookieValid(acc.email)) return true;
    // one retry before verdict — throttled probes look exactly like dead sessions
    await sleep(5000);
    if (await cookieValid(acc.email)) { log(`-> ${acc.email} valid on retry (transient probe failure).`); return true; }
    // dead/stale cookie: quarantine and retry the login
    try { const bad = join(COOKIE_DIR, "invalid"); mkdirSync(bad, { recursive: true, mode: 0o700 }); renameSync(cfile, join(bad, acc.email.replace(/[@.]/g, "_") + ".json")); log(`-> quarantined stale cookie ${acc.email}`); } catch {}
    return false;
  }
  return false;
}

// P1-2 cookie-first refresh (no password use on this path).
// Reuses cookieValid (fetch check / fast path) + CDP Network domain.
async function refreshWithCookies(email) {
  try {
    const f = join(COOKIE_DIR, email.replace(/[@.]/g, "_") + ".json");
    if (!existsSync(f)) return false;
    let cookies;
    try { cookies = JSON.parse(readFileSync(f, "utf8")); } catch { return false; }
    if (!Array.isArray(cookies) || !cookies.length) return false;
    // No live CDP yet (e.g. before first resetBrowser): fall back to fetch check.
    if (typeof send === "undefined" || !send) return await cookieValid(email);
    await send("Network.clearBrowserCookies").catch(() => {});
    for (const c of cookies) {
      if (!c || !c.name) continue;
      try {
        await send("Network.setCookie", {
          name: c.name, value: String(c.value ?? ""),
          url: "https://mail.google.com/",
          domain: c.domain || ".google.com", path: c.path || "/",
          secure: !!c.secure, httpOnly: !!c.httpOnly,
        });
      } catch {}
    }
    await send("Page.navigate", { url: "https://mail.google.com/mail/u/0/" });
    await sleep(6000);
    const st = await state().catch(() => null);
    if (st && MAILRE.test(st.url || "")) {
      if (await saveCookies(email)) return true;
      return true;
    }
    return false;
  } catch { return false; }
}

// Normalize proxy string for Chromium --proxy-server:
//   socks5://user:pass:host:port  -> socks5://user:pass@host:port
//   socks5://user:pass@host:port  -> unchanged
//   host:port:user:pass           -> socks5://user:pass@host:port (webshare format)
function normalizeProxy(raw) {
  raw = String(raw).trim();
  let m;
  // scheme://creds@host:port  (already correct)
  if (/^(socks4|socks5|socks5h|http|https):\/\/.+@.+:\d+$/.test(raw)) return raw;
  // scheme://user:pass:host:port  (colon between pass and host — niceproxy format)
  m = raw.match(/^(socks4|socks5|socks5h|http|https):\/\/([^:]+):([^:]+):([^:]+):(\d+)$/);
  if (m) return `${m[1]}://${m[2]}:${m[3]}@${m[4]}:${m[5]}`;
  // host:port:user:pass  (webshare format)
  m = raw.match(/^([^:\s]+):(\d+):([^:]+):([^:]+)$/);
  if (m) return `socks5://${m[3]}:${m[4]}@${m[1]}:${m[2]}`;
  // host:port (no creds)
  m = raw.match(/^([^:\s]+):(\d+)$/);
  if (m) return `socks5://${m[1]}:${m[2]}`;
  return raw;
}

async function main() {
  // CLI: node run-batch.mjs [email [password [2fa]]] [--proxy <url|proxy.txt>] [--no-vnc] [--xvfb] [--security-code]
  // single-account password also via env RUNBATCH_PW (+RUNBATCH_TOK); proxy via env RUNBATCH_PROXY
  const argv = process.argv.slice(2);
  // pull out --proxy <val> (and handle --proxy=val) and --no-vnc / --security-code flags
  let proxyArg = process.env.RUNBATCH_PROXY || null;
  let proxyFlagSeen = false;
  let noVnc = false;
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--proxy") { proxyFlagSeen = true; proxyArg = argv[i + 1] || ""; i++; }
    else if (argv[i].startsWith("--proxy=")) { proxyFlagSeen = true; proxyArg = argv[i].slice("--proxy=".length); }
    else if (argv[i] === "--no-vnc") noVnc = true;
    else if (argv[i] === "--xvfb") { /* headful Xvfb, consumed via XVFB_FLAG global */ }
    else if (argv[i] === "--security-code") { /* opt-in: consumed here, active via USE_SECURITY_CODE global */ }
    else positional.push(argv[i]);
  }
  if (proxyFlagSeen && !proxyArg) { log("!! --proxy requires a value (URL or proxy.txt path)"); process.exit(1); }
  // resolve proxy list: single URL or a file (one per line, # comments ignored)
  const PROXY_LIST = (() => {
    if (!proxyArg) return [];
    if (proxyArg.endsWith(".txt")) {
      try {
        const txt = readFileSync(proxyArg, "utf8");
        const list = txt.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
        if (!list.length) throw new Error("empty");
        log(`-> Loaded ${list.length} proxies from ${proxyArg}`);
        return list.map(normalizeProxy);
      } catch (e) { log(`!! Cannot read proxy file ${proxyArg}: ${String(e.message || e)}`); process.exit(1); }
    }
    return [normalizeProxy(proxyArg)];
  })();
  // smart load-balancing proxy assignment:
  // - each proxy logs in 1-3 random accounts first
  // - when every proxy has hit the cap (3), pick the least-used proxy
  // - ties go to the first in the list (top); recycles indefinitely.
  const proxyUsage = PROXY_LIST.map(() => 0); // accounts assigned per proxy
  const proxyFor = () => {
    if (!PROXY_LIST.length) return null;
    // 1) pick randomly among proxies that have used < 3 accounts
    const available = PROXY_LIST.map((_, i) => i).filter((i) => proxyUsage[i] < 3);
    if (available.length) {
      const pick = available[Math.floor(Math.random() * available.length)];
      proxyUsage[pick]++;
      return PROXY_LIST[pick];
    }
    // 2) all proxies at cap — reuse the least-used one (ties -> first in list)
    const min = Math.min(...proxyUsage);
    const leastUsed = PROXY_LIST.map((_, i) => i).filter((i) => proxyUsage[i] === min);
    const pick = leastUsed[0];
    proxyUsage[pick]++;
    return PROXY_LIST[pick];
  };

  for (let i = positional.length - 1; i >= 0; i--) if (String(positional[i]).startsWith("--")) positional.splice(i, 1);
let todo;
  const envPw = process.env.RUNBATCH_PW || "";
  const envTok = process.env.RUNBATCH_TOK || "";
  const isSingleEnv = positional.length === 1 && !!envPw;
  if (positional.length >= 2) {
    log("!! password on command line is visible via ps; prefer RUNBATCH_PW");
    todo = [{ email: positional[0], pw: positional[1], tok: positional[2] || "" }];
  } else if (isSingleEnv) {
    todo = [{ email: positional[0], pw: envPw, tok: envTok || "" }];
  } else {
    if (envPw) log("!! RUNBATCH_PW is set but no single-account email given; ignoring env password");
    todo = buildTodo({
      listFile: LIST_FILE,
      loggedFile: LOGGED_FILE,
      failedFile: FAILED_FILE,
      argv: process.argv,
      parseLine,
      all: process.argv.includes("--all"),
    });
async function fastCookieAlive(email) {
  const fn = String(email).toLowerCase().replace(/\./g, "_").replace(/@/g, "_") + ".json";
  const fp = join(COOKIE_DIR, fn);
  if (!existsSync(fp)) return { alive: false, why: "NO-COOKIE" };
  let arr = [];
  try { arr = JSON.parse(readFileSync(fp, "utf8")); } catch { return { alive: false, why: "PARSE_ERR" }; }
  const hdr = arr.filter((c) => String(c.domain || "").includes("google")).map((c) => `${c.name}=${c.value}`).join("; ");
  if (!hdr) return { alive: false, why: "EMPTY_COOKIE" };
  try {
    const r = await fetch("https://mail.google.com/mail/u/0/", { headers: { Cookie: hdr, "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/153.0.0.0 Safari/537.36" }, redirect: "manual", signal: AbortSignal.timeout(15000) });
    if (r.status === 200) return { alive: true, why: "200" };
    return { alive: false, why: `${r.status}` };
  } catch { return { alive: false, why: "NET_ERR" }; }
}

if (process.argv.includes("--logged-out") && !process.argv.slice(2).some((a) => a && a.includes("@"))) {
  const allEntries = buildTodo({ listFile: LIST_FILE, loggedFile: LOGGED_FILE, failedFile: FAILED_FILE, argv: [...process.argv, "--all"] });
  const byEmail = new Map(allEntries.map((x) => [String((x && x.email) || "").toLowerCase(), x]));
  const cand = [];
  const seen = new Set();
  for (const line of readFileSync(LOGGED_FILE, "utf8").split("\n")) {
    const e = String(line).split("|")[0].trim().toLowerCase();
    if (!e.includes("@") || seen.has(e)) continue;
    seen.add(e);
    cand.push(e);
  }
  const DRY = process.argv.includes("--dry");
  log(`-> --logged-out: cek ${cand.length} akun di logged.txt${DRY ? " (dry-run)" : ""}`);
  const t0 = Date.now();
  const verdict = new Map();
  for (let i = 0; i < cand.length; i += 8) {
    const batch = cand.slice(i, i + 8);
    await Promise.all(batch.map(async (e) => {
      let res = { alive: false, why: "ERR" };
      try { res = await fastCookieAlive(e); } catch {}
      verdict.set(e, res.alive);
      log(`   ${e}: ${res.alive ? "ALIVE" : "LOGGED_OUT"} (${res.why})`);
    }));
  }
  const dead = cand.filter((e) => !verdict.get(e));
  log(`-> hasil: ${cand.length - dead.length} alive, ${dead.length} logout (${Math.round((Date.now() - t0) / 1000)}s)`);
  if (DRY) { log("-> dry-run: nggak login apa-apa"); process.exit(0); }
  todo = dead.map((e) => byEmail.get(e) || { email: e, pw: "", tok: "" });
  if (!todo.length) { log("-> nggak ada akun logout, kelar"); process.exit(0); }
}
const WANT_EMAIL = (process.argv.slice(2).find((a) => a && a.includes("@")) || "").trim().toLowerCase();
if (WANT_EMAIL && !process.argv.includes("--all")) {
  let hits = todo.filter((x) => String((x && x.email) || "").toLowerCase() === WANT_EMAIL);
  if (!hits.length) {
    for (const line of readFileSync(LIST_FILE, "utf8").split("\n")) {
      const parts = line.split("|");
      if ((parts[0] || "").trim().toLowerCase() !== WANT_EMAIL) continue;
      hits = [{ email: parts[0].trim(), pw: (parts[1] || "").trim(), tok: "" }];
      break;
    }
  }
  log(`-> single-account: ${WANT_EMAIL} (${hits.length} dari ${todo.length} queue)`);
  todo = hits;
  if (!todo.length) { log("!! akun nggak ada di queue"); process.exit(1); }
}
    if (process.argv.includes("--failed")) log(`-> --failed: ${todo.length} akun dari failed.txt`);
    else if (process.argv.includes("--all")) log(`-> --all: ${todo.length} akun (abaikan logged.txt)`);
    else log(`-> todo: ${todo.length} akun (list.txt dikurangi logged.txt)`);
  }
  try {
  for (let accnumber = 0; accnumber < todo.length; accnumber++) {
    const acc = todo[accnumber];
    CUR_ACC = acc.email || "";
    if (!positional.length && await isDone(acc)) { log(`-> Skipping ${acc.email} (valid cookies).`); continue; }
    const { email, pw, tok } = acc;
    // P1-2 cookie-first refresh (password-free): try existing cookies before any browser work.
    try {
      const cfile = join(COOKIE_DIR, email.replace(/[@.]/g, "_") + ".json");
      if (existsSync(cfile) && await refreshWithCookies(email)) {
        log(`-> cookie refresh ok ${email}`);
        try { await reconcileFailed(); } catch {}
        try { await demoteDeadLogged(); } catch {}
        log("-> Cleaning environment for next account....");
    await hardChromeReset();
        await sleep(8000); // FIXED cooldown between accounts
        await sleep(2000);
        continue;
      }
    } catch {}
    // P2-1 one browser per batch: reuse single Chrome (isolation = clearBrowserCookies + fresh CDP target + P1-2 refresh).
    // Hard restart only on CDP-unreachable (P1-3 retry), proxy switch, or every BROWSER_RESTART_EVERY accounts.
    const wantedProxy = proxyFor();
    let browserReady = false;
    for (let attempt = 1; attempt <= 3 && !browserReady; attempt++) {
      try {
        const how = await ensureBrowser(wantedProxy);
        log(how === "reused" ? `-> Reusing browser for ${email} (${ACCOUNTS_SINCE_RESTART}/${BROWSER_RESTART_EVERY} since restart)` : `-> Browser restarted for ${email}`);
        browserReady = true;
      } catch (e) {
        log(`!! ensureBrowser failed (attempt ${attempt}/3): ${String(e && e.message || e).slice(0, 120)}`);
        try { log("-> liveness free -m: " + sh("free -m | tail -5").replace(/\n/g, " | ")); } catch {}
        try { log("-> liveness /dev/shm: " + sh("df -h /dev/shm 2>&1 | tail -3").replace(/\n/g, " | ")); } catch {}
        try {
          const t = await (await fetch(`${CDP}/json`, { signal: AbortSignal.timeout(5000) })).json();
          log(`-> liveness CDP /json reachable: ${Array.isArray(t) ? t.length : 0} targets`);
        } catch (ee) { log(`-> liveness CDP /json unreachable: ${String(ee && ee.message || ee).slice(0, 120)}`); }
        if (attempt >= 3) {
          markFailed(email, 'cdp-unreachable', pw, tok);
          break;
        }
        await sleep(2000);
      }
    }
    if (!browserReady) { continue; }
    try { await loginOne(acc); } catch (e) { log("ERR " + String(e)); }
    ACCOUNTS_SINCE_RESTART++;
    log("-> Cleaning environment for next account....");
    await hardChromeReset();
    await sleep(8000); // FIXED cooldown between accounts
    await sleep(2000);
  }
  } finally {
  log("-> Batch finished.");
  // single-account runs (argv pw or env pw) must not drain the shared queue —
  // only the attempted address may leave list.txt, and only via logged/failed.
  cleanupList(positional.length >= 1);
  if (!NO_VNC_FLAG || XVFB_FLAG) { log("-> Clearing VNC stack...."); clearVnc(); }
  else { log("-> --no-vnc: killing login browser...."); killBrowser(); }
  }
  process.exit(0);
}
// remove from list.txt any account now in logged.txt (success) or failed.txt (hard fail),
// so the next run only processes accounts that still need login. Skipped entirely in
// single-shot mode (one address given): the shared queue is not ours to drain.
function cleanupList(singleShot) {
  log("-> list.txt = master (tidak diubah); progress ada di logged.txt / failed.txt");
}
function killBrowser() {
  // the login browser must die with the batch in EVERY mode — a leaked headless
  // Chrome eats ~500MB and fails the next run's RAM preflight.
  for (const c of SPAWNED) { try { process.kill(c.pid, "SIGTERM"); } catch {} }
  const waitMs = globalThis.__fastKill ? 800 : 7000;
  const _tk = Date.now();
  while (Date.now() - _tk < waitMs) {
    const alive = SPAWNED.some((c) => { try { process.kill(c.pid, 0); return true; } catch { return false; } });
    if (!alive) break;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
  }
  for (const c of SPAWNED) { try { process.kill(c.pid, "SIGKILL"); } catch {} }
  try { sh(`pkill -u ${UID} -f "[r]emote-debugging-port=9222" ; true`); } catch {}
}
function clearVnc() {
  killBrowser();
  try { sh(`pkill -u ${UID} -f "[x]11vnc -display ${DISPLAY}" ; pkill -u ${UID} -f "[w]ebsockify ${VNC_PORT}" ; pkill -u ${UID} -f "[X]vfb ${DISPLAY}" ; true`); } catch {}
}
process.on("uncaughtException", (err) => {
  const msg = err && err.stack ? err.stack : String(err);
  log(`!! uncaughtException: ${msg}`);
  void captureFailArtifacts(shotPath(ROOT, "fatal", "uncaught")).catch(() => { });
  setTimeout(() => process.exit(1), 1500);
});
process.on("unhandledRejection", (err) => {
  const msg = err && err.stack ? err.stack : String(err);
  log(`!! unhandledRejection: ${msg}`);
});
function backupState(tag) {
  try {
    const dir = join(ROOT, "_backup_files", `state-${tag}-${new Date().toISOString().replace(/[:.]/g, "-")}`);
    mkdirSync(dir, { recursive: true });
    try { sh(`cp -a "${COOKIE_DIR}" "${dir}/cookies" 2>/dev/null`); } catch {}
    for (const f of ["list.txt", "logged.txt", "failed.txt"]) { const q = join(ROOT, f); if (existsSync(q)) { try { sh(`cp -a "${q}" "${dir}/"`); } catch {} } }
    if (!globalThis.__fastKill) { try { sh(`cd "${ROOT}" && tar czf "${dir}/profiles-id.tar.gz" --exclude='*/Cache' --exclude='*/Code Cache' --exclude='*/GPUCache' --exclude='*/Service Worker' .chrome-profiles 2>/dev/null`); } catch {} }
    try {
      const bdir = join(ROOT, "_backup_files");
      const states = fsReaddir(bdir, { withFileTypes: true }).filter((e) => e.isDirectory() && e.name.startsWith("state-")).map((e) => e.name).sort();
      while (states.length > 8) {
        const old = states.shift();
        try { mkdirSync(join(ROOT, ".trash"), { recursive: true }); sh(`mv "${join(bdir, old)}" "${join(ROOT, ".trash", old)}"`); } catch {}
      }
    } catch {}
    log(`-> backup state (${tag}): ${dir}`);
    return dir;
  } catch (e) { log("!! backup state gagal: " + ((e && e.message) || e)); return ""; }
}

async function verifySessions(reason = "finish") {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outFile = join(ROOT, "logs", `session-verify-${stamp}.txt`);
  const readRows = (f) => { try { return readFileSync(f, "utf8").split("\n").map((l) => l.trim()).filter(Boolean); } catch { return []; } };
  const parse = (f) => readRows(f).map((l) => { const parts = l.split("|"); return { e: (parts[0] || "").trim(), rest: parts.slice(1), raw: l }; }).filter((r) => /\S+@\S+\.\S+/.test(r.e));
  const list = parse(LIST_FILE), logged = parse(LOGGED_FILE), failed = parse(FAILED_FILE);
  const pwOf = new Map([...list, ...logged].map((r) => [r.e, r.rest[0] || ""]));
  const emails = [...RUN_LOGGED];
  if (!emails.length) { log("-> verify sesi: nggak ada akun yang dilogin di run ini — skip"); return []; }
  const waitMs = Math.max(0, VERIFY_WAIT_MS);
  if (waitMs) { log(`-> verify sesi: nunggu ${Math.round(waitMs / 1000)}s biar cookie settle dulu...`); await sleep(waitMs); }
  const rows = [];
  for (const e of emails) {
    const f = join(COOKIE_DIR, e.replace(/[@.]/g, "_") + ".json");
    const where = logged.some((r) => r.e === e) ? "logged" : failed.some((r) => r.e === e) ? "failed" : "list";
    if (!existsSync(f)) { rows.push({ e, st: "NO-COOKIE", where }); continue; }
    let st = "DEAD";
    try { st = (await cookieValidPath(f)) ? "OK" : "DEAD"; } catch { st = "ERR"; }
    rows.push({ e, st, where });
  }
  try { mkdirSync(join(ROOT, "logs"), { recursive: true }); writeFileSync(outFile, rows.map((r) => `${r.e}|${r.st}|${r.where}`).join("\n") + "\n"); } catch {}
  const cnt = (s) => rows.filter((r) => r.st === s).length;
  log(`-> verify sesi (${reason}): OK ${cnt("OK")} | DEAD ${cnt("DEAD")} | NO-COOKIE ${cnt("NO-COOKIE")}${cnt("ERR") ? " | ERR " + cnt("ERR") : ""} | total ${rows.length}`);
  log(`-> laporan: ${outFile}`);
  const okRows = rows.filter((r) => r.st === "OK");
  const demoted = rows.filter((r) => r.where === "logged" && (r.st === "DEAD" || r.st === "NO-COOKIE"));
  const promoted = okRows.filter((r) => r.where !== "logged");
  if (okRows.length || demoted.length) backupState("verify");
  try {
    if (demoted.length || promoted.length) {
      const loggedSet = new Set(logged.map((r) => r.e));
      for (const p of promoted) loggedSet.add(p.e);
      for (const d of demoted) loggedSet.delete(d.e);
      writeFileSync(LOGGED_FILE, [...loggedSet].map((e) => `${e}|${pwOf.get(e) || ""}`).join("\n") + (loggedSet.size ? "\n" : ""));
      const failedLines = readRows(FAILED_FILE).filter((l) => !promoted.some((p) => l.split("|")[0].trim() === p.e));
      const seenF = new Set(failedLines.map((l) => l.split("|")[0].trim()));
      for (const d of demoted) if (!seenF.has(d.e)) failedLines.push(`${d.e}|verify-${d.st.toLowerCase()}|${new Date().toISOString()}`);
      writeFileSync(FAILED_FILE, failedLines.join("\n") + (failedLines.length ? "\n" : ""));
      log(`-> reconcile: +${promoted.length} ke logged.txt, -${demoted.length} ke failed.txt`);
    } else {
      log("-> reconcile: nggak ada perubahan");
    }
  } catch (e) { log("!! reconcile gagal: " + ((e && e.message) || e)); }
  return rows;
}

async function finishWithVerify(reason) {
  try { await verifySessions(reason); } catch (e) { log("!! verify: " + ((e && e.message) || e)); }
  globalThis.__verifiedExit = true;
  process.exit(0);
}

process.on("SIGINT", () => { globalThis.__fastKill = true; log("-> Interrupted; clearing VNC stack...."); clearVnc(); void finishWithVerify("interrupt"); });
const __realExit = process.exit.bind(process);
process.exit = (code = 0) => {
  if (globalThis.__verifiedExit) return __realExit(code);
  globalThis.__verifiedExit = true;
  verifySessions("exit").catch(() => {}).finally(() => __realExit(code));
};
process.on("beforeExit", () => { if (!globalThis.__verified) { globalThis.__verified = true; void verifySessions("finish"); } });
process.on("SIGTERM", () => { clearVnc(); void finishWithVerify("signal"); });
// terminal keybinds (TTY only): k = screenshot the login browser to
// screenshots/manual/<ts>-<account>.png (repeatable). Ctrl-C keeps working.
let CUR_ACC = "";
if (process.stdin.isTTY) {
  try {
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on("data", async (d) => {
      const k = d.toString();
      if (k === "\u0003") { log("-> Interrupted; clearing VNC stack...."); try { process.stdin.setRawMode(false); } catch {} globalThis.__fastKill = true; clearVnc(); process.exit(130); }
      if (k === "k" || k === "K") {
        const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
        const dir = join(ROOT, "screenshots", "manual");
        try { mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch {}
        try {
          if (typeof send === "function" && send) {
            const s = await send("Page.captureScreenshot", { format: "png" });
            const file = join(dir, `${stamp}-${(CUR_ACC || "batch").replace(/[^A-Za-z0-9._-]+/g, "_")}.png`);
            writeFileSync(file, Buffer.from(s.result.data, "base64"), { mode: 0o600 });
            log("-> Manual screenshot: " + file);
          } else log("-> No browser attached yet — screenshot skipped");
        } catch { log("-> Screenshot failed (no CDP page?)"); }
      }
    });
  } catch {}
}
if (process.argv.includes("--vnc-only")) {
  try {
    preflight();
    log(`-> VNC-ONLY siap. DISPLAY=${DISPLAY}; login manual di browser lewat VNC.`);
    log(`-> tunnel dari laptop: ssh -L 5900:127.0.0.1:5900 <user>@<host-ini>`);
    log(`-> password VNC: env VNC_PASSWORD (kalau kosong, dibaca dari .env)`);
    setInterval(() => { }, 1 << 30);
  } catch (e) {
    log("FATAL vnc-only: " + String(e && e.message ? e.message : e));
    process.exit(1);
  }
} else {
  main().catch((e) => { log("FATAL " + String(e)); clearVnc(); process.exit(1); });
}

function baseChromeArgs(headless) {
  const a = baseChromeArgsRaw(headless);
  const ua = winUa();
  if (!a.some((x) => String(x).startsWith("--user-agent="))) a.push("--user-agent=" + ua, "--lang=en-US");
  return a;
}

function winUa() { return loadEnv().CHROME_UA || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"; }
