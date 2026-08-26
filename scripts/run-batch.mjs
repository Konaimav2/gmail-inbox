#!/usr/bin/env node
// run-batch: semi-auto Gmail login batch from list.txt (email|password|2fa token optional)
// Flow: setup VNC+Chromium -> count accounts -> loop: login, handle challenge (phone-tap / passkey / code / selfie-home-phone skips), save cookies, next.
import { execSync, spawnSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// prefer system chrome; fall back to agent-browser
// prefer known-working headful binaries over snap chromium (snap often fails to bind CDP headless)
const CHROME_CANDIDATES = [
  "/root/.agent-browser/browsers/chrome-150.0.7871.46/chrome",
  "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "/usr/bin/chromium-browser",
];
const CHROME = (() => {
  for (const c of CHROME_CANDIDATES) {
    try { const p = spawnSync("bash", ["-c", `command -v '${c}'`], { encoding: "utf8" }).stdout.trim(); if (p) return p; } catch {}
    if (existsSync(c)) return c;
  }
  return "chromium";
})();
const PROFILE = join(ROOT, ".chrome-profile");
const COOKIE_DIR = join(ROOT, "cookies");
const LIST_FILE = join(ROOT, "list.txt");
const LOGGED_FILE = join(ROOT, "loggedmail.txt");
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
  try {
    const cur = existsSync(FAILED_FILE) ? readFileSync(FAILED_FILE, "utf8") : "";
    const lines = cur.split("\n").filter((l) => !l.startsWith(email + "|"));
    // format: email|password|[2fa] — keep the credential so the account can be
    // retried with 2FA on (token literal or .2fa-secrets authenticator).
    lines.push(pw ? `${email}|${pw}${tok ? `|${tok}` : ""}` : `${email}|${reason}`);
    writeFileSync(FAILED_FILE, lines.join("\n") + "\n");
  } catch {}
}
function clearFailed(email) {
  try {
    const cur = existsSync(FAILED_FILE) ? readFileSync(FAILED_FILE, "utf8") : "";
    writeFileSync(FAILED_FILE, cur.split("\n").filter((l) => !l.startsWith(email + "|")).join("\n"));
  } catch {}
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
      if (existing) existing.value = value; else jar.push({ name, value, domain: dm, path: pth, secure: /Secure/i.test(sc), expires: -1 });
    }
    if (res.status >= 300 && res.status < 400) { const loc = res.headers.get("location"); if (!loc) return { status: res.status, body: "" }; cur = new URL(loc, cur).toString(); continue; }
    return { status: res.status, body: await res.text(), jar };
  }
  return { status: 599, body: "" };
}
// true session check: simls payload present = actually signed in
async function cookieValid(email) {
  try {
    const f = join(COOKIE_DIR, email.replace(/[@.]/g, "_") + ".json");
    if (!existsSync(f)) return false;
    const cookies = JSON.parse(readFileSync(f, "utf8"));
    const { status, body } = await fetchWithJar(cookies, "https://mail.google.com/mail/u/0/h/?v=m&s=q&q=newer_than%3A30d");
    return status === 200 && /\"simls\",null,\"/.test(body);
  } catch { return false; }
}
const DISPLAY = ":99";
const CDP = "http://127.0.0.1:9222";
const OUT = "/tmp/batch-out.txt";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
mkdirSync(COOKIE_DIR, { recursive: true });
const log = (s) => { const line = s; console.log(line); try { appendFileSync(OUT, line + "\n"); } catch {} };
const sh = (cmd, opts = {}) => { try { return spawnSync("bash", ["-c", cmd], { encoding: "utf8", ...opts }).stdout.trim(); } catch { return ""; } };

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
// ensure /opt/noVNC/index.html -> vnc.html for convenience (http://ip:6080/ serves viewer directly)
try { sh("ln -sf vnc.html /opt/noVNC/index.html"); } catch {}
log("-> Setting up VNC and Chromium....");
const NO_VNC_FLAG = process.argv.slice(2).includes("--no-vnc");
if (!NO_VNC_FLAG) {
  sh(`pkill -f "[X]vfb ${DISPLAY}" ; pkill -f "[r]emote-debugging-port=9222" ; pkill -f "[x]11vnc -display ${DISPLAY}" ; pkill -f "[w]ebsockify 6080" ; sleep 1`);
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
  // 3. memory: VNC+Chrome+Xvfb need ~1.5GB free
  const memKB = sh("free -k | awk 'NR==2{print $7}'"); // available
  if (memKB && +memKB < 1024 * 1024) problems.push("low free RAM (" + Math.round(memKB / 1024) + "MB) — need ~1GB+");
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
sh(`rm -rf ${PROFILE}/Default/Cookies* 2>/dev/null; true`);
const detach = (cmd, args) => { const c = spawn(cmd, args, { detached: true, env: { ...process.env, DISPLAY }, stdio: ["ignore", "ignore", "ignore"] }); c.unref(); return c; };
if (!NO_VNC_FLAG) {
  detach("Xvfb", [DISPLAY, "-screen", "0", "1366x900x24", "-ac"]);
  await sleep(1500);
  detach(CHROME, [`--user-data-dir=${PROFILE}`, "--no-sandbox", "--no-first-run", "--disable-background-networking", "--window-size=1366,900", "--remote-debugging-port=9222", "about:blank"]);
  await sleep(2500);
  detach("x11vnc", ["-display", DISPLAY, "-forever", "-shared", "-passwd", VNCPASS, "-rfbport", "5900", "-bg", "-o", "/tmp/batch-x11vnc.log"]);
  // WebSocket tunnel + noVNC web UI for human assistance (QR/captcha/phone).
  // --web=/opt/noVNC serves ONLY noVNC's own files (vnc.html, js, css) — NOT project files.
  // websockify may resolve to "python3 -m websockify" or a bare binary; detach expects (cmd, args)
  const [wsCmd, ...wsPre] = String(WEBSOCKIFY).split(" ");
  detach(wsCmd, [...wsPre, `--web=/opt/noVNC`, `${VNC_BIND}:6080`, `localhost:5900`]);
  log(`-> VNC ready: http://${VNC_BIND}:6080/  (password in .env VNC_PASSWORD)`);
} else {
  log("-> --no-vnc: skipping Xvfb/VNC, starting headless Chromium...");
  detach(CHROME, [`--user-data-dir=${PROFILE}`, "--no-sandbox", "--no-first-run", "--disable-background-networking", "--window-size=1366,900", "--remote-debugging-port=9222", "about:blank"]);
  await sleep(2500);
}
// wait CDP
(async () => { for (let i = 0; i < 30; i++) { try { const t = await (await fetch(`${CDP}/json`)).json(); if (t.length) break; } catch {} await sleep(1000); } })();

// ------------------------------------------------ count accounts
log("-> Counting accounts....");
const lines = readFileSync(LIST_FILE, "utf8").split("\n").map((l) => l.trim()).filter(Boolean);
const accounts = [];
for (const l of lines) {
  const idx = l.indexOf("|");
  if (idx <= 0) { markFailed(l.slice(0, 40), "bad format"); continue; }
  const email = l.slice(0, idx).trim();
  const rest = l.slice(idx + 1);
  // password = EVERYTHING after the first | (may itself contain |);
  // 3rd field (after the last |) can be: a numeric TOTP code, a base32 secret,
  // or empty (no 2FA).
  let pw = rest, tok = "", secret = "";
  if (pw.endsWith("|")) pw = pw.slice(0, -1); // drop trailing empty 2FA field
  const lastBar = pw.lastIndexOf("|");
  if (lastBar > 0) {
    const tail = pw.slice(lastBar + 1).trim();
    if (/^\d{1,8}$/.test(tail)) { tok = tail; pw = pw.slice(0, lastBar).trim(); }
    else if (/^[A-Z2-7]{16,}$/i.test(tail.replace(/\s/g, ""))) {
      // base32 authenticator secret -> persist to .2fa-secrets so fetch2FA can compute codes
      secret = tail.replace(/\s/g, "").toUpperCase();
      try {
        const cur = existsSync(SECRETS_FILE) ? readFileSync(SECRETS_FILE, "utf8") : "";
        const others = cur.split("\n").filter((l) => l && !l.startsWith(email + "|"));
        others.push(`${email}|${secret}`);
        writeFileSync(SECRETS_FILE, others.join("\n") + "\n", { mode: 0o600 });
        log(`-> Saved base32 2FA secret for ${email}`);
      } catch {}
      pw = pw.slice(0, lastBar).trim();
    }
  }
  if (!pw && rest) pw = rest; // edge: password was only a pipe
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) && pw) accounts.push({ email, pw, tok, secret });
  else markFailed(email || l.slice(0, 40), "bad format");
}
const invalid = lines.length - accounts.length;
log(`-> Find ${accounts.length} valid and ${invalid} invalid format! Setting the loop to ${accounts.length}....`);

// ------------------------------------------------ cdp helpers
let ws, send, pageTarget;
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
      ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
      send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
      await send("Page.enable"); await send("Runtime.enable"); await send("Network.enable");
      await send("Page.addScriptToEvaluateOnNewDocument", { source: `Object.defineProperty(navigator,'webdriver',{get:()=>undefined}); window.chrome=window.chrome||{runtime:{}};` });
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
async function solveAudioCaptcha(timeoutMs = 60000) {
  const t0 = Date.now();
  // find reCAPTCHA frames (classic v2 AND enterprise)
  async function findCaptchaFrame() {
    for (const f of await send("Page.getFrameTree").then(r => r.result?.frameTree ? [r.result.frameTree] : []).catch(() => [])) {
      // flatten frame tree
      const walk = (n) => { let out = n.url ? [n] : []; (n.childFrames || []).forEach(c => out = out.concat(walk(c))); return out; };
      const all = walk(f);
      for (const fr of all) {
        if ((fr.url || "").includes("recaptcha") && (/anchor/.test(fr.url) || /bframe/.test(fr.url))) return fr;
      }
    }
    return null;
  }
  // audio element is inside the challenge; use main-frame JS to click by title/aria (post-iframe)
  const clicked = await evalJs(`(() => {
    const nodes = [...document.querySelectorAll('iframe')];
    for (const n of nodes) { try { const d = n.contentDocument; if(!d) continue; const b = [...d.querySelectorAll('button,[role=button]')].find(x => /audio/i.test((x.title||'')+' '+(x.getAttribute('aria-label')||''))); if (b) { b.click(); return 'clicked-js'; } } catch(e){} }
    return null; })()`).catch(() => null);
  if (clicked === "clicked-js") {
    log("-> Audio auto-solve: clicked audio switch (JS).");
    await sleep(2500);
  }
  // get audio src
  const src = await evalJs(`(() => {
    for (const n of document.querySelectorAll('iframe')) { try { const d = n.contentDocument; if(!d) continue; const a = d.getElementById('audio-source'); if (a && a.src) return a.src; const au = d.querySelector('audio'); if(au && au.currentSrc) return au.currentSrc; const s = d.querySelector('audio source'); if(s && s.src) return s.src; } catch(e){} }
    return ''; })()`).catch(() => "");
  if (!src) { log("-> Audio auto-solve: no audio source found."); return false; }

  // transcribe via sibling Python helper (proven pipeline)
  const { execFileSync } = await import("node:child_process");
  let answer = "";
  try {
    const out = execFileSync("/root/temp/token-harbor/.venv/bin/python3",
      [__dirname + "/audio-solver.py"], { input: JSON.stringify({ audio_url: src }), encoding: "utf8", timeout: 40000, stdio: ["pipe","pipe","pipe"] });
    const parsed = JSON.parse(out.trim().split("\n").pop());
    if (parsed.ok && parsed.answer) { answer = parsed.answer; }
    else log("-> Audio auto-solve: transcription failed: " + (parsed.error || "?"));
  } catch (e) { log("-> Audio auto-solve: python helper error: " + String(e).slice(0,80)); return false; }
  if (!answer) return false;
  log(`-> Audio auto-solve: heard "${answer}"`);

  // type + verify (trusted), the field may be in any recaptcha frame
  await evalJs(`(() => { for (const n of document.querySelectorAll('iframe')) { try { const d=n.contentDocument; if(!d) continue; const i=d.getElementById('audio-response'); if(i){ const s=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set; s.call(i, ${JSON.stringify(answer)}); i.dispatchEvent(new Event('input',{bubbles:true})); const v=d.getElementById('recaptcha-verify-button'); if(v) v.click(); return true; } } catch(e){} } return false; })()`).catch(() => false);
  // confirm token appeared
  const deadline = t0 + timeoutMs;
  while (Date.now() < deadline) {
    await sleep(3000);
    const tok = await evalJs(`(() => { try { const g=window.grecaptcha; if(g&&g.getResponse&&g.getResponse()) return g.getResponse(); } catch(e){} return ''; })()`).catch(() => "");
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
    // real success: reached Gmail inbox
    if (/\/mail\.google\.com\/mail/.test(u)) { log(`-> ${label}: reached Gmail — resolved`); return true; }
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
async function clickText(txt) {
  const t = String(txt).toLowerCase();
  return await realClick(`[...document.querySelectorAll('button,[role=button],a,div,span')].find(x=>(x.innerText||'').trim().toLowerCase()===${JSON.stringify(t)})`);
}
async function saveCookies(email) {
  const { result } = await send("Network.getAllCookies");
  const cookies = (result?.cookies || []).filter((c) => c.domain.includes("google.com"));
  if (!cookies.some((c) => ["SID", "SSID", "__Secure-1PSID"].includes(c.name) && c.value.length > 20)) return false;
  writeFileSync(join(COOKIE_DIR, email.replace(/[@.]/g, "_") + ".json"), JSON.stringify(cookies, null, 2));
  return true;
}
const SS_DIR = join(ROOT, "screenshots");
mkdirSync(SS_DIR, { recursive: true });
async function screenshot(email) {
  const file = join(SS_DIR, `fail-${email.replace(/[@.]/g,"_")}.png`);
  try { const s = await send("Page.captureScreenshot", { format: "png" }); writeFileSync(file, Buffer.from(s.result.data, "base64")); log("-> Screenshot saved: " + file); return true; } catch { return false; }
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

// ---- 2FA.live auto-fill ----
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
  // 1) try 2fa.live (the provider the user named) — may be down/renamed, so fall through
  try {
    const url = `https://2fa.live/totp/${encodeURIComponent(secret)}`;
    const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("json")) {
      const j = await r.json();
      const code = j?.token || j?.code || j?.data?.token || j?.data?.code;
      if (code && /^\d{6}$/.test(String(code))) return { code: String(code), source: "2fa.live" };
    }
  } catch {}
  // 2) compute TOTP locally (RFC 6238 / HMAC-SHA1, 30s step, 6 digits) — offline, always works
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

// ------------------------------------------------ main loop
// success path: save cookies + record to loggedmail
async function finishLogin(email, pw, tok) {
  await sleep(4000);
  const st = await state();
  if (!MAILRE.test(st.url)) { log("-> bounced after submit (not signed in): " + (st.url || "--").slice(0, 70)); return false; }
  log("-> Login complete, saving cookies....");
  const ok = await saveCookies(email);
  if (ok) {
    if (await cookieValid(email)) { log("-> Done! (session verified)"); clearFailed(email); try { const LGF = LOGGED_FILE; const cur = existsSync(LGF) ? readFileSync(LGF, "utf8") : ""; if (!cur.split("\n").some((l) => l.startsWith(email + "|"))) appendFileSync(LGF, `${email}|${pw}|${tok || ""}\n`); } catch {} }
    else { log("-> Cookie invalid after login (verification skipped) — marked failed"); markFailed(email, "session invalid", pw, tok); }
  } else log("-> Failed to save cookies (no session).");
  return ok;
}
async function loginOne(acc) {
  const { email, pw, tok } = acc;
  log(`-> Logging in account ${email}....`);
  await send("Network.clearBrowserCookies").catch(() => {});
  // kill any residual session so the identifier page is clean
  await send("Page.navigate", { url: "https://accounts.google.com/Logout" });
  await sleep(2500);
  await clickText("Sign out");
  await sleep(2000);
  await send("Page.navigate", { url: "https://accounts.google.com/AddSession?continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&hl=en" });
  await sleep(3500);
  // if account chooser is open, jump to "Use another account"
  const chooser = await evalJs(`(() => { const t=document.body.innerText||''; return /Use another account/i.test(t) ? true : false; })()`).catch(() => false);
  if (chooser) { await clickText("Use another account"); await sleep(2000); }
  // email
  for (let i = 0; i < 24; i++) { const s = await state(); if (s.inputs.some((x) => x.includes("email") || x.includes("identifier"))) break; await sleep(500); }
  const s1 = await state();
  const emailSel = 'input[name=identifier], #identifierId, input[type=email]';
  // verify the field has our email; type only if missing
  const cur = await evalJs(`(() => { const el=document.querySelector('input[name=identifier], #identifierId, input[type=email]'); return el?el.value:''; })()`).catch(() => "");
  if (cur !== email) { await typeChars('input[name=identifier], #identifierId, input[type=email]', email); }
  await clickNext();
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
      log("-> Captcha before password input detected; trying AUDIO AUTO-SOLVER first (VNC optional)...");
      const autoSolved = await solveAudioCaptcha(45000);
      if (autoSolved) {
        log("-> Audio auto-solver handled captcha; continuing.");
        i = 0; continue;   // re-evaluate current state (password field should now appear)
      }
      log("-> Audio auto-solver did not solve; falling back to human in VNC...");
      // webshare-style: poll for the grecaptcha token to confirm it's actually solved
      const captchaTimeout = Date.now() + 120000;
      let captchaResolved = false;
      let grecaptchaToken = "";
      while (Date.now() < captchaTimeout) {
        await sleep(2500);
        // Poll for grecaptcha token (webshare approach) — confirms real solve
        try {
          grecaptchaToken = await evalJs(`(() => { try { const gr = window.grecaptcha; if (gr && gr.getResponse && gr.getResponse()) return gr.getResponse(); } catch(e){}; const inp = document.querySelector('textarea[name="g-recaptcha-response"], input[name="g-recaptcha-response"]'); return inp ? inp.value : ''; })()`) || "";
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
        log("-> Captcha not solved after 120s, skipping.");
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
          if (!findingLogged) { log(`-> Finding text "Verify it's you" and "Passkey" and getting the code`); findingLogged = true; }
          const st2 = await state();
          const code = extractCode(st2.text);
          if (code && !codeLogged) { log(`-> Code found! Click ${code} on your phone. Waiting....`); codeLogged = true; }
          else if (!code) { log("-> No text match, continuing...."); }
          continue;
        }
        if (/Verifikasi info|verify your info|phone verification|QR code|scan the QR/i.test(T)) {
          log("-> Manual phone/QR verification detected");
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
        const uk = (st.title || st.url || "").slice(0, 120);
        if (lastUnknown === uk && Date.now() - lastUnknownAt > 60000) {
          log("-> Stuck on unknown screen >60s; waiting for human assistance...");
          const ok = await waitHuman(email, "unknown screen", "gmail");
          if (ok) { lastUnknown = ""; lastUnknownAt = Date.now(); continue; }
          markFailed(email, "timeout (" + uk.slice(0, 30) + ")", pw, tok); return false;
        }
        if (lastUnknown !== uk) { lastUnknown = uk; lastUnknownAt = Date.now(); }
      }
    };
    return await challengeLoop();
  }
  log("-> Inserting password....");
  await typeChars('input[type=password]', pw);
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
        log(`-> Authenticator setup key found: ${keyMatch[1]}`);
        const saved = saveSecretFromScreen(email, keyMatch[1]);
        log(saved ? "-> Saved 2FA secret; future logins auto-fill via 2fa.live" : "-> Could not save 2FA secret");
        // try to auto-complete right away: fetch code and type it if a code field is present
        const auto = await fetch2FA(email);
        const stNow = await state();
        const codeInput = stNow.inputs.find((x) => x.includes("tel") || x.includes("code"));
        if (auto && codeInput) {
          const sel = codeInput ? `input[type=tel]` : `input[type=text]`;
          log(`-> Auto-filled code from ${auto.source}: ${auto.code}`);
          await setInput(sel, auto.code); await sleep(300); await submitForm(); await sleep(1500); continue;
        }
        log("-> Waiting for manual 2FA code entry in VNC (or a 2FA token via CLI)...");
      } else {
        log("-> Authenticator setup screen detected; waiting for manual handling in VNC...");
      }
      await sleep(3000);
      continue;
    }
    if (/Verify it's you|Check your/i.test(T)) {
      if (!findingLogged) { log('-> Finding text "Verify it\'s you" and "Passkey" and getting the code'); findingLogged = true; }
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
      // auto-fill from 2fa.live if a secret is stored for this account
      const auto = await fetch2FA(email);
      if (auto && codeInput) {
        const sel = codeInput ? `input[type=tel]` : `input[type=text]`;
        log(`-> Auto-filled code from ${auto.source}: ${auto.code}`);
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
    if (/This browser or app may not be secure|Sign in blocked|Access blocked|Account disabled/i.test(T)) {
      log("-> Security flag / access blocked — waiting for human (may unlock in VNC)");
      const ok = await waitHuman(email, "blocked screen", "gmail");
      if (ok) continue;
      markFailed(email, "blocked", pw, tok); return false;
    }
    if (/Your account is at risk|unusual sign-in|Confirm you're not a robot|suspicious|high risk/i.test(T)) {
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
      if (ok) { lastUnknown = ""; lastUnknownAt = Date.now(); continue; }
      markFailed(email, "timeout (" + uk.slice(0, 30) + ")", pw, tok); break;
    }
  }
  await screenshot(email);
  return false;
}

async function resetBrowser(proxy) {
  // fresh chrome profile per account run: avoids the 8-account-per-session cap
  sh(`pkill -f "[r]emote-debugging-port=9222" ; sleep 1 ; rm -rf ${PROFILE}`);
  const args = [`--user-data-dir=${PROFILE}`, "--no-sandbox", "--no-first-run", "--disable-background-networking", "--window-size=1366,900", "--remote-debugging-port=9222"];
  if (NO_VNC_FLAG) args.push("--headless=new", "--disable-gpu", "--disable-dev-shm-usage");
  if (proxy) {
    // route login Chrome through the proxy; keep localhost (CDP) unproxied
    args.push(`--proxy-server=${proxy}`, "--proxy-bypass-list=<-loopback>");
    log(`-> Using proxy: ${proxy.replace(/\/\/[^@:]+:[^@]+@/, "//***@")} (creds hidden)`);
  }
  args.push("about:blank");
  detach(CHROME, args);
  for (let i = 0; i < 30; i++) { try { const t = await (await fetch(`${CDP}/json`)).json(); if (t.some((x) => x.type === "page")) break; } catch {} await sleep(1000); }
  await connectCDP();
}

async function isDone(acc) {
  const cfile = join(COOKIE_DIR, acc.email.replace(/[@.]/g, "_") + ".json");
  if (existsSync(cfile)) {
    if (await cookieValid(acc.email)) return true;
    // dead/stale cookie: quarantine and retry the login
    try { const bad = join(COOKIE_DIR, "invalid"); mkdirSync(bad, { recursive: true }); renameSync(cfile, join(bad, acc.email.replace(/[@.]/g, "_") + ".json")); log(`-> quarantined stale cookie ${acc.email}`); } catch {}
    return false;
  }
  return false;
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
  // CLI: node run-batch.mjs [email password [2fa]] [--proxy <url|proxy.txt>]
  const argv = process.argv.slice(2);
  // pull out --proxy <val> (and handle --proxy=val) and --no-vnc flag
  let proxyArg = null;
  let noVnc = false;
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--proxy") { proxyArg = argv[i + 1] || ""; i++; }
    else if (argv[i].startsWith("--proxy=")) proxyArg = argv[i].slice("--proxy=".length);
    else if (argv[i] === "--no-vnc") noVnc = true;
    else positional.push(argv[i]);
  }
  if (argv.some((a) => a === "--proxy") && !proxyArg) { log("!! --proxy requires a value (URL or proxy.txt path)"); process.exit(1); }
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

  let todo;
  if (positional.length >= 2) {
    todo = [{ email: positional[0], pw: positional[1], tok: positional[2] || "" }];
  } else {
    todo = accounts;
  }
  for (let accnumber = 0; accnumber < todo.length; accnumber++) {
    const acc = todo[accnumber];
    if (!positional.length && await isDone(acc)) { log(`-> Skipping ${acc.email} (valid cookies).`); continue; }
    if (!NO_VNC_FLAG) {
  log("-> Setting up VNC and Chromium (fresh)....");
} else {
  log("-> Starting headless Chromium...");
}
    await resetBrowser(proxyFor());
    try { await loginOne(acc); } catch (e) { log("ERR " + String(e)); }
    log("-> Cleaning environment for next account....");
    await sleep(8000); // FIXED cooldown between accounts
    await sleep(2000);
  }
  log("-> Batch finished.");
  cleanupList(positional.length >= 2);
  if (!NO_VNC_FLAG) { log("-> Clearing VNC stack...."); clearVnc(); }
  else { log("-> --no-vnc: skipping VNC cleanup"); }
  process.exit(0);
}
// remove from list.txt any account now in loggedmail.txt (success) or failed.txt (hard fail),
// so the next run only processes accounts that still need login. Only runs on full-list mode.
function cleanupList(singleShot) {
  try {
    if (singleShot) return; // only clean when running the whole list
    const logged = new Set(readFileSync(LOGGED_FILE, "utf8").split("\n").map((l) => l.split("|")[0].trim().toLowerCase()).filter(Boolean));
    const failed = new Set(readFileSync(FAILED_FILE, "utf8").split("\n").map((l) => l.split("|")[0].trim().toLowerCase()).filter(Boolean));
    const done = new Set([...logged, ...failed]);
    if (!done.size) return;
    const kept = readFileSync(LIST_FILE, "utf8").split("\n").map((l) => l.trim()).filter(Boolean)
      .filter((l) => !done.has(l.split("|")[0].trim().toLowerCase()));
    const removed = readFileSync(LIST_FILE, "utf8").split("\n").map((l) => l.trim()).filter(Boolean).length - kept.length;
    writeFileSync(LIST_FILE, kept.join("\n") + (kept.length ? "\n" : ""));
    if (removed > 0) log(`-> Cleaned list.txt: removed ${removed} processed account(s). ${kept.length} remaining.`);
  } catch (e) { log("!! cleanupList: " + String(e.message || e)); }
}
function clearVnc() {
  // [x]/[w] brackets stop pkill matching this script's own shell
  try { sh("pkill -f '[x]11vnc -display :99' ; pkill -f '[w]ebsockify' ; pkill -f '[r]emote-debugging-port=9222' ; pkill -f '[X]vfb :99' ; true"); } catch {}
}
process.on("SIGINT", () => { log("-> Interrupted; clearing VNC stack...."); clearVnc(); process.exit(130); });
process.on("SIGTERM", () => { clearVnc(); process.exit(143); });
main().catch((e) => { log("FATAL " + String(e)); clearVnc(); process.exit(1); });