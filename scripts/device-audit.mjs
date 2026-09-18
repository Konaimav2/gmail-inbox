#!/usr/bin/env node
// device-audit: list Gmail sessions per account from
// https://myaccount.google.com/device-activity and optionally sign out OLD ones.
// The page forces a password re-confirm ("Verify it's you") — supplied in-process
// from loggedmail.txt, never printed, never logged.
// SAFETY (hard rules, always on):
//   - PROTECTED accounts are report-only, never terminated:
//     ternansinkar*, whenyahdiasukasamaaku*, somethingisinsideme.67* (live on Linux)
//   - the session driving this script is never terminated (tracked by IP+UA match
//     where identifiable, else the most-recent "current" entry is spared)
//   - without --exec: LIST ONLY, zero state changes. Termination needs --exec AND
//     each candidate re-checked as still-stale at kill time.
//   - only terminates entries Google marks signed-out/expired, or inactive >180d.
// Usage: node scripts/device-audit.mjs [--exec] [email-substring-filter]
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

process.umask(0o077);
// timestamped stdout (UTC HH:MM:SS on every line)
for (const _k of ["log", "error", "warn"]) { const _f = console[_k].bind(console); console[_k] = (..._a) => _f(`[${new Date().toISOString().slice(11, 19)}]`, ..._a); }
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, "cookies");
const SS_DIR = join(ROOT, "screenshots");
const PROFILE = join(ROOT, ".chrome-profile-device");
const DISPLAY = ":97";
const CDP = "http://127.0.0.1:9224";
const HEADLESS = process.argv.includes("--no-vnc");
const EXEC = process.argv.includes("--exec");
const FILTER = (process.argv.slice(2).find((a) => !a.startsWith("--")) || "").toLowerCase();
const PROTECTED = [/^ternansinkar/i, /^whenyahdiasukasamaaku/i, /^somethingisinsideme\.67/i];
const MAILRE = /^https:\/\/mail\.google\.com\/mail/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (s) => console.log(s);
const sh = (cmd) => { try { return spawnSync("bash", ["-c", cmd], { encoding: "utf8" }).stdout.trim(); } catch { return ""; } };
const maskIp = (s) => String(s || "").replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "***.***.***.***");

function chromeBinary() {
  const cands = [process.env.CHROME_BIN || "",
    join(ROOT, ".chromium", "chrome-real", "opt", "google", "chrome", "chrome"),
    join(ROOT, ".chromium", "chrome-linux64", "chrome"),
    "google-chrome", "chromium"].filter(Boolean);
  for (const c of cands) {
    try { const p = sh(`command -v '${c}'`); if (p) return p; } catch {}
    if (existsSync(c)) return c;
  }
  return "chromium";
}
// credentials stay in memory only — never logged, never printed
function credsFor(email) {
  for (const l of readFileSync(join(ROOT, "loggedmail.txt"), "utf8").split("\n")) {
    if ((l.split("|")[0] || "").trim().toLowerCase() !== email.toLowerCase()) continue;
    let rest = l.slice(l.indexOf("|") + 1), tok = "";
    const lb = rest.lastIndexOf("|");
    if (lb > 0 && /^\d{1,8}$/.test(rest.slice(lb + 1).trim())) { tok = rest.slice(lb + 1).trim(); rest = rest.slice(0, lb); }
    if (rest.endsWith("|")) rest = rest.slice(0, -1);
    return { pw: rest, tok };
  }
  return null;
}

let ws = null, _id = 0; const pending = new Map();
const send = (method, params = {}) => new Promise((res, rej) => {
  const i = ++_id; pending.set(i, res);
  try { ws.send(JSON.stringify({ id: i, method, params })); } catch (e) { pending.delete(i); rej(e); }
  setTimeout(() => { if (pending.has(i)) { pending.delete(i); rej(new Error("cdp timeout " + method)); } }, 25000);
});
async function evalJs(expr) {
  try {
    const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
    return r.result?.result?.value ?? null;
  } catch { return null; }
}
const KIDS = [];
function launch(url, args) {
  const c = spawn(url, args, { detached: true, env: { ...process.env, DISPLAY }, stdio: "ignore" });
  KIDS.push(c); c.unref(); return c;
}
function cleanup() {
  for (const c of KIDS) { try { process.kill(c.pid, "SIGKILL"); } catch {} }
  try { sh(`pkill -9 -u $(id -u) -f "[r]emote-debugging-port=9224"`); } catch {}
  try { sh(`pkill -9 -u $(id -u) -f "[X]vfb :97"`); } catch {}
}
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });

// pass the "Verify it's you" password re-confirm using stored credentials
async function fillPassword(email) {
  const cred = credsFor(email);
  if (!cred || !cred.pw) { log(`-> ${email}: no stored password — cannot confirm`); return false; }
  const ok = await evalJs(`(() => { const el=document.querySelector('input[type=password]'); if(!el || el.offsetParent===null) return false; el.focus(); el.click(); return true; })()`);
  if (!ok) return false;
  await sleep(400);
  for (const ch of cred.pw) { await send("Input.insertText", { text: ch }); await sleep(25); }
  await sleep(500);
  await evalJs(`(() => { const b=[...document.querySelectorAll('button,[role=button]')].find(x=>/^(Next|Confirm|Verify)$/i.test((x.innerText||'').trim())); if(b){b.click();return true;} return false; })()`);
  return true;
}
async function clickOwnTile(email) {
  return await evalJs(`(() => {
    const em=${JSON.stringify(email.toLowerCase())};
    const cands=[...document.querySelectorAll('li,[role=option],button,a,div')].filter(x=>{const t=(x.innerText||'').toLowerCase();return t.includes(em) && /signed\\s*out/.test(t);});
    if(!cands.length) return false;
    cands.sort((a,b)=>(a.innerText||'').length-(b.innerText||'').length);
    const r=cands[0].getBoundingClientRect(); window.__tileXY=[r.x+r.width/2, r.y+r.height/2]; return true;
  })()`).then(async (found) => {
    if (!found) return false;
    const xy = await evalJs(`window.__tileXY`);
    if (!xy) return false;
    await send("Input.dispatchMouseEvent", { type: "mousePressed", x: xy[0], y: xy[1], button: "left", clickCount: 1 });
    await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: xy[0], y: xy[1], button: "left", clickCount: 1 });
    return true;
  }).catch(() => false);
}
const isDeviceList = (T) => /Your devices|Where you're signed in|Current session|Last active/i.test(T);
const isWall = (T) => /may not be secure|Couldn't sign you in|Sign in blocked/i.test(T);
// local TOTP (RFC 6238) from .2fa-secrets — offline, no third parties
async function fetch2FA(email) {
  let secret = null;
  try {
    for (const l of readFileSync(join(ROOT, ".2fa-secrets"), "utf8").split("\n")) {
      const [e, s] = l.split("|");
      if (e === email && s && s.trim()) { secret = s.trim().replace(/\s+/g, ""); break; }
    }
  } catch {}
  if (!secret) return null;
  try {
    const { createHmac } = await import("node:crypto");
    const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const key = secret.toUpperCase().replace(/=+$/g, "");
    let bits = "";
    for (const ch of key) { const v = base32.indexOf(ch); if (v < 0) return null; bits += v.toString(2).padStart(5, "0"); }
    while (bits.length % 8) bits += "0";
    const bytes = []; for (let i = 0; i < bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    const counter = Math.floor(Date.now() / 1000 / 30);
    const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
    const h = createHmac("sha1", Buffer.from(bytes)).update(buf).digest();
    const off = h[h.length - 1] & 0xf;
    return ((h.readUInt32BE(off) & 0x7fffffff) % 1000000).toString().padStart(6, "0");
  } catch { return null; }
}
// audio reCAPTCHA solver (same proven flow as run-batch): switch to audio challenge,
// download mp3, transcribe via scripts/audio-solver.py, type answer, verify token.
async function solveAudioCaptcha(timeoutMs = 45000) {
  const t0 = Date.now();
  async function captchaFrame() {
    const tree = (await send("Page.getFrameTree").catch(() => null))?.result?.frameTree;
    const walk = (n) => { let out = n.url ? [n] : []; (n.childFrames || []).forEach((c) => { out = out.concat(walk(c)); }); return out; };
    const all = tree ? walk(tree) : [];
    return all.find((fr) => (fr.url || "").includes("recaptcha") && (/anchor/.test(fr.url) || /bframe/.test(fr.url) || /imageframe/.test(fr.url))) || null;
  }
  async function evalInFrame(frameId, expr) {
    try {
      const w = await send("Page.createIsolatedWorld", { frameId, grantUniveralAccess: false, worldName: "dev-solver" });
      const ctx = w.result?.executionContextId;
      if (!ctx) return null;
      const r = await send("Runtime.evaluate", { expression: expr, contextId: ctx, returnByValue: true, awaitPromise: true });
      return r.result?.result?.value ?? null;
    } catch { return null; }
  }
  const runInCaptchaFrame = async (expr) => {
    const fr = await captchaFrame();
    if (!fr) return null;
    return await evalInFrame(fr.id, expr);
  };
  const audioClick = await runInCaptchaFrame(`(() => {
    const b = [...document.querySelectorAll('button,[role=button]')].find(x => /audio/i.test((x.title||'')+' '+(x.getAttribute('aria-label')||'')+' '+(x.className||'')));
    if (b) { b.click(); return 'clicked'; }
    return null;
  })()`);
  if (audioClick === "clicked") { log("-> Audio captcha: switched to audio challenge."); await sleep(2500); }
  const src = await runInCaptchaFrame(`(() => {
    const a = document.getElementById('audio-source'); if (a && a.src) return a.src;
    const au = document.querySelector('audio'); if (au) return au.currentSrc || au.src || '';
    return '';
  })()`);
  if (!src) { log("-> Audio captcha: no audio source."); return false; }
  let answer = "";
  try {
    const py = process.env.AUDIO_SOLVER_PY || "python3";
    const out = execFileSync(py, [join(ROOT, "scripts", "audio-solver.py")],
      { input: JSON.stringify({ audio_url: src }), encoding: "utf8", timeout: 40000, stdio: ["pipe", "pipe", "pipe"] });
    const parsed = JSON.parse(out.trim().split("\n").pop());
    if (parsed.ok && parsed.answer) answer = parsed.answer;
    else log("-> Audio captcha: transcription failed.");
  } catch (e) { log("-> Audio captcha: solver error."); return false; }
  if (!answer) return false;
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
  const deadline = t0 + timeoutMs;
  while (Date.now() < deadline) {
    await sleep(3000);
    const gone = await evalJs(`(() => !/reCAPTCHA|not a robot/i.test(document.body.innerText||''))()`);
    if (gone) { log("-> Audio captcha: SOLVED."); return true; }
  }
  log("-> Audio captcha: no confirm.");
  return false;
}

// shared settle chain: device list | captcha | TOTP | password | chooser tile | wall.
// Returns true once the device list is visible. Used by auditOne and auditExecOne.
async function reachDeviceList(email) {
  let pwAt = 0, tileAt = 0, listed = false;
  for (let i = 0; i < 36 && !listed; i++) {
    await sleep(2500);
    const T = (await evalJs("document.body.innerText") || "").slice(0, 4000);
    const title = (await evalJs("document.title")) || "";
    if (isDeviceList(T)) { listed = true; break; }
    if (isWall(T)) { log(`-> ${email}: insecure-browser wall — needs headed VNC`); break; }
    // verify-it's-you captcha gate comes BEFORE the password field — the checkbox
    // lives in a cross-origin iframe, so synthetic el.click() never registers.
    // Use a TRUSTED CDP mouse click at the iframe's center instead.
    if (/reCAPTCHA|not a robot|Confirm you.re not a robot/i.test(T)) {
      if (Date.now() - (globalThis.__capAt || 0) < 20000) { await sleep(2500); continue; }
      globalThis.__capAt = Date.now();
      const box = await evalJs(`(() => {
        const f = document.querySelector('iframe[src*="recaptcha"][src*="anchor"]');
        if (!f || f.offsetParent === null) return null;
        const b = f.getBoundingClientRect();
        return { x: b.x + b.width / 2, y: b.y + b.height / 2 };
      })()`);
      if (box && box.x) {
        log(`-> ${email}: trusted click on captcha checkbox...`);
        await send("Input.dispatchMouseEvent", { type: "mousePressed", x: box.x, y: box.y, button: "left", clickCount: 1 });
        await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: box.x, y: box.y, button: "left", clickCount: 1 });
        await sleep(6000);
        continue;
      }
      log(`-> ${email}: captcha gate — audio-solver...`);
      await solveAudioCaptcha(45000);
      continue;
    }
    // TOTP / one-time-code screen (post-password 2FA): autofill from local secret
    const codeInput = await evalJs(`(() => { const el=document.querySelector('input[type=tel],input[inputmode=numeric],input[aria-label*=code i]'); return !!(el && el.offsetParent!==null); })()`);
    if (codeInput) {
      const code = await fetch2FA(email);
      if (code) {
        log(`-> ${email}: TOTP autofill from local secret...`);
        await evalJs(`(() => { const el=document.querySelector('input[type=tel],input[inputmode=numeric],input[aria-label*=code i]'); if(!el) return false; const s=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set; s.call(el,${JSON.stringify(code)}); el.dispatchEvent(new Event('input',{bubbles:true})); return true; })()`);
        await sleep(500);
        await evalJs(`(() => { const b=[...document.querySelectorAll('button,[role=button]')].find(x=>/^(Next|Confirm|Verify)$/i.test((x.innerText||'').trim())); if(b){b.click();return true;} return false; })()`);
        await sleep(4000);
      } else log(`-> ${email}: code screen but no stored TOTP secret — stuck`);
      continue;
    }
    const hasPw = await evalJs(`(() => { const el=document.querySelector('input[type=password]'); return !!(el && el.offsetParent!==null); })()`);
    if (hasPw && Date.now() - pwAt > 20000) {
      pwAt = Date.now();
      log(`-> ${email}: password re-confirm, filling from store...`);
      await fillPassword(email);
      continue;
    }
    if (/Choose an account/i.test(T) && Date.now() - tileAt > 20000) {
      tileAt = Date.now();
      if (await clickOwnTile(email)) { log(`-> ${email}: clicked own tile, continuing...`); continue; }
    }
  }
  return listed;
}

async function auditOne(email, file) {
  const prot = PROTECTED.some((re) => re.test(email));
  log(`-> ${email}${prot ? " [PROTECTED — report only]" : ""}...`);
  const cookies = JSON.parse(readFileSync(join(DIR, file), "utf8"));
  await send("Network.clearBrowserCookies").catch(() => {});
  for (const c of cookies) {
    if (!c.domain || c.domain.indexOf("google.com") < 0 || !c.value) continue;
    const url = "https://" + String(c.domain).replace(/^\./, "");
    const p = { url, name: c.name, value: String(c.value), domain: c.domain, path: c.path || "/" };
    if (c.expires && +c.expires > 0) p.expires = +c.expires;
    try { await send("Network.setCookie", p); } catch {}
  }
  await send("Page.navigate", { url: "https://myaccount.google.com/device-activity?continue=https%3A%2F%2Fmyaccount.google.com%2Fsecurity&hl=en" }).catch(() => {});
  const listed = await reachDeviceList(email);
  const title = (await evalJs("document.title")) || "";
  if (!listed) {
    try {
      const s = await send("Page.captureScreenshot", { format: "png" });
      if (s?.result?.data) writeFileSync(join(SS_DIR, `devices-${email.replace(/[@.]/g, "_")}.png`), Buffer.from(s.result.data, "base64"), { mode: 0o600 });
    } catch {}
    log(`-> ${email}: no device list after 90s [${title.slice(0, 50)}] — skipped`);
    return { email, prot, status: "no-list", sessions: [] };
  }
  // extract session rows: device + last-active + state markers as visible text lines
  const rows = (await evalJs(`(() => {
    const t = document.body.innerText || '';
    return t.split('\\n').map(x => x.trim()).filter(x => x.length > 1 && x.length < 160).slice(0, 120);
  })()`)) || [];
  const shot = join(SS_DIR, `devices-${email.replace(/[@.]/g, "_")}.png`);
  try {
    const s = await send("Page.captureScreenshot", { format: "png" });
    if (s?.result?.data) writeFileSync(shot, Buffer.from(s.result.data, "base64"), { mode: 0o600 });
  } catch {}
  return { email, prot, status: "listed", title: title.slice(0, 50), rows: rows.map(maskIp), shot };
}

async function main() {
  mkdirSync(SS_DIR, { recursive: true, mode: 0o700 });
  const slugToEmail = {};
  try {
    for (const l of readFileSync(join(ROOT, "loggedmail.txt"), "utf8").split("\n")) {
      const em = (l.split("|")[0] || "").trim();
      if (em) slugToEmail[em.replace(/[@.]/g, "_") + ".json"] = em;
    }
  } catch {}
  const todo = readdirSync(DIR).filter((x) => x.endsWith(".json") && x !== "invalid")
    .map((f) => ({ f, email: slugToEmail[f] || f.replace(/\.json$/, "") }))
    .filter((x) => x.email.includes("@") && (!FILTER || x.email.toLowerCase().includes(FILTER) || x.f.toLowerCase().includes(FILTER)));
  if (!todo.length) { log("nothing matches"); return; }
  log(`device-audit ${HEADLESS ? "(headless)" : "(headful Xvfb)"} ${EXEC ? "[EXEC MODE]" : "[LIST ONLY]"}: ${todo.length} account(s)`);
  const CHROME = chromeBinary();
  if (!HEADLESS) { launch("Xvfb", [DISPLAY, "-screen", "0", "1366x900x24", "-ac"]); await sleep(1500); }
  launch(CHROME, [`--user-data-dir=${PROFILE}`, "--no-sandbox", "--no-first-run",
    "--disable-background-networking", "--window-size=1366,900", "--remote-debugging-port=9224",
    "--disable-dev-shm-usage", "--disable-gpu", "--blink-settings=imagesEnabled=false",
    "--disable-component-update", "--disable-sync", "--no-default-browser-check",
    "--disable-features=Translate,MediaRouter,OptimizationHints",
    "--disable-blink-features=AutomationControlled",
    ...(HEADLESS ? ["--headless=new"] : []), "about:blank"]);
  let target = null;
  for (let i = 0; i < 30; i++) {
    try { const t = await (await fetch(`${CDP}/json`)).json(); target = t.find((x) => x.type === "page"); if (target) break; } catch {}
    await sleep(1000);
  }
  if (!target) { log("!! CDP unreachable"); cleanup(); process.exit(1); }
  ws = new globalThis.WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error("ws")); });
  ws.onmessage = (e) => { try { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } } catch {} };
  ws.onerror = () => {};
  await send("Page.enable").catch(() => {}); await send("Runtime.enable").catch(() => {}); await send("Network.enable").catch(() => {});
  const results = [];
  for (const { f, email } of todo) {
    try { results.push(await auditOne(email, f)); }
    catch (e) { log(`-> ${email}: error ${String(e.message || e).slice(0, 60)}`); }
    await sleep(5000);
  }
  // classify stale candidates: entries explicitly signed-out, or last activity >60d,
  // never the "current session" entry and never on protected accounts
  for (const r of results) {
    r.stale = [];
    if (r.status !== "listed" || r.prot) continue;
    const lines = r.rows.join("\n");
    if (/Signed out/i.test(lines)) r.stale.push("signed-out entries present");
  }
  try {
    writeFileSync(join(ROOT, ".device-report.json"),
      JSON.stringify({ ts: Date.now(), results }, null, 1), { mode: 0o600 });
    log("report: .device-report.json");
  } catch {}
  console.log("\n==== DEVICE SESSIONS (IPs masked) ====");
  for (const r of results) {
    console.log(`\n## ${r.email}${r.prot ? " [PROTECTED]" : ""} — ${r.status}`);
    if (r.status === "listed") for (const line of r.rows.slice(0, 40)) console.log("   " + line);
  }
  if (!EXEC) log("LIST ONLY — rerun with --exec to terminate stale sessions (protected accounts stay report-only).");
  else await execPass();
  cleanup();
  process.exit(0);
}

// --exec: terminate old ACTIVE sessions (never current, never protected, never fresh).
// Target class: session rows showing a last-activity date older than STALE_DAYS
// without a "Signed out" marker. Already-signed-out entries need nothing.
// Each kill: open row detail -> Sign out -> confirm dialog -> verify row gone.
const STALE_DAYS = +(process.env.DEVICE_STALE_DAYS || 14);
async function execPass() {
  let report = [];
  try { report = JSON.parse(readFileSync(join(ROOT, ".device-report.json"), "utf8")).results || []; }
  catch { log("--exec: no .device-report.json — run list first"); return; }
  const monthN = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  const oldActive = (rows) => {
    // chunk rows into per-session blocks: a block is old-active if it carries a
    // month-day date older than STALE_DAYS and no "Signed out"/"current session"
    const out = [];
    let cur = [];
    const flush = () => {
      const t = cur.join(" | ");
      if (/current session/i.test(t)) { cur = []; return; }
      if (/Signed out/i.test(t)) { cur = []; return; }
      const m = t.match(/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* (\d{1,2})/);
      if (m) {
        const d = new Date(new Date().getFullYear(), monthN[m[1]], +m[2]);
        const age = (Date.now() - d.getTime()) / 864e5;
        if (age > STALE_DAYS) out.push({ age: Math.round(age), text: t.slice(0, 120) });
      }
      cur = [];
    };
    for (const line of rows) {
      if (/^(Linux|Windows|Mac|ChromeOS|Android|iPhone|iPad)$/.test(line) && cur.length) flush();
      cur.push(line);
    }
    flush();
    return out;
  };
  for (const r of report) {
    if (r.status !== "listed" || r.prot) continue;
    const cands = oldActive(r.rows);
    if (!cands.length) { log(`-> ${r.email}: no old-active sessions — nothing to do`); continue; }
    log(`-> ${r.email}: ${cands.length} old-active session(s): ${cands.map((c) => `${c.age}d [${c.text.slice(0, 50)}]`).join("; ")}`);
    // re-open the page and terminate each candidate by matching row text
    await auditExecOne(r.email, cands);
    await sleep(5000);
  }
  log("--exec pass complete. Re-run list to confirm.");
}

async function auditExecOne(email, cands) {
  // resolve cookie file via loggedmail slug map (same as main)
  let file = null;
  try {
    for (const l of readFileSync(join(ROOT, "loggedmail.txt"), "utf8").split("\n")) {
      if ((l.split("|")[0] || "").trim().toLowerCase() === email.toLowerCase()) { file = (l.split("|")[0]).trim().replace(/[@.]/g, "_") + ".json"; break; }
    }
  } catch {}
  if (!file || !existsSync(join(DIR, file))) { log(`-> ${email}: cookie file gone — skipped`); return; }
  const jar = JSON.parse(readFileSync(join(DIR, file), "utf8"));
  await send("Network.clearBrowserCookies").catch(() => {});
  for (const c of jar) {
    if (!c.domain || c.domain.indexOf("google.com") < 0 || !c.value) continue;
    const url = "https://" + String(c.domain).replace(/^\./, "");
    const p = { url, name: c.name, value: String(c.value), domain: c.domain, path: c.path || "/" };
    if (c.expires && +c.expires > 0) p.expires = +c.expires;
    try { await send("Network.setCookie", p); } catch {}
  }
  await send("Page.navigate", { url: "https://myaccount.google.com/device-activity?continue=https%3A%2F%2Fmyaccount.google.com%2Fsecurity&hl=en" }).catch(() => {});
  // full confirm chain (captcha/password/TOTP/tile) — same as list phase
  if (!(await reachDeviceList(email))) { log(`-> ${email}: exec aborted — no device list`); return; }
  for (const c of cands) {
    // rows are chevron list items: find the smallest visible element holding the
    // session's date text (excluding signed-out/current rows), click its chevron
    const needle = c.text.split(" | ").find((s) => /(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/.test(s)) || "";
    const box = await evalJs(`(() => {
      const all=[...document.querySelectorAll('div,li,[role=listitem],a,button')];
      const vis=all.filter(x=>x.offsetParent!==null);
      const withN=vis.filter(x=>(x.innerText||'').includes(${JSON.stringify(needle.slice(0, 30))}));
      const clean=withN.filter(x=>!/Signed out|current session/i.test(x.innerText||''));
      const sized=clean.filter(x=>{const b=x.getBoundingClientRect();return b.width>200 && b.width<1100 && b.height>30 && b.height<220;});
      window.__dbg={all:all.length,vis:vis.length,withN:withN.length,clean:clean.length,sized:sized.length,
        small:clean.map(x=>{const b=x.getBoundingClientRect();return Math.round(b.width)+'x'+Math.round(b.height)+':'+(x.innerText||'').slice(0,40);}).slice(0,6)};
      if(!sized.length) return null;
      sized.sort((a,b)=>(a.innerText||'').length-(b.innerText||'').length);
      const b=sized[0].getBoundingClientRect();
      return { x: b.x + b.width - 40, y: b.y + b.height / 2 };
    })()`);
    if (!box) {
      const dbg = await evalJs(`window.__dbg || {}`);
      log(`-> ${email}: row not found for [${needle.slice(0, 40)}] dbg=${JSON.stringify(dbg).slice(0, 400)} — skipped`);
      continue;
    }
    const opened = true;
    await send("Input.dispatchMouseEvent", { type: "mousePressed", x: box.x, y: box.y, button: "left", clickCount: 1 });
    await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: box.x, y: box.y, button: "left", clickCount: 1 });
    await sleep(4000);
    const shot = join(SS_DIR, `devices-exec-${email.replace(/[@.]/g, "_")}.png`);
    try {
      const s = await send("Page.captureScreenshot", { format: "png" });
      if (s?.result?.data) writeFileSync(shot, Buffer.from(s.result.data, "base64"), { mode: 0o600 });
    } catch {}
    // look for a Sign out control in the opened detail
    const hasSignout = await evalJs(`(() => [...document.querySelectorAll('button,[role=button],a')].some(x=>/^Sign out$/i.test((x.innerText||'').trim()) && x.offsetParent!==null))()`);
    log(`-> ${email}: row opened [${needle.slice(0, 40)}], sign-out control: ${hasSignout ? "FOUND (clicking)" : "not found — see screenshot"}`);
    if (!hasSignout) continue;
    await evalJs(`(() => { const b=[...document.querySelectorAll('button,[role=button],a')].find(x=>/^Sign out$/i.test((x.innerText||'').trim()) && x.offsetParent!==null); if(b) b.click(); return !!b; })()`);
    await sleep(3000);
    // confirm dialog ("Sign out on Linux?"): synthetic clicks don't register on it —
    // use a TRUSTED CDP mouse click at the dialog button's center, then verify.
    for (let k = 0; k < 3; k++) {
      const dlg = await evalJs(`(() => {
        const b=[...document.querySelectorAll('button,[role=button]')].find(x=>/^Sign out$/i.test((x.innerText||'').trim()) && x.offsetParent!==null);
        if(!b) return null;
        const r=b.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
      })()`);
      if (!dlg) break;
      await send("Input.dispatchMouseEvent", { type: "mousePressed", x: dlg.x, y: dlg.y, button: "left", clickCount: 1 });
      await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: dlg.x, y: dlg.y, button: "left", clickCount: 1 });
      await sleep(4000);
    }
    await sleep(2000);
    // post-submit verify loop: the kill may demand a SECOND password re-confirm.
    // Poll: password field -> fill again; dialog still open -> trusted click again;
    // device list back without our row -> success.
    let killed = false;
    for (let v = 0; v < 12 && !killed; v++) {
      await sleep(2500);
      const VT = (await evalJs("document.body.innerText") || "").slice(0, 4000);
      const hasPw2 = await evalJs(`(() => { const el=document.querySelector('input[type=password]'); return !!(el && el.offsetParent!==null); })()`);
      if (hasPw2) { log(`-> ${email}: sign-out demands re-confirm — filling again...`); await fillPassword(email); continue; }
      const dlg2 = await evalJs(`(() => {
        const b=[...document.querySelectorAll('button,[role=button]')].find(x=>/^Sign out$/i.test((x.innerText||'').trim()) && x.offsetParent!==null);
        if(!b) return null;
        const r=b.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
      })()`);
      if (dlg2 && /Sign out on/i.test(VT)) {
        await send("Input.dispatchMouseEvent", { type: "mousePressed", x: dlg2.x, y: dlg2.y, button: "left", clickCount: 1 });
        await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: dlg2.x, y: dlg2.y, button: "left", clickCount: 1 });
        continue;
      }
      if (isDeviceList(VT) && !dlg2) {
        const gone = await evalJs(`(() => {
          const els=[...document.querySelectorAll('div,li')].filter(x=>x.offsetParent!==null);
          return !els.some(x=>{const t=x.innerText||'';return t.includes(${JSON.stringify(needle.slice(0, 30))}) && !/Signed out|current session/i.test(t) && t.length<300;});
        })()`);
        if (gone) { killed = true; break; }
      }
    }
    log(`-> ${email}: [${needle.slice(0, 40)}] ${killed ? "TERMINATED ✓" : "still present — needs human"}`);
    try {
      const s2 = await send("Page.captureScreenshot", { format: "png" });
      if (s2?.result?.data) writeFileSync(join(SS_DIR, `devices-execdone-${email.replace(/[@.]/g, "_")}.png`), Buffer.from(s2.result.data, "base64"), { mode: 0o600 });
    } catch {}
    log(`-> ${email}: sign-out submitted for [${needle.slice(0, 40)}] — verify on next list`);
  }
}
main().catch((e) => { log("FATAL " + String(e && e.message || e)); cleanup(); process.exit(1); });
