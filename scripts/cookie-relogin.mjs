#!/usr/bin/env node
// cookie-relogin: re-establish Gmail sessions using SAVED COOKIES only.
// No passwords, no credential login, no list.txt needed. Launches ONE browser
// (headful Xvfb by default; --no-vnc for headless), loads each cookie file,
// opens mail.google.com and keeps whatever lands in the inbox:
//   - valid session  -> re-save cookies (0600), move back from invalid/ if needed
//   - login wall     -> stays quarantined, reported for credential login
// Screenshots on failure land in screenshots/ for eyes-on review.
// Usage: node scripts/cookie-relogin.mjs [--no-vnc] [email-substring-filter] [--all]
// By default ONLY cookies/invalid/ (dead sessions needing revival) are attempted —
// hammering healthy sessions from a fresh automation profile gets them challenged.
// Pass --all to include healthy cookies/*.json too (slow, gentle pacing).
import { spawn, spawnSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

process.umask(0o077);
// timestamped stdout (UTC HH:MM:SS on every line)
for (const _k of ["log", "error", "warn"]) { const _f = console[_k].bind(console); console[_k] = (..._a) => _f(`[${new Date().toISOString().slice(11, 19)}]`, ..._a); }
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, "cookies");
const BAD = join(DIR, "invalid");
const SS_DIR = join(ROOT, "screenshots");
const PROFILE = join(ROOT, ".chrome-profile-relogin");
const DISPLAY = ":98";
const CDP = "http://127.0.0.1:9223";
const HEADLESS = process.argv.includes("--no-vnc");
const FILTER = (process.argv.slice(2).find((a) => !a.startsWith("--")) || "").toLowerCase();
const SCOPE_ALL = process.argv.includes("--all");
const MAILRE = /^https:\/\/mail\.google\.com\/mail/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (s) => console.log(s);
const sh = (cmd) => { try { return spawnSync("bash", ["-c", cmd], { encoding: "utf8" }).stdout.trim(); } catch { return ""; } };

// binary: $CHROME_BIN > .chromium real > .chromium testing > system
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

// ---- CDP helpers ----
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
const STEALTH = `(() => { try {
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  window.chrome = window.chrome || {}; window.chrome.runtime = window.chrome.runtime || {};
  const ua = navigator.userAgent;
} catch {} })();`;

// ---- browser lifecycle ----
const KIDS = [];
function launch(url, args) {
  const c = spawn(url, args, { detached: true, env: { ...process.env, DISPLAY }, stdio: "ignore" });
  KIDS.push(c); c.unref(); return c;
}
function cleanup() {
  for (const c of KIDS) { try { process.kill(c.pid, "SIGKILL"); } catch {} }
  try { sh(`pkill -9 -u $(id -u) -f "[r]emote-debugging-port=9223"`); } catch {}
  try { sh(`pkill -9 -u $(id -u) -f "[X]vfb :98"`); } catch {}
}
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });

async function reloginOne(file, fromInvalid) {
  const path = join(fromInvalid ? BAD : DIR, file);
  const email = file.replace(/\.json$/, "").replace(/_/g, ".");
  log(`-> Cookie login ${file}...`);
  let cookies;
  try { cookies = JSON.parse(readFileSync(path, "utf8")); }
  catch { log(`-> ${file}: unreadable cookie file`); return "bad-file"; }
  const sess = cookies.filter((c) => ["SID", "SSID", "__Secure-1PSID"].includes(c.name) && c.value && c.value.length > 20);
  if (!sess.length) { log(`-> ${file}: no session cookies inside`); return "no-session"; }
  await send("Network.clearBrowserCookies").catch(() => {});
  // set stored cookies (domain-grouped so setCookie accepts them)
  let set = 0;
  for (const c of cookies) {
    if (!c.domain || c.domain.indexOf("google.com") < 0 || !c.value) continue;
    const url = "https://" + String(c.domain).replace(/^\./, "");
    const p = { url, name: c.name, value: String(c.value), domain: c.domain, path: c.path || "/" };
    if (c.expires && +c.expires > 0) p.expires = +c.expires;
    try { const r = await send("Network.setCookie", p); if (r?.result?.success) set++; } catch {}
  }
  log(`-> ${file}: set ${set} cookies, opening Gmail...`);
  await send("Page.navigate", { url: "https://mail.google.com/mail/u/0/" }).catch(() => {});
  await sleep(12000); // let challenges/redirects settle before verdict
  const url = (await evalJs("location.href")) || "";
  if (MAILRE.test(url)) {
    // session alive — re-save fresh jar
    try {
      const { result } = await send("Network.getAllCookies");
      const fresh = (result?.cookies || []).filter((c) => c.domain && c.domain.includes("google.com"));
      if (fresh.some((c) => ["SID", "SSID", "__Secure-1PSID"].includes(c.name) && c.value.length > 20)) {
        writeFileSync(join(DIR, file), JSON.stringify(fresh, null, 2), { mode: 0o600 });
        if (fromInvalid) { try { await import("node:fs").then((fs) => fs.unlinkSync(join(BAD, file))); } catch {} }
        log(`-> ${file}: INBOX — session re-established${fromInvalid ? " (moved back from invalid/)" : ""}`);
        return "ok";
      }
    } catch {}
    log(`-> ${file}: inbox reached but jar thin — kept as-is`);
    return "thin";
  }
  // not inbox — screenshot the wall for eyes-on review
  const shot = join(SS_DIR, `relogin-${file.replace(/\.json$/, "")}.png`);
  try {
    const s = await send("Page.captureScreenshot", { format: "png" });
    if (s?.result?.data) { writeFileSync(shot, Buffer.from(s.result.data, "base64"), { mode: 0o600 }); log(`-> ${file}: wall (screenshot ${shot})`); }
  } catch {}
  const title = (await evalJs("document.title")) || "";
  log(`-> ${file}: NO inbox (${(title || url).slice(0, 70)}) — needs credential login`);
  if (!fromInvalid) {
    try { mkdirSync(BAD, { recursive: true, mode: 0o700 }); renameSync(join(DIR, file), join(BAD, file)); log(`-> ${file}: quarantined`); } catch {}
  }
  return "wall";
}

async function main() {
  mkdirSync(SS_DIR, { recursive: true, mode: 0o700 });
  const files = [];
  if (SCOPE_ALL) for (const f of readdirSync(DIR).filter((x) => x.endsWith(".json"))) files.push({ f, bad: false });
  if (existsSync(BAD)) for (const f of readdirSync(BAD).filter((x) => x.endsWith(".json"))) {
    if (!files.some((x) => x.f === f)) files.push({ f, bad: true });
  }
  const todo = files.filter((x) => !FILTER || x.f.toLowerCase().includes(FILTER));
  if (!todo.length) { log("nothing matches"); return; }
  log(`cookie-relogin ${HEADLESS ? "(headless)" : "(headful Xvfb)"}: ${todo.length} session(s), no passwords involved`);
  const CHROME = chromeBinary();
  log(`browser: ${CHROME}`);
  if (!HEADLESS) { launch("Xvfb", [DISPLAY, "-screen", "0", "1366x900x24", "-ac"]); await sleep(1500); }
  launch(CHROME, [`--user-data-dir=${PROFILE}`, "--no-sandbox", "--no-first-run",
    "--disable-background-networking", "--window-size=1366,900", "--remote-debugging-port=9223",
    "--disable-dev-shm-usage", "--disable-gpu", "--blink-settings=imagesEnabled=false",
    "--disable-component-update", "--disable-sync", "--no-default-browser-check",
    "--disable-features=Translate,MediaRouter,OptimizationHints",
    "--disable-blink-features=AutomationControlled",
    ...(HEADLESS ? ["--headless=new"] : []), "about:blank"]);
  // connect CDP
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
  await send("Page.addScriptToEvaluateOnNewDocument", { source: STEALTH }).catch(() => {});
  // normalize UA (headless advertises HeadlessChrome)
  try {
    const uaR = await send("Runtime.evaluate", { expression: "navigator.userAgent", returnByValue: true });
    const ua = uaR?.result?.result?.value || "";
    if (/HeadlessChrome/i.test(ua)) await send("Network.setUserAgentOverride", { userAgent: ua.replace(/HeadlessChrome/g, "Chrome") });
  } catch {}
  const tally = { ok: 0, thin: 0, wall: 0, skipped: 0 };
  for (const { f, bad } of todo) {
    try {
      const r = await reloginOne(f, bad);
      tally[r] = (tally[r] || 0) + 1;
    } catch (e) { log(`-> ${f}: error ${String(e.message || e).slice(0, 60)}`); tally.skipped++; }
    await sleep(8000); // gentle pacing — rapid-fire sessions from one profile get challenged
  }
  log(`done: ${tally.ok} re-established, ${tally.thin || 0} thin, ${tally.wall || 0} walled, ${tally.skipped || 0} errors.`);
  cleanup();
  process.exit(0);
}
main().catch((e) => { log("FATAL " + String(e && e.message || e)); cleanup(); process.exit(1); });
