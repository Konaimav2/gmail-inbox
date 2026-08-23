// Semi-auto Gmail login driver via CDP. stdin commands:
//   email <addr>   type email + next
//   pass <pw>      type password + submit
//   code <code>    type 2FA/verification code + submit
//   fresh          navigate to fresh accounts.google.com login
//   check          print current step (url, visible inputs, needs what)
//   dump [name]    force dump cookies
//   next           wait for next account (goes back to fresh login)
// Auto-dumps cookies to cookies/<email>.json when session cookie appears after login.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import readline from "node:readline";
import { join } from "node:path";
import crypto from "node:crypto";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const COOKIE_DIR = join(ROOT, "cookies");
const CDP = "http://127.0.0.1:9222";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let ws, send;
async function connect() {
  for (let i = 0; i < 30; i++) {
    try {
      const targets = await (await fetch(`${CDP}/json`)).json();
      const page = targets.find((t) => t.type === "page") || targets[0];
      if (!page) throw 0;
      ws = new WebSocket(page.webSocketDebuggerUrl);
      await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error("ws")); });
      let id = 0; const pending = new Map();
      ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
      send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
      await send("Page.enable"); await send("Runtime.enable"); await send("Network.enable");
      await send("Page.addScriptToEvaluateOnNewDocument", {
        source: `Object.defineProperty(navigator, 'webdriver', {get: () => undefined}); window.chrome = window.chrome || { runtime: {} };`,
      });
      return;
    } catch { await sleep(1000); }
  }
  throw new Error("cdp unreachable");
}

async function evalJs(expr) {
  const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
  if (r.result?.exceptionDetails) return { err: JSON.stringify(r.result.exceptionDetails).slice(0, 200) };
  return r.result?.result?.value;
}

async function pageState() {
  return evalJs(`(() => {
    const inputs = [...document.querySelectorAll('input')].map(i => ({type: i.type, name: i.name, id: i.id, ph: i.placeholder, visible: !!i.offsetParent}));
    const title = document.title, url = location.href;
    const buttons = [...document.querySelectorAll('button, [role=button]')].map(b => b.innerText || b.getAttribute('aria-label') || '').filter(t => t && t.length < 60).slice(0, 8);
    const errs = [...document.querySelectorAll('[role=alert], .error, #errorMessage, [jsname="LgbsSe"]')].map(e => (e.innerText || e.textContent || '').trim()).filter(Boolean).slice(0, 3);
    return JSON.stringify({ title, url, inputs, buttons, errs });
  })()`);
}

async function typeField(sel, text) {
  await evalJs(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (!el) return false; el.focus(); el.click(); return true; })()`);
  await sleep(250);
  await send("Input.insertText", { text });
  return true;
}

async function hasVisible(sel) {
  return await evalJs(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); return !!(el && el.offsetParent !== null); })()`);
}

function emailFromCookies(cookies) {
  // best effort: read from embedded page title/URL or from email input state
  return null;
}

async function dumpCookies(tag) {
  const { result } = await send("Network.getAllCookies");
  const cookies = (result?.cookies || []).filter((c) => c.domain.includes("google.com"));
  const hasSess = cookies.some((c) => ["SID", "SSID", "__Secure-1PSID"].includes(c.name) && c.value.length > 20);
  if (!hasSess) return { ok: false, reason: "no session cookie yet" };
  // only accept when actually landed on mail (challenge screens still carry SID but are NOT logged in)
  const st = await pageState().catch(() => ({ url: "" }));
  if (!/mail\.google\.com|myaccount\.google\.com/.test(st.url || "")) return { ok: false, reason: "on-challenge:" + ((st.url || "").slice(0, 80)) };
  // figure out email
  let email = tag || null;
  const m = (st.url || st.title || "").match(/([\w.+-]+@[\w.-]+)/);
  if (m) email = m[1];
  if (!email) {
    const bodyTxt = await evalJs(`document.body.innerText.slice(0, 3000)`).catch(() => "");
    const m2 = bodyTxt.match(/([\w.+-]+@[\w.-]+)/);
    if (m2) email = m2[1];
  }
  if (!email) email = "unknown_" + Date.now();
  const fname = join(COOKIE_DIR, email.replace(/[@.]/g, "_") + ".json");
  writeFileSync(fname, JSON.stringify(cookies, null, 2));
  return { ok: true, file: fname, email };
}

async function waitSession(tag, timeoutMs = 120000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const r = await dumpCookies(tag);
    if (r.ok) return r;
    await sleep(4000);
  }
  return { ok: false, reason: "timeout" };
}

const INQ = "/tmp/driver-in.txt", OUTQ = "/tmp/driver-out.txt";
import { appendFileSync, readFileSync as _rfs } from "node:fs";
let processed = 0;
const log = (s) => { console.log(s); try { appendFileSync(OUTQ, s + "\n"); } catch {} };
async function runCommand(line) {
  const [cmd, ...rest] = line.trim().split(/\s+/);
  const arg = rest.join(" ");
  try {
    switch (cmd) {
      case "logout": {
        await send("Page.navigate", { url: "https://accounts.google.com/Logout?continue=https%3A%2F%2Faccounts.google.com%2FAddSession%3Fcontinue%3Dhttps%253A%252F%252Fmail.google.com%252Fmail%252Fu%252F0%252F" });
        log("> logging out");
        break;
      }
      case "fresh": {
        await send("Page.navigate", { url: "https://accounts.google.com/AddSession?continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&hl=en" });
        log("> navigating to account chooser");
        break;
      }
      case "email": {
        if (!arg) return log("> need email");
        // wait for email field
        for (let i = 0; i < 20; i++) {
          const em = await hasVisible('input[type=email], input[name=identifier], input[autocomplete=username]');
          if (em) break; await sleep(500);
        }
        const sel = 'input[type=email], input[name=identifier], input[autocomplete=username]';
        await typeField(sel, arg);
        log("> email typed; clicking next");
        await evalJs(`(() => { const b=[...document.querySelectorAll('button, [role=button]')].find(x=>(x.innerText||'').trim()==='Next'); if(b){b.click();return true;} return false; })()`);
        break;
      }
      case "pass": {
        if (!arg) return log("> need password");
        for (let i = 0; i < 20; i++) {
          const pw = await hasVisible('input[type=password], input[name=password]');
          if (pw) break; await sleep(500);
        }
        await typeField('input[type=password], input[name=password]', arg);
        await evalJs(`(() => { const b=[...document.querySelectorAll('button, [role=button]')].find(x=>(x.innerText||'').trim()==='Next'); if(b){b.click();return true;} return false; })()`);
        log("> password submitted");
        break;
      }
      case "code": {
        if (!arg) return log("> need code");
        for (let i = 0; i < 20; i++) {
          const inp = await hasVisible('input[type=tel], input[name=code], input[autocomplete=one-time-code], input[name="idvPin"]');
          if (inp) break; await sleep(500);
        }
        const sel = 'input[type=tel], input[name=code], input[autocomplete=one-time-code], input[name="idvPin"]';
        await typeField(sel, arg);
        await evalJs(`(() => { const b=[...document.querySelectorAll('button, [role=button]')].find(x=>/verify|next|continue/i.test((x.innerText||''))); if(b){b.click();return true;} return false; })()`);
        log("> code submitted");
        break;
      }
      case "login": {
        const [em, pw] = line.trim().slice(6).split(/\s+/);
        if (!em || !pw) return log("> login <email> <password>");
        log("LOGIN " + em);
        await send("Page.navigate", { url: "https://accounts.google.com/AddSession?continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&hl=en" });
        await sleep(4000);
        // email
        for (let i = 0; i < 20; i++) { if (await hasVisible('input[type=email], input[name=identifier]')) break; await sleep(500); }
        await typeField('input[type=email], input[name=identifier]', em);
        await evalJs(`(() => { const b=[...document.querySelectorAll('button, [role=button]')].find(x=>(x.innerText||'').trim()==='Next'); if(b){b.click();return true;} return false; })()`);
        // password
        for (let i = 0; i < 30; i++) { if (await hasVisible('input[type=password], input[name=password]')) break; await sleep(700); }
        const pwVisible = await hasVisible('input[type=password], input[name=password]');
        if (!pwVisible) { log("> no password field (unexpected screen)"); return; }
        await typeField('input[type=password], input[name=password]', pw);
        await evalJs(`(() => { const b=[...document.querySelectorAll('button, [role=button]')].find(x=>(x.innerText||'').trim()==='Next'); if(b){b.click();return true;} return false; })()`);
        // outcome poll
                const t0 = Date.now();
                let challengeSince = null;
                while (Date.now() - t0 < 240000) {
                  await sleep(3000);
                  const dmp = await dumpCookies(em).catch(() => ({ ok: false, reason: "err" }));
                  if (dmp.ok) { log("> OK dumped " + dmp.file); return; }
                  const st = await pageState().catch(() => "{}");
                  const text = st.url + " " + (st.title || "") + " " + JSON.stringify(st);
                  if (/\/challenge\//.test(st.url || "")) {
                    if (!challengeSince) { challengeSince = Date.now(); log("> PHONE: challenge — tap number on phone"); }
                    if (Date.now() - challengeSince > 200000) { log("> PHONE_TIMEOUT"); return; }
                    // check for code-input variant
                    if (/"type":"tel"|one-time-code|idvPin|Enter the code/i.test(text)) { log("> NEED_CODE"); return; }
                    continue;
                  }
                  if (/"type":"tel"|one-time-code|idvPin|Enter the code|verification code/i.test(text) && /challenge|2sv|signin/i.test(st.url || "")) { log("> NEED_CODE"); return; }
                  if (/recaptcha|captcha|not a robot|verify you're|unusual traffic|confirm you're not a robot/i.test(text)) { log("> NEED_MANUAL captcha"); return; }
                  if (/password was incorrect|couldn't find your google account|couldn't sign you in|wrong password|forgot your password/i.test(text)) { log("> FAIL bad creds: " + (st.errs || []).join("|")); return; }
                  if (/This browser or app may not be secure/i.test(text)) { log("> FAIL insecure-browser"); return; }
                }
                log("> TIMEOUT no result");
                break;
              }
      case "shot": {
        const s = await send("Page.captureScreenshot", { format: "png" });
        const f = "/tmp/login-screen.png";
        writeFileSync(f, Buffer.from(s.result.data, "base64"));
        log("> shot " + f);
        break;
      }
      case "check": {
        log("STATE " + await pageState().catch((e) => JSON.stringify({ err: String(e) })));
        break;
      }
      case "wait": {
        const tag = arg || null;
        const r = await waitSession(tag);
        log("> " + JSON.stringify(r));
        break;
      }
      case "dump": {
        log("> " + JSON.stringify(await dumpCookies(arg || null)));
        break;
      }
      default: log("> unknown cmd");
    }
  } catch (e) { log("ERR " + String(e)); }
}

async function pollQueue() {
  let lastSize = 0;
  for (;;) {
    try {
      const txt = existsSync(INQ) ? _rfs(INQ, "utf8") : "";
      const lines = txt.split("\n").filter(Boolean);
      while (processed < lines.length) {
        const line = lines[processed++];
        log("CMD " + line);
        await runCommand(line);
      }
      if (txt.length) lastSize = txt.length;
    } catch (e) { log("POLLERR " + String(e)); }
    await sleep(1000);
  }
}

connect().then(async () => { log("READY driver connected; send commands via " + INQ); const st = await pageState().catch(() => ({ url: "" })); if (!/(accounts|mail|myaccount)\.google\.com/.test(st.url || "")) await send("Page.navigate", { url: "https://accounts.google.com/AddSession?continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&hl=en" }).catch(() => {}); else log("> left page as-is: " + (st.url || "").slice(0, 90)); pollQueue(); });
process.on("SIGINT", () => process.exit(0));;