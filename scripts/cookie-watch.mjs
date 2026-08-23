// Watch Chrome CDP (port 9222). When a Google session cookie (SID/SSID) appears,
// dump all google.com cookies to cookies/<email>.json and confirm mail session.
const CDP = "http://127.0.0.1:9222";
import { writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const COOKIE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "cookies");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getTargets() {
  const res = await fetch(`${CDP}/json`);
  return res.json();
}

async function connect(wsUrl) {
  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  };
  const send = (method, params = {}) => new Promise((res) => {
    const mid = ++id;
    pending.set(mid, res);
    ws.send(JSON.stringify({ id: mid, method, params }));
  });
  return { ws, send };
}

const hasSessionCookie = (cookies) =>
  cookies.some((c) => c.domain.includes("google.com") &&
    (c.name === "SID" || c.name === "SSID" || c.name === "__Secure-1PSID") &&
    c.value.length > 20);

async function main() {
  await mkdir(COOKIE_DIR, { recursive: true });
  console.log("[watch] waiting for Chrome CDP...");
  let targets;
  for (let i = 0; i < 60; i++) {
    try { targets = await getTargets(); if (targets.length) break; } catch {}
    await sleep(1000);
  }
  if (!targets?.length) { console.error("[watch] CDP unreachable"); process.exit(1); }
  const page = targets.find((t) => t.type === "page") || targets[0];
  console.log(`[watch] page: ${page.url}`);
  const { ws, send } = await connect(page.webSocketDebuggerUrl);

  // hide automation markers so Google login isn't flagged
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Page.addScriptToEvaluateOnNewDocument", {
    source: `Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
             window.chrome = window.chrome || { runtime: {} };`,
  });
  await send("Network.enable");
  await send("Page.navigate", { url: "https://accounts.google.com/ServiceLogin?hl=en" });
  console.log("[watch] opened accounts.google.com — waiting for Tuan to log in via noVNC...");

  let dumped = new Set();
  while (true) {
    await sleep(3000);
    const { result } = await send("Network.getAllCookies");
    const cookies = result?.cookies || [];
    if (!hasSessionCookie(cookies)) {
      const url = (await send("Page.getNavigationHistory")).result?.entries?.at(-1)?.url || "";
      if (/accounts\.google\.com/.test(url)) continue;
      continue;
    }
    // logged in: extract email via google identity script or page title
    const emailExpr = await send("Runtime.evaluate", {
      expression: `(document.title + '|' + (document.querySelector('a[href*="SignOut"], header')?.textContent || ''))`,
      returnByValue: true,
    }).catch(() => ({}));
    const pageInfo = typeof emailExpr?.result?.result?.value === "string" ? emailExpr.result.result.value : "";
    const emailFromTitle = (pageInfo.match(/([\w.+-]+@[\w-]+(\.[\w-]+)+)/) || [])[1] || "unknown";
    const key = emailFromTitle + "|" + cookies.length;
    if (dumped.has(key)) {
      // already saved; keep waiting only if not at mail
      await send("Page.navigate", { url: "https://mail.google.com/mail/u/0/#inbox" });
      continue;
    }
    const fname = `${COOKIE_DIR}/${emailFromTitle.replace(/[@.]/g, "_")}.json`;
    await writeFile(fname, JSON.stringify(cookies, null, 2));
    dumped.add(key);
    console.log(`[watch] SESSION SAVED -> ${fname}`);
    console.log(`[watch] navigating to mail.google.com to warm session...`);
    await send("Page.navigate", { url: "https://mail.google.com/mail/u/0/#inbox" });
  }
}

main().catch((e) => { console.error(e); process.exit(1); });