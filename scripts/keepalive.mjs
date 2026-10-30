#!/usr/bin/env node
// keepalive: buka Gmail di browser ASLI pakai profile per-akun.
// PENTING: cookie dari JSON (yang paling fresh / sudah dirotasi) DIINJEKSI dulu
// ke browser sebelum navigate. Kalau browser pakai cookie DB lama, token
// __Secure-1PSIDTS yang stale bisa dianggap replay -> Google revoke session.
import { spawn } from "node:child_process";
import { readdirSync, existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const PBASE = join(ROOT, ".chrome-profiles");
const CDIR = join(ROOT, "cookies");
const CHROME = join(ROOT, ".chromium/chrome-real/opt/google/chrome/chrome");
const PORT = 9341;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const WANT = process.argv.slice(2).filter((a) => a.includes("@"));

if (!existsSync(PBASE)) { console.log("profile belum ada — belum ada akun yang login"); process.exit(0); }
const dirs = readdirSync(PBASE).filter((d) => existsSync(join(PBASE, d, "Default")));
const pick = WANT.length
  ? dirs.filter((d) => WANT.some((w) => d.toLowerCase() === w.toLowerCase().replace(/@/g, "_")))
  : dirs;

function cookieFileFor(slug) {
  const cands = [join(CDIR, `${slug}.json`), join(CDIR, `${slug.replace(/\./g, "_")}.json`)];
  for (const f of cands) if (existsSync(f)) return f;
  return null;
}

let alive = 0, out = 0;
for (const d of pick) {
  const em = d.replace(/_gmail\.com$/, "@gmail.com");
  const prof = join(PBASE, d);
  const cf = cookieFileFor(d);
  const ch = spawn(CHROME, ["--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
    `--remote-debugging-port=${PORT}`, `--user-data-dir=${prof}`, "about:blank"], { stdio: "ignore" });
  let ok = false;
  for (let i = 0; i < 40; i++) { try { await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json(); ok = true; break; } catch { await sleep(300); } }
  if (!ok) { console.log(`${em}: CHROME_GAGAL`); ch.kill("SIGKILL"); continue; }
  const t = await (await fetch(`http://127.0.0.1:${PORT}/json/new?https://mail.google.com/mail/u/0/`, { method: "PUT" })).json();
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  let id = 0; const q = new Map();
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && q.has(m.id)) { q.get(m.id)(m.result || m.error); q.delete(m.id); } };
  const send = (m, p = {}) => new Promise((r) => { const i = ++id; q.set(i, r); ws.send(JSON.stringify({ id: i, method: m, params: p })); });
  await new Promise((r) => (ws.onopen = r));

  let injected = 0;
  if (cf) {
    try {
      await send("Network.enable");
      const arr = JSON.parse(readFileSync(cf, "utf8"));
      for (const c of arr) {
        if (!c || !c.name || !c.domain) continue;
        const p = { name: c.name, value: String(c.value ?? ""), domain: c.domain, path: c.path || "/",
          secure: !!c.secure, httpOnly: !!c.httpOnly, sourceScheme: c.sourceScheme || "Secure", sourcePort: c.sourcePort || 443 };
        const r = await send("Network.setCookie", p);
        if (r && r.success) injected++;
      }
      const gc = await send("Network.getCookies", { urls: ["https://mail.google.com/mail/u/0/"] });
      injected = (gc && gc.cookies ? gc.cookies.length : injected);
    } catch (e) { console.log(`${em}: inject gagal ${String(e.message).slice(0, 40)}`); }
  }

  await send("Page.navigate", { url: "https://mail.google.com/mail/u/0/" });
  await sleep(2500);
  await send("Page.reload", { ignoreCache: false }).catch(() => {});
  await sleep(6000);
  const r = await send("Runtime.evaluate", { expression: "JSON.stringify({u: location.href.slice(0,48), t: document.body.innerText.slice(0,40)})", returnByValue: true });
  const v = String((r && r.result && r.result.value) || "");
  const signedIn = v.includes("mail.google.com") && !v.includes("Choose an account");
  if (signedIn) alive++; else out++;
  console.log(`${em}: ${signedIn ? "ALIVE" : "SIGNED_OUT"} inject=${injected} ${v.slice(0, 46)}`);
  ws.close();
  ch.kill("SIGTERM");
  await new Promise((res) => { const to = setTimeout(res, 8000); ch.on("exit", () => { clearTimeout(to); res(); }); });
  await sleep(300);
}
console.log(`-> hasil: ${alive} alive, ${out} signed_out (browser-based, cookie dirotasi Chrome)`);
