#!/usr/bin/env node
// timestamped stdout (UTC HH:MM:SS on every line)
for (const _k of ["log", "error", "warn"]) { const _f = console[_k].bind(console); console[_k] = (..._a) => _f(`[${new Date().toISOString().slice(11, 19)}]`, ..._a); }
// check-cookies: validate each cookies/*.json against mail.google.com; move invalid to cookies/invalid/
import { readdirSync, readFileSync, renameSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

process.umask(0o077);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, "cookies");
const BAD = join(DIR, "invalid");
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";

mkdirSync(DIR, { recursive: true, mode: 0o700 });
mkdirSync(BAD, { recursive: true, mode: 0o700 });

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

async function check(file) {
  const cookies = JSON.parse(readFileSync(join(DIR, file), "utf8"));
  const hasSession = cookies.some((c) => ["SID", "SSID", "__Secure-1PSID"].includes(c.name) && c.value.length > 20);
  if (!hasSession) return { ok: false, why: "no session cookie" };
  const { status, body: t } = await fetchWithJar(cookies, "https://mail.google.com/mail/u/0/h/?v=m&s=q&q=newer_than%3A30d");
  if (status !== 200) return { ok: false, why: `http ${status}` };
  if (/\"simls\",null,\"/.test(t)) return { ok: true };
  if (/accounts\.google\.com\/(ServiceLogin|signin|Logout)/.test(t) || /Sign in - Google Accounts/.test(t)) return { ok: false, why: "login wall" };
  if (/Enter the code|Verify it's you|Make sure you can always sign in/.test(t)) return { ok: false, why: "challenge/recovery" };
  return { ok: false, why: "no simls payload" };
}

let ok = 0, bad = 0;
for (const f of readdirSync(DIR).filter((x) => x.endsWith(".json") && x !== "invalid")) {
  const r = await check(f).catch((e) => ({ ok: false, why: String(e.message || e).slice(0, 80) }));
  if (r.ok) { ok++; console.log(`OK    ${f}`); }
  else {
    bad++; 
    try { renameSync(join(DIR, f), join(BAD, f)); console.log(`MOVE  ${f}  (${r.why}) -> cookies/invalid/`); }
    catch (e) { console.log(`FAIL  ${f}  (${r.why}; move error ${e.message})`); }
  }
}
console.log(`\nChecked: ${ok} valid, ${bad} invalid/moved.`);
process.exit(bad ? 1 : 0);