#!/usr/bin/env node
// reverify-cookies: relogin/reverify using cookies ONLY — no passwords, no browser.
// For each cookies/*.json: fetch Gmail /h/ with the saved jar. Valid sessions get
// any rotated Set-Cookies written back (session refreshed/kept warm). Dead sessions
// move to cookies/invalid/ (same as check-cookies). Transient network errors retry
// once before any quarantine decision — a single failed fetch never kills a cookie.
// Usage: node scripts/reverify-cookies.mjs [email-substring-filter]
import { readdirSync, readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

process.umask(0o077);
// timestamped stdout (UTC HH:MM:SS on every line)
for (const _k of ["log", "error", "warn"]) { const _f = console[_k].bind(console); console[_k] = (..._a) => _f(`[${new Date().toISOString().slice(11, 19)}]`, ..._a); }
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, "cookies");
const BAD = join(DIR, "invalid");
const FILTER = (process.argv[2] || "").toLowerCase();
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

mkdirSync(BAD, { recursive: true, mode: 0o700 });

async function fetchWithJar(cookies, url) {
  const rank = (c) => [c.domain.split(".").length, c.path ? c.path.length : 0, c.domain.startsWith(".") ? c.domain : c.domain];
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
    if (res.status >= 300 && res.status < 400) { const loc = res.headers.get("location"); if (!loc) return { status: res.status, body: "", jar }; cur = new URL(loc, cur).toString(); continue; }
    return { status: res.status, body: await res.text(), jar };
  }
  return { status: 599, body: "", jar };
}

async function reverify(file) {
  const path = join(DIR, file);
  const cookies = JSON.parse(readFileSync(path, "utf8"));
  const hasSession = cookies.some((c) => ["SID", "SSID", "__Secure-1PSID"].includes(c.name) && c.value.length > 20);
  if (!hasSession) return { ok: false, why: "no session cookie", rotated: 0 };
  const URL = "https://mail.google.com/mail/u/0/h/?v=m&s=q&q=newer_than%3A30d";
  let lastErr = "";
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const { status, body, jar } = await fetchWithJar(cookies, URL);
      if (status !== 200) {
        // HTTP error can be transient (rate limit, blip) — retry once before verdict
        lastErr = `http ${status}`;
        if (attempt === 1) { await sleep(5000); continue; }
        return { ok: false, why: lastErr, rotated: 0 };
      }
      if (/\"simls\",null,\"/.test(body)) {
        // valid session — persist any server-rotated cookies (the actual refresh)
        const rotated = cookies.filter((c) => jar.find((j) => j.name === c.name && j.value !== c.value));
        if (rotated.length) {
          for (const c of cookies) { const j = jar.find((x) => x.name === c.name); if (j) c.value = j.value; }
          writeFileSync(path, JSON.stringify(cookies, null, 2), { mode: 0o600 });
        }
        return { ok: true, rotated: rotated.length };
      }
      if (/accounts\.google\.com\/(ServiceLogin|signin|Logout)/.test(body) || /Sign in - Google Accounts/.test(body)) return { ok: false, why: "login wall", rotated: 0 };
      if (/Enter the code|Verify it's you|Make sure you can always sign in/.test(body)) return { ok: false, why: "challenge/recovery", rotated: 0 };
      // empty-but-signed-in (no simls payload, no login wall): session alive, nothing to read
      return { ok: true, rotated: 0, note: "empty" };
    } catch (e) {
      lastErr = String(e.message || e).slice(0, 80);
      if (attempt === 1) { await sleep(5000); continue; }
      return { ok: false, why: lastErr, rotated: 0 };
    }
  }
  return { ok: false, why: lastErr || "unknown", rotated: 0 };
}

let ok = 0, refreshed = 0, bad = 0;
for (const f of readdirSync(DIR).filter((x) => x.endsWith(".json") && x !== "invalid")) {
  if (FILTER && !f.toLowerCase().includes(FILTER)) continue;
  let r;
  try { r = await reverify(f); }
  catch (e) { r = { ok: false, why: String(e.message || e).slice(0, 80), rotated: 0 }; }
  if (r.ok) {
    ok++; refreshed += r.rotated;
    console.log(`OK    ${f}${r.rotated ? ` (refreshed ${r.rotated} cookies)` : ""}${r.note ? ` [${r.note}]` : ""}`);
  } else {
    bad++;
    try { renameSync(join(DIR, f), join(BAD, f)); console.log(`MOVE  ${f}  (${r.why}) -> cookies/invalid/`); }
    catch (e) { console.log(`FAIL  ${f}  (${r.why}; move error ${e.message})`); }
  }
  await sleep(800); // gentle pacing between accounts
}
console.log(`\nChecked: ${ok} valid (${refreshed} rotated), ${bad} invalid/moved.`);
process.exit(bad ? 1 : 0);
