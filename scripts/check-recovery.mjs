#!/usr/bin/env node
// check-recovery: audit recovery email/phone on https://myaccount.google.com/personal-info
// for every account with a working cookie. Cookie-only, no passwords, no browser.
// Recovery addresses are printed MASKED (first char + ***) — presence is what matters.
// Usage: node scripts/check-recovery.mjs [email-substring-filter]
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

process.umask(0o077);
// timestamped stdout (UTC HH:MM:SS on every line)
for (const _k of ["log", "error", "warn"]) { const _f = console[_k].bind(console); console[_k] = (..._a) => _f(`[${new Date().toISOString().slice(11, 19)}]`, ..._a); }
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, "cookies");
const FILTER = (process.argv.slice(2).find((a) => !a.startsWith("--")) || "").toLowerCase();
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mask = (s) => {
  const v = String(s || "");
  const at = v.indexOf("@");
  if (at > 0) return v[0] + "***@" + v.slice(at + 1);
  if (v.length > 4) return v.slice(0, 2) + "***" + v.slice(-2);
  return v ? "***" : "";
};

async function fetchPage(cookies) {
  const rank = (c) => [c.domain.split(".").length, c.path ? c.path.length : 0];
  const hdr = (jar) => {
    const best = new Map();
    for (const c of jar) { if (!c.domain || c.domain.indexOf("google.com") < 0) continue; if (!best.has(c.name) || JSON.stringify(rank(c)) > JSON.stringify(rank(best.get(c.name)))) best.set(c.name, c); }
    return [...best.values()].filter((c) => c.name !== "NID" && c.name !== "AEC").map((c) => `${c.name}=${c.value}`).join("; ");
  };
  let jar = [...cookies], cur = "https://myaccount.google.com/personal-info?hl=en";
  for (let hop = 0; hop < 8; hop++) {
    const res = await fetch(cur, { headers: { "User-Agent": UA, Cookie: hdr(jar) }, redirect: "manual" });
    for (const sc of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) {
      const [pair] = sc.split(";"); const eq = pair.indexOf("="); if (eq < 1) continue;
      const ex = jar.find((c) => c.name === pair.slice(0, eq).trim());
      if (ex) ex.value = pair.slice(eq + 1).trim();
    }
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location"); if (!loc) return { status: res.status, body: "" };
      cur = new URL(loc, cur).toString(); continue;
    }
    return { status: res.status, body: await res.text() };
  }
  return { status: 599, body: "" };
}

// Section model learned from page markup: <div class="IlKlLe">Email|Phone</div> followed
// by <div class="oeTldb"><div class="qqVS5">value</div></div> entries. Email section's
// first entry is the primary address; further entries are recovery emails. "Add a
// recovery ..." text means none set.
function parseRecovery(html) {
  const out = { recoveryEmails: [], hasPhone: null, error: null };
  const emailSec = html.split('IlKlLe">Email<')[1]?.split('IlKlLe">')[0] || "";
  const phoneSec = html.split('IlKlLe">Phone<')[1]?.split('IlKlLe">')[0] || "";
  if (!emailSec && !phoneSec) { out.error = "sections not found (login wall?)"; return out; }
  const vals = [...emailSec.matchAll(/oeTldb"><div class="qqVS5">([^<]{1,120})<\/div>/g)].map((m) => m[1].trim());
  const primary = vals[0] || "";
  out.recoveryEmails = vals.slice(1).filter((v) => v && v !== primary && !/^Add a recovery/i.test(v));
  if (/Add a recovery email/i.test(emailSec) && !out.recoveryEmails.length) out.recoveryEmails = [];
  if (/Add a recovery phone/i.test(phoneSec)) out.hasPhone = false;
  else {
    const pv = [...phoneSec.matchAll(/oeTldb"><div class="qqVS5">([^<]{1,40})<\/div>/g)].map((m) => m[1].trim());
    out.hasPhone = pv.length > 0;
    out.phoneMasked = pv.length ? mask(pv[0]) : "";
  }
  return out;
}

const files = readdirSync(DIR).filter((x) => x.endsWith(".json") && x !== "invalid")
  .filter((f) => !FILTER || f.toLowerCase().includes(FILTER));
// real emails from loggedmail.txt (slug reversal mangles dots, so reverse-map instead)
const slugToEmail = {};
try {
  for (const l of readFileSync(join(ROOT, "loggedmail.txt"), "utf8").split("\n")) {
    const em = (l.split("|")[0] || "").trim();
    if (em) slugToEmail[em.replace(/[@.]/g, "_") + ".json"] = em;
  }
} catch {}
const noRecovery = [], withRecovery = [], failed = [];
for (const f of files) {
  const email = slugToEmail[f] || f.replace(/\.json$/, "");
  let r;
  try {
    const cookies = JSON.parse(readFileSync(join(DIR, f), "utf8"));
    const { status, body } = await fetchPage(cookies);
    if (status !== 200 || !/Personal info/.test(body)) { failed.push(`${email} (http ${status})`); console.log(`FAIL  ${email}  (http ${status})`); continue; }
    r = parseRecovery(body);
    if (r.error) { failed.push(`${email} (${r.error})`); console.log(`FAIL  ${email}  (${r.error})`); continue; }
  } catch (e) { failed.push(`${email} (${String(e.message || e).slice(0, 50)})`); console.log(`FAIL  ${email}  (fetch error)`); continue; }
  const em = r.recoveryEmails.map(mask).join(", ") || "—";
  const ph = r.hasPhone ? `yes${r.phoneMasked ? ` (${r.phoneMasked})` : ""}` : "no";
  if (!r.recoveryEmails.length) { noRecovery.push(email); console.log(`NONE  ${email}  phone:${ph}`); }
  else { withRecovery.push(email); console.log(`OK    ${email}  recovery:[${em}] phone:${ph}`); }
  await sleep(2000);
}
console.log(`\n${files.length} checked: ${withRecovery.length} have recovery email, ${noRecovery.length} WITHOUT, ${failed.length} failed.`);
if (noRecovery.length) console.log("WITHOUT recovery email:\n- " + noRecovery.join("\n- "));
if (failed.length) console.log("FAILED:\n- " + failed.join("\n- "));
