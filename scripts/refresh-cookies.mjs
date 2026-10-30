#!/usr/bin/env node
// refresh-cookies: probe Gmail per cookie file, capture Set-Cookie rotation
// (__Secure-1PSIDTS / 3PSIDTS / *PSIDCC), merge into JSON, report ALIVE/DEAD.
// Usage: node refresh-cookies.mjs [--dry] [email ...]
import { readFileSync, writeFileSync, readdirSync, mkdirSync, copyFileSync, existsSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const CDIR = join(ROOT, "cookies");
const BDIR = join(ROOT, "_backup_files");
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36";
const DRY = process.argv.includes("--dry");
const WANT = process.argv.slice(2).filter((a) => a.includes("@"));
const ROTATE = /^(__Secure-1PSIDTS|__Secure-3PSIDTS|__Secure-1PSIDCC|__Secure-3PSIDCC|SIDCC|NID|AEC|__Host-GAPS)$/;

if (!existsSync(CDIR)) { console.log("cookies/ belum ada — belum ada akun yang login"); process.exit(0); }
const files = readdirSync(CDIR).filter((f) => f.endsWith(".json")).filter((f) => {
  if (!WANT.length) return true;
  const em = f.replace(/_gmail_com\.json$/, "").replace(/_/g, ".");
  return WANT.some((w) => w.toLowerCase() === em.toLowerCase());
});
if (!files.length) { console.log("nggak ada cookie file yang cocok"); process.exit(0); }

function cookieHeader(arr) {
  return arr.filter((c) => /google\.com$/.test(String(c.domain || ""))).map((c) => `${c.name}=${c.value}`).join("; ");
}

function parseSetCookie(sc) {
  const i = sc.indexOf("=");
  if (i < 1) return null;
  const name = sc.slice(0, i).trim();
  const rest = sc.slice(i + 1);
  const semi = rest.indexOf(";");
  const value = (semi === -1 ? rest : rest.slice(0, semi)).trim();
  const attrs = {};
  for (const part of (semi === -1 ? "" : rest.slice(semi + 1)).split(";")) {
    const p = part.trim();
    if (!p) continue;
    const eq = p.indexOf("=");
    const k = (eq === -1 ? p : p.slice(0, eq)).toLowerCase();
    attrs[k] = eq === -1 ? "" : p.slice(eq + 1);
  }
  return { name, value, attrs };
}

function merge(arr, scs) {
  const touched = [];
  for (const sc of scs) {
    const p = parseSetCookie(sc);
    if (!p || !ROTATE.test(p.name)) continue;
    const domain = p.attrs.domain || ".google.com";
    const path = p.attrs.path || "/";
    let hit = arr.find((c) => c.name === p.name && c.path === path);
    const exp = p.attrs.expires ? Math.floor(Date.parse(p.attrs.expires) / 1000) : 0;
    if (hit) {
      if (hit.value === p.value) continue;
      hit.value = p.value;
      if (exp) hit.expires = exp;
      touched.push(p.name);
    } else {
      arr.push({
        name: p.name, value: p.value, domain, path,
        expires: exp, httpOnly: "httponly" in p.attrs,
        secure: "secure" in p.attrs, sameSite: p.attrs.samesite || "None",
      });
      touched.push("+" + p.name);
    }
  }
  return touched;
}

await (async () => {
  mkdirSync(BDIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  let alive = 0, dead = 0, rotated = 0;
  for (const f of files) {
    const em = f.replace(/_gmail_com\.json$/, "").replace(/_/g, ".");
    const path = join(CDIR, f);
    let arr;
    try { arr = JSON.parse(readFileSync(path, "utf8")); } catch (e) { console.log(`${em}: JSON rusak (${e.message})`); dead++; continue; }
    let res;
    try {
      res = await fetch("https://mail.google.com/mail/u/0/", {
        headers: { cookie: cookieHeader(arr), "user-agent": UA, "accept-language": "en-US,en;q=0.9" },
        redirect: "manual",
      });
    } catch (e) { console.log(`${em}: ERR ${e.message}`); dead++; continue; }
    const scs = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    if (res.status !== 200) {
      console.log(`${em}: DEAD (${res.status}) rotasi=${scs.length}`);
      dead++;
      continue;
    }
    const touched = merge(arr, scs);
    if (touched.length) {
      if (!DRY) {
        copyFileSync(path, join(BDIR, `${basename(path)}.${stamp}.rotate.bak`));
        writeFileSync(path, JSON.stringify(arr, null, 2));
      }
      rotated += touched.length;
      console.log(`${em}: ALIVE (200) rotasi=${touched.length} [${touched.join(",")}]`);
    } else {
      console.log(`${em}: ALIVE (200) rotasi=0`);
    }
    alive++;
  }
  console.log(`-> hasil: ${alive} alive, ${dead} dead, ${rotated} cookie dirotasi${DRY ? " (dry)" : ""}`);
})();
