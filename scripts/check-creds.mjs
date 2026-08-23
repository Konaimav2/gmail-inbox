#!/usr/bin/env node
// check-creds: pre-flight audit of list.txt for likely-wrong passwords and format problems.
// Does NOT hit Google — it flags obvious issues before the batch burns a login attempt.
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const LIST = join(ROOT, "list.txt");
const LOGGED = join(ROOT, "loggedmail.txt");
const FAILED = join(ROOT, "failed.txt");

const rd = (f) => (existsSync(f) ? readFileSync(f, "utf8") : "");
const lines = rd(LIST).split("\n").map((l) => l.trim()).filter(Boolean);

// parse like run-batch.mjs (password = everything after first |, optional trailing numeric 2FA)
function parseLine(l) {
  const idx = l.indexOf("|");
  if (idx <= 0) return { bad: true, reason: "no | separator" };
  const email = l.slice(0, idx).trim();
  const rest = l.slice(idx + 1);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return { bad: true, reason: "bad email format" };
  let pw = rest, tok = "";
  if (pw.endsWith("|")) pw = pw.slice(0, -1); // drop trailing empty 2FA delimiter
  const lastBar = pw.lastIndexOf("|");
  if (lastBar > 0) {
    const tail = pw.slice(lastBar + 1).trim();
    if (/^\d{1,8}$/.test(tail)) { tok = tail; pw = pw.slice(0, lastBar).trim(); }
  }
  if (!pw && rest) pw = rest;
  if (!pw) return { bad: true, reason: "empty password" };
  return { email, pw, tok, ok: true };
}

const logged = new Set(rd(LOGGED).split("\n").map((l) => l.split("|")[0].trim().toLowerCase()).filter(Boolean));
const failedByEmail = {};
for (const l of rd(FAILED).split("\n").filter(Boolean)) {
  const [e, reason] = l.split("|");
  if (e) failedByEmail[e.trim().toLowerCase()] = (reason || "?").trim();
}

let problems = 0, ok = 0, skip = 0;
console.log(`Checking ${lines.length} accounts in list.txt`);
for (const l of lines) {
  const p = parseLine(l);
  if (p.bad) { problems++; console.log(`  [FORMAT] ${l.slice(0, 40)}… -> ${p.reason}`); continue; }
  const lower = p.email.toLowerCase();
  if (logged.has(lower)) { skip++; continue; } // already logged in, skip
  const fails = failedByEmail[lower];
  let flags = [];
  if (fails === "bad creds") flags.push("PREVIOUSLY FAILED: bad creds");
  if (p.pw.length < 8) flags.push("short password (<8)");
  if (/^(password|pass|123456|qwerty|changeme|test)/i.test(p.pw)) flags.push("placeholder-looking password");
  if (flags.length) { problems++; console.log(`  [WARN] ${p.email}: ${flags.join("; ")}`); }
  else ok++;
}
console.log(`\nSummary: ${ok} look-OK, ${skip} already logged-in (skipped), ${problems} potential problem(s).`);
console.log("This is a pre-flight heuristic — it does not verify passwords against Google.");
if (problems > 0) process.exit(2);
