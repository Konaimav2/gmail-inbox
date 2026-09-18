#!/usr/bin/env node
// relogin-invalid: requeue quarantined cookies/invalid/*.json sessions for re-login.
// Resolves each slug to credentials in loggedmail.txt (slug = email with [@.] -> _),
// dedupes by lowercase email, appends missing ones to list.txt as full
// email|pw|tok lines. Never prints secrets — emails and counts only.
// Usage: node scripts/relogin-invalid.mjs [--dry-run]
import { readdirSync, readFileSync, writeFileSync, existsSync, appendFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

process.umask(0o077);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DRY = process.argv.includes("--dry-run");
const slug = (email) => email.replace(/[@.]/g, "_") + ".json";

const logged = existsSync(join(ROOT, "loggedmail.txt"))
  ? readFileSync(join(ROOT, "loggedmail.txt"), "utf8").split("\n").filter(Boolean)
  : [];
const credBySlug = new Map(); // slug -> full line
for (const l of logged) {
  const email = l.slice(0, l.indexOf("|")).trim().toLowerCase();
  if (email) credBySlug.set(slug(email), l);
}
const listed = new Set(
  (existsSync(join(ROOT, "list.txt")) ? readFileSync(join(ROOT, "list.txt"), "utf8") : "")
    .split("\n").filter(Boolean).map((l) => l.slice(0, l.indexOf("|")).trim().toLowerCase())
);
let invalid = [];
try {
  invalid = readdirSync(join(ROOT, "cookies", "invalid")).filter((f) => f.endsWith(".json"));
} catch { console.log("no cookies/invalid/ dir — nothing to requeue"); process.exit(0); }

let queued = [], missing = [], skipped = [];
for (const f of invalid) {
  const line = credBySlug.get(f);
  if (!line) { missing.push(f.replace(/\.json$/, "")); continue; }
  const email = line.slice(0, line.indexOf("|")).trim().toLowerCase();
  if (listed.has(email)) { skipped.push(email); continue; }
  queued.push({ email, line });
}
if (DRY) console.log("(dry run — list.txt untouched)");
else for (const q of queued) {
  appendFileSync(join(ROOT, "list.txt"), q.line + "\n", { mode: 0o600 });
  listed.add(q.email);
}
console.log(`invalid cookies: ${invalid.length}`);
console.log(`requeued to list.txt: ${queued.length}${queued.length ? " (" + queued.map((q) => q.email).join(", ") + ")" : ""}`);
console.log(`already in list.txt: ${skipped.length}`);
console.log(`no credentials in loggedmail.txt: ${missing.length}${missing.length ? " (" + missing.join(", ") + ")" : ""}`);
console.log(DRY ? "dry run done" : "next: node scripts/run-batch.mjs");
