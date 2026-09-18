#!/usr/bin/env node
// retry-failed --retry: Success loggedmail(email|pass|2fa) WITHOUT reason, clear from failed.
// Per spec: list.txt(email|pass|2fa) -> loggedmail(email|pass|2fa) vs failed(email|pass|2fa|reason)
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

process.umask(0o077);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FAILED = join(ROOT, "failed.txt");
const LIST = join(ROOT, "list.txt");
const LOGGED = join(ROOT, "loggedmail.txt");

function parseLine(l) {
  const idx = l.indexOf("|");
  if (idx <= 0) return null;
  const email = l.slice(0, idx).trim();
  let rest = l.slice(idx + 1);
  let reason = "";
  const reasonBar = rest.lastIndexOf("|");
  if (reasonBar >= 0) {
    const tail = rest.slice(reasonBar + 1).trim();
    if (tail !== "" && !/^\d{1,8}$/.test(tail)) { reason = tail; rest = rest.slice(0, reasonBar); }
  }
  let pw = rest, tok = "";
  if (pw.endsWith("|")) pw = pw.slice(0, -1);
  const lastBar = pw.lastIndexOf("|");
  if (lastBar > 0) {
    const tail = pw.slice(lastBar + 1).trim();
    if (/^\d{1,8}$/.test(tail)) { tok = tail; pw = pw.slice(0, lastBar).trim(); }
  }
  if (!pw && rest) pw = rest;
  return { email, pw, tok, reason };
}

if (!existsSync(FAILED)) { console.log("no failed.txt — nothing to retry"); process.exit(0); }
const pwmap = new Map();
if (existsSync(LIST))
  for (const l of readFileSync(LIST, "utf8").split("\n").filter(Boolean)) {
    const p = parseLine(l);
    if (p) pwmap.set(p.email.toLowerCase(), p);
  }

let left = readFileSync(FAILED, "utf8").split("\n").filter(Boolean)
  .filter((l) => l.includes("|"))
  .map((l) => l.split("|")[0].trim())
  .filter((e) => pwmap.has(e.toLowerCase()));

for (let pass = 1; pass <= 2 && left.length; pass++) {
  console.log(`pass ${pass}: ${left.length} to retry`);
  const todo = [...left];
  left = [];
  for (const email of todo) {
    const acc = pwmap.get(email.toLowerCase());
    console.log(`-> retrying ${email}`);
    const args = [join(ROOT, "scripts", "run-batch.mjs"), acc.email];
    // forward a --proxy arg if provided on the CLI
    const pi = process.argv.indexOf("--proxy");
    if (pi >= 0) args.push("--proxy", process.argv[pi + 1] || "");
    // password/token via env (never on the cmdline — visible via ps)
    const r = spawnSync("node", args, { encoding: "utf8", timeout: 360000, env: { ...process.env, RUNBATCH_PW: acc.pw, RUNBATCH_TOK: acc.tok } });
    if (r.status === 0) {
      // success: run-batch appended to loggedmail + cleanupList removed from failed.txt
      const cur = existsSync(FAILED) ? readFileSync(FAILED, "utf8") : "";
      if (!cur.split("\n").some((l) => l.startsWith(email + "|"))) console.log(`  ${email} recovered ✓`);
      else left.push(email);
    } else left.push(email);
  }
  if (left.length && pass === 1) { console.log(`waiting 30s before pass 2...`); await new Promise((r) => setTimeout(r, 30000)); }
}
console.log(`retry done; remaining in failed.txt: ${left.length}`);
if (left.length) process.exit(1);
