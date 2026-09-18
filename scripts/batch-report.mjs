#!/usr/bin/env node
// batch-report: summarize .batch-out.txt into a per-account report for handoff.
// Prints emails + outcomes + tap codes + wall counts. Never prints secrets —
// the batch log itself carries none; lines with credential-looking material are
// skipped defensively.
// Usage: node scripts/batch-report.mjs [--tail N]   (default: whole log)
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, ".batch-out.txt");
if (!existsSync(OUT)) { console.log("no .batch-out.txt yet — run the batch first"); process.exit(0); }
const tailN = +(process.argv.find((a) => /^\d+$/.test(a)) || 0);
let lines = readFileSync(OUT, "utf8").split("\n").filter(Boolean);
if (tailN) lines = lines.slice(-tailN);

const accts = new Map(); // email -> {start,end,outcome,taps[],bounces,screens[]}
let cur = null;
const FailRe = /(marking failed|Wrong password|Invalid email|insecure-browser|persistent-unknown|manual-verify|session invalid|bad creds|cdp-unreachable|blocked|risk\/robot|timeout \(|Captcha not solved|manual password)/;
for (const line of lines) {
  if (/RUNBATCH_PW|BEGIN .*PRIVATE|mh_live_[0-9a-f]{10,}/.test(line)) continue; // paranoia
  let m = line.match(/Logging in account (\S+?)\.(\.\.\.|$)/);
  if (m) { cur = m[1]; if (!accts.has(cur)) accts.set(cur, { start: line.slice(0, 10), end: "", outcome: "IN-PROGRESS", taps: [], bounces: 0, screens: [] }); else { accts.get(cur).start = line.slice(0, 10); accts.get(cur).outcome = "IN-PROGRESS"; } continue; }
  if (!cur || !accts.has(cur)) continue;
  const a = accts.get(cur);
  a.end = line.slice(0, 10);
  if (/Done! \(session verified\)/.test(line)) a.outcome = "SUCCESS";
  else if (/Skipping .* \(valid cookies\)/.test(line)) a.outcome = "SKIPPED-valid";
  else if (FailRe.test(line)) a.outcome = "FAILED: " + (line.match(/marking failed|Wrong password.{0,40}|Invalid email|insecure-browser|persistent-unknown \S*|manual-verify|session invalid|bad creds|cdp-unreachable|\(blocked\)|blocked|risk\/robot|timeout \([^)]*\)|Captcha not solved|manual password/) || ["see log"])[0];
  m = line.match(/Code found! Click (\d+)/);
  if (m && !a.taps.includes(m[1])) a.taps.push(m[1]);
  if (/bounced back/i.test(line)) a.bounces++;
  m = line.match(/Screenshot saved: (\S+)/);
  if (m) a.screens.push(m[1].split("/").pop());
  if (/Batch finished/.test(line)) cur = null;
}
console.log("ACCOUNT | START | END | OUTCOME | TAPS | BOUNCES | SHOT");
for (const [e, a] of accts) console.log(`${e} | ${a.start} | ${a.end} | ${a.outcome} | ${a.taps.join(",") || "-"} | ${a.bounces} | ${a.screens.join(",") || "-"}`);
const vals = [...accts.values()];
console.log(`\nTOTAL ${accts.size}: ${vals.filter((a) => a.outcome === "SUCCESS").length} success, ${vals.filter((a) => a.outcome.startsWith("FAILED")).length} failed, ${vals.filter((a) => /SKIPPED|IN-PROGRESS/.test(a.outcome)).length} skipped/in-progress`);
console.log("\nPaste this table back to report. Full lines: grep <email> .batch-out.txt");
