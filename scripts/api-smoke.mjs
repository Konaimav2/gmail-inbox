#!/usr/bin/env node
// api-smoke: regression suite for the Mail Hub HTTP API.
// Exits 0 with "ALL N CHECKS PASS" or 1 with failures. Writes /tmp/api-smoke.json.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const BASE = process.env.BASE || "http://127.0.0.1:8790";
const db = await import("node:sqlite").then(() => {});
// load secrets from local DB (settings table) or .env
let API_KEY = null, PUBLIC_TOKEN = null, PASSWORD = null;
try {
  const { DatabaseSync } = await import("node:sqlite");
  const d = new DatabaseSync(join(ROOT, "inbox.db"));
  const g = (k) => { const r = d.prepare("SELECT value FROM settings WHERE key=?").get(k); return r ? r.value : null; };
  API_KEY = g("api_key"); PUBLIC_TOKEN = g("public_token");
} catch {}
if (existsSync(join(ROOT, ".env")))
  for (const l of readFileSync(join(ROOT, ".env"), "utf8").split("\n")) {
    const m = l.match(/^([A-Z0-9_]+)=(.*)$/); if (m) { if (m[1] === "PASSWORD" && !PASSWORD) PASSWORD = m[2]; }
  }

let pass = 0, fail = 0; const results = [];
function check(name, cond, extra) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}${extra ? " -> " + extra : ""}`); }
  results.push({ name, ok: !!cond });
}

async function call(method, path, { key, pub, xkey, body, big } = {}) {
  const h = {};
  if (key) h["Authorization"] = key;
  if (xkey) h["X-API-Key"] = xkey;
  if (pub) h["Authorization"] = pub;
  if (body !== undefined) h["Content-Type"] = "application/json";
  const payload = big ? Buffer.alloc(1_100_000, "a") : (body !== undefined ? JSON.stringify(body) : undefined);
  const r = await fetch(BASE + path, { method, headers: h, body: payload });
  return { status: r.status, json: await r.json().catch(() => null) };
}

console.log("api-smoke against", BASE);
check("login correct pw -> 200 + token", await (async () => { const r = await call("POST", "/api/login", { body: { password: PASSWORD } }); return r.status === 200 && r.json?.data?.token; })());
check("login wrong pw -> 401", await (async () => { const r = await call("POST", "/api/login", { body: { password: "WRONG_" + Date.now() } }); return r.status === 401; })());
check("/api/docs no auth -> 401", await (async () => { const r = await call("GET", "/api/docs"); return r.status === 401; })());
check("/api/docs with key -> 200", await (async () => { const r = await call("GET", "/api/docs", { xkey: API_KEY }); return r.status === 200; })());
check("/api/accounts with key -> 200 array", await (async () => { const r = await call("GET", "/api/accounts", { xkey: API_KEY }); return r.status === 200 && Array.isArray(r.json); })());
check("/api/public/emailList no token -> 401", await (async () => { const r = await call("POST", "/api/public/emailList", { body: { size: 1 } }); return r.status === 401; })());
check("/api/public/emailList with token -> 200", await (async () => { const r = await call("POST", "/api/public/emailList", { pub: PUBLIC_TOKEN, body: { size: 1 } }); return r.status === 200; })());
check("/api/email/list with key -> 200", await (async () => { const r = await call("POST", "/api/email/list", { key: API_KEY, body: { size: 1 } }); return r.status === 200; })());
check("oversized body -> 413", await (async () => { const r = await call("POST", "/api/public/emailList", { pub: PUBLIC_TOKEN, big: true }); return r.status === 413; })());
check("/api/sse no auth -> 401", await (async () => { const r = await call("GET", "/api/sse"); return r.status === 401; })());
check("/api/rotate needs auth -> 401", await (async () => { const r = await call("POST", "/api/rotate"); return r.status === 401; })());
check("account/list removed -> 404", await (async () => { const r = await call("POST", "/api/account/list", { xkey: API_KEY, body: {} }); return r.status === 404; })());

writeFileSync("/tmp/api-smoke.json", JSON.stringify({ pass, fail, results }, null, 2));
console.log(`\n${fail ? "FAILED" : "ALL"} ${pass + fail} CHECKS PASS (${pass} ok, ${fail} fail)`);
process.exit(fail ? 1 : 0);
