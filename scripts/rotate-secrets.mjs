#!/usr/bin/env node
// timestamped stdout (UTC HH:MM:SS on every line)
for (const _k of ["log", "error", "warn"]) { const _f = console[_k].bind(console); console[_k] = (..._a) => _f(`[${new Date().toISOString().slice(11, 19)}]`, ..._a); }
// rotate-secrets: rotate PASSWORD (env), API_KEY + PUBLIC_TOKEN (SQLite settings table).
// Backs up .env and the DB before rotating; never logs new secrets.
import { readFileSync, writeFileSync, copyFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ENV = join(ROOT, ".env");
const DB = join(ROOT, "inbox.db");
const bakDir = join(ROOT, "_backup_files");
mkdirSync(bakDir, { recursive: true });
const ts = Date.now();

// backup .env (if exists)
if (existsSync(ENV)) copyFileSync(ENV, join(bakDir, `env-${ts}.bak`));
// backup DB (sqlite copy via VACUUM-free file copy is fine while server is running? use .backup to be safe)
copyFileSync(DB, join(bakDir, `inbox-${ts}.db.bak`));

const db = new DatabaseSync(DB);
const up = (k, v) => db.prepare("UPDATE settings SET value=?, updated_at=? WHERE key=?").run(v, Date.now(), k);
const upsert = (k, v) => { const r = db.prepare("UPDATE settings SET value=?, updated_at=? WHERE key=?").run(v, Date.now(), k); if (r.changes === 0) db.prepare("INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)").run(k, v, Date.now()); };

const newKey = "mh_live_" + crypto.randomBytes(32).toString("hex");
const newPub = crypto.randomBytes(16).toString("hex");
upsert("api_key", newKey);
upsert("public_token", newPub);

// rotate PASSWORD in .env
if (existsSync(ENV)) {
  let s = readFileSync(ENV, "utf8");
  const npw = crypto.randomBytes(18).toString("base64url").slice(0, 24);
  s = s.replace(/^PASSWORD=.*/m, "PASSWORD=" + npw);
  writeFileSync(ENV, s, { mode: 0o600 });
}

console.log(`rotated API key + public token + PASSWORD; backup dir: ${bakDir} (${ts})`);
console.log("NEXT: pm2 restart gmail-inbox  (or restart the server) for changes to take effect");
