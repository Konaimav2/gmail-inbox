// gmail-inbox: cookie-based multi-Gmail inbox API + web UI
// Fetch: mail.google.com /h/ (embedded simls payload) with saved cookies
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import http from "node:http";
import { DatabaseSync } from "node:sqlite";
import crypto from "node:crypto";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const COOKIE_DIR = join(ROOT, "cookies");
const DB_PATH = join(ROOT, "inbox.db");
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";

// env config (from .env if present)
const ENV = {};
if (existsSync(join(ROOT, ".env")))
  for (const line of readFileSync(join(ROOT, ".env"), "utf8").split("\n")) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m) ENV[m[1]] = m[2];
  }
const PORT = +(ENV.PORT || 8790);
const HOST = ENV.HOST || "127.0.0.1";
const TRUST_PROXY = ENV.TRUST_PROXY === "1";
const PASSWORD = ENV.PASSWORD || "changeme123";
if (!PASSWORD || PASSWORD === "changeme123") { console.error("[gmail-inbox] missing PASSWORD — set PASSWORD in .env and restart"); process.exit(1); }
const SYNC_MINUTES = +(ENV.SYNC_MINUTES || 300); // legacy (keepalive replaces syncLoop)
const MONITOR_SECONDS = +(ENV.MONITOR_SECONDS || 30); // SSE selected-account poll interval
const REFRESH_STALE_MS = +(ENV.REFRESH_STALE_MS || 5 * 60 * 1000); // P2-4 freshness threshold
const KEEPALIVE_HOURS = +(ENV.KEEPALIVE_HOURS || 12); // P2-4b keepalive interval (0 disables)

// ---- spam sync (all mail = inbox + spam): Playwright full-UI scrape via python child ----
// spam gate: enabled only when SPAM_SYNC=1 (default OFF)
import { spawn as _spawn } from "node:child_process";
const SPAM_ENABLED = ENV.SPAM_SYNC === "1";
const SPAM_PYTHON = ENV.SPAM_PYTHON || "/root/temp/token-harbor/.venv/bin/python3";
const SPAM_SYNC_MINUTES = +(ENV.SPAM_SYNC_MINUTES || 60);
let _spamRunning = false;
function spamSync(emails = []) {
  if (_spamRunning) { console.log("[gmail-inbox] spam sync already running — skip"); return; }
  if (!existsSync(join(ROOT, "tools", "spam_sync.py"))) { console.log("[gmail-inbox] tools/spam_sync.py missing — skip"); return; }
  _spamRunning = true;
  const args = [join(ROOT, "tools", "spam_sync.py"), ...emails];
  const child = _spawn(SPAM_PYTHON, args, {
    env: { ...process.env, DISPLAY: ENV.SPAM_DISPLAY || ":99" },
    stdio: "ignore", detached: false,
  });
  child.on("exit", (code) => { _spamRunning = false; console.log(`[gmail-inbox] spam sync done (rc=${code})`); });
  child.on("error", (e) => { _spamRunning = false; console.log(`[gmail-inbox] spam sync spawn fail: ${e.message}`); });
  console.log(`[gmail-inbox] spam sync started (${emails.length ? emails.join(",") : "all accounts"})`);
}
let API_KEY = ENV.API_KEY || null; // set below from local DB (auto-generated + persisted)
let PUBLIC_TOKEN = ENV.PUBLIC_TOKEN || null;
console.log("  no secrets in logs: credentials live in .env / local DB / cookies/");

// ---- db ----
const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;");
db.exec(`
CREATE TABLE IF NOT EXISTS accounts(email TEXT PRIMARY KEY, name TEXT, cookie_file TEXT, added_at INTEGER, last_sync INTEGER, last_error TEXT);
CREATE TABLE IF NOT EXISTS threads(thread_id TEXT, email TEXT, ts INTEGER, subject TEXT, snippet TEXT, PRIMARY KEY(email, thread_id));
CREATE TABLE IF NOT EXISTS messages(msg_id TEXT, email TEXT, thread_id TEXT, ts INTEGER, subject TEXT, sender TEXT, sender_name TEXT, recipients TEXT, body_html TEXT, PRIMARY KEY(email, msg_id));
CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(email, ts DESC);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER);
CREATE TABLE IF NOT EXISTS web_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT UNIQUE, created INTEGER, expiry INTEGER, ip TEXT, last_seen INTEGER);
`);
// ---- auto-generate + persist secrets in the local DB (survives restarts, no .env needed) ----
function getOrCreateSetting(name, gen) {
  const row = db.prepare("SELECT value FROM settings WHERE key=?").get(name);
  if (row) return row.value;
  const v = gen();
  db.prepare("INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)").run(name, v, Date.now());
  return v;
}
if (!API_KEY) { API_KEY = getOrCreateSetting("api_key", () => "mh_live_" + crypto.randomBytes(32).toString("hex")); console.log("[gmail-inbox] API key auto-generated and stored in local DB"); }
else { // persist the env-provided key into the DB so it stays consistent across restarts
  const row = db.prepare("SELECT value FROM settings WHERE key='api_key'").get();
  if (!row) { db.prepare("INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)").run("api_key", API_KEY, Date.now()); console.log("[gmail-inbox] API key from .env migrated into local DB"); }
}
if (!PUBLIC_TOKEN) {
  // migrate existing .public-token file into DB (if present) so current clients keep working
  const legacy = existsSync(join(ROOT, ".public-token")) ? readFileSync(join(ROOT, ".public-token"), "utf8").trim() : null;
  PUBLIC_TOKEN = getOrCreateSetting("public_token", () => legacy || crypto.randomBytes(16).toString("hex"));
  if (!legacy) console.log("[gmail-inbox] public token auto-generated and stored in local DB");
}
const SESSION_SECRET = ENV.SESSION_SECRET || (() => { const row = db.prepare("SELECT value FROM settings WHERE key='session_secret'").get(); if (row) return row.value; const s = crypto.randomBytes(32).toString("hex"); db.prepare("INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)").run("session_secret", s, Date.now()); return s; })();
const prep = (sql) => db.prepare(sql);
const LIST_ACCOUNTS = prep("SELECT rowid,* FROM accounts ORDER BY email");
const GET_ACCOUNT = prep("SELECT * FROM accounts WHERE email=?");
const UPSERT_ACCOUNT = prep("INSERT INTO accounts(email,name,cookie_file,added_at) VALUES(?,?,?,?) ON CONFLICT(email) DO UPDATE SET name=excluded.name, cookie_file=excluded.cookie_file");
const ACCOUNT_SYNC = prep("UPDATE accounts SET last_sync=?, last_error=? WHERE email=?");
const UPSERT_THREAD = prep("INSERT INTO threads(thread_id,email,ts,subject,snippet) VALUES(?,?,?,?,?) ON CONFLICT(email,thread_id) DO UPDATE SET ts=excluded.ts, subject=excluded.subject, snippet=excluded.snippet");
const UPSERT_MSG = prep("INSERT INTO messages(msg_id,email,thread_id,ts,subject,sender,sender_name,recipients,body_html) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(email,msg_id) DO UPDATE SET body_html=excluded.body_html, subject=excluded.subject, sender=excluded.sender");
const MSGS_BY_THREAD = prep("SELECT * FROM messages WHERE email=? AND thread_id=? ORDER BY ts");
const RECENT = prep("SELECT t.*, (SELECT sender FROM messages m WHERE m.email=t.email AND m.thread_id=t.thread_id ORDER BY ts LIMIT 1) sender FROM threads t WHERE t.email=? ORDER BY t.ts DESC LIMIT ? OFFSET ?");
const PRUNE = prep("DELETE FROM threads WHERE email=? AND ts < ?");
const PRUNE_M = prep("DELETE FROM messages WHERE email=? AND ts < ?");

// ---- accounts discovered from cookie files ----
function discoverAccounts() {
  if (!existsSync(COOKIE_DIR)) return;
  // reverse-map cookie filenames to real emails from loggedmail.txt (authoritative)
  const slugToEmail = {};
  try {
    for (const l of readFileSync(join(ROOT, "loggedmail.txt"), "utf8").split("\n")) {
      const em = (l.split("|")[0] || "").trim();
      if (em) slugToEmail[em.replace(/[@.]/g, "_") + ".json"] = em;
    }
  } catch {}
  for (const f of readdirSync(COOKIE_DIR)) {
    if (!f.endsWith(".json") || f === "invalid") continue;
    const em = slugToEmail[f] || null;
    if (!em) continue;
    try {
      const c = JSON.parse(readFileSync(join(COOKIE_DIR, f), "utf8"));
      const hasSess = c.some((x) => x.name === "SID" || x.name === "SSID" || x.name === "__Secure-1PSID");
      if (!hasSess) continue;
      UPSERT_ACCOUNT.run(em, em, f, Date.now());
    } catch {}
  }
}

// ---- gmail fetch (cookie-jar aware: follows redirects + applies Set-Cookie) ----
function cookieHeader(arr) {
  const best = new Map();
  const rank = (c) => [c.domain.split(".").length, c.path ? c.path.length : 0, c.domain.startsWith(".") ? 0 : 1];
  for (const c of arr) {
    if (!c.domain || c.domain.indexOf("google.com") < 0) continue;
    const k = c.name;
    if (!best.has(k) || rank(c) > rank(best.get(k))) best.set(k, c);
  }
  return [...best.values()].filter((c) => c.name !== "NID" && c.name !== "AEC").map((c) => `${c.name}=${c.value}`).join("; ");
}
async function fetchWithJar(cookies, url, extraHeaders = {}) {
  let jar = [...cookies];
  let cur = url;
  for (let hop = 0; hop < 6; hop++) {
    const res = await fetch(cur, { headers: { "User-Agent": UA, ...extraHeaders, Cookie: cookieHeader(jar) }, redirect: "manual" });
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const sc of setCookies) {
      const [pair] = sc.split(";");
      const eq = pair.indexOf("=");
      if (eq < 1) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const dm = (sc.match(/Domain=([^;]+)/i) || [])[1] || "google.com";
      const pth = (sc.match(/Path=([^;]+)/i) || [])[1] || "/";
      const existing = jar.find((c) => c.name === name);
      if (existing) existing.value = value;
      else jar.push({ name, value, domain: dm, path: pth, secure: /Secure/i.test(sc), expires: -1 });
    }
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return { status: res.status, body: "", jar };
      cur = new URL(loc, cur).toString();
      continue;
    }
    return { status: res.status, body: await res.text(), jar };
  }
  return { status: 599, body: "", jar };
}
// fetch one /h/ page for a query and parse its simls payload
async function fetchInboxPage(cookies, q, cf, email) {
  const url = `https://mail.google.com/mail/u/0/h/?v=m&s=q&q=${encodeURIComponent(q)}`;
  const { status, body: t, jar } = await fetchWithJar(cookies, url);
  try {
    const changed = cookies.filter((c) => jar.find((j) => j.name === c.name && j.value !== c.value));
    if (changed.length) {
      for (const c of cookies) { const j = jar.find((x) => x.name === c.name); if (j) c.value = j.value; }
      writeFileSync(cf, JSON.stringify(cookies, null, 2), { mode: 0o600 });
      console.log(`[gmail-inbox] rotated cookies for ${email} (${changed.length} changed)`);
    }
  } catch {}
  if (status !== 200) throw new Error("http " + status);
  const m = t.match(/"simls",null,"((?:[^"\\]|\\.)*)"/);
  if (!m) {
    if (/<title>Sign in - Google Accounts/.test(t) || t.includes("gaia_loginform")) {
      try {
        const { mkdirSync, renameSync } = await import("node:fs");
        const badDir = join(COOKIE_DIR, "invalid");
        mkdirSync(badDir, { recursive: true });
        renameSync(cf, join(badDir, email.replace(/[@.]/g, "_") + ".json"));
        console.log("[gmail-inbox] quarantined dead cookie:", email);
      } catch {}
      throw new Error("session expired");
    }
    return []; // no simls (empty result) — not an error
  }
  const arr = JSON.parse(JSON.parse('"' + m[1] + '"'));
  const out = [];
  for (const e of arr[1] || []) {
    if (!Array.isArray(e) || e.length < 2) continue;
    const meta = e[1];
    const msgs = (meta[4] && Array.isArray(meta[4])) ? meta[4].filter((x) => Array.isArray(x)) : [];
    for (const msg of msgs) {
      let body = null;
      try { body = msg[8][1][0][2][1]; } catch {}
      const sender = (msg[1] && msg[1][1]) || "";
      const subject = meta[0] || "";
      // skip empty system placeholders: no real subject, and no real sender
      // ((unknown sender) from Google counts as no sender)
      const realSender = sender && !/^\(unknown sender\)$/i.test(sender);
      if (!subject && !realSender && !(meta[1] || "")) continue;
      out.push({
        thread_id: meta[3] || null,
        ts: meta[2] || 0,
        subject: subject,
        snippet: meta[1] || "",
        msg_id: msg[0] || null,
        sender: sender,
        sender_name: (msg[1] && msg[1][2]) || "",
        recipients: (msg[2] && msg[2][0] && msg[2][0][1]) || "",
        body_html: body || "",
      });
    }
  }
  return out;
}
// Gmail atom feed — returns up to ~20 recent INBOX items with subject/sender/date.
// Far more than the /h/ view's 5-cap, and cheap. Entries have no body_html (fetched on open).
async function fetchAtom(cookies, cf, email, label = "") {
  // label "" = inbox; "spam" = [Gmail]/Spam (via feed/atom/<label>)
  const url = label
    ? `https://mail.google.com/mail/u/0/feed/atom/${encodeURIComponent(label)}`
    : "https://mail.google.com/mail/u/0/feed/atom";
  const { status, body, jar } = await fetchWithJar(cookies, url);
  try {
    const changed = cookies.filter((c) => jar.find((j) => j.name === c.name && j.value !== c.value));
    if (changed.length) {
      for (const c of cookies) { const j = jar.find((x) => x.name === c.name); if (j) c.value = j.value; }
      writeFileSync(cf, JSON.stringify(cookies, null, 2), { mode: 0o600 });
    }
  } catch {}
  if (status !== 200) throw new Error("atom http " + status);
  if (/<title>Sign in - Google Accounts/.test(body) || body.includes("gaia_loginform")) {
    try {
      const { mkdirSync, renameSync } = await import("node:fs");
      const badDir = join(COOKIE_DIR, "invalid");
      mkdirSync(badDir, { recursive: true });
      renameSync(cf, join(badDir, email.replace(/[@.]/g, "_") + ".json"));
      console.log("[gmail-inbox] quarantined dead cookie:", email);
    } catch {}
    throw new Error("session expired");
  }
  const out = [];
  const re = /<entry>([\s\S]*?)<\/entry>/g;
  let m;
  while ((m = re.exec(body))) {
    const e = m[1];
    const t = (s) => { const x = e.match(new RegExp(`<${s}>(.*?)</${s}>`, "s")); return x ? x[1].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'") : ""; };
    const subj = t("title");
    const summ = t("summary");
    const issued = t("issued");
    const idm = e.match(/<id>tag:gmail\.google\.com,2004:(\d+)<\/id>/);
    const authorName = t("name");
    const authorEmail = t("email");
    out.push({
      thread_id: idm ? idm[1] : null,
      msg_id: idm ? idm[1] : null,
      ts: issued ? new Date(issued).getTime() : 0,
      subject: subj,
      snippet: summ,
      sender: authorEmail || "",
      sender_name: authorName || "",
      recipients: "",
      body_html: "",
    });
  }
  // also filter atom entries older than 30 days (Gmail returns >20 by default)
  const cutoff = Date.now() - 20 * 864e5;
  return out.filter((x) => x.ts >= cutoff);
}

async function fetchInbox(email, q = "in:anywhere newer_than:20d") {
  const acct = GET_ACCOUNT.get(email);
  if (!acct) throw new Error("no account");
  const cf = join(COOKIE_DIR, acct.cookie_file);
  const cookies = JSON.parse(readFileSync(cf, "utf8"));
  // merge: atom feed (up to ~20 inbox items) + adaptive /h/ split (older / other labels).
  // Dedupe by thread/msg id — atom gives real subjects/senders, /h/ adds bodies + coverage.
  const all = [];
  const seen = new Set();
  // atom: inbox + spam (in:anywhere /h/ misses spam — TH verify emails land there)
  for (const label of ["", "spam"]) {
    try {
      const atom = await fetchAtom(cookies, cf, email, label);
      for (const it of atom) {
        const k = it.thread_id || it.msg_id;
        if (seen.has(k)) continue;
        seen.add(k); all.push(it);
      }
    } catch (e) {
      if (String(e.message || e) === "session expired") throw e;
      if (label === "spam") console.log(`[gmail-inbox] spam atom skip for ${email}: ${e.message || e}`);
    }
  }
  // Gmail /h/ returns at most ~5 conversations per query, regardless of pagination.
  // To capture up to `target` conversations, recursively split the [start,end) window
  // into smaller buckets; a bucket that still returns ~5 (== "full") is split further.
  const target = 100;
  const DAY = 864e5;
  const now = Date.now();
  const MIN_DAY = 1; // stop splitting below 1 day to bound request count

  async function walk(from, to, depth) {
    if (seen.size >= target) return;
    if (to - from < MIN_DAY * DAY || depth > 9) return;
    let page;
    try {
      const qw = `in:anywhere after:${Math.floor(from / 1000)} before:${Math.floor(to / 1000)}`;
      page = await fetchInboxPage(cookies, qw, cf, email);
    } catch (e) {
      if (String(e.message || e) === "session expired") throw e;
      return;
    }
    let added = 0;
    for (const it of page) {
      const k = it.thread_id || it.msg_id;
      if (seen.has(k)) continue;
      seen.add(k); all.push(it); added++;
    }
    // only recurse into a bucket if it returned NEW items AND was near the page cap;
    // if everything was already seen, deeper splits just repeat the same results.
    if (added === 0) return;
    if (page.length >= 4 && seen.size < target) {
      const mid = from + Math.floor((to - from) / 2);
      await walk(mid, to, depth + 1);
      await walk(from, mid, depth + 1);
    }
  }

  // start with the full past-20-day window; recursion narrows as needed
  await walk(now - 20 * DAY, now, 0);
  // spam pass: in:anywhere misses spam — run the same window with in:spam
  if (seen.size < target) {
    async function walkSpam(from, to, depth) {
      if (seen.size >= target) return;
      if (to - from < MIN_DAY * DAY || depth > 5) return;
      let page;
      try {
        const qw = `in:spam after:${Math.floor(from / 1000)} before:${Math.floor(to / 1000)}`;
        page = await fetchInboxPage(cookies, qw, cf, email);
      } catch (e) {
        if (String(e.message || e) === "session expired") throw e;
        return;
      }
      let added = 0;
      for (const it of page) {
        const k = (it.thread_id || it.msg_id) + ":spam";
        if (seen.has(k)) continue;
        seen.add(k); it.label = "spam"; all.push(it); added++;
      }
      if (added === 0) return;
      if (page.length >= 4 && seen.size < target) {
        const mid = from + Math.floor((to - from) / 2);
        await walkSpam(mid, to, depth + 1);
        await walkSpam(from, mid, depth + 1);
      }
    }
    await walkSpam(now - 20 * DAY, now, 0);
  }
  return all;
}

// on-demand body fetch: Gmail conversation view for one thread → messages with bodies.
// Used when opening a thread whose stored rows have empty body_html (atom-feed entries).
async function fetchThreadBody(email, threadId) {
  const acct = GET_ACCOUNT.get(email);
  if (!acct) throw new Error("no account");
  const cf = join(COOKIE_DIR, acct.cookie_file);
  const cookies = JSON.parse(readFileSync(cf, "utf8"));
  const url = `https://mail.google.com/mail/u/0/h/?v=c&th=${encodeURIComponent(threadId)}`;
  let { status, body, jar } = await Promise.race([
    fetchWithJar(cookies, url),
    new Promise((res) => setTimeout(() => res({ status: 0, body: "", jar: [...cookies] }), 15000)),
  ]);
  if (!status) throw new Error("timeout");
  try {
    const changed = cookies.filter((c) => jar.find((j) => j.name === c.name && j.value !== c.value));
    if (changed.length) {
      for (const c of cookies) { const j = jar.find((x) => x.name === c.name); if (j) c.value = j.value; }
      writeFileSync(cf, JSON.stringify(cookies, null, 2), { mode: 0o600 });
    }
  } catch {}
  if (status !== 200) throw new Error("http " + status);
  if (/<title>Sign in - Google Accounts/.test(body) || body.includes("gaia_loginform")) throw new Error("session expired");
  const m = body.match(/"simls",null,"((?:[^"\\]|\\.)*)"/);
  if (!m) return [];
  const arr = JSON.parse(JSON.parse('"' + m[1] + '"'));
  const out = [];
  for (const e of arr[1] || []) {
    if (!Array.isArray(e) || e.length < 2) continue;
    const meta = e[1];
    // The conversation view returns the single requested thread. Match by thread id OR
    // by numeric msg-id suffix (atom uses numeric ids, simls uses thread-f:...), and if
    // nothing matches take the first conversation as a fallback.
    const tid = meta[3] || "";
    const tidNumeric = tid.replace(/^thread-f:/, "").split(":")[0];
    const wantNumeric = String(threadId).replace(/^thread-f:/, "").split(":")[0];
    const matches = tid === threadId || tidNumeric === wantNumeric || tid.endsWith(wantNumeric) || (out.length === 0 && arr[1].length === 1);
    if (!matches && out.length) continue;
    const msgs = (meta[4] && Array.isArray(meta[4])) ? meta[4].filter((x) => Array.isArray(x)) : [];
    for (const msg of msgs) {
      let bodyHtml = null;
      try { bodyHtml = msg[8][1][0][2][1]; } catch {}
      out.push({
        thread_id: meta[3] || null,
        ts: meta[2] || 0,
        subject: meta[0] || "",
        snippet: meta[1] || "",
        msg_id: msg[0] || null,
        sender: (msg[1] && msg[1][1]) || "",
        sender_name: (msg[1] && msg[1][2]) || "",
        recipients: (msg[2] && msg[2][0] && msg[2][0][1]) || "",
        body_html: bodyHtml || "",
      });
    }
  }
  return out;
}

// background body backfill: fetch + cache bodies for messages that have none.
// Reads empty-body messages for the account, fetches each thread's conversation view
// (capped concurrency), persists the bodies. Never throws out — caller ignores.
const backfillRunning = new Set();
async function backfillBodies(email) {
  if (backfillRunning.has(email)) return;
  backfillRunning.add(email);
  try {
    const rows = db.prepare(
      "SELECT thread_id, msg_id FROM messages WHERE email=? AND (body_html IS NULL OR body_html='') AND thread_id IS NOT NULL ORDER BY ts DESC LIMIT 200"
    ).all(email);
    const seen = new Set();
    const cap = 3;
    let i = 0;
    async function worker() {
      while (i < rows.length) {
        const row = rows[i++];
        if (!row || seen.has(row.thread_id)) continue;
        seen.add(row.thread_id);
        try {
          const live = await fetchThreadBody(email, row.thread_id);
          if (!live.length) continue;
          const body = live.find((l) => l.body_html);
          if (!body) continue;
          // fill every message of this thread that lacks a body (atom + simls ids both)
          const threadRows = db.prepare("SELECT msg_id FROM messages WHERE email=? AND thread_id=? AND (body_html IS NULL OR body_html='')").all(email, row.thread_id);
          for (const tr of threadRows) {
            db.prepare("UPDATE messages SET body_html=?, sender=?, sender_name=? WHERE email=? AND msg_id=?").run(body.body_html, body.sender || "", body.sender_name || "", email, tr.msg_id);
          }
        } catch { /* skip failures (session/timeout) */ }
        await new Promise((r) => setTimeout(r, 300));
      }
    }
    await Promise.all(Array.from({ length: cap }, worker));
    console.log(`[gmail-inbox] backfilled bodies for ${email}`);
  } catch { } finally { backfillRunning.delete(email); }
}

// normalize thread ids: strip the "thread-f:" prefix so atom (numeric) and /h/ (thread-f:)
// entries for the SAME conversation collapse into one thread. msg-f: similarly.
// Returns "" for malformed ids (e.g. bare "thread-f" with no numeric core) so they're skipped.
function normTid(t) {
  const s = String(t || "").replace(/^thread-f:/, "").split(":")[0];
  return /^\d{6,}$/.test(s) ? s : "";
}
function normMid(m) { return String(m || "").replace(/^msg-f:/, "").split(":")[0]; }

// P2-4 stale-while-revalidate: fire-and-forget refresh when cache older than threshold
function maybeRefresh(email) {
  if (!email) return;
  try {
    const acct = GET_ACCOUNT.get(email);
    if (!acct) return;
    if (Date.now() - (acct.last_sync || 0) > REFRESH_STALE_MS) syncAccount(email).catch(() => {});
  } catch {}
}
function maybeRefreshAll() {
  try { for (const a of LIST_ACCOUNTS.all()) maybeRefresh(a.email); } catch {}
}
async function syncAccount(email) {
  try {
    const items = await fetchInbox(email);
    const now = Date.now(), cutoff = now - 20 * 864e5;
    for (const it of items) {
      if (!it.thread_id) continue;
      const tid = normTid(it.thread_id);
      if (!tid) continue;
      UPSERT_THREAD.run(tid, email, it.ts || now, it.subject, it.snippet);
      if (it.msg_id) UPSERT_MSG.run(normMid(it.msg_id), email, tid, it.ts || now, it.subject, it.sender, it.sender_name, it.recipients, it.body_html);
    }
    PRUNE.run(email, cutoff); PRUNE_M.run(email, cutoff);
    ACCOUNT_SYNC.run(now, null, email);
    console.log(`[gmail-inbox] active ${email} (${items.length} threads)`);
    // background body backfill: fetch bodies for messages that have none, so opening is
    // instant. Fire-and-forget, capped concurrency, never blocks the sync.
    backfillBodies(email).catch(() => {});
    return items.length;
  } catch (e) {
    ACCOUNT_SYNC.run(Date.now(), String(e.message || e), email);
    throw e;
  }
}

// ---- monitor: atom feed new-mail detection (lightweight HTTP fullcount probe) ----
const lastAtom = new Map();
let SELECTED = null; // account receiving realtime new-mail checks (set via /api/select)
async function checkMail(email) {
  const acct = GET_ACCOUNT.get(email);
  if (!acct) return;
  try {
    const cookies = JSON.parse(readFileSync(join(COOKIE_DIR, acct.cookie_file), "utf8"));
    const { status, body: x } = await fetchWithJar(cookies, "https://mail.google.com/mail/u/0/feed/atom");
    if (status !== 200) {
      // stale session or rate limit — log and trigger full re-sync
      console.log(`[gmail-inbox] atom ${email}: HTTP ${status} — re-syncing...`);
      ACCOUNT_SYNC.run(Date.now(), "http " + status, email);
      syncAccount(email).catch(() => {});
      lastAtom.delete(email);  // reset so next poll re-checks
      return;
    }
    const full = (x.match(/<fullcount>(\d+)<\/fullcount>/) || [])[1] || "0";
    // full-sync ONLY when fullcount changed or cache older than 24h
    const prev = lastAtom.get(email);
    const lastSync = (GET_ACCOUNT.get(email) || {}).last_sync || 0;
    const tooOld = Date.now() - lastSync > 24 * 3600 * 1000;
    if (prev === undefined || prev !== full || tooOld) {
      lastAtom.set(email, full);
      console.log(`[gmail-inbox] atom ${email}: fullcount ${prev ?? "?"}→${full}${tooOld ? " (stale >24h)" : ""} — syncing`);
      syncAccount(email).catch(() => {});
    }
  } catch (e) {
    // log error and trigger re-sync on failure (stale cookies, network error, etc.)
    console.log(`[gmail-inbox] atom ${email} error: ${e.message || e} — re-syncing...`);
    ACCOUNT_SYNC.run(Date.now(), "error: " + (e.message || String(e)).slice(0, 80), email);
    syncAccount(email).catch(() => {});
    lastAtom.delete(email);
  }
}

// P2-4b keepalive: ONE interval (env KEEPALIVE_HOURS, default 12, 0 disables).
// Staggered per-account atom fullcount probes, all HTTP; full syncAccount only on
// fullcount change or last_sync older than 24h (see checkMail). No browser, no spam_sync.
async function keepalive() {
  const accts = LIST_ACCOUNTS.all();
  console.log(`[gmail-inbox] keepalive run (${accts.length} accounts)`);
  for (const a of accts) {
    try { await checkMail(a.email); } catch {}
    await new Promise((r) => setTimeout(r, 2000 + Math.random() * 3000)); // stagger + jitter
  }
}
if (KEEPALIVE_HOURS > 0) setInterval(keepalive, KEEPALIVE_HOURS * 3600 * 1000);
else console.log("[gmail-inbox] keepalive disabled (KEEPALIVE_HOURS=0)");

// ---- SSE + selected-account polling (P2-5: poll ONLY while viewers exist) ----
const sseClients = new Set();
function broadcast(type, data) {
  const s = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of sseClients) { try { c.write(s); } catch {} }
}
let selectedTimer = null; // SELECTED IdleTimer: cleared when last viewer leaves, SELECTED value kept
function stopSelectedPoll() {
  if (selectedTimer) { clearInterval(selectedTimer); selectedTimer = null; }
}
function startSelectedPoll() {
  if (selectedTimer || !SELECTED) return;
  selectedTimer = setInterval(() => {
    if (sseClients.size === 0 || !SELECTED) { stopSelectedPoll(); return; }
    checkMail(SELECTED).catch(() => {});
  }, MONITOR_SECONDS * 1000);
}
function sseAttach(res, req) {
  sseClients.add(res);
  const first = sseClients.size === 1;
  req.on("close", () => {
    sseClients.delete(res);
    if (sseClients.size === 0) stopSelectedPoll();
  });
  // fetch-latest for SELECTED when the first viewer connects
  if (first && SELECTED) { checkMail(SELECTED).catch(() => {}); startSelectedPoll(); }
}
function selectAccount(email) {
  SELECTED = email || null;
  // /api/select change while clients exist: fetch-latest + (re)start polling
  if (sseClients.size > 0) {
    stopSelectedPoll();
    if (SELECTED) { checkMail(SELECTED).catch(() => {}); startSelectedPoll(); }
  }
  return SELECTED;
}
discoverAccounts();
// periodic autopurge: drop threads/messages older than 20 days from cache
function purgeOld() {
  const cutoff = Date.now() - 20 * 864e5;
  let t = 0, m = 0;
  try {
    for (const a of LIST_ACCOUNTS.all()) {
      const r1 = PRUNE.run(a.email, cutoff), r2 = PRUNE_M.run(a.email, cutoff);
      t += r1.changes; m += r2.changes;
    }
    if (t + m > 0) console.log(`[gmail-inbox] autopurge: removed ${t} threads, ${m} messages >20d`);
  } catch {}
}
setInterval(purgeOld, 6 * 3600 * 1000); // every 6h
setTimeout(purgeOld, 120000); // once shortly after boot
// one-time body backfill at boot: fetch + cache bodies for all accounts' empty-body threads
setTimeout(async () => {
  try {
    const accts = LIST_ACCOUNTS.all();
    for (const a of accts) await backfillBodies(a.email).catch(() => {});
    console.log(`[gmail-inbox] boot body backfill complete (${accts.length} accounts)`);
  } catch {}
}, 30000);
// auto-reload accounts: re-scan cookie files every 30s so newly batch-logged accounts
// appear in the web UI without a server restart. Idempotent (UPSERT), no duplicates.
setInterval(() => { discoverAccounts(); broadcast("update", { ts: Date.now() }); }, 30 * 1000);

// ---- http ----
const SEC_HDR = { "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" };
const json = (res, code, obj, extra) => { res.writeHead(code, { "Content-Type": "application/json", ...SEC_HDR, ...(extra || {}) }); res.end(JSON.stringify(obj)); };
const sess = new Map(); // token -> {exp}  (legacy: replaced by signed stateless cookies)
const RATE = new Map(); // ip -> {fails[], blockedUntil}
const REFRESH_LAST = new Map(); // email -> last manual refresh ms
function safeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a), bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ab, bb); } catch { return false; }
}
function sessHash(tok) { return crypto.createHash("sha256").update(String(tok)).digest("hex"); }
function parseSess(tok) {
  if (typeof tok !== "string") return null;
  const parts = tok.split(".");
  if (parts.length === 2) {
    const [expHex, sig] = parts;
    if (!/^[0-9a-f]+$/i.test(expHex) || !sig) return null;
    const expMs = parseInt(expHex, 16);
    if (!Number.isFinite(expMs)) return null;
    return { sid: null, expHex, sig, expMs };
  }
  if (parts.length === 3) {
    const [sid, expHex, sig] = parts;
    if (!/^[0-9a-f]{32}$/i.test(sid)) return null;
    if (!/^[0-9a-f]+$/i.test(expHex) || !sig) return null;
    const expMs = parseInt(expHex, 16);
    if (!Number.isFinite(expMs)) return null;
    return { sid, expHex, sig, expMs };
  }
  return null;
}
function sessWant(tok, p) {
  p = p || parseSess(tok);
  if (!p) return null;
  const data = p.sid ? `${p.sid}.${p.expHex}` : p.expHex;
  return crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("base64url");
}
function sessSigOk(tok) {
  const p = parseSess(tok);
  if (!p) return false;
  const want = sessWant(tok, p);
  if (!want || p.sig.length !== want.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(p.sig), Buffer.from(want)); } catch { return false; }
}
function getSessToken(req) {
  const m = (req.headers.cookie || "").match(/(?:__Host-)?gsess=([A-Za-z0-9_.-]+)/);
  return m ? m[1] : null;
}
function isHttps(req) {
  const p = ((req.headers["x-forwarded-proto"] || "").split(",")[0] || "").trim().toLowerCase();
  if (p === "https") return true;
  if (p === "http") return false;
  try { if (req.socket && req.socket.encrypted) return true; } catch {}
  return false;
}
function sessCookieName(req) { return isHttps(req) ? "__Host-gsess" : "gsess"; }
function sessSetCookie(req, tok) {
  const n = sessCookieName(req);
  const sec = isHttps(req) ? "; Secure" : "";
  return `${n}=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${sec}`;
}
// restart-proof sessions: stateless HMAC-signed cookie (secret persisted in DB)
// new format: sid.exp.sig (sid = 16 random bytes hex); legacy exp.sig still accepted
function signSessionToken() {
  const sid = crypto.randomBytes(16).toString("hex");
  const exp = (Date.now() + 7 * 864e5).toString(16);
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(`${sid}.${exp}`).digest("base64url");
  return `${sid}.${exp}.${sig}`;
}
// server-side session registry: store only SHA-256 hash so DB theft does not yield cookies
function recordSession(tok, ip) {
  const p = parseSess(tok);
  if (!p) return;
  try { db.prepare("INSERT INTO web_sessions(token_hash, created, expiry, ip, last_seen) VALUES(?,?,?,?,?)").run(sessHash(tok), Date.now(), p.expMs, ip || "", Date.now()); } catch {}
}
function touchSession(tok) {
  const h = sessHash(tok);
  try {
    const r = db.prepare("UPDATE web_sessions SET last_seen=? WHERE token_hash=?").run(Date.now(), h);
    if (r.changes === 0) {
      const leg = db.prepare("SELECT id FROM web_sessions WHERE token_hash=?").get(tok);
      if (leg) db.prepare("UPDATE web_sessions SET token_hash=?, last_seen=? WHERE id=?").run(h, Date.now(), leg.id);
    }
  } catch {}
}
function listSessions() {
  return db.prepare("SELECT id, token_hash, created, expiry, ip, last_seen FROM web_sessions ORDER BY created DESC").all();
}
function revokeSession(tok) {
  try { db.prepare("DELETE FROM web_sessions WHERE token_hash=? OR token_hash=?").run(sessHash(tok), tok); return true; } catch { return false; }
}
function revokeSessionById(id) {
  try { db.prepare("DELETE FROM web_sessions WHERE id=?").run(id); return true; } catch { return false; }
}
function pruneSessions() {
  try { db.prepare("DELETE FROM web_sessions WHERE expiry < ?").run(Date.now()); } catch {}
}
function verifySessionToken(tok) {
  if (typeof tok !== "string") return false;
  const p = parseSess(tok);
  if (!p) return false;
  const want = sessWant(tok, p);
  if (!want || p.sig.length !== want.length) return false;
  let ok = false;
  try { ok = crypto.timingSafeEqual(Buffer.from(p.sig), Buffer.from(want)); } catch { return false; }
  if (!ok) return false;
  if (!(p.expMs > Date.now())) return false;
  try {
    const h = sessHash(tok);
    const row = db.prepare("SELECT id, expiry FROM web_sessions WHERE token_hash=?").get(h);
    if (row) {
      if (row.expiry && row.expiry < Date.now()) return false;
      return true;
    }
    const leg = db.prepare("SELECT id, expiry FROM web_sessions WHERE token_hash=?").get(tok);
    if (leg) {
      if (leg.expiry && leg.expiry < Date.now()) return false;
      return true;
    }
  } catch { return false; }
  return false;
}
function okAuth(ip) { try { RATE.delete(ip); } catch {} }
function isBlocked(ip) { const r = RATE.get(ip); return r && r.blockedUntil > Date.now() ? Math.ceil((r.blockedUntil - Date.now()) / 1000) : 0; }
function failAuth(ip) {
  const now = Date.now();
  if (!RATE.has(ip) && RATE.size >= 10000) { const k = RATE.keys().next().value; try { RATE.delete(k); } catch {} }
  let r = RATE.get(ip) || (RATE.set(ip, { fails: [], blockedUntil: 0 }), RATE.get(ip));
  r.fails = r.fails.filter((t) => now - t < 60000);
  r.fails.push(now);
  if (r.fails.length >= 20) { r.blockedUntil = now + 5 * 60 * 1000; r.fails = []; return 300; }
  return 0;
}
function authPage(req, res) {
  const tok = getSessToken(req);
  if (!tok) return false;
  pruneSessions();
  if (!verifySessionToken(tok)) {
    try { if (sessSigOk(tok)) console.log("[gmail-inbox] rejected untracked session (revoked or pre-tracking)"); } catch {}
    return false;
  }
  touchSession(tok);
  return true;
}
function csrf() { return crypto.randomBytes(16).toString("hex"); }
function csrfOriginOk(req) {
  const o = req.headers["origin"] || req.headers["referer"];
  if (!o) return false;
  try {
    const oh = new URL(o, `http://${req.headers.host}`).host;
    const h = (req.headers.host || "").split(",")[0].trim();
    if (!oh || !h) return false;
    return safeEq(oh.toLowerCase(), h.toLowerCase());
  } catch { return false; }
}
function authedViaKey(req) {
  const a = req.headers["authorization"] || "";
  const k = req.headers["x-api-key"];
  return safeEq(a, API_KEY) || safeEq(k, API_KEY);
}
function validHost(h) {
  if (typeof h !== "string") return null;
  const v = h.split(",")[0].trim();
  if (!v || v.length > 253) return null;
  if (/[\s\/]/.test(v)) return null;
  if (!/^[A-Za-z0-9.-]+(?::\d+)?$/.test(v)) return null;
  return v;
}
function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (xff) return xff;
  }
  try { return req.socket.remoteAddress || "?"; } catch { return "?"; }
}
function escLike(s) { return String(s).replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_"); }

// ---- cloud-mail compatible API helpers ----
const MAX_BODY = 1_000_000; // 1MB request body cap
function readBody(req, strict) {
  return new Promise((resolve) => {
    let b = "", too = false, done = false;
    const fin = (v) => { if (!done) { done = true; resolve(v); } };
    req.on("data", (d) => {
      if (too) return;
      b += d;
      if (b.length > MAX_BODY) { too = true; try { req.destroy(); } catch {} }
    });
    req.on("end", () => {
      if (too) return fin({ __too: true });
      if (!b) return fin(strict ? { __bad: true } : {});
      try { const o = JSON.parse(b); fin(o); }
      catch { fin({ __bad: true }); }
    });
    req.on("close", () => { if (too) fin({ __too: true }); });
    req.on("error", () => { if (too) fin({ __too: true }); });
  });
}
async function cloudBody(req, res) {
  const b = await readBody(req, true);
  if (b.__too) { json(res, 413, cloudFail("payload too large", 413)); return null; }
  if (b.__bad) { json(res, 400, cloudFail("bad json", 400)); return null; }
  return b;
}
function stripHtml(h) {
  return String(h || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}
function cloudOk(data) { return { code: 200, message: "success", data: data ?? null }; }
function cloudFail(message, code = 500) { return { code, message }; }
function msgRow(r) {
  return {
    emailId: r.rowid,
    sendEmail: r.sender,
    sendName: r.sender_name,
    subject: r.subject,
    toEmail: r.email,
    type: 0,
    createTime: r.ts,
    content: r.body_html || "",
    text: stripHtml(r.body_html).slice(0, 500),
    isDel: 0,
  };
}
function searchMessages(params, extraEmail) {
  params = params || {};
  const conds = [], vals = [];
  const like = (field, v) => { if (v) { conds.push(`${field} LIKE ? ESCAPE '\\'`); vals.push(`%${escLike(v)}%`); } };
  like("email", extraEmail || params.toEmail);
  like("sender", params.sendEmail);
  like("sender_name", params.sendName);
  like("subject", params.subject);
  if (extraEmail) { } // covered by like above
  const order = params.timeSort === "asc" ? "ts ASC" : params.timeSort === "desc" ? "ts DESC" : "ts DESC";
  let size = parseInt(params.size, 10);
  if (!Number.isFinite(size)) size = 20;
  size = Math.min(Math.max(size, 1), 100);
  let num = parseInt(params.num, 10);
  if (!Number.isFinite(num)) num = 1;
  num = Math.max(num, 1);
  const offset = (num - 1) * size;
  const sql = `SELECT rowid,* FROM messages ${conds.length ? "WHERE " + conds.join(" AND ") : ""} ORDER BY ${order} LIMIT ? OFFSET ?`;
  const rows = db.prepare(sql).all(...vals, size, offset);
  return rows.map(msgRow);
}
const DOCS = {
  name: "Mail Hub",
  description: "Cookie-based multi-Gmail inbox. Cloud-Mail compatible API + native REST.",
  auth: { public: "Authorization: <PUBLIC_TOKEN>", full: "Authorization: <API_KEY> (or X-API-Key)" },
  endpoints: [
    { path: "/api/docs", method: "GET", auth: "none", desc: "this documentation" },
    { path: "/api/login", method: "POST", auth: "none", params: { password: "page password" }, returns: { token: "API_KEY" } },
    { path: "/api/public/genToken", method: "POST", auth: "public", params: {}, returns: { token: "public token" } },
    { path: "/api/public/emailList", method: "POST", auth: "public", params: { toEmail: "account email LIKE", sendEmail: "sender LIKE", sendName: "sender name LIKE", subject: "subject LIKE", num: "page (1-based)", size: "page size (default 20)", timeSort: "asc|desc" }, returns: "[email rows]" },
    { path: "/api/email/list", method: "POST", auth: "full", params: { accountEmail: "restrict to account", "same as emailList": true }, returns: "[email rows]" },
    { path: "/api/email/latest", method: "POST", auth: "full", params: { accountEmail: "", size: "default 20" }, returns: "[latest email rows]" },
    { path: "/api/email/read", method: "POST", auth: "full", params: { emailId: "rowid" }, returns: "ok (no-op, read state not tracked)" },
    { path: "/api/allEmail/list", method: "POST", auth: "full", params: { num: "page", size: "page size", timeSort: "asc|desc" }, returns: "[email rows across all accounts]" },
    { path: "/api/accounts", method: "GET", auth: "full", desc: "native REST" },
    { path: "/api/accounts/<email>/messages", method: "GET", auth: "full", desc: "native REST threads" },
    { path: "/api/accounts/<email>/messages/<thread_id>", method: "GET", auth: "full", desc: "native REST thread detail" },
  ],
  emailRow: { emailId: "msg rowid", sendEmail: "sender", sendName: "sender name", subject: "subject", toEmail: "inbox account", type: 0, createTime: "epoch ms", content: "html body", text: "plain snippet", isDel: 0 },
};
// dynamic base URL: honors X-Forwarded-Proto/Host (behind tunnel/proxy) else the request host
function requestBaseUrl(req) {
  let proto = (req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  if (proto !== "http" && proto !== "https") proto = "http";
  const host = validHost(req.headers["x-forwarded-host"]) || validHost(req.headers["host"]) || "";
  return host ? `${proto}://${host}` : "";
}
async function cloudApi(p, req, res, url) {
  const cip = clientIp(req);
  const auth = req.headers["authorization"] || "";
  const authed = safeEq(auth, API_KEY) || safeEq(req.headers["x-api-key"], API_KEY) || authPage(req, res);
  const pubOk = safeEq(auth, PUBLIC_TOKEN);
  const baseUrl = requestBaseUrl(req);
  const OPENAPI = {
    openapi: "3.0.3",
    info: { title: "Mail Hub", version: "1.0.0", description: `Cookie-based multi-Gmail inbox. Native REST + cloud-mail compatible wrapper. Base URL: ${baseUrl}` },
    servers: [{ url: baseUrl }],
    security: [{ ApiKey: [] }],
    components: {
      securitySchemes: {
        ApiKey: { type: "apiKey", in: "header", name: "X-API-Key", description: "native routes" },
        AuthHeader: { type: "apiKey", in: "header", name: "Authorization", description: "cloud routes / public token" },
      },
      schemas: {
        Error: { type: "object", properties: { error: { type: "string" } }, required: ["error"] },
        CloudError: { type: "object", properties: { code: { type: "integer" }, message: { type: "string" } }, required: ["code", "message"] },
        Account: { type: "object", properties: { email: { type: "string" }, last_sync: { type: "integer", description: "epoch ms" }, last_error: { type: ["string", "null"] } } },
        Thread: { type: "object", properties: { thread_id: { type: "string" }, email: { type: "string" }, ts: { type: "integer" }, subject: { type: "string" }, snippet: { type: "string" }, sender: { type: "string" } } },
        Message: { type: "object", properties: { msg_id: { type: "string" }, email: { type: "string" }, thread_id: { type: "string" }, ts: { type: "integer" }, subject: { type: "string" }, sender: { type: "string" }, sender_name: { type: "string" }, recipients: { type: "string" }, body_html: { type: "string" } } },
        EmailRow: { type: "object", properties: { emailId: { type: "integer" }, sendEmail: { type: "string" }, sendName: { type: "string" }, subject: { type: "string" }, toEmail: { type: "string" }, type: { type: "integer" }, createTime: { type: "integer" }, content: { type: "string" }, text: { type: "string" }, isDel: { type: "integer" } } },
        SearchParams: { type: "object", properties: { toEmail: { type: "string" }, sendEmail: { type: "string" }, subject: { type: "string" }, accountEmail: { type: "string" }, num: { type: "integer", default: 1 }, size: { type: "integer", default: 20 }, timeSort: { type: "string", enum: ["asc", "desc"] } } },
      },
    },
    paths: {
      "/login": { post: { summary: "Page password login", security: [], requestBody: { content: { "application/json": { schema: { type: "object", properties: { password: { type: "string" } } } } } }, responses: { "200": { description: "sets session cookie" }, "401": { $ref: "#/components/schemas/Error" } } } },
      "/api/accounts": { get: { summary: "List accounts", security: [{ ApiKey: [] }], responses: { "200": { description: "array of Account", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Account" } } } } } } } },
      "/api/accounts/{email}/messages": { get: { summary: "Thread list", security: [{ ApiKey: [] }], parameters: [{ name: "email", in: "path", required: true, schema: { type: "string" } }, { name: "limit", in: "query", schema: { type: "integer", default: 50 } }], responses: { "200": { description: "array of Thread", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Thread" } } } } } } } },
      "/api/accounts/{email}/messages/{thread_id}": { get: { summary: "Thread detail", security: [{ ApiKey: [] }], parameters: [{ name: "email", in: "path", required: true, schema: { type: "string" } }, { name: "thread_id", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "array of Message", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Message" } } } } } } } },
      "/api/accounts/{email}/messages/refresh": { post: { summary: "Force sync", security: [{ ApiKey: [] }], parameters: [{ name: "email", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "ok" } } } },
      "/api/sse": { get: { summary: "SSE events stream", security: [{ ApiKey: [] }], responses: { "200": { description: "text/event-stream: update | new" } } } },
      "/api/login": { post: { summary: "API key exchange", security: [], requestBody: { content: { "application/json": { schema: { type: "object", properties: { password: { type: "string" } } } } } }, responses: { "200": { description: "cloud envelope {code,message,data:{token}}" }, "401": { $ref: "#/components/schemas/CloudError" } } } },
      "/api/public/emailList": { post: { summary: "Public mail search", security: [{ AuthHeader: [] }], requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/SearchParams" } } } }, responses: { "200": { description: "cloud envelope data: [EmailRow]" }, "401": { $ref: "#/components/schemas/CloudError" } } } },
      "/api/public/genToken": { post: { summary: "Return public token", security: [{ AuthHeader: [] }], responses: { "200": { description: "cloud envelope data: {token}" } } } },
      "/api/email/list": { post: { summary: "Full mail search", security: [{ AuthHeader: [] }, { ApiKey: [] }], requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/SearchParams" } } } }, responses: { "200": { description: "cloud envelope data: [EmailRow]" } } } },
      "/api/email/latest": { post: { summary: "Latest messages", security: [{ AuthHeader: [] }, { ApiKey: [] }], requestBody: { content: { "application/json": { schema: { type: "object", properties: { accountEmail: { type: "string" }, size: { type: "integer", default: 20 } } } } } }, responses: { "200": { description: "cloud envelope data: [EmailRow]" } } } },
      "/api/email/read": { post: { summary: "Ack (no-op)", security: [{ AuthHeader: [] }], responses: { "200": { description: "cloud ok" } } } },
      "/api/email/delete": { post: { summary: "Unsupported", security: [{ AuthHeader: [] }], responses: { "501": { description: "cloud not supported" } } } },
      "/api/allEmail/list": { post: { summary: "Search all accounts", security: [{ AuthHeader: [] }, { ApiKey: [] }], requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/SearchParams" } } } }, responses: { "200": { description: "cloud envelope data: [EmailRow]" } } } },
      "/api/docs": { get: { summary: "Endpoint list", security: [{ AuthHeader: [] }], responses: { "200": { description: "JSON docs" } } } },
      "/api/openapi": { get: { summary: "This spec", security: [{ AuthHeader: [] }], responses: { "200": { description: "OpenAPI 3.0.3 JSON" } } } },
    },
  };
  if (p === "/api/docs") {
    if (!authed) { failAuth(cip); json(res, 401, cloudFail("authExpired", 401)); return true; }
    okAuth(cip); json(res, 200, DOCS); return true;
  }
  if (p === "/api/openapi") {
    if (!authed) { failAuth(cip); json(res, 401, cloudFail("authExpired", 401)); return true; }
    okAuth(cip); json(res, 200, OPENAPI); return true;
  }
  if (p === "/api/login" && req.method === "POST") {
    const b = await cloudBody(req, res); if (!b) return true;
    if (safeEq(b.password, PASSWORD)) { okAuth(cip); json(res, 200, cloudOk({ token: API_KEY })); }
    else { failAuth(cip); json(res, 401, cloudFail("bad password", 401)); }
    return true;
  }
  if (p === "/api/register" && req.method === "POST") { json(res, 501, cloudFail("not supported", 501)); return true; }
  if (p.startsWith("/api/public/")) {
    if (!pubOk) { failAuth(cip); json(res, 401, cloudFail("publicTokenFail", 401)); return true; }
    okAuth(cip);
    if (p === "/api/public/genToken" && req.method === "POST") { json(res, 200, cloudOk({ token: PUBLIC_TOKEN })); return true; }
    if (p === "/api/public/emailList" && req.method === "POST") { const b = await cloudBody(req, res); if (!b) return true; if (b.toEmail || b.accountEmail) maybeRefresh(b.toEmail || b.accountEmail); json(res, 200, cloudOk(searchMessages(b))); return true; }
    json(res, 404, cloudFail("not found", 404)); return true;
  }
  if (p.startsWith("/api/email/") || p.startsWith("/api/account/") || p.startsWith("/api/allEmail/")) {
    if (!authed) { failAuth(cip); json(res, 401, cloudFail("authExpired", 401)); return true; }
    okAuth(cip);
    if (p === "/api/email/list" && req.method === "POST") { const b = await cloudBody(req, res); if (!b) return true; if (b.accountEmail) maybeRefresh(b.accountEmail); json(res, 200, cloudOk(searchMessages(b, b.accountEmail))); return true; }
    if (p === "/api/email/latest" && req.method === "POST") { const b = await cloudBody(req, res); if (!b) return true; json(res, 200, cloudOk(searchMessages({ ...b, num: 1, size: b.size || 20 }))); return true; }
    if (p === "/api/email/read" && req.method === "POST") { const b = await cloudBody(req, res); if (!b) return true; json(res, 200, cloudOk(null)); return true; }
    if (p === "/api/email/delete" && req.method === "POST") { const b = await cloudBody(req, res); if (!b) return true; json(res, 501, cloudFail("not supported", 501)); return true; }
    if (p === "/api/allEmail/list" && req.method === "POST") { const b = await cloudBody(req, res); if (!b) return true; if (b.toEmail || b.accountEmail) maybeRefresh(b.toEmail || b.accountEmail); else maybeRefreshAll(); json(res, 200, cloudOk(searchMessages(b))); return true; }
    json(res, 404, cloudFail("not found", 404)); return true;
  }
  return false;
}

const server = http.createServer(async (req, res) => {
  try {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;

  // ---- brute-force guard: /login and /api/login ----
  const ip = clientIp(req);
  const blocked = isBlocked(ip);
  if (blocked) return json(res, 429, { error: "too many attempts; blocked", retryAfter: blocked });
  const cl = parseInt(req.headers["content-length"] || "0", 10);
  if (cl > MAX_BODY) return json(res, 413, { error: "payload too large" });

  if (p === "/api/sse") {
    if (!authPage(req, res)) { failAuth(ip); return json(res, 401, { error: "auth" }); }
    okAuth(ip);
    res.writeHead(200, { ...SEC_HDR, "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
    sseAttach(res, req);
    res.write("retry: 10000\n\n");
    return;
  }

  if (p === "/login" && req.method === "POST") {
    const b = await readBody(req, true);
    if (b.__too) return json(res, 413, { error: "payload too large" });
    if (b.__bad) { failAuth(ip); return json(res, 400, { error: "json" }); }
    if (safeEq(b.password, PASSWORD)) { const t = signSessionToken(); recordSession(t, ip); okAuth(ip); res.writeHead(200, { ...SEC_HDR, "Content-Type": "application/json", "Cache-Control": "no-store", "Set-Cookie": sessSetCookie(req, t) }); res.end(JSON.stringify({ apiKey: API_KEY, publicToken: PUBLIC_TOKEN })); }
    else { failAuth(ip); json(res, 401, { error: "bad password" }); }
    return;
  }

    // docs: same login gate as the app — one password unlocks mail AND docs
  if (p === "/docs" && req.method === "GET") {
    if (!authPage(req, res)) return res.writeHead(302, { ...SEC_HDR, Location: "/login.html?next=/docs" }).end();
    const tpl = readFileSync(join(ROOT, "public", "docs.html"), "utf8");
    // inject real secrets into a JS global (NOT the visible HTML) so they can be
    // revealed on demand and rotated, but never appear in a screenshot/page view.
    const creds = JSON.stringify({ apiKey: API_KEY, publicToken: PUBLIC_TOKEN }).replace(/</g, "\\u003c");
    const baseUrl = requestBaseUrl(req);
    const html = tpl
      .replaceAll("__API_KEY__", "••••••••••••••••")
      .replaceAll("__PUBLIC_TOKEN__", "••••••••••••••••")
      .replaceAll("__BASE_URL__", baseUrl)
      .replace("<!--CREDS-->", `<script>window.__CREDS__=${creds};</script>`);
    res.writeHead(200, { ...SEC_HDR, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(html);
    return;
  }
  if (p === "/docs/auth" && req.method === "POST") {
    // shared login: same password as the mail app, sets the same gsess cookie
    const b = await readBody(req, true);
    if (b.__bad || b.__too) return json(res, b.__too ? 413 : 400, { error: b.__too ? "payload too large" : "bad json" });
    if (b.password === PASSWORD) {
      const t = signSessionToken();
      recordSession(t, ip);
      okAuth(ip);
      res.writeHead(200, { ...SEC_HDR, "Content-Type": "application/json", "Cache-Control": "no-store", "Set-Cookie": sessSetCookie(req, t) });
      res.end(JSON.stringify({ ok: true }));
    } else { failAuth(ip); json(res, 401, { error: "bad password" }); }
    return;
  }
  if (p.startsWith("/api/")) {
    if (await cloudApi(p, req, res, url)) return;
    if (req.headers["x-api-key"] !== API_KEY && !authPage(req, res)) { failAuth(ip); return json(res, 401, { error: "auth" }); }
    okAuth(ip);
    const parts = p.split("/").filter(Boolean).slice(1); // accounts, email, messages, id
    // web session info: expiry from the signed gsess token
    if (p === "/api/session" && req.method === "GET") {
      const cur = getSessToken(req);
      let expiry = null, valid = false, token_fp = null;
      if (cur) {
        const ps = parseSess(cur);
        if (ps) expiry = ps.expMs;
        valid = verifySessionToken(cur);
        if (valid) touchSession(cur);
        token_fp = sessHash(cur).slice(0, 16);
      }
      return json(res, 200, { valid, expiry, token_fp, maxAge: 7 * 864e5 });
    }
    // list all logged-in web sessions across browsers/devices
    if (p === "/api/sessions" && req.method === "GET") {
      pruneSessions();
      const c = (req.headers.cookie || "").match(/(?:__Host-)?gsess=([A-Za-z0-9_.-]+)/);
      const curTok = c ? c[1] : null;
      const list = listSessions().map((s) => ({
        id: s.id,
        current: !!curTok && (s.token_hash === sessHash(curTok) || s.token_hash === curTok),
        created: s.created,
        expiry: s.expiry,
        ip: s.ip,
        last_seen: s.last_seen,
      }));
      return json(res, 200, list);
    }
    // revoke a session by id (only self-revoke allowed unless it's via the same cookie)
    if (p === "/api/session/revoke" && req.method === "POST") {
      if (!authedViaKey(req) && !csrfOriginOk(req)) return json(res, 403, { error: "csrf" });
      const b = await readBody(req, true);
      if (b.__too) return json(res, 413, { error: "payload too large" });
      if (b.__bad) return json(res, 400, { error: "bad json" });
      const rid = Number(b.id);
      if (!authedViaKey(req)) {
        const cur = getSessToken(req);
        if (!cur) return json(res, 403, { error: "forbidden" });
        const ch = sessHash(cur);
        let row = null;
        try { row = db.prepare("SELECT token_hash FROM web_sessions WHERE id=?").get(rid); } catch {}
        if (!row) return json(res, 404, { error: "not found" });
        if (row.token_hash !== ch && row.token_hash !== cur) return json(res, 403, { error: "forbidden" });
      }
      const ok = revokeSessionById(rid);
      return json(res, ok ? 200 : 404, ok ? { ok: true } : { error: "not found" });
    }
    if (p === "/api/accounts" && req.method === "GET") {
      const accts = LIST_ACCOUNTS.all().map((a) => {
        // session expiry = earliest expiry among session cookies in the cookie file
        let sessionExpiry = null;
        try {
          const c = JSON.parse(readFileSync(join(COOKIE_DIR, a.cookie_file), "utf8"));
          const sess = c.filter((x) => ["SID", "SSID", "__Secure-1PSID"].includes(x.name) && x.expires);
          if (sess.length) sessionExpiry = Math.min(...sess.map((x) => +x.expires * 1000));
        } catch {}
        return { email: a.email, cookie_file: a.cookie_file, last_sync: a.last_sync, last_error: a.last_error, session_expiry: sessionExpiry };
      });
      return json(res, 200, accts);
    }
    if (parts.length >= 4 && parts[0] === "accounts" && parts[2] === "messages" && req.method === "GET") {
      const email = decodeURIComponent(parts[1]), tid = decodeURIComponent(parts[3]);
      maybeRefresh(email);
      backfillBodies(email).catch(() => {});
      let msgs = MSGS_BY_THREAD.all(email, tid);
      // if any stored message lacks a body, fetch it live from Gmail (atom entries have no body)
      const needBody = msgs.some((m) => !m.body_html);
      if (needBody) {
        try {
          const live = await fetchThreadBody(email, tid);
          if (live.length) {
            // merge by msg_id OR thread_id (atom ids differ from simls msg-f ids)
            for (const lm of live) {
              if (!lm.body_html) continue;
              let existing = msgs.find((m) => m.msg_id === lm.msg_id);
              if (!existing) existing = msgs.find((m) => m.thread_id === lm.thread_id || (m.msg_id && lm.thread_id && String(m.msg_id).replace("msg-f:", "") === String(lm.thread_id).replace("thread-f:", "").split(":")[0]));
              if (existing) { existing.body_html = lm.body_html; if (!existing.sender && lm.sender) { existing.sender = lm.sender; existing.sender_name = lm.sender_name; } }
              else msgs.push(lm);
            }
            // persist fetched bodies to ALL messages of this thread that lack one
            const body = live.find((l) => l.body_html);
            if (body) {
              for (const m of msgs) {
                if (!m.body_html && m.thread_id) { m.body_html = body.body_html; if (!m.sender && body.sender) { m.sender = body.sender; m.sender_name = body.sender_name; } }
                if (m.msg_id && m.body_html) try { UPSERT_MSG.run(m.msg_id, email, tid, m.ts || 0, m.subject || "", m.sender || "", m.sender_name || "", m.recipients || "", m.body_html); } catch {}
              }
            }
          }
        } catch (e) { /* body fetch failed — return what we have */ }
      }
      return json(res, 200, msgs);
    }
    if (parts.length >= 3 && parts[0] === "accounts" && parts[2] === "messages") {
      const email = decodeURIComponent(parts[1]);
      const limit = +(url.searchParams.get("limit") || 50), offset = +(url.searchParams.get("offset") || 0);
      if (req.method === "GET") { maybeRefresh(email); return json(res, 200, RECENT.all(email, limit, offset)); }
      if (req.method === "POST" && parts.length === 4 && parts[3] === "refresh") {
        if (!authedViaKey(req) && !csrfOriginOk(req)) return json(res, 403, { error: "csrf" });
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(res, 400, { error: "bad email" });
        const now = Date.now();
        const last = REFRESH_LAST.get(email) || 0;
        if (now - last < 60000) return json(res, 429, { error: "throttle", retryAfter: Math.ceil((60000 - (now - last)) / 1000) });
        REFRESH_LAST.set(email, now);
        syncAccount(email).then(() => json(res, 200, { ok: 1 })).catch((e) => json(res, 502, { error: String(e.message || e) })); if (SPAM_ENABLED) spamSync([email]); return;
      }
    }
    if (p === "/api/select" && req.method === "POST") {
      if (!authedViaKey(req) && !csrfOriginOk(req)) return json(res, 403, { error: "csrf" });
      const b = await readBody(req, false);
      if (!b || b.__bad || b.__too) return json(res, 400, { error: "json" });
      return json(res, 200, { ok: 1, selected: selectAccount(b.email) });
    }
    if (p === "/api/selected" && req.method === "GET") return json(res, 200, { selected: SELECTED });
    // rotate API key: requires a valid full auth (session cookie or current X-API-Key). Returns the new key.
    if (p === "/api/rotate" && req.method === "POST") {
      if (!authedViaKey(req) && !csrfOriginOk(req)) return json(res, 403, { error: "csrf" });
      const b = await readBody(req, true);
      if (b.__too) return json(res, 413, { error: "payload too large" });
      if (b.__bad) return json(res, 400, { error: "bad json" });
      if (b.password !== PASSWORD) { failAuth(ip); return json(res, 401, { error: "bad password" }); }
      okAuth(ip);
      const newKey = "mh_live_" + crypto.randomBytes(32).toString("hex");
      db.prepare("UPDATE settings SET value=?, updated_at=? WHERE key='api_key'").run(newKey, Date.now());
      API_KEY = newKey; // live-update this process
      console.log("[gmail-inbox] API key rotated");
      return json(res, 200, cloudOk({ apiKey: API_KEY }));
    }
    return json(res, 404, { error: "nf" });
  }

  if (p === "/" || p === "/index.html") {
    if (!authPage(req, res)) return res.writeHead(302, { Location: "/login.html" }).end();
    return serveFile(res, join(ROOT, "public", "index.html"));
  }
  if (p === "/login.html") return serveFile(res, join(ROOT, "public", "login.html"));
  if (p.startsWith("/static/")) {
    if (!authPage(req, res)) { failAuth(ip); return json(res, 401, { error: "auth" }); }
    okAuth(ip);
    return serveFile(res, join(ROOT, "public", p.slice(1)));
  }
  if (p === "/logout") { res.writeHead(302, { ...SEC_HDR, Location: "/login.html", "Set-Cookie": ["gsess=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0", "__Host-gsess=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"] }).end(); return; }
  json(res, 404, { error: "nf" });
  } catch (e) {
    if (!res.headersSent) json(res, 500, { error: "internal" });
    else { try { res.end(); } catch {} }
  }
});

function serveFile(res, path) {
  const real = resolve(path);
  if (!real.startsWith(join(ROOT, "public"))) return json(res, 403, { error: "forbidden" });
  if (!existsSync(real)) return json(res, 404, { error: "nf" });
  const ext = real.split(".").pop();
  const type = { html: "text/html", js: "application/javascript", css: "text/css" }[ext] || "text/plain";
  // HTML: always fresh (inline CSS/JS) so edits show immediately; assets: short cache
  const cache = ext === "html" ? "no-cache, no-store, must-revalidate" : "public, max-age=300";
  res.writeHead(200, { "Content-Type": type, "Cache-Control": cache, ...SEC_HDR });
  res.end(readFileSync(real));
}

server.listen(PORT, HOST, () => console.log(`[gmail-inbox] http://${HOST}:${PORT}`));
if (!SPAM_ENABLED) console.log("[gmail-inbox] spam-sync disabled (set SPAM_SYNC=1 to enable)");
// spam sweep: 60s after startup (let account syncs settle), then hourly — only when SPAM_SYNC=1
if (SPAM_ENABLED) setTimeout(() => spamSync(), 60_000);
setInterval(() => { if (SPAM_ENABLED) spamSync(); }, SPAM_SYNC_MINUTES * 60_000);