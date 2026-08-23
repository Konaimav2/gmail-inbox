// extract-session: dump cookies from the live Chrome session (manual login done in VNC)
// and move the account into loggedmail.txt so the batch skips it.
// Usage: node scripts/extract-session.mjs [email]
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const COOKIE_DIR = join(ROOT, "cookies");
const LIST_FILE = join(ROOT, "list.txt");
const LOGGED_FILE = join(ROOT, "loggedmail.txt");
const CDP = "http://127.0.0.1:9222";

const targets = await (await fetch(`${CDP}/json`)).json();
const page = targets.find((t) => t.type === "page" && /^https?:/.test(t.url)) || targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map();
ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const evalJs = (expression) => send("Runtime.evaluate", { expression, returnByValue: true }).then((r) => r.result?.result?.value);

const title = (await evalJs("document.title")) || "";
const url = page.url || "";
const m = (title + " " + url).match(/([\w.+-]+@[\w.-]+)/);
const email = process.argv[2] || (m ? m[1] : "");
if (!email) { console.log("no email found; pass it: node scripts/extract-session.mjs <email>"); process.exit(1); }

// sanity: real session cookies present?
const { result } = await send("Network.getAllCookies");
const g = (result?.cookies || []).filter((c) => c.domain.includes("google.com"));
const hasSess = g.some((c) => /(^|_)(SID|SSID)$/.test(c.name) && c.value.length > 20);
if (!hasSess) { console.log("no valid Google session cookies yet — finish login in VNC first"); process.exit(2); }

const fname = join(COOKIE_DIR, email.replace(/[@.]/g, "_") + ".json");
writeFileSync(fname, JSON.stringify(g, null, 2));
console.log("cookies saved:", fname, "(" + g.length + " cookies)");

// append to loggedmail (skip if present), remove from failed
let logged = existsSync(LOGGED_FILE) ? readFileSync(LOGGED_FILE, "utf8") : "";
if (!logged.split("\n").some((l) => l.startsWith(email + "|"))) {
  const list = existsSync(LIST_FILE) ? readFileSync(LIST_FILE, "utf8") : "";
  const line = list.split("\n").find((l) => l.startsWith(email + "|"));
  const pw = line ? line.split("|")[1] || "" : "";
  logged += `${email}|${pw}|\n`;
  writeFileSync(LOGGED_FILE, logged);
  console.log("moved to loggedmail.txt");
}
const failed = join(ROOT, "failed.txt");
if (existsSync(failed)) {
  const f = readFileSync(failed, "utf8").split("\n").filter((l) => !l.startsWith(email + "|")).join("\n");
  writeFileSync(failed, f);
}
console.log("done. restart server to pick up: pm2 restart gmail-inbox");
process.exit(0);