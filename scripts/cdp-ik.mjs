// timestamped stdout (UTC HH:MM:SS on every line)
for (const _k of ["log", "error", "warn"]) { const _f = console[_k].bind(console); console[_k] = (..._a) => _f(`[${new Date().toISOString().slice(11, 19)}]`, ..._a); }
// Pull ik + confirm from the live logged-in Gmail tab via CDP
const list = await (await fetch("http://127.0.0.1:9222/json")).json();
const page = list.find((t) => t.type === "page" && /mail\.google\.com/.test(t.url)) || list.find((t) => t.type === "page");
if (!page) { console.error("no page"); process.exit(1); }
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map();
ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });

const expr = `(() => {
  const out = { title: document.title, url: location.href };
  try {
    const res = performance.getEntriesByType('resource')
      .map(e => e.name)
      .filter(n => /\\/mail\\/u\\/\\d+\\/data/.test(n));
    out.dataUrls = res.slice(0, 5);
    const ikM = res.map(n => n.match(/[?&]ik=([A-Za-z0-9_-]+)/)).filter(Boolean).map(m => m[1]);
    out.ik = [...new Set(ikM)].slice(0, 3);
  } catch (e) { out.err = String(e); }
  return JSON.stringify(out);
})()`;
const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true });
console.log(r.result?.result?.value || JSON.stringify(r));
process.exit(0);