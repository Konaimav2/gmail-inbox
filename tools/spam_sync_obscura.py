#!/usr/bin/env python3
"""spam_sync_obscura — Obscura-backed variant of tools/spam_sync.py.
Same DB writes ([SPAM] threads) but the browser is Obscura via CDP (stealth + 30MB).

Usage: python3 tools/spam_sync_obscura.py [email]
Env:   OBSCURA_URL (default http://127.0.0.1:9222)
"""
import os, re, sys, time, sqlite3
import datetime as _dt, builtins as _bi  # timestamped stdout (UTC HH:MM:SS)
_op = _bi.print
def print(*a, **k):
    _op(f"[{_dt.datetime.now(_dt.timezone.utc).strftime('%H:%M:%S')}]", *a, **{**k, "flush": True})
ROOT = "/root/projects/gmail-inbox"
DB = f"{ROOT}/inbox.db"
OBSCURA_URL = os.environ.get("OBSCURA_URL", "http://127.0.0.1:9222")

def _log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

def main():
    db = sqlite3.connect(DB)
    emails = sys.argv[1:] or [r[0] for r in db.execute("SELECT email FROM accounts ORDER BY email").fetchall()]
    from playwright.sync_api import sync_playwright
    total = 0
    with sync_playwright() as p:
        b = p.chromium.connect_over_cdp(OBSCURA_URL)
        ctx = b.contexts[0] if b.contexts else b.new_context()
        for email in emails:
            row = db.execute("SELECT cookie_file FROM accounts WHERE email=?", (email,)).fetchone()
            if not row: continue
            cf = f"{ROOT}/cookies/{row[0]}"
            if not os.path.exists(cf): continue
            raw = json.load(open(cf))
            ck = [{"name": c["name"], "value": c["value"], "domain": c["domain"],
                   "path": c.get("path", "/"), "secure": bool(c.get("secure", True)),
                   "httpOnly": bool(c.get("httpOnly", False))}
                  for c in raw if "google" in c.get("domain", "")]
            try: ctx.clear_cookies()
            except Exception: pass
            ctx.add_cookies(ck)
            pg = ctx.new_page()
            try:
                _log(f"{email}: opening #spam")
                pg.goto("https://mail.google.com/mail/u/0/#spam", timeout=40000)
                time.sleep(6)
                rows = pg.evaluate("""() => {
                    const out = [];
                    for (const tr of document.querySelectorAll('tr.zA')) {
                        const a = tr.querySelector('span.yP, span[email]');
                        const subj = tr.querySelector('span.bog');
                        const link = tr.querySelector('a') ? tr.querySelector('a').href : '';
                        out.push({subject: subj ? subj.innerText : '',
                                  sender: a ? (a.getAttribute('email') || a.innerText) : '',
                                  link});
                    }
                    return out;
                }""")
                n = 0
                for r in rows:
                    if not r["subject"]: continue
                    m = re.search(r"th=([a-f0-9]+)", r.get("link") or "")
                    tid = m.group(1) if m else f"spam-{abs(hash(r['subject']))&0xffffffffffff}"
                    db.execute("""INSERT INTO threads(thread_id,email,ts,subject,snippet)
                                  VALUES(?,?,?,?,?)
                                  ON CONFLICT(email,thread_id) DO UPDATE SET subject=excluded.subject""",
                               (tid, email, int(time.time()*1000), "[SPAM] " + r["subject"], ""))
                    n += 1
                db.commit()
                _log(f"{email}: {n} spam convs")
                total += n
            except Exception as e:
                _log(f"{email}: ERROR {str(e)[:70]}")
            finally:
                try: pg.close()
                except Exception: pass
    _log(f"TOTAL: {total} spam convs (Obscura)")

if __name__ == "__main__":
    import json
    main()