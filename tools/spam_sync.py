#!/usr/bin/env python3
"""mailg spam sync via Playwright full Gmail UI (basic HTML /h/ ignores queries).
Scrapes #spam conversation list → writes to inbox.db (label-tagged subjects).
Usage: python3 tools/spam_sync.py [email]   (no arg = all accounts)"""
import os, re, json, sys, time, sqlite3
import datetime as _dt, builtins as _bi  # timestamped stdout (UTC HH:MM:SS)
_op = _bi.print
def print(*a, **k):
    _op(f"[{_dt.datetime.now(_dt.timezone.utc).strftime('%H:%M:%S')}]", *a, **{**k, "flush": True})
os.environ.setdefault("DISPLAY", ":99")
ROOT = "/root/projects/gmail-inbox"
DB = f"{ROOT}/inbox.db"

def sync_spam(email, pw, cf):
    from playwright.sync_api import sync_playwright
    raw = json.loads(open(cf).read())
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path="/usr/bin/google-chrome",
                              headless=True, args=["--no-sandbox", "--disable-gpu"])
        ctx = b.new_context(viewport={"width": 1280, "height": 900}, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/138.0.0.0 Safari/537.36")
        # inject cookies
        ck = [{"name": c["name"], "value": c["value"], "domain": c["domain"],
               "path": c.get("path", "/"), "secure": bool(c.get("secure", True)),
               "httpOnly": bool(c.get("httpOnly", False))} for c in raw
              if "google" in c.get("domain", "")]
        ctx.add_cookies(ck)
        pg = ctx.new_page()
        try:
            pg.goto("https://mail.google.com/mail/u/0/#spam", wait_until="domcontentloaded", timeout=45000)
            time.sleep(6)
            # logged in?
            body = pg.inner_text("body")[:300]
            if "Sign in" in body or "gaia_loginform" in body:
                print(f"  ⛔ session expired for {email}")
                b.close(); return 0
            # wait for spam table
            for _ in range(10):
                if pg.locator("table.cf.tB tr, tr.zA").count(): break
                time.sleep(2)
            rows = pg.evaluate("""() => {
                const out = [];
                for (const tr of document.querySelectorAll('tr.zA')) {
                    const a = tr.querySelector('span.bA4, span.yP, span[email]');
                    const subj = tr.querySelector('span.bog');
                    const tid = tr.getAttribute('data-legacy-thread-id') || (tr.querySelector('a') ? tr.querySelector('a').href : '');
                    const dt = tr.querySelector('td.xW span');
                    out.push({
                        subject: subj ? subj.innerText : '',
                        sender: a ? (a.getAttribute('email') || a.innerText) : '',
                        sender_name: a ? a.innerText : '',
                        link: tid,
                        date: dt ? dt.getAttribute('title') || dt.innerText : ''
                    });
                }
                return out;
            }""")
            n = 0
            db = sqlite3.connect(DB)
            for r in rows:
                tid = ""
                m = re.search(r"th=([a-f0-9]+)", r.get("link") or "")
                if m: tid = m.group(1)
                if not r["subject"]: continue
                db.execute("""INSERT INTO threads(thread_id,email,ts,subject,snippet) VALUES(?,?,?,?,?)
                              ON CONFLICT(email,thread_id) DO UPDATE SET subject=excluded.subject""",
                           (tid or f"spam-{hash(r['subject'])&0xffffffffffff}", email, int(time.time()*1000),
                            "[SPAM] " + r["subject"], r.get("date", "")))
                n += 1
            db.commit()
            print(f"  ✅ {email}: {n} spam convs scraped")
            return n
        except Exception as e:
            print(f"  ⛔ {email}: {str(e)[:80]}")
            return 0
        finally:
            b.close()

def main():
    db = sqlite3.connect(DB)
    if len(sys.argv) > 1:
        emails = [sys.argv[1]]
    else:
        emails = [r[0] for r in db.execute("SELECT email FROM accounts").fetchall()]
    from pathlib import Path
    total = 0
    for email in emails:
        row = db.execute("SELECT cookie_file FROM accounts WHERE email=?", (email,)).fetchone()
        if not row: continue
        cf = f"{ROOT}/cookies/{row[0]}"
        if not Path(cf).exists(): continue
        print(f"=== {email} ===")
        total += sync_spam(email, None, cf) or 0
    print(f"\nTOTAL spam convs scraped: {total}")

if __name__ == "__main__":
    main()