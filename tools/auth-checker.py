#!/usr/bin/env python3
"""auth-checker — Google re-verification / blocked-by-reverify detector.
Checks mailg sessions (cookies) by actually opening Gmail via Playwright using the
saved cookies. Result is the TRUE Google auth state (not just cookie file exists).

Blocked signals:
  - "Verify it's you" challenge / "check your phone" / "g.co/sc"
  - "Confirm you’re not a robot" / "suspicious activity"
  - Redirects to https://accounts.google.com/signin/challenge/*  (account locked)
  - missing Gmail inbox (simls payload absent) -> soft-fail = needs re-login

Usage:
  python3 tools/auth-checker.py              # all loggedmail (via inbox.db accounts)
  python3 tools/auth-checker.py --all        # all loggedmail
  python3 tools/auth-checker.py you@gmail.com
  python3 tools/auth-checker.py --fix        # re-run run-batch for blocked
"""
import json, time, sys, glob, re
import datetime as _dt, builtins as _bi  # timestamped stdout (UTC HH:MM:SS)
_op = _bi.print
def print(*a, **k):
    _op(f"[{_dt.datetime.now(_dt.timezone.utc).strftime('%H:%M:%S')}]", *a, **{**k, "flush": True})
from pathlib import Path

ROOT = Path("/root/projects/gmail-inbox")
COOKIE_DIR = ROOT / "cookies"
SECRETS = ROOT / ".2fa-secrets"

def load_done():
    p = ROOT / "loggedmail.txt"
    if not p.exists(): return {}
    out = {}
    for l in p.read_text().splitlines():
        if not l.strip() or "|" not in l: continue
        parts = l.strip().split("|")
        email = parts[0].lower()
        out[email] = [p.strip() for p in parts]
    return out

def cookie_for(email):
    import sqlite3
    try:
        db = sqlite3.connect(str(ROOT / "inbox.db"))
        cur = db.execute("SELECT cookie_file FROM accounts WHERE email=?", (email,))
        row = cur.fetchone()
        if row: return COOKIE_DIR / row[0]
    except Exception as _e: print(f"[swallow auth-checker.py:43] {_e}")
    return COOKIE_DIR / (email.replace("@","_").replace(".","_") + ".json")

def check_one(email, raw_cookies):
    """Returns (state, reason). state in ok/challenge/blocked/missing."""
    from playwright.sync_api import sync_playwright
    g_cookies = []
    for c in raw_cookies:
        dom = c.get("domain","")
        if "google.com" not in dom and "youtube.com" not in dom: continue
        g_cookies.append({"name":c["name"],"value":c["value"],"domain":dom,"path":c.get("path","/"),"secure":bool(c.get("secure",True)),"httpOnly":bool(c.get("httpOnly",False)),"sameSite":c.get("sameSite","Lax")})
    if not g_cookies:
        return ("missing","no google cookies in file")

    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path="/usr/bin/google-chrome", headless=True, args=["--no-sandbox","--disable-gpu"])
        ctx = b.new_context()
        pg = ctx.new_page()
        ctx.add_cookies(g_cookies)
        try:
            # Gmail h/ — simls present = ok
            pg.goto("https://mail.google.com/mail/u/0/h/?v=m&s=q&q=newer_than%3A7d", wait_until="domcontentloaded", timeout=25000)
            time.sleep(4)
            url = pg.url or ""
            body = (pg.inner_text("body", timeout=5000) or "")[:400] if pg.url else ""
            text = (url + " " + body).lower()
            if "challenge" in url or "verify" in text and "phone" in text or "confirm you" in text:
                return ("challenge", url[:120])
            if "suspicious" in text or "robot" in text or "risk" in text:
                return ("blocked", body[:120])
            if "g.co/sc" in text or "get a code to sign in" in text:
                return ("challenge","g.co/sc code screen")
            if "sign in" in body.lower() and "simls" not in body.lower() and "inbox" not in body.lower():
                # redirected to login
                if "accounts.google.com" in url:
                    return ("blocked","redirected to login: " + url[:80])
            # simls payload present
            html = pg.content() or ""
            if '"simls"' in html:
                return ("ok","simls present")
            return ("blocked","no simls payload")
        except Exception as e:
            return ("blocked", str(e)[:100])
        finally:
            try: b.close()
            except Exception as _e: print(f"[swallow auth-checker.py:88] {_e}")

if __name__ == "__main__":
    done = load_done()
    emails = list(done.keys()) if "--all" not in sys.argv and len(sys.argv)<=2 or sys.argv[1:] in ([], ["--fix"]) else [a.lower() for a in sys.argv[1:] if "@" in a]
    if "--all" in sys.argv or (len(sys.argv)==1 and not emails):
        emails = list(done.keys())
    if not emails:
        if "--all" in sys.argv:
            emails = list(done.keys())
        else:
            print("usage: auth-checker.py [email] [--all] [--fix]")
            sys.exit(1)

    results = {}
    for email in emails:
        cf = cookie_for(email)
        if not cf.exists():
            results[email] = ("missing","no cookie file")
            print(f"❓ {email:40s}  MISSING  no cookie file")
            continue
        raw = json.loads(cf.read_text())
        state, reason = check_one(email, raw)
        results[email] = (state, reason)
        icon = {"ok":"✅","challenge":"⚠️","blocked":"⛔","missing":"❓"}[state]
        print(f"{icon} {email:40s}  {state.upper():10s}  {reason[:60]}")

    if "--fix" in sys.argv:
        need = [e for e,(s,_) in results.items() if s != "ok"]
        if need:
            print(f"\nRe-running run-batch for {len(need)} blocked/challenge accounts...")
            import subprocess as sp
            sp.run(["node","scripts/run-batch.mjs"] + need[:5], cwd=str(ROOT))

    print(f"\nDone: {sum(1 for s,_ in results.values() if s=='ok')}/{len(results)} OK")
