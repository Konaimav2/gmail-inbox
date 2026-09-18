#!/usr/bin/env python3
"""gcp-check — detect Google service restrictions ("Restricted access to services")
across all mailg accounts, via myaccount.google.com with saved cookies.

Checks per account (pre-mortem outcome map):
  RESTRICTED  — page shows "Restricted access to services" / "policy violations"
                (or redirects to /restrictions/)
  CLEAN       — account page loads, no restriction banner
  SESSION_DEAD — google asks sign-in (gaia_loginform / "Sign in")
  WEAK        — password re-ask (session needs re-auth)
  UNKNOWN     — timeout/layout error → screenshot /tmp/gcp_<email>.png

Usage:
  python3 tools/gcp-check.py            # all accounts
  python3 tools/gcp-check.py a@gmail.com b@gmail.com
Logs: timestamped, no silent skip. Summary table at end + /tmp/gcp_report.txt
"""
import os, re, sys, json, time, sqlite3
import datetime as _dt, builtins as _bi  # timestamped stdout (UTC HH:MM:SS)
_op = _bi.print
def print(*a, **k):
    _op(f"[{_dt.datetime.now(_dt.timezone.utc).strftime('%H:%M:%S')}]", *a, **{**k, "flush": True})
os.environ.setdefault("DISPLAY", ":99")
ROOT = "/root/projects/gmail-inbox"
DB = f"{ROOT}/inbox.db"

def _log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def check_account(ctx, email, cf):
    """Returns status string. All outcomes logged."""
    try:
        raw = json.loads(open(cf).read())
    except Exception as e:
        _log(f"  ⛔ cookie unreadable: {e}")
        return "COOKIE_ERROR"
    g = [{"name": c["name"], "value": c["value"], "domain": c["domain"],
          "path": c.get("path", "/"), "secure": bool(c.get("secure", True)),
          "httpOnly": bool(c.get("httpOnly", False))}
         for c in raw if "google" in c.get("domain", "")]
    if not g:
        _log("  ⛔ no google cookies")
        return "NO_COOKIES"
    try:
        ctx.clear_cookies()
        ctx.add_cookies(g)
    except Exception as e:
        _log(f"  ⛔ inject fail: {e}")
        return "INJECT_ERROR"
    pg = ctx.new_page()
    try:
        pg.goto("https://myaccount.google.com/", wait_until="domcontentloaded", timeout=40000)
        time.sleep(4)
        url = pg.url or ""
        body = ""
        try: body = pg.inner_text("body", timeout=8000)[:3000]
        except Exception: pass
        html = ""
        try: html = pg.content()[:400000]
        except Exception: pass
        hay = body + " " + html
        # session dead
        if "gaia_loginform" in hay or ("Sign in" in body and "Google Account" not in body):
            _log(f"  {email}: SESSION_DEAD")
            return "SESSION_DEAD"
        # password re-ask
        if re.search(r"verify.*(it's|it is) you|Verifikasi diri", body, re.I) and pg.locator('input[name="Passwd"], input[type="password"]').count():
            _log(f"  {email}: WEAK (password re-ask)")
            return "WEAK"
        # restriction banner (per user: "Restricted access to services / policy violations")
        restricted = (
            "/restrictions" in url
            or re.search(r"Restricted access to services", hay, re.I)
            or re.search(r"access was restricted due to policy violations", hay, re.I)
            or re.search(r"policy violation", hay, re.I)
            or re.search(r"Review service restriction", hay, re.I)
        )
        if restricted:
            # capture the restricted card text for evidence
            m = re.search(r"(Restricted access to services.{0,120})", body, re.I | re.S)
            _log(f"  {email}: RESTRICTED — {m.group(1)[:80] if m else 'banner present'}")
            return "RESTRICTED"
        if ("google akun" in hay.lower() or "google account" in hay.lower()
            or email.split("@")[0].lower() in hay.lower()):
            _log(f"  {email}: CLEAN")
            return "CLEAN"
        _log(f"  {email}: UNKNOWN (no banner, no account markers) — url={url[:60]}")
        try: pg.screenshot(path=f"/tmp/gcp_unknown_{email.split('@')[0]}.png", full_page=True)
        except Exception: pass
        return "UNKNOWN"
    except Exception as e:
        _log(f"  {email}: ERROR {str(e)[:80]}")
        try: pg.screenshot(path=f"/tmp/gcp_err_{email.split('@')[0]}.png", full_page=True)
        except Exception: pass
        return "ERROR"
    finally:
        try: pg.close()
        except Exception: pass

def main():
    db = sqlite3.connect(DB)
    targets = sys.argv[1:] or [r[0] for r in db.execute("SELECT email FROM accounts ORDER BY email").fetchall()]
    _log(f"gcp-check: {len(targets)} accounts")
    from playwright.sync_api import sync_playwright
    results = {}
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path="/usr/bin/google-chrome",
                              headless=True, args=["--no-sandbox", "--disable-gpu"])
        ctx = b.new_context(viewport={"width": 1280, "height": 900})
        for i, email in enumerate(targets, 1):
            row = db.execute("SELECT cookie_file FROM accounts WHERE email=?", (email,)).fetchone()
            if not row:
                _log(f"[{i}/{len(targets)}] {email}: NO_DB_ROW")
                results[email] = "NO_DB_ROW"; continue
            cf = f"{ROOT}/cookies/{row[0]}"
            if not os.path.exists(cf):
                _log(f"[{i}/{len(targets)}] {email}: NO_COOKIE_FILE")
                results[email] = "NO_COOKIE_FILE"; continue
            _log(f"[{i}/{len(targets)}] {email}")
            results[email] = check_account(ctx, email, cf)
        b.close()
    # summary
    counts = {}
    for st in results.values(): counts[st] = counts.get(st, 0) + 1
    print("\n" + "=" * 70)
    print("GCP RESTRICTION REPORT")
    print("=" * 70)
    for email in sorted(results):
        marker = "⛔" if results[email] == "RESTRICTED" else ("✅" if results[email] == "CLEAN" else "⚠️")
        print(f"  {marker} {results[email]:<14} {email}")
    print("-" * 70)
    for st, n in sorted(counts.items()):
        print(f"  {st}: {n}")
    print("=" * 70)
    with open("/tmp/gcp_report.txt", "w") as f:
        for email in sorted(results):
            f.write(f"{results[email]:<14} {email}\n")
    _log("report saved: /tmp/gcp_report.txt")

if __name__ == "__main__":
    main()