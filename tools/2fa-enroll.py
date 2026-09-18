#!/usr/bin/env python3
"""2fa-enroll — enroll mailg gmail accounts into Google Authenticator TOTP + store secret.

WHY: accounts hitting Google device-prompt challenges (Verifikasi diri Anda) can be
auto-solved via "Cara lainnya" → Google Authenticator → TOTP — but only if the account
has 2FA enrolled AND the secret is in .2fa-secrets. This script enrolls + stores.

Usage:
  python3 tools/2fa-enroll.py enroll <email>   # browser-enroll via mailg cookies
  python3 tools/2fa-enroll.py gen <email>      # generate random secret (manual enroll via QR)
  python3 tools/2fa-enroll.py show <email>     # show stored secret + otpauth URI
  python3 tools/2fa-enroll.py list             # list stored secrets

Secrets: /root/projects/gmail-inbox/.2fa-secrets (email|base32, 0600)
Logs:    timestamped stdout, no silent skip (pre-mortem rule #3/#5)

OUTCOME MAP (pre-mortem, all handled):
  enroll:  cookie missing → FAIL | session dead (gaia_loginform) → FAIL
           2FA already on + authenticator set → CANNOT re-view key → report, skip
           security page layout change → screenshot + FAIL
           mid-flow phone challenge → screenshot + FAIL (enroll needs user tap once)
           key found (textContent 32-char base32) → validate base32 → store 0600
           key save: file backup to _backup_files/ first; duplicate email → replace only --force
  gen:     email already stored → refuse (no overwrite) unless --force
           invalid email → FAIL
  store:   base32 decode validation BEFORE write; 0600 perms enforced
"""
import os, sys, re, time, json, base64, secrets as _pysecrets
from pathlib import Path

ROOT = Path("/root/projects/gmail-inbox")
SECRETS = ROOT / ".2fa-secrets"
BACKUP_DIR = ROOT / "_backup_files"
COOKIE_DIR = ROOT / "cookies"
INBOX_DB = ROOT / "inbox.db"

def _log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def load_secrets():
    d = {}
    if SECRETS.exists():
        for l in SECRETS.read_text().splitlines():
            if "|" in l:
                e, s = l.split("|", 1)
                d[e.strip().lower()] = s.strip()
    return d

def valid_b32(s):
    try:
        t = s.strip().replace(" ", "").upper()
        if len(t) % 8: t += "=" * (8 - len(t) % 8)
        base64.b32decode(t)
        return True
    except Exception:
        return False

def store_secret(email, secret, force=False):
    """Store email|secret with backup + validation. Returns True on write."""
    email = email.strip().lower()
    if "@" not in email:
        _log(f"⛔ invalid email: {email}"); return False
    if not valid_b32(secret):
        _log(f"⛔ secret not valid base32 ({len(secret)} chars) — refusing to store"); return False
    existing = load_secrets()
    if email in existing and not force:
        _log(f"⛔ {email} already stored — use --force to replace"); return False
    # backup before write (config safety rule)
    BACKUP_DIR.mkdir(exist_ok=True)
    if SECRETS.exists():
        bak = BACKUP_DIR / ".2fa-secrets.bak"
        bak.write_text(SECRETS.read_text())
        os.chmod(bak, 0o600)
        _log(f"backup: {bak}")
    lines = [l for l in (SECRETS.read_text().splitlines() if SECRETS.exists() else []) if l.strip()]
    if email in {l.split("|", 1)[0].strip().lower() for l in lines if "|" in l}:
        lines = [l for l in lines if not l.lower().startswith(email.lower() + "|")]
    lines.append(f"{email}|{secret}")
    SECRETS.write_text("\n".join(lines) + "\n")
    os.chmod(SECRETS, 0o600)
    _log(f"✅ stored {email} (secret {len(secret)} chars, 0600)")
    return True

def gen_secret():
    # 160-bit → 32 base32 chars (standard Google Authenticator length)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(_pysecrets.choice(alphabet) for _ in range(32))

def cookie_file_for(email):
    try:
        import sqlite3
        db = sqlite3.connect(INBOX_DB)
        row = db.execute("SELECT cookie_file FROM accounts WHERE email=?", (email,)).fetchone()
        if row: return COOKIE_DIR / row[0]
    except Exception as e:
        _log(f"  inbox.db lookup fail: {e}")
    slug = email.replace("@", "_").replace(".", "_") + ".json"
    return COOKIE_DIR / slug

def enroll(email):
    """Browser-enroll via mailg cookies: myaccount.google.com → 2FA → Authenticator → capture key."""
    os.environ.setdefault("DISPLAY", ":99")
    cf = cookie_file_for(email)
    if not cf.exists():
        _log(f"⛔ no cookie file for {email} ({cf.name}) — run mailg login first"); return False
    from playwright.sync_api import sync_playwright
    raw = json.loads(cf.read_text())
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path="/usr/bin/google-chrome",
                              headless=True, args=["--no-sandbox", "--disable-gpu"])
        ctx = b.new_context(viewport={"width": 1280, "height": 900})
        ck = [{"name": c["name"], "value": c["value"], "domain": c["domain"],
               "path": c.get("path", "/"), "secure": bool(c.get("secure", True)),
               "httpOnly": bool(c.get("httpOnly", False))}
              for c in raw if "google" in c.get("domain", "")]
        ctx.add_cookies(ck)
        pg = ctx.new_page()
        try:
            _log(f"opening myaccount.google.com/security for {email}")
            pg.goto("https://myaccount.google.com/security", wait_until="domcontentloaded", timeout=45000)
            time.sleep(5)
            body = pg.inner_text("body")[:400]
            if "Sign in" in body and "Google Account" not in body:
                _log(f"⛔ session dead for {email}"); _shot(pg, f"2fa_dead_{email.split('@')[0]}"); b.close(); return False
            _log("security page loaded")
            # 2-Step Verification card → click
            clicked = False
            for sel in ["a:has-text('2-Step Verification')", "div:has-text('2-Step Verification') a",
                        "[data-identifier] :text('2-Step Verification')"]:
                try:
                    loc = pg.locator(sel).first
                    if loc.count():
                        loc.click(); clicked = True; _log(f"clicked 2SV card ({sel})"); break
                except Exception: pass
            if not clicked:
                _log("⛔ 2SV card not found — layout change?"); _shot(pg, f"2fa_layout_{email.split('@')[0]}"); b.close(); return False
            time.sleep(5)
            # Google may ask password again (verify session) — password from loggedmail
            try:
                T = pg.inner_text("body")[:600]
            except Exception: T = ""
            if "password" in T.lower() and pg.locator('input[name="Passwd"], input[type="password"]').count():
                _log("⛔ password re-ask — enrollment needs password (add --pw flow later)"); _shot(pg, f"2fa_pw_{email.split('@')[0]}"); b.close(); return False
            # Authenticator → set up
            auth_clicked = False
            for sel in ["div:has-text('Authenticator app')", "a:has-text('Authenticator')", ":text('Authenticator app')"]:
                try:
                    loc = pg.locator(sel).first
                    if loc.count():
                        loc.click(); auth_clicked = True; _log(f"clicked authenticator ({sel})"); break
                except Exception: pass
            if not auth_clicked:
                _log("⛔ authenticator option not found — 2FA maybe already on"); _shot(pg, f"2fa_auth_{email.split('@')[0]}"); b.close(); return False
            time.sleep(5)
            # "Set up" button (or directly shows QR/key)
            for sel in ["button:has-text('Set up')", "span:has-text('Set up')"]:
                try:
                    loc = pg.locator(sel).first
                    if loc.count():
                        loc.click(); _log(f"clicked set up ({sel})"); break
                except Exception: pass
            time.sleep(6)
            # capture setup key: 32-char base32 text on page (may be behind "Can't scan?")
            key = ""
            for attempt in range(3):
                m = re.search(r"\b([A-Z2-7]{32})\b", pg.inner_text("body") or "")
                if m: key = m.group(1); break
                # try "Can't scan" / "Enter code" expander
                for t2 in ["Can't scan", "Tidak dapat memindai", "Enter the code", "Masukkan kode"]:
                    if click_text(pg, t2): _log(f"clicked '{t2}'"); time.sleep(3); break
            if not key:
                _log("⛔ setup key not visible — QR-only flow"); _shot(pg, f"2fa_nokey_{email.split('@')[0]}"); b.close(); return False
            _log(f"key captured: {key[:8]}...{key[-4:]}")
            ok = store_secret(email, key, force="--force" in sys.argv)
            _shot(pg, f"2fa_enrolled_{email.split('@')[0]}")
            b.close()
            return ok
        except Exception as e:
            _log(f"⛔ enroll error: {str(e)[:100]}")
            try: _shot(pg, f"2fa_err_{email.split('@')[0]}")
            except Exception: pass
            b.close(); return False

def _shot(pg, name):
    try:
        p = f"/tmp/2fa_{name}.png"
        pg.screenshot(path=p, full_page=True)
        _log(f"[vision] {p}")
    except Exception as e:
        _log(f"[vision fail] {e}")

def click_text(pg, txt):
    try:
        for sel in [f"button:has-text('{txt}')", f"a:has-text('{txt}')", f"span:has-text('{txt}')",
                    f"div:has-text('{txt}')"]:
            loc = pg.locator(sel).first
            if loc.count():
                loc.click(); return True
    except Exception: pass
    return False

def main():
    args = [a for a in sys.argv[1:] if a != "--force"]
    force = "--force" in sys.argv
    if len(args) < 1:
        print(__doc__); return
    cmd = args[0]
    if cmd == "list":
        for e, s in sorted(load_secrets().items()):
            print(f"  {e:42s} {s[:8]}...{s[-4:]}")
    elif cmd == "show" and len(args) > 1:
        email = args[1].lower()
        s = load_secrets().get(email)
        if not s: _log(f"⛔ no secret stored for {email}"); return
        print(f"  email:   {email}")
        print(f"  secret:  {s}")
        print(f"  otpauth: otpauth://totp/{email.replace('@','%40')}?secret={s}&issuer=Gmail")
        # inline TOTP (get-2fa.py has hyphen — not importable)
        try:
            import hmac, hashlib, struct
            t = s.strip().upper().replace(" ", "")
            if len(t) % 8: t += "=" * (8 - len(t) % 8)
            key = base64.b32decode(t)
            msg = struct.pack(">Q", int(time.time() // 30))
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = h[19] & 0x0f
            code = f"{(struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000:06d}"
            print(f"  code now: {code}")
        except Exception as e:
            _log(f"  code gen fail: {e}")
    elif cmd == "gen" and len(args) > 1:
        email = args[1].lower()
        existing = load_secrets()
        if email in existing and not force:
            _log(f"⛔ {email} already has secret — use --force to replace (or 'show')"); return
        s = gen_secret()
        if store_secret(email, s, force=force):
            print(f"  email:   {email}")
            print(f"  secret:  {s}")
            print(f"  otpauth: otpauth://totp/{email.replace('@','%40')}?secret={s}&issuer=Gmail")
            _log("manual enroll: add this secret in Google Authenticator app (or account 2FA page)")
    elif cmd == "enroll" and len(args) > 1:
        enroll(args[1].lower())
    else:
        print(__doc__)

if __name__ == "__main__":
    main()