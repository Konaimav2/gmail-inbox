#!/usr/bin/env python3
"""get-2fa — TOTP code + QR for gmail 2FA secrets.
Usage:
  python3 tools/get-2fa.py ceweeliteampremsulit@gmail.com
  python3 tools/get-2fa.py --all
  python3 tools/get-2fa.py --qr ceweeliteampremsulit@gmail.com  # prints otpauth:// URL for QR
Secrets: /root/projects/gmail-inbox/.2fa-secrets (email|base32)
"""
import sys, time, base64, hmac, hashlib, struct, os
from pathlib import Path

SECRETS = Path("/root/projects/gmail-inbox/.2fa-secrets")
ROOT = Path("/root/projects/gmail-inbox")

def totp(secret_b32, digits=6, period=30):
    secret_b32 = secret_b32.strip().replace(' ','').upper()
    # pad
    secret_b32 += '=' * (-len(secret_b32) % 8) if len(secret_b32) % 8 else ''
    key = base64.b32decode(secret_b32)
    counter = int(time.time() // period)
    msg = struct.pack('>Q', counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 0x0f
    code = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % (10**digits)
    return f"{code:0{digits}d}"

def load_secrets():
    if not SECRETS.exists(): return {}
    d={}
    for l in SECRETS.read_text().splitlines():
        if '|' in l:
            e,s=l.split('|',1)
            d[e.strip().lower()]=s.strip()
    return d

def qr_url(email, secret):
    label = email.replace('@','%40')
    return f"otpauth://totp/{label}?secret={secret}&issuer=Gmail"

if __name__ == "__main__":
    secrets = load_secrets()
    if not secrets:
        print(f"no secrets in {SECRETS}"); sys.exit(1)

    if "--qr" in sys.argv:
        idx = sys.argv.index("--qr")
        email = sys.argv[idx+1] if idx+1 < len(sys.argv) else list(secrets)[0]
        email_l = email.lower()
        if email_l not in secrets:
            print(f"no secret for {email}"); sys.exit(1)
        url = qr_url(email, secrets[email_l])
        print(url)
        # also try to render QR as ascii if qrcode available
        try:
            import qrcode
            qr = qrcode.QRCode(border=1)
            qr.add_data(url); qr.make()
            qr.print_ascii(invert=True)
        except ImportError:
            print("(pip install qrcode for ascii QR)")
        sys.exit(0)

    if "--all" in sys.argv:
        for email, sec in secrets.items():
            code = totp(sec)
            remain = 30 - int(time.time() % 30)
            print(f"{email:40s} {code}  ({remain}s left)  secret {sec[:6]}...")
        sys.exit(0)

    if len(sys.argv) > 1 and "@" in sys.argv[1]:
        email = sys.argv[1].lower()
        if email not in secrets:
            print(f"no secret for {email}"); sys.exit(1)
        code = totp(secrets[email])
        remain = 30 - int(time.time() % 30)
        print(code)
        print(f"  {email}  valid {remain}s  ->  {qr_url(email, secrets[email])}")
        sys.exit(0)

    # default: show all
    for email, sec in secrets.items():
        code = totp(sec)
        remain = 30 - int(time.time() % 30)
        print(f"{email:40s} {code} ({remain}s)")
