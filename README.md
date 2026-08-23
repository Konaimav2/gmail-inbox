# Mail Hub — multi-Gmail cookie inbox

> ## ⚠️ CREATED USING DEEPSEEK V4 FLASH
> This project was generated with assistance from **DeepSeek V4 Flash** (AI).
> Review the code and security posture before deploying; do not assume it is
> production-hardened or audited by a human.

Cookie-based multi-Gmail inbox API + web UI. Log accounts once (semi-auto script),
the server fetches mail via `mail.google.com` with saved cookies and serves it
through a tempmail-style web app and a cloud-mail-compatible API.

## Requirements
- Node.js 22.5+ (uses built-in `node:sqlite`)
- For the login script only: `x11vnc`, `websockify`, noVNC (`/opt/noVNC`), `Xvfb`,
  and ~1 GB free RAM. `scripts/run-batch.mjs` runs a preflight check and fails fast
  with a clear reason if the machine can't run it.

## Run the web
```bash
cd gmail-inbox

# 1. env (create if missing):
#    PORT=8790  HOST=127.0.0.1  PASSWORD=<page password>
cp .env.example .env   # then edit PASSWORD

# 2. start
node server.mjs
# or: pm2 start server.mjs --name gmail-inbox

# 3. open http://127.0.0.1:8790   (login with PASSWORD)
```

### Secrets & the local DB
The API key, public token and session secret are **auto-generated and persisted in
the local SQLite DB** (`inbox.db`, `settings` table) — they survive restarts with no
`.env` entries needed. To pin values, set `API_KEY`/`PUBLIC_TOKEN` in `.env` (they're
migrated into the DB on first run). `inbox.db` is gitignored.

### One login for mail + docs
A single `PASSWORD` unlocks both the mail app (`/`) and the API docs (`/docs`).
`/docs` redirects to the login page if you aren't authenticated, then returns you to
the docs. One session cookie (`gsess`, 7 days, restart-proof HMAC-signed) covers both.

## API (header `X-API-Key: <key>`)
- `GET /api/accounts` — inboxes + last_sync
- `GET /api/accounts/<email>/messages?limit=50` — last-365d threads
- `GET /api/accounts/<email>/messages/<thread_id>` — full thread + HTML bodies
- `POST /api/accounts/<email>/messages/refresh` — force sync now
- `GET /api/sse` — realtime update events (selected account only)
- `POST /api/select` / `GET /api/selected` — which account gets realtime new-mail checks

## Cloud-Mail compatible API
Envelope: `{code, message, data}`. Tokens go in `Authorization` header (no `Bearer`).

| Endpoint | Auth | Params (POST JSON) | Returns |
|---|---|---|---|
| `GET /api/docs` | API key | — | full endpoint docs |
| `GET /api/openapi` | API key | — | OpenAPI 3.0.3 spec |
| `POST /api/login` | none | `password` (page password) | `{token: API_KEY}` |
| `POST /api/public/genToken` | public token | — | `{token}` |
| `POST /api/public/emailList` | public token | `toEmail, sendEmail, sendName, subject, num, size, timeSort` | `[email rows]` |
| `POST /api/email/list` | API key | `accountEmail` + same filters | `[email rows]` |
| `POST /api/email/latest` | API key | `accountEmail, size` | `[latest email rows]` |
| `POST /api/email/read` | API key | `emailId` | ok (no-op) |
| `POST /api/allEmail/list` | API key | `num, size, timeSort` | `[email rows]` (all accounts) |
| `POST /api/account/list` | API key | — | `[{email, name, lastSync, lastError}]` |

Email row: `{emailId, sendEmail, sendName, subject, toEmail, type, createTime, content (html), text (plain), isDel}`

Example:
```bash
curl -X POST -H "Authorization: <public_token>" -H "Content-Type: application/json" \
  -d '{"size":20}' http://127.0.0.1:8790/api/public/emailList
```

## Accounts: `list.txt` format
One account per line — `email|password` (password may contain `|`, `\`, etc.). An
optional trailing numeric 2FA (≤8 digits) goes after a final `|`:

```
user1@gmail.com|myP@ssw0rd
user2@gmail.com|pass-with|pipes
user4@gmail.com|realPassword|482103      <- 482103 is 2FA
```

See `list.txt.example`. Copy it to `list.txt` and fill in real accounts.

> ⚠️ If your real password ends with `|` + digits, the batch will treat that tail as
> 2FA. Check with `node scripts/check-creds.mjs` before running.

### Pre-flight password check (NEW)
`scripts/check-creds.mjs` audits `list.txt` for likely-wrong/placeholder passwords and
format problems — without hitting Google (no wasted login attempts / lockouts):
```bash
node scripts/check-creds.mjs
```
It flags short/placeholder passwords, previously-failed (`bad creds`) accounts, and
lines where the password looks like it may end in a `|` or `\` delimiter artifact.

## Add accounts (semi-auto login)
```bash
# single account (password passed as-is, pipes safe as one arg):
node scripts/run-batch.mjs user@gmail.com 'my|piped|password'

# headless mode (no VNC, lower resource usage):
node scripts/run-batch.mjs --no-vnc

# whole remaining list.txt:
node scripts/run-batch.mjs
```
The script runs a VM preflight, sets up Xvfb + Chrome + VNC (noVNC), logs each account,
auto-handles challenges (phone-tap code relay, 2FA setup-key capture, selfie/home/phone
skips), validates the session (`simls` payload) before saving, then clears the VNC stack.
Watch the VNC page at `http://<host>:6080/vnc.html` (password from `.env` `VNC_PASSWORD`).  
Success → `cookies/<user>.json` + added to `loggedmail.txt`. Failures → `failed.txt` with a reason.

### New: --no-vnc mode
Pass `--no-vnc` to skip Xvfb/x11vnc/websockify and run Chrome headless. Useful on
low-resource or headless machines where you only need cookie renewal, not visual
debugging. Chromium runs with `--headless=new --disable-gpu`.

### Improved: Captcha before password
The script now properly handles captchas that appear **before** the password field
by (1) notifying the human via VNC, (2) polling until the captcha text disappears,
and (3) detecting the password field to resume automatically. Previously it used a
blind timeout which caused false failures.

### Improved: Wrong password & invalid email detection
- **Wrong password** caught immediately after submit (not after a 300s timeout)
- **Invalid email** ("Couldn't find your Google Account") detected and skipped fast
- Both are logged to `failed.txt` with clear reason

2FA automation: if the authenticator setup screen shows a key, the batch logs it,
**saves it to `.2fa-secrets`**, and later auto-fills the code via a **local RFC-6238 TOTP generator** (no network needed).

### Routing / rotating proxies (`--proxy`)
Route the login browser through a proxy so the login IP differs from the server IP
(avoids Google flagging many accounts from one address).

```bash
# single proxy for every account:
node scripts/run-batch.mjs --proxy http://user:pass@1.2.3.4:8080

# rotate from a file (one proxy per line, '#' comments ignored):
node scripts/run-batch.mjs --proxy proxy.txt
```

`proxy.txt`:
```
http://user:pass@1.2.3.4:8080
socks5://user:pass@5.6.7.8:1080
https://9.10.11.12:3128
```

- Supported schemes: `http://`, `https://`, `socks5://` (optional `user:pass@`).
- **Smart load-balancing:** each proxy is randomly assigned **1-3 accounts** first.
  Once every proxy has hit that cap, the batch picks the **least-used** proxy; ties
  go to the first in the file. Proxies recycle smoothly, works with 1 or many.
- Proxy credentials are **never logged**; only `host:port` is shown.
- The proxy applies to the **login browser only**. Cookie-validity fetches and the
  server sync run on the real server IP to keep sessions healthy.
- `proxy.txt` is gitignored so credentials don't leak.

## Cookie health
```bash
node scripts/check-cookies.mjs   # validates each cookie against real Gmail, moves dead to cookies/invalid/
```
The server also auto-quarantines a cookie when sync hits a dead session.

## Activity ping
Server fetches each Gmail every `SYNC_MINUTES` (default 300 = 5h) to keep sessions
active. Realtime new-mail check runs every `MONITOR_SECONDS` (default 120s) for the
**selected** account only.

## License

[MIT](LICENSE)

> ⚠️ **CREATED USING DEEPSEEK V4 FLASH** — AI-generated. Use at your own risk;
> review before deploying in production.

