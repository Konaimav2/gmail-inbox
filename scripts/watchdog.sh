#!/usr/bin/env bash
# watchdog.sh — alert if any account hasn't synced in 26h or the edge is down.
# Designed for cron/systemd daily runs; prints ALERT lines to stdout for delivery.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp)"

# local API reachable? (native routes need X-API-Key)
if ! curl -s -m 15 -H "X-API-Key: $(python3 -c "import sqlite3;print(sqlite3.connect('$ROOT/inbox.db').execute(\"select value from settings where key='api_key'\").fetchone()[0])")" \
  http://127.0.0.1:8790/api/accounts > "$OUT" 2>/dev/null; then
  echo "ALERT: local API unreachable (is gmail-inbox running?)"
  rm -f "$OUT"
  exit 0
fi

python3 - "$OUT" <<'PY' || exit 0
import json, sys, time
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("ALERT: /api/accounts returned non-JSON (check auth)")
    sys.exit(0)
now = time.time() * 1000
stale = [a.get("email") for a in d if not a.get("last_sync") or now - a.get("last_sync", 0) > 26 * 3600 * 1000]
if stale:
    print("ALERT: stale accounts (>26h no sync): " + ", ".join(stale))
else:
    print(f"all accounts synced OK ({len(d)} accounts)")
PY
rm -f "$OUT"

# public edge
code="$(curl -s -m 15 -o /dev/null -w '%{http_code}' https://mailg.arraffi.my.id/login.html || echo 000)"
echo "edge_http=$code"
if [ "$code" != "200" ] && [ "$code" != "302" ]; then
  echo "ALERT: public edge returned $code"
fi
