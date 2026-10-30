#!/usr/bin/env bash
# warm.sh — jaga session Gmail tetap hidup.
# 1) refresh-cookies: probe + tangkep Set-Cookie rotasi (__Secure-1PSIDTS dll)
# 2) keepalive: buka Gmail di browser asli HANYA untuk akun yang masih ALIVE,
#    biar Chrome yang muter token (persis kayak di PC).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p logs
# jangan ganggu batch yang sedang login (profile lock / CDP bentrok)
if pgrep -f "scripts/run-batch.mjs" >/dev/null 2>&1; then
  echo "=== warm $(date +%Y-%m-%dT%H:%M:%S) ==="
  echo "-> batch sedang jalan — warm di-skip (hindari profile lock)"
  exit 0
fi
STAMP=$(date +%Y-%m-%dT%H:%M:%S)
OUT=$(node scripts/refresh-cookies.mjs 2>&1)
echo "=== warm $STAMP ==="
echo "$OUT"
EMAILS=$(printf '%s\n' "$OUT" | awk '/: ALIVE/{print $1}')
if [ -z "$EMAILS" ]; then
  echo "-> nggak ada akun alive — keepalive di-skip (nggak buang CPU)"
  exit 0
fi
echo "-> keepalive: $(printf '%s ' $EMAILS)"
node scripts/keepalive.mjs $EMAILS
