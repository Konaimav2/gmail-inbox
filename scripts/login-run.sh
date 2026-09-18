#!/usr/bin/env bash
# Gmail login session: Xvfb + headful Chromium + x11vnc + noVNC
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(cd "$SELF/.." && pwd)"
CHROME="$(command -v chromium-browser || command -v google-chrome || command -v google-chrome-stable || command -v chromium || echo /root/.agent-browser/browsers/chrome-150.0.7871.46/chrome)"
PROFILE="$PROJECT/.chrome-profile"
COOKIE_DIR="$PROJECT/cookies"
VNC_DIR="$PROJECT/.vnc"
mkdir -p "$PROFILE" "$COOKIE_DIR" "$VNC_DIR"
DISPLAY_NUM=:99

# VNC password
VNCPASS="$(head -c 12 /dev/urandom | base64 | tr -d '/+=' | head -c 10)"
echo "$VNCPASS" > "$VNC_DIR/vncpw.txt"

# 1. Xvfb
pkill -f "Xvfb $DISPLAY_NUM" 2>/dev/null || true
Xvfb "$DISPLAY_NUM" -screen 0 1366x900x24 -ac &
XPID=$!
sleep 1.5

# 2. Chrome headful on the virtual display, real UA, remote debugging on localhost
DISPLAY="$DISPLAY_NUM" "$CHROME" \
  --user-data-dir="$PROFILE" \
  --no-sandbox --no-first-run --disable-background-networking \
  --window-size=1366,900 --window-position=0,0 \
  --remote-debugging-port=9222 \
  --disable-features=Translate,OptimizationHints \
  about:blank &
echo $! > "$VNC_DIR/chrome.pid"

# 3. x11vnc
pkill -f "x11vnc -display $DISPLAY_NUM" 2>/dev/null || true
sleep 1
x11vnc -display "$DISPLAY_NUM" -forever -shared -nopw -rfbport 5900 -bg -o "$VNC_DIR/x11vnc.log" 2>/dev/null || \
x11vnc -display "$DISPLAY_NUM" -forever -shared -passwd "$VNCPASS" -rfbport 5900 -bg -o "$VNC_DIR/x11vnc.log"

# 4. websockify -> noVNC
pkill -f "websockify 6080" 2>/dev/null || true
sleep 0.5
WEBSOCKIFY="${WEBSOCKIFY:-$(command -v websockify || echo /usr/local/lib/hermes-agent/venv/bin/websockify)}"
NOVNC_DIR="${NOVNC_DIR:-/opt/noVNC}"
"$WEBSOCKIFY" --web="$NOVNC_DIR" 6080 localhost:5900 >"$VNC_DIR/websockify.log" 2>&1 &
echo $! > "$VNC_DIR/websockify.pid"

echo "READY"
echo "noVNC:  http://192.25.205.17:6080/vnc.html"
echo "VNC pass: $VNCPASS"
echo "Chrome CDP: http://127.0.0.1:9222/json"