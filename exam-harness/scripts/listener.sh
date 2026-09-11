#!/bin/bash
# Usage: ./listener.sh [port]   (default 443)
PORT="${1:-443}"
command -v rlwrap >/dev/null && RL=rlwrap || RL=
echo "[*] Listening on 0.0.0.0:$PORT"
$RL nc -lvnp "$PORT"
