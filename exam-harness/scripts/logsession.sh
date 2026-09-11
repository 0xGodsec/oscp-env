#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# logsession.sh — start a fully-logged shell (typescript) for OSCP evidence.
# Uses `script` to capture EVERY command + output (incl. reverse shells) to a
# timestamped file. Inspired by PakCyberbot's toggle-terminal-logging, but
# self-contained (no rc-file edits) and per-box aware.
#
# Usage:
#   logsession.sh [name]      # start a logged shell; logs -> $KIT/logs/
#   WORKDIR-aware: if you 'export WORKDIR=~/Desktop/HTB', logs go under there too.
#   Type 'exit' to stop logging. Replay a log with:  scriptreplay -t timing log
LOGROOT="${WORKDIR:-$KIT}/logs"
[ "${WORKDIR:+x}" = x ] && LOGROOT="$WORKDIR/_logs"
mkdir -p "$LOGROOT"
NAME="${1:-session}"
TS=$(date '+%Y-%m-%d_%H-%M-%S')
LOG="$LOGROOT/${NAME}_${TS}.log"
TIMING="$LOGROOT/${NAME}_${TS}.timing"
if [ -n "$UNDER_OSCP_LOG" ]; then
  echo "[!] Already inside a logged session ($UNDER_OSCP_LOG). Type 'exit' first."; exit 1
fi
echo "[*] Logging this shell -> $LOG"
echo "    everything you type & see is captured (reverse shells included)."
echo "    Type 'exit' to stop. Replay later:  scriptreplay -t '$TIMING' '$LOG'"
# -f flushes after each write (so a crash/DC still keeps the log); -q quiet;
# --timing records timing so the session can be replayed in real time.
UNDER_OSCP_LOG="$LOG" script -f -q --timing="$TIMING" "$LOG"
echo "[+] Session saved: $LOG"
