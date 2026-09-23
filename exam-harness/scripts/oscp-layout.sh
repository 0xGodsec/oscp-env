#!/bin/bash
# oscp-layout.sh — open a tmux exam/practice layout: serve | listener | work.
# Usage: ./oscp-layout.sh [session-name]
#   Honors $WORKDIR (exported before running) so 'work' pane targets your
#   practice folder. Attach later with:  tmux attach -t oscp
SES="${1:-oscp}"
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
if tmux has-session -t "$SES" 2>/dev/null; then
  echo "[*] session '$SES' exists — attaching."; exec tmux attach -t "$SES"
fi
WD_ENV=""; [ -n "$WORKDIR" ] && WD_ENV="export WORKDIR='$WORKDIR'; "
# window 0: serve (top) + listener (bottom-left) + work (bottom-right)
tmux new-session -d -s "$SES" -n main -c "$KIT"
tmux send-keys  -t "$SES":main "${WD_ENV}echo '[serve] run: ./scripts/serve.sh 7890'" C-m
tmux split-window -v -t "$SES":main -c "$KIT"
tmux send-keys  -t "$SES":main "${WD_ENV}echo '[listener] run: ./scripts/listener.sh 443'" C-m
tmux split-window -h -t "$SES":main -c "$KIT"
tmux send-keys  -t "$SES":main "${WD_ENV}echo '[work] newtarget/rx/proof here'; cd '$KIT'" C-m
tmux select-layout -t "$SES":main tiled
tmux select-pane  -t "$SES":main.2
echo "[+] tmux session '$SES' ready (serve | listener | work). Attaching..."
exec tmux attach -t "$SES"
