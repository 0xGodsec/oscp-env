#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# rx.sh — run reconx into a box's OSCP workspace (creates it if needed).
# Thin wrapper around $KIT/../Tools/reconx/reconx.py so recon output and its
# NOTES.md land under targets/<name>/scans/reconx/ alongside everything else.
#
# Usage:
#   rx.sh <name> <target> [extra reconx flags...]
# Examples:
#   ./rx.sh box1 10.10.10.10                      # full pipeline
#   ./rx.sh box1 10.10.10.10 --quick              # fast top-1000
#   ./rx.sh dc01 192.168.120.5 -u alex -p 'Pw!' -d corp.htb --bloodhound  # authed AD
#   ./rx.sh net  192.168.120.0/24 --ping-sweep    # sweep a subnet
RECONX="$KIT/../Tools/reconx/reconx.py"
NAME="$1"; TARGET="$2"; shift 2 2>/dev/null
[ -z "$NAME" ] || [ -z "$TARGET" ] && { echo "Usage: rx.sh <name> <target> [reconx flags...]"; exit 1; }
[ -f "$RECONX" ] || { echo "[!] reconx not found at $RECONX"; exit 1; }
OUT="${WORKDIR:-$KIT/targets}/$NAME/scans/reconx"
mkdir -p "$OUT"
echo "[*] reconx $TARGET  ->  $OUT"
python3 "$RECONX" "$TARGET" -o "$OUT" "$@"
echo
echo "[+] Done. Ranked notes: $OUT/$TARGET/NOTES.md"
echo "    (feed the findings into targets/$NAME/notes.md and your report)"
