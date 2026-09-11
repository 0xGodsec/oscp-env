#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# proof.sh — OSCP proof/local flag capture helper.
# Two jobs: (1) print the exact on-target one-liners that put the flag AND the
# host IP in one screenshot (what OSCP requires), and (2) record captured flags
# into the workspace + a running points tally you copy straight into the report.
#
# Usage:
#   proof.sh -o linux|windows                     # print on-target capture commands
#   proof.sh -n <name> -i <ip> -t local|proof -f <flag>   # record a captured flag
#   proof.sh -l                                    # show the running tally + est. points
#   -n workspace name   -i target IP   -t local|proof   -f flag string
#   -o print capture one-liners for that OS and exit    -l list tally
#
# Examples:
#   ./proof.sh -o windows
#   ./proof.sh -n box1 -i 10.10.10.10 -t local -f 2f8a...   # record local.txt
#   ./proof.sh -n box1 -i 10.10.10.10 -t proof -f a91c...   # record proof.txt
#   ./proof.sh -l

set -o pipefail
BASE=$KIT
TALLY="$BASE/report/proof-tally.csv"
NAME=""; IP=""; TYPE=""; FLAG=""; OSMODE=""; LIST=0
while getopts "n:i:t:f:o:lh" o; do case "$o" in
  n) NAME=$OPTARG;; i) IP=$OPTARG;; t) TYPE=$OPTARG;; f) FLAG=$OPTARG;;
  o) OSMODE=$OPTARG;; l) LIST=1;; h|*) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
esac; done

mkdir -p "$(dirname "$TALLY")"
[ -f "$TALLY" ] || echo "timestamp,name,ip,type,flag" > "$TALLY"

# --- print on-target capture commands ---
if [ -n "$OSMODE" ]; then
  echo "# Run ON THE TARGET so the flag + IP are in ONE screenshot:"
  case "${OSMODE,,}" in
    win*|windows)
      echo 'type C:\Users\Administrator\Desktop\proof.txt & whoami & ipconfig'
      echo '  (user flag)  type C:\Users\<user>\Desktop\local.txt & whoami & ipconfig'
      echo '  PowerShell:  type proof.txt; whoami; ipconfig' ;;
    lin*|linux|nix)
      echo 'cat /root/proof.txt; id; hostname; ip -4 a | grep inet'
      echo '  (user flag)  cat ~/local.txt; id; hostname -I'
      echo '  no ip? use:  cat proof.txt; whoami; /sbin/ifconfig 2>/dev/null || ip a' ;;
    *) echo "[!] -o must be 'linux' or 'windows'"; exit 1;;
  esac
  exit 0
fi

# --- list tally ---
if [ "$LIST" = 1 ]; then
  echo "== Proof tally ($TALLY) =="
  column -t -s, "$TALLY"
  P=$(tail -n +2 "$TALLY" | grep -c ',proof,'); L=$(tail -n +2 "$TALLY" | grep -c ',local,')
  echo "----"
  echo "local flags: $L    proof flags: $P"
  echo "rough standalone points (10 each): $(( (L + P) * 10 ))  (AD set is scored separately)"
  exit 0
fi

# --- record a flag ---
[ -z "$NAME" ] || [ -z "$IP" ] || [ -z "$TYPE" ] || [ -z "$FLAG" ] && {
  echo "[!] to record: -n <name> -i <ip> -t local|proof -f <flag>   (or -o OS / -l). -h for help."; exit 1; }
case "$TYPE" in local|proof) ;; *) echo "[!] -t must be 'local' or 'proof'."; exit 1;; esac

# OSCP flags are typically 32 hex chars — warn but still record if it differs
if ! echo "$FLAG" | grep -qiE '^[a-f0-9]{32}$'; then
  echo "[!] warning: flag isn't the usual 32-hex format — recording anyway."
fi

TDIR="${WORKDIR:-$BASE/targets}/$NAME"
mkdir -p "$TDIR"
echo "$FLAG" > "$TDIR/$TYPE.txt"
echo "$(date '+%Y-%m-%d %H:%M:%S'),$NAME,$IP,$TYPE,$FLAG" >> "$TALLY"

echo "[+] recorded $TYPE flag for $NAME ($IP) -> $TDIR/$TYPE.txt"
echo "    >> SCREENSHOT REMINDER: capture $TYPE.txt WITH the IP visible on the target:"
echo "       Windows:  type $TYPE.txt & ipconfig"
echo "       Linux:    cat $TYPE.txt; ip a"
echo
echo "== running tally =="
P=$(tail -n +2 "$TALLY" | grep -c ',proof,'); L=$(tail -n +2 "$TALLY" | grep -c ',local,')
echo "local: $L   proof: $P   (standalone est. $(( (L + P) * 10 )) pts)"
