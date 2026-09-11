#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# gen-hosts.sh — build a hosts.txt of live IPs for ad-secretsdump.sh -S / netexec.
# Two sources: (1) discover a range with nmap, or (2) harvest IPs already found in
# your saved nmap scans. Output is one IP per line (the format -S expects).
#
# Usage:
#   gen-hosts.sh -r <CIDR|range> [-o out] [-x ip[,ip]] [-P] [-A]
#   gen-hosts.sh -f              [-o out] [-x ip[,ip]]        # harvest from saved scans
#   -r  range to discover, e.g. 10.10.10.0/24 or 172.16.5.1-254 (nmap host discovery)
#   -f  harvest IPs from $KIT/targets/*/scans/nmap/*.txt
#   -o  output file (default $KIT/loot/hosts.txt)
#   -x  comma-separated IPs to exclude (e.g. your Kali IP / already-owned box)
#   -P  run the nmap discovery through proxychains (internal/pivoted network)
#   -A  discovery via common-port TCP-SYN sweep instead of ping (better past host firewalls)
#
# Examples:
#   ./gen-hosts.sh -r 10.10.10.0/24 -x 10.10.10.10          # ping-sweep, drop own IP
#   ./gen-hosts.sh -r 172.16.5.0/24 -P -A                   # pivoted subnet, port-based
#   ./gen-hosts.sh -f                                        # reuse what you already scanned

set -o pipefail
RANGE=""; HARVEST=0; OUT=$KIT/loot/hosts.txt; EXCL=""; PROXY=0; SYN=0
while getopts "r:fo:x:PAh" o; do case "$o" in
  r) RANGE=$OPTARG;; f) HARVEST=1;; o) OUT=$OPTARG;; x) EXCL=$OPTARG;;
  P) PROXY=1;; A) SYN=1;; h|*) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
esac; done
[ -z "$RANGE" ] && [ "$HARVEST" = 0 ] && { echo "[!] give -r <range> or -f. -h for help."; exit 1; }
mkdir -p "$(dirname "$OUT")"
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT

if [ -n "$RANGE" ]; then
  PC=""; [ "$PROXY" = 1 ] && PC="proxychains4 -q"
  if [ "$SYN" = 1 ]; then
    # TCP sweep on common ports — works when ICMP is blocked; -sT needed under proxychains
    STYPE="-sT"; [ "$PROXY" = 0 ] && STYPE="-sS"
    echo "[*] nmap TCP discovery on $RANGE (ports 21,22,80,135,139,443,445,3389,5985)..."
    $PC nmap $STYPE -Pn -n --open -p21,22,80,135,139,443,445,3389,5985 "$RANGE" -oG "$TMP" 2>/dev/null
  else
    echo "[*] nmap ping-sweep host discovery on $RANGE..."
    $PC nmap -sn -n "$RANGE" -oG "$TMP" 2>/dev/null
  fi
  grep -oP '\d+\.\d+\.\d+\.\d+' "$TMP" | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$TMP.ips"
else
  echo "[*] harvesting live IPs from saved nmap scans..."
  # grab IPs on lines showing open ports / 'Up' / 'scan report for'
  grep -rhoP 'Nmap scan report for \K\d+\.\d+\.\d+\.\d+' $KIT/targets/*/scans/nmap/*.txt 2>/dev/null >  "$TMP.ips"
  grep -rhoP '^\K\d+\.\d+\.\d+\.\d+(?=\b.*Status: Up)'    $KIT/targets/*/scans/nmap/*.txt 2>/dev/null >> "$TMP.ips"
  sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n "$TMP.ips" -o "$TMP.ips"
fi

# apply exclusions
if [ -n "$EXCL" ]; then
  echo "$EXCL" | tr ',' '\n' | sed '/^$/d' > "$TMP.excl"
  grep -vxFf "$TMP.excl" "$TMP.ips" > "$OUT"
else
  cp "$TMP.ips" "$OUT"
fi

N=$(wc -l < "$OUT")
echo "[+] $N host(s) -> $OUT"
[ "$N" -gt 0 ] && { echo "----"; cat "$OUT"; echo "----"; \
  echo "Next: ./scripts/ad-secretsdump.sh -t <DC> -d <domain> -u <adm> -p <pass> -S $OUT"; }
