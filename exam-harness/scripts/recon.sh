#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# Usage: ./recon.sh <ip> [name]
# Fast full TCP scan -> targeted service scan -> web enum on http ports.
IP="$1"; NAME="${2:-$IP}"
if [ -z "$IP" ]; then echo "Usage: recon.sh <ip> [name]"; exit 1; fi
OUT="${WORKDIR:-$KIT/targets}/$NAME/scans"
mkdir -p "$OUT/nmap" "$OUT/web"
echo "[*] Stage 1: full TCP port sweep..."
nmap -p- --min-rate 2000 -T4 -Pn "$IP" -oN "$OUT/nmap/allports.txt"
# parse ports from the saved scan (no shared /tmp file -> safe for concurrent boxes)
PORTS=$(grep -oP '^\d+(?=/tcp)' "$OUT/nmap/allports.txt" | paste -sd, -)
if [ -z "$PORTS" ]; then echo "[!] No open ports found."; exit 0; fi
echo "[*] Open: $PORTS"
echo "[*] Stage 2: version + default scripts on open ports..."
nmap -sVC -p"$PORTS" -Pn "$IP" -oN "$OUT/nmap/services.txt"
# Web enum on common http ports
for wp in 80 443 8080 8000 8443; do
  if echo ",$PORTS," | grep -q ",$wp,"; then
    scheme=http; [ "$wp" = "443" -o "$wp" = "8443" ] && scheme=https
    echo "[*] Web enum on $scheme://$IP:$wp ..."
    whatweb "$scheme://$IP:$wp" 2>/dev/null | tee "$OUT/web/whatweb_$wp.txt"
    feroxbuster -u "$scheme://$IP:$wp" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
      -k -q -o "$OUT/web/ferox_$wp.txt" -t 50 --scan-limit 2 2>/dev/null || true
  fi
done
echo "[+] Recon done -> $OUT"
