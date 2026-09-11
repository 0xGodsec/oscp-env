#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# Usage: ./newtarget.sh <name> <ip>
NAME="$1"; IP="$2"
if [ -z "$NAME" ] || [ -z "$IP" ]; then echo "Usage: newtarget.sh <name> <ip>"; exit 1; fi
BASE="${WORKDIR:-$KIT/targets}/$NAME"
mkdir -p "$BASE"/{scans/{nmap,web},loot,exploits,privesc}
touch "$BASE/proof.txt" "$BASE/local.txt"
cat > "$BASE/notes.md" <<NOTE
# $NAME  ($IP)

- **IP:** $IP
- **OS:** 
- **Started:** $(date '+%Y-%m-%d %H:%M')

## Open Ports

## Enumeration

## Foothold / Initial Access
- **User creds:** 
- **local.txt:** 

## Privilege Escalation
- **Vector:** 
- **proof.txt:** 

## Commands run
NOTE
echo "export IP=$IP" > "$BASE/.env"
echo "[+] Created $BASE"
echo "    cd $BASE  &&  source .env"
