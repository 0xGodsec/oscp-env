#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# bloodhound.sh — start/stop BloodHound CE in Docker to analyze collected data.
# Usage: ./bloodhound.sh start | stop | status | pw
#   start  : bring up BloodHound CE (web UI at http://localhost:8080)
#   stop   : tear it down
#   status : show container state
#   pw     : print the randomly-generated initial admin password from logs
# Needs Docker (daemon running). First start pulls ~1GB and prints the initial
# 'admin' password in the logs — grab it with './bloodhound.sh pw'.
BHDIR=$KIT/bloodhound
COMPOSE_URL="https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/docker-compose.yml"
mkdir -p "$BHDIR"; cd "$BHDIR" || exit 1
# docker compose v2 plugin, else docker-compose
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
SUDO=""; docker info >/dev/null 2>&1 || SUDO="sudo"
need_compose(){ [ -f docker-compose.yml ] || { echo "[*] fetching compose file..."; curl -sL "$COMPOSE_URL" -o docker-compose.yml; }; }

case "$1" in
  start)
    if ! $SUDO docker info >/dev/null 2>&1; then
      echo "[!] Docker daemon not reachable. Start it first:  sudo systemctl start docker"; exit 1; fi
    need_compose
    echo "[*] starting BloodHound CE ($DC up -d)..."
    $SUDO $DC up -d && echo "[+] UI: http://localhost:8080  (user: admin)" \
      && echo "    initial password ->  ./bloodhound.sh pw"
    ;;
  stop)   need_compose; $SUDO $DC down && echo "[+] stopped.";;
  status) $SUDO $DC ps;;
  pw)     $SUDO $DC logs 2>&1 | grep -iE 'Initial Password|password set to' | tail -1 || echo "[!] not found — check './bloodhound.sh status'";;
  *) echo "Usage: bloodhound.sh start|stop|status|pw";;
esac
