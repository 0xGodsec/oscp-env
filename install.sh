#!/usr/bin/env bash
#
# oscp-env installer — one command to make a fresh Kali box exam-ready.
#
#   git clone https://github.com/0xGodsec/oscp-env.git
#   cd oscp-env && ./install.sh
#
# Installs the environment commands + the ReconX recon engine, wires up the
# shell, terminal logging and Terminator layout, and (unless --no-notes) pulls
# in the methodology vault. Idempotent — safe to re-run.
#
set -euo pipefail

REPO="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
NOTES_REPO="https://github.com/0xGodsec/OSCP-Notes.git"
NOTES_DIR="$HOME/Desktop/Notes"
WITH_NOTES=1
WITH_APT=1

for a in "$@"; do
  case "$a" in
    --no-notes) WITH_NOTES=0 ;;
    --no-apt)   WITH_APT=0 ;;
    -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

G='\033[1;32m'; Y='\033[1;33m'; C='\033[1;36m'; R='\033[1;31m'; N='\033[0m'
say()  { echo -e "${C}[oscp-env]${N} $*"; }
ok()   { echo -e "${G}[oscp-env]${N} $*"; }
warn() { echo -e "${Y}[oscp-env]${N} $*"; }
err()  { echo -e "${R}[oscp-env]${N} $*" >&2; }

[ "$(id -u)" -eq 0 ] && { err "run as your normal user, not root (it will sudo when needed)."; exit 1; }

say "repo: $REPO"
say "requesting sudo (needed to install commands into /usr/local/bin)…"
sudo -v

# --- 1. environment commands -> /usr/local/bin --------------------------------
say "installing environment commands…"
sudo install -m 755 "$REPO/env/setup_pentest_env"      /usr/local/bin/setup_pentest_env
sudo install -m 755 "$REPO/env/md2pdf_reportgen"       /usr/local/bin/md2pdf_reportgen
sudo install -m 755 "$REPO/env/toggle-terminal-logging" /usr/local/bin/toggle-terminal-logging

# --- 2. ReconX launchers -> /usr/local/bin (symlinks track repo updates) ------
say "linking ReconX (recon, recon-exam, admap)…"
sudo ln -sf "$REPO/reconx/recon"      /usr/local/bin/recon
sudo ln -sf "$REPO/reconx/recon-exam" /usr/local/bin/recon-exam
sudo ln -sf "$REPO/reconx/admap"      /usr/local/bin/admap
chmod +x "$REPO/reconx/recon" "$REPO/reconx/recon-exam" "$REPO/reconx/admap" \
         "$REPO/reconx/reconx.py" "$REPO/reconx/admap.py" 2>/dev/null || true

# --- 3. exam-harness scripts (rx.sh, proof.sh, …) on PATH via a wrapper dir ---
if [ -d "$REPO/exam-harness/scripts" ]; then
  say "linking exam-harness scripts…"
  for s in "$REPO/exam-harness/scripts/"*.sh; do
    [ -f "$s" ] || continue
    chmod +x "$s" 2>/dev/null || true
    name="$(basename "${s%.sh}")"
    # Don't clobber the ReconX launchers installed just above: exam-harness
    # ships its own recon.sh (a simpler nmap wrapper), and a blanket link would
    # overwrite `recon` -> ReconX with `recon` -> recon.sh. The top-level README
    # documents `recon` as ReconX and exam-harness docs always call recon.sh by
    # path, so keep ReconX on `recon` and expose the wrapper as `recon-basic`.
    case "$name" in
      recon|recon-exam)
        warn "exam-harness $name.sh renamed to ${name}-basic (so it doesn't shadow the ReconX '$name')"
        name="${name}-basic" ;;
    esac
    sudo ln -sf "$s" "/usr/local/bin/$name"
  done
fi

# --- 4. shell wiring: ~/.myterm_settings (aliases, bloodhound-docker, logging) -
say "installing shell settings (~/.myterm_settings)…"
cp "$REPO/env/myterm_settings" "$HOME/.myterm_settings"
# point ReconX at the vault by default
grep -q 'RECONX_VAULT' "$HOME/.myterm_settings" || \
  echo "export RECONX_VAULT=\"$NOTES_DIR\"" >> "$HOME/.myterm_settings"
# make sure this user's shell sources it
rc="$HOME/.$(basename "${SHELL:-/bin/bash}")rc"
grep -q 'source $HOME/.myterm_settings' "$rc" 2>/dev/null || \
  echo 'source $HOME/.myterm_settings' >> "$rc"

# --- 5. Terminator layout -----------------------------------------------------
if [ -f "$REPO/env/terminator_config" ]; then
  mkdir -p "$HOME/.config/terminator"
  cp "$REPO/env/terminator_config" "$HOME/.config/terminator/config"
  ok "Terminator layout installed (terminator -l Pentesting)"
fi

# --- 6. working root ----------------------------------------------------------
mkdir -p "$HOME/ACTIVE_PENTEST"

# --- 7. methodology vault -----------------------------------------------------
if [ "$WITH_NOTES" -eq 1 ]; then
  if [ -d "$NOTES_DIR/.git" ]; then
    ok "notes vault already present ($NOTES_DIR)"
  else
    say "cloning methodology vault -> $NOTES_DIR …"
    git clone --depth 1 "$NOTES_REPO" "$NOTES_DIR" 2>/dev/null \
      && ok "vault cloned" \
      || warn "vault clone failed (no network / private?) — set RECONX_VAULT later, or --no-notes"
  fi
fi

# --- 8. optional packages -----------------------------------------------------
if [ "$WITH_APT" -eq 1 ]; then
  command -v terminator >/dev/null 2>&1 || { say "installing terminator…"; sudo apt-get install -y terminator >/dev/null 2>&1 || warn "terminator install skipped"; }
  command -v fuzzy-httpserver >/dev/null 2>&1 || { say "installing fuzzy-httpserver…"; pipx install fuzzy-httpserver >/dev/null 2>&1 || pip install --user fuzzy-httpserver >/dev/null 2>&1 || warn "fuzzy-httpserver skipped"; }
fi

echo
ok "done. Open a NEW terminal (loads the env), then:"
echo -e "   ${C}setup_pentest_env --oscp-exam targets.txt${N}   # build the exam workspace + IP vars"
echo -e "   ${C}recon-exam -u <user> -p <pass> --staged --parallel 3${N}   # two-pass AD recon"
echo -e "   ${C}recon <ip>${N}                                   # single box into its workspace"
echo -e "   ${C}admap dc01 -d <dom> -u <u> -p <pw> --run${N}     # AD attack-path playbook (mindmap)"
echo -e "   check missing tools with: ${C}$REPO/env/… / oscp-doctor${N} (optional)"
