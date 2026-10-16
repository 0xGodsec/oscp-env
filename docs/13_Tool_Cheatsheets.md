# 🧰 oscp-env Tool Cheatsheets

One-page quick reference for **every command the kit installs**. These are the
*kit's own* tools (unlike `10_Commands_Quick_Reference`, which is general
pentest commands). Grounded in each tool's actual flags.

> Authorized targets only — your own lab, HTB/PG/THM, or the OSCP exam. ReconX
> and `admap` orchestrate standard **enumeration** only; exploitation is printed,
> never auto-run.

## Installed command names (after `./install.sh`)

| Command | Source | What it is |
|---|---|---|
| `setup_pentest_env` | `env/` | build the exam workspace + IP vars |
| `recon` | `reconx/recon` | ReconX engine launcher (per box) |
| `recon-exam` | `reconx/recon-exam` | two-pass recon across the whole project |
| `admap` | `reconx/admap` | AD attack-path assistant (mindmap playbook) |
| `rx` | `exam-harness` | ReconX wrapper → `targets/<name>/scans/reconx` |
| `recon-basic` | `exam-harness` (`recon.sh`) | simple nmap→web wrapper *(renamed so it doesn't shadow `recon` — see B12)* |
| `ad-fastpath` `ad-secretsdump` `gen-hosts` `bloodhound` | `exam-harness` | AD helpers |
| `serve` `listener` `logsession` `oscp-layout` `newtarget` `proof` | `exam-harness` | infra / evidence |
| `md2pdf_reportgen` `md2report` | `env/` + `exam-harness` | report → PDF |
| `toggle-terminal-logging` | `env/` | toggle the auto-logging block |

---

## `setup_pentest_env` — workspace + IP vars
```bash
setup_pentest_env --oscp-exam targets.txt   # 6 IPs: DC01/MS01/MS02 (AD) + T1/T2/T3; exports ALL 6
setup_pentest_env targets.txt               # file of  x.x.x.x  or  x.x.x.x:VARNAME  → IP1.. / named vars
setup_pentest_env                           # interactive IP entry
setup_pentest_env --help
```
Writes `~/.my_penenv_settings` (sourced by every shell), builds `~/ACTIVE_PENTEST/<proj>/`, then offers to collect creds and launch `recon-exam`.

## `recon` / `reconx.py` — the recon-enum engine
```bash
recon <target|var> [flags]          # IP, hostname, or a setup_pentest_env var (dc01/t1/…)
python3 reconx/reconx.py <ip> [flags]
```
| Flag | Use |
|---|---|
| `--quick` / `--mode quick\|full\|deep` | top-1000 fast / default / + heavy vuln scripts |
| `--web` | deep web pass: dir-brute (ferox→gobuster→ffuf) + nikto + **vhost fuzz** |
| `--ad` | AD-only re-enum, reuse cached ports (got-a-cred, re-hit DC) |
| `-u -p / -H / -d` `--local-auth` | authenticated enum (SMB/WinRM/LDAP/MSSQL/SSH/PG) |
| `--spray` | one credential across a CIDR (SMB/WinRM); confirm lockout first |
| `--bloodhound` | full `bloodhound-python -c All` in background |
| `--resume` | pick up an interrupted/crashed scan |
| `--dry-run` | print the command plan, run nothing (ports shown are a `(sample)`) |
| `--no-udp` `--no-scripts` `--no-web` `--no-rustscan` `--no-exploit-search` | trim phases |
| `--top-ports N` `--parallel N` `--workers N` `--web-timeout S` `-v` | tuning |
| `-o DIR` / `--workspace DIR` | output dir / PakCyberbot box (flat: `DIR/scans/reconx/NOTES.md`) |
```bash
python3 reconx/reconx.py --man        # full manual
```

## `recon-exam` — two-pass project recon
```bash
recon-exam -u alex -p 'Pw!' --staged --parallel 3
#  Pass1 quick-scan every box → learn domains → /etc/hosts → Pass2 authed on the AD set
recon-exam                                  # no creds: Pass 1 + /etc/hosts only
recon-exam -u svc -H <LM:NT> -d corp.local  # pass-the-hash
recon-exam --targets 10.129.1.5,10.129.1.6  # ad-hoc list (ignore saved vars)
recon-exam --pass1-only | --no-hosts | --yes | --dry-run
```
Writes a triage table to `~/ACTIVE_PENTEST/<proj>/PROGRESS.md` + per-box `notes.md`.

## `admap` — AD attack-path assistant
Maps *what you currently hold* to the Orange Cyberdefense AD mindmap and prints a ranked, copy-paste playbook. `[ENUM]`=read-only (auto-runnable); `[SPRAY]`/`[MANUAL]`=printed only.
```bash
admap dc01 --anon                                   # no creds → outsider playbook
admap dc01 -d corp.local --users users.txt          # have usernames → spray / AS-REP targets
admap dc01 -d corp.local -u alex -p 'Pw!' --dc-ip <dc> --run   # creds + run the read-only ENUM
admap ms01 -u administrator -H <lm:nt> --local-admin           # PtH, already local admin
admap dc01 -d corp.local -u alex -p pw --dry-run   # plan only  ·  admap dc01 --all  # full catalog
```
Access flags: `--anon` `--local-auth` `--local-admin` `--domain-admin`. Output + `ad_playbook.md` to `-o DIR` (`--no-md` to skip).

## `rx` — ReconX into a box workspace (exam-harness)
```bash
rx <name> <target> [reconx flags…]   # output + NOTES.md → targets/<name>/scans/reconx/<target>/
rx box1 10.129.x.x --quick
rx dc01 10.129.x.x -u alex -p 'Pw!' -d corp.htb --bloodhound
```

## `recon-basic` — simple nmap + web wrapper
```bash
recon-basic <ip> [name]    # full TCP sweep → -sVC on open ports → whatweb+feroxbuster on web ports
```

## AD post-compromise helpers
```bash
# Fast-path: null enum + kerbrute userenum + AS-REP (+ Kerberoast/BloodHound/crack with creds)
ad-fastpath -d corp.local -i <DC>                      # unauth
ad-fastpath -d corp.local -i <DC> -u bob -p 'Pw1' -c   # +Kerberoast, auto-hashcat(rockyou)
ad-fastpath -d corp.local -i <DC> -u bob -p 'Pw1' -b   # +BloodHound     ·  -s = spray -U list with -p
#   -U userlist  -H nthash  -n workspace-name

# Secretsdump (DCSync / local SAM) → parse → optional lateral spray
ad-secretsdump -t <DC> -d corp.local -u Administrator -p 'DAPass!'     # DCSync
ad-secretsdump -t <host> -u Administrator -H <nthash> -l               # local SAM via PtH
ad-secretsdump -t <DC> -d corp.local -u adm -p 'Pw' -S hosts.txt       # +spray recovered hashes

# Build hosts.txt for -S / netexec
gen-hosts -r 10.129.x.0/24 -x <your-ip>    # ping-sweep (-A TCP sweep, -P proxychains)
gen-hosts -f                               # harvest from saved nmap scans

# BloodHound CE in Docker (UI :8080)
bloodhound start | stop [-v] | status | pw
```

## Infra, evidence & scoring
```bash
serve [port]                 # HTTP delivery (updog/fuzzy/python); prints wget+certutil one-liners (def :7890)
listener [port]              # rlwrap nc -lvnp (default 443)
logsession [name]            # fully-logged (script) shell; replay: scriptreplay -t <timing> <log>
oscp-layout [session]        # tmux: serve | listener | work
newtarget <name> <ip>        # scaffold a box dir + notes.md

# Flag capture (flag + IP in ONE screenshot) + running tally
proof -o linux | windows                               # print on-target capture one-liners
proof -n box1 -i <ip> -t local|proof -f <32-hex>       # record a flag
proof -l                                               # tally + rough points

# Exam scoreboard + 23h45m clock (root=full, foothold=half)
reconx exam init OSCP-YYYY-MM-DD --vault-note '~/Desktop/Notes/OSCP Exam.md'
reconx exam start
reconx exam add <ip> --points 20 [--set AD --os ad]
reconx exam set <ip> --status todo|recon|foothold|root
reconx exam status | list | use <name> | note
```

## Reporting
```bash
md2pdf_reportgen -i            # one-time: install pandoc/xelatex/eisvogel
md2pdf_reportgen report.md     # → styled PDF (eisvogel, TOC, numbered)
md2pdf_reportgen report.md -z  # + 7z zip, OSCP-OS-XXXXX name, md5 (submission-ready)
md2report report.md [-d]       # no-pandoc alternative (weasyprint; -d also .docx)
```

## Shell logging
```bash
toggle-terminal-logging        # enable/disable the auto-`script` logging block in ~/.myterm_settings
```

---

### The 5 commands you'll live in
```bash
setup_pentest_env --oscp-exam targets.txt        # load the 6 IPs + workspace
recon-exam -u u -p 'p' --staged --parallel 3     # two-pass recon → PROGRESS.md
rx <box> <ip> [--web | --ad | -u u -p p -d dom]  # drive a single box
admap <dc> -d <dom> -u u -p p --run              # AD attack-path playbook
proof -n <box> -i <ip> -t local|proof -f <flag>  # bank each flag + tally
```
