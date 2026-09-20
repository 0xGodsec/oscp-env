# reconx

A lean, fast, accurate reconnaissance orchestrator — an **AutoRecon alternative**
built around OSCP methodology. It discovers ports fast, confirms them for
accuracy, runs *targeted* per-service enumeration concurrently, then prints a
**ranked "look at this first" summary** instead of burying you in 200 files.

> Authorized targets only: your own lab, HTB / PG / THM, or written permission.

## Quickstart

```bash
# 1. Install the launchers (optional; matches PakCyberbot's /usr/local/bin pattern)
sudo ln -sf "$PWD/recon"      /usr/local/bin/recon
sudo ln -sf "$PWD/recon-exam" /usr/local/bin/recon-exam
sudo cp integration/setup_pentest_env /usr/local/bin/setup_pentest_env   # PakCyberbot hook
```

**Scan one box** (standalone — no PakCyberbot needed):

```bash
python3 reconx.py 10.10.10.10            # full pipeline -> ranked summary + reconx-results/
python3 reconx.py 10.10.10.10 --quick    # top-1000 ports, fast
```

**Inside the PakCyberbot OSCP environment** (recon lands in the box's workspace + notes.md):

```bash
recon 10.10.10.10          # one box -> ~/ACTIVE_PENTEST/<box>/{scans/reconx,notes.md}
recon-exam                 # every target in the project: unauth pass + /etc/hosts + triage
recon-exam -u alex -p 'Pw!' --staged --parallel 3
#   two-pass AD flow: quick scan of all boxes at once -> learn domains -> /etc/hosts ->
#   authenticated pass on the AD hosts -> full -p-/UDP finishes in the background
```

**What you get, per box:** raw per-service output under `scans/reconx/<ip>/`, findings merged
into `notes.md`, a ranked "look first" summary, and a project `PROGRESS.md` triage table.

See [`integration/`](integration/) for the PakCyberbot `setup_pentest_env` hook, and
`python3 reconx.py --man` for the full manual.

## Why this instead of AutoRecon

| Problem with heavy scanners | What reconx does |
|---|---|
| Dumps hundreds of files; you drown | Ranks findings by severity, tells you what matters |
| Slow (UDP + full wordlists on everything) | Lean curated commands per service; heavy stuff is opt-in |
| Silent failures look like "nothing there" | Flags missing tools and degrades gracefully |
| Hard to hack mid-exam | Single Python file, stdlib only, readable |

It's a **lean orchestrator**, not a full clone: fast discovery + the enumeration
you'd run anyway, in parallel — you still do the thinking.

## Requirements

- Python 3.8+ (standard library only — nothing to `pip install`)
- Optional external tools (each degrades gracefully if absent):
  `rustscan`, `nmap`, `enum4linux-ng`/`enum4linux`, `nxc`/`netexec`/`crackmapexec`, `smbclient`,
  `rpcclient`, `ldapsearch`, `snmpwalk`, `onesixtyone`, `showmount`, `dig`,
  `curl`, `redis-cli`, `smtp-user-enum`, `psql`, `openssl`, `ncat`/`nc`,
  `searchsploit`, `impacket` (`GetUserSPNs`/`GetNPUsers`, for Kerberoast /
  AS-REP roast cross-checks), `bloodhound-python`/`bloodhound-ce-python`

On Kali these are mostly preinstalled. reconx prints which it found and which it's skipping.

## Usage

```bash
python3 reconx.py --man                       # full manual: modes, all flags, examples
python3 reconx.py 10.10.10.10                 # single host, full pipeline
python3 reconx.py 10.10.10.10 --quick         # top-1000 ports, fast
python3 reconx.py 10.10.10.0/24 --ping-sweep  # sweep a subnet first
python3 reconx.py target.htb -o loot/         # custom output dir
python3 reconx.py 10.10.10.10 --web           # deep web re-enum (dir-brute + nikto), reuses cached ports
python3 reconx.py 10.10.10.10 --dry-run       # print the command plan, run nothing
python3 reconx.py 10.10.10.10 --resume        # pick up an interrupted scan where it left off
```

> Initial scans **fingerprint** web ports only (whatweb + root grab) to stay
> fast — directory brute-forcing moved behind `--web`, a web-focused deep
> re-enum (feroxbuster/gobuster + nikto) that reuses the earlier scan's ports.

Handy flags: `--no-udp`, `--no-scripts` (skip nmap `-sC`), `--no-rustscan`
(force built-in scanner), `--top-ports N`, `--parallel N`,
`-v` (echo every command), `--no-color`, `--resume` (skip jobs already
completed in `<outdir>/<host>/`, so a Ctrl-C or crash mid-scan doesn't cost
you the work already done).

### Authenticated mode (once you have a credential)

Feed reconx a credential and the SMB/WinRM/LDAP/MSSQL/SSH/Postgres modules
re-run *authenticated* — checking access, admin (`Pwn3d!`), shares, users, and
AD roasting, and printing the exact follow-up command (evil-winrm, xfreerdp,
BloodHound) when a login works.

```bash
reconx dc01.corp.htb -u alex.turner -p 'Passw0rd!' -d corp.htb   # domain creds
reconx 10.10.10.5 -u admin -H <LM:NT> --local-auth               # pass-the-hash
reconx 10.10.10.0/24 -u svc -p 'S3cret!' --spray                 # spray one cred
reconx dc01.corp.htb -u alex.turner -p 'Passw0rd!' -d corp.htb --bloodhound  # + full BloodHound collection
reconx dc01.corp.htb -u alex.turner -p 'Passw0rd!' -d corp.htb --ad          # fast AD re-enum, reuse cached ports
```

Credential flags: `-u/--user`, `-p/--pass`, `-H/--hash` (NTLM PtH),
`-d/--domain`, `--local-auth` (local account, not domain), `--spray` (test the
**one** credential across every host in a CIDR via SMB/WinRM), `--bloodhound`
(once authenticated to LDAP, run a full `bloodhound-python -c All` collection
in the background — needs `bloodhound-python`/`bloodhound-ce-python`
installed; without the flag reconx just prints the manual command to run).

`--ad` is the "got a cred, re-hit the DC" shortcut: it **reuses the ports and
services** from the target's prior-run state file (falling back to a quick
DC-port probe if there's no cache), skips general discovery and every non-AD
module, and runs **only** the AD suite (SMB/LDAP/Kerberos/DNS/WinRM) with the
`-u/-p/-H/-d` credential — no second full port scan. Run it after an initial
scan surfaces a credential; without creds it degrades to unauthenticated
null/guest AD enum and warns.

> Credential reuse is the fastest path from foothold to root. reconx sprays a
> **single** credential (never a list) and stops on `STATUS_ACCOUNT_LOCKED_OUT`,
> but you should still confirm the lockout policy before spraying a domain
> account. Authenticated checks need **netexec** (`nxc`) installed.

## How it works

1. **Discovery** — rustscan if present, else a built-in async TCP connect sweep
   (full 65535 by default). Fast. Both find ports by firing bursts of
   connections, which a rate-limiting host or firewall can silently drop —
   leaving an empty *or a partial* port list that still looks like a real
   result. reconx defends against that:
   - If the first pass finds 0 ports, it retries once at a much lower
     concurrency before deciding the host is down.
   - On bounded scopes (`--quick` / `--top-ports`) an nmap confirmation pass is
     cheap, so reconx always runs it and unions in any port the fast sweep
     missed (it warns when nmap recovers ports the fast sweep dropped).
   - If everything still comes up empty, nmap gets the last word — its adaptive
     timing and retransmission survive throttling that defeats a raw sweep.
   - Full-range (`-p-`) keeps the fast sweep as the result (an nmap `-p-`
     confirm would cost minutes) and only falls back to nmap on 0 ports; re-run
     with `--quick`/`--top-ports` if you suspect a throttled full scan.
2. **Accuracy pass** — `nmap -sCV` on *confirmed* ports for real service/version,
   with a top-100 UDP scan in parallel.
3. **Targeted enumeration** — dispatches per-service modules concurrently:
   - **SMB/AD** (139/445/389/88/135): netexec shares/users/groups/policy + `--rid-brute` over null & guest sessions, enum4linux-ng, smbclient, ldapsearch anon dump, DC detection; *authenticated* adds full netexec enum (sessions/disks/computers/LAPS + `gpp_password`/`enum_av` modules), share **content spidering** (`spider_plus`), and — with confirmed admin — `--sam`/`--lsa`/`--dpapi`/`--ntds` dumping and `-x` command-execution proof. LDAP authed runs the full AD sweep: asrep/kerberoast, delegation, weak-UAC accounts, gMSA, `adcs`/ESC, `maq`, user-description creds
   - **Remote access** (21/22/23/3389/5985/5900): FTP anon (+nxc `--ls`), SSH NSE + netexec `--sudo-check`/exec, RDP NTLM info + nxc banner, WinRM banner→(authed) dump+exec, VNC no-auth detection
   - **DB & misc** (1433/5432/6379/161/25/53/2049): MSSQL (auth + sa/blank sweep, authed `--query`/`--rid-brute`/dump/xp_cmdshell), **PostgreSQL** (default-cred sweep + psql probe), Redis, SNMP walk, SMTP user-enum, NFS exports (+nxc `--shares`), DNS
   - **Web** (80/443/8080/8000/8443/8888/3128/9200/5000/8081): an initial scan **fingerprints only** (whatweb + root grab) — the slow directory brute is left out so scans stay fast. Re-run with `--web` for the deep pass (feroxbuster→gobuster dir-brute + nikto), a web-focused re-enum that reuses the earlier scan's ports just like `--ad`. `--no-web` skips web entirely

   > netexec is used across **every** protocol it supports. Read-only enumeration
   > runs whenever the service is up; credential **dumping** and **command
   > execution** only fire once you supply working creds (and, for the loudest
   > paths — `--ntds`, `-x` — only after admin/`Pwn3d!` is confirmed).
   - **Mail** (110/995 POP3, 143/993 IMAP): NSE capabilities + banner/CAPABILITY grab (TLS-aware via openssl), cred-reuse hints
4. **Findings engine** — regex rules classify output into CRITICAL / HIGH /
   MEDIUM / INFO, deduped and ranked. A filename heuristic also ranks juicy
   files out of the authenticated share-spider inventory (private keys / `.kdbx`,
   GPP `Groups.xml` / `unattend.xml` / `web.config` → CRITICAL; `.env` / creds /
   `*.ovpn` → HIGH; backups & scripts → MEDIUM), naming the share and path — by
   filename only, the files themselves are never opened.
5. **Output** — colored terminal summary + ranked findings + suggested next
   steps, plus a per-host `scans/` tree and a `NOTES.md` for your report.

## Output layout

```
reconx-results/
└── 10.10.10.10/
    ├── scans/        rustscan, nmap service, nmap udp
    ├── smb/          netexec, enum4linux-ng, smbclient
    ├── ldap/         rootdse, anon dump
    ├── ftp/ ssh/ snmp/ nfs/ ...
    └── NOTES.md      ports table + ranked findings, ready for your notes
```

## Extending it

Add a service module: write `async def enum_x(host, port, runner, args, findings)`,
run commands via `runner.run(cmd, outfile, label)`, append `Finding(...)` objects,
then wire it into `register_service_jobs()`. Add a detection: append a
`(severity, regex, service, message)` tuple to `FINDING_RULES`. That's the
whole extension surface.

## Automated two-pass exam recon (`recon-exam`)

### recon-exam speed & triage flags

- `--staged` — run a fast top-1000 pass now (start working in ~30s), then a full
  `-p-` + UDP scan continues **in the background** and refreshes each box's notes
  when done. Best of both: speed now, completeness later.
- `--parallel N` — scan N boxes at once in Pass 1 (default 1). Per-host output is
  captured to `scans/reconx/<ip>/recon-exam_pass1.log`; a one-line result prints as
  each host finishes. Great for a 3-box AD set: `recon-exam -u alex -p 'Pw!' --parallel 3`.
- **Project triage dashboard** — after each pass, `recon-exam` prints a per-box table
  (OS, #ports, top finding, suggested first move) and writes `<project>/PROGRESS.md`,
  so you instantly know which machine to attack first.

Example exam-morning run:

```bash
recon-exam -u alex -p 'Passw0rd!' --staged --parallel 3
#  Pass 1 (quick) on 3 boxes at once -> triage table -> /etc/hosts ->
#  Pass 2 authed on the AD hosts -> full scans finish in the background
```



For an AD set where you start with initial creds, `recon-exam` runs the whole
flow across every target in the project:

```
Pass 1  unauthenticated ReconX on each IP, one by one
          -> learn the domain + hostname (LDAP/SMB/RDP/Kerberos)
/etc/hosts  offer to add "IP  host  host.domain  domain"  (asks Y/N)
Pass 2  authenticated ReconX (-u -p/-H -d) on the hosts that revealed a
          domain (the AD set); standalone boxes stay Pass 1 only
```

It reads the targets + project from `~/.my_penenv_settings` (what
`setup_pentest_env` wrote) and writes into each box's workspace. Creds are
optional — with none it does Pass 1 + `/etc/hosts` and stops.

```bash
recon-exam                              # no creds: Pass 1 + /etc/hosts
recon-exam -u alex -p 'Passw0rd!'       # full two-pass, domain auto-detected
recon-exam -u svc -H <ntlm-hash> -d corp.local --quick
recon-exam --dry-run                    # show the plan, run nothing
```

`setup_pentest_env` now (after the additive patch) asks for initial creds and
offers to launch `recon-exam` automatically — so on exam morning you load your
IPs, hand it the creds you were given, and both passes run into your PakCyberbot
notes. Skipping the prompt leaves PakCyberbot behaving exactly as before.

**Install** (updates the PakCyberbot command + adds the two launchers):

```bash
R=~/Desktop/OSCP-Notes-and-Environment
sudo cp "$R/pakcyberbots_OSCP_environment/setup_pentest_env" /usr/local/bin/setup_pentest_env
sudo ln -sf "$R/Tools/reconx/recon"       /usr/local/bin/recon
sudo ln -sf "$R/Tools/reconx/recon-exam"  /usr/local/bin/recon-exam
```

## PakCyberbot OSCP environment integration (recon engine)

ReconX plugs into PakCyberbot's OSCP environment as the **recon/enum engine** —
PakCyberbot stays the workflow; ReconX just does the fast parallel legwork and
files it where PakCyberbot already expects it. Nothing in PakCyberbot is
modified or duplicated.

**One command per box** (`recon`, in this directory):

```bash
setup_pentest_env --oscp-exam targets.txt   # PakCyberbot: makes the box + env vars
recon t1                                     # ReconX into the T1 workspace
recon dc01 -u alex -p 'Pw!' -d corp.htb --bloodhound   # authed AD box
recon 10.11.1.5 --quick                      # literal IP, fast top-1000
```

`recon` resolves the target and workspace **from PakCyberbot's own environment**:

- **Target** — an IP, or a PakCyberbot var name (`dc01 ms01 ms02 t1 t2 t3 ip1..`,
  from `~/.my_penenv_settings`). Omit it and the first defined exam IP is used.
- **Workspace** — the current box dir if you're in one, else `~/ACTIVE_PENTEST/$DIR_NAME`
  (set by `setup_pentest_env`), else `-w <dir>`.

It then runs ReconX and:

1. **Output** lands in the box's existing `scans/reconx/<target>/` — same `scans/`
   dir PakCyberbot scaffolds, not a new tree.
2. **Findings merge into the box's `notes.md`**, reusing PakCyberbot's template
   *in place*: fills the header (IP/OS/Date), appends open ports to the
   `## Ports / Services` table (deduped — your hand-added rows survive), and drops
   a marker-delimited **ReconX findings** block (host profile, ranked findings,
   `[[wikilinks]]`, next steps) above `## Foothold`. Re-runs refresh only that
   block; everything you typed by hand is never touched.
3. **Terminal logging** (`toggle-terminal-logging`) captures the run automatically —
   ReconX needs no special handling.
4. The filled `notes.md` flows straight into **`md2pdf_reportgen`** for the report,
   and complements `bloodhound-docker` (ReconX collects with `--bloodhound`; the
   Docker UI consumes it).

**Install** (match PakCyberbot's pattern — a symlink so updates are automatic):

```bash
sudo ln -sf "$PWD/recon" /usr/local/bin/recon
# optional convenience alias instead of a symlink:
echo "alias recon='python3 $PWD/recon'" >> ~/.myterm_settings
```

You can also call ReconX directly with `--workspace`:
`python3 reconx.py 10.11.1.5 --workspace ~/ACTIVE_PENTEST/box1`.

## Exam mode & Obsidian / PakCyberbot integration

Two optional companion modules (stdlib-only, drop them next to `reconx.py`):
`reconx_exam.py` (multi-target exam manager + time budget) and
`reconx_notes.py` (vault note generation). If either is missing reconx still
runs — the feature just switches off.

### Per-host notes (auto)

Every scan writes an enriched `NOTES.md` per host: YAML frontmatter,
host-profile callout, ports table, **wikilinks into your methodology vault**
picked from the open services (e.g. `[[SMB]]`, `[[Kerberoasting]]`,
`[[Linux Privilege Escalation]]`), ranked findings and suggested next steps.
Vault auto-detected from `$RECONX_VAULT` or `~/Desktop/Notes`.

### Exam manager

```bash
reconx exam init OSCP-2026-09-10 --vault-note "~/Desktop/Notes/OSCP Exam.md"
reconx exam start                          # start the 23h45m clock
reconx exam add 192.168.1.10 --points 20   # register a standalone box
reconx exam add 192.168.1.50 --points 40 --set AD --os ad
reconx exam status                         # live dashboard: score + budget left
reconx exam set 192.168.1.10 --status root # todo -> recon -> foothold -> root
```

Dashboard shows each target's OS, points, status and time-to-milestone, your
running score vs the pass mark, and how much of the exam clock remains.
Scoring is partial-credit: **root = full points, foothold/local = half**.
State lives in `~/.reconx/exams/<name>.json`; the current exam is remembered.

### Wiring a scan into the exam

```bash
reconx 192.168.1.10 --exam OSCP-2026-09-10 --points 20
# or just:  reconx 192.168.1.10     # auto-joins the *current* exam if one exists
```

When a scan finishes it registers/advances the target (→ `recon`), records its
OS + ports + top findings into the dashboard, and refreshes the vault exam
note. Add `--no-vault` to update the dashboard only.

### The vault exam note

Shaped like the PakCyberbot **Network Pentest Template** (CREDS.txt block,
Hashes, per-Machine sections, Attack Narrative). reconx owns only the recon
summary inside marker-delimited *managed blocks*; everything you type by hand
(creds, foothold story, flags) sits outside those markers and is **never
overwritten** on refresh. New machines get appended; existing ones are updated
in place.

## Exam-rules note

reconx only orchestrates standard enumeration tools — no automated *exploitation*,
no mass vulnerability scanning. That keeps it on the right side of the OSCP tool
policy, same category as AutoRecon. Always confirm against the current official
OSCP Exam Guide before your attempt.
