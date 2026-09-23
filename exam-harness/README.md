# OSCP Exam Environment

Layout:
```
OSCP-Exam/
├── scripts/       newtarget.sh · recon.sh · serve.sh · listener.sh
├── serve/         HTTP-servable tool kit  (linux/ windows/ ad/)  + MANIFEST.sha256
├── targets/       one folder per box  (created by newtarget.sh)
├── report/        OSCP-Report-Template.md
├── cheatsheets/   OSCP-Cheatsheet.md
└── loot/          creds / hashes / dumps
```

## Exam-day flow
```
cd ~/Desktop/OSCP-Notes-and-Environment/OSCP-Exam
./scripts/serve.sh 7890 &                    # serve tools (default 7890, no sudo; pass 80 to use :80)
./scripts/newtarget.sh box1 10.10.10.10      # workspace + notes.md
./scripts/recon.sh 10.10.10.10 box1          # auto nmap + web enum
./scripts/listener.sh 443                     # catch shells
```
Fill in `targets/<box>/notes.md` as you go; copy into `report/` at the end.

## AD scripts
- `ad-fastpath.sh`   — enum + AS-REP + Kerberoast (+ spray/BloodHound/crack)
- `ad-secretsdump.sh` — DCSync / local SAM dump, parses hashes, sprays for lateral movement
- `gen-hosts.sh`     — builds `loot/hosts.txt` of live IPs (subnet scan or harvest saved scans) for `-S`
- `proof.sh`         — record local/proof flags into workspace + a points tally (`report/proof-tally.csv`); prints IP-visible capture commands
- `md2report.sh`     — convert final markdown report to PDF (+`-d` for DOCX); run before submitting
- `logsession.sh`    — logged shell (script transcript) for evidence backup
- `oscp-layout.sh`   — one-command tmux layout (serve|listener|work)
- `bloodhound.sh`    — start/stop BloodHound CE (Docker) to analyze AD data

## Notes
- `serve/` tools: linpeas, pspy64, winPEAS, nc.exe, chisel(+.exe, v1.10.1 matched),
  ligolo-agent(+.exe), mimikatz, PrintSpoofer64, GodPotato-NET4, RunasCs,
  SharpHound, PowerView/PowerUp/powercat.
- Install rlwrap for nicer shells:  `sudo apt install -y rlwrap`
- `serve.sh` auto-fills your `tun0` VPN IP in the printed download one-liners and
  prefers `updog` (adds a browser **upload** endpoint at `/upload` to pull loot
  back) → `fuzzy-httpserver` (typo-tolerant) → `python -m http.server`. For the
  upload endpoint:  `pip install updog`
- Verify kit integrity anytime:  `cd serve && sha256sum -c MANIFEST.sha256`
- Regenerate the manifest after adding/updating a tool (run from `serve/`):
  `find . -type f ! -name MANIFEST.sha256 | sort | xargs sha256sum > MANIFEST.sha256`
