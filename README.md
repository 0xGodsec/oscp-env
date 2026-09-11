# OSCP Exam Environment

My complete, self-contained OSCP setup — clone it on a fresh Kali box, run one
installer, and start the exam. It bundles the working environment, an automated
recon/enum engine, and the exam workflow into a single project.

```bash
git clone https://github.com/0xGodsec/oscp-env.git
cd oscp-env && ./install.sh          # add --no-notes to skip the vault clone
# open a new terminal, then you're ready
```

## What's inside

| Path | What it is |
|------|-----------|
| `env/` | The environment: `setup_pentest_env` (builds per-box workspaces + IP vars, with the recon hook baked in), `md2pdf_reportgen` (notes → PDF), `toggle-terminal-logging`, the shell settings (`myterm_settings`: aliases + `bloodhound-docker`), Terminator layout, and Obsidian note/report templates. |
| `reconx/` | **ReconX** — the recon/enum engine. Fast parallel port discovery, targeted per-service enumeration, automated web dir-busting, ranked findings, and `recon` / `recon-exam` launchers that file everything into the box workspace + notes. |
| `exam-harness/` | Exam-day helpers: proof/flag tally, report templates, listener/serve/bloodhound scripts, and a servable toolkit (`serve/`). |
| `install.sh` | One-command setup for a fresh machine. |

`install.sh` also clones the methodology vault (`0xGodsec/OSCP-Notes`) to
`~/Desktop/Notes` and points ReconX at it, so its findings link straight into
your notes.

## Exam-day flow

```bash
setup_pentest_env --oscp-exam targets.txt        # 3 AD + 3 standalone -> workspaces + IP vars
#   it then prompts for initial creds and can launch recon-exam automatically

recon-exam -u alex -p 'Passw0rd!' --staged --parallel 3
#   Pass 1 (quick) on every box at once  ->  learn domains  ->  /etc/hosts  ->
#   Pass 2 authenticated on the AD hosts ->  full -p-/UDP finishes in background
#   =>  ranked findings in each box's notes.md, and a PROGRESS.md triage table

recon <ip>                                        # or drive a single box manually
```

Every box gets: raw per-service output under `scans/reconx/<ip>/`, findings
merged into its `notes.md`, a ranked "look first" summary, and the project
`PROGRESS.md` telling you which machine to hit first. Then write the report
with `md2pdf_reportgen`.

See `reconx/README.md` for the full ReconX manual (`python3 reconx/reconx.py --man`),
and `CREDITS.md` for the open-source components this builds on.

> Authorized targets only: your own lab, HTB / PG / THM, or the OSCP exam. Recon
> and enumeration only — no automated exploitation.
