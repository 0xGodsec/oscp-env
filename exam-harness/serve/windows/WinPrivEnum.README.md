# WinPrivEnum

Read-only Windows **privilege-escalation enumeration** for authorized OSCP labs and
penetration-testing assessments. Single-file PowerShell, no external dependencies,
compatible with **Windows PowerShell 5.1** and **PowerShell 7+**.

It identifies potential local-privesc vectors and reports each with a **severity**,
a **confidence** level, concrete **evidence**, likely **impact**, **prerequisites**,
and **manual-validation** steps — then exports to TXT / JSON / CSV.

> It **never exploits anything** and **never changes system configuration**. A scanner
> match alone is never reported as "exploitable" — findings are graded by confidence so
> you can tell a proven misconfiguration from a lead that still needs confirming.

---

## Why another enum script

WinPEAS / PrivescCheck / PowerUp are excellent. WinPrivEnum is deliberately smaller and
OSCP-exam-shaped:

- **One `.ps1`, zero dependencies** — easy to transfer and run on a fresh shell.
- **Confidence-graded output** — `Confirmed` (observed misconfig) vs `Potential`
  (plausible, validate it) vs `Info`. Keeps you honest in the report.
- **ACLs checked against *your* token**, not "admin yes/no" — writability is decided by
  comparing each ACE against the SIDs in your current token (user + groups), so a
  `Users`/`Authenticated Users`/`Everyone` write grant is caught even as a low-priv user.
- **Every finding tells you how to validate it manually** — the point is to move you to
  the real exploitation step, not to auto-pwn.

---

## Installation / transfer to a target

No install. Copy the single file to the target and run it. Typical OSCP transfer from
this repo's `serve/` HTTP host (see `exam-harness/scripts/serve.sh`):

```powershell
# On the target (PowerShell):
iwr http://<KALI>:<PORT>/windows/WinPrivEnum.ps1 -OutFile C:\Windows\Temp\wpe.ps1
# or:  certutil -urlcache -f http://<KALI>:<PORT>/windows/WinPrivEnum.ps1 C:\Windows\Temp\wpe.ps1
```

If script execution is restricted, run it for this process only (does not change machine
policy):

```powershell
powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\wpe.ps1
# or load into memory:
iex (iwr http://<KALI>:<PORT>/windows/WinPrivEnum.ps1 -UseBasicParsing).Content
```

---

## Usage

```
.\WinPrivEnum.ps1 [-Quick|-Full] [-OutputDir <dir>] [-Format TXT,JSON,CSV,ALL]
                  [-MinSeverity Info|Low|Medium|High|Critical] [-NoColor] [-Help]
```

| Option         | Meaning |
|----------------|---------|
| `-Full`        | **(default)** Every check, incl. bounded credential file search + software inventory. |
| `-Quick`       | Fast triage; skips the recursive credential search and full software inventory. |
| `-OutputDir`   | Where to write reports. Default: `.\WinPrivEnum_<timestamp>\`. |
| `-Format`      | `TXT`, `JSON`, `CSV`, or `ALL` (default). Console output is always shown. |
| `-MinSeverity` | Console display floor. Exports always contain **every** finding. |
| `-NoColor`     | Disable coloured output (for piping / dumb terminals). |
| `-Help`        | Usage and exit. |

### Examples

```powershell
.\WinPrivEnum.ps1                                   # full run, all exports, timestamped dir
.\WinPrivEnum.ps1 -Quick -Format JSON -OutputDir C:\Temp\wpe
.\WinPrivEnum.ps1 -MinSeverity High -NoColor        # only High/Critical on screen
```

---

## What it checks

**System** — OS / build / architecture, hostname, install + boot time, domain
membership, network interfaces; current user, elevation, integrity level; **group
memberships** (with privileged groups — Backup/Server/Print Operators, DnsAdmins,
Hyper-V Administrators, … — flagged with the escalation path each enables).

**Privilege escalation**
- Token privileges: `SeImpersonate`, `SeAssignPrimaryToken`, `SeDebug`, `SeBackup`,
  `SeRestore`, `SeTakeOwnership`, `SeLoadDriver`, `SeManageVolume`, `SeTcb`,
  `SeCreateToken` — each mapped to the primitive it enables.
- Unquoted service paths (flagged **High/Confirmed** only when an intermediate directory
  is actually writable by you; otherwise **Medium/Potential**).
- Weak service **binary** and **directory** permissions.
- Weak service **registry** permissions (ImagePath tamper).
- **Modifiable service object DACL** (`sc sdshow` → `SERVICE_CHANGE_CONFIG`/WriteDac/
  GenericAll granted to your token — the proper PowerUp-style config-tamper check).
- Inventory of **third-party services running as SYSTEM** (info — the tamper targets).
- Writable **scheduled-task** binaries/scripts.
- `AlwaysInstallElevated` (Critical only when **both** hives are set).
- Writable **autorun** entries: `Run`/`RunOnce` (HKLM + HKCU, incl. Wow6432Node) and the
  all-users **Startup** folder.
- Writable directories on `PATH` (DLL / binary planting leads).
- UAC configuration (`EnableLUA`, `LocalAccountTokenFilterPolicy`, …).
- Other security settings: **WDigest `UseLogonCredential`** (cleartext creds in LSASS),
  **LSA `RunAsPPL`** (LSASS protection status), **Defender status + writable AV
  exclusions** (payload-drop leads).
- Kernel / patch **leads** from build + hotfix inventory (explicitly *not* a vuln claim —
  feed to `wesng` / Watson).
- **Third-party running drivers** (info — candidates for BYOVD / loldrivers.io matching).

**Credential exposure** — PowerShell history, `cmdkey` saved-credential metadata,
unattend / sysprep files, Winlogon autologon password, **readable SAM/SYSTEM/SECURITY
hive backups** (RegBack/Repair — skips empty 1803+ stubs), **application credential stores
in the registry** (PuTTY, WinSCP, RealVNC/TightVNC/TigerVNC, SNMP communities, OpenSSH
agent), and (in `-Full`) a **bounded** search of common config locations for
credential-looking tokens. It only inspects known config/credential locations and never
collects unrelated personal data.

**Applications & processes** — installed-software inventory (`-Full`), and processes
running as SYSTEM/Administrator whose on-disk binary is writable by you.

---

## Output model

Each finding carries:

```
Severity    Critical | High | Medium | Low | Info
Confidence  Confirmed | Potential | Info
Category    System | Privilege | Service | ScheduledTask | Registry | Autorun |
            DLLHijack | UAC | Kernel | Driver | Credential | Software | Process
Evidence    what was observed (paths, ACE grants, privilege state, …)
Impact      what it buys an attacker
Prereq      conditions needed to exploit it
Validate    the manual step to confirm before you claim it
```

Console shows a colour-coded findings list, an **executive summary** (counts by severity
+ run stats), and a **prioritised** top-vector list (Critical/High, confirmed first).
Exports:

- **JSON** — full structured report incl. run metadata and per-check errors.
- **CSV** — one row per finding (easy to paste into notes / a report).
- **TXT** — human-readable, report-ready.

---

## Sample output (abridged)

```
==========================================================================
  FINDINGS
==========================================================================

[CRITICAL] (Confirmed) AlwaysInstallElevated enabled (both hives)
  Category   : Registry
  Evidence   : HKLM=1  HKCU=1
  Impact     : Any .msi installs as SYSTEM. Craft an MSI payload for SYSTEM code exec.
  Validate   : Build a benign MSI (msfvenom /msi) and confirm it runs elevated in the lab.

[HIGH] (Confirmed) Privilege held: SeImpersonatePrivilege
  Category   : Privilege
  Evidence   : SeImpersonatePrivilege  Enabled  [State: Enabled]
  Impact     : Token impersonation -> Potato family (PrintSpoofer/GodPotato) for SYSTEM.
  Validate   : Confirm the primitive manually; do not assume success from the flag alone.

==========================================================================
  EXECUTIVE SUMMARY
==========================================================================
  Critical : 1
  High     : 1
  ...
  Prioritised vectors:
   1. [Critical/Confirmed] AlwaysInstallElevated enabled (both hives)
   2. [High/Confirmed] Privilege held: SeImpersonatePrivilege
```

---

## Limitations

- Local **privesc enumeration** only — not AD/domain, web, or remote enumeration.
- Kernel/patch output is a **lead**, never a vulnerability verdict. Confirm the CVE and
  test a PoC before claiming exploitability.
- Writability is judged from ACLs against your current token. It cannot model every
  edge case (e.g. privileges that would let you *rewrite* an ACL you don't yet have) —
  always confirm with `icacls` before acting.
- The credential file search is **bounded** (curated roots, `-Depth 4`, file-size and
  hit caps) for speed and to avoid trawling unrelated data; it is not exhaustive.
- Some checks need elevation to see everything; without it they degrade gracefully
  (skipped with a note) rather than failing.

## Optional integrations (not required, not bundled)

- `wesng` / Watson — feed the build + hotfix list for kernel-exploit shortlisting.
- WinPEAS / PrivescCheck — broader coverage if you want a second opinion.

## Legal

For **authorized** testing only — OSCP/PEN-200 labs, Proving Grounds, HTB, and
engagements you have written permission to test. Read-only; no exploitation; no config
changes. You are responsible for staying in scope.
