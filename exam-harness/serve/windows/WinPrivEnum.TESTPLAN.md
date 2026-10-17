# WinPrivEnum — Test Plan

Covers syntax, output generation, permission handling, cross-version compatibility, and
representative privilege-escalation scenarios. Authorized lab environments only.

## 0. Legend

- **Pre** = how to set up the condition (run in an elevated shell on a throwaway lab VM).
- **Expect** = what WinPrivEnum should report.
- Reset / snapshot the VM between destructive setup steps.

---

## 1. Static / platform tests (no Windows target needed)

| # | Test | Command | Expect |
|---|------|---------|--------|
| 1.1 | Syntax parses | `[Parser]::ParseFile(...)` (see below) | No parse errors |
| 1.2 | Help | `pwsh -File WinPrivEnum.ps1 -Help` | Usage printed, no errors, no enumeration |
| 1.3 | Non-Windows guard | run under PowerShell 7 on Linux/macOS | Banner + graceful "must run on Windows" message, clean exit |
| 1.4 | Finding model / dedup / exports | dot-source + inject findings (see below) | Duplicate dropped; TXT/JSON/CSV written and well-formed; severity-sorted |

Syntax check:
```powershell
$e=$null;$t=$null
[void][System.Management.Automation.Language.Parser]::ParseFile("$PWD\WinPrivEnum.ps1",[ref]$t,[ref]$e)
if($e){$e}else{'SYNTAX OK'}
```

Model/export smoke test (cross-platform, pure .NET):
```powershell
. .\WinPrivEnum.ps1 *> $null
$script:Findings.Clear(); $script:FindingKeys.Clear()
New-Finding -Category Registry -Title 'AlwaysInstallElevated enabled (both hives)' -Severity Critical -Confidence Confirmed -Evidence 'HKLM=1 HKCU=1'
New-Finding -Category Registry -Title 'AlwaysInstallElevated enabled (both hives)' -Severity Critical -Confidence Confirmed -Evidence 'HKLM=1 HKCU=1'  # dup
Show-ConsoleReport; Show-Summary
Export-Report -Dir $env:TEMP\wpe-test -Formats ALL
Get-Content $env:TEMP\wpe-test\*.json -Raw | ConvertFrom-Json   # must parse
```
*Status: executed on PowerShell 7 (Linux) — PASS (dedup=1, all three exports valid).*

---

## 2. Compatibility

| # | Test | Expect |
|---|------|--------|
| 2.1 | Windows PowerShell 5.1 (`$PSVersionTable.PSVersion.Major -eq 5`) | Runs; `Get-CimInstance`/`whoami` paths work; no `$IsWindows` errors |
| 2.2 | PowerShell 7+ on Windows | Same findings as 5.1; no `Get-WmiObject` dependency |
| 2.3 | `-NoColor` piped to file | No ANSI color codes in the file |
| 2.4 | Restricted ExecutionPolicy | `powershell -ExecutionPolicy Bypass -File ...` runs without changing machine policy |

---

## 3. Permission handling

| # | Test | Pre | Expect |
|---|------|-----|--------|
| 3.1 | Non-admin run | Run as a standard user | Warning that admin checks are skipped; run completes; no unhandled errors |
| 3.2 | Admin run | Run elevated | Registry/service ACL checks fully populate |
| 3.3 | Access-denied resilience | Standard user hits protected keys/files | Individual checks log a WARN, run continues, `ChecksFailed` increments |

---

## 4. Privilege-escalation scenarios

### 4.1 Token privileges
- **Pre:** Use an account/service context that holds `SeImpersonatePrivilege` (e.g. a
  service account, or `PsExec -s` for SYSTEM to sanity-check parsing).
- **Expect:** `High / Confirmed` "Privilege held: SeImpersonatePrivilege" with the
  Potato-family impact note. Disabled-but-present privileges → `Potential`.

### 4.2 Unquoted service path — writable (High/Confirmed)
- **Pre:**
  ```cmd
  sc create wpeunq binPath= "C:\Program Files\Vuln App\svc.exe" start= demand
  icacls "C:\Program Files\Vuln App" /grant Users:(OI)(CI)M
  ```
- **Expect:** `High / Confirmed` "Unquoted service path (writable intermediate dir): wpeunq",
  evidence lists the writable directory.

### 4.3 Unquoted service path — not writable (Medium/Potential)
- **Pre:** Same service without the `icacls` grant.
- **Expect:** `Medium / Potential` "Unquoted service path: wpeunq" — no writability claim.

### 4.4 Writable service binary (High/Confirmed)
- **Pre:**
  ```cmd
  sc create wpebin binPath= "C:\wpe\svc.exe"
  icacls C:\wpe\svc.exe /grant Users:M
  ```
- **Expect:** `High / Confirmed` "Writable service binary: wpebin" with the granted rights.

### 4.5 Writable service registry key (High/Confirmed)
- **Pre:** Grant `Users` write on `HKLM\SYSTEM\CurrentControlSet\Services\wpebin`
  (e.g. via `regedit` → Permissions, in the lab).
- **Expect:** `High / Confirmed` "Writable service registry key: wpebin".

### 4.6 Writable scheduled-task target (High/Confirmed)
- **Pre:**
  ```powershell
  schtasks /create /tn wpetask /tr "C:\wpe\task.bat" /sc minute /ru SYSTEM
  icacls C:\wpe\task.bat /grant Users:M
  ```
- **Expect:** `High / Confirmed` "Writable scheduled-task target: wpetask", RunAs SYSTEM.

### 4.7 AlwaysInstallElevated (Critical/Confirmed)
- **Pre:**
  ```cmd
  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
  reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
  ```
- **Expect:** `Critical / Confirmed`. Set only one hive → `Low / Info` (not exploitable).

### 4.8 Writable PATH directory (Medium/Potential — DLL hijack lead)
- **Pre:** `setx PATH "%PATH%;C:\wpe\pathdir" /M` and grant `Users:M` on `C:\wpe\pathdir`.
- **Expect:** `Medium / Potential` "Writable directory on PATH" with a Procmon-validation note.

### 4.9 UAC disabled
- **Pre:** `reg add HKLM\...\Policies\System /v EnableLUA /t REG_DWORD /d 0` (reboot).
- **Expect:** `Medium / Confirmed` UAC finding noting `EnableLUA=0`.

### 4.10 Autologon password
- **Pre:** Set `DefaultUserName` + `DefaultPassword` under Winlogon (lab only).
- **Expect:** `High / Confirmed` "Autologon password stored in registry" (value marked
  `<present>`, not dumped to console).

### 4.11 Credential-bearing config (Full mode)
- **Pre:** Drop `C:\inetpub\wwwroot\web.config` containing `password=Secret123`.
- **Expect:** `Medium / Potential` "Possible credentials in file: web.config" with the
  matched line; **not** reported in `-Quick`.

### 4.12 Unattend file
- **Pre:** Place a sample `C:\Windows\Panther\Unattend.xml` with a `<Password><Value>` node.
- **Expect:** `High / Confirmed` "Unattend file present" (hint that value may be base64).

### 4.13 Kernel/patch leads
- **Pre:** Any host.
- **Expect:** `Info` patch-level finding; if `< 5` hotfixes, an extra `Low / Potential`.
  Explicitly worded as a lead, never "exploitable".

### 4.14 Privileged group membership (High/Potential)
- **Pre:** `net localgroup "Backup Operators" <user> /add` (lab), re-login.
- **Expect:** `High / Potential` "Member of privileged group: Backup Operators" with the
  SeBackup/SeRestore impact note; plus an Info "Group memberships" listing.

### 4.15 Writable autorun binary (High/Confirmed)
- **Pre:**
  ```cmd
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v wpe /t REG_SZ /d "C:\wpe\run.exe"
  icacls C:\wpe\run.exe /grant Users:M
  ```
- **Expect:** `High / Confirmed` "Writable autorun binary: wpe", scope noted as HKLM.
  An HKCU equivalent → `Medium`.

### 4.16 Registry credential store (Medium/Potential)
- **Pre:** Create `HKCU\Software\SimonTatham\PuTTY\Sessions\lab` (any value).
- **Expect:** `Medium / Potential` "Credential store present: PuTTY saved sessions".

### 4.17 Third-party services as SYSTEM / drivers (Info)
- **Pre:** Any host with non-OS services/drivers (most lab VMs).
- **Expect:** Info "Third-party services running as SYSTEM (N)" and Info "Non-standard
  running drivers (N)" — leads only, no exploitability claim.

### 4.18 Negative / clean host
- **Pre:** Fully patched, hardened lab VM with none of the above.
- **Expect:** Only `Info` findings; summary shows 0 Critical/High; no false `Confirmed`.

---

## 5. Output verification

| # | Test | Expect |
|---|------|--------|
| 5.1 | `-Format JSON` | Single `.json`, parses via `ConvertFrom-Json`, contains metadata + findings + errors |
| 5.2 | `-Format CSV` | One header row + one row per finding; fields quoted/escaped |
| 5.3 | `-Format TXT` | Human-readable, severity-sorted |
| 5.4 | `-MinSeverity High` | Console shows only High/Critical; **exports still contain all** |
| 5.5 | Dedup | A condition matched twice appears once |
| 5.6 | Stats | Summary shows checks run/failed, finding counts, duration |

---

## 6. Regression checklist (run before committing changes)

1. `SYNTAX OK` from the parser test.
2. `-Help` prints with no errors.
3. Model/export smoke test (§1.4) passes.
4. At least one Windows VM run across PS 5.1 **and** 7 with scenarios 4.2, 4.4, 4.7, 4.10.
5. Non-admin run completes without unhandled exceptions (§3.1).
