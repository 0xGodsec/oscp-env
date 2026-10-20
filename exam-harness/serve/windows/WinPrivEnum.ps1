<#
.SYNOPSIS
    WinPrivEnum - Windows privilege-escalation enumeration for authorized OSCP labs
    and penetration-testing assessments.

.DESCRIPTION
    Read-only enumeration tool that identifies potential Windows privilege-escalation
    vectors and reports them with severity, confidence, evidence, impact, prerequisites
    and recommended manual-validation steps.

    The script NEVER modifies system configuration and NEVER attempts exploitation.
    Every finding is classified by confidence so that confirmed misconfigurations are
    distinguished from potential vectors and purely informational results. A scanner
    match alone is never reported as "exploitable".

    Compatible with Windows PowerShell 5.1 and PowerShell 7+. Runs without external
    dependencies. Handles non-administrator execution gracefully (checks requiring
    elevation are skipped with a note rather than erroring out).

.PARAMETER Quick
    Fast triage: skips the time-consuming recursive credential file search and the
    full installed-software inventory. Good first pass on a fresh shell.

.PARAMETER Full
    Runs every check including bounded recursive credential searches and the full
    software inventory. This is the default when neither -Quick nor -Full is given.

.PARAMETER OutputDir
    Directory to write exported reports into. Defaults to a timestamped folder under
    the current directory. The directory is created if it does not exist.

.PARAMETER Format
    One or more export formats: TXT, JSON, CSV, or ALL. Defaults to ALL. Console
    output is always shown regardless.

.PARAMETER NoColor
    Disable ANSI/console colour output (useful when piping to a file or a dumb term).

.PARAMETER MinSeverity
    Only display findings at or above this severity on the console: Info, Low, Medium,
    High, Critical. Exports always contain every finding. Default: Info.

.PARAMETER Help
    Show usage help and exit.

.EXAMPLE
    PS> .\WinPrivEnum.ps1
    Full enumeration, all export formats, into a timestamped folder.

.EXAMPLE
    PS> .\WinPrivEnum.ps1 -Quick -Format JSON -OutputDir C:\Temp\wpe
    Fast triage, JSON report only, into C:\Temp\wpe.

.EXAMPLE
    PS> .\WinPrivEnum.ps1 -MinSeverity High -NoColor | Out-File loot.txt
    Show only High/Critical findings, no colour, teed to a file.

.NOTES
    Authorized testing only. Read-only. No exploitation. No configuration changes.

    OSCP exam-safe: this is a read-only enumeration/reporting tool, not an
    automated-exploitation tool. It only finds and reports vectors and leaves all
    exploitation to the operator, so it is permitted on every exam target and does
    not count against the one-Metasploit-box rule. (Operational note: it is an
    unsigned custom script, so expect to bypass the execution policy and possibly
    AMSI/Defender to run it.)
#>

[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [switch] $Quick,
    [switch] $Full,
    [string] $OutputDir,
    [ValidateSet('TXT', 'JSON', 'CSV', 'ALL')]
    [string[]] $Format = @('ALL'),
    [switch] $NoColor,
    [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
    [string] $MinSeverity = 'Info',
    [switch] $Help
)

# ============================================================================
#region  Globals & constants
# ============================================================================

$script:Version       = '1.0.0'
$script:StartTime      = Get-Date
$script:Findings       = [System.Collections.Generic.List[object]]::new()
$script:FindingKeys    = [System.Collections.Generic.HashSet[string]]::new()
$script:Errors         = [System.Collections.Generic.List[object]]::new()
$script:ChecksRun      = 0
$script:ChecksFailed   = 0

# Severity ordering for filtering / sorting (higher = more severe).
$script:SevRank = @{ 'Info' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Critical' = 4 }

# Console colours per severity.
$script:SevColor = @{
    'Critical' = 'Red'
    'High'     = 'Magenta'
    'Medium'   = 'Yellow'
    'Low'      = 'Cyan'
    'Info'     = 'Gray'
}

# FileSystemRights / RegistryRights bits that represent the ability to write,
# change permissions, take ownership, or exercise generic write/all. Matching
# any of these against an ACE granted to the current principal flags the object
# as writable-by-me. (GenericWrite = 0x40000000, GenericAll = 0x10000000.)
$script:WriteMask = 0x00000002 -bor `  # WriteData / CreateFiles / SetValue
                    0x00000004 -bor `  # AppendData / CreateSubKey
                    0x00000010 -bor `  # WriteExtendedAttributes
                    0x00000100 -bor `  # WriteAttributes
                    0x00010000 -bor `  # Delete
                    0x00040000 -bor `  # ChangePermissions / WriteDAC
                    0x00080000 -bor `  # TakeOwnership
                    0x10000000 -bor `  # GenericAll
                    0x40000000         # GenericWrite

# $IsWindows is a read-only automatic variable on PS 6+, and absent on 5.1
# (which only ever runs on Windows). Derive our own flag without shadowing it.
$script:OnWindows = $true
$autoWin = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
if ($autoWin) { $script:OnWindows = [bool]$autoWin.Value }

#endregion

# ============================================================================
#region  Output helpers
# ============================================================================

function Write-Color {
    <# Colour-aware Write-Host wrapper that respects -NoColor. #>
    param(
        [string] $Text,
        [string] $Color = 'Gray',
        [switch] $NoNewline
    )
    if ($script:NoColor -or $NoColor) {
        Write-Host $Text -NoNewline:$NoNewline
    }
    else {
        Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
    }
}

function Write-Section {
    param([string] $Title)
    Write-Host ''
    Write-Color ('=' * 74) 'DarkCyan'
    Write-Color ("  {0}" -f $Title) 'White'
    Write-Color ('=' * 74) 'DarkCyan'
}

function Write-Log {
    <# Timestamped status line to the console (stderr-ish, not a finding). #>
    param(
        [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')]
        [string] $Level = 'INFO'
    )
    $ts = (Get-Date).ToString('HH:mm:ss')
    $color = switch ($Level) {
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'OK'    { 'Green' }
        default { 'DarkGray' }
    }
    Write-Color ("[{0}] [{1}] {2}" -f $ts, $Level, $Message) $color
}

#endregion

# ============================================================================
#region  Finding model
# ============================================================================

function New-Finding {
    <#
    .SYNOPSIS  Record a single finding (deduplicated).
    .DESCRIPTION
        Confidence levels:
          Confirmed - a concrete misconfiguration was observed (e.g. a service
                      binary is writable by the current user).
          Potential - a vector that is plausible but needs manual confirmation
                      (e.g. an unquoted path where writability could not be proven).
          Info      - context with no direct exploitability claim.
    #>
    param(
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
        [string] $Severity,
        [Parameter(Mandatory)]
        [ValidateSet('Confirmed', 'Potential', 'Info')]
        [string] $Confidence,
        [string]   $Evidence    = '',
        [string]   $Impact      = '',
        [string]   $Prerequisite = '',
        [string]   $Validation  = ''
    )

    # Deduplicate on category + title + evidence so repeated checks (or the same
    # object matched two ways) do not spam the report.
    $key = "{0}|{1}|{2}" -f $Category, $Title, $Evidence
    if (-not $script:FindingKeys.Add($key)) { return }

    $script:Findings.Add([pscustomobject]@{
        Category     = $Category
        Title        = $Title
        Severity     = $Severity
        Confidence   = $Confidence
        Evidence     = $Evidence
        Impact       = $Impact
        Prerequisite = $Prerequisite
        Validation   = $Validation
        SevRank      = $script:SevRank[$Severity]
    }) | Out-Null
}

function Invoke-Check {
    <#
    .SYNOPSIS  Run one check function with isolated error handling + stats.
    .DESCRIPTION
        A single failing check (missing cmdlet, access denied, unexpected data)
        must never abort the whole run. Failures are logged and counted.
    #>
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $Body
    )
    $script:ChecksRun++
    Write-Log "Running: $Name" 'INFO'
    try {
        & $Body
    }
    catch {
        $script:ChecksFailed++
        $script:Errors.Add([pscustomobject]@{ Check = $Name; Error = $_.Exception.Message }) | Out-Null
        Write-Log "Check '$Name' failed: $($_.Exception.Message)" 'WARN'
    }
}

#endregion

# ============================================================================
#region  Environment / capability helpers
# ============================================================================

function Test-CommandExists {
    param([Parameter(Mandatory)] [string] $Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Test-IsAdmin {
    <# True if the current token is elevated (member of local Administrators with
       an elevated integrity level). Safe on non-Windows (returns $false). #>
    if (-not $script:OnWindows) { return $false }
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Get-MyTokenSids {
    <# SIDs that represent "me": the user SID plus every group SID in the current
       token (this already includes Everyone / Authenticated Users / Users where
       applicable). Used to decide whether an ACE grants access to the caller. #>
    $sids = [System.Collections.Generic.HashSet[string]]::new()
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        [void]$sids.Add($id.User.Value)
        foreach ($g in $id.Groups) { [void]$sids.Add($g.Value) }
    }
    catch { }
    return $sids
}

function Test-PathWritableByMe {
    <#
    .SYNOPSIS  Does the current principal have write-ish access to a filesystem path?
    .DESCRIPTION
        Validates ACLs against the caller's own token SIDs rather than assuming
        admin == all. Returns a result object { Writable; GrantedTo; Rights } so
        callers can cite concrete evidence. Denies are respected: an explicit Deny
        ACE matching the caller suppresses a match.
    #>
    param([Parameter(Mandatory)] [string] $Path)

    $result = [pscustomobject]@{ Writable = $false; GrantedTo = ''; Rights = '' }
    if (-not $script:OnWindows) { return $result }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return $result }

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    catch { return $result }

    $mine = $script:MyTokenSids
    $matched = @()
    foreach ($ace in $acl.Access) {
        # Resolve the ACE identity to a SID for comparison.
        $sid = $null
        try {
            if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                $sid = $ace.IdentityReference.Value
            }
            else {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
        }
        catch { continue }

        if (-not $mine.Contains($sid)) { continue }

        $rightsInt = [int]$ace.FileSystemRights
        $hasWrite  = ($rightsInt -band $script:WriteMask) -ne 0

        if ($hasWrite) {
            if ($ace.AccessControlType -eq 'Deny') {
                # An explicit deny to me on write wins - stop and report not writable.
                return [pscustomobject]@{ Writable = $false; GrantedTo = ''; Rights = '' }
            }
            $matched += ("{0}:{1}" -f $ace.IdentityReference, $ace.FileSystemRights)
        }
    }

    if ($matched.Count -gt 0) {
        $result.Writable  = $true
        $result.GrantedTo = ($matched -join '; ')
        $result.Rights    = ($matched -join '; ')
    }
    return $result
}

function Get-ExeFromCommandLine {
    <# Extract the executable path from a service PathName / command line, stripping
       surrounding quotes and trailing arguments. Best-effort. #>
    param([string] $CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cl = $CommandLine.Trim()
    if ($cl.StartsWith('"')) {
        $end = $cl.IndexOf('"', 1)
        if ($end -gt 1) { return $cl.Substring(1, $end - 1) }
    }
    # Unquoted: take up to the first ".exe" token (case-insensitive) if present,
    # else up to the first space.
    $m = [regex]::Match($cl, '^(.*?\.exe)\b', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    $sp = $cl.IndexOf(' ')
    if ($sp -gt 0) { return $cl.Substring(0, $sp) }
    return $cl
}

#endregion

# ============================================================================
#region  Phase 1 - System enumeration
# ============================================================================

function Invoke-SystemEnum {
    Write-Section 'SYSTEM'

    Invoke-Check 'OS / build / architecture' {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $arch = $env:PROCESSOR_ARCHITECTURE
        $ev = @(
            "Host     : $($env:COMPUTERNAME)"
            "OS       : $($os.Caption) ($($os.Version), build $($os.BuildNumber))"
            "Arch     : $arch"
            "Installed: $($os.InstallDate)"
            "Boot     : $($os.LastBootUpTime)"
            "Domain   : $(if ($cs) { $cs.Domain } else { 'n/a' })  (PartOfDomain=$(if ($cs) { $cs.PartOfDomain } else { '?' }))"
        ) -join "`n"
        New-Finding -Category 'System' -Title 'Operating system details' -Severity 'Info' `
            -Confidence 'Info' -Evidence $ev `
            -Impact 'Baseline for kernel-exploit and patch-gap assessment.'
    }

    Invoke-Check 'Current user / integrity / privileges' {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $admin = Test-IsAdmin
        $integrity = 'Unknown'
        $privs = @()
        $groups = @()
        if (Test-CommandExists 'whoami.exe') {
            $g = (whoami /groups) 2>$null
            $label = $g | Select-String 'Mandatory Label'
            if ($label) {
                if ($label -match 'High')     { $integrity = 'High' }
                elseif ($label -match 'System') { $integrity = 'System' }
                elseif ($label -match 'Medium') { $integrity = 'Medium' }
                elseif ($label -match 'Low')    { $integrity = 'Low' }
            }
            $privs = (whoami /priv) 2>$null
            $groups = (whoami /groups) 2>$null
        }
        $ev = @(
            "User      : $($id.Name)"
            "Elevated  : $admin"
            "Integrity : $integrity"
        ) -join "`n"
        New-Finding -Category 'System' -Title 'Current user context' -Severity 'Info' `
            -Confidence 'Info' -Evidence $ev `
            -Impact 'Determines which escalation primitives are reachable.'

        # Stash parsed privileges for the dedicated token check.
        $script:RawPriv = $privs
        $script:RawGroups = $groups
    }

    Invoke-Check 'Group memberships' {
        # Resolve the current token's group SIDs to names for the report, and flag
        # groups that grant a direct or near-direct escalation path.
        $names = @()
        try {
            $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            foreach ($g in $id.Groups) {
                try { $names += $g.Translate([System.Security.Principal.NTAccount]).Value }
                catch { $names += $g.Value }
            }
        } catch { }
        if ($names) {
            New-Finding -Category 'System' -Title 'Group memberships' -Severity 'Info' `
                -Confidence 'Info' -Evidence (($names | Sort-Object -Unique) -join "`n") `
                -Impact 'Group membership can grant indirect privilege-escalation paths.'
        }
        $notable = @{
            'Backup Operators'            = @{ Sev = 'High';   Note = 'SeBackup/SeRestore -> read any file (dump SAM/SYSTEM) or overwrite privileged binaries.' }
            'Server Operators'            = @{ Sev = 'High';   Note = 'Manage services -> reconfigure a service to run an attacker binary as SYSTEM.' }
            'Print Operators'             = @{ Sev = 'High';   Note = 'SeLoadDriverPrivilege -> load a vulnerable driver for kernel code execution.' }
            'Account Operators'           = @{ Sev = 'Medium'; Note = 'Modify many non-admin accounts/groups -> pivot toward higher privilege.' }
            'DnsAdmins'                   = @{ Sev = 'High';   Note = 'Load an arbitrary DLL into the DNS service (SYSTEM), classically on a DC.' }
            'Hyper-V Administrators'      = @{ Sev = 'High';   Note = 'Full control of VMs / known host-escalation primitives.' }
            'Group Policy Creator Owners' = @{ Sev = 'Medium'; Note = 'Potential GPO abuse for privilege escalation.' }
            'Remote Management Users'     = @{ Sev = 'Low';    Note = 'WinRM access - useful for lateral movement.' }
            'Distributed COM Users'       = @{ Sev = 'Low';    Note = 'DCOM activation rights - potential lateral/priv paths.' }
        }
        foreach ($n in $names) {
            foreach ($k in $notable.Keys) {
                if ($n -match ('\\' + [regex]::Escape($k) + '$') -or $n -eq $k) {
                    $info = $notable[$k]
                    New-Finding -Category 'Privilege' -Title "Member of privileged group: $k" `
                        -Severity $info.Sev -Confidence 'Potential' -Evidence $n `
                        -Impact $info.Note `
                        -Validation 'Confirm the specific abuse path applies in this environment before relying on it.'
                }
            }
        }
    }

    Invoke-Check 'Network interfaces' {
        $lines = @()
        try {
            Get-NetIPAddress -ErrorAction Stop |
                Where-Object { $_.IPAddress -notmatch '^169\.254|^fe80|^::1$' } |
                ForEach-Object { $lines += "$($_.InterfaceAlias): $($_.IPAddress)/$($_.PrefixLength)" }
        }
        catch {
            # Fallback for hosts without the NetTCPIP module (older/stripped systems).
            $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction SilentlyContinue
            foreach ($a in $cfg) { foreach ($ip in $a.IPAddress) { $lines += "$($a.Description): $ip" } }
        }
        if ($lines.Count) {
            New-Finding -Category 'System' -Title 'Network interfaces' -Severity 'Info' `
                -Confidence 'Info' -Evidence ($lines -join "`n") `
                -Impact 'Pivot candidates / dual-homed hosts.'
        }
    }
}

#endregion

# ============================================================================
#region  Phase 2 - Privilege-escalation checks
# ============================================================================

function Invoke-TokenPrivilegeCheck {
    Write-Section 'TOKEN PRIVILEGES'
    Invoke-Check 'Token privileges (whoami /priv)' {
        if (-not $script:RawPriv) {
            if (Test-CommandExists 'whoami.exe') { $script:RawPriv = (whoami /priv) 2>$null }
        }
        if (-not $script:RawPriv) { Write-Log 'whoami /priv unavailable' 'WARN'; return }

        # High-value privileges and the escalation primitive each enables.
        $interesting = @{
            'SeImpersonatePrivilege'        = @{ Sev = 'High'; Note = 'Token impersonation -> Potato family (PrintSpoofer, GodPotato, JuicyPotato) for SYSTEM.' }
            'SeAssignPrimaryTokenPrivilege' = @{ Sev = 'High'; Note = 'Primary-token assignment -> Potato-style SYSTEM escalation.' }
            'SeDebugPrivilege'              = @{ Sev = 'High'; Note = 'Debug any process -> inject into / dump SYSTEM processes (e.g. lsass).' }
            'SeBackupPrivilege'             = @{ Sev = 'High'; Note = 'Read any file -> copy SAM/SYSTEM/NTDS for offline credential extraction.' }
            'SeRestorePrivilege'            = @{ Sev = 'High'; Note = 'Write any file / registry -> overwrite privileged binaries or services.' }
            'SeTakeOwnershipPrivilege'      = @{ Sev = 'High'; Note = 'Take ownership of securable objects -> grant yourself access to privileged files.' }
            'SeLoadDriverPrivilege'         = @{ Sev = 'High'; Note = 'Load a (vulnerable) driver -> kernel-level code execution.' }
            'SeManageVolumePrivilege'       = @{ Sev = 'Medium'; Note = 'Full volume access -> arbitrary file read primitives in some chains.' }
            'SeTcbPrivilege'                = @{ Sev = 'High'; Note = 'Act as part of the OS -> construct a SYSTEM token.' }
            'SeCreateTokenPrivilege'        = @{ Sev = 'High'; Note = 'Create arbitrary tokens -> direct SYSTEM impersonation.' }
        }

        foreach ($line in $script:RawPriv) {
            foreach ($priv in $interesting.Keys) {
                if ($line -match [regex]::Escape($priv)) {
                    $enabled = ($line -match 'Enabled')
                    $state   = if ($enabled) { 'Enabled' } else { 'Disabled (can often be enabled programmatically)' }
                    $conf    = if ($enabled) { 'Confirmed' } else { 'Potential' }
                    $info    = $interesting[$priv]
                    New-Finding -Category 'Privilege' -Title "Privilege held: $priv" `
                        -Severity $info.Sev -Confidence $conf `
                        -Evidence "$($line.Trim())  [State: $state]" `
                        -Impact $info.Note `
                        -Prerequisite 'A process/shell running under this token.' `
                        -Validation 'Confirm the primitive manually against the matching technique; do not assume success from the flag alone.'
                }
            }
        }
    }
}

function Invoke-ServiceChecks {
    Write-Section 'SERVICES'
    $services = $null
    Invoke-Check 'Enumerate services' {
        $script:AllServices = Get-CimInstance Win32_Service -ErrorAction Stop
    }
    $services = $script:AllServices
    if (-not $services) { return }

    Invoke-Check 'Unquoted service paths' {
        foreach ($s in $services) {
            $path = $s.PathName
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $trimmed = $path.Trim()
            # Unquoted AND contains a space in the path portion before .exe.
            if ($trimmed.StartsWith('"')) { continue }
            $exe = Get-ExeFromCommandLine $trimmed
            if ($exe -and $exe -match '\s' -and $exe -match '\\') {
                # Determine which intermediate directories an attacker could plant into.
                $writableSpots = @()
                $parts = $exe.Split('\')
                $accum = $parts[0]
                for ($i = 1; $i -lt $parts.Count - 1; $i++) {
                    $accum = "$accum\$($parts[$i])"
                    if ($accum -match '\s') {
                        # The hijackable candidate is the directory preceding the space break.
                        $candidateDir = Split-Path $accum -Parent
                        if ($candidateDir) {
                            $w = Test-PathWritableByMe $candidateDir
                            if ($w.Writable) { $writableSpots += "$candidateDir ($($w.Rights))" }
                        }
                    }
                }
                if ($writableSpots.Count -gt 0) {
                    New-Finding -Category 'Service' -Title "Unquoted service path (writable intermediate dir): $($s.Name)" `
                        -Severity 'High' -Confidence 'Confirmed' `
                        -Evidence "PathName: $path`nStart: $($s.StartMode) RunAs: $($s.StartName)`nWritable: $($writableSpots -join '; ')" `
                        -Impact 'Plant a malicious .exe in the writable path segment; the service launches it with its own (often SYSTEM) privileges.' `
                        -Prerequisite 'Ability to restart the service or wait for a reboot.' `
                        -Validation 'Confirm write access and that the service account is privileged; stage a benign payload first.'
                }
                else {
                    New-Finding -Category 'Service' -Title "Unquoted service path: $($s.Name)" `
                        -Severity 'Medium' -Confidence 'Potential' `
                        -Evidence "PathName: $path`nStart: $($s.StartMode) RunAs: $($s.StartName)" `
                        -Impact 'Unquoted path with spaces may allow binary planting if any intermediate directory is writable.' `
                        -Prerequisite 'A writable intermediate directory (none proven for the current user).' `
                        -Validation 'Check icacls on each path segment for your groups; verify service restart ability.'
                }
            }
        }
    }

    Invoke-Check 'Weak service binary / directory permissions' {
        foreach ($s in $services) {
            $exe = Get-ExeFromCommandLine $s.PathName
            if (-not $exe) { continue }
            if (-not (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) { continue }

            $wb = Test-PathWritableByMe $exe
            if ($wb.Writable) {
                New-Finding -Category 'Service' -Title "Writable service binary: $($s.Name)" `
                    -Severity 'High' -Confidence 'Confirmed' `
                    -Evidence "Binary: $exe`nGranted: $($wb.Rights)`nRunAs: $($s.StartName) Start: $($s.StartMode)" `
                    -Impact 'Replace the binary; it executes with the service account privileges on next start.' `
                    -Prerequisite 'Ability to restart the service or wait for reboot.' `
                    -Validation 'Confirm with icacls; back up the original before any authorized replacement.'
                continue
            }
            $dir = Split-Path $exe -Parent
            $wd = Test-PathWritableByMe $dir
            if ($wd.Writable) {
                New-Finding -Category 'Service' -Title "Writable service directory: $($s.Name)" `
                    -Severity 'Medium' -Confidence 'Potential' `
                    -Evidence "Dir: $dir`nGranted: $($wd.Rights)`nBinary: $exe RunAs: $($s.StartName)" `
                    -Impact 'A writable service directory may enable DLL planting / binary replacement depending on load order.' `
                    -Prerequisite 'Service loads a hijackable DLL or binary can be swapped.' `
                    -Validation 'Inspect the binary imports / Procmon for missing DLLs loaded from this directory.'
            }
        }
    }

    Invoke-Check 'Weak service registry permissions (config tamper)' {
        foreach ($s in $services) {
            $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)"
            if (-not (Test-Path $key)) { continue }
            try {
                $acl = Get-Acl -Path $key -ErrorAction Stop
            } catch { continue }
            $mine = $script:MyTokenSids
            foreach ($ace in $acl.Access) {
                $sid = $null
                try {
                    $sid = if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) { $ace.IdentityReference.Value }
                           else { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                } catch { continue }
                if (-not $mine.Contains($sid)) { continue }
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if (([int]$ace.RegistryRights -band $script:WriteMask) -ne 0) {
                    New-Finding -Category 'Service' -Title "Writable service registry key: $($s.Name)" `
                        -Severity 'High' -Confidence 'Confirmed' `
                        -Evidence "Key: $key`nGranted: $($ace.IdentityReference) : $($ace.RegistryRights)`nRunAs: $($s.StartName)" `
                        -Impact 'Rewrite ImagePath to an attacker binary; the service runs it with its account privileges.' `
                        -Prerequisite 'Ability to restart the service or wait for reboot.' `
                        -Validation 'Confirm write with reg query / Get-Acl; do not alter ImagePath outside an authorized test.'
                    break
                }
            }
        }
    }

    Invoke-Check 'Services running as privileged accounts' {
        # Informational inventory: non-OS services running as SYSTEM are the
        # high-value targets the writable-binary/dir/registry checks above hunt in.
        $priv = $services | Where-Object {
            [string]::IsNullOrEmpty($_.StartName) -or $_.StartName -match 'LocalSystem|NT AUTHORITY'
        }
        $thirdParty = $priv | Where-Object {
            $exe = Get-ExeFromCommandLine $_.PathName
            $exe -and $exe -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\'
        }
        if ($thirdParty) {
            $ev = (($thirdParty | Select-Object -First 30 |
                    ForEach-Object { "{0} [{1}] -> {2}" -f $_.Name, $_.StartName, $_.PathName }) -join "`n")
            New-Finding -Category 'Service' -Title "Third-party services running as SYSTEM ($(@($thirdParty).Count))" `
                -Severity 'Info' -Confidence 'Info' -Evidence $ev `
                -Impact 'Non-OS services running as SYSTEM are prime targets for binary/DLL/config tampering (see dedicated findings).' `
                -Validation 'Cross-check product versions against known local-privesc CVEs; review each binary/dir ACL.'
        }
    }

    Invoke-Check 'Modifiable service configuration (DACL via sc sdshow)' {
        # The real "weak service configuration" check: does the current principal hold
        # SERVICE_CHANGE_CONFIG / WRITE_DAC / WRITE_OWNER / GENERIC_ALL|WRITE on the
        # service object itself? If so you can repoint its binPath and start it as its
        # (often SYSTEM) account - independent of registry-key or binary ACLs.
        if (-not (Test-CommandExists 'sc.exe')) {
            Write-Log 'sc.exe unavailable; skipping service-DACL check.' 'WARN'
            return
        }
        $dangerRights = @('DC','WD','WO','GA','GW')   # ChangeConfig, WriteDac, WriteOwner, GenericAll, GenericWrite
        $startRights  = @('RP','WP')                   # Start / Stop (needed to trigger the new binary)
        # SDDL SID aliases a low-privilege user commonly holds.
        $aliasSid = @{
            'WD' = 'S-1-1-0'        # Everyone
            'AU' = 'S-1-5-11'       # Authenticated Users
            'BU' = 'S-1-5-32-545'   # BUILTIN\Users
            'IU' = 'S-1-5-4'        # Interactive
            'SU' = 'S-1-5-6'        # Service
            'AN' = 'S-1-5-7'        # Anonymous
        }
        $mine = $script:MyTokenSids
        foreach ($s in $services) {
            $sddl = ((& sc.exe sdshow $s.Name 2>$null) -join '').Trim()
            if (-not $sddl -or $sddl -notmatch 'D:') { continue }
            foreach ($m in [regex]::Matches($sddl, '\(A;[^;]*;([^;]*);[^;]*;[^;]*;([^)]*)\)')) {
                $rights = $m.Groups[1].Value
                $sidTok = $m.Groups[2].Value
                $aceSid = if ($sidTok -like 'S-*') { $sidTok }
                          elseif ($aliasSid.ContainsKey($sidTok)) { $aliasSid[$sidTok] }
                          else { $null }
                if (-not $aceSid -or -not $mine.Contains($aceSid)) { continue }
                # Split the rights field into its 2-char SDDL tokens (avoids cross-token
                # substring false positives like "SD"+"CC" matching "DC").
                $tokens  = [regex]::Matches($rights, '..') | ForEach-Object { $_.Value }
                $canCfg  = @($tokens | Where-Object { $dangerRights -contains $_ })
                if ($canCfg.Count -gt 0) {
                    $canStart = @($tokens | Where-Object { $startRights -contains $_ }).Count -gt 0
                    New-Finding -Category 'Service' -Title "Modifiable service configuration: $($s.Name)" `
                        -Severity 'High' -Confidence 'Confirmed' `
                        -Evidence "Service: $($s.Name)  RunAs: $($s.StartName)`nGrants [$($canCfg -join ',')] to '$sidTok'; start/stop=$canStart`nSDDL: $sddl" `
                        -Impact 'Repoint the service binary (sc config <svc> binPath=) and (re)start it to run code as the service account (often SYSTEM).' `
                        -Prerequisite 'Ability to start/restart the service (RP/WP in the same DACL, or a reboot).' `
                        -Validation 'Confirm with: sc qc <svc> and accesschk.exe -uwcqv <user> <svc>; reconfigure only under authorization.'
                    break
                }
            }
        }
    }
}

function Invoke-ScheduledTaskChecks {
    Write-Section 'SCHEDULED TASKS'
    Invoke-Check 'Scheduled task writable actions' {
        if (-not (Test-CommandExists 'Get-ScheduledTask')) {
            Write-Log 'Get-ScheduledTask not available; skipping (consider: schtasks /query /v /fo list)' 'WARN'
            return
        }
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            foreach ($a in @($t.Actions)) {
                $exe = $a.Execute
                if ([string]::IsNullOrWhiteSpace($exe)) { continue }
                # Expand environment variables that appear in task actions.
                $expanded = [Environment]::ExpandEnvironmentVariables($exe)
                $resolved = Get-ExeFromCommandLine $expanded
                if (-not $resolved) { continue }
                # If the action references a script, the argument may be the real target.
                $targets = @($resolved)
                if ($a.Arguments) {
                    $argExp = [Environment]::ExpandEnvironmentVariables($a.Arguments)
                    $scriptMatch = [regex]::Match($argExp, '([A-Za-z]:\\[^"'']+\.(ps1|bat|cmd|vbs|js))', 'IgnoreCase')
                    if ($scriptMatch.Success) { $targets += $scriptMatch.Groups[1].Value }
                }
                foreach ($tgt in ($targets | Select-Object -Unique)) {
                    if (-not (Test-Path -LiteralPath $tgt -ErrorAction SilentlyContinue)) { continue }
                    $w = Test-PathWritableByMe $tgt
                    if ($w.Writable) {
                        $principal = try { $t.Principal.UserId } catch { 'unknown' }
                        New-Finding -Category 'ScheduledTask' -Title "Writable scheduled-task target: $($t.TaskName)" `
                            -Severity 'High' -Confidence 'Confirmed' `
                            -Evidence "Task: $($t.TaskPath)$($t.TaskName)`nTarget: $tgt`nGranted: $($w.Rights)`nRunAs: $principal" `
                            -Impact 'Overwrite the task binary/script; it runs under the task principal at the next trigger.' `
                            -Prerequisite 'The task fires on a schedule/trigger you can reach or wait for.' `
                            -Validation 'Confirm the run-as account is privileged and inspect the trigger schedule.'
                    }
                }
            }
        }
    }
}

function Invoke-RegistryChecks {
    Write-Section 'REGISTRY & POLICY'

    Invoke-Check 'AlwaysInstallElevated' {
        $hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        $hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        if ($hklm -eq 1 -and $hkcu -eq 1) {
            New-Finding -Category 'Registry' -Title 'AlwaysInstallElevated enabled (both hives)' `
                -Severity 'Critical' -Confidence 'Confirmed' `
                -Evidence "HKLM=$hklm  HKCU=$hkcu" `
                -Impact 'Any .msi installs as SYSTEM. Craft an MSI payload for direct SYSTEM code execution.' `
                -Prerequisite 'Ability to run msiexec (default for standard users).' `
                -Validation 'Build a benign MSI (e.g. msfvenom /msi) and confirm it executes elevated in the lab.'
        }
        elseif ($hklm -eq 1 -or $hkcu -eq 1) {
            New-Finding -Category 'Registry' -Title 'AlwaysInstallElevated set in one hive only' `
                -Severity 'Low' -Confidence 'Info' `
                -Evidence "HKLM=$hklm  HKCU=$hkcu" `
                -Impact 'Both hives must be 1 to be exploitable; single hive is not sufficient.' `
                -Validation 'No action; informational.'
        }
    }

    Invoke-Check 'Winlogon autologon credentials' {
        $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        if ($wl -and $wl.DefaultPassword) {
            New-Finding -Category 'Credential' -Title 'Autologon password stored in registry' `
                -Severity 'High' -Confidence 'Confirmed' `
                -Evidence "DefaultUserName=$($wl.DefaultUserName)  DefaultDomainName=$($wl.DefaultDomainName)  DefaultPassword=<present>" `
                -Impact 'Cleartext credentials for the autologon account; reuse for lateral movement / RunAs.' `
                -Prerequisite 'None (readable by standard users when set).' `
                -Validation 'Read the value and test the credential with runas / a service logon in scope.'
        }
    }
}

function Invoke-PathAndDllChecks {
    Write-Section 'PATH & DLL HIJACKING'
    Invoke-Check 'Writable directories on system PATH' {
        $paths = $env:PATH -split ';' | Where-Object { $_ -and $_.Trim() }
        foreach ($p in ($paths | Select-Object -Unique)) {
            $pp = [Environment]::ExpandEnvironmentVariables($p).Trim()
            if (-not (Test-Path -LiteralPath $pp -ErrorAction SilentlyContinue)) { continue }
            $w = Test-PathWritableByMe $pp
            if ($w.Writable) {
                New-Finding -Category 'DLLHijack' -Title "Writable directory on PATH: $pp" `
                    -Severity 'Medium' -Confidence 'Potential' `
                    -Evidence "Dir: $pp`nGranted: $($w.Rights)" `
                    -Impact 'A privileged process that loads a DLL by name, or runs a command without an absolute path, may pick up a planted file here.' `
                    -Prerequisite 'A privileged process performs a name-based DLL/binary lookup resolving to this directory.' `
                    -Validation 'Use Procmon (NAME NOT FOUND on a DLL in a privileged process) to confirm a real hijack target before planting.'
            }
        }
    }
}

function Invoke-UacCheck {
    Write-Section 'UAC & SECURITY SETTINGS'
    Invoke-Check 'UAC configuration' {
        $sys = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
        if ($sys) {
            $ev = @(
                "EnableLUA               = $($sys.EnableLUA)   (0 = UAC disabled)"
                "ConsentPromptBehaviorAdmin = $($sys.ConsentPromptBehaviorAdmin)"
                "LocalAccountTokenFilterPolicy = $($sys.LocalAccountTokenFilterPolicy)  (1 = remote admins get full token)"
                "FilterAdministratorToken = $($sys.FilterAdministratorToken)"
            ) -join "`n"
            $sev = 'Info'; $conf = 'Info'
            if ($sys.EnableLUA -eq 0) { $sev = 'Medium'; $conf = 'Confirmed' }
            New-Finding -Category 'UAC' -Title 'UAC configuration' -Severity $sev -Confidence $conf `
                -Evidence $ev `
                -Impact 'EnableLUA=0 means no UAC prompts; LocalAccountTokenFilterPolicy=1 eases remote admin logons / pass-the-hash.' `
                -Validation 'Combine with admin-group membership to judge bypass relevance.'
        }
    }

    Invoke-Check 'WDigest cleartext credential caching' {
        $wd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
              -Name UseLogonCredential -ErrorAction SilentlyContinue
        if ($wd -and $wd.UseLogonCredential -eq 1) {
            New-Finding -Category 'Credential' -Title 'WDigest cleartext credentials enabled (UseLogonCredential=1)' `
                -Severity 'High' -Confidence 'Confirmed' `
                -Evidence 'HKLM\...\SecurityProviders\WDigest\UseLogonCredential = 1' `
                -Impact 'LSASS caches plaintext passwords; an LSASS dump recovers cleartext credentials of logged-on users.' `
                -Prerequisite 'Ability to read LSASS (SeDebug/admin) after a user has logged on.' `
                -Validation 'With SYSTEM/SeDebug: dump LSASS and parse (mimikatz sekurlsa::logonpasswords / pypykatz).'
        }
    }

    Invoke-Check 'LSA protection (RunAsPPL)' {
        $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
        $ppl = if ($lsa) { $lsa.RunAsPPL } else { $null }
        $pplStr = if ([string]::IsNullOrEmpty([string]$ppl)) { 'not set' } else { "$ppl" }
        New-Finding -Category 'UAC' -Title "LSA protection RunAsPPL = $pplStr" `
            -Severity 'Info' -Confidence 'Info' `
            -Evidence "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = $pplStr" `
            -Impact 'RunAsPPL unset/0 means LSASS is not a protected process - standard LSASS dumping works once you have the rights.' `
            -Validation 'Combine with SeDebug/admin to judge whether an LSASS dump is viable.'
    }

    Invoke-Check 'Defender status & path exclusions' {
        if (Test-CommandExists 'Get-MpComputerStatus') {
            try {
                $mp = Get-MpComputerStatus -ErrorAction Stop
                New-Finding -Category 'System' -Title 'Microsoft Defender status' -Severity 'Info' -Confidence 'Info' `
                    -Evidence "RealTimeProtection=$($mp.RealTimeProtectionEnabled)  AntivirusEnabled=$($mp.AntivirusEnabled)  TamperProtection=$($mp.IsTamperProtected)" `
                    -Impact 'Informs tooling/payload choice (whether AV evasion is needed).' `
                    -Validation 'Review exclusions below; confirm behaviour before relying on it.'
            } catch { }
        }
        if (Test-CommandExists 'Get-MpPreference') {
            $pref = Get-MpPreference -ErrorAction SilentlyContinue
            foreach ($ex in @($pref.ExclusionPath)) {
                if ([string]::IsNullOrWhiteSpace($ex)) { continue }
                $w = Test-PathWritableByMe $ex
                $sev  = if ($w.Writable) { 'Medium' } else { 'Info' }
                $conf = if ($w.Writable) { 'Confirmed' } else { 'Info' }
                $extra = if ($w.Writable) { " (writable by you: $($w.Rights))" } else { '' }
                New-Finding -Category 'System' -Title "Defender path exclusion: $ex" `
                    -Severity $sev -Confidence $conf `
                    -Evidence "Excluded path: $ex$extra" `
                    -Impact 'Files in an AV-excluded path are not scanned; a writable exclusion is an ideal payload drop location.' `
                    -Validation 'Stage tooling in a writable exclusion to avoid AV during an authorized test.'
            }
        }
    }
}

function Invoke-KernelHints {
    Write-Section 'KERNEL / PATCH LEADS'
    Invoke-Check 'OS build & hotfix summary' {
        $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $hf  = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue
        $hfList = @($hf | Select-Object -ExpandProperty HotFixID -ErrorAction SilentlyContinue)
        $latest = ($hf | Sort-Object InstalledOn -ErrorAction SilentlyContinue | Select-Object -Last 1)
        $ev = @(
            "OS build : $($os.Version) / $($os.BuildNumber)"
            "Hotfixes : $($hfList.Count) installed"
            "Most recent: $(if ($latest) { "$($latest.HotFixID) ($($latest.InstalledOn))" } else { 'unknown' })"
            "List     : $($hfList -join ', ')"
        ) -join "`n"
        New-Finding -Category 'Kernel' -Title 'Patch level (lead only - NOT a vulnerability claim)' `
            -Severity 'Info' -Confidence 'Info' -Evidence $ev `
            -Impact 'Feed build + hotfix data to an offline matcher (wesng / Watson) to shortlist kernel exploits.' `
            -Validation 'A build/patch gap is only a lead. Confirm the specific CVE applies and test a PoC before claiming exploitability.'
        if ($hfList.Count -lt 5) {
            New-Finding -Category 'Kernel' -Title 'Few hotfixes installed' -Severity 'Low' -Confidence 'Potential' `
                -Evidence "Only $($hfList.Count) hotfixes present." `
                -Impact 'A sparsely patched host raises the odds that a known kernel exploit applies.' `
                -Validation 'Run wesng/Watson offline against systeminfo output.'
        }
    }
}

function Invoke-AutorunChecks {
    Write-Section 'AUTORUNS'

    Invoke-Check 'Autorun registry entries (writable binaries)' {
        $runKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        foreach ($rk in $runKeys) {
            if (-not (Test-Path $rk)) { continue }
            $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like 'PS*') { continue }   # skip PSPath/PSParentPath/etc.
                $exe = Get-ExeFromCommandLine ([Environment]::ExpandEnvironmentVariables([string]$p.Value))
                if (-not $exe -or -not (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) { continue }
                $w = Test-PathWritableByMe $exe
                if ($w.Writable) {
                    $isHklm = $rk -like 'HKLM*'
                    $sev  = if ($isHklm) { 'High' } else { 'Medium' }
                    $hive = if ($isHklm) { 'HKLM (runs for any user at logon / boot)' } else { 'HKCU (current user only)' }
                    New-Finding -Category 'Autorun' -Title "Writable autorun binary: $($p.Name)" `
                        -Severity $sev -Confidence 'Confirmed' `
                        -Evidence "Key: $rk`nValue: $($p.Value)`nBinary: $exe`nGranted: $($w.Rights)`nScope: $hive" `
                        -Impact 'Replace the autorun binary; it executes when the relevant user logs on (SYSTEM/admin for HKLM).' `
                        -Prerequisite 'A privileged user logs on (HKLM) or triggers the autorun.' `
                        -Validation 'Confirm which account triggers the autorun before any authorized swap.'
                }
            }
        }
    }

    Invoke-Check 'Writable startup-folder locations' {
        $all = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'
        if (Test-Path -LiteralPath $all -ErrorAction SilentlyContinue) {
            $w = Test-PathWritableByMe $all
            if ($w.Writable) {
                New-Finding -Category 'Autorun' -Title 'Writable all-users Startup folder' `
                    -Severity 'High' -Confidence 'Confirmed' `
                    -Evidence "Dir: $all`nGranted: $($w.Rights)" `
                    -Impact 'Drop a payload that executes when any user (incl. an admin) logs on.' `
                    -Prerequisite 'A privileged user logs on to this host.' `
                    -Validation 'Confirm a privileged user actually logs on interactively.'
            }
        }
    }
}

function Invoke-DriverChecks {
    Write-Section 'DRIVERS'
    Invoke-Check 'Third-party kernel drivers (BYOVD leads)' {
        $drv = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
               Where-Object { $_.State -eq 'Running' }
        $third = $drv | Where-Object {
            $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\System32\\(drivers|DriverStore)\\'
        }
        if ($third) {
            $ev = (($third | Select-Object -First 30 |
                    ForEach-Object { "{0}: {1}" -f $_.Name, $_.PathName }) -join "`n")
            New-Finding -Category 'Driver' -Title "Non-standard running drivers ($(@($third).Count))" `
                -Severity 'Info' -Confidence 'Info' -Evidence $ev `
                -Impact 'Third-party drivers are candidates for known vulnerable-driver (BYOVD) kernel exploitation.' `
                -Validation 'Match driver names/hashes against loldrivers.io; confirm the specific CVE and PoC before claiming exploitability.'
        }
    }
}

#endregion

# ============================================================================
#region  Phase 3 - Credential exposure
# ============================================================================

function Invoke-CredentialChecks {
    param([switch] $Deep)
    Write-Section 'CREDENTIAL EXPOSURE'

    Invoke-Check 'PowerShell history' {
        $histPaths = @()
        try { $histPaths += (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath } catch { }
        $histPaths += (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
        foreach ($h in ($histPaths | Where-Object { $_ } | Select-Object -Unique)) {
            if (Test-Path -LiteralPath $h -ErrorAction SilentlyContinue) {
                $hits = Select-String -Path $h -Pattern 'password|passwd|pwd|secret|-AsPlainText|ConvertTo-SecureString|net user|Invoke-WebRequest.*-Credential' -ErrorAction SilentlyContinue
                if ($hits) {
                    New-Finding -Category 'Credential' -Title 'Sensitive commands in PowerShell history' `
                        -Severity 'Medium' -Confidence 'Potential' `
                        -Evidence ("File: $h`n" + (($hits | Select-Object -First 10 | ForEach-Object { $_.Line.Trim() }) -join "`n")) `
                        -Impact 'Operators often paste credentials into the shell; history may reveal reusable secrets.' `
                        -Validation 'Review the full file manually; test any discovered credential in scope.'
                }
            }
        }
    }

    Invoke-Check 'Saved credential metadata (cmdkey)' {
        if (Test-CommandExists 'cmdkey.exe') {
            $out = (cmdkey /list) 2>$null | Out-String
            if ($out -match 'Target:') {
                New-Finding -Category 'Credential' -Title 'Saved credentials present (cmdkey)' `
                    -Severity 'Medium' -Confidence 'Potential' `
                    -Evidence ($out.Trim()) `
                    -Impact 'Stored credentials can be reused non-interactively (e.g. runas /savecred) without knowing the plaintext.' `
                    -Prerequisite 'A stored credential usable by the current user.' `
                    -Validation 'Try runas /savecred /user:<target> against an in-scope action to confirm reuse.'
            }
        }
    }

    Invoke-Check 'Readable SAM / SYSTEM registry hive backups' {
        # Classic local-hash source: backup copies of the SAM/SYSTEM/SECURITY hives
        # that a standard user can read. (Since Win10 1803 the RegBack copies are
        # often zero-byte stubs - those are skipped.)
        $hives = @(
            "$env:SystemRoot\System32\config\RegBack\SAM"
            "$env:SystemRoot\System32\config\RegBack\SYSTEM"
            "$env:SystemRoot\System32\config\RegBack\SECURITY"
            "$env:SystemRoot\Repair\SAM"
            "$env:SystemRoot\Repair\SYSTEM"
            "$env:SystemRoot\Repair\SECURITY"
        )
        foreach ($h in $hives) {
            if (-not (Test-Path -LiteralPath $h -ErrorAction SilentlyContinue)) { continue }
            $fi = Get-Item -LiteralPath $h -Force -ErrorAction SilentlyContinue
            if (-not $fi -or $fi.Length -eq 0) { continue }   # skip empty RegBack stubs
            $readable = $false
            try { $fs = [System.IO.File]::OpenRead($h); $fs.Close(); $readable = $true } catch { }
            if ($readable) {
                $loc = Split-Path (Split-Path $h -Parent) -Leaf
                New-Finding -Category 'Credential' -Title "Readable registry hive backup: $(Split-Path $h -Leaf) ($loc)" `
                    -Severity 'High' -Confidence 'Confirmed' `
                    -Evidence "File: $h  ($([math]::Round($fi.Length/1KB)) KB, opened for read OK)" `
                    -Impact 'Copy SAM+SYSTEM (and SECURITY) offline and extract local account hashes.' `
                    -Prerequisite 'A matching SYSTEM hive is also readable (required to decrypt SAM).' `
                    -Validation 'Exfil the files and run: impacket-secretsdump -sam SAM -system SYSTEM [-security SECURITY] LOCAL'
            }
        }
    }

    Invoke-Check 'Application credential stores (registry)' {
        # Well-known registry locations where apps persist (often weakly obfuscated)
        # credentials. Presence is reported as a lead; decode/test manually.
        $locations = @(
            @{ Path = 'HKCU:\Software\SimonTatham\PuTTY\Sessions';            What = 'PuTTY saved sessions (usernames, proxy creds)' }
            @{ Path = 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions';      What = 'WinSCP sessions (may store saved passwords)' }
            @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'; What = 'SNMP community strings' }
            @{ Path = 'HKCU:\Software\ORL\WinVNC3\Password';                  What = 'WinVNC3 password (obfuscated)' }
            @{ Path = 'HKLM:\SOFTWARE\RealVNC\WinVNC4';                       What = 'RealVNC password' }
            @{ Path = 'HKLM:\SOFTWARE\TightVNC\Server';                       What = 'TightVNC password' }
            @{ Path = 'HKCU:\Software\TigerVNC\WinVNC4';                      What = 'TigerVNC password' }
            @{ Path = 'HKCU:\Software\OpenSSH\Agent\Keys';                    What = 'OpenSSH agent keys' }
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\PasswordExpiryWarning'; What = 'WinLogon settings' }
        )
        foreach ($l in $locations) {
            if (Test-Path -LiteralPath $l.Path -ErrorAction SilentlyContinue) {
                New-Finding -Category 'Credential' -Title "Credential store present: $($l.What)" `
                    -Severity 'Medium' -Confidence 'Potential' `
                    -Evidence "Registry: $($l.Path)" `
                    -Impact 'Application may hold reusable or weakly-obfuscated credentials.' `
                    -Prerequisite 'Read access to the key (varies by hive/ACL).' `
                    -Validation 'Extract with the matching tool (WinSCP/VNC decryptor, PuTTY session dump) and test the credential in scope.'
            }
        }
    }

    Invoke-Check 'Unattended install files' {
        $candidates = @(
            "$env:SystemDrive\Windows\Panther\Unattend.xml"
            "$env:SystemDrive\Windows\Panther\Autounattend.xml"
            "$env:SystemDrive\Windows\System32\Sysprep\Unattend.xml"
            "$env:SystemDrive\Windows\System32\Sysprep\Panther\Unattend.xml"
            "$env:SystemDrive\unattend.xml"
            "$env:SystemDrive\sysprep.inf"
        )
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c -ErrorAction SilentlyContinue) {
                $hit = Select-String -Path $c -Pattern 'Password|AdministratorPassword|<Value>' -ErrorAction SilentlyContinue
                $sev = if ($hit) { 'High' } else { 'Low' }
                $conf = if ($hit) { 'Confirmed' } else { 'Info' }
                New-Finding -Category 'Credential' -Title "Unattend file present: $c" `
                    -Severity $sev -Confidence $conf `
                    -Evidence ("File: $c" + $(if ($hit) { "`nContains Password/Value nodes (possibly base64)." } else { '' })) `
                    -Impact 'Unattend files frequently embed a local admin password (often base64-encoded).' `
                    -Validation 'Read the <Password><Value> node; base64-decode and test the credential in scope.'
            }
        }
    }

    if ($Deep) {
        Invoke-Check 'Config-file credential search (bounded)' {
            # Search a curated set of locations for credential-looking tokens. Bounded
            # by directory list and file patterns to stay fast and avoid unrelated data.
            $roots = @(
                "$env:SystemDrive\inetpub\wwwroot"
                "$env:SystemDrive\xampp"
                "$env:SystemDrive\wamp"
                "$env:SystemDrive\laragon\www"
                "$env:ProgramData"
                "$env:USERPROFILE"
                "$env:SystemDrive\Users\Public"
            ) | Select-Object -Unique
            $patterns = '*.config','*.xml','*.ini','*.txt','*.ps1','*.bat','*.cmd','*.yml','*.yaml','*.json','*.php','*.properties'
            $credRegex = 'password\s*[:=]|pwd\s*=|connectionstring|<password>|secret\s*[:=]|api[_-]?key\s*[:=]'
            $found = 0
            foreach ($root in $roots) {
                if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) { continue }
                try {
                    $files = Get-ChildItem -LiteralPath $root -Include $patterns -Recurse -File -ErrorAction SilentlyContinue -Depth 4
                } catch { continue }
                foreach ($f in $files) {
                    if ($found -ge 40) { break }      # cap total reported hits
                    if ($f.Length -gt 2MB) { continue } # skip large files
                    $hits = Select-String -Path $f.FullName -Pattern $credRegex -ErrorAction SilentlyContinue |
                            Select-Object -First 3
                    if ($hits) {
                        $found++
                        New-Finding -Category 'Credential' -Title "Possible credentials in file: $($f.Name)" `
                            -Severity 'Medium' -Confidence 'Potential' `
                            -Evidence ("File: $($f.FullName)`n" + (($hits | ForEach-Object { $_.Line.Trim() }) -join "`n")) `
                            -Impact 'Config files commonly hold DB / service / app credentials reusable elsewhere.' `
                            -Validation 'Open the file, extract the full credential, and test it against the relevant service in scope.'
                    }
                }
            }
            if ($found -ge 40) { Write-Log 'Credential search hit the 40-file report cap; narrow -OutputDir review manually.' 'WARN' }
        }
    }
    else {
        Write-Log 'Skipping deep config-file credential search (use -Full to enable).' 'INFO'
    }
}

#endregion

# ============================================================================
#region  Phase 4 - Applications & processes
# ============================================================================

function Invoke-AppProcessChecks {
    param([switch] $Deep)
    Write-Section 'APPLICATIONS & PROCESSES'

    if ($Deep) {
        Invoke-Check 'Installed software inventory' {
            $keys = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            $apps = foreach ($k in $keys) {
                Get-ItemProperty $k -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName } |
                    Select-Object DisplayName, DisplayVersion, Publisher
            }
            $apps = $apps | Sort-Object DisplayName -Unique
            if ($apps) {
                $ev = ($apps | ForEach-Object { "{0}  {1}  [{2}]" -f $_.DisplayName, $_.DisplayVersion, $_.Publisher }) -join "`n"
                New-Finding -Category 'Software' -Title "Installed software ($($apps.Count) products)" `
                    -Severity 'Info' -Confidence 'Info' -Evidence $ev `
                    -Impact 'Cross-reference third-party products/versions against known local-privesc CVEs.' `
                    -Validation 'Match versions to vendor advisories / exploit-db; confirm the specific build is affected.'
            }
        }
    }

    Invoke-Check 'Processes running as privileged accounts' {
        try {
            $procs = Get-CimInstance Win32_Process -ErrorAction Stop
        } catch { return }
        foreach ($p in $procs) {
            $owner = $null
            try {
                $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($o) { $owner = ("{0}\{1}" -f $o.Domain, $o.User) }
            } catch { }
            if ($owner -match 'NT AUTHORITY\\SYSTEM' -or $owner -match '\\Administrator$') {
                $exe = $p.ExecutablePath
                if ($exe -and (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) {
                    $w = Test-PathWritableByMe $exe
                    if ($w.Writable) {
                        New-Finding -Category 'Process' -Title "Writable binary of privileged process: $($p.Name)" `
                            -Severity 'High' -Confidence 'Confirmed' `
                            -Evidence "PID $($p.ProcessId)  Owner: $owner`nBinary: $exe`nGranted: $($w.Rights)" `
                            -Impact 'Replacing the on-disk binary of a privileged process yields its privileges at next launch.' `
                            -Validation 'Confirm restart/relaunch path; back up the original before any authorized swap.'
                    }
                }
            }
        }
    }
}

#endregion

# ============================================================================
#region  Reporting
# ============================================================================

function Show-ConsoleReport {
    $minRank = $script:SevRank[$MinSeverity]
    $shown = $script:Findings | Where-Object { $_.SevRank -ge $minRank } |
             Sort-Object -Property @{ Expression = 'SevRank'; Descending = $true }, Category, Title

    Write-Section 'FINDINGS'
    if (-not $shown) {
        Write-Color '  No findings at or above the selected severity.' 'Green'
        return
    }
    foreach ($f in $shown) {
        $c = $script:SevColor[$f.Severity]
        Write-Host ''
        Write-Color ("[{0}] ({1}) {2}" -f $f.Severity.ToUpper(), $f.Confidence, $f.Title) $c
        Write-Color ("  Category   : {0}" -f $f.Category) 'DarkGray'
        if ($f.Evidence)     { foreach ($l in ($f.Evidence -split "`n")) { Write-Color ("  Evidence   : {0}" -f $l) 'Gray' } }
        if ($f.Impact)       { Write-Color ("  Impact     : {0}" -f $f.Impact) 'Gray' }
        if ($f.Prerequisite) { Write-Color ("  Prereq     : {0}" -f $f.Prerequisite) 'Gray' }
        if ($f.Validation)   { Write-Color ("  Validate   : {0}" -f $f.Validation) 'DarkYellow' }
    }
}

function Show-Summary {
    Write-Section 'EXECUTIVE SUMMARY'
    $by = $script:Findings | Group-Object Severity
    $counts = @{}
    foreach ($g in $by) { $counts[$g.Name] = $g.Count }
    foreach ($s in 'Critical','High','Medium','Low','Info') {
        $n = if ($counts.ContainsKey($s)) { $counts[$s] } else { 0 }
        Write-Color ("  {0,-9}: {1}" -f $s, $n) $script:SevColor[$s]
    }
    $dur = (Get-Date) - $script:StartTime
    Write-Host ''
    Write-Color ("  Checks run : {0}  (failed: {1})" -f $script:ChecksRun, $script:ChecksFailed) 'DarkGray'
    Write-Color ("  Findings   : {0}" -f $script:Findings.Count) 'DarkGray'
    Write-Color ("  Duration   : {0:n1}s" -f $dur.TotalSeconds) 'DarkGray'

    # Prioritised top actions (Critical + High, confirmed first).
    $top = $script:Findings |
           Where-Object { $_.SevRank -ge $script:SevRank['High'] } |
           Sort-Object -Property @{ Expression = 'SevRank'; Descending = $true },
                                  @{ Expression = { $_.Confidence -eq 'Confirmed' }; Descending = $true } |
           Select-Object -First 8
    if ($top) {
        Write-Host ''
        Write-Color '  Prioritised vectors:' 'White'
        $i = 1
        foreach ($t in $top) {
            Write-Color ("   {0}. [{1}/{2}] {3}" -f $i, $t.Severity, $t.Confidence, $t.Title) $script:SevColor[$t.Severity]
            $i++
        }
    }
}

function Export-Report {
    param([string] $Dir, [string[]] $Formats)

    if (-not (Test-Path -LiteralPath $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }
    $stamp = $script:StartTime.ToString('yyyyMMdd_HHmmss')
    $base  = Join-Path $Dir "WinPrivEnum_$stamp"
    $want  = if ($Formats -contains 'ALL') { @('TXT','JSON','CSV') } else { $Formats }

    $ordered = $script:Findings |
               Sort-Object -Property @{ Expression = 'SevRank'; Descending = $true }, Category, Title

    if ($want -contains 'JSON') {
        $meta = [pscustomobject]@{
            Tool      = 'WinPrivEnum'
            Version   = $script:Version
            Host      = $env:COMPUTERNAME
            User      = $env:USERNAME
            Generated = $script:StartTime.ToString('o')
            ChecksRun = $script:ChecksRun
            ChecksFailed = $script:ChecksFailed
            Findings  = $ordered
            Errors    = $script:Errors
        }
        $meta | ConvertTo-Json -Depth 6 | Out-File "$base.json" -Encoding UTF8
        Write-Log "Wrote $base.json" 'OK'
    }
    if ($want -contains 'CSV') {
        $ordered | Select-Object Severity, Confidence, Category, Title, Evidence, Impact, Prerequisite, Validation |
            Export-Csv "$base.csv" -NoTypeInformation -Encoding UTF8
        Write-Log "Wrote $base.csv" 'OK'
    }
    if ($want -contains 'TXT') {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("WinPrivEnum $($script:Version) - $($env:COMPUTERNAME) - $($script:StartTime)")
        [void]$sb.AppendLine(('=' * 74))
        foreach ($f in $ordered) {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("[$($f.Severity)] ($($f.Confidence)) $($f.Title)")
            [void]$sb.AppendLine("  Category   : $($f.Category)")
            if ($f.Evidence)     { [void]$sb.AppendLine("  Evidence   :`n    $($f.Evidence -replace "`n","`n    ")") }
            if ($f.Impact)       { [void]$sb.AppendLine("  Impact     : $($f.Impact)") }
            if ($f.Prerequisite) { [void]$sb.AppendLine("  Prereq     : $($f.Prerequisite)") }
            if ($f.Validation)   { [void]$sb.AppendLine("  Validate   : $($f.Validation)") }
        }
        $sb.ToString() | Out-File "$base.txt" -Encoding UTF8
        Write-Log "Wrote $base.txt" 'OK'
    }
}

#endregion

# ============================================================================
#region  Help & main
# ============================================================================

function Show-Help {
@"
WinPrivEnum $($script:Version) - Windows privilege-escalation enumeration (read-only)
Authorized OSCP labs / penetration-testing assessments only.

USAGE
  .\WinPrivEnum.ps1 [-Quick|-Full] [-OutputDir <dir>] [-Format TXT,JSON,CSV,ALL]
                    [-MinSeverity Info|Low|Medium|High|Critical] [-NoColor] [-Help]

MODES
  -Full        (default) every check, including bounded credential file search.
  -Quick       fast triage; skips recursive cred search + software inventory.

OUTPUT
  -OutputDir   where to write reports (default: .\WinPrivEnum_<timestamp>).
  -Format      export formats (default ALL). Console output always shown.
  -MinSeverity console display floor (exports always contain everything).
  -NoColor     disable coloured output.

EXAMPLES
  .\WinPrivEnum.ps1
  .\WinPrivEnum.ps1 -Quick -Format JSON -OutputDir C:\Temp\wpe
  .\WinPrivEnum.ps1 -MinSeverity High -NoColor

NOTES
  Read-only. Never exploits, never changes configuration. Confidence levels
  (Confirmed / Potential / Info) distinguish proven misconfigurations from leads.
  Compatible with Windows PowerShell 5.1 and PowerShell 7+.
"@ | Write-Host
}

function Invoke-Main {
    if ($Help) { Show-Help; return }

    # Banner.
    Write-Color ("WinPrivEnum {0} - read-only Windows privesc enumeration" -f $script:Version) 'White'
    Write-Color  '  Authorized testing only. No exploitation. No configuration changes.' 'DarkGray'

    if (-not $script:OnWindows) {
        Write-Log 'This tool enumerates Windows hosts and must run on Windows (PowerShell 5.1 / 7+).' 'ERROR'
        Write-Log 'Syntax/logic load succeeded; exiting without enumeration on this platform.' 'INFO'
        return
    }

    if (-not (Test-IsAdmin)) {
        Write-Log 'Running without elevation - checks requiring admin are skipped gracefully.' 'WARN'
    }

    # Cache the caller token SIDs once for all ACL comparisons.
    $script:MyTokenSids = Get-MyTokenSids

    $deep = -not $Quick    # Full is default; -Quick narrows scope.

    Invoke-SystemEnum
    Invoke-TokenPrivilegeCheck
    Invoke-ServiceChecks
    Invoke-ScheduledTaskChecks
    Invoke-RegistryChecks
    Invoke-AutorunChecks
    Invoke-PathAndDllChecks
    Invoke-UacCheck
    Invoke-KernelHints
    Invoke-DriverChecks
    Invoke-CredentialChecks -Deep:$deep
    Invoke-AppProcessChecks -Deep:$deep

    Show-ConsoleReport
    Show-Summary

    if (-not $OutputDir) {
        $OutputDir = Join-Path (Get-Location) ("WinPrivEnum_" + $script:StartTime.ToString('yyyyMMdd_HHmmss'))
    }
    try {
        Export-Report -Dir $OutputDir -Formats $Format
        Write-Host ''
        Write-Color ("Reports written to: {0}" -f (Resolve-Path $OutputDir)) 'Green'
    }
    catch {
        Write-Log "Export failed: $($_.Exception.Message)" 'ERROR'
    }
}

# Expose -NoColor to the helper scope.
$script:NoColor = $NoColor.IsPresent

Invoke-Main

#endregion
