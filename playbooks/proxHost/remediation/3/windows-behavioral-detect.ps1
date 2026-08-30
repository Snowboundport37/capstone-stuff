#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioral malware detection script for Ansible-driven remediation pipeline.
    Outputs a single JSON object to stdout with score, indicators, and metadata.

.PARAMETER LookbackHours
    How far back (in hours) to look for suspicious file/log activity. Default: 24

.PARAMETER HighCpuSeconds
    How long (seconds) to sample CPU before flagging high usage. Default: 3

.PARAMETER HighMemoryMB
    Memory threshold (MB) above which an unknown process is flagged. Default: 500

.PARAMETER PowerShellBurstThreshold
    Number of PS log entries within 60 seconds that triggers burst flag. Default: 5

.PARAMETER EnablePowerShellLogging
    If specified, ensures PS Script Block Logging is enabled before scanning.
    Safe to pass on VMs where logging is already on.

.PARAMETER EnableRegistryBlobScan
    If specified, runs deep recursive registry blob scanning (slower).
#>

param(
    [int]$LookbackHours              = 24,
    [int]$HighCpuSeconds             = 3,
    [int]$HighMemoryMB               = 500,
    [int]$PowerShellBurstThreshold   = 5,
    [int]$StagerRecentMinutes        = 15,
    [switch]$RequirePsStagerObfuscation,
    [int]$DetectionThreshold         = 12,
    [int]$MinStrongHitsToConfirm     = 2,
    [int]$MinCategoriesToConfirm     = 2,
    [switch]$EnablePowerShellLogging,
    [switch]$EnableRegistryBlobScan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Helpers ───────────────────────────────────────────────────────────────────

function New-Indicator {
    param(
        [string]$Category,
        [string]$Detail,
        [int]$Weight
    )
    [PSCustomObject]@{
        category = $Category
        detail   = $Detail
        weight   = $Weight
    }
}

function Test-HighEntropy {
    <#
    Checks whether a filename (without extension) looks like a random hash.
    Criteria: 8+ chars, no real dictionary fragment, high ratio of hex/random chars.
    #>
    param([string]$Name)
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($Name)
    if ($stem.Length -lt 8) { return $false }
    # All hex characters → very likely a hash
    if ($stem -match '^[0-9a-fA-F]{8,}$') { return $true }
    # High ratio of digits + no vowels → likely random
    $digits  = ($stem.ToCharArray() | Where-Object { $_ -match '\d' }).Count
    $vowels  = ($stem.ToCharArray() | Where-Object { $_ -match '[aeiouAEIOU]' }).Count
    $ratio   = $digits / [Math]::Max($stem.Length, 1)
    if ($ratio -gt 0.5 -and $vowels -eq 0) { return $true }
    # Long runs of consonants with no vowels
    if ($stem -match '^[^aeiouAEIOU\s]{10,}$') { return $true }
    return $false
}

function Test-KovterEncodedValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $trimmed = $Value.Trim()
    if ($trimmed.Length -lt 50) { return $false }
    if ($trimmed -match '(?i)^[A-Za-z0-9+/=]{50,}$') { return $true }
    if ($trimmed -match '(?i)[A-Za-z0-9+/]{40,}') { return $true }
    if ($trimmed -match '(?i)frombase64string|invoke-expression|\biex\b|javascript:|vbscript:|mshta') { return $true }
    return $false
}

# ── Optional: ensure PS logging is on ────────────────────────────────────────

if ($EnablePowerShellLogging) {
    $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $sbPath)) {
        New-Item -Path $sbPath -Force | Out-Null
    }
    Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
}

# ── Accumulators ──────────────────────────────────────────────────────────────

$indicators  = [System.Collections.Generic.List[PSCustomObject]]::new()
$totalScore  = 0
$scanNow     = Get-Date
$cutoff      = (Get-Date).AddHours(-$LookbackHours)
$stagerRecentCutoff = $scanNow.AddMinutes(-$StagerRecentMinutes)

# Known-good process parent relationships (process → acceptable parents)
# Anything not in this map spawning cmd/powershell is suspicious
$legitimateParents = @(
    'explorer','services','svchost','taskhost','taskhostw',
    'msiexec','cmd','powershell','pwsh','conhost','wscript',
    'cscript','mmc','devenv','code','WindowsTerminal','RuntimeBroker'
)

# Ransom note filename fragments (case-insensitive)
$ransomPatterns = @(
    'READ_ME','DECRYPT','@Please','RECOVER','YOUR_FILES',
    'HOW_TO','RESTORE','WANNACRY','WNCRY','!HELP'
)

# Suspicious executable locations
$suspiciousPaths = @(
    $env:TEMP,
    $env:TMP,
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "$env:ProgramData",
    "$env:PUBLIC"
) | Where-Object { $_ -and (Test-Path $_) }

# Executable extensions to flag
$execExtensions = @('.exe','.dll','.ps1','.vbs','.bat','.cmd','.scr','.hta')

###############################################################################
# CATEGORY 0 — WANNACRY HIGH-CONFIDENCE IOC CHECKS
###############################################################################

# Detect known WannaCry artifacts regardless of lookback window.
try {
    $wcKnownFiles = @(
        'C:\Windows\tasksche.exe',
        'C:\Windows\qeriuwjhrf',
        'C:\Windows\qeriuwjhrf\qeriuwjhrf.wnry',
        'C:\Windows\qeriuwjhrf\tasksche.exe',
        'C:\ProgramData\qeriuwjhrf\qeriuwjhrf.wnry'
    )

    foreach ($wcFile in $wcKnownFiles) {
        if (Test-Path -LiteralPath $wcFile) {
            $ind = New-Indicator -Category 'wannacry_ioc' `
                -Detail "Known WannaCry artifact present: $wcFile" `
                -Weight 15
            $indicators.Add($ind)
            $totalScore += 15
        }
    }
} catch { }

try {
    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        $wcProcPattern = '(?i)^(tasksche|taskdl|taskse|taskhsvc|mssecsvc2\.0|wcry|wnry)(\.exe)?$'
        $running = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($p in $running) {
            $pn = if ($p.Name) { [string]$p.Name } else { '' }
            $pp = if ($p.ExecutablePath) { [string]$p.ExecutablePath } else { '' }
            $cmd = if ($p.CommandLine) { [string]$p.CommandLine } else { '' }
            if (
                $pn -match $wcProcPattern -or
                $pp -match '(?i)\\qeriuwjhrf\\|\\tasksche\.exe$|\.wnry($|\s)' -or
                $cmd -match '(?i)qeriuwjhrf|tasksche\.exe|@Please_Read_Me@|\.wnry'
            ) {
                $ind = New-Indicator -Category 'wannacry_ioc' `
                    -Detail "WannaCry-like process observed: name='$pn' pid=$($p.ProcessId) path='$pp'" `
                    -Weight 15
                $indicators.Add($ind)
                $totalScore += 15
            }
        }
    }
} catch { }

try {
    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        $svcHits = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name -match '(?i)mssecsvc2\.0|tasksche|wnry|wcry') -or
            ($_.DisplayName -match '(?i)microsoft security center \(2\.0\)|wannacry|wnry|wcry') -or
            ($_.PathName -match '(?i)qeriuwjhrf|tasksche\.exe|\.wnry')
        }
        foreach ($svc in ($svcHits | Select-Object -First 10)) {
            $ind = New-Indicator -Category 'wannacry_ioc' `
                -Detail "WannaCry-like service detected: name='$($svc.Name)' display='$($svc.DisplayName)' path='$($svc.PathName)'" `
                -Weight 15
            $indicators.Add($ind)
            $totalScore += 15
        }
    }
} catch { }

try {
    $wcRoots = @(
        "$env:SystemDrive\Users",
        "$env:ProgramData",
        "$env:PUBLIC",
        "$env:TEMP"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $wcRoots) {
        $wcFiles = Get-ChildItem -Path $root -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -ieq '@Please_Read_Me@.txt' -or
                $_.Extension -ieq '.wnry'
            } |
            Select-Object -First 5

        foreach ($hit in $wcFiles) {
            $ind = New-Indicator -Category 'wannacry_ioc' `
                -Detail "WannaCry ransom artifact found: $($hit.FullName)" `
                -Weight 12
            $indicators.Add($ind)
            $totalScore += 12
        }
    }
} catch { }

###############################################################################
# CATEGORY 0B — LOKIBOT HIGH-CONFIDENCE IOC CHECKS (RUNTIME ONLY)
###############################################################################

try {
    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        $lbProcHits = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name -match '(?i)^loki(bot)?(\.exe)?$') -or
            ($_.ExecutablePath -match '(?i)\\Downloads\\Loki\\|\\AppData\\Roaming\\Loki\\') -or
            ($_.CommandLine -match '(?i)\\Downloads\\Loki\\|\\AppData\\Roaming\\Loki\\|fre\.php') -or
            (
                $_.ExecutablePath -match '(?i)\\AppData\\Local\\Temp\\' -and
                (
                    $_.Name -match '^(?i)[a-z]{3,5}(\.exe)?$' -or
                    $_.Name -match '^(?i)\.ses(\.exe)?$' -or
                    $_.Name -match '^(?i)wct[a-z0-9]{3,8}\.tmp(\.exe)?$'
                )
            )
        }
        foreach ($p in ($lbProcHits | Select-Object -First 15)) {
            $cmdText = if ($p.CommandLine) { [string]$p.CommandLine } else { '' }
            $ind = New-Indicator -Category 'lokibot_ioc' `
                -Detail "LokiBot runtime process observed: name='$($p.Name)' pid=$($p.ProcessId) path='$($p.ExecutablePath)' cmd='$cmdText'" `
                -Weight 15
            $indicators.Add($ind)
            $totalScore += 15
        }
    }
} catch { }

###############################################################################
# CATEGORY 0C — KOVTER HIGH-CONFIDENCE IOC CHECKS
###############################################################################

try {
    $kovterRunKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($rk in $kovterRunKeys) {
        if (-not (Test-Path $rk)) { continue }
        $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($prop in ($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
            $val = [string]$prop.Value
            $looksHiddenStager = $val -match '(?i)powershell(\.exe)?\s+.*(-w|--windowstyle)\s*hidden'
            $looksFilelessExec = $val -match '(?i)frombase64string|invoke-expression|\biex\b|javascript:|vbscript:|mshta|rundll32|regsvr32'
            if ($looksHiddenStager -and $looksFilelessExec) {
                $ind = New-Indicator -Category 'kovter_ioc' `
                    -Detail "Kovter-like hidden fileless Run key '$($prop.Name)' in '$rk': $val" `
                    -Weight 12
                $indicators.Add($ind)
                $totalScore += 12
            }
        }
    }
} catch { }

try {
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
        foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            foreach ($a in ($t.Actions | Where-Object { $_ })) {
                $aText = "$($a.Execute) $($a.Arguments)"
                if ($aText -match '(?i)powershell.*hidden' -and $aText -match '(?i)frombase64string|iex|javascript:|vbscript:|mshta') {
                    $ind = New-Indicator -Category 'kovter_ioc' `
                        -Detail "Kovter-like scheduled task '$($t.TaskPath)$($t.TaskName)' action: $aText" `
                        -Weight 10
                    $indicators.Add($ind)
                    $totalScore += 10
                }
            }
        }
    }
} catch { }

try {
    # Kovter commonly leaves randomized keys under HKCU\Software with many pseudo-random
    # value names and encoded payload chunks.
    if (Test-Path 'HKCU:\Software') {
        $candidateKeys = Get-ChildItem -Path 'HKCU:\Software' -ErrorAction SilentlyContinue | Where-Object {
            $_.PSChildName -match '^(?i)[a-f0-9]{8,12}$|^\d{8,12}$'
        }
        foreach ($k in ($candidateKeys | Select-Object -First 80)) {
            $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $valueProps = @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })
            if ($valueProps.Count -lt 4) { continue }

            $randomValueNameCount = 0
            $encodedValueCount = 0
            foreach ($vp in $valueProps) {
                $n = [string]$vp.Name
                $v = [string]$vp.Value
                if ($n -match '^(?i)[a-f0-9]{6,10}$|^\d{6,10}$') { $randomValueNameCount++ }
                if (Test-KovterEncodedValue -Value $v) { $encodedValueCount++ }
            }

            if ($randomValueNameCount -ge 3 -and $encodedValueCount -ge 2) {
                $ind = New-Indicator -Category 'kovter_ioc' `
                    -Detail "Kovter-like random registry payload key found: HKCU\\Software\\$($k.PSChildName) (random_values=$randomValueNameCount, encoded_values=$encodedValueCount)" `
                    -Weight 14
                $indicators.Add($ind)
                $totalScore += 14
            }
        }
    }
} catch { }

try {
    # Dedicated Kovter script block signatures for fileless chains (mshta -> powershell/iex/reflection).
    # To reduce false positives, require at least one execution/stager signal and correlation.
    $kovterExecPatterns = @(
        '(?i)\biex\s+\$env:[a-z0-9_]{4,}',
        '(?i)\[Text\.Encoding\]::ASCII\.GetString\(\[Convert\]::FromBase64String',
        '(?i)\bmshta(\.exe)?\b.+(javascript:|vbscript:)',
        '(?i)powershell(\.exe)?\s+.*(-w|--windowstyle)\s*hidden.*(frombase64string|\biex\b)'
    )
    $kovterSupportPatterns = @(
        '(?i)DefineDynamicAssembly|RunAndCollect|DefineDynamicModule',
        '(?i)GlobalAssemblyCache.+System\.dll'
    )
    $kovterExecHits = [System.Collections.Generic.HashSet[string]]::new()
    $kovterSupportHits = [System.Collections.Generic.HashSet[string]]::new()
    $kovterPsEvents = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $cutoff -and $_.Id -eq 4104 }
    foreach ($evt in $kovterPsEvents) {
        $msg = if ($evt.Message) { [string]$evt.Message } else { '' }
        if ([string]::IsNullOrWhiteSpace($msg)) { continue }
        foreach ($pat in $kovterExecPatterns) {
            if ($msg -match $pat) { [void]$kovterExecHits.Add($pat) }
        }
        foreach ($pat in $kovterSupportPatterns) {
            if ($msg -match $pat) { [void]$kovterSupportHits.Add($pat) }
        }
    }

    $hasKovterPsCorrelation = $false
    if ($kovterExecHits.Count -ge 2) {
        $hasKovterPsCorrelation = $true
    } elseif ($kovterExecHits.Count -ge 1 -and $kovterSupportHits.Count -ge 1) {
        $hasKovterPsCorrelation = $true
    }

    if ($hasKovterPsCorrelation) {
        $execList = @($kovterExecHits) -join '; '
        $supportList = @($kovterSupportHits) -join '; '
        $ind = New-Indicator -Category 'kovter_ioc' `
            -Detail "Kovter-like scriptblock correlation detected (exec_patterns=[$execList] support_patterns=[$supportList])" `
            -Weight 12
        $indicators.Add($ind)
        $totalScore += 12
    }
} catch { }

###############################################################################
# CATEGORY 1 — FILE SYSTEM
###############################################################################

foreach ($dir in $suspiciousPaths) {
    try {
        $files = Get-ChildItem -Path $dir -Recurse -Force -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -gt $cutoff }

        foreach ($f in $files) {
            # Skip our own staging directory
            if ($f.FullName -like "*MalwareRemediation*") { continue }
	    if ($f.FullName -like "*Microsoft\Crypto*") { continue }
	    if ($f.FullName -like "*Windows Defender*") { continue }
	    if ($f.FullName -like "*WinDefend*") { continue }

            $ext = $f.Extension.ToLower()

            # Ransom note filename check (weight 3)
            foreach ($pat in $ransomPatterns) {
                if ($f.Name -like "*$pat*") {
                    $ind = New-Indicator -Category 'filesystem' `
                        -Detail "Ransom note pattern '$pat' found: $($f.FullName)" `
                        -Weight 3
                    $indicators.Add($ind)
                    $totalScore += 3
                    break
                }
            }

            # Executable in suspicious location (weight 3)
            if ($ext -in @('.exe','.dll','.scr')) {
                $ind = New-Indicator -Category 'filesystem' `
                    -Detail "Executable dropped in suspicious path: $($f.FullName)" `
                    -Weight 3
                $indicators.Add($ind)
                $totalScore += 3
            }

            # High-entropy filename (weight 2)
            if (Test-HighEntropy $f.Name) {
                $ind = New-Indicator -Category 'filesystem' `
                    -Detail "High-entropy filename detected: $($f.FullName)" `
                    -Weight 2
                $indicators.Add($ind)
                $totalScore += 2
            }

            # Script/macro dropped recently (weight 2)
            if ($ext -in @('.ps1','.vbs','.bat','.cmd','.hta')) {
                $ind = New-Indicator -Category 'filesystem' `
                    -Detail "Script file dropped in suspicious path: $($f.FullName)" `
                    -Weight 2
                $indicators.Add($ind)
                $totalScore += 2
            }
        }
    } catch { }
}

###############################################################################
# CATEGORY 2 — REGISTRY
###############################################################################

$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)

# Collect current run key values and flag anything pointing at suspicious paths
foreach ($key in $runKeys) {
    if (-not (Test-Path $key)) { continue }
    try {
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        $props.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' } |
            ForEach-Object {
                $rawVal = [string]$_.Value
                $val = $rawVal.ToLower()
                $expandedVal = [Environment]::ExpandEnvironmentVariables($rawVal).ToLower()

                $suspiciousMatch = $false
                foreach ($sp in $suspiciousPaths) {
                    $spl = $sp.ToLower()
                    if ($val -like "*$spl*" -or $expandedVal -like "*$spl*") {
                        $suspiciousMatch = $true
                        break
                    }
                }

                if (-not $suspiciousMatch) {
                    $envPathMarkers = @('%appdata%','%localappdata%','%temp%','%tmp%','%public%','%programdata%')
                    foreach ($marker in $envPathMarkers) {
                        if ($val -like "*$marker*") {
                            $suspiciousMatch = $true
                            break
                        }
                    }
                }

                if ($suspiciousMatch) {
                        $weight = if ($key -like '*RunOnce*') { 5 } else { 5 }
                        $ind = New-Indicator -Category 'registry' `
                            -Detail "Run key '$($_.Name)' points to suspicious path: $($_.Value)" `
                            -Weight $weight
                        $indicators.Add($ind)
                        $totalScore += $weight
                }
            }
    } catch { }
}

# Scheduled task actions launching from user-writable locations (weight 5)
try {
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $st = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $st) {
            foreach ($a in ($t.Actions | Where-Object { $_ })) {
                $exec = [string]$a.Execute
                $args = [string]$a.Arguments
                $cmdText = ($exec + ' ' + $args).ToLower()
                $expandedCmd = [Environment]::ExpandEnvironmentVariables($cmdText).ToLower()

                $taskSuspicious = $false
                foreach ($sp in $suspiciousPaths) {
                    if ($expandedCmd -like "*$($sp.ToLower())*") {
                        $taskSuspicious = $true
                        break
                    }
                }

                if (-not $taskSuspicious) {
                    foreach ($marker in @('%appdata%','%localappdata%','%temp%','%tmp%','%public%','%programdata%')) {
                        if ($cmdText -like "*$marker*") {
                            $taskSuspicious = $true
                            break
                        }
                    }
                }

                if ($taskSuspicious) {
                    # Common benign updaters that legitimately run from user-writable paths.
                    $isKnownBenignTask = $false
                    if (
                        $t.TaskName -match '(?i)^OneDrive (Reporting|Standalone Update) Task-' -and
                        $cmdText -match '(?i)onedrivestandaloneupdater\.exe'
                    ) {
                        $isKnownBenignTask = $true
                    }
                    if ($isKnownBenignTask) { continue }

                    $ind = New-Indicator -Category 'persistence' `
                        -Detail "Scheduled task '$($t.TaskName)' executes from suspicious path: $exec $args" `
                        -Weight 5
                    $indicators.Add($ind)
                    $totalScore += 5
                }
            }
        }
    }
} catch { }

# Image File Execution Options — debugger hijacking (weight 3)
$ifeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeoPath) {
    try {
        Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
            $debugger = (Get-ItemProperty -Path $_.PSPath -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
            if ($debugger) {
                $ind = New-Indicator -Category 'registry' `
                    -Detail "IFEO debugger hijack on '$($_.PSChildName)': $debugger" `
                    -Weight 3
                $indicators.Add($ind)
                $totalScore += 3
            }
        }
    } catch { }
}

# Winlogon hijack check (weight 4)
$winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (Test-Path $winlogonPath) {
    try {
        $wl = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue
        $shellVal = $wl.Shell
        $userinit = $wl.Userinit
        if ($shellVal -and $shellVal -notmatch '^explorer\.exe$') {
            $ind = New-Indicator -Category 'registry' `
                -Detail "Winlogon Shell modified: '$shellVal'" `
                -Weight 4
            $indicators.Add($ind)
            $totalScore += 4
        }
        if ($userinit -and $userinit -notmatch 'userinit\.exe') {
            $ind = New-Indicator -Category 'registry' `
                -Detail "Winlogon Userinit modified: '$userinit'" `
                -Weight 4
            $indicators.Add($ind)
            $totalScore += 4
        }
    } catch { }
}

# Large binary blob in registry (fileless indicator, weight 4)
# Kovter and similar fileless malware stores encoded payloads here.
# This scan is intentionally optional because recursive registry walks are slow.
if ($EnableRegistryBlobScan) {
    $blobKeys = @(
        'HKCU:\SOFTWARE',
        'HKLM:\SOFTWARE'
    )
    foreach ($bk in $blobKeys) {
        if (-not (Test-Path $bk)) { continue }
        try {
            Get-ChildItem -Path $bk -Recurse -ErrorAction SilentlyContinue |
                ForEach-Object {
                    try {
                        Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue |
                            ForEach-Object {
                                $_.PSObject.Properties |
                                    Where-Object {
                                        $_.Name -notmatch '^PS' -and
                                        $_.Value -is [byte[]] -and
                                        $_.Value.Length -gt 5000
                                    } |
                                    ForEach-Object {
                                        $ind = New-Indicator -Category 'registry' `
                                            -Detail "Large binary blob ($($_.Value.Length) bytes) in registry at: $($_.Name)" `
                                            -Weight 4
                                        $indicators.Add($ind)
                                        $totalScore += 4
                                    }
                            }
                    } catch { }
                }
        } catch { }
    }
}

###############################################################################
# CATEGORY 3 — PROCESSES
###############################################################################

# Sample CPU over HighCpuSeconds
$before  = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, Name, CPU
Start-Sleep -Seconds $HighCpuSeconds
$after   = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, Name, CPU,
                                                        WorkingSet, Path, @{
                                                            N='ParentId'
                                                            E={ (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).ParentProcessId }
                                                        }

$knownPaths = @(
    "$env:SystemRoot\",
    "${env:ProgramFiles}\",
    "${env:ProgramFiles(x86)}\",
    "$env:ProgramData\Microsoft\Windows Defender\Platform\"
) | Where-Object { $_ }

# Additional known-safe process path fragments that can live outside standard roots.
$knownSafeProcessPathPatterns = @(
    '(?i)\\Microsoft\\Windows Defender\\platform\\'
)

foreach ($proc in $after) {
    # Skip kernel/system pseudo-processes that do not map to userland malware execution.
    if (($proc.Id -as [int]) -le 4 -or $proc.Name -in @('System','Idle')) { continue }

    # Process running from suspicious path (weight 4)
    if ($proc.Path) {
        $procPathLow = $proc.Path.ToLower()
        $isKnownPath = $false
        foreach ($kp in $knownPaths) {
            if ($procPathLow.StartsWith($kp.ToLower())) { $isKnownPath = $true; break }
        }
        if (-not $isKnownPath) {
            foreach ($safePattern in $knownSafeProcessPathPatterns) {
                if ($proc.Path -match $safePattern) { $isKnownPath = $true; break }
            }
        }
        if (-not $isKnownPath) {
            foreach ($sp in $suspiciousPaths) {
                if ($procPathLow.StartsWith($sp.ToLower())) {
                    $ind = New-Indicator -Category 'process' `
                        -Detail "Process '$($proc.Name)' (PID $($proc.Id)) running from suspicious path: $($proc.Path)" `
                        -Weight 4
                    $indicators.Add($ind)
                    $totalScore += 4
                    break
                }
            }
        }
    }

    # High CPU usage by unknown process (weight 2)
    $beforeEntry = $before | Where-Object { $_.Id -eq $proc.Id } | Select-Object -First 1
    if ($beforeEntry -and $proc.CPU) {
        $cpuDelta = $proc.CPU - $beforeEntry.CPU
        $cpuPct   = ($cpuDelta / $HighCpuSeconds) * 10   # rough % estimate
        if ($cpuPct -gt 20) {
            $isKnown = $false
            foreach ($kp in $knownPaths) {
                if ($proc.Path -and $proc.Path.ToLower().StartsWith($kp.ToLower())) { $isKnown = $true; break }
            }
            if (-not $isKnown) {
                $ind = New-Indicator -Category 'process' `
                    -Detail "Unknown process '$($proc.Name)' (PID $($proc.Id)) consuming high CPU (~$([Math]::Round($cpuPct))%)" `
                    -Weight 2
                $indicators.Add($ind)
                $totalScore += 2
            }
        }
    }

    # High memory by unknown process (weight 2)
    $memMB = [Math]::Round($proc.WorkingSet / 1MB, 1)
    if ($memMB -gt $HighMemoryMB -and $proc.Path) {
        $isKnown = $false
        foreach ($kp in $knownPaths) {
            if ($proc.Path.ToLower().StartsWith($kp.ToLower())) { $isKnown = $true; break }
        }
        if (-not $isKnown) {
            $ind = New-Indicator -Category 'process' `
                -Detail "Unknown process '$($proc.Name)' (PID $($proc.Id)) using $memMB MB RAM from suspicious path" `
                -Weight 2
            $indicators.Add($ind)
            $totalScore += 2
        }
    }

    # PowerShell or cmd spawned by unusual parent (weight 4)
    if ($proc.Name -in @('powershell','pwsh','cmd') -and $proc.ParentId) {
        $parent = $after | Where-Object { $_.Id -eq $proc.ParentId } | Select-Object -First 1
        if ($parent -and $parent.Name -notin $legitimateParents) {
            $ind = New-Indicator -Category 'process' `
                -Detail "'$($proc.Name)' (PID $($proc.Id)) spawned by unusual parent '$($parent.Name)' (PID $($parent.Id))" `
                -Weight 4
            $indicators.Add($ind)
            $totalScore += 4
        }
    }
}

###############################################################################
# CATEGORY 4 — POWERSHELL SCRIPT BLOCK LOGS
###############################################################################

$psLogName = 'Microsoft-Windows-PowerShell/Operational'
$psEvents  = @()

try {
    $psEvents = Get-WinEvent -LogName $psLogName -ErrorAction SilentlyContinue |
                Where-Object { $_.TimeCreated -gt $cutoff -and $_.Id -eq 4104 }
} catch { }

$suspiciousPS = @{
    'Invoke-Expression|\bIEX\b'                          = 3
    'DownloadString|WebClient|Invoke-WebRequest|curl'    = 3
    'FromBase64String|-EncodedCommand'                   = 3
    'vssadmin\s+delete'                                  = 5
    'New-ItemProperty|Set-ItemProperty'                  = 2
    'Start-Process.+-WindowStyle\s+Hidden'               = 3
    'Net\.WebClient|System\.Net\.Http'                   = 2
}

$matchedPS = [System.Collections.Generic.HashSet[string]]::new()
$filteredPsEvents = [System.Collections.Generic.List[object]]::new()
$powerShellBurstHit = $false
$powerShellBurstRecentHit = $false
$psMatchedPatterns = [System.Collections.Generic.HashSet[string]]::new()
$psMatchedPatternsRecent = [System.Collections.Generic.HashSet[string]]::new()
$filteredPsEventsRecent = [System.Collections.Generic.List[object]]::new()

# Ignore script block events generated by this detector itself.
$selfScriptMarkers = @(
    'windows-behavioral-detect.ps1',
    'Behavioral malware detection script for Ansible-driven remediation pipeline',
    '$suspiciousPS = @{',
    'function New-Indicator',
    'PowerShellBurstThreshold'
)

foreach ($evt in $psEvents) {
    $msg = if ($evt.Message) { $evt.Message } else { '' }
    if (-not [string]::IsNullOrWhiteSpace($msg)) {
        $isSelfEvent = $false
        foreach ($marker in $selfScriptMarkers) {
            if ($msg -like "*$marker*") {
                $isSelfEvent = $true
                break
            }
        }
        if ($isSelfEvent) { continue }
    }

    $filteredPsEvents.Add($evt)
    if ($evt.TimeCreated -and $evt.TimeCreated -ge $stagerRecentCutoff) {
        $filteredPsEventsRecent.Add($evt)
    }
    foreach ($pattern in $suspiciousPS.Keys) {
        if ($msg -match $pattern -and -not $matchedPS.Contains($pattern)) {
            $matchedPS.Add($pattern) | Out-Null
            $psMatchedPatterns.Add($pattern) | Out-Null
            if ($evt.TimeCreated -and $evt.TimeCreated -ge $stagerRecentCutoff) {
                $psMatchedPatternsRecent.Add($pattern) | Out-Null
            }
            $weight = $suspiciousPS[$pattern]
            $ind = New-Indicator -Category 'powershell_log' `
                -Detail "Suspicious PS pattern '$pattern' found in Script Block log at $($evt.TimeCreated)" `
                -Weight $weight
            $indicators.Add($ind)
            $totalScore += $weight
        }
    }
}

# Burst detection — 5+ PS events within any 60-second window (weight 2)
if ($filteredPsEvents.Count -ge $PowerShellBurstThreshold) {
    $sorted    = $filteredPsEvents | Sort-Object TimeCreated
    $burstHit  = $false
    for ($i = 0; $i -lt $sorted.Count - $PowerShellBurstThreshold + 1; $i++) {
        $windowStart = $sorted[$i].TimeCreated
        $windowEnd   = $windowStart.AddSeconds(60)
        $inWindow    = ($sorted | Where-Object { $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd }).Count
        if ($inWindow -ge $PowerShellBurstThreshold) {
            $burstHit = $true
            break
        }
    }
    if ($burstHit) {
        $powerShellBurstHit = $true
        $ind = New-Indicator -Category 'powershell_log' `
            -Detail "$PowerShellBurstThreshold+ PowerShell Script Block events detected within a 60-second window" `
            -Weight 2
        $indicators.Add($ind)
        $totalScore += 2
    }
}

# Recent burst signal for stager confirmation logic.
if ($filteredPsEventsRecent.Count -ge $PowerShellBurstThreshold) {
    $sortedRecent = $filteredPsEventsRecent | Sort-Object TimeCreated
    for ($i = 0; $i -lt $sortedRecent.Count - $PowerShellBurstThreshold + 1; $i++) {
        $windowStart = $sortedRecent[$i].TimeCreated
        $windowEnd   = $windowStart.AddSeconds(60)
        $inWindow    = ($sortedRecent | Where-Object { $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd }).Count
        if ($inWindow -ge $PowerShellBurstThreshold) {
            $powerShellBurstRecentHit = $true
            break
        }
    }
}

###############################################################################
# CATEGORY 5 — WINDOWS EVENT LOGS
###############################################################################

# Event ID 7045 — new service installed (weight 3)
try {
    $svcEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 7045
        StartTime = $cutoff
    } -ErrorAction SilentlyContinue

    foreach ($evt in $svcEvents) {
        $ind = New-Indicator -Category 'event_log' `
            -Detail "New service installed (Event 7045): '$($evt.Properties[0].Value)' at $($evt.TimeCreated)" `
            -Weight 3
        $indicators.Add($ind)
        $totalScore += 3
    }
} catch { }

# Event ID 4698 — new scheduled task created (weight 3)
try {
    $taskEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4698
        StartTime = $cutoff
    } -ErrorAction SilentlyContinue

    foreach ($evt in $taskEvents) {
        $ind = New-Indicator -Category 'event_log' `
            -Detail "New scheduled task created (Event 4698) at $($evt.TimeCreated)" `
            -Weight 3
        $indicators.Add($ind)
        $totalScore += 3
    }
} catch { }

# Event ID 4688 — process created at odd hours (weight 1)
try {
    $procEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4688
        StartTime = $cutoff
    } -ErrorAction SilentlyContinue |
    Where-Object {
        $h = $_.TimeCreated.Hour
        $h -lt 6 -or $h -gt 22
    }

    if ($procEvents -and $procEvents.Count -gt 0) {
        $ind = New-Indicator -Category 'event_log' `
            -Detail "$($procEvents.Count) process creation event(s) (Event 4688) during off-hours (10pm-6am)" `
            -Weight 1
        $indicators.Add($ind)
        $totalScore += 1
    }
} catch { }

# Event ID 1102 — audit log cleared (weight 5)
try {
    $clearEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 1102
        StartTime = $cutoff
    } -ErrorAction SilentlyContinue

    if ($clearEvents -and $clearEvents.Count -gt 0) {
        $ind = New-Indicator -Category 'event_log' `
            -Detail "Security audit log was cleared (Event 1102) at $($clearEvents[0].TimeCreated)" `
            -Weight 5
        $indicators.Add($ind)
        $totalScore += 5
    }
} catch { }

###############################################################################
# CATEGORY 6 — WINDOWS DEFENDER TELEMETRY
###############################################################################

# Prefer explicit AV detections over pure heuristics.
try {
    if (Get-Command -Name Get-MpThreatDetection -ErrorAction SilentlyContinue) {
        $mpDetections = Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
            ($_.InitialDetectionTime -and $_.InitialDetectionTime -gt $cutoff) -or
            ($_.LastThreatStatusChangeTime -and $_.LastThreatStatusChangeTime -gt $cutoff)
        }

        foreach ($det in ($mpDetections | Select-Object -First 20)) {
            $threatName = if ($det.ThreatName) { $det.ThreatName } else { 'unknown' }
            $resource   = if ($det.Resources) { ($det.Resources -join ', ') } else { 'unknown resource' }
            $status     = if ($det.ThreatStatusErrorCode) { $det.ThreatStatusErrorCode } else { 'unknown status' }
            $ind = New-Indicator -Category 'defender' `
                -Detail "Windows Defender detection: '$threatName' on $resource (status $status)" `
                -Weight 10
            $indicators.Add($ind)
            $totalScore += 10
        }
    }
} catch { }

###############################################################################
# FINAL SCORING NORMALIZATION + DECISION GATE
###############################################################################

# Prevent duplicate indicator lines from inflating score.
$dedupedIndicators = [System.Collections.Generic.List[PSCustomObject]]::new()
$seenKeys = [System.Collections.Generic.HashSet[string]]::new()
foreach ($ind in $indicators) {
    $key = "$($ind.category)|$($ind.detail)"
    if ($seenKeys.Add($key)) {
        $dedupedIndicators.Add($ind)
    }
}
$indicators = $dedupedIndicators

$scoreSum = ($indicators | Measure-Object -Property weight -Sum).Sum
if ($null -eq $scoreSum) {
    $totalScore = 0
} else {
    $totalScore = [int]$scoreSum
}

$categoriesSeen = [System.Collections.Generic.HashSet[string]]::new()
foreach ($ind in $indicators) {
    [void]$categoriesSeen.Add([string]$ind.category)
}

$defenderHits = @($indicators | Where-Object { $_.category -eq 'defender' }).Count
$wannacryHits = @($indicators | Where-Object { $_.category -eq 'wannacry_ioc' }).Count
$lokibotHits = @($indicators | Where-Object { $_.category -eq 'lokibot_ioc' }).Count
$kovterHits = @($indicators | Where-Object { $_.category -eq 'kovter_ioc' }).Count
$strongHits   = @($indicators | Where-Object { [int]$_.weight -ge 5 }).Count
$ransomHits   = @($indicators | Where-Object {
    $_.category -eq 'filesystem' -and $_.detail -like "Ransom note pattern*"
}).Count
$onlyPowerShellNoise = $categoriesSeen.Count -eq 1 -and $categoriesSeen.Contains('powershell_log')
$psHasDownloadStager = $false
$psHasObfuscation = $false
foreach ($p in $psMatchedPatternsRecent) {
    if ($p -eq 'DownloadString|WebClient|Invoke-WebRequest|curl') { $psHasDownloadStager = $true }
    if ($p -eq 'FromBase64String|-EncodedCommand' -or $p -eq 'Invoke-Expression|\bIEX\b') { $psHasObfuscation = $true }
}
$psLikelyStagerActivity = $false
if ($RequirePsStagerObfuscation) {
    $psLikelyStagerActivity = $psHasDownloadStager -and $psHasObfuscation
} else {
    $psLikelyStagerActivity = $psHasDownloadStager -and ($psHasObfuscation -or $powerShellBurstRecentHit)
}

$threshold      = [Math]::Max($DetectionThreshold, 1)
$likelyInfected = $false
$confirmedInfection = $false
$decisionReason = 'insufficient_correlated_evidence'
$confidence     = 'low'
$malwareFamilyDetected = 'none'

if ($wannacryHits -gt 0) {
    $likelyInfected = $true
    $confirmedInfection = $true
    $decisionReason = 'wannacry_ioc_detected'
    $confidence = 'high'
    $malwareFamilyDetected = 'wannacry'
} elseif ($lokibotHits -gt 0) {
    $likelyInfected = $true
    $confirmedInfection = $true
    $decisionReason = 'lokibot_ioc_detected'
    $confidence = 'high'
    $malwareFamilyDetected = 'lokibot'
} elseif ($kovterHits -gt 0) {
    $likelyInfected = $true
    $confirmedInfection = $true
    $decisionReason = 'kovter_ioc_detected'
    $confidence = 'high'
    $malwareFamilyDetected = 'kovter'
} elseif ($defenderHits -gt 0) {
    $likelyInfected = $true
    $confirmedInfection = $true
    $decisionReason = 'windows_defender_detection'
    $confidence = 'high'
    $malwareFamilyDetected = 'defender'
} elseif (
    $totalScore -ge $threshold -and
    $strongHits -ge $MinStrongHitsToConfirm -and
    $categoriesSeen.Count -ge $MinCategoriesToConfirm -and
    -not $onlyPowerShellNoise
) {
    $likelyInfected = $true
    $confirmedInfection = $true
    $decisionReason = 'multi_signal_high_severity_correlation'
    $confidence = 'medium'
} elseif (
    $totalScore -ge ($threshold - 4) -and
    $ransomHits -gt 0 -and
    $strongHits -ge [Math]::Max(($MinStrongHitsToConfirm - 1), 1) -and
    $categoriesSeen.Count -ge $MinCategoriesToConfirm -and
    -not $onlyPowerShellNoise
) {
    $likelyInfected = $true
    $confirmedInfection = $true
    $decisionReason = 'ransom_note_plus_high_severity_signals'
    $confidence = 'medium'
} elseif ($psLikelyStagerActivity -and $totalScore -ge 5) {
    # Covers commodity infostealer behavior (e.g. LokiBot) where downloader + bursted script blocks
    # may be the strongest telemetry without Defender hits.
    $likelyInfected = $true
    $confirmedInfection = $true
    $decisionReason = 'powershell_stager_pattern_confirmed'
    $confidence = 'medium'
} elseif ($onlyPowerShellNoise) {
    $decisionReason = 'powershell_activity_only_not_confirmed'
}

$malwareEvidence = @(
    $indicators |
    Where-Object { $_.category -in @('wannacry_ioc','lokibot_ioc','kovter_ioc','defender') } |
    Select-Object -ExpandProperty detail -First 20
)

###############################################################################
# OUTPUT — single JSON object to stdout
###############################################################################

$output = [ordered]@{
    vmid             = $env:COMPUTERNAME
    scan_time        = (Get-Date -Format 'o')
    lookback_hours   = $LookbackHours
    score            = $totalScore
    threshold        = $threshold
    likely_infected  = $likelyInfected
    confirmed_infection = $confirmedInfection
    confidence       = $confidence
    decision_reason  = $decisionReason
    malware_family_detected = $malwareFamilyDetected
    malware_evidence = $malwareEvidence
    strong_hits      = $strongHits
    defender_hits    = $defenderHits
    wannacry_hits    = $wannacryHits
    lokibot_hits     = $lokibotHits
    kovter_hits      = $kovterHits
    ps_stager_activity = $psLikelyStagerActivity
    only_powershell_noise = $onlyPowerShellNoise
    categories_seen  = @($categoriesSeen)
    indicator_count  = $indicators.Count
    indicators       = $indicators
}

# Emit clean JSON — this is what the Ansible playbook parses
$output | ConvertTo-Json -Depth 6 -Compress
