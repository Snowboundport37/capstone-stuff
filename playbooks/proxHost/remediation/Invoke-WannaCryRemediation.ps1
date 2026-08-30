[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Audit,
    [switch]$Contain,
    [switch]$Remediate,
    [switch]$ReportOnly,
    [switch]$DryRun,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'output'),
    [string]$QuarantinePath = "$env:ProgramData\WannaCry-Quarantine",
    [switch]$DisableSMBv1,
    [switch]$BlockSMBTemporarily,
    [switch]$RunDefenderScan,
    [switch]$CreateRestorePointIfSupported,
    [switch]$SkipNetworkIsolation,
    [switch]$SkipRegistryCleanup,
    [switch]$SkipServiceCleanup,
    [switch]$SkipFileQuarantine,
    [switch]$IsolateHost,
    [string]$ManagementAdapterAlias = '',
    [switch]$CheckKillSwitch,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'iocs.json'),
    [string]$ReportInputPath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:PSCmd = $PSCmdlet
$script:ActionLog = New-Object System.Collections.Generic.List[string]
$script:ErrorLog  = New-Object System.Collections.Generic.List[string]
$script:Findings  = New-Object System.Collections.Generic.List[object]
$script:DetectedFiles = New-Object System.Collections.Generic.List[object]
$script:ComputedHashes = New-Object System.Collections.Generic.List[object]
$script:ServiceFindings = New-Object System.Collections.Generic.List[object]
$script:RegistryFindings = New-Object System.Collections.Generic.List[object]
$script:NetworkFindings = New-Object System.Collections.Generic.List[object]
$script:Recommendations = New-Object System.Collections.Generic.List[string]
$script:EvidenceExports = New-Object System.Collections.Generic.List[string]

function Add-ActionLog { param([string]$Message) $script:ActionLog.Add($Message) | Out-Null; Write-Verbose $Message }
function Add-ErrorLog  { param([string]$Message) $script:ErrorLog.Add($Message) | Out-Null; Write-Warning $Message }
function Add-Finding {
    param([string]$Type, [string]$Indicator, [string]$Severity, [string]$Details)
    $script:Findings.Add([pscustomobject]@{ type=$Type; indicator=$Indicator; severity=$Severity; details=$Details }) | Out-Null
}
function Invoke-Guarded {
    param([string]$Target, [string]$Action, [scriptblock]$ScriptBlock)
    if ($DryRun -or $WhatIfPreference) { Add-ActionLog "DRYRUN: $Action :: $Target"; return }
    if ($script:PSCmd.ShouldProcess($Target, $Action)) {
        try { & $ScriptBlock; Add-ActionLog "$Action :: $Target" }
        catch { Add-ErrorLog "$Action failed for $Target :: $($_.Exception.Message)" }
    }
}

function Resolve-Mode {
    $set = @($Audit, $Contain, $Remediate, $ReportOnly) | Where-Object { $_ }
    if ($set.Count -eq 0) { return 'Audit' }
    if ($set.Count -gt 1) { throw 'Specify only one mode: -Audit, -Contain, -Remediate, or -ReportOnly.' }
    if ($Audit) { return 'Audit' }
    if ($Contain) { return 'Contain' }
    if ($Remediate) { return 'Remediate' }
    return 'ReportOnly'
}

function Assert-AdminIfNeeded {
    param([string]$Mode)
    if ($Mode -in @('Contain','Remediate')) {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) { throw 'Contain/Remediate mode requires running as Administrator.' }
    }
}

function Load-Configuration {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Config file not found: $ConfigPath" }
    return (Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json)
}

function New-RunPaths {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $root = Join-Path $OutputPath "$env:COMPUTERNAME-$stamp"
    $null = New-Item -Path $root -ItemType Directory -Force
    return [ordered]@{
        Root = $root
        Transcript = Join-Path $root 'transcript.log'
        JsonReport = Join-Path $root 'remediation-report.json'
        TextSummary = Join-Path $root 'remediation-summary.txt'
        MarkdownSummary = Join-Path $root 'incident-summary.md'
        RegistryExport = Join-Path $root 'registry-artifacts.reg'
    }
}

function Get-FileHashesSafe {
    param([string]$Path)
    $o = [ordered]@{ SHA256=''; SHA1=''; MD5='' }
    try { $o.SHA256 = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch {}
    try { $o.SHA1   = (Get-FileHash -Path $Path -Algorithm SHA1   -ErrorAction Stop).Hash.ToLowerInvariant() } catch {}
    try { $o.MD5    = (Get-FileHash -Path $Path -Algorithm MD5    -ErrorAction Stop).Hash.ToLowerInvariant() } catch {}
    return [pscustomobject]$o
}

function Get-OwnerSafe {
    param([string]$Path)
    try { return (Get-Acl -Path $Path -ErrorAction Stop).Owner } catch { return '' }
}

function Expand-ScanPaths {
    param([object[]]$Paths)
    $out = @()
    foreach ($p in $Paths) {
        $ep = [Environment]::ExpandEnvironmentVariables([string]$p)
        if (Test-Path -LiteralPath $ep) { $out += $ep }
    }
    if (Test-Path 'C:\Users') { $out += 'C:\Users' }
    return ($out | Select-Object -Unique)
}

function Detect-FileIndicators {
    param([object]$Config, [string[]]$ScanRoots)
    $nameSet = @{}; foreach ($n in $Config.artifact_names) { $nameSet[$n.ToLowerInvariant()] = $true }
    $h256 = @{}; foreach ($h in $Config.hashes.sha256) { $h256[$h.ToLowerInvariant()] = $true }
    $h1 = @{}; foreach ($h in $Config.hashes.sha1) { $h1[$h.ToLowerInvariant()] = $true }
    $hmd5 = @{}; foreach ($h in $Config.hashes.md5) { $hmd5[$h.ToLowerInvariant()] = $true }

    foreach ($root in $ScanRoots) {
        Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $f = $_
            $name = $f.Name.ToLowerInvariant()
            $nameHit = $nameSet.ContainsKey($name)
            $wnryInWorkDir = ($f.Extension -ieq '.wnry') -and ($f.FullName -match '\\Users\\|\\ProgramData\\')
            if (-not $nameHit -and -not $wnryInWorkDir) { return }

            $hashes = Get-FileHashesSafe -Path $f.FullName
            $hashHit = $h256.ContainsKey($hashes.SHA256) -or $h1.ContainsKey($hashes.SHA1) -or $hmd5.ContainsKey($hashes.MD5)

            $info = [pscustomobject]@{
                path = $f.FullName; name = $f.Name; size = $f.Length; owner = (Get-OwnerSafe -Path $f.FullName)
                last_write_utc = $f.LastWriteTimeUtc.ToString('o'); sha256 = $hashes.SHA256; sha1 = $hashes.SHA1; md5 = $hashes.MD5
                name_match = $nameHit; hash_match = $hashHit; wnry_artifact = $wnryInWorkDir
            }
            $script:DetectedFiles.Add($info) | Out-Null
            $script:ComputedHashes.Add([pscustomobject]@{ path = $f.FullName; sha256 = $hashes.SHA256; sha1 = $hashes.SHA1; md5 = $hashes.MD5 }) | Out-Null
            if ($hashHit) { Add-Finding 'hash' $f.FullName 'high' "Exact hash match for configured WannaCry IOC." }
            elseif ($nameHit -or $wnryInWorkDir) { Add-Finding 'artifact' $f.FullName 'medium' 'Known WannaCry family artifact filename/path.' }
        }
    }
}

function Detect-ServiceIndicators {
    param([object]$Config)
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $svc = $_
        if ($svc.Name -ieq $Config.services.known_name -or
            $svc.DisplayName -like "*$($Config.services.display_name_pattern)*" -or
            $svc.PathName -match [regex]::Escape($Config.services.path_parameter_pattern)) {
            $obj = [pscustomobject]@{ name=$svc.Name; display_name=$svc.DisplayName; state=$svc.State; start_mode=$svc.StartMode; path_name=$svc.PathName }
            $script:ServiceFindings.Add($obj) | Out-Null
            Add-Finding 'service' $svc.Name 'high' 'Service indicator consistent with WannaCry persistence.'
        }
    }
}

function Detect-RegistryIndicators {
    param([object]$Config)
    $runPath = "Registry::" + $Config.registry.run_key_path
    if (Test-Path $runPath) {
        $props = Get-ItemProperty -Path $runPath -ErrorAction SilentlyContinue
        if ($props) {
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                if (($p.Value -as [string]) -match 'tasksche\.exe|@WanaDecryptor@\.exe|main_Cry\.exe|m\.vbs') {
                    $script:RegistryFindings.Add([pscustomobject]@{ path=$runPath; name=$p.Name; value=[string]$p.Value }) | Out-Null
                    Add-Finding 'registry' "$runPath\$($p.Name)" 'high' 'Suspicious Run key persistence.'
                }
            }
        }
    }
    $wcPath = "Registry::" + $Config.registry.wanacrypt0r_key_path
    if (Test-Path $wcPath) {
        $wd = (Get-ItemProperty -Path $wcPath -Name $Config.registry.wanacrypt0r_value_name -ErrorAction SilentlyContinue).$($Config.registry.wanacrypt0r_value_name)
        $script:RegistryFindings.Add([pscustomobject]@{ path=$wcPath; name=$Config.registry.wanacrypt0r_value_name; value=[string]$wd }) | Out-Null
        Add-Finding 'registry' $wcPath 'high' 'WanaCrypt0r registry key present.'
    }

    # Wallpaper indicator in current and loaded user hives.
    $wallRel = 'Control Panel\Desktop'
    $wallValue = $Config.registry.wallpaper_value_name
    foreach ($hivePath in @('HKCU:\' ,'HKU:\')) {
        if (-not (Test-Path $hivePath)) { continue }
        Get-ChildItem -Path $hivePath -ErrorAction SilentlyContinue | ForEach-Object {
            $sid = $_.PSChildName
            if ($hivePath -eq 'HKU:\' -and $sid -notmatch '^S-1-5-21-') { return }
            $k = Join-Path $_.PSPath $wallRel
            if (Test-Path $k) {
                $wall = (Get-ItemProperty -Path $k -Name $wallValue -ErrorAction SilentlyContinue).$wallValue
                if (($wall -as [string]) -match '@WanaDecryptor@\.bmp') {
                    $script:RegistryFindings.Add([pscustomobject]@{ path=$k; name=$wallValue; value=[string]$wall }) | Out-Null
                    Add-Finding 'registry' "$k\$wallValue" 'medium' 'Wallpaper points to WannaCry artifact.'
                }
            }
        }
    }
}

function Stop-SuspiciousProcesses {
    param([object]$Config)
    $h256 = @{}; foreach ($h in $Config.hashes.sha256) { $h256[$h.ToLowerInvariant()] = $true }
    $patterns = '@WanaDecryptor@|main_Cry|tasksche|taskdl|taskse|wannacry|wncry|wcry|mssecsvc|b547dc7a'
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $proc = $_
        $isSuspicious = ($proc.Name -match $patterns) -or ($proc.CommandLine -match $patterns)
        $ep = $proc.ExecutablePath
        if (-not $isSuspicious -and $ep -and (Test-Path -LiteralPath $ep)) {
            try {
                $sha = (Get-FileHash -Path $ep -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                if ($h256.ContainsKey($sha)) { $isSuspicious = $true }
            } catch {}
        }
        if ($isSuspicious) {
            Invoke-Guarded -Target "PID $($proc.ProcessId) $($proc.Name)" -Action 'Stop suspicious process' -ScriptBlock {
                Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Detect-Exposure {
    param([object]$Config)
    try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $smb1 = $null }
    $script:NetworkFindings.Add([pscustomobject]@{ check='SMBv1Enabled'; value=$smb1 }) | Out-Null
    if ($smb1 -eq $true) { Add-Finding 'exposure' 'SMBv1Enabled' 'medium' 'SMBv1 is enabled.' }

    try {
        $ports = Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -in 445,139 }
        $script:NetworkFindings.Add([pscustomobject]@{ check='ListeningSMBPorts'; value=($ports.LocalPort | Select-Object -Unique) }) | Out-Null
        if ($ports) { Add-Finding 'exposure' 'Listening445or139' 'medium' 'SMB listening ports exposed.' }
    } catch {}

    # Best-effort SMB scanning signal: high volume SMBServer operational events in recent window.
    try {
        $since = (Get-Date).AddMinutes(-15)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-SMBServer/Operational'
            StartTime = $since
        } -ErrorAction Stop
        $count = @($events).Count
        $script:NetworkFindings.Add([pscustomobject]@{ check='SMBServerOperationalEvents15m'; value=$count }) | Out-Null
        if ($count -ge 500) {
            Add-Finding 'exposure' 'PotentialSMBScanningPattern' 'medium' 'High SMBServer event volume in last 15 minutes.'
        }
    } catch {}

    $kbs = @(); try { $kbs = Get-HotFix -ErrorAction Stop | Select-Object -ExpandProperty HotFixID } catch {}
    $matchedKb = @($Config.ms17_010_kbs | Where-Object { $kbs -contains $_ })
    $script:NetworkFindings.Add([pscustomobject]@{ check='MS17_010PatchEvidence'; value=$matchedKb }) | Out-Null
    if ($matchedKb.Count -eq 0) { Add-Finding 'exposure' 'MS17_010PatchEvidenceMissing' 'medium' 'No configured MS17-010-era KB evidence found.' }

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $script:NetworkFindings.Add([pscustomobject]@{ check='Defender'; value=[pscustomobject]@{ real_time=$mp.RealTimeProtectionEnabled; av_sig_age=$mp.AntivirusSignatureAge; service=$mp.AMServiceEnabled } }) | Out-Null
        } catch {}
    }

    if ($CheckKillSwitch) {
        foreach ($d in $Config.kill_switch_domains) {
            $dns = $null; $http = $null
            try { $dns = (Resolve-DnsName -Name $d -Type A -ErrorAction Stop | Select-Object -First 1 -ExpandProperty IPAddress) } catch {}
            try { $http = (Invoke-WebRequest -UseBasicParsing -Method Head -Uri ("http://{0}" -f $d) -TimeoutSec 5 -ErrorAction Stop).StatusCode } catch {}
            $script:NetworkFindings.Add([pscustomobject]@{ check='KillSwitch'; domain=$d; dns=$dns; http_status=$http }) | Out-Null
        }
    }
}

function Get-Confidence {
    param([object]$Config)
    $score = 0
    $hasExact = ($script:Findings | Where-Object { $_.type -eq 'hash' }).Count -gt 0
    if ($hasExact) { return 100 }
    if (($script:ServiceFindings | Where-Object { $_.name -ieq $Config.services.known_name }).Count -gt 0) { $score += 40 }
    if (($script:DetectedFiles | Where-Object { $_.name -ieq '@WanaDecryptor@.exe' }).Count -gt 0) { $score += 50 }
    if (($script:DetectedFiles | Measure-Object).Count -ge 3) { $score += 30 }
    if (($script:RegistryFindings | Measure-Object).Count -gt 0) { $score += 25 }
    $smb1Finding = $script:NetworkFindings | Where-Object { $_.check -eq 'SMBv1Enabled' -and $_.value -eq $true }
    $patchMissing = $script:NetworkFindings | Where-Object { $_.check -eq 'MS17_010PatchEvidence' -and (@($_.value).Count -eq 0) }
    if ($smb1Finding -and $patchMissing) { $score += 15 }
    if ($score -gt 100) { $score = 100 }
    return $score
}

function Quarantine-MatchedFiles {
    param([object[]]$FileItems)
    $null = New-Item -Path $QuarantinePath -ItemType Directory -Force
    foreach ($f in $FileItems) {
        $src = $f.path
        # Do not remove encrypted user documents automatically.
        if ($f.wnry_artifact -or $src -match '\.wnry$|\.wncry$') {
            Add-ActionLog "Skipped quarantine for encrypted artifact: $src"
            continue
        }
        if (-not (Test-Path -LiteralPath $src)) { continue }
        $stamp = Get-Date -Format 'yyyyMMddHHmmss'
        $dst = Join-Path $QuarantinePath ("{0}_{1}" -f $stamp, [IO.Path]::GetFileName($src))
        Invoke-Guarded -Target $src -Action 'Quarantine file' -ScriptBlock { Move-Item -LiteralPath $src -Destination $dst -Force }
    }
}

function Export-RegistryArtifacts {
    param([object]$Config, [string]$DestinationRegFile)
    try {
        if (Test-Path -LiteralPath $DestinationRegFile) { Remove-Item -LiteralPath $DestinationRegFile -Force -ErrorAction SilentlyContinue }
        $paths = @(
            $Config.registry.run_key_path,
            $Config.registry.wanacrypt0r_key_path,
            'HKCU\Control Panel\Desktop'
        )
        foreach ($kp in $paths) {
            $safeName = ($kp -replace '[\\/:*?"<>| ]','_')
            $out = [IO.Path]::ChangeExtension($DestinationRegFile, ".$safeName.reg")
            $null = & reg.exe export $kp $out /y 2>$null
            if (Test-Path -LiteralPath $out) {
                $script:EvidenceExports.Add($out) | Out-Null
                Add-ActionLog "Exported registry artifact: $kp -> $out"
            }
        }
    } catch {
        Add-ErrorLog "Registry export failed: $($_.Exception.Message)"
    }
}

function Build-Recommendations {
    param([int]$Score)
    if ($Score -ge 71) { $script:Recommendations.Add('Likely/confirmed infection: isolate host, investigate lateral movement, and plan full reimage for high-trust recovery.') | Out-Null }
    if (($script:DetectedFiles | Where-Object { $_.wnry_artifact }).Count -gt 0) { $script:Recommendations.Add('Encrypted artifacts present: restore from known-good offline backups; do not expect direct decryption.') | Out-Null }
    $script:Recommendations.Add('Patch systems for MS17-010-era exposure and disable SMBv1 when business requirements permit.') | Out-Null
    $script:Recommendations.Add('Review credential hygiene and rotate potentially exposed local/admin credentials.') | Out-Null
    $script:Recommendations.Add('Review neighboring systems for SMB exposure (445/139) and similar WannaCry indicators.') | Out-Null
}

try {
    $Mode = Resolve-Mode
    Assert-AdminIfNeeded -Mode $Mode
    $Config = Load-Configuration
    $RunPaths = New-RunPaths
    Start-Transcript -Path $RunPaths.Transcript -Force | Out-Null

    if ($Mode -eq 'ReportOnly') {
        if (-not $ReportInputPath) { throw 'ReportOnly mode requires -ReportInputPath <json report path>.' }
        $prior = Get-Content -LiteralPath $ReportInputPath -Raw | ConvertFrom-Json
        $prior | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $RunPaths.JsonReport -Encoding UTF8
        $txt = @(
            "WannaCry ReportOnly Summary"
            "Host: $($prior.hostname)"
            "Infection status: $($prior.infection_status)"
            "Confidence score: $($prior.confidence_score)"
            "Indicators matched: $(@($prior.indicators_matched).Count)"
            "Errors: $(@($prior.errors).Count)"
            "Source report: $ReportInputPath"
            "Output report: $($RunPaths.JsonReport)"
        ) -join [Environment]::NewLine
        $txt | Set-Content -LiteralPath $RunPaths.TextSummary -Encoding UTF8
        $md = @(
            "# WannaCry ReportOnly Summary"
            ""
            "## Executive Summary"
            "- Host: $($prior.hostname)"
            "- Infection status: $($prior.infection_status)"
            "- Confidence score: $($prior.confidence_score)"
            ""
            "## Findings"
            "- Indicators matched: $(@($prior.indicators_matched).Count)"
            "- Reported errors: $(@($prior.errors).Count)"
            ""
            "## Next Steps"
            "- Validate containment and eradication completion."
            "- Share report with IR lead and management."
        ) -join [Environment]::NewLine
        $md | Set-Content -LiteralPath $RunPaths.MarkdownSummary -Encoding UTF8
        Write-Host $txt
        Stop-Transcript | Out-Null
        return
    }

    $scanRoots = Expand-ScanPaths -Paths $Config.scan_paths
    Detect-FileIndicators -Config $Config -ScanRoots $scanRoots
    Detect-ServiceIndicators -Config $Config
    Detect-RegistryIndicators -Config $Config
    Detect-Exposure -Config $Config

    if ($Mode -in @('Contain','Remediate')) {
        Export-RegistryArtifacts -Config $Config -DestinationRegFile $RunPaths.RegistryExport
        Stop-SuspiciousProcesses -Config $Config
        if (-not $SkipServiceCleanup) {
            Invoke-Guarded -Target 'mssecsvc2.0' -Action 'Stop service' -ScriptBlock { Stop-Service -Name 'mssecsvc2.0' -Force -ErrorAction SilentlyContinue }
            Invoke-Guarded -Target 'mssecsvc2.0' -Action 'Disable service' -ScriptBlock { Set-Service -Name 'mssecsvc2.0' -StartupType Disabled -ErrorAction SilentlyContinue }
        }
        if ($BlockSMBTemporarily) {
            Invoke-Guarded -Target 'Firewall' -Action 'Block SMB inbound TCP 445/139' -ScriptBlock {
                netsh advfirewall firewall add rule name="WCR-Block-SMB-In-445" dir=in action=block protocol=TCP localport=445 | Out-Null
                netsh advfirewall firewall add rule name="WCR-Block-SMB-In-139" dir=in action=block protocol=TCP localport=139 | Out-Null
                netsh advfirewall firewall add rule name="WCR-Block-SMB-Out-445" dir=out action=block protocol=TCP remoteport=445 | Out-Null
                netsh advfirewall firewall add rule name="WCR-Block-SMB-Out-139" dir=out action=block protocol=TCP remoteport=139 | Out-Null
            }
        }
        if ($IsolateHost -and -not $SkipNetworkIsolation) {
            Invoke-Guarded -Target 'NetworkAdapters' -Action 'Disable non-management adapters' -ScriptBlock {
                Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {
                    $_.Status -eq 'Up' -and ($ManagementAdapterAlias -eq '' -or $_.Name -ne $ManagementAdapterAlias)
                } | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }

    if ($Mode -eq 'Remediate') {
        if ($CreateRestorePointIfSupported) {
            Invoke-Guarded -Target 'SystemRestore' -Action 'Create restore point' -ScriptBlock { Checkpoint-Computer -Description 'WannaCryRemediation' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop }
        }
        if (-not $SkipFileQuarantine) { Quarantine-MatchedFiles -FileItems $script:DetectedFiles }
        if (-not $SkipRegistryCleanup) {
            $runPath = "Registry::" + $Config.registry.run_key_path
            if (Test-Path $runPath) {
                $props = Get-ItemProperty -Path $runPath -ErrorAction SilentlyContinue
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                    if (($p.Value -as [string]) -match 'tasksche\.exe|@WanaDecryptor@\.exe|main_Cry\.exe|m\.vbs') {
                        Invoke-Guarded -Target "$runPath\$($p.Name)" -Action 'Remove Run persistence value' -ScriptBlock { Remove-ItemProperty -Path $runPath -Name $p.Name -Force }
                    }
                }
            }
            $wcPath = "Registry::" + $Config.registry.wanacrypt0r_key_path
            if (Test-Path $wcPath -and ($script:DetectedFiles.Count -gt 0 -or $script:ServiceFindings.Count -gt 0)) {
                Invoke-Guarded -Target $wcPath -Action 'Remove WanaCrypt0r registry key' -ScriptBlock { Remove-Item -Path $wcPath -Recurse -Force }
            }
            # Reset wallpaper only when set to known WannaCry bitmap artifact.
            Get-ChildItem -Path 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' } | ForEach-Object {
                $desk = Join-Path $_.PSPath 'Control Panel\Desktop'
                if (Test-Path $desk) {
                    $wall = (Get-ItemProperty -Path $desk -Name 'Wallpaper' -ErrorAction SilentlyContinue).Wallpaper
                    if (($wall -as [string]) -match '@WanaDecryptor@\.bmp') {
                        Invoke-Guarded -Target "$desk\Wallpaper" -Action 'Reset malicious wallpaper reference' -ScriptBlock {
                            Set-ItemProperty -Path $desk -Name Wallpaper -Value ''
                        }
                    }
                }
            }
        }
        if ($DisableSMBv1) { Invoke-Guarded -Target 'SMBv1' -Action 'Disable SMBv1 protocol' -ScriptBlock { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } }
        if ($RunDefenderScan -and (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
            Invoke-Guarded -Target 'Microsoft Defender' -Action 'Run Defender quick scan' -ScriptBlock { Start-MpScan -ScanType QuickScan }
        }
    }

    $score = Get-Confidence -Config $Config
    Build-Recommendations -Score $score

    $infectionStatus = if ($score -ge 71) { 'likely_or_confirmed_infection' } elseif ($score -ge 31) { 'suspicious' } else { 'exposed_not_confirmed' }
    $report = [ordered]@{
        hostname = $env:COMPUTERNAME
        username = "$env:USERDOMAIN\$env:USERNAME"
        timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
        os_version = (Get-CimInstance Win32_OperatingSystem).Caption
        mode = $Mode
        infection_status = $infectionStatus
        confidence_score = $score
        indicators_matched = $script:Findings
        files_found = $script:DetectedFiles
        hashes_computed = $script:ComputedHashes
        services_found = $script:ServiceFindings
        registry_artifacts = $script:RegistryFindings
        network_exposure_findings = $script:NetworkFindings
        remediation_actions = $script:ActionLog
        evidence_exports = $script:EvidenceExports
        errors = $script:ErrorLog
        recommendations = $script:Recommendations
    }

    $json = $report | ConvertTo-Json -Depth 8
    $json | Set-Content -LiteralPath $RunPaths.JsonReport -Encoding UTF8

    $txt = @(
        "WannaCry Remediation Summary"
        "Host: $($report.hostname)"
        "Mode: $Mode"
        "Infection status: $infectionStatus"
        "Confidence score: $score"
        "Matched indicators: $($script:Findings.Count)"
        "Files found: $($script:DetectedFiles.Count)"
        "Service findings: $($script:ServiceFindings.Count)"
        "Registry findings: $($script:RegistryFindings.Count)"
        "SMBv1 status: $((($script:NetworkFindings | Where-Object { $_.check -eq 'SMBv1Enabled' } | Select-Object -First 1).value))"
        "Patch confidence items: $((($script:NetworkFindings | Where-Object { $_.check -eq 'MS17_010PatchEvidence' } | Select-Object -First 1).value -join ','))"
        "Defender status captured: $([bool]($script:NetworkFindings | Where-Object { $_.check -eq 'Defender' }))"
        "Actions taken: $($script:ActionLog.Count)"
        "Errors: $($script:ErrorLog.Count)"
        "JSON report: $($RunPaths.JsonReport)"
    ) -join [Environment]::NewLine
    $txt | Set-Content -LiteralPath $RunPaths.TextSummary -Encoding UTF8

    $nextSteps = ($script:Recommendations | ForEach-Object { "- $_" }) -join [Environment]::NewLine
    $md = @(
        "# WannaCry Incident Summary"
        ""
        "## Executive Summary"
        "- Infection status: $infectionStatus"
        "- Confidence score: $score"
        "- Mode executed: $Mode"
        ""
        "## Findings"
        "- Indicators matched: $($script:Findings.Count)"
        "- Files found: $($script:DetectedFiles.Count)"
        "- Services found: $($script:ServiceFindings.Count)"
        "- Registry artifacts: $($script:RegistryFindings.Count)"
        ""
        "## Containment Performed"
        "- Actions logged: $($script:ActionLog.Count)"
        ""
        "## Eradication Performed"
        "- Quarantine path: $QuarantinePath"
        "- Registry/service cleanup options respected"
        ""
        "## Remaining Risk"
        "- Errors recorded: $($script:ErrorLog.Count)"
        "- If encryption artifacts exist, perform backup restore and consider full reimage."
        ""
        "## Next Steps"
        $nextSteps
    ) -join [Environment]::NewLine
    $md | Set-Content -LiteralPath $RunPaths.MarkdownSummary -Encoding UTF8

    Write-Host $txt
}
catch {
    Add-ErrorLog "Fatal error: $($_.Exception.Message)"
    throw
}
finally {
    try { Stop-Transcript | Out-Null } catch {}
}
