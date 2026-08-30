[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch { }

$diagDir = 'C:\ProgramData\AgentTeslaRemediation'
$diagFile = 'C:\ProgramData\AgentTeslaRemediation\agenttesla-run.log'
try {
    New-Item -Path $diagDir -ItemType Directory -Force | Out-Null
    Remove-Item -LiteralPath $diagFile -Force -ErrorAction SilentlyContinue
} catch { }

function Log([string]$m) {
    if (-not $m) { return }
    Write-Output $m
    [Console]::Out.Flush()
    try { Add-Content -LiteralPath $diagFile -Value "[$(Get-Date -Format 'HH:mm:ss')] $m" -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
}

function Add-FlaggedPath([string]$candidate) {
    if (-not $candidate) { return }
    $resolved = [Environment]::ExpandEnvironmentVariables($candidate).Trim('"').Trim()
    if (-not $resolved) { return }
    # Capture explicit executable names and also real files that may have no visible extension.
    if ($resolved -match '\.(exe|scr|com)\b' -or (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        if (-not $script:flaggedPaths.Contains($resolved)) {
            [void]$script:flaggedPaths.Add($resolved)
            Log "FLAGGED FILE PATH: $resolved"
        }
    }
}

function Get-UserProfiles {
    try {
        return @(
            Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('All Users','Default','Default User','Public') } |
            Select-Object -ExpandProperty FullName
        )
    } catch {
        return @()
    }
}

function Remove-FileSafe([string]$path) {
    if (-not $path) { return }
    try {
        if (-not (Test-Path -LiteralPath $path)) { return }
        attrib -h -s -r "$path" 2>$null
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $path)) {
            $script:deletedCount++
            Log "DELETED FILE: $path"
        } else {
            $script:errorCount++
            Log "FAILED TO DELETE FILE: $path"
        }
    } catch {
        $script:errorCount++
    }
}

Log 'Starting Agent Tesla cleanup'
$deletedCount = 0
$errorCount = 0
$flaggedPaths = New-Object System.Collections.Generic.List[string]

# 1) Admin/SYSTEM check
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = $id.User.Value -eq 'S-1-5-18'
    if (-not ($isAdmin -or $isSystem)) {
        Log 'FAIL: Script must run as Administrator or SYSTEM'
        exit 1
    }
} catch {
    Log 'FAIL: Unable to validate privileges'
    exit 1
}

# 2) Stop suspicious processes and gather payload paths
Log 'Step 1: stopping suspicious processes'
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $_
        $name = "$($p.Name)"
        $cmd = "$($p.CommandLine)"
        $exe = "$($p.ExecutablePath)"
        $isSuspicious = $false

        if ($name -match '(?i)agent|tesla') { $isSuspicious = $true }
        if ($cmd -match '(?i)agent|tesla|smtp|mail\.') { $isSuspicious = $true }
        if ($exe -match '(?i)\\Users\\.*\\AppData\\|\\Windows\\Temp\\|\\ProgramData\\') { $isSuspicious = $true }

        if ($isSuspicious) {
            Add-FlaggedPath -candidate $exe
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Log "KILLED PROCESS: pid=$($p.ProcessId) name=$name"
        }
    }
} catch {
    $errorCount++
}

# 3) Remove common Run key persistence
Log 'Step 2: removing Run key persistence'
foreach ($rk in @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
)) {
    try {
        if (-not (Test-Path -LiteralPath $rk)) { continue }
        $props = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
            $value = "$($prop.Value)"
            $name = "$($prop.Name)"
            if ($value -match '(?i)agent|tesla|\\AppData\\|\\Temp\\|smtp') {
                Add-FlaggedPath -candidate $value
                Remove-ItemProperty -LiteralPath $rk -Name $name -Force -ErrorAction SilentlyContinue
                Log "REMOVED RUN KEY: $rk :: $name"
                $deletedCount++
            }
        }
    } catch {
        $errorCount++
    }
}

# 4) Delete payloads from likely locations and flagged paths
Log 'Step 3: deleting payload files'
$knownPaths = @(
    "$env:APPDATA\agenttesla.exe",
    "$env:APPDATA\agent.exe",
    "$env:APPDATA\tesla.exe",
    "$env:APPDATA\tesla",
    "$env:TEMP\agenttesla.exe",
    "$env:TEMP\tesla.exe",
    "$env:TEMP\tesla",
    "C:\ProgramData\agenttesla.exe",
    "C:\ProgramData\tesla.exe",
    "C:\ProgramData\tesla"
)
foreach ($p in $knownPaths) { Add-FlaggedPath -candidate $p }

# Sample-aware artifacts from lab runs (e.g., Downloads\Tesla\tesla)
foreach ($profile in Get-UserProfiles) {
    Add-FlaggedPath -candidate (Join-Path $profile 'Downloads\Tesla\tesla')
    Add-FlaggedPath -candidate (Join-Path $profile 'Downloads\Tesla\tesla.exe')
    Add-FlaggedPath -candidate (Join-Path $profile 'AppData\Roaming\Tesla\tesla')
    Add-FlaggedPath -candidate (Join-Path $profile 'AppData\Roaming\Tesla\tesla.exe')
}
foreach ($p in $flaggedPaths | Select-Object -Unique) { Remove-FileSafe -path $p }

# 5) Remove suspicious scheduled tasks
Log 'Step 4: removing suspicious scheduled tasks'
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($t in $tasks) {
        $hit = $false
        foreach ($a in $t.Actions) {
            $aText = "$($a.Execute) $($a.Arguments)"
            if ($aText -match '(?i)agent|tesla|\\AppData\\|\\Temp\\|powershell\s+-enc') {
                $hit = $true
                break
            }
        }
        if ($hit) {
            Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
            Log "REMOVED TASK: $($t.TaskPath)$($t.TaskName)"
            $deletedCount++
        }
    }
} catch {
    $errorCount++
}

# 6) Network containment: block outbound SMTP commonly used for exfiltration
Log 'Step 5: blocking outbound SMTP exfil ports'
try {
    New-NetFirewallRule `
        -DisplayName 'AgentTesla-Block-SMTP-25' `
        -Direction Outbound `
        -Protocol TCP `
        -RemotePort 25 `
        -Action Block `
        -Profile Any `
        -ErrorAction SilentlyContinue | Out-Null

    New-NetFirewallRule `
        -DisplayName 'AgentTesla-Block-SMTP-465' `
        -Direction Outbound `
        -Protocol TCP `
        -RemotePort 465 `
        -Action Block `
        -Profile Any `
        -ErrorAction SilentlyContinue | Out-Null

    New-NetFirewallRule `
        -DisplayName 'AgentTesla-Block-SMTP-587' `
        -Direction Outbound `
        -Protocol TCP `
        -RemotePort 587 `
        -Action Block `
        -Profile Any `
        -ErrorAction SilentlyContinue | Out-Null

    Log 'APPLIED SMTP firewall blocks: 25, 465, 587'
} catch {
    $errorCount++
}

# Optional C2 IP blocking list from PCAP analysis
$c2Ips = @()
foreach ($ip in $c2Ips) {
    try {
        if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
            New-NetFirewallRule `
                -DisplayName "AgentTesla-C2-Block-$ip" `
                -Direction Outbound `
                -RemoteAddress $ip `
                -Action Block `
                -Profile Any `
                -ErrorAction SilentlyContinue | Out-Null
            Log "BLOCKED C2 IP: $ip"
        }
    } catch {
        $errorCount++
    }
}

Log "SUMMARY: deleted_items=$deletedCount errors=$errorCount"
Log 'Cleanup finished'
exit 0
