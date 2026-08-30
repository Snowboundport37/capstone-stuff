[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch { }

$diagDir = 'C:\ProgramData\LokiBotRemediation'
$diagFile = 'C:\ProgramData\LokiBotRemediation\lokibot-run.log'
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
    # Capture executable-style payload names and also existing files without extension.
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

function Test-LokiVariantName([string]$name, [string]$ext) {
    if (-not $name) { return $false }
    # Variant drops are often short random lowercase names (e.g., bfm/bfo/jfx) with no extension.
    if (($name -match '^[a-z]{3,5}$') -and [string]::IsNullOrWhiteSpace($ext)) { return $true }
    # Keep handling known temp marker style names.
    if ($name -match '^(?i)\.ses$|^wct[a-z0-9]{3,8}\.tmp$') { return $true }
    return $false
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
            $fileName = [System.IO.Path]::GetFileName($path)
            if ($fileName -and ($script:removedFileNames -notcontains $fileName)) {
                [void]$script:removedFileNames.Add($fileName)
            }
        } else {
            $script:errorCount++
            Log "FAILED TO DELETE FILE: $path"
        }
    } catch {
        $script:errorCount++
    }
}

Log 'Starting LokiBot cleanup'
$deletedCount = 0
$errorCount = 0
$flaggedPaths = New-Object System.Collections.Generic.List[string]
$removedFileNames = New-Object System.Collections.Generic.List[string]
$skipProcessNames = @(
    'powershell.exe',
    'pwsh.exe',
    'cmd.exe',
    'conhost.exe',
    'explorer.exe',
    'onedrive.exe',
    'filecoauth.exe'
)

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

# 2) Kill suspicious running processes and collect executable paths
Log 'Step 1: stopping suspicious processes'
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $_
        $name = "$($p.Name)"
        $cmd = "$($p.CommandLine)"
        $exe = "$($p.ExecutablePath)"
        $nameLower = $name.ToLowerInvariant()
        $isSuspicious = $false

        # Avoid killing our own shell/agent processes or common benign user apps.
        if ($nameLower -in $skipProcessNames) { return }

        # Strong indicators only: known names, known Loki paths, or Loki C2 marker.
        if ($name -match '(?i)^loki(?:bot)?(\.exe)?$') { $isSuspicious = $true }
        if ($exe -match '(?i)\\Downloads\\Loki\\(loki|lokibot)(\.exe)?$') { $isSuspicious = $true }
        if ($exe -match '(?i)\\AppData\\Roaming\\Loki\\') { $isSuspicious = $true }
        if ($cmd -match '(?i)\\Downloads\\Loki\\|\\AppData\\Roaming\\Loki\\|fre\.php') { $isSuspicious = $true }

        if ($isSuspicious) {
            Add-FlaggedPath -candidate $exe
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Log "KILLED PROCESS: pid=$($p.ProcessId) name=$name"
        }
    }
} catch {
    $errorCount++
}

# 3) Remove Run persistence values and collect payload paths from values
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
            if ($value -match '(?i)loki|lokibot|fre\.php|\\AppData\\|\\Temp\\') {
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

# 4) Remove common LokiBot drop locations and any flagged payload paths
Log 'Step 3: deleting payload files'
$knownPaths = @(
    "$env:APPDATA\lokibot.exe",
    "$env:APPDATA\loki.exe",
    "$env:APPDATA\loki",
    "$env:TEMP\lokibot.exe",
    "$env:TEMP\loki.exe",
    "$env:TEMP\loki",
    "C:\Users\Public\lokibot.exe",
    "C:\Users\Public\loki.exe",
    "C:\Users\Public\loki"
)
foreach ($p in $knownPaths) { Add-FlaggedPath -candidate $p }

# Sample-aware paths from the current lab workflow.
foreach ($profile in Get-UserProfiles) {
    Add-FlaggedPath -candidate (Join-Path $profile 'Downloads\Loki\loki.exe')
    Add-FlaggedPath -candidate (Join-Path $profile 'Downloads\Loki\loki')
    Add-FlaggedPath -candidate (Join-Path $profile 'AppData\Roaming\Loki\loki.exe')
    Add-FlaggedPath -candidate (Join-Path $profile 'AppData\Roaming\Loki\loki')
    Add-FlaggedPath -candidate (Join-Path $profile 'AppData\Local\Temp\.ses')
    Add-FlaggedPath -candidate (Join-Path $profile 'AppData\Local\Temp\wct93D1.tmp')
    try {
        $dropDir = Join-Path $profile 'Downloads\Loki'
        if (Test-Path -LiteralPath $dropDir) {
            Get-ChildItem -LiteralPath $dropDir -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Extension.ToLowerInvariant() -ne '.pcap') {
                    Add-FlaggedPath -candidate $_.FullName
                }
            }
        }
    } catch { }
}

foreach ($p in $flaggedPaths | Select-Object -Unique) { Remove-FileSafe -path $p }

# Clean likely drop artifacts from Downloads\Loki while preserving captured PCAP evidence.
foreach ($profile in Get-UserProfiles) {
    $dropDir = Join-Path $profile 'Downloads\Loki'
    try {
        if (-not (Test-Path -LiteralPath $dropDir)) { continue }
        Get-ChildItem -LiteralPath $dropDir -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $f = $_
            $name = $f.Name
            $ext = $f.Extension.ToLowerInvariant()
            if ($ext -eq '.pcap') { return }
            # In this sample staging folder, remove every non-PCAP file to cover variant names.
            Remove-FileSafe -path $f.FullName
        }
    } catch {
        $errorCount++
    }
}

# Adaptive cleanup for variant temp artifacts (short random names / known marker patterns).
foreach ($profile in Get-UserProfiles) {
    $tempDir = Join-Path $profile 'AppData\Local\Temp'
    try {
        if (-not (Test-Path -LiteralPath $tempDir)) { continue }
        Get-ChildItem -LiteralPath $tempDir -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $f = $_
            if (Test-LokiVariantName -name $f.Name -ext $f.Extension) {
                Remove-FileSafe -path $f.FullName
            }
        }
    } catch {
        $errorCount++
    }
}

# 5) Remove scheduled tasks that relaunch suspicious binaries
Log 'Step 4: removing suspicious scheduled tasks'
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($t in $tasks) {
        $hit = $false
        foreach ($a in $t.Actions) {
            $aText = "$($a.Execute) $($a.Arguments)"
            if ($aText -match '(?i)loki|lokibot|fre\.php|\\Downloads\\Loki\\|\\AppData\\Roaming\\Loki\\') {
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

# 6) Optional network containment for known C2 IPs (from PCAP/lab notes)
Log 'Step 5: applying outbound firewall blocks'
$c2Ips = @()
foreach ($ip in $c2Ips) {
    try {
        if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
            New-NetFirewallRule `
                -DisplayName "LokiBot-C2-Block-$ip" `
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

# 7) Verification pass (processes, files, persistence, tasks)
Log 'Step 6: verification checks'
$verificationFailed = $false

try {
    $leftProc = @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '(?i)^loki(?:bot)?(\.exe)?$' -or
            "$($_.ExecutablePath)" -match '(?i)\\Downloads\\Loki\\|\\AppData\\Roaming\\Loki\\'
        }
    )
    if ($leftProc.Count -gt 0) {
        $verificationFailed = $true
        foreach ($p in $leftProc) { Log "VERIFY FAIL PROCESS: pid=$($p.ProcessId) name=$($p.Name) path=$($p.ExecutablePath)" }
    } else {
        Log 'VERIFY OK: no suspicious Loki processes'
    }
} catch {
    $verificationFailed = $true
    Log 'VERIFY FAIL: unable to inspect processes'
}

try {
    $leftRun = @()
    foreach ($rk in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        if (-not (Test-Path -LiteralPath $rk)) { continue }
        $props = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
            $v = "$($prop.Value)"
            if ($v -match '(?i)loki|lokibot|fre\.php|\\AppData\\|\\Temp\\|\\Downloads\\Loki\\') {
                $leftRun += "$rk::$($prop.Name)=$v"
            }
        }
    }
    if ($leftRun.Count -gt 0) {
        $verificationFailed = $true
        foreach ($r in $leftRun) { Log "VERIFY FAIL RUNKEY: $r" }
    } else {
        Log 'VERIFY OK: no suspicious Run key entries'
    }
} catch {
    $verificationFailed = $true
    Log 'VERIFY FAIL: unable to inspect Run keys'
}

try {
    $leftTasks = @()
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $t = $_
        foreach ($a in $t.Actions) {
            $aText = "$($a.Execute) $($a.Arguments)"
            if ($aText -match '(?i)loki|lokibot|fre\.php|\\Downloads\\Loki\\') {
                $leftTasks += "$($t.TaskPath)$($t.TaskName) => $aText"
            }
        }
    }
    if ($leftTasks.Count -gt 0) {
        $verificationFailed = $true
        foreach ($t in $leftTasks) { Log "VERIFY FAIL TASK: $t" }
    } else {
        Log 'VERIFY OK: no suspicious scheduled tasks'
    }
} catch {
    $verificationFailed = $true
    Log 'VERIFY FAIL: unable to inspect scheduled tasks'
}

try {
    $leftFiles = New-Object System.Collections.Generic.List[string]
    foreach ($profile in Get-UserProfiles) {
        $dropDir = Join-Path $profile 'Downloads\Loki'
        if (Test-Path -LiteralPath $dropDir) {
            Get-ChildItem -LiteralPath $dropDir -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Extension.ToLowerInvariant() -ne '.pcap') {
                    [void]$leftFiles.Add($_.FullName)
                }
            }
        }
        foreach ($path in @(
            (Join-Path $profile 'Downloads\Loki\loki.exe'),
            (Join-Path $profile 'Downloads\Loki\loki'),
            (Join-Path $profile 'AppData\Local\Temp\.ses'),
            (Join-Path $profile 'AppData\Local\Temp\wct93D1.tmp')
        )) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                [void]$leftFiles.Add($path)
            }
        }
        $tempDir = Join-Path $profile 'AppData\Local\Temp'
        if (Test-Path -LiteralPath $tempDir) {
            Get-ChildItem -LiteralPath $tempDir -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if (Test-LokiVariantName -name $_.Name -ext $_.Extension) {
                    [void]$leftFiles.Add($_.FullName)
                }
            }
        }
    }
    if ($leftFiles.Count -gt 0) {
        $verificationFailed = $true
        foreach ($f in ($leftFiles | Select-Object -Unique)) { Log "VERIFY FAIL FILE: $f" }
    } else {
        Log 'VERIFY OK: targeted Loki files removed'
    }
} catch {
    $verificationFailed = $true
    Log 'VERIFY FAIL: unable to inspect targeted files'
}

if ($verificationFailed) {
    $errorCount++
    Log 'VERIFICATION RESULT: FAILED'
} else {
    Log 'VERIFICATION RESULT: PASSED'
}

Log 'REMOVED FILES (NAMES ONLY):'
if ($removedFileNames.Count -gt 0) {
    foreach ($name in ($removedFileNames | Sort-Object -Unique)) {
        Log "REMOVED FILE NAME: $name"
    }
} else {
    Log 'REMOVED FILE NAME: (none)'
}

Log "SUMMARY: deleted_items=$deletedCount errors=$errorCount"
Log 'Cleanup finished'
if ($verificationFailed) { exit 1 }
exit 0
