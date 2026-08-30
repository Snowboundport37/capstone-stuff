# WannaCry Remediation Script
# Force UTF-8 so QEMU agent captures readable text
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch { }

# ── Diag log ──────────────────────────────────────────────────────────────────
$diagFile = 'C:\ProgramData\WannaCryRemediation\wcr-run.log'
try { Remove-Item -LiteralPath $diagFile -Force -ErrorAction SilentlyContinue } catch { }

function Log([string]$m) {
    if (-not $m) { return }
    Write-Output $m
    [Console]::Out.Flush()
    try { Add-Content -LiteralPath $diagFile -Value "[$(Get-Date -Format 'HH:mm:ss')] $m" -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
}

# ── Auth check ────────────────────────────────────────────────────────────────
# SID S-1-5-18 = SYSTEM, locale-independent.
try {
    $id        = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSYSTEM  = ($id.User.Value -eq 'S-1-5-18')
} catch { $isAdmin = $false; $isSYSTEM = $false }

if (-not ($isAdmin -or $isSYSTEM)) {
    Log 'FAIL: Not admin/SYSTEM'
    exit 1
}

$deleted = 0
$errors  = 0

function Unhide([string]$p) {
    try { cmd.exe /c "attrib -h -s -r `"$p`" /s /d >nul 2>&1" | Out-Null } catch { }
}

function DelFile([string]$p) {
    if (-not $p) { return }
    try { if (-not (Test-Path -LiteralPath $p)) { return } } catch { return }
    try { Unhide $p; Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } catch { }
    try {
        if (Test-Path -LiteralPath $p) { cmd.exe /c "del /f /q `"$p`" >nul 2>&1" | Out-Null }
        if (-not (Test-Path -LiteralPath $p)) { $script:deleted++; Log "DELETED FILE: $p" }
        else { $script:errors++; Log "FAILED TO DELETE: $p" }
    } catch { $script:errors++ }
}

function DelDir([string]$p) {
    if (-not $p) { return }
    try { if (-not (Test-Path -LiteralPath $p)) { return } } catch { return }
    try { Unhide $p; Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    try {
        if (Test-Path -LiteralPath $p) { cmd.exe /c "rd /s /q `"$p`" >nul 2>&1" | Out-Null }
        if (-not (Test-Path -LiteralPath $p)) { $script:deleted++; Log "DELETED DIR: $p" }
        else { $script:errors++; Log "FAILED TO DELETE DIR: $p" }
    } catch { $script:errors++ }
}

$script:profileCache = $null
function Profiles {
    if ($null -eq $script:profileCache) {
        $script:profileCache = @()
        try {
            $script:profileCache = @(
                Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin @('All Users','Default','Default User','Public') } |
                Select-Object -ExpandProperty FullName
            )
        } catch { }
    }
    return $script:profileCache
}

function Roots {
    $r = [System.Collections.Generic.List[string]]@(
        'C:\ProgramData',
        'C:\Windows\Intel',
        'C:\Windows\Tasks',
        'C:\Users\Public'
    )
    foreach ($u in (Profiles)) {
        $r.Add($u)  # full profile scan — catches Downloads\Wannacry and any subfolder
    }
    return @($r | Select-Object -Unique)
}

$iocNames = @{}
foreach ($n in @(
    'tasksche.exe','mssecsvc.exe','mssecsvc2.exe','taskdl.exe','taskse.exe',
    '@wanadecryptor@','@wanadecryptor@.exe','@wanadecryptor@.bmp',
    '@wanadecryptor@.exe.lnk','@please_read_me@.txt','@please_read_me@.bat',
    '@please_read_me@',
    'wannacry.exe','wcry.exe','wncry.exe','publickey','public.key',
    'c.wnry','b.wnry','r.wnry','s.wnry','t.wnry','u.wnry','f.wnry',
    '00000000.pky','00000000.eky','00000000.res',
    'b547dc7a77af8022abbf19a7006213342444caea1cede20ea2409ce9bc9790bf.exe'
)) { $iocNames[$n] = $true }

$RC = [System.Text.RegularExpressions.RegexOptions]
$reWnryName = [regex]::new('^m_.*\.wnry$',    $RC::IgnoreCase -bor $RC::Compiled)
$reBatName  = [regex]::new('^\d{15}\.bat$',   $RC::Compiled)
$reWnryExt  = [regex]::new('\.(wnry|wncry)$', $RC::IgnoreCase -bor $RC::Compiled)
$reMalDirs  = [regex]::new('\\TaskData\\Tor$|\\qeriuwjhrf$|\\WanaCrypt0r$|\\WannaCry$|\\Wannacry$', $RC::IgnoreCase -bor $RC::Compiled)
$reProcName = [regex]::new('wanadecryptor|wannacry|tasksche|mssecsvc|taskdl|taskse|wnry|wncry', $RC::IgnoreCase -bor $RC::Compiled)
$reRegVal   = [regex]::new('tasksche\.exe|@WanaDecryptor@\.exe|main_Cry\.exe|m\.vbs|mssecsvc|wcry|wnry|wannacry|wanacry|taskdl|taskse|WanaCrypt0r', $RC::IgnoreCase -bor $RC::Compiled)
$_psSkip    = @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')

Log 'Starting WannaCry cleanup'

# ═════════════════════════════════════════════════════════════════════════════
# STEP 1 — Disable services, kill processes
#
# CIM/WMI is intentionally NOT used here. WannaCry damages the WMI repository
# on infected machines and Get-CimInstance throws a hard terminating exception
# that exits PowerShell before the catch block fires, giving rc=1.
# tasklist.exe is a pure Win32 call with no WMI dependency and is reliable
# even on heavily compromised systems.
# ═════════════════════════════════════════════════════════════════════════════
Log 'Step 1: disabling services'

foreach ($svc in @('mssecsvc2.0', 'mssecsvc', 'mssecsvc2')) {
    try {
        $p = Start-Process 'sc.exe' -ArgumentList "config `"$svc`" start= disabled" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        if ($p) { $null = $p.WaitForExit(3000) }
    } catch { }
    try {
        $p = Start-Process 'sc.exe' -ArgumentList "stop `"$svc`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        if ($p) { $null = $p.WaitForExit(5000) }
    } catch { }
}

Log 'Step 1: killing processes by name'

# Stop-Process returns nothing for missing processes — no rc leakage
foreach ($n in @('tasksche','mssecsvc','mssecsvc2','wcry','wnry','taskdl','taskse','WanaDecryptor','wannacry')) {
    try { Stop-Process -Name $n -Force -ErrorAction SilentlyContinue } catch { }
}

Log 'Step 1: taskkill cross-session sweep'

foreach ($im in @(
    '@WanaDecryptor@.exe', 'tasksche.exe', 'mssecsvc.exe',
    'mssecsvc2.exe', 'taskdl.exe', 'taskse.exe', 'wcry.exe', 'wnry.exe'
)) {
    try {
        $null = & cmd.exe /c "taskkill /F /IM `"$im`" >nul 2>&1"
        Log "taskkill: $im"
    } catch { }
}

Log 'Step 1: tasklist sweep'

# tasklist.exe sweep for renamed variants — pure Win32, no WMI dependency
try {
    $tlOut = & tasklist.exe /FO CSV /NH 2>$null
    foreach ($line in $tlOut) {
        try {
            $fields = $line -split '","'
            if ($fields.Count -ge 2) {
                $pName = $fields[0].TrimStart('"')
                $pId   = [int]($fields[1].Trim('"'))
                if ($reProcName.IsMatch($pName)) {
                    Stop-Process -Id $pId -Force -ErrorAction SilentlyContinue
                    Log "Killed: pid=$pId name=$pName"
                }
            }
        } catch { }
    }
} catch { $errors++ }

Log 'Step 1: deleting services'

foreach ($svc in @('mssecsvc2.0', 'mssecsvc', 'mssecsvc2')) {
    try {
        $p = Start-Process 'sc.exe' -ArgumentList "delete `"$svc`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        if ($p) { $null = $p.WaitForExit(3000) }
    } catch { }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 2 — Remove registry persistence
# ═════════════════════════════════════════════════════════════════════════════
Log 'Step 2: cleaning registry'

foreach ($k in @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
)) {
    try {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -in $_psSkip) { continue }
            if ($reRegVal.IsMatch("$($p.Value)")) {
                try {
                    Remove-ItemProperty -LiteralPath $k -Name $p.Name -Force -ErrorAction SilentlyContinue
                    Log "Removed Run key value: $($p.Name)"
                } catch { $errors++ }
            }
        }
    } catch { $errors++ }
}

foreach ($regPath in @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\mssecsvc2.0',
    'HKLM:\SOFTWARE\WanaCrypt0r',
    'HKCU:\SOFTWARE\WanaCrypt0r'
)) {
    try {
        if (Test-Path -LiteralPath $regPath) {
            Remove-Item -LiteralPath $regPath -Recurse -Force -ErrorAction SilentlyContinue
            Log "Removed registry key: $regPath"
        }
    } catch { $errors++ }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 3 — Delete known absolute-path files and sample drop directories
# ═════════════════════════════════════════════════════════════════════════════
Log 'Step 3: removing known-path files and directories'

foreach ($fp in @(
    'C:\@WanaDecryptor@.exe','C:\@WanaDecryptor@','C:\@Please_Read_Me@.txt',
    'C:\PublicKey','C:\Public.KEY',
    'C:\ProgramData\@WanaDecryptor@.exe','C:\ProgramData\@WanaDecryptor@',
    'C:\ProgramData\@Please_Read_Me@.txt',
    'C:\ProgramData\mssecsvc.exe','C:\ProgramData\mssecsvc2.exe',
    'C:\Windows\tasksche.exe','C:\Windows\Intel\tasksche.exe',
    'C:\Users\Public\Desktop\@WanaDecryptor@.bmp'
)) { DelFile $fp }

# Explicitly nuke known sample drop directories across all user profiles
foreach ($u in (Profiles)) {
    foreach ($subdir in @('Wannacry','WannaCry','WanaCry','wcry')) {
        DelDir (Join-Path $u "Downloads\$subdir")
        DelDir (Join-Path $u "Desktop\$subdir")
        DelDir (Join-Path $u "Documents\$subdir")
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 4 — Filesystem sweep (parallel runspaces, full user profile scan)
# ═════════════════════════════════════════════════════════════════════════════
Log 'Step 4: filesystem sweep'

$scanRoots  = Roots
$sweepBlock = {
    param($root, $iocNames, $reWnryName, $reBatName, $reWnryExt, $reMalDirs)

    $ld = 0; $le = 0
    $ll = [System.Collections.Generic.List[string]]@()

    function _Unhide([string]$p) { try { cmd.exe /c "attrib -h -s -r `"$p`" /s /d >nul 2>&1" | Out-Null } catch { } }
    function _DelFile([string]$p) {
        if (-not $p) { return }
        try { if (-not (Test-Path -LiteralPath $p)) { return } } catch { return }
        try { _Unhide $p; Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } catch { }
        try {
            if (Test-Path -LiteralPath $p) { cmd.exe /c "del /f /q `"$p`" >nul 2>&1" | Out-Null }
            if (-not (Test-Path -LiteralPath $p)) { $ld++; $ll.Add("DELETED FILE: $p") }
            else { $le++; $ll.Add("FAILED TO DELETE: $p") }
        } catch { $le++ }
    }
    function _DelDir([string]$p) {
        if (-not $p) { return }
        try { if (-not (Test-Path -LiteralPath $p)) { return } } catch { return }
        try { _Unhide $p; Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } catch { }
        try {
            if (Test-Path -LiteralPath $p) { cmd.exe /c "rd /s /q `"$p`" >nul 2>&1" | Out-Null }
            if (-not (Test-Path -LiteralPath $p)) { $ld++; $ll.Add("DELETED DIR: $p") }
            else { $le++; $ll.Add("FAILED TO DELETE DIR: $p") }
        } catch { $le++ }
    }

    try { if (-not (Test-Path -LiteralPath $root)) { return [pscustomobject]@{d=0;e=0;l=@()} } } catch { return [pscustomobject]@{d=0;e=0;l=@()} }

    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            try {
                $name = $f.Name.ToLowerInvariant()
                if ($iocNames.ContainsKey($name) -or
                    $reWnryName.IsMatch($name)   -or
                    $reBatName.IsMatch($name)     -or
                    $reWnryExt.IsMatch($name)) {
                    _DelFile $f.FullName
                }
            } catch { $le++ }
        }
    } catch { $le++ }

    try {
        foreach ($d in @(Get-ChildItem -LiteralPath $root -Recurse -Directory -Force -ErrorAction SilentlyContinue)) {
            try { if ($reMalDirs.IsMatch($d.FullName)) { _DelDir $d.FullName } } catch { $le++ }
        }
    } catch { $le++ }

    return [pscustomobject]@{d=$ld;e=$le;l=$ll}
}

try {
    $pool = [runspacefactory]::CreateRunspacePool(1, [math]::Min(4, [math]::Max(1, $scanRoots.Count)))
    $pool.Open()
    $handles = [System.Collections.Generic.List[object]]@()
    foreach ($root in $scanRoots) {
        try {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($sweepBlock).AddArgument($root).AddArgument($iocNames).AddArgument($reWnryName).AddArgument($reBatName).AddArgument($reWnryExt).AddArgument($reMalDirs)
            $handles.Add([pscustomobject]@{ ps=$ps; h=$ps.BeginInvoke() })
        } catch { $errors++ }
    }
    foreach ($item in $handles) {
        try {
            $r = $item.ps.EndInvoke($item.h)
            if ($r) { $deleted += $r.d; $errors += $r.e; foreach ($line in $r.l) { Log $line } }
        } catch { $errors++ }
        finally { try { $item.ps.Dispose() } catch { } }
    }
    $pool.Close(); $pool.Dispose()
} catch { $errors++ }

# ═════════════════════════════════════════════════════════════════════════════
# STEP 5 — Restore wallpaper
# Runs as SYSTEM so HKCU = SYSTEM's hive, not the user's.
# Must write to the correct user SID under HKU and delete the wallpaper cache.
# ═════════════════════════════════════════════════════════════════════════════
Log 'Step 5: restoring wallpaper'

$default = 'C:\Windows\Web\Wallpaper\Windows\img0.jpg'
try { if (-not (Test-Path -LiteralPath $default)) { $default = '' } } catch { $default = '' }

# Map each user profile path → SID via ProfileList
try {
    $profileList = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue
    foreach ($entry in $profileList) {
        try {
            $sid         = $entry.PSChildName
            $profilePath = (Get-ItemProperty $entry.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
            if (-not $profilePath) { continue }
            if ($profilePath -notmatch 'C:\\Users\\') { continue }
            if ($profilePath -match 'systemprofile|LocalService|NetworkService') { continue }

            # ── 1. Delete wallpaper cache so Windows cannot fall back to it ──
            $themesDir = Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Themes'
            $cacheFiles = @(
                (Join-Path $themesDir 'TranscodedWallpaper'),
                (Join-Path $themesDir 'TranscodedWallpaper.jpg')
            )
            foreach ($cf in $cacheFiles) {
                try {
                    if (Test-Path -LiteralPath $cf) {
                        Remove-Item -LiteralPath $cf -Force -ErrorAction SilentlyContinue
                        Log "Deleted wallpaper cache: $cf"
                    }
                } catch { }
            }
            # Delete CachedFiles subfolder (stores per-resolution cache)
            try {
                $cachedDir = Join-Path $themesDir 'CachedFiles'
                if (Test-Path -LiteralPath $cachedDir) {
                    Remove-Item -LiteralPath $cachedDir -Recurse -Force -ErrorAction SilentlyContinue
                    Log "Deleted wallpaper CachedFiles for: $profilePath"
                }
            } catch { }

            # ── 2. Write wallpaper registry key to the correct user hive ─────
            $hiveMounted = $false
            $huKey       = "HKU:\$sid\Control Panel\Desktop"

            # Check if hive is already loaded (user is logged in)
            if (-not (Test-Path "HKU:\$sid" -ErrorAction SilentlyContinue)) {
                $ntuser = Join-Path $profilePath 'NTUSER.DAT'
                if (Test-Path -LiteralPath $ntuser) {
                    $null = & reg.exe load "HKU\$sid" $ntuser 2>&1
                    $hiveMounted = $true
                    Start-Sleep -Milliseconds 300
                }
            }

            if (Test-Path "HKU:\$sid\Control Panel\Desktop" -ErrorAction SilentlyContinue) {
                Set-ItemProperty -Path "HKU:\$sid\Control Panel\Desktop" -Name Wallpaper      -Value $default -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKU:\$sid\Control Panel\Desktop" -Name WallpaperStyle -Value '0'     -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKU:\$sid\Control Panel\Desktop" -Name TileWallpaper  -Value '0'     -Force -ErrorAction SilentlyContinue
                Log "Reset wallpaper registry for SID: $sid ($profilePath)"
            }

            if ($hiveMounted) {
                [GC]::Collect()
                Start-Sleep -Milliseconds 500
                $null = & reg.exe unload "HKU\$sid" 2>&1
            }
        } catch { }
    }
} catch { }

# ═════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
Log "SUMMARY: deleted_items=$deleted errors=$errors"
Log 'Cleanup finished'
[Console]::Out.Flush()
& shutdown.exe /r /t 10 /f /c "Remediation complete. Currently Rebooting the VM"
exit 0


