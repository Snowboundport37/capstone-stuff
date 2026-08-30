param(
  [int]$LookbackHours = 6,
  [int]$HighCpuSeconds = 120,
  [int]$HighMemoryMB = 600,
  [int]$PowerShellBurstThreshold = 10,
  [switch]$EnablePowerShellLogging
)

$ErrorActionPreference = "SilentlyContinue"

function Get-HashLikeFiles {
  param([datetime]$Since, [string[]]$SuspiciousWords)
  $roots = @(
    "C:\Users\Public\Downloads",
    "C:\Users\Public",
    "C:\ProgramData",
    "C:\Windows\Temp"
  )
  $hashNamePattern = '^[a-fA-F0-9]{24,64}(\.[a-zA-Z0-9]{1,5})?$'
  $wordPattern = ($SuspiciousWords | ForEach-Object { [regex]::Escape($_) }) -join "|"
  $items = @()
  foreach ($root in $roots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -ge $Since } |
      ForEach-Object {
        $name = $_.Name
        $isHash = $name -match $hashNamePattern
        $hasWord = $false
        if ($wordPattern) {
          $hasWord = $name.ToLower() -match $wordPattern.ToLower()
        }
        if ($isHash -or $hasWord) {
          $items += [PSCustomObject]@{
            path = $_.FullName
            name = $_.Name
            last_write = $_.LastWriteTime.ToString("o")
            hash_like = $isHash
            keyword_like = $hasWord
          }
        }
      }
  }
  return $items
}

function Get-StartupAutoruns {
  $paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  )
  $autoruns = @()
  foreach ($path in $paths) {
    if (-not (Test-Path $path)) { continue }
    $props = Get-ItemProperty -LiteralPath $path
    foreach ($p in $props.PSObject.Properties) {
      if ($p.Name -match '^PS') { continue }
      $value = [string]$p.Value
      if (-not $value) { continue }
      $autoruns += [PSCustomObject]@{
        hive_path = $path
        key_name = $p.Name
        value = $value
      }
    }
  }
  return $autoruns
}

function Get-HighUsageProcesses {
  param([int]$CpuThreshold, [int]$MemThresholdMB)
  $suspicious = @()
  $allowList = @(
    "System", "Idle", "MsMpEng", "svchost", "dwm", "explorer", "winlogon",
    "services", "Registry", "csrss", "smss", "lsass", "sihost"
  )
  Get-Process | ForEach-Object {
    $cpu = [double]($_.CPU | ForEach-Object { $_ })
    $memMB = [Math]::Round($_.WorkingSet64 / 1MB, 2)
    $name = $_.ProcessName
    if (($cpu -ge $CpuThreshold -or $memMB -ge $MemThresholdMB) -and ($allowList -notcontains $name)) {
      $suspicious += [PSCustomObject]@{
        process = $name
        pid = $_.Id
        cpu_seconds = $cpu
        memory_mb = $memMB
      }
    }
  }
  return $suspicious
}

function Get-PowerShellSignal {
  param([datetime]$Since, [int]$BurstThreshold)
  $result = [PSCustomObject]@{
    recent_event_count = 0
    suspicious_event_count = 0
    burst_detected = $false
  }
  $logName = "Microsoft-Windows-PowerShell/Operational"
  $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $Since; Id = 4104 } -ErrorAction SilentlyContinue
  if (-not $events) {
    return $result
  }
  $events = @($events)
  $result.recent_event_count = $events.Count
  $suspPattern = '(invoke-webrequest|iwr|downloadstring|new-object\s+net\.webclient|start-process|reg\s+add|set-itemproperty|frombase64string|bitsadmin)'
  $susp = @($events | Where-Object { $_.Message -match $suspPattern })
  $result.suspicious_event_count = $susp.Count
  if ($susp.Count -ge $BurstThreshold) {
    $result.burst_detected = $true
  }
  return $result
}

function Enable-PowerShellLogging {
  $base = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
  New-Item -Path "$base\ScriptBlockLogging" -Force | Out-Null
  Set-ItemProperty -Path "$base\ScriptBlockLogging" -Name EnableScriptBlockLogging -Type DWord -Value 1
  New-Item -Path "$base\ModuleLogging" -Force | Out-Null
  Set-ItemProperty -Path "$base\ModuleLogging" -Name EnableModuleLogging -Type DWord -Value 1
  New-Item -Path "$base\Transcription" -Force | Out-Null
  Set-ItemProperty -Path "$base\Transcription" -Name EnableTranscripting -Type DWord -Value 1
  Set-ItemProperty -Path "$base\Transcription" -Name OutputDirectory -Type String -Value "C:\ProgramData\PowerShellTranscripts"
}

$now = Get-Date
$since = $now.AddHours(-1 * [math]::Abs($LookbackHours))
$suspiciousWords = @("temp", "update", "invoice", "password", "chrome", "wallet", "payload", "run", "task")

if ($EnablePowerShellLogging.IsPresent) {
  Enable-PowerShellLogging
}

$hashFiles = Get-HashLikeFiles -Since $since -SuspiciousWords $suspiciousWords
$autoruns = Get-StartupAutoruns
$highUsage = Get-HighUsageProcesses -CpuThreshold $HighCpuSeconds -MemThresholdMB $HighMemoryMB
$psSignal = Get-PowerShellSignal -Since $since -BurstThreshold $PowerShellBurstThreshold

$autorunSuspicious = @($autoruns | Where-Object {
  $_.value -match '(appdata|temp|powershell|cmd\.exe|wscript|cscript|bitsadmin|mshta|rundll32|regsvr32)'
})

$score = 0
$reasons = @()

if ($hashFiles.Count -ge 3) {
  $score += 30
  $reasons += "multiple_recent_hash_like_files"
} elseif ($hashFiles.Count -gt 0) {
  $score += 10
  $reasons += "recent_hash_like_files"
}

if ($autorunSuspicious.Count -ge 2) {
  $score += 35
  $reasons += "multiple_suspicious_startup_registry_entries"
} elseif ($autorunSuspicious.Count -gt 0) {
  $score += 20
  $reasons += "suspicious_startup_registry_entry"
}

if ($highUsage.Count -ge 2) {
  $score += 20
  $reasons += "multiple_high_usage_background_processes"
} elseif ($highUsage.Count -gt 0) {
  $score += 10
  $reasons += "high_usage_background_process"
}

if ($psSignal.burst_detected) {
  $score += 30
  $reasons += "powershell_command_burst_detected"
} elseif ($psSignal.suspicious_event_count -gt 0) {
  $score += 10
  $reasons += "suspicious_powershell_commands_seen"
}

$likelyInfected = $score -ge 60

$report = [PSCustomObject]@{
  generated_at = $now.ToString("o")
  hostname = $env:COMPUTERNAME
  lookback_hours = $LookbackHours
  score = $score
  likely_infected = $likelyInfected
  reasons = $reasons
  counts = [PSCustomObject]@{
    hash_like_files = $hashFiles.Count
    startup_entries = $autoruns.Count
    suspicious_startup_entries = $autorunSuspicious.Count
    high_usage_processes = $highUsage.Count
    powershell_events = $psSignal.recent_event_count
    suspicious_powershell_events = $psSignal.suspicious_event_count
  }
  details = [PSCustomObject]@{
    hash_like_files = $hashFiles
    suspicious_startup_entries = $autorunSuspicious
    high_usage_processes = $highUsage
    powershell_signal = $psSignal
  }
}

$report | ConvertTo-Json -Depth 8 -Compress
