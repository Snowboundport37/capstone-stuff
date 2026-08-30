# WannaCry Remediation Scripts - Easy Overview

This is a plain-English guide for what the remediation scripts do today.

## What Files Matter

- `wannacry-remediation.yaml` - Ansible playbook (entry point)
- `files/guest_stage_and_remediate.py` - helper that sends script to VM through QEMU Guest Agent
- `files/wannacry-remediate.ps1` - cleanup script that runs inside Windows VM

## High-Level Flow

1. Playbook runs on `remediator` (the Proxmox node).
2. It checks VM `2004` is reachable and running.
3. It stages the PowerShell cleanup script into the guest VM through QGA.
4. It runs the cleanup script in the guest.
5. It prints cleanup output and summary.

## What `wannacry-remediation.yaml` Does

- Targets host: `remediator_host` (default is `remediator`)
- Uses VM id: `target_vmid` (default is `2004`)
- Verifies:
  - host is `remediator`
  - `qm status <vmid>` is running
  - `qm agent <vmid> ping` works
- Copies helper + cleanup scripts to `/tmp/wcr-remediation`
- Runs helper: `guest_stage_and_remediate.py`
- Shows:
  - progress lines
  - helper stdout/stderr
- Cleans temp helper directory

## What `guest_stage_and_remediate.py` Does

- Reads local `wannacry-remediate.ps1`
- Base64 chunks the script and sends chunks into the guest using `qm guest exec`
- Rebuilds script in guest at:
  - `C:/ProgramData/WannaCryRemediation/wannacry-remediate.ps1`
- Executes script with PowerShell in guest
- Polls `qm guest exec-status` until exit
- Handles transient QGA issues:
  - retries on short QGA drops/timeouts
  - retries once if `PID does not exist` race happens
- Returns guest script output to Ansible

## What `wannacry-remediate.ps1` Does

### 1) Safety checks

- Requires admin or SYSTEM context

### 2) Stop active malware

- Kills known process names:
  - `tasksche`, `mssecsvc`, `taskdl`, `taskse`, `WanaDecryptor`, `wannacry`, etc.
- Also kills processes whose command lines match WannaCry patterns

### 3) Remove persistence

- Removes known malicious services:
  - `mssecsvc2.0`, `mssecsvc`, `mssecsvc2`
- Cleans suspicious `Run` key entries in HKLM/HKCU
- Deletes known WannaCry registry keys

### 4) Delete known files and folders

- Direct known paths first (fast wins)
- Sweeps key locations:
  - `C:\ProgramData`
  - `C:\Windows\Intel`
  - `C:\Windows\Tasks`
  - each user `Desktop`, `Downloads`, `AppData\Local\Temp`
- Removes known artifact names, for example:
  - `@WanaDecryptor@`
  - `@WanaDecryptor@.exe`
  - `@Please_Read_Me@.txt`
  - `tasksche.exe`
  - `mssecsvc.exe`
  - `*.wnry`, `*.wncry`
- Removes known suspicious dirs (like `WannaCry`, `WanaCrypt0r`, `TaskData\Tor`)

### 5) Restore wallpaper

- Resets wallpaper registry values to Windows default wallpaper
- Refreshes desktop parameters

### 6) Print final summary

- Prints:
  - how many items were deleted
  - how many delete/operation errors happened

## Why Runs Can Feel Slow

- QGA command execution is not a live shell stream.
- The helper stages script chunks and polls status.
- If QGA briefly drops, helper retries to avoid false failure.

## Typical Runtime

- Most runs: about 20-90 seconds
- Heavier infected systems: 2-10 minutes

## Command to Run

```bash
ansible-playbook -i ../inventories/hosts proxHost/remediation/wannacry-remediation.yaml -e "target_vmid=2004 remediator_host=remediator" -vv
```

## Quick Success Signals

- Playbook finishes without `failed=1`
- Output includes:
  - `Starting WannaCry cleanup`
  - `SUMMARY: deleted_items=... errors=...`
  - `Cleanup finished`

