# WannaCry remediation

Defensive lab cleanup for the WannaCry family used in the capstone. Not a generic ransomware product. Not a guide for infecting anything.

## Files

- `wannacry-remediation.yaml` — Ansible entry
- `guest_stage_and_remediate.py` — chunks the script into the guest through QEMU guest agent
- `wannacry-remediate.ps1` / `Invoke-WannaCryRemediation.ps1` — in-guest cleanup
- `iocs.json` — hashes and artifact names (hashes are fine to discuss; binaries are not published)

## Flow

1. Confirm the target VM is running and guest agent answers ping
2. Stage the PowerShell script into the guest
3. Run it as admin/SYSTEM
4. Print a deleted-item summary

Typical runtime: about 20–90 seconds. Heavier guests: a few minutes. That is cleanup time, not "detect to full lab rebuild."

## In-guest steps

1. Privilege check
2. Kill known process names (`tasksche`, `mssecsvc`, `taskdl`, `taskse`, `WanaDecryptor`, and command-line matches)
3. Remove services `mssecsvc2.0` / `mssecsvc` and suspicious Run-key entries
4. Delete known files and folders (`@WanaDecryptor@`, `@Please_Read_Me@.txt`, `tasksche.exe`, `*.wnry`, `*.wncry`, and the usual ProgramData / Tasks / Temp locations)
5. Reset wallpaper to default
6. Print `SUMMARY: deleted_items=... errors=...`

Modes on the standalone script: `-Audit`, `-Contain`, `-Remediate`, `-ReportOnly`.

## Success

Playbook `failed=0`, output contains `Starting WannaCry cleanup`, a summary line, and `Cleanup finished`.
