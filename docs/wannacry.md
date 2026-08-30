# WannaCry remediation

Defensive lab cleanup for the WannaCry family we detonated in the capstone. Not a generic ransomware product. Not a guide for infecting anything. Isolated guests only.

I am documenting the playbook the team ran. Cleanup of this family is one of the two solid in-guest paths we have (the other is LokiBot). Agent Tesla is not in the same league; that page says so.

## Files

- `wannacry-remediation.yaml` — Ansible entry. Lives under `playbooks/proxHost/remediation/` in the private tree.
- `guest_stage_and_remediate.py` — chunks the script into the guest through QEMU guest agent. Shared with the other family playbooks.
- `wannacry-remediate.ps1` / `Invoke-WannaCryRemediation.ps1` — in-guest cleanup.
- `iocs.json` — hashes and artifact names. Hashes are fine to discuss. Binaries are not published.
- `remediation-reports/wannacry-report.json` — run output shape. Live host rows are not pasted here.

Older copies of scan playbooks sit under `remediation/2` and `remediation/3` (`scan.yml`, `per_vm_scan.yml`). Those are earlier generations, not the family cleanup described below.

## Flow

1. Confirm the target VM is running and the guest agent answers ping. If QGA is down, this playbook has nothing to talk to. Run `QemuAgent_Online.yaml` first if you like being less surprised.
2. Stage the PowerShell script into the guest with `guest_stage_and_remediate.py`. QGA does not love huge one-shot payloads, so the helper chunks.
3. Run the script as admin / SYSTEM.
4. Print a deleted-item summary.

Typical runtime: **about 20–90 seconds** once QGA is up. Heavier guests: a few minutes. That is **cleanup time**, not "detect to full lab rebuild." A rebuild is a different playbook (`windows-behavioral-redeploy.yaml`) and takes minutes per VM for stop / destroy / clone / start. Mixing those two numbers is how a resume ends up saying five minutes.

## In-guest steps

1. Privilege check. No admin, no run.
2. Kill known process names: `tasksche`, `mssecsvc`, `taskdl`, `taskse`, `WanaDecryptor`, plus command-line matches.
3. Remove services `mssecsvc2.0` / `mssecsvc` and suspicious Run-key entries.
4. Delete known files and folders: `@WanaDecryptor@`, `@Please_Read_Me@.txt`, `tasksche.exe`, `*.wnry`, `*.wncry`, and the usual ProgramData / Tasks / Temp locations.
5. Reset wallpaper to default. (WannaCry's joke wallpaper is how a lot of people notice the run in a demo. Leaving it is sloppy.)
6. Print `SUMMARY: deleted_items=... errors=...`

Modes on the standalone script: `-Audit`, `-Contain`, `-Remediate`, `-ReportOnly`.

- **Audit** — look, do not delete.
- **Contain** — kill processes / services, leave files for forensics.
- **Remediate** — the full cleanup.
- **ReportOnly** — write what would have happened.

Use Audit on a guest you still want to screenshot.

## Success

Playbook `failed=0`. Output contains `Starting WannaCry cleanup`, a summary line, and `Cleanup finished`.

This does not decrypt files. If the sample finished encrypting, the golden-image rebuild is the restore path, not this script. This script is for the lab case where we detonated, watched artifacts, and wanted them gone without recloning.

## Honest limits

- Family-specific. It looks for WannaCry names, not "any ransomware."
- Needs QGA.
- Needs the guest healthy enough to run PowerShell as SYSTEM.
- Does not replace Zeek, FakeNet, or the behavioral detector. Those are how we noticed the run. This is how we cleaned this family.
- `iocs.json` hashes are identifiers. They are not a substitute for a sandbox.

## Safety

Authorized lab use only. Isolated segment. No internet during detonation. Snapshots before and after. Do not point this playbook at a machine that is not an isolated lab VM.
