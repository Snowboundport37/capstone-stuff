# LokiBot remediation

Defensive lab cleanup for LokiBot-style infostealer artifacts. Isolated guests only. Not a guide for running stealers. Not a generic "clean my PC" tool.

This is the second solid family playbook. WannaCry is the ransomware path. LokiBot is the stealer path. Agent Tesla was supposed to be a third and is thinner; see that page.

## Files

- `lokibot-remediation.yaml` — Ansible entry under `playbooks/proxHost/remediation/`.
- `lokibot-remediate.ps1` — in-guest cleanup.
- `guest_stage_and_remediate.py` — same QGA chunking helper as WannaCry.
- Log on the guest: `C:\ProgramData\LokiBotRemediation\lokibot-run.log`

## Flow

Same pattern as WannaCry on purpose. Ansible on the Proxmox node, QEMU guest agent into Windows, SYSTEM script, log on disk, verify at the end.

1. Guest up, QGA answers.
2. Stage `lokibot-remediate.ps1`.
3. Run as admin / SYSTEM.
4. Contain, clean, verify.
5. Exit 0 only if verification passes.

## In-guest steps

- Log setup and admin / SYSTEM guard. If you are not SYSTEM, stop.
- Process containment: name / path / command-line indicators `loki`, `Downloads\Loki`, `AppData\Roaming\Loki`, `fre.php`. Skips obvious benign processes so we do not kill explorer because a path substring got cute.
- Run-key cleanup in HKCU and HKLM.
- File cleanup, including `Downloads\Loki`, **while keeping `.pcap`** for forensics. That is deliberate. A stealer lab without a packet capture is a story with the ending torn off.
- Scheduled-task cleanup for Loki-specific actions only. Not "delete every task."
- Optional C2 firewall blocks if a list is provided. If the list is empty, this step is a no-op. We are not publishing our list.
- Verification: processes, Run keys, tasks, files. Exit 0 only on `VERIFICATION RESULT: PASSED`.

## Output you should see

`Starting LokiBot cleanup`, FLAG / DELETED lines, four `VERIFY OK` lines, `VERIFICATION RESULT: PASSED`, `Cleanup finished`.

If verification fails, the playbook fails. That is the contract. WannaCry prints a summary and moves on with an error count. LokiBot is stricter because an infostealer that still has a Run key is still an infostealer.

## Why keep pcaps

Zeek and FakeNet sit on the isolated segment. The guest-side `.pcap` is the local copy of "what did this thing try to talk to." Deleting it during cleanup would make the report dumber. The script is allowed to delete Loki binaries and dropper folders. It is not allowed to wipe the evidence folder's captures.

## Honest limits

- Indicators are Loki-shaped. A renamed stealer with none of those paths will not be caught by this script. That is what the behavioral detector is for, and what a rebuild is for.
- Needs QGA and SYSTEM.
- Optional firewall blocks are only as good as the list you pass. An empty list is not "we blocked C2."
- This is not Velociraptor. Velociraptor can collect. This script deletes.

## Safety

Authorized lab use only. Isolated segment. No internet during detonation. Snapshots before and after. Do not run it on a machine that is not this lab.
