# LokiBot remediation

Defensive lab cleanup for LokiBot-style infostealer artifacts. Isolated guests only.

## Files

- `lokibot-remediation.yaml`
- `lokibot-remediate.ps1`
- `guest_stage_and_remediate.py`

## Flow

Same pattern as WannaCry: Ansible on the Proxmox node, QEMU guest agent into Windows, SYSTEM script, log at `C:\ProgramData\LokiBotRemediation\lokibot-run.log`.

## In-guest steps

- Log setup and admin/SYSTEM guard
- Process containment: name/path/command-line indicators (`loki`, `Downloads\Loki`, `AppData\Roaming\Loki`, `fre.php`). Skips obvious benign processes
- Run-key cleanup (HKCU and HKLM)
- File cleanup, including `Downloads\Loki` while keeping `.pcap` for forensics
- Scheduled-task cleanup for Loki-specific actions only
- Optional C2 firewall blocks if a list is provided
- Verification: processes, Run keys, tasks, files. Exit 0 only on `VERIFICATION RESULT: PASSED`

## Output you should see

`Starting LokiBot cleanup`, FLAG/DELETED lines, four `VERIFY OK` lines, `VERIFICATION RESULT: PASSED`, `Cleanup finished`.
