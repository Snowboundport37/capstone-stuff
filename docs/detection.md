# Behavioral detection and golden-image rebuild

Playbook: `windows-behavioral-redeploy.yaml`
Detector: `windows-behavioral-detect.ps1` (runs in the guest via QEMU guest agent)

## Flow

1. Select VMIDs (explicit list, or running VMs in a range)
2. Keep Windows guests that are up
3. Run the detector inside each guest
4. Score signals. `likely_infected` if the internal threshold is hit
5. If `replace_infected=true` and (likely_infected or score >= playbook threshold):
   - stop, destroy, clone golden image to the same VMID, restore basic settings, start
6. Write a JSON report with a per-VM timeline

## Signals

- Recent files with hash-like / random names
- Recent files whose names include words like `update`, `invoice`, `payload`, `wallet`
- Autorun persistence in HKLM/HKCU Run and RunOnce, especially command paths under AppData, Temp, powershell, bitsadmin
- High CPU-seconds or memory on non-allowlisted background processes
- PowerShell Operational log: volume burst plus patterns such as `iwr`, `DownloadString`, `reg add`, `bitsadmin`, `FromBase64String`

Optional: turn on script-block, module, and transcription logging during the run.

## Redeploy trigger

Both must be true:

- `replace_infected=true`
- detector `likely_infected=true` **or** `score >= detection_score_threshold`

## Report fields (per VM)

VM identity, score, likely_infected, reasons, whether redeploy ran, timestamps for scan / detect / destroy / clone / finish, and `qm` result codes.

Reports land on the remediator host under a timestamped JSON filename. Sample output is not checked into git yet. That is a gap.

## Example (placeholders)

Detect only:

```bash
ansible-playbook -i inventories/hosts.example playbooks/proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "remediator_host=proxmox scan_vmids=[2004,2005] replace_infected=false"
```

Detect and rebuild:

```bash
ansible-playbook -i inventories/hosts.example playbooks/proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "remediator_host=proxmox vmid_range_start=2000 vmid_range_end=2100 replace_infected=true"
```

Do not point this at a host that is not an isolated lab VM.
