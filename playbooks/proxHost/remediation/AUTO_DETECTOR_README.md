# Windows Auto Detector + Auto Redeploy

This guide is only for the behavioral auto-detector workflow:

- Playbook: `playbooks/proxHost/remediation/windows-behavioral-redeploy.yaml`

It detects suspicious Windows VM behavior and can automatically rebuild infected VMs from a golden image while keeping the same VMID.

## What It Does

For each target VM:

1. Verifies VM is running and appears to be Windows.
2. Runs detector script inside the guest through QEMU Guest Agent.
3. Scores suspicious behavior.
4. If score/flags cross threshold and redeploy is enabled:
   - stop VM
   - destroy VM
   - clone golden image to same VMID
   - restore basic settings (`name`, `cores`, `memory`, `net0`)
   - start VM
5. Writes a JSON report with timeline + decision data.

## What It Checks

Detector script:

- `playbooks/proxHost/remediation/files/windows-behavioral-detect.ps1`

Signals checked:

- **Recent suspicious files**
  - hash-like/random filenames
  - suspicious keywords in names (example: `update`, `invoice`, `payload`, `wallet`)
- **Startup persistence**
  - `HKLM/HKCU ...\Run`
  - `HKLM/HKCU ...\RunOnce`
  - suspicious command paths (`AppData`, `Temp`, `powershell`, `bitsadmin`, etc.)
- **High-usage background processes**
  - unusual CPU seconds and/or memory
- **PowerShell activity spikes**
  - ScriptBlock log patterns + burst threshold

Optional:

- Enables PowerShell logging policies (script block, module, transcription).

## Golden Image Selection Logic

Order of precedence:

1. `vmid_template_overrides` explicit VMID mapping
2. inferred from VM `name`/`ostype` using `golden_template_map`
3. fallback `default_windows_template_vmid`

Current default map:

- `win11` -> `3002`
- `winsrv`/`server` -> `3003`
- `malware` -> `3013`
- default windows -> `3001`

## How to Deploy / Run

## 1) Prerequisites

- Run from Ansible control host.
- Inventory path is valid.
- Remediator host (default `remediator`) can execute `qm`.
- Guest VMs have QEMU guest agent working.

## 2) Run for specific VMIDs

```bash
ansible-playbook -i ../inventories/hosts proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "remediator_host=remediator scan_vmids=[2004,2005] replace_infected=true"
```

## 3) Run by VMID range (auto-discovery)

```bash
ansible-playbook -i ../inventories/hosts proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "remediator_host=remediator vmid_range_start=2000 vmid_range_end=2100 replace_infected=true"
```

## 4) Detection-only mode (no rebuild)

```bash
ansible-playbook -i ../inventories/hosts proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "remediator_host=remediator scan_vmids=[2004,2005] replace_infected=false"
```

## Main Variables You Can Tune

In `windows-behavioral-redeploy.yaml`:

- `replace_infected`: enable/disable rebuild action
- `scan_vmids`: explicit VMID list
- `vmid_range_start` / `vmid_range_end`: discovery range
- `detection_lookback_hours`: how far back events/files are checked
- `detection_high_cpu_seconds`: CPU usage threshold
- `detection_high_memory_mb`: memory threshold
- `detection_powershell_burst_threshold`: command burst threshold
- `detection_score_threshold`: score needed for playbook trigger
- `enable_powershell_logging`: enable additional logging policies
- `vmid_template_overrides`: per-VM golden image override map

## How to Edit It (Practical)

### A) Change what gets detected

Edit:

- `playbooks/proxHost/remediation/files/windows-behavioral-detect.ps1`

Most common edits:

- Add/remove suspicious filename keywords (`$suspiciousWords`)
- Adjust scoring values (`$score += ...`)
- Add new registry paths to inspect
- Add new command patterns to the PowerShell suspicious regex
- Tune high-process allowlist and thresholds

### B) Change redeploy decision behavior

Edit:

- `playbooks/proxHost/remediation/windows-behavioral-redeploy.yaml`
- `playbooks/proxHost/remediation/tasks/windows_behavioral_redeploy_vm.yml`

Most common edits:

- Raise/lower `detection_score_threshold`
- Require both `likely_infected` and score threshold (stricter policy)
- Disable automatic start after rebuild (`start_redeployed_vm: false`)

### C) Change golden image mapping

Edit in `windows-behavioral-redeploy.yaml`:

- `golden_template_map`
- `default_windows_template_vmid`
- `vmid_template_overrides`

Example override at runtime:

```bash
ansible-playbook -i ../inventories/hosts proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "scan_vmids=[2004] vmid_template_overrides={'2004':3002}"
```

### D) Test safely before live replacement

1. Run detection-only first: `replace_infected=false`
2. Review JSON report
3. Adjust thresholds/keywords if noisy
4. Re-run with `replace_infected=true`

## Report Output

Report directory on remediator host:

- `/tmp/windows-behavioral-reports/`

File name pattern:

- `behavioral-redeploy-<timestamp>.json`

Includes:

- VM identity (`vmid`, `vm_name`, `ostype`)
- detection score/details/reasons
- decision (`redeploy_triggered`)
- timeline:
  - `scan_started_at`
  - `detected_at`
  - `destroyed_at`
  - `redeployed_at`
  - `scan_finished_at`

## File Map (Quick Reference)

- Orchestrator playbook: `playbooks/proxHost/remediation/windows-behavioral-redeploy.yaml`
- Per-VM action task file: `playbooks/proxHost/remediation/tasks/windows_behavioral_redeploy_vm.yml`
- In-guest detector script: `playbooks/proxHost/remediation/files/windows-behavioral-detect.ps1`
- Guest execution helper: `playbooks/proxHost/remediation/files/guest_stage_and_remediate.py`
