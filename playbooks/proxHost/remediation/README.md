# Malware Remediation Toolkit

This folder contains defensive-only remediation and rebuild workflows for your Proxmox cyber range.

Current focus:

- `WannaCry` remediation workflow
- `LokiBot` remediation workflow
- `Windows behavioral detection + auto-redeploy` workflow

## Quick Links

- Root project docs: `README.md`
- WannaCry script: `playbooks/proxHost/remediation/Invoke-WannaCryRemediation.ps1`
- WannaCry playbook: `playbooks/proxHost/remediation/wannacry-remediation.yaml`
- LokiBot playbook: `playbooks/proxHost/remediation/lokibot-remediation.yaml`
- LokiBot runbook: `playbooks/proxHost/remediation/LOKIBOT_REMEDIATION_GUIDE.md`
- Behavioral playbook: `playbooks/proxHost/remediation/windows-behavioral-redeploy.yaml`
- Behavioral runbook: `playbooks/proxHost/remediation/BEHAVIORAL_REDEPLOY_GUIDE.md`

## Safety and Scope

- Defensive/authorized IR use only
- Isolated lab workflows only
- No exploit or offensive payload guidance
- Snapshot and evidence handling should be enforced by lab SOP

## Behavioral Detection + Auto-Redeploy (Main Workflow)

Main playbook:

- `playbooks/proxHost/remediation/windows-behavioral-redeploy.yaml`

### What it does end-to-end

1. Selects target VMIDs (explicit list or discovered running VMIDs in a range)
2. Filters to runnable Windows guests
3. Runs in-guest PowerShell behavioral detection via QEMU Guest Agent
4. Scores suspicious activity and decides infected/not infected
5. If infected and enabled:
   - stop VM
   - destroy VM
   - clone from golden image to the same VMID
   - restore key settings (`name`, `cores`, `memory`, `net0`)
   - start VM
6. Writes a JSON report with a per-VM timeline and outcome

### What it checks

Detection script:

- `playbooks/proxHost/remediation/files/windows-behavioral-detect.ps1`

Signals:

- Recent files with hash-like/random names
- Recent files containing suspicious words (for example: `update`, `invoice`, `payload`, `wallet`)
- Autorun persistence in common startup registry locations:
  - `HKLM/HKCU ...\Run`
  - `HKLM/HKCU ...\RunOnce`
- High CPU or high memory background processes (non-baseline allowlist)
- PowerShell Operational log behavior:
  - event volume burst
  - suspicious command patterns (`iwr`, `DownloadString`, `reg add`, `bitsadmin`, `FromBase64String`, etc.)

Optional logging hardening:

- Script block logging
- Module logging
- Transcription logging

### Scoring and infection decision

- Signals add to a risk score
- `likely_infected=true` if score reaches built-in threshold in detector
- Playbook redeploy trigger is:
  - `replace_infected=true`, and
  - `likely_infected=true` OR `score >= detection_score_threshold`

## Golden Image Logic

The playbook chooses which golden template to clone in this order:

1. **Explicit override map** (`vmid_template_overrides`)  
   Highest priority, per VMID
2. **Identity-based map** (`golden_template_map`)  
   Inferred from VM `name` / `ostype`:
   - `win11` -> `3002`
   - `winsrv` or `server` -> `3003`
   - `malware` -> `3013`
   - default windows profile -> `3001`
3. **Fallback default** (`default_windows_template_vmid`)  
   Used if key not found (default `3001`)

Result: infected VM is replaced from the selected golden template while keeping the same VMID.

## Deploy / Run

### Prerequisites

- Run from a host that can execute your Ansible playbooks
- Inventory reachable (example: `../inventories/hosts`)
- Remediator host has Proxmox CLI access (`qm`) and QEMU guest agent connectivity to guest VMs
- Windows guests should have QEMU guest agent available/running

### Basic command (specific VMIDs)

```bash
ansible-playbook -i ../inventories/hosts proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "remediator_host=remediator scan_vmids=[2004,2005] replace_infected=true"
```

### Basic command (scan range, detect only)

```bash
ansible-playbook -i ../inventories/hosts proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "remediator_host=remediator vmid_range_start=2000 vmid_range_end=2100 replace_infected=false"
```

### Useful runtime variables

- `remediator_host`: host alias where `qm` is executed (default `remediator`)
- `scan_vmids`: explicit VMID list (if unset, auto-discovery is used)
- `vmid_range_start` / `vmid_range_end`: range for auto-discovery
- `replace_infected`: whether to redeploy infected VMs
- `start_redeployed_vm`: auto-start replacement VM
- `detection_lookback_hours`: event/file lookback window
- `detection_high_cpu_seconds`: process CPU threshold
- `detection_high_memory_mb`: process memory threshold
- `detection_powershell_burst_threshold`: suspicious PowerShell burst level
- `detection_score_threshold`: playbook-side score trigger
- `enable_powershell_logging`: enable additional PowerShell logging
- `vmid_template_overrides`: per-VM golden template override map

## Output and Reporting

Report output location on remediator host:

- `/tmp/windows-behavioral-reports/behavioral-redeploy-<timestamp>.json`

Per-VM report fields include:

- VM identity (`vmid`, `vm_name`, `ostype`)
- detection data (`score`, `likely_infected`, reasons/details)
- action decision (`redeploy_triggered`)
- timeline (`scan_started_at`, `detected_at`, `destroyed_at`, `redeployed_at`, `scan_finished_at`)
- command result codes for stop/destroy/clone/set/start actions

## WannaCry Script Quick Use

`Invoke-WannaCryRemediation.ps1` modes:

- `-Audit`
- `-Contain`
- `-Remediate`
- `-ReportOnly`

Example:

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-WannaCryRemediation.ps1 -Audit -Verbose
```
