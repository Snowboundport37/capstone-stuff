# Malware Detection + Auto-Rollback (`remediation/2`)

This playbook suite scans Windows VMs for behavioral + known-artifact malware indicators and reverts confirmed-infected VMs to a clean snapshot.

## What This Is For

Use this when you want to:

- run one command and scan eligible lab VMs
- automatically roll back confirmed-infected Windows guests
- skip non-eligible VMs without failing the entire job
- produce a JSON report for every VM decision

## Standard Defaults (Current Operating Standard)

Running `scan.yml` with no extra args will:

- connect through Proxmox host `remediator`, node `pve-node`
- target only VMIDs `2004`, `2005`, and `2015` by default
- skip powered-off VMs
- skip non-Windows VMs
- in remediation mode, skip VMs missing clean snapshot `pre-malware-421`
- only allow rollback to exact snapshot name `pre-malware-421`
- continue through configured targets and write one final report

## Prerequisites

- Ansible controller can SSH to `remediator`
- Proxmox tools available on `remediator` (`qm`, `pvesh`, `python3`, `timeout`)
- Windows target VMs have QEMU guest agent enabled/responding
- Clean snapshot exists on rollback-eligible VMs:
  - `pre-malware-421`

## Files and Responsibilities

- `scan.yml`
  - main entrypoint
  - discovers targets or accepts explicit target list
  - enforces snapshot policy globally
  - includes `per_vm_scan.yml` once per VM
  - writes final report to `/tmp/remediation_report_<timestamp>.json`

- `per_vm_scan.yml`
  - executes per-VM lifecycle:
    1) gather VM runtime/config info
    2) apply skip logic (off/non-Windows)
    3) in remediation mode, verify snapshot exists
    4) run helper to stage/execute detector script
    5) parse JSON result
    6) if infected: stop -> rollback -> start
    7) append per-VM report entry

- `guest_stage_and_remediate.py`
  - robust guest execution helper
  - chunked script staging via QEMU guest agent
  - emits progress logs and returns script output

- `windows-behavioral-detect.ps1`
  - detector run inside guest
  - checks multiple indicator categories
  - includes family IOC checks for WannaCry, LokiBot, and Kovter (processes, files, registry, tasks)
  - emits one JSON object containing score, threshold decision, and indicators

## Decision Logic

- Detector threshold: default `12` (passed into `windows-behavioral-detect.ps1`)
- Infection condition:
  - `confirmed_infection=true` from detector output
  - score is still reported for context/triage, but does not trigger rollback by itself
  - detector can also confirm infostealer-like PowerShell stager activity (`powershell_stager_pattern_confirmed`)
- Rollback condition:
  - `confirmed_infection=true`
  - `replace_infected=true`
  - snapshot policy checks pass

If no malware is detected:

- VM is marked `no_malware`
- no stop/rollback/start occurs
- playbook immediately moves to next VM

## Per-VM Status Meanings

- `redeployed`: malware detected and rollback completed
- `detected_no_redeploy`: malware detected but remediation was disabled (`replace_infected=false`)
- `no_malware`: scan completed and no malware action was required
- `skipped`: intentionally skipped (`vm_not_running`, `not_windows_guest`, `missing_clean_snapshot`)
- `failed`: per-VM task error (playbook still continues to other VMs)

## Snapshot Rollback Policy

Rollback is pinned to:

- `pre-malware-421`

Guardrails exist in both `scan.yml` and `per_vm_scan.yml` to prevent rollback to any other snapshot name.

## Run Examples

### 1) Standard run (detect + remediate)

```bash
ansible-playbook playbooks/proxHost/remediation/2/scan.yml
```

### 2) Scan-only run (no rollback)

```bash
ansible-playbook playbooks/proxHost/remediation/2/scan.yml \
  --extra-vars '{"replace_infected": false}'
```

### 3) Single-VM run (remediation enabled)

```bash
ansible-playbook playbooks/proxHost/remediation/2/scan.yml \
  --extra-vars '{"target_vmids":[{"vmid":2005,"label":"LokiBot"}]}'
```

### 4) Single-VM scan-only

```bash
ansible-playbook playbooks/proxHost/remediation/2/scan.yml \
  --extra-vars '{"replace_infected": false, "target_vmids":[{"vmid":2005,"label":"LokiBot"}]}'
```

## What to Expect During a Run

Typical live progress:

- target list printed once
- per-VM config/flags shown
- helper step shows:
  - `ASYNC POLL ... started=True finished=False`
  - then `ASYNC OK ... finished=True`
- per-VM summary prints status, reason, score, and timeline fields

### Example outcomes

- Infected VM:
  - `Status  : redeployed`
  - `Reason  : rollback_to_pre-malware-421`

- Clean VM:
  - `Status  : no_malware`
  - `Reason  : no_malware_move_on`

- Powered off VM:
  - `Status  : skipped`
  - `Reason  : vm_not_running`

- Missing snapshot in remediation mode:
  - `Status  : skipped`
  - `Reason  : missing_clean_snapshot`

## Tunable Variables

You can override these at runtime with `--extra-vars`:

- Detection:
  - `detection_score_threshold` (default `12`, report/display alignment)
  - `detection_min_strong_hits` (default `2`)
  - `detection_min_categories` (default `2`)
  - `detection_stager_recent_minutes` (default `15`; only recent PS stager activity can self-confirm)
  - `detection_require_ps_stager_obfuscation` (default `false`; if true, stager confirmation requires obfuscation signal)
  - `detection_overrides_by_vmid` (per-VM detection overrides map, e.g. stricter only for `2004`)
  - `detection_lookback_hours` (default `24`)
  - `detection_high_cpu_seconds` (default `3`)
  - `detection_high_memory_mb` (default `500`)
  - `detection_powershell_burst_threshold` (default `5`)
  - `detection_enable_registry_blob_scan` (default `false`, slower when true)

- Helper/runtime:
  - `guest_exec_timeout_seconds` (default `180`)
  - `guest_chunk_size` (default `8000`)
  - `guest_chunk_write_attempts` (default `8`)
  - `helper_max_runtime_seconds` (default `900`)
  - `helper_poll_seconds` (default `10`)

- Targeting:
  - `target_vmids` (default set to `2004`, `2005`, `2015`)
  - `min_vmid_for_scan` (default `2004`)

- Remediation:
  - `replace_infected` (default `true`)
  - `start_redeployed_vm` (default `true`)
  - `clean_snapshot` (must stay `pre-malware-421`)

## Report Format

Output path:

- `/tmp/remediation_report_<timestamp>.json`

Top-level fields:

- `report_generated_at`
- `score_threshold`
- `clean_snapshot`
- `pipeline_start_time`
- `pipeline_end_time`
- `pipeline_duration_seconds`
- `vms_scanned`
- `vms_infected`
- `vms_redeployed`
- `results` (array of per-VM entries)

Per-VM fields (common):

- Identity: `vmid`, `vm_name`, `ostype`
- Timing: `scan_started_at`, `detected_at`, `nuked_at`, `redeployed_at`, `scan_finished_at`
- Detection: `detection_score`, `likely_infected`, `confirmed_infection`, `detection_result`
- Action: `redeploy_triggered`, `remediation_action`, `status`, `reason`

## Troubleshooting

- `provided hosts list is empty` warning
  - expected for this playbook; it runs on `localhost` and delegates to `remediator`

- Long wait at helper execution
  - expected to show repeated `ASYNC POLL` lines
  - if excessive, increase visibility with shorter poll interval:
    - `--extra-vars '{"helper_poll_seconds": 3}'`

- VM always skipped
  - check per-VM `Reason` in terminal/report:
    - `vm_not_running`
    - `not_windows_guest`
    - `missing_clean_snapshot`

- No rollback when malware detected
  - verify `replace_infected=true`
  - verify snapshot exists and is named exactly `pre-malware-421`

- Want faster scans
  - keep `detection_enable_registry_blob_scan=false` (default)

## Safety Notes

- This can power off and revert VMs in remediation mode.
- Run scan-only mode when validating detection logic:
  - `--extra-vars '{"replace_infected": false}'`

