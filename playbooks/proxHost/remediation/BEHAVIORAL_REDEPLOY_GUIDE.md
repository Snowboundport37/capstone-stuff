# Behavioral Detection and Auto-Redeploy Guide

## Purpose

`windows-behavioral-redeploy.yaml` is a defensive automation playbook that identifies suspicious Windows VM behavior and, when threshold is met, rebuilds that VM from a known-good golden image while keeping the same VMID.

## Detection Signals

The in-guest script `files/windows-behavioral-detect.ps1` scores each Windows VM by inspecting:

- Recent files with hash-like/random names and suspicious keywords
- Startup registry autoruns in common `Run` and `RunOnce` paths
- Background processes with high CPU or memory usage
- Burst/suspicious PowerShell activity from `Microsoft-Windows-PowerShell/Operational`

Optional hardening:

- Enables PowerShell script block/module/transcription logging when `enable_powershell_logging=true`

## Redeploy Decision

Redeploy is triggered when both conditions are true:

- `replace_infected=true`
- Either:
  - detector says `likely_infected=true`, or
  - detector `score >= detection_score_threshold`

## Golden Image Decision Logic

Template VMID is selected in this order:

1. `vmid_template_overrides` explicit map (highest priority)
2. `golden_template_map` inferred by VM identity:
   - `win11` -> `3002`
   - `winsrv`/`server` -> `3003`
   - `malware` -> `3013`
   - default Windows -> `3001`
3. `default_windows_template_vmid` fallback if key is missing

## What Happens During Replacement

For a flagged VM:

1. Stop VM
2. Destroy VM
3. Clone selected golden image to the **same VMID**
4. Reapply core settings (`name`, `cores`, `memory`, `net0`)
5. Start replacement VM (if enabled)

## Outputs and Timeline

Playbook writes a JSON report on the remediator host:

- Path: `/tmp/windows-behavioral-reports/behavioral-redeploy-<timestamp>.json`
- Includes per-VM timeline fields:
  - `scan_started_at`
  - `detected_at`
  - `destroyed_at`
  - `redeployed_at`
  - `scan_finished_at`

## Usage

Scan selected VMIDs:

```bash
ansible-playbook -i ../inventories/hosts proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "remediator_host=remediator scan_vmids=[2004,2005] replace_infected=true"
```

Scan all running VMIDs in a range without redeploy:

```bash
ansible-playbook -i ../inventories/hosts proxHost/remediation/windows-behavioral-redeploy.yaml \
  -e "remediator_host=remediator vmid_range_start=2000 vmid_range_end=2100 replace_infected=false"
```
