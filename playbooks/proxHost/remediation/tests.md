# WannaCry Toolkit Test Plan

## Prerequisites

- Authorized lab environment only
- Snapshot-capable Windows VM
- Administrator PowerShell session
- Baseline backup/restore process available

## Test Matrix

### 1. Syntax and Safe Defaults
- Run `-Audit` with no additional switches.
- Confirm no containment/remediation actions are taken.
- Confirm reports are generated (JSON, text, markdown).

### 2. WhatIf and DryRun
- Run `-Contain -WhatIf`.
- Run `-Remediate -DryRun`.
- Confirm risky actions are logged as planned but not executed.

### 3. IOC Detection
- Place known artifact names in lab paths.
- Validate hash matches for primary sample IOC:
  - SHA256 `b547dc7a77af8022abbf19a7006213342444caea1cede20ea2409ce9bc9790bf`
- Confirm findings and confidence scoring reflect detections.

### 4. Containment Actions
- Simulate service indicator and suspicious process artifacts.
- Run `-Contain -BlockSMBTemporarily`.
- Verify service stop/disable, process stop attempts, firewall rule insertion.

### 5. Remediation Actions
- Run `-Remediate -DisableSMBv1`.
- Verify:
  - suspicious files moved to quarantine path
  - persistence keys removed when matched
  - WanaCrypt0r key removal only when malicious confirmation criteria are met
  - SMBv1 changed only when explicit switch is passed

### 6. Defender and Patch Checks
- Run `-Remediate -RunDefenderScan`.
- Validate Defender quick scan invocation where available.
- Validate MS17-010-era patch evidence section is populated or gracefully marked unknown.

### 7. ReportOnly Mode
- Run `-ReportOnly -ReportInputPath <prior_json>`.
- Validate parser and summary generation from prior report.

## Pass/Fail Criteria

- No unhandled exceptions in normal path
- Output files always generated (except fatal startup conditions)
- Risky actions only occur with explicit mode/switches
- Confidence score aligns with configured model inputs
