# Methodology: Automated Deployment and Malware Remediation Tool

This project builds a safe cyber lab that can deploy virtual machines, run controlled malware tests, and clean infected systems automatically.  
The current primary malware samples are `WannaCry` and `LokiBot`.

---

## 1) Overview

### What this project does

- Deploys isolated enterprise-like lab environments on Proxmox
- Uses Ansible playbooks for detection, containment, and remediation
- Uses Semaphore as the job runner/orchestration service for repeatable playbook execution
- Compares manual remediation vs automated remediation using the same test process

### Why this project matters

- Manual malware cleanup is slow and inconsistent
- Automated remediation can be faster and easier to repeat
- The lab design supports academic research and safe classroom demonstrations

---

## 2) Infrastructure and Network Architecture

### 2.1 Physical infrastructure

- Dell R430 server running Proxmox VE
- TP-Link AX5400 router (gateway)
- Cisco Catalyst 2960-CX switch with logging enabled
- Kasa SmartPlug for remote power management

### 2.2 Network architecture

The malware testing network is isolated from normal internet traffic.

- Segmented lab networks with firewall controls
- NAT filtering and DNS filtering
- Zeek network visibility for traffic monitoring
- FakeNet for safe network emulation when needed

### 2.3 VM infrastructure

- Golden image templates: Windows 10/11, Windows Server 2019/2022, Ubuntu, Kali, VyOS
- Standard VM sizing: 2 vCPU, 4-8 GB RAM
- QEMU Guest Agent enabled for automation
- Images validated with CIS benchmarks and hash checks (`SHA256`, `MD5`, `DeepHash`)

---

## 3) Preliminary Findings (Seraphim Benchmarks)

Current benchmark trend from Seraphim test runs:

- Manual remediation baseline: slower, more variation between runs
- Automated remediation: more consistent artifact cleanup and reporting
- Average remediation cycle time reduced from multi-day manual effort toward sub-48-hour automated workflows
- Repeatability improved through snapshot restore + scripted redeployment

These benchmarks are used as a decision guide, not final production SLAs.

---

## 4) Malware Sample Acquisition and Security

### 4.1 Acquisition policy

Samples are sourced from verified providers:

- Faculty/professor-provided samples
- Academic partner sources
- Malware Bazaar or equivalent trusted repositories
- Lab-generated test specimens when appropriate

### 4.2 Safety protocol

- Samples are encrypted at rest (minimum 14-character alphanumeric password)
- Chain-of-custody records are maintained
- Execution only occurs inside isolated VM segments
- Internet access is disabled during malware execution windows
- Snapshot rollback is required before and after testing

---

## 5) Automation Framework (General)

The framework uses Ansible + Semaphore to automate:

- VM deployment and network creation
- Post-deployment snapshots
- CIS hardening tasks
- Domain join and validation steps
- Golden image redeploy based on hash verification
- Detection and remediation playbook execution

Quality checks include IP/network validation and standardized run logs for every job.

---

## 6) Research Design and Methodology

### 6.1 Baseline control (manual)

Manual remediation is first documented as the control baseline:

- Steps performed
- Time required
- Artifact removal completeness

### 6.2 Automated experiment flow

1. Capture pre-execution baseline state
2. Execute malware sample for controlled 15-minute window
3. Monitor behavior with Sysinternals, ProcMon, Zeek, and DNS telemetry
4. Collect artifacts (files, registry, tasks, services, network indicators)
5. Run detection and remediation playbooks
6. Verify post-remediation state
7. Compare results against manual baseline

---

## 7) Data Collection and Analysis

### 7.1 Pre-execution baseline

- System hashes
- Registry exports
- Running processes and services
- Active connections
- Scheduled tasks and startup items

### 7.2 Execution monitoring

- 15-minute sample execution windows
- Process and file behavior tracking
- Network and DNS observation

### 7.3 Post-execution forensics

- KAPE artifact collection
- Event logs, prefetch, hives, tasks, service configs, browser traces
- IOC cataloging for remediation logic updates

---

## 8) Remediation Deployment and Validation

### 8.1 Detection playbook

Automated checks for:

- Malicious files
- Persistence methods
- Scheduled tasks and services
- Suspicious network indicators

### 8.2 Remediation playbook

Automated actions can include:

- Terminate malicious processes
- Remove files, registry keys, and tasks
- Clear persistence paths
- Flush DNS and reset selected network settings
- Apply patches/hardening checks
- Generate full action logs

### 8.3 Validation cycle

- Re-run samples in clean redeployed environments
- Confirm artifact removal completeness
- Confirm behavior is neutralized after remediation
- Determine readiness for educational deployment

---

## 9) Why We Moved Away from Conficker and njRAT

### Conficker

We reduced Conficker focus because modern Windows versions in the lab already patch many of the behaviors we needed to observe.  
Result: fewer clear artifacts and less useful remediation testing data.

### njRAT

njRAT is highly dependent on open network/C2-style communication.  
Our lab is intentionally closed and uses FakeNet controls, so realistic njRAT behavior is harder to reproduce without sandbox-specific tuning that does not match our target enterprise realism.

### Current focus

- `WannaCry`: strong ransomware/worm behavior for remediation testing
- `LokiBot`: clear infostealer/persistence artifact patterns

### Near-term roadmap

We plan to expand testing with `Agent Tesla` soon to broaden infostealer coverage.

---

## 10) Sample Scope (Current)

| Family | Category | Why Used |
|------|------|------|
| WannaCry | Ransomware/Worm | Useful for spread, persistence, and containment validation |
| LokiBot | Infostealer | Useful for file/registry/task artifact remediation validation |
| Agent Tesla (planned) | Infostealer | Next expansion target for credential theft behavior testing |

---

## 11) Simple Explanation (Kid-Friendly)

Think of this project like a safety drill:

- We set up a fake city of computers
- We let a "bad program" run in one safe room
- We watch what it breaks
- Then our robot scripts clean everything up
- We check if the room is truly clean again

That is how we test if automated cyber cleanup really works.
