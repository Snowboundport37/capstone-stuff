# LokiBot Remediation Guide (Detailed)

This runbook explains, in detail, how the LokiBot remediation in this repository works, what each script phase does, how to run it, what output to expect, and how to do manual remediation and validation.

---

## 1) Scope and files

- **Malware family:** LokiBot variants used in this lab
- **Default VMID:** `2005`
- **Default remediator host:** `remediator`
- **Playbook entrypoint:** `playbooks/proxHost/remediation/lokibot-remediation.yaml`
- **Guest cleanup script:** `playbooks/proxHost/remediation/files/lokibot-remediate.ps1`
- **QGA helper:** `playbooks/proxHost/remediation/files/guest_stage_and_remediate.py`

---

## 2) High-level architecture

The remediation runs from Linux/Ansible and cleans Windows through QEMU guest agent:

1. Ansible connects to Proxmox host (`remediator`).
2. It stages a PowerShell script in guest `2005` via `qm guest exec`.
3. It executes the script inside guest as SYSTEM context.
4. It collects output logs, asserts success, and exits.

This gives deterministic orchestration from the hypervisor side without interactive guest login.

---

## 3) How to run (automated)

From repo root on AWX/controller:

```bash
ansible-playbook -i inventories/hosts playbooks/proxHost/remediation/lokibot-remediation.yaml -e "target_vmid=2005 remediator_host=remediator" -vv
```

### Expected Ansible success indicators

- `TASK [Run remediation helper]` ends with `rc: 0`
- Helper stderr includes `Remediation finished with exitcode=0`
- Script stdout includes:
  - `VERIFICATION RESULT: PASSED`
  - `Cleanup finished`
- `TASK [Assert remediation completed]` passes
- `PLAY RECAP` shows `failed=0`

---

## 4) Playbook behavior (task-by-task)

`lokibot-remediation.yaml` performs:

1. **Gathering facts** on `remediator`.
2. **Run configuration print** (`target_vmid`, host).
3. **Host assertion** to ensure intended remediator target.
4. **VM status check** (`qm status 2005`) and assert `running`.
5. **QGA ping check** (`qm agent 2005 ping`).
6. **Helper workspace reset/create** in `/tmp/lokibot-remediation`.
7. **Asset copy**:
   - `lokibot-remediate.ps1`
   - `guest_stage_and_remediate.py`
8. **Run helper** to stage + execute script in guest.
9. **Read guest run log** from `C:\ProgramData\LokiBotRemediation\lokibot-run.log`.
10. **Print helper stdout/stderr + progress log** for analyst visibility.
11. **Assert completion**:
    - helper `rc == 0`
    - stdout contains `Cleanup finished`
12. **Always cleanup** helper tmp directory.

---

## 5) Guest script behavior (line-by-line intent)

`lokibot-remediate.ps1` does the following:

### Step A - Setup and logging

- Forces UTF-8 output.
- Creates/rotates run log: `C:\ProgramData\LokiBotRemediation\lokibot-run.log`.
- Uses `Log()` wrapper so every key action is printed and persisted.

### Step B - Privilege guard

- Requires Administrator or SYSTEM token.
- Exits hard if privileges are insufficient.

### Step C - Process containment

- Enumerates `Win32_Process`.
- Skips known benign control processes (`powershell`, `cmd`, `explorer`, `onedrive`, etc.).
- Flags/kills only strong Loki indicators:
  - process name resembles `loki(.exe)` / `lokibot(.exe)`
  - executable path references `Downloads\Loki` or `AppData\Roaming\Loki`
  - command line contains Loki markers (`fre.php`, Loki path)

### Step D - Persistence cleanup

- Scans both Run keys:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- Removes values referencing Loki/AppData/Temp patterns.

### Step E - File cleanup (adaptive)

- Adds known candidate payload paths (Roaming/Temp/Public).
- Adds sample-aware paths under each user profile.
- Scans `Downloads\Loki` and removes **all non-`.pcap` files** (keeps forensic PCAP).
- Deletes known markers:
  - `.ses`
  - `wct*.tmp`
- Includes adaptive variant detection for short random no-extension names (e.g., `bfm`, `bfo`, `jfx`) and temp marker families.

### Step F - Scheduled task cleanup

- Reads scheduled task actions.
- Removes only Loki-specific task actions (Loki/fre.php/Loki paths).
- Avoids over-broad appdata/temp-only matching to prevent benign task removal.

### Step G - Optional network containment

- Supports optional C2 block list (`$c2Ips`).
- No blocks are added unless valid IPs are populated.

### Step H - Verification phase

Runs four verification groups:

1. **Process verification**: no suspicious Loki process remains.
2. **Run key verification**: no suspicious persistence values remain.
3. **Task verification**: no suspicious scheduled task remains.
4. **File verification**:
   - no targeted artifacts remain,
   - no non-PCAP files remain in `Downloads\Loki`,
   - no variant marker files remain in temp.

Result:

- `VERIFICATION RESULT: PASSED` -> script exits `0`
- `VERIFICATION RESULT: FAILED` -> script exits `1`

### Step I - Final reporting

- Prints summary:
  - `SUMMARY: deleted_items=<N> errors=<M>`
  - `Cleanup finished`
- Prints bottom removal report:
  - `REMOVED FILES (NAMES ONLY):`
  - one line per actually deleted filename:
    - `REMOVED FILE NAME: <file>`

---

## 6) Expected output (full structure)

The exact names/counts vary by run, but the script output format should look like this:

```text
Starting LokiBot cleanup
Step 1: stopping suspicious processes
FLAGGED FILE PATH: C:\Users\windows10\Downloads\Loki\loki.exe
KILLED PROCESS: pid=1324 name=loki.exe
Step 2: removing Run key persistence
Step 3: deleting payload files
FLAGGED FILE PATH: C:\Users\windows10\AppData\Local\Temp\.ses
FLAGGED FILE PATH: C:\Users\windows10\AppData\Local\Temp\wct93D1.tmp
FLAGGED FILE PATH: C:\Users\windows10\Downloads\Loki\<variant-name>
DELETED FILE: C:\Users\windows10\AppData\Local\Temp\.ses
DELETED FILE: C:\Users\windows10\AppData\Local\Temp\wct93D1.tmp
DELETED FILE: C:\Users\windows10\Downloads\Loki\<variant-name>
... (possible many DELETED FILE lines for wct*.tmp variants) ...
Step 4: removing suspicious scheduled tasks
Step 5: applying outbound firewall blocks
Step 6: verification checks
VERIFY OK: no suspicious Loki processes
VERIFY OK: no suspicious Run key entries
VERIFY OK: no suspicious scheduled tasks
VERIFY OK: targeted Loki files removed
VERIFICATION RESULT: PASSED
REMOVED FILES (NAMES ONLY):
REMOVED FILE NAME: .ses
REMOVED FILE NAME: <variant-name>
REMOVED FILE NAME: wct93D1.tmp
... (all actually removed filenames) ...
SUMMARY: deleted_items=<N> errors=0
Cleanup finished
```

### Output meanings

- `FLAGGED FILE PATH` = candidate identified.
- `DELETED FILE` = removed successfully.
- `VERIFY FAIL ...` = leftover still exists in that category.
- `errors` in summary = operational issues (delete failures, check failures, etc.).

---

## 7) Manual remediation checklist (analyst mode)

Use this for independent validation or non-automated response.

### 7.1 Contain process activity

- Find and stop Loki process(es):
  - suspicious path: `Downloads\Loki`, `AppData\Roaming\Loki`
  - suspicious name: `loki*`, `lokibot*`

### 7.2 Remove persistence

- Check/remove suspicious Run values in HKCU/HKLM.
- Check/remove suspicious scheduled tasks with Loki markers.

### 7.3 Remove file artifacts

- Delete payload and variant drops from `Downloads\Loki` (except `.pcap` if preserving evidence).
- Delete temp markers:
  - `.ses`
  - `wct*.tmp`
- Delete confirmed Roaming/Public/temp payload copies.

### 7.4 Verify manually

- No suspicious process.
- No suspicious Run value.
- No suspicious task.
- No targeted artifacts remaining.

### 7.5 Keep forensic context

- Prefetch (`LOKI*.pf`) may remain and is normal as execution evidence.
- Preserve PCAP and hashes where needed for reporting.

---

## 8) Useful operator commands

### Run remediation

```bash
ansible-playbook -i inventories/hosts playbooks/proxHost/remediation/lokibot-remediation.yaml -e "target_vmid=2005 remediator_host=remediator" -vv
```

### Quick post-run status check from Proxmox

```bash
qm guest exec 2005 -- "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" -NoProfile -NonInteractive -Command "Get-ChildItem 'C:\Users\windows10\Downloads\Loki' -File -ErrorAction SilentlyContinue | Select Name,Length,LastWriteTime | Format-Table -AutoSize"
```

### Full artifact triage (all-in-one)

Use the existing one-shot QGA triage command used during testing and confirm:

- `"cleanup_passed": true`
- `counts.processes/runkeys/tasks/files` all `0`

---

## 9) Troubleshooting

### Playbook fails with host errors

- Ensure you run with working inventory path:
  - `-i inventories/hosts`
- Ensure `remediator` resolves from controller and SSH works.

### Script exits with verification failure

- Read `Print helper stdout` and `Print guest run log` sections.
- Look for first `VERIFY FAIL ...` line; it tells exactly what class failed.

### Weird characters in filenames (e.g., `ÂªOz`)

- This is usually encoding display conversion through guest-agent/base64 transport.
- Treat as variant artifact if it is in `Downloads\Loki` and non-PCAP.

---

## 10) Acceptance criteria

A run is considered successful only when all are true:

1. Ansible play ends with `failed=0`.
2. Helper exits `rc=0`.
3. Script prints `VERIFICATION RESULT: PASSED`.
4. Script prints `Cleanup finished`.
5. No suspicious leftovers in manual or one-shot triage checks.
