# Agent Tesla remediation (sketched)

Defensive lab cleanup for Agent Tesla-style stealer artifacts. Isolated guests only.

**This page is thinner than WannaCry and LokiBot because the playbook is thinner.** I am not going to write a long family analysis around a sketched script. The catalog would be a lie without it. The catalog would also be a lie if I made this look equal.

## Files

- `agenttesla-remediation.yaml` — Ansible entry under `playbooks/proxHost/remediation/`.
- `agenttesla-remediate.ps1` — in-guest cleanup.
- `guest_stage_and_remediate.py` — same QGA chunker as the other families.

## What exists

The same skeleton as the other two:

1. Confirm the VM is up and QGA answers.
2. Stage the PowerShell script.
3. Run as SYSTEM.
4. Kill obvious processes, wipe obvious paths, poke at persistence.

That skeleton is real. The depth is not. Process names, path lists, verification gates, and "what does a pass look like" are not at LokiBot's `VERIFICATION RESULT: PASSED` standard, and not at WannaCry's mode-switched Audit/Contain/Remediate/ReportOnly standard. Testing was lighter. I did not hang a demo on this family the way we hung demos on WannaCry.

## What I will not claim

- That we have Agent Tesla coverage comparable to the other two families
- That this script is a generic RAT cleaner
- That a rebuild is unnecessary if this script exits 0 (I would rebuild anyway if the detector was loud)
- A runtime number. I have 20-90 seconds for WannaCry because we watched it. I do not have the same measured number here.

## When we would use it versus a rebuild

If a guest was a known Agent Tesla detonation and we wanted leftover artifacts listed or roughly removed, this is the file we would call. If we wanted a clean disk, `windows-behavioral-redeploy.yaml` with `replace_infected=true` is the grown-up path and does not care which family it was.

## Why it is still in the tree

Three malware categories were in the proposal (ransomware, worm, RAT / stealer). WannaCry covered ransomware. LokiBot covered stealer. Agent Tesla was the other stealer/RAT-shaped attempt. Shipping two solid families and one sketch is ugly. Pretending the sketch is solid is worse.

If I continued the project I would either finish verification to LokiBot's bar or delete the playbook from the story.
