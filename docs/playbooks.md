# Playbook catalog

Private tree: `playbooks/proxHost/`. This page names every major file I am willing to talk about in public and says what it does in plain English. It does not include inventory contents, passwords, Semaphore job URLs, or live addresses.

I did not write every file. Deployment generations, inventories, and some of the network bring-up are team work (Snowboundport37, seraphim, seraphimgerber, ConnorEast). Detection, rebuild, and the family cleanup path are the parts I will walk without looking at the YAML. If a filename below is "we", that is honest.

Run order we actually used: ping → deploy → recon (QGA) → detonate → detect → family cleanup **or** rebuild → hash templates → tear down.

---

## Sanity

### `ping_test.yml`

The first playbook anyone should run. Ansible `ping` against the remediator. Proves inventory parsing, SSH or local connection to the Proxmox node, and that Semaphore is pointed at a real git directory. If this fails, nothing downstream is a malware problem. It is a wiring problem. We used it as the Semaphore "does the UI actually run Ansible" job.

---

## Deployment

Several generations. That is not a flex. That is a student repo.

### `deployment1-benchmark`

First real clone-from-template path that we measured. Pulls golden images, sets CPU / RAM / NIC, starts VMs. Benchmark in the name means we were timing it, not that it is a published benchmark suite. Treat it as the ancestor, not the one I would copy forward.

### `deployment1-remastered`

Rewrite of the benchmark playbook after we learned which `qm` flags we were getting wrong. Same job: clone templates, apply resources, start. Cleaner variable layout than the first one. Still not the final form.

### `deployment2`

Second generation of lab bring-up. More roles, more guests, fewer "we forgot the bridge" mistakes. This is the generation I would point at if someone asked "what did you actually use later in the term."

### `deployment2_backup`

A copy of `deployment2` we kept so a bad edit did not wipe the only working bring-up. Not a disaster-recovery product. It is a file named backup because we had already been burned.

### `nonProd-Scripts`

Non-production helpers around deployment. Includes a `credentials.yaml` in the private tree. **Contents are not published.** That file is one of the reasons this public repo is documentation instead of source. If I rebuilt this, those values would be vaulted or they would not exist.

### `singularVM-Deployment-MN.yaml`

Deploy **one** VM from a template instead of the whole lab. Useful when we wanted a fresh Windows box for a single sample without cloning the entire roster. The filename is ugly. The job is simple: pick a template, pick a VMID, clone, set resources, start.

### `removal_scripts`

Destroy lab VMs by pool or by VMID range. The opposite of deploy. This is how we reset the malware VLAN at the end of a session. It is also the playbook I am the most careful talking about, because a wrong range is a bad day. Never point it at anything that is not this isolated lab.

---

## Integrity

### `baseVMs-Sha256Collection.yaml`

Walk the golden templates (the 3000-range roles in [inventories.md](inventories.md)) and collect SHA-256 hashes. Proves the template disk we are about to clone is the template disk we hashed last time. Output lands with the other hash files.

### `asciiVMs-sha256Collection.yaml`

Same idea for the example user clones ("ASCII" clones). Those VMs are mixed-template copies, not the golden images themselves. Hashing them separately keeps "the Windows 11 template drifted" from being confused with "this student's clone drifted."

### `vm-hashes/*.json`

Where the collection playbooks write. One JSON per hashed VM or a bundle of them, depending on the run. I am not dumping the hashes here. The public fact is: we hashed, we stored JSON, we compared. See [integrity.md](integrity.md).

---

## Recon

### `IP_collect.yaml`

Ask running guests for addressing information and record it for the run. Needed because clones do not always come up the way you expected, and because the family playbooks and reports want a name to hang on a VMID. The output of this playbook is exactly the kind of live data this public repo refuses to print.

### `QemuAgent_Online.yaml`

Is the QEMU guest agent actually answering. If it is not, the detector will not run, the family scripts will not stage, and a rebuild that expects to talk to the guest first will sit there looking stupid. We learned to run this before remediation. It looks like a toy. It saved hours.

---

## Detection and rebuild

### `windows-behavioral-redeploy.yaml`

The orchestrator. Selects VMIDs, runs the detector through QGA, reads score / `likely_infected`, and if `replace_infected` is set and the gates pass, stops, destroys, clones the matching golden image onto the **same VMID**, restores name / CPU / RAM / NIC, starts. Writes a JSON timeline. Full writeup: [detection.md](detection.md).

### `windows-behavioral-detect.ps1`

The in-guest detector. Lookback in hours. Hash-like files, keyword files, Run / RunOnce, CPU/memory vs allowlist, PowerShell Operational 4104 bursts (`iwr`, `DownloadString`, `FromBase64String`, `reg add`, `bitsadmin`). Example we observed: `hashFiles.Count >= 3` → +30. Sets `likely_infected` when its internal threshold is hit. Lives under `files/` in the private tree, next to the family scripts.

---

## Family remediation

### `wannacry-remediation.yaml`

Ansible entry for WannaCry in-guest cleanup. Confirm QGA, stage script, run as SYSTEM, print summary. [wannacry.md](wannacry.md).

### `wannacry-remediate.ps1`

Kills `tasksche`, `mssecsvc`, `taskdl`, `taskse`, `WanaDecryptor`. Removes `mssecsvc2.0`. Deletes `@WanaDecryptor@`, `@Please_Read_Me@.txt`, `*.wnry`, `*.wncry`. Modes: Audit / Contain / Remediate / ReportOnly. Typical 20–90 seconds once QGA is up.

### `lokibot-remediation.yaml`

Ansible entry for LokiBot. Same QGA staging pattern. [lokibot.md](lokibot.md).

### `lokibot-remediate.ps1`

Process / path indicators `loki`, `Downloads\Loki`, `AppData\Roaming\Loki`, `fre.php`. Keeps `.pcap`. Scheduled-task cleanup for Loki actions. Optional C2 firewall blocks. Exit 0 only on `VERIFICATION RESULT: PASSED`.

### `agenttesla-remediation.yaml`

Ansible entry for Agent Tesla. Same shape. Thinner. [agent-tesla.md](agent-tesla.md).

### `agenttesla-remediate.ps1`

Sketched in-guest cleanup. Not the same depth of process list, verification, or testing as the other two. I am listing it so the catalog is complete, not so it looks like a third equal family.

### `guest_stage_and_remediate.py`

Python helper used by the family playbooks. QEMU guest agent is a small pipe. This script chunks a PowerShell file into the guest and then invokes it. Without it, we were fighting argument length and half-written scripts. Shared tooling. Not family-specific logic.

### `iocs.json`

Hashes and artifact names for the families we detonated. Hashes are identifiers and are fine to discuss. Binaries are not in this public repo and should not be. Do not treat this file as a threat feed.

---

## Older scan copies

### `remediation/2/scan.yml` and `remediation/2/per_vm_scan.yml`

Earlier scan generation. Per-VM and bulk variants. Kept because that is how the tree grew, not because I want anyone to run them instead of `windows-behavioral-redeploy.yaml`.

### `remediation/3/scan.yml` and `remediation/3/per_vm_scan.yml`

Third copy. Same story. If you are mapping git history, these folders are the breadcrumb. If you are mapping the system as built, use the named family playbooks and the behavioral redeploy playbook.

---

## Reports

### `remediation-reports/wannacry-report.json`

A real run's report file in the private tree. Shape: per-host cleanup results, timestamps, deleted-item counts. **I am not pasting live host data.** The public docs describe fields. A redacted sample belongs in `samples/` and is not here yet.

---

## Collector (Velociraptor)

### `siem/server.yaml`

Bring up or configure the Velociraptor server VM. This is the SIEM-shaped piece that actually exists. It is not Splunk. Admin password lived in this file in the private tree, which is another reason the source stays private. [siem.md](siem.md).

### `siem/agents.yaml`

Push Velociraptor agents to guests on a chosen bridge. Collection, not scoring. The PowerShell detector still decides `likely_infected`. Velociraptor is how we pull more artifacts after.

---

## What is not in this catalog on purpose

- Inventory files: see [inventories.md](inventories.md) for roles. Contents stay private.
- Semaphore project definitions, job URLs, UI logins.
- `credentials.yaml` contents.
- Malware binaries.
- Terraform / Pulumi. Researched, not shipped. The class tools page still lists them; this catalog does not.
