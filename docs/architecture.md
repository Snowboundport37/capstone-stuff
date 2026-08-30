# Capstone architecture

High-level path:

```
Ansible / Semaphore
        |
        v
 Proxmox host (qm + QEMU guest agent)
        |
        +--> Windows guests (detector + family remediation scripts)
        +--> Linux guests
        +--> Velociraptor server VM
        +--> network tools on the isolated segment (pfSense, Zeek, FakeNet)
```

Nothing in this public wiki uses real lab hostnames, passwords, or the live IP plan.

## Pieces

**Hypervisor.** Proxmox VE on a Dell rack server. Golden templates for Windows 10/11, Windows Server, Ubuntu, Kali, VyOS, pfSense.

**Orchestration.** Ansible playbooks, run ad hoc or from Semaphore. The remediator host is the Proxmox node (inventory alias, not documented here). All guest work goes through `qm guest exec`, not SSH into Windows.

**Detection.** `windows-behavioral-detect.ps1` inside the guest. JSON report back to the playbook.

**Containment / rebuild.** If score crosses threshold and `replace_infected=true`, the playbook stops the VM, destroys it, clones the matching golden template onto the same VMID, reapplies name/CPU/RAM/NIC, starts it.

**Family cleanup.** WannaCry and LokiBot playbooks stage a PowerShell script into the guest and run it as SYSTEM. Used when we want artifact removal instead of a full rebuild.

**Collector.** Velociraptor server in a Linux VM, agents pushed to guests on a chosen bridge.

## Golden image selection

In order:

1. Per-VMID override map
2. Inferred from VM name / ostype (win11, server, malware profile, default Windows)
3. Fallback default template VMID

## What I would change

Vault for secrets from day one. Sigma/YARA next to the PowerShell detector so the logic is portable. Checked-in sample detector JSON. A public sanitized repo with example inventory, not the live one.
