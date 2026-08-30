# Proxmox malware remediation lab

Public documentation for my Champlain College senior capstone. Team project. I am one of the authors.

This repository is the public face: architecture, detection, and remediation writeups. The private team source still lives in a class org until credentials are stripped from git history. Do not expect `git clone` of this repo to deploy a lab.

**Wiki (start here):** https://github.com/Snowboundport37/capstone-stuff/wiki

## What it does

- Deploys isolated Windows and Linux VMs on Proxmox from CIS-hardened golden images
- Runs a PowerShell behavioral detector inside Windows guests through QEMU guest agent
- Optionally destroys a flagged VM and clones the golden image back onto the same VMID
- Family playbooks for WannaCry and LokiBot
- Velociraptor as the collector (not Splunk)

## What it is not

- Not Splunk, not Cuckoo, not YARA
- Not a production EDR
- Not a dump of lab passwords, hostnames, or live IP plans

## Docs in this repo

- [Architecture](docs/architecture.md)
- [Behavioral detection](docs/detection.md)
- [WannaCry remediation](docs/wannacry.md)
- [LokiBot remediation](docs/lokibot.md)
- [Original proposal](docs/proposal.md)

## Team

Git history on the private repo includes Snowboundport37, seraphim, seraphimgerber, and ConnorEast. Ask me which playbooks I wrote.
