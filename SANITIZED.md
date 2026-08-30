# Sanitized lab tree

This is a public copy of the private class repo (`ASC-ll/Capstone`) as of commit `b687290`.
The private org was not modified.

Replaced before publish:
- Lab RFC1918 addresses became `10.10.x.x` (the isolated lab LAN is documented as `10.10.0.0/24` here)
- Inventory/playbook passwords became `CHANGE_ME`
- Teammate hostnames became `pve-node` / `remediator`

Hashes in `vm-hashes/` are real SHA-256 of golden images. IOC hashes in `iocs.json` are identifiers, not samples. Malware binaries are not in this tree.

Use Ansible vault for real secrets if you clone this and point it at a lab.
