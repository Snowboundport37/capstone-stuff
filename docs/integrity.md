# Golden-image integrity (SHA-256)

The proposal promised hash-verified restores. This is the part that actually landed: two Ansible playbooks that collect SHA-256 over the golden templates and the ASCII clones, and JSON files that store the result.

It is not FOG. The proposal named FOG as an imaging option. We cloned from Proxmox templates with `qm`. The hash is how we argue the template did not drift, not how we streamed a disk over the LAN.

## Files

- `baseVMs-Sha256Collection.yaml` — hash the golden templates (roles 3000–3013).
- `asciiVMs-sha256Collection.yaml` — hash the example user clones.
- `vm-hashes/*.json` — output.

I am not publishing the hash values. A hash plus a VMID plus a timestamp from a real run is more identity than this public repo needs. The mechanism is the point.

## Why both playbooks

Golden templates are the restore source. If template 3002's hash moves and nobody rebuilt Windows 11 on purpose, the clean disk is no longer clean. ASCII clones are mixed-template user VMs. They are supposed to change when a student uses them. Hashing them anyway gives a before/after for a detonation: here is the clone at t0, here is the clone after the sample, here is the template we will clone back.

If we only hashed templates, we could prove "restore source is known." We could not prove "this particular clone is the one we started with." If we only hashed clones, we could not prove the restore source was still the restore source.

## Flow

1. Confirm the target VMs exist on the Proxmox node. These playbooks run on the remediator, same as everything else.
2. Collect SHA-256 for the disks we care about. Implementation detail stays in the private YAML. Public fact: SHA-256, JSON out.
3. Write `vm-hashes/*.json`.
4. Next run, compare. Mismatch on a template is an incident for the lab, not for the guest. Mismatch on a clone after detonation is expected. Mismatch on a clone after a rebuild should disappear.

We used this to argue a rebuild came from a known-good image. We did not use it as a file-integrity monitor inside the guest. The in-guest detector is a different tool ([detection.md](detection.md)).

## What a JSON file is for

Each file is evidence for a report: this VMID, this role, this hash, this collection time. A capstone demo without that is "trust me, I cloned the right disk." A capstone demo with a mismatched hash is how you notice you cloned yesterday's infected snapshot because someone forgot to convert it back to a template.

I would check a redacted example into `samples/` if I did this again. Same gap as the detector report.

## What this does not do

- It does not hash every file inside the guest OS. That would be a different product.
- It does not replace Velociraptor.
- It does not run during the WannaCry 20–90 second cleanup. Cleanup does not rehash the template. Rebuild does not rehash unless we run these playbooks again. We ran them around sessions, not around every process kill.
- It does not use YARA.

## Honest limits

Proxmox templates can move for boring reasons: a Windows update baked in, a tool installed, a convert-to-template that included a leftover ISO. A hash change is a signal to go look, not automatic proof of malware. The malware proof is the detector plus the family artifacts plus Zeek. The hash is the golden-image proof.
