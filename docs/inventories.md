# Inventory roles

The private tree has two inventory files. I am documenting **roles and template VMIDs**, not contents.

- `inventories/hosts` — remediator and group membership. Had passwords and teammate hostnames. Not published.
- `inventories/base-vms.ini` — golden templates by role. Had the live address plan. Not published.

If I ever check in an example inventory, it will be `hosts.example` with documentation addresses, vault placeholders, and no human names. That file is not in this repo yet.

## Remediator

Ansible talks to the Proxmox node. That node is the remediator. Guest work is `qm` plus QEMU guest agent, not SSH into Windows. The inventory alias for that host is not written here. Neither is the management address.

Semaphore uses the same inventory. I am not publishing the Semaphore URL.

## Golden templates

These are the CIS-hardened (or at least "this is the clean disk") images we cloned from. VMID is the Proxmox template id. Role is the name we used in lab notes.

| Role | Template VMID | Job in the lab |
| --- | ---: | --- |
| `fakenet` | 3000 | Fake network services on the detonation segment. Malware that wants the internet gets a lie, not a route. |
| `win10` | 3001 | Windows 10 golden image. Default rebuild target. |
| `win11` | 3002 | Windows 11 golden image. Rebuild map for win11 guests. |
| `winsrv` | 3003 | Windows Server golden image. Rebuild map for server guests. |
| `ubusrv` | 3004 | Ubuntu server. Linux services; Velociraptor server lived on a Linux VM of this kind of role. |
| `ubu` | 3005 | Ubuntu desktop-style guest. |
| `rocky` | 3006 | Rocky Linux baseline. |
| `kali` | 3007 | Offensive tools, still on the isolated side of the house. |
| `vyos` | 3008 | Routing. Generic VyOS template. |
| `pfsense` | 3009 | Firewall for the isolated segment. |
| `vyos-gw` | 3010 | Gateway role, split from generic VyOS so we could clone a gateway without arguing with the DHCP box. |
| `vyos-dhcp` | 3011 | DHCP for the lab segment. |
| `zeek` | 3012 | Network monitoring on the malware VLAN. |
| `malware` | 3013 | Dedicated detonation profile. Rebuild map for guests we named as malware boxes. |

WAN-side bridge role: `vmbr3`. Naming the bridge role is fair. Naming the subnet is not, because the live plan is in git history.

## ASCII clones

Example user VMs were cloned from mixed templates. We called them ASCII clones. They are not golden images. They get hashed by `asciiVMs-sha256Collection.yaml` so a drift on a student clone does not look like a drift on template 3002. Domain join is mentioned in the private README. There is no standalone Active Directory project in the public story. If someone asks "did you build AD," the honest answer is: join was in the notes, not a published automation repo.

## Groups, conceptually

I will not paste group names that encode people. Conceptually the inventory had:

- a remediator / Proxmox host
- a set of golden templates (the table above)
- a set of running clones (Windows detonation targets, Linux utilities, network appliances)
- a collector (Velociraptor server) and the guests that should get agents

Windows clones are what `windows-behavioral-redeploy.yaml` iterates. Network appliances are what you do not detonate on.

## What will never be in this file

- RFC1918 addresses from the lab
- VPN endpoints
- Teammate hostnames
- `ansible_password` / API tokens
- Semaphore and Proxmox UI locations

Those are the reason the private repo stays private. See the README section on public vs private.
