# Velociraptor collector

The SIEM-shaped piece in this capstone is **Velociraptor**. It is not Splunk. It is not a heavy forwarder. It is not the thing that sets `likely_infected`.

Proposal language said "SIEM." Early research notes and the class tools page wander through other logos. The files in the private tree are:

- `playbooks/proxHost/siem/server.yaml`
- `playbooks/proxHost/siem/agents.yaml`

That naming (`siem/`) is leftover from the proposal. I am not going to rename it in a private repo I do not own. I am going to say the word Velociraptor in public so nobody interviews me about SPL.

## What it does in this lab

**Server.** `server.yaml` brings up or configures a Velociraptor server on a Linux VM (Ubuntu-server role in the roster). That VM is on the lab side of the house, not on the internet. The private file had an admin password in it. That password is one of the reasons the source is still private. Rotate it. Do not copy it here.

**Agents.** `agents.yaml` pushes agents to guests on a chosen bridge. Collection of process lists, files, event logs — the usual Velociraptor hunt/collect story. We used it to pull more telemetry after a detonation than the PowerShell detector's JSON contained.

**Not in the rebuild trigger.** `windows-behavioral-redeploy.yaml` scores with `windows-behavioral-detect.ps1`. Velociraptor does not flip `replace_infected`. If the collector is down, we can still detect and rebuild. If the detector is down, Velociraptor still being up does not clone a golden image.

## How it sits next to the rest

```
Isolated VLAN
  Windows guest  --QGA-->  detector / family scripts
  Windows guest  --agent-->  Velociraptor server
  Linux guest    --agent-->  Velociraptor server
  Zeek           --pcap/logs-->  analysts (not Splunk)
  FakeNet        --fake services-->  the sample
```

Zeek is network. Velociraptor is host. The PowerShell script is the automated "is this guest dirty enough to kill." Three different jobs. Combining them into "we built a SIEM" is how the proposal read. Splitting them is how the lab actually ran.

## What I will not publish

- Server URL, GUI port, admin password
- Client enrollment secrets
- Agent lists with live addresses
- The bridge's subnet

## What I would change

Put the admin password in a vault. Do not name the folder `siem/` if the tool is Velociraptor; hiring managers grep. Write one hunt we actually ran (PowerShell 4104, Run keys, hash-like files) and check that YAML in as an example, redacted. That would make this page a lot less "trust me, we installed it."

Until then, the honest sentence is: we deployed Velociraptor with Ansible, we pushed agents, we used it as a collector, and the scoring/rebuild loop does not depend on it.
