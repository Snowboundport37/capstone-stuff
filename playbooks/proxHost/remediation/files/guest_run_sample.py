#!/usr/bin/env python3
"""Run malware sample inside Windows guest via qm guest exec (Proxmox). Env: WCR_VMID, WCR_PS, WCR_SAMPLE, WCR_SETTLE."""
import json
import os
import subprocess
import sys

VMID = os.environ["WCR_VMID"]
PS = os.environ["WCR_PS"]
SAMPLE = os.environ["WCR_SAMPLE"].replace("\\", "/")
SETTLE = int(os.environ["WCR_SETTLE"])

cmd = (
    "Start-Process -FilePath '" + SAMPLE + "' -WindowStyle Hidden; "
    + "Start-Sleep -Seconds " + str(SETTLE) + "; Write-Output 'sample_ok'"
)
r = subprocess.run(
    [
        "qm",
        "guest",
        "exec",
        VMID,
        "--",
        PS,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        cmd,
    ],
    capture_output=True,
    text=True,
)
if r.returncode != 0:
    print(json.dumps({"success": False, "error": r.stderr.strip() or r.stdout.strip()}))
    sys.exit(1)
print(json.dumps({"success": True, "stdout": r.stdout.strip()}))
