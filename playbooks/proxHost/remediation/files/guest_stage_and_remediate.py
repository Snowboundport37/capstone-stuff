#!/usr/bin/env python3
"""
Stage remediation PowerShell script into Windows guest and execute it.
Script name is dynamic via SCRIPT_NAME env var.
"""
import base64
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone

SCRIPT_NAME = os.environ.get("SCRIPT_NAME", "wannacry-remediate.ps1")
VMID = os.environ.get("VMID", os.environ.get("WCR_VMID", "")).strip()
if not VMID:
    raise RuntimeError("VMID/WCR_VMID environment variable is required")

PS = os.environ.get("WCR_PS", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
default_stage = "C:/ProgramData/WannaCryRemediation"

STAGE = os.environ.get("WCR_STAGE", default_stage)
B64 = os.environ.get("WCR_B64", f"{default_stage}/stage.b64")
PS1 = os.environ.get("WCR_PS1", f"{default_stage}/{SCRIPT_NAME}")
LOCAL = os.environ.get("WCR_LOCAL_PS1", f"/tmp/{SCRIPT_NAME}")
CHUNK = int(os.environ.get("WCR_CHUNK_SIZE", "2200"))
QM_TIMEOUT = int(os.environ.get("WCR_QM_TIMEOUT", "180"))
CHUNK_WRITE_ATTEMPTS = int(os.environ.get("WCR_CHUNK_WRITE_ATTEMPTS", "8"))
PROGRESS_FILE = os.environ.get("WCR_PROGRESS_FILE", "")
SCRIPT_ARGS = os.environ.get("SCRIPT_ARGS", "").strip()


def log_step(msg):
    line = f"[{datetime.now(timezone.utc).isoformat()}] {msg}"
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        pass
    if PROGRESS_FILE:
        try:
            with open(PROGRESS_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def parse_json(txt):
    try:
        return json.loads(txt)
    except Exception:
        return {}


def qga_exec(argv):
    cmd = ["qm", "guest", "exec", str(VMID), "--timeout", str(QM_TIMEOUT), "--"]
    cmd.extend(argv)
    return subprocess.run(cmd, capture_output=True, text=True)


def qga_exec_retry(argv, attempts=4, delay_s=2):
    last = None
    for _ in range(attempts):
        rv = qga_exec(argv)
        last = rv
        if rv.returncode == 0:
            return rv
        out = ((rv.stderr or "") + " " + (rv.stdout or "")).lower()
        if "qemu guest agent is not running" in out or "timeout" in out:
            time.sleep(delay_s)
            continue
        return rv
    return last


def decode_stream(result, key):
    raw = (result.get(key, "") or "").strip()
    if not raw:
        return ""
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8", errors="replace")
    except Exception:
        return raw


def exec_collect(argv, allow_pid_retry=True):
    launch = qga_exec_retry(argv)
    if launch is None or launch.returncode != 0:
        msg = (launch.stderr if launch else "") or (launch.stdout if launch else "") or "failed to launch command"
        raise RuntimeError(msg.strip())
    first = parse_json(launch.stdout or "")
    if "pid" not in first:
        return first
    pid = first["pid"]
    transient_qga_failures = 0
    for _ in range(1800):
        rs = subprocess.run(
            ["qm", "guest", "exec-status", str(VMID), str(pid)],
            capture_output=True,
            text=True,
        )
        if rs.returncode != 0:
            msg = (rs.stderr or rs.stdout or "exec-status failed").strip()
            low = msg.lower()
            if "pid" in low and "does not exist" in low and allow_pid_retry:
                # qga sometimes loses pid state while command is still running/finished; rerun once.
                log_step("PID disappeared during polling, retrying remediation command once")
                return exec_collect(argv, allow_pid_retry=False)
            if "qemu guest agent is not running" in low or "timeout" in low:
                transient_qga_failures += 1
                # Tolerate brief QGA service restarts/flaps.
                if transient_qga_failures <= 30:
                    time.sleep(2)
                    continue
            raise RuntimeError(msg)
        status = parse_json(rs.stdout or "")
        if status.get("exited") is True:
            return status
        transient_qga_failures = 0
        time.sleep(1)
    raise RuntimeError("timeout waiting for guest script completion")


def stage_script():
    log_step("Loading local remediation script")
    with open(LOCAL, "rb") as f:
        blob = base64.b64encode(f.read()).decode("ascii")
    chunks = [blob[i : i + CHUNK] for i in range(0, len(blob), CHUNK)]
    log_step(f"Chunking script: {len(chunks)} chunks")

    prep = (
        "New-Item -ItemType Directory -Force -Path '" + STAGE + "' | Out-Null; "
        + "Remove-Item -LiteralPath '" + B64 + "' -Force -ErrorAction SilentlyContinue; "
        + "Remove-Item -LiteralPath '" + PS1 + "' -Force -ErrorAction SilentlyContinue"
    )
    rv = qga_exec_retry([PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prep])
    if rv.returncode != 0:
        raise RuntimeError("guest stage prep failed: " + ((rv.stderr or rv.stdout).strip()))
    log_step("Guest staging directory prepared")

    for i, chunk in enumerate(chunks):
        cmdlet = "Set-Content" if i == 0 else "Add-Content"
        ps_cmd = cmdlet + " -LiteralPath '" + B64 + "' -Value '" + chunk + "' -Encoding Ascii"
        ok = False
        for _ in range(CHUNK_WRITE_ATTEMPTS):
            wr = qga_exec_retry([PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd], attempts=2)
            if wr.returncode == 0:
                ok = True
                break
            time.sleep(1)
        if not ok:
            raise RuntimeError(f"chunk write failed at {i + 1}/{len(chunks)}")
        if i == 0 or (i + 1) % 10 == 0 or (i + 1) == len(chunks):
            log_step(f"Chunk write progress {i + 1}/{len(chunks)}")

    dec = (
        "$t = Get-Content -Raw -LiteralPath '" + B64 + "'; "
        + "$b = [Convert]::FromBase64String($t.Trim()); "
        + "[IO.File]::WriteAllBytes('" + PS1 + "', $b)"
    )
    rv = qga_exec_retry([PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", dec])
    if rv.returncode != 0:
        raise RuntimeError("guest decode failed: " + ((rv.stderr or rv.stdout).strip()))
    log_step(f"Guest script written to {PS1}")


def get_vm_host_info():
    rv = subprocess.run(["qm", "config", str(VMID)], capture_output=True, text=True)
    if rv.returncode != 0:
        return "qm config unavailable"
    lines = []
    for line in (rv.stdout or "").splitlines():
        if line.startswith("name:") or line.startswith("agent:") or line.startswith("ostype:"):
            lines.append(line.strip())
    return " | ".join(lines) if lines else "config read ok"


def get_guest_identity():
    cmd = (
        "$u=[Environment]::UserName; "
        "$h=$env:COMPUTERNAME; "
        "$os=(Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption; "
        "$o='guest_host=' + $h + ';user=' + $u + ';os=' + $os; "
        "Write-Output $o"
    )
    rv = qga_exec_retry([PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd])
    if rv.returncode != 0:
        return "guest identity unavailable"
    result = parse_json(rv.stdout or "")
    return decode_stream(result, "out-data").strip() or "guest identity unavailable"


def main():
    try:
        start = time.time()
        log_step(f"Starting helper for VMID={VMID}")
        log_step("Host VM config: " + get_vm_host_info())
        stage_script()
        log_step("Guest identity: " + get_guest_identity())
        log_step("Executing remediation script inside guest")
        guest_cmd = [PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", PS1]
        if SCRIPT_ARGS:
            guest_cmd.extend(shlex.split(SCRIPT_ARGS))
        result = exec_collect(guest_cmd)
        exitcode = int(result.get("exitcode", 1))
        out = decode_stream(result, "out-data").strip()
        err = decode_stream(result, "err-data").strip()
        elapsed = round(time.time() - start, 1)
        log_step(f"Remediation finished with exitcode={exitcode} elapsed_seconds={elapsed}")

        if out:
            print(out)
        if err:
            sys.stderr.write(err + "\n")

        sys.exit(exitcode)
    except Exception as exc:
        sys.stderr.write("guest_stage_and_remediate.py failed: " + str(exc) + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
