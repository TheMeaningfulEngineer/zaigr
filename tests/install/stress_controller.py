"""Safely freeze one verified v10 outer QEMU for the stress suspend test."""

import argparse
import json
import os
import re
import select
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

ALLOWED_DURATIONS = {2, 3, 120, 900}
CONTROL_PATH = re.compile(
    r"^/home/user/vsock-v10-validation/[^/]+/suspend-control\.json$"
)
STOP_REQUESTED = False
STDIN_CLOSED = False


def _stop_signal(signum, frame):
    global STOP_REQUESTED
    STOP_REQUESTED = True


def _log(path, event):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(event, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())


def _boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def _process_identity(metadata):
    pid = int(metadata["pid"])
    stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = stat_line[stat_line.rfind(")") + 2 :].split()
    start_time = fields[19]
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    arguments = [item.decode("utf-8", "replace") for item in cmdline]
    executable = os.stat(f"/proc/{pid}/exe")
    executable_path = os.readlink(f"/proc/{pid}/exe")
    if not Path(executable_path).name.startswith("qemu-system"):
        raise RuntimeError(f"metadata PID {pid} is not QEMU: {executable_path}")

    disk = str(Path(metadata["disk"]).resolve())
    workdir = str(Path(metadata["workdir"]).resolve())
    disk_argument = any(
        part == f"file={disk}" or part.startswith(f"file={disk},")
        for argument in arguments
        for part in argument.split(",")
    )
    workdir_argument = any(
        argument == workdir or argument.startswith(workdir + os.sep)
        for argument in arguments
    )
    if not disk_argument or not workdir_argument:
        raise RuntimeError(
            f"metadata PID {pid} command line does not contain its exact disk and workdir"
        )
    return {
        "pid": pid,
        "ppid": int(fields[1]),
        "start_time": start_time,
        "exe_path": executable_path,
        "exe_device": executable.st_dev,
        "exe_inode": executable.st_ino,
        "disk": disk,
        "workdir": workdir,
        "cmdline": arguments,
    }


def _same_process(metadata, initial):
    current = _process_identity(metadata)
    identity_fields = (
        "pid",
        "start_time",
        "exe_device",
        "exe_inode",
        "disk",
        "workdir",
    )
    if any(current[field] != initial[field] for field in identity_fields):
        raise RuntimeError(
            "QEMU process identity changed during suspend controller run"
        )
    return current


def _ssh_command(metadata, remote_command, timeout=2):
    ssh = list(metadata["ssh"])
    destination = ssh.pop()
    ssh.extend(["-o", "ServerAliveInterval=0", "-o", "ConnectTimeout=1", destination])
    result = subprocess.run(
        ssh + [remote_command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return result


def _read_remote_control(metadata, control_path):
    command = "cat -- " + shlex.quote(control_path)
    try:
        result = _ssh_command(metadata, command)
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except ValueError:
        return None


def _wait_for_ready(metadata, control_path, consumed_tokens, timeout=1800):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not STOP_REQUESTED:
        request = _read_remote_control(metadata, control_path)
        if request is not None and request.get("phase") == "ready":
            token = request.get("token", "")
            if not re.fullmatch(r"[0-9a-f]{32}", token):
                raise RuntimeError(
                    "suspend request token must be 32 lowercase hex digits"
                )
            if token in consumed_tokens:
                _wait_or_stop(1)
                continue
            duration = request.get("duration")
            if type(duration) is not int or duration not in ALLOWED_DURATIONS:
                raise RuntimeError(
                    f"suspend duration must be one of {sorted(ALLOWED_DURATIONS)}"
                )
            return request
        _wait_or_stop(1)
    if STOP_REQUESTED:
        return None
    raise TimeoutError(f"no ready suspend request arrived within {timeout}s")


def _sleep_bounded(seconds):
    deadline = time.monotonic() + seconds
    while not STOP_REQUESTED:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 1))


def _wait_or_stop(seconds):
    global STOP_REQUESTED
    global STDIN_CLOSED
    if STOP_REQUESTED:
        return
    if STDIN_CLOSED:
        _sleep_bounded(seconds)
        return
    try:
        readable, _, _ = select.select([sys.stdin], [], [], seconds)
    except (OSError, ValueError):
        readable = []
        _sleep_bounded(seconds)
    if readable:
        line = sys.stdin.readline()
        if not line:
            STDIN_CLOSED = True
            _sleep_bounded(seconds)
        elif line.strip() == "stop":
            STOP_REQUESTED = True


def _send_resume(pidfd):
    signal.pidfd_send_signal(pidfd, signal.SIGCONT)


def _write_remote_ack(metadata, control_path, ack):
    payload = json.dumps(ack, separators=(",", ":"))
    remote_path = repr(control_path + ".ack")
    python = (
        "import json,os,tempfile; "
        f"p={remote_path}; data={payload!r}; "
        "fd,tmp=tempfile.mkstemp(prefix='.suspend-ack-',dir=os.path.dirname(p)); "
        "f=os.fdopen(fd,'w'); f.write(data+chr(10)); f.flush(); os.fsync(f.fileno()); f.close(); "
        "os.replace(tmp,p)"
    )
    command = "python3 -c " + shlex.quote(python)
    deadline = time.monotonic() + 30
    last_error = "SSH did not reconnect"
    while time.monotonic() < deadline:
        try:
            result = _ssh_command(metadata, command, timeout=3)
        except subprocess.TimeoutExpired:
            last_error = "SSH acknowledgment command timed out"
            time.sleep(0.5)
            continue
        if result.returncode == 0:
            return
        last_error = (
            result.stderr or result.stdout
        ).strip() or f"SSH returned {result.returncode}"
        time.sleep(0.5)
    raise TimeoutError(
        f"could not write resume acknowledgment within 30s: {last_error}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metadata", required=True, help="existing outer-v10 JSON metadata"
    )
    parser.add_argument(
        "--control", required=True, help="absolute outer suspend rendezvous JSON path"
    )
    parser.add_argument("--log", required=True, help="local JSONL controller log")
    args = parser.parse_args()

    control_path = args.control
    if not Path(control_path).is_absolute() or not CONTROL_PATH.fullmatch(control_path):
        parser.error(
            "--control must be /home/user/vsock-v10-validation/<label>/suspend-control.json"
        )
    metadata_path = Path(args.metadata)
    if not metadata_path.is_file():
        parser.error(f"--metadata does not exist: {metadata_path}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    log_path = Path(args.log).expanduser().resolve()

    global STOP_REQUESTED
    global STDIN_CLOSED
    STOP_REQUESTED = False
    STDIN_CLOSED = False
    signal.signal(signal.SIGINT, _stop_signal)
    signal.signal(signal.SIGTERM, _stop_signal)
    initial = _process_identity(metadata)
    pidfd = os.pidfd_open(initial["pid"])
    _same_process(metadata, initial)
    pre_main_boot_id = _boot_id()
    try:
        existing = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
        ]
    except FileNotFoundError:
        existing = []
    consumed_tokens = {
        item.get("token")
        for item in existing
        if item.get("event") == "resumed" and item.get("token")
    }
    try:
        while not STOP_REQUESTED:
            ready = _wait_for_ready(metadata, control_path, consumed_tokens)
            if ready is None:
                break
            token = ready["token"]
            pre_outer_result = _ssh_command(
                metadata, "cat /proc/sys/kernel/random/boot_id", timeout=3
            )
            pre_outer_boot_id = pre_outer_result.stdout.strip()
            if pre_outer_result.returncode != 0 or not re.fullmatch(
                r"[0-9a-f-]{36}", pre_outer_boot_id
            ):
                raise RuntimeError("could not read outer VM boot ID before freeze")
            initial = _same_process(metadata, initial)
            started = time.monotonic()
            stop_sent = False
            post_outer_boot_id = None
            post_main_boot_id = None
            final_identity = None
            last_error = None
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
                stop_sent = True
                _log(
                    log_path,
                    {
                        "event": "stopped",
                        "token": token,
                        "duration_requested": ready["duration"],
                        "started_monotonic": started,
                        "main_boot_id_before": pre_main_boot_id,
                        "outer_boot_id_before": pre_outer_boot_id,
                        "qemu_before": initial,
                    },
                )
                while (
                    not STOP_REQUESTED
                    and time.monotonic() - started < ready["duration"]
                ):
                    _wait_or_stop(1)
            finally:
                if stop_sent:
                    _send_resume(pidfd)

            resume_deadline = time.monotonic() + 30
            while time.monotonic() < resume_deadline:
                try:
                    final_identity = _process_identity(metadata)
                    post_main_boot_id = _boot_id()
                    result = _ssh_command(
                        metadata, "cat /proc/sys/kernel/random/boot_id", timeout=3
                    )
                    if result.returncode == 0:
                        post_outer_boot_id = result.stdout.strip()
                        break
                    last_error = (result.stderr or result.stdout).strip()
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                    last_error = str(error)
                time.sleep(0.5)
            elapsed = time.monotonic() - started
            event = {
                "event": "resumed",
                "token": token,
                "duration_requested": ready["duration"],
                "elapsed_seconds": elapsed,
                "cancelled": STOP_REQUESTED,
                "main_boot_id_before": pre_main_boot_id,
                "main_boot_id_after": post_main_boot_id,
                "outer_boot_id_before": pre_outer_boot_id,
                "outer_boot_id_after": post_outer_boot_id,
                "qemu_before": initial,
                "qemu_after": final_identity,
                "reconnect_error": last_error,
            }
            _log(log_path, event)
            if post_outer_boot_id is None:
                raise TimeoutError(f"outer SSH did not recover within 30s: {last_error}")
            ack = {
                "token": token,
                "phase": "resumed",
                "main_boot_id": post_main_boot_id,
                "elapsed": elapsed,
                "cancelled": STOP_REQUESTED,
            }
            _write_remote_ack(metadata, control_path, ack)
            consumed_tokens.add(token)
            print("SUSPEND_RESUMED " + json.dumps(event, sort_keys=True), flush=True)
    finally:
        os.close(pidfd)
        _log(
            log_path,
            {
                "event": "controller-stopped",
                "consumed_tokens": sorted(consumed_tokens),
                "main_boot_id": _boot_id(),
                "qemu": _process_identity(metadata),
            },
        )


if __name__ == "__main__":
    main()
