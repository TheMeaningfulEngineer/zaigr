"""Safe signaling helpers for test-owned host-network processes."""

import os
import signal
from pathlib import Path


def open_supervisor_pidfd(project):
    """Find this test project's supervisor for fault injection, without store metadata."""
    expected_executable = Path(project.zaigr_bin).stat()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        pidfd = None
        try:
            pidfd = os.pidfd_open(int(proc.name))
            args = (proc / "cmdline").read_bytes().split(b"\0")
            executable = (proc / "exe").stat()
            if (len(args) > 2 and args[1] == b"__supervise-vm"
                    and b"--workspace" in args
                    and args[args.index(b"--workspace") + 1] == os.fsencode(project.cwd)
                    and executable.st_dev == expected_executable.st_dev
                    and executable.st_ino == expected_executable.st_ino):
                result, pidfd = pidfd, None
                return result
        except (OSError, IndexError):
            continue
        finally:
            if pidfd is not None:
                os.close(pidfd)
    raise AssertionError("test project supervisor was not found")


def signal_recorded_process(record, name, sig, network_process=False):
    """Signal only the live process matching its supervisor-recorded identity."""
    identity = record["network_processes"][name] if network_process else record[name]
    pidfd = os.pidfd_open(identity["pid"])
    try:
        proc_stat = Path(f"/proc/{identity['pid']}/stat").read_text()
        fields = proc_stat[proc_stat.rfind(")") + 2:].split()
        assert fields[19] == str(identity["start_time"]), identity
        executable = os.stat(f"/proc/{identity['pid']}/exe")
        assert executable.st_dev == identity["exe_device"], identity
        assert executable.st_ino == identity["exe_inode"], identity
        signal.pidfd_send_signal(pidfd, sig)
    finally:
        os.close(pidfd)
