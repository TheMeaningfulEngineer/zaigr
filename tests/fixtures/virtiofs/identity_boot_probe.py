"""Boot the built guest through two static virtiofsd exports and check ID translation.

Run from the repository root after building bzImage and base-rootfs.img.zst.
This disposable prerequisite probe never touches a project store.
"""

import base64
import os
import pathlib
import signal
import socket
import subprocess
import tempfile
import time


def command(*args, **kwargs):
    """Run a prerequisite tool and return its stdout."""
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, **kwargs).stdout


def daemon(binary, shared, sock, guest_uid, guest_gid, log):
    """Start a daemon with the calling host identity and both guest ID aliases."""
    host_uid, host_gid = os.geteuid(), os.getegid()
    flags = [
        binary, "--sandbox", "namespace", "--cache", "auto",
        "--inode-file-handles=never", "--shared-dir", str(shared),
        "--socket-path", str(sock),
        "--translate-uid", f"squash-guest:0:{host_uid}:1",
        "--translate-uid", f"guest:{guest_uid}:{host_uid}:1",
        "--translate-uid", f"host:{host_uid}:{guest_uid}:1",
        "--translate-gid", f"squash-guest:0:{host_gid}:1",
        "--translate-gid", f"guest:{guest_gid}:{host_gid}:1",
        "--translate-gid", f"host:{host_gid}:{guest_gid}:1",
    ]
    return subprocess.Popen(flags, stdout=log, stderr=log, start_new_session=True)


def wait_socket(sock, proc):
    """Wait for the daemon to publish its Unix socket."""
    for _ in range(100):
        if sock.exists():
            return
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited {proc.returncode} before {sock}")
        time.sleep(0.1)
    raise RuntimeError(f"daemon did not create {sock}")


def ssh(key, port, user, *remote):
    """Execute an SSH command in the disposable guest."""
    return subprocess.run([
        "ssh", "-F", "/dev/null", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=2",
        "-o", "LogLevel=ERROR", "-i", str(key), "-p", str(port),
        f"{user}@127.0.0.1", *remote,
    ], text=True, capture_output=True, check=False)


def main():
    """Build a disposable disk, boot both mounts, and assert host-owned writes."""
    repo = pathlib.Path(__file__).resolve().parents[3]
    binary = repo / "cmd/zaigr/vm_data/virtiofsd"
    kernel = repo / "cmd/zaigr/vm_data/bzImage"
    rootfs = repo / "cmd/zaigr/vm_data/base-rootfs.img.zst"
    with tempfile.TemporaryDirectory(prefix="vfs-id-") as tmp:
        root = pathlib.Path(tmp)
        workspace, state = root / "workspace", root / "state"
        workspace.mkdir()
        state.mkdir(mode=0o700)
        key = root / "id_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        pubkey = (root / "id_ed25519.pub").read_text().strip()
        raw = root / "rootfs.raw"
        with raw.open("wb") as stream:
            subprocess.run(["zstd", "-dc", str(rootfs)], check=True, stdout=stream)
        image = root / "rootfs.qcow2"
        command("qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(image))
        raw.unlink()
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        sockets = [root / "workspace.sock", root / "state.sock"]
        log = (root / "daemon.log").open("w")
        daemons = []
        qemu = None
        try:
            # Factory rootfs has user UID 1000 and primary GID 1001.
            for shared, sock in zip((workspace, state), sockets):
                proc = daemon(str(binary), shared, sock, 1000, 1001, log)
                daemons.append(proc)
                wait_socket(sock, proc)
            append = " ".join((
                "console=ttyS0 root=/dev/vda rw init=/usr/lib/systemd/systemd",
                "systemd.unit=multi-user.target panic=-1 quiet",
                f"zaigr.host-epoch={int(time.time())}",
                "zaigr.root-pubkey=" + base64.b64encode(pubkey.encode()).decode(),
                "zaigr.user-pubkey=" + base64.b64encode(pubkey.encode()).decode(),
            ))
            qemu_args = [
                "qemu-system-x86_64", "-M", "microvm,acpi=off,auto-kernel-cmdline=on,isa-serial=on,memory-backend=mem",
                "-nodefaults", "-nographic", "-no-reboot", "-m", "512", "-smp", "1",
                "-object", "memory-backend-memfd,id=mem,size=512M,share=on",
                "-serial", "file:" + str(root / "serial.log"), "-kernel", str(kernel),
                "-drive", f"id=root,file={image},format=qcow2,if=none",
                "-device", "virtio-blk-device,drive=root",
                "-chardev", f"socket,id=workspace_fs,path={sockets[0]},server=off",
                "-device", "vhost-user-fs-device,chardev=workspace_fs,tag=workspace",
                "-chardev", f"socket,id=agent_state_fs,path={sockets[1]},server=off",
                "-device", "vhost-user-fs-device,chardev=agent_state_fs,tag=zaigr_agent_state",
                "-append", append, "-netdev", f"user,id=net0,ipv6=off,hostfwd=tcp::{port}-:22",
                "-device", "virtio-net-device,netdev=net0", "-accel", "kvm", "-cpu", "host",
            ]
            qemu = subprocess.Popen(qemu_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if qemu.poll() is not None:
                    raise RuntimeError(f"QEMU exited {qemu.returncode}; see {root / 'serial.log'}")
                ready = ssh(key, port, "root", "true")
                if ready.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError(f"SSH timeout: {ready.stderr}; see {root / 'serial.log'}")
            for user in ("user", "root"):
                result = ssh(key, port, user, "set -eu; findmnt -n -o FSTYPE /home/user/workspace; findmnt -n -o FSTYPE /home/user/.zaigr-agent-state; touch /home/user/workspace/" + user + "-write; touch /home/user/.zaigr-agent-state/" + user + "-write; chmod 600 /home/user/workspace/" + user + "-write /home/user/.zaigr-agent-state/" + user + "-write")
                print(user, result.returncode, result.stdout, result.stderr)
                if result.returncode != 0 or result.stdout.splitlines() != ["virtiofs", "virtiofs"]:
                    raise RuntimeError("guest mount/write failed")
                for shared in (workspace, state):
                    stat = (shared / f"{user}-write").stat()
                    print(shared.name, user, "host stat", stat.st_uid, stat.st_gid, oct(stat.st_mode & 0o777))
                    assert (stat.st_uid, stat.st_gid, stat.st_mode & 0o777) == (os.geteuid(), os.getegid(), 0o600)
            print("PASS: both mounts, guest user/root create and chmod, host ownership")
        except Exception:
            for name in ("serial.log", "daemon.log"):
                path = root / name
                if path.exists():
                    print(name, path.read_text(errors="replace")[-10000:])
            raise
        finally:
            for proc in ([qemu] if qemu else []) + daemons:
                if proc and proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
            for proc in ([qemu] if qemu else []) + daemons:
                if proc:
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
            log.close()


if __name__ == "__main__":
    main()
