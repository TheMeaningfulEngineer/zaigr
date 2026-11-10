"""Disposable, checksum-verified distro VMs for install acceptance tests."""

import atexit
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, err_msg, run, spawn_interactive

DISTROS = {
    "ubuntu-22.04": {
        "url": "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img",
        "checksum": "SHA256SUMS",
        "algorithm": "sha256",
        "name": "ubuntu-22.04-server-cloudimg-amd64.img",
        "login": "user",
        "redirect_hosts": {"cloud-images.ubuntu.com"},
    },
    "ubuntu-24.04": {
        "url": "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img",
        "checksum": "SHA256SUMS",
        "algorithm": "sha256",
        "name": "ubuntu-24.04-server-cloudimg-amd64.img",
        "login": "user",
        "redirect_hosts": {"cloud-images.ubuntu.com"},
    },
    "ubuntu-26.04": {
        "url": "https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img",
        "checksum": "SHA256SUMS",
        "algorithm": "sha256",
        "name": "ubuntu-26.04-server-cloudimg-amd64.img",
        "login": "user",
        "redirect_hosts": {"cloud-images.ubuntu.com"},
    },
    "debian-12": {
        "url": "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2",
        "checksum": "SHA512SUMS",
        "algorithm": "sha512",
        "name": "debian-12-generic-amd64.qcow2",
        "login": "user",
        "redirect_hosts": {"cloud.debian.org", "chuangtzu.ftp.acc.umu.se", "gemmei.ftp.acc.umu.se", "laotzu.ftp.acc.umu.se"},
    },
    "debian-13": {
        "url": "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2",
        "checksum": "SHA512SUMS",
        "algorithm": "sha512",
        "name": "debian-13-generic-amd64.qcow2",
        "login": "user",
        "redirect_hosts": {"cloud.debian.org", "chuangtzu.ftp.acc.umu.se", "gemmei.ftp.acc.umu.se", "laotzu.ftp.acc.umu.se"},
    },
}

# Baseline packages in prepared distro images. slirp4netns remains installed
# here so acceptance tests can cover both system-package states by removing it.
# This is the prepared outer test VM's baseline package set, not Zaigr's
# install prerequisites. gcc and libsqlite3-dev support the virtiofs integrity
# probe. uidmap and the subordinate ID ranges served the IP namespace fixture,
# removed for 0.4.0; they stay because the package list is part of the
# prepared image cache key, and changing it re-downloads every distro image.
# The controller's SSH/scp/keygen live outside that VM; product commands inside
# it use a restricted PATH without host OpenSSH tools.
GUEST_PACKAGES = (
    "coreutils", "e2fsprogs", "gcc", "libsqlite3-dev", "openssh-client",
    "qemu-system-x86", "qemu-utils", "slirp4netns", "uidmap", "util-linux",
)
KEEP_ENV = "ZAIGR_KEEP_CLOUDVM"
_LIVE_VMS = set()


def _external_sources():
    return Path(os.environ.get("ZAIGR_EXTERNAL_SOURCES", str(Path.home() / ".zaigr" / "external-sources"))).expanduser().resolve()


def _harness_root():
    path = Path(REPO_ROOT) / ".local" / "cloudvm-verification" / "harness"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _prerequisites():
    missing = [name for name in ("qemu-system-x86_64", "qemu-img", "cloud-localds", "ssh", "scp", "ssh-keygen") if not shutil.which(name)]
    if not Path("/dev/kvm").exists():
        missing.append("/dev/kvm")
    elif not os.access("/dev/kvm", os.R_OK | os.W_OK):
        pytest.fail("Cloud-VM install tests require read/write access to /dev/kvm")
    if missing:
        guidance = " Rebuild the zaigr-dev setup (cloud-image-utils provides cloud-localds)." if "cloud-localds" in missing else ""
        pytest.fail("Cloud-VM install tests require: " + ", ".join(missing) + "." + guidance)


def _checked(command, timeout=60, cwd=None, context="cloudvm"):
    stdout, stderr, rc = run(command, timeout=timeout, cwd=cwd, context=context)
    if rc != 0:
        pytest.fail(f"Cloud-VM setup command failed ({shlex.join([str(x) for x in command])}):\n{err_msg(stdout, stderr)}")
    return stdout


def _download(url, expected_hosts, destination, timeout=600):
    """Download a file while rejecting newly introduced redirect hostnames."""
    request = urllib.request.Request(url, headers={"User-Agent": "zaigr-cloudvm-tests/1"})

    class CheckedRedirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, file, code, message, headers, new_url):
            host = urllib.parse.urlparse(new_url).hostname
            if host not in expected_hosts:
                file.close()
                pytest.fail(
                    f"Cloud image URL {url} redirected to unexpected hostname {host!r} "
                    f"({new_url}). Add only that documented mirror hostname after review."
                )
            return super().redirect_request(request, file, code, message, headers, new_url)

    try:
        response = urllib.request.build_opener(CheckedRedirects()).open(request, timeout=30)
    except (urllib.error.URLError, OSError) as error:
        pytest.fail(f"Could not download {url}: {error}")
    final_url = response.geturl()
    final_host = urllib.parse.urlparse(final_url).hostname
    if final_host not in expected_hosts:
        response.close()
        pytest.fail(
            f"Cloud image URL {url} redirected to unexpected hostname {final_host!r} "
            f"({final_url}). Add only that documented mirror hostname after review."
        )
    temporary = destination.with_name(destination.name + f".part-{os.getpid()}")
    try:
        with response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        temporary.replace(destination)
    except (urllib.error.URLError, OSError) as error:
        temporary.unlink(missing_ok=True)
        pytest.fail(f"Could not download {url}: {error}")


def _image(distro):
    config = DISTROS[distro]
    cache = _external_sources() / "cloud-images"
    cache.mkdir(parents=True, exist_ok=True)
    checksum_url = config["url"].rsplit("/", 1)[0] + "/" + config["checksum"]
    checks = cache / f"{distro}-{config['checksum']}"
    with open(cache / f".{distro}.download.lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Fetch the small official manifest each time so a mutable `latest`
        # Debian path cannot silently keep using yesterday's digest.
        _download(checksum_url, config["redirect_hosts"], checks)
        checksum = None
        for row in checks.read_text(encoding="utf-8").splitlines():
            fields = row.split()
            if len(fields) >= 2 and fields[-1].lstrip("*").removeprefix("./") == config["name"]:
                checksum = fields[0]
                break
        if not checksum:
            pytest.fail(f"{checksum_url} has no checksum entry for {config['name']}")
        algorithm = config["algorithm"]
        image = cache / f"{checksum[:16]}-{config['name']}"
        if not image.is_file():
            _download(config["url"], config["redirect_hosts"], image)
        digest = hashlib.new(algorithm)
        with image.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest().lower() != checksum.lower():
            image.unlink(missing_ok=True)
            pytest.fail(f"Checksum mismatch for {distro} image {image}: expected {checksum}, got {digest.hexdigest()}")
    sha256 = hashlib.sha256()
    with image.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            sha256.update(block)
    return image, checksum, algorithm, sha256.hexdigest()


def _keypair(distro):
    directory = _external_sources() / "cloud-images" / "keys"
    directory.mkdir(parents=True, exist_ok=True)
    key = directory / f"{distro}-install-tests"
    with open(directory / f".{distro}.key.lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not key.exists():
            _checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], timeout=30)
    return key, Path(str(key) + ".pub")


def _quiet_config():
    return """#cloud-config
bootcmd:
  - |
    for unit in unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer motd-news.timer motd-news.service snapd.service snapd.socket snapd.seeded.service snapd.autoimport.service snapd.snap-repair.timer esm-cache.service ubuntu-advantage.timer ua-timer.service apt-news.service; do
      systemctl mask --runtime --now "$unit" >/dev/null 2>&1 || true
    done
package_update: true
packages:
""" + "".join(f"  - {package}\n" for package in GUEST_PACKAGES) + """write_files:
  - path: /etc/apt/apt.conf.d/99zaigr-cloudvm-no-auto
    permissions: '0644'
    content: |
      APT::Periodic::Update-Package-Lists "0";
      APT::Periodic::Unattended-Upgrade "0";
      Acquire::Retries "3";
  - path: /etc/apt/apt.conf.d/99zaigr-cloudvm-force-ipv4
    permissions: '0644'
    content: |
      Acquire::ForceIPv4 "true";
runcmd:
  - |
    for unit in unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer motd-news.timer motd-news.service snapd.service snapd.socket snapd.seeded.service snapd.autoimport.service snapd.snap-repair.timer esm-cache.service ubuntu-advantage.timer ua-timer.service apt-news.service; do
      systemctl mask --now "$unit" >/dev/null 2>&1 || true
    done
  - [mkdir, -p, /tmp/zaigr-home, /tmp/zaigr-project]
  - |
    touch /etc/subuid /etc/subgid
    for map in subuid subgid; do
      map_file="/etc/$map"
      if ! awk -F: '$1 == "user" && $3 >= 65536 { found = 1 } END { exit !found }' "$map_file"; then
        first=$(awk -F: 'BEGIN { first = 100000 } { start = $2; end = start + $3; if (start < first + 65536 && end > first) first = int((end + 65535) / 65536) * 65536 } END { print first }' "$map_file")
        last=$((first + 65535))
        if [ "$map" = subuid ]; then
          usermod --add-subuids "$first-$last" user
        else
          usermod --add-subgids "$first-$last" user
        fi
      fi
    done
  - |
    if command -v pro >/dev/null 2>&1; then
      pro disable esm-apps esm-infra || true
    fi
"""


def _write_seed(root, distro, public_key, user_data, unique):
    seed_dir = root / "seed"
    seed_dir.mkdir(parents=True, exist_ok=True)
    (seed_dir / "user-data").write_text(user_data.replace("@SSH_KEY@", public_key.read_text(encoding="utf-8").strip()), encoding="utf-8")
    (seed_dir / "meta-data").write_text(f"instance-id: zaigr-{distro}-{unique}\nlocal-hostname: zaigr-{distro.replace('.', '-')}-{unique[:8]}\n", encoding="utf-8")
    seed = root / "seed.iso"
    _checked(["cloud-localds", str(seed), str(seed_dir / "user-data"), str(seed_dir / "meta-data")], timeout=60)
    return seed


def _ssh_base(key, port):
    return ["ssh", "-i", str(key), "-p", str(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR", "user@127.0.0.1"]


def _wait_for_guest(key, port, qemu_pid, serial_log, timeout, stage):
    started = time.monotonic()
    last_output = ""
    while time.monotonic() - started < timeout:
        if not _pid_alive(qemu_pid):
            pytest.fail(f"QEMU exited while waiting for {stage}; serial log tail:\n{_tail(serial_log)}")
        try:
            stdout, stderr, rc = run(_ssh_base(key, port) + ["true"], timeout=12, context=f"cloudvm wait for SSH ({stage})")
            last_output = stdout + stderr
            if rc == 0:
                stdout, stderr, rc = run(_ssh_base(key, port) + ["sudo cloud-init status --wait"], timeout=1200, context=f"cloudvm wait for cloud-init ({stage})")
                if rc != 0:
                    diagnostic_script = (
                        "cloud-init status --long || true; "
                        "cloud-init schema --system || true; "
                        "cat /var/lib/cloud/data/status.json 2>/dev/null || true; "
                        "grep -i -C 3 'schema\\|warning\\|error' /var/log/cloud-init.log 2>/dev/null | tail -n 100 || true; "
                        "tail -n 100 /var/log/cloud-init-output.log 2>/dev/null || true"
                    )
                    diagnostic_command = "sudo sh -c " + shlex.quote(diagnostic_script)
                    diag_out, diag_err, diag_rc = run(
                        _ssh_base(key, port) + [diagnostic_command], timeout=45,
                        context=f"cloudvm collect cloud-init diagnostics ({stage})",
                    )
                    pytest.fail(
                        f"cloud-init did not finish during {stage} (status command exit {rc}):\n"
                        f"{err_msg(stdout, stderr)}\nGuest diagnostics (exit {diag_rc}):\n"
                        f"{err_msg(diag_out, diag_err)}\nserial log tail:\n{_tail(serial_log)}"
                    )
                return
        except subprocess.TimeoutExpired:
            last_output = "SSH readiness probe timed out"
        time.sleep(3)
    pytest.fail(f"Timed out after {timeout}s waiting for SSH/cloud-init during {stage}. Last probe: {last_output}\nserial log tail:\n{_tail(serial_log)}")


def _pid_alive(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()[2]
        if state in {"Z", "X"}:
            return False
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return False


def _tail(path, lines=100):
    try:
        return "".join(path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)[-lines:]) or "(serial log is empty)"
    except OSError as error:
        return f"(serial log unavailable: {error})"


def _preserve_logs_then_remove(work):
    log_root = _harness_root() / "logs" / work.name
    existing = [
        work / name
        for name in ("serial.log", "qemu.log", "guest-diagnostics.log")
        if (work / name).is_file()
    ]
    if existing:
        log_root.mkdir(parents=True, exist_ok=True)
        for source in existing:
            shutil.move(str(source), str(log_root / source.name))
        print(f"Cloud-VM logs retained: {log_root}")
    shutil.rmtree(work, ignore_errors=True)


def _start_qemu(distro, disk, seed, key, work, timeout=600):
    serial = work / "serial.log"
    qemu_log = work / "qemu.log"
    pidfile = work / "qemu.pid"
    port = None
    for _ in range(20):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            candidate = sock.getsockname()[1]
        command = [
            "qemu-system-x86_64", "-M", "q35", "-accel", "kvm", "-cpu", "host", "-smp", "4", "-m", "6144",
            "-display", "none", "-serial", f"file:{serial}", "-monitor", "none", "-daemonize", "-pidfile", str(pidfile), "-D", str(qemu_log),
            "-drive", f"file={disk},if=virtio,cache=none", "-drive", f"file={seed},media=cdrom,readonly=on",
            "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{candidate}-:22", "-device", "virtio-net-pci,netdev=n0",
        ]
        stdout, stderr, rc = run(command, timeout=30, context=f"cloudvm qemu boot ({distro})")
        if rc == 0:
            port = candidate
            break
        if "Address already in use" not in stdout + stderr:
            pytest.fail(f"Could not boot {distro} with QEMU:\n{err_msg(stdout, stderr)}\n{_tail(qemu_log)}")
    if port is None:
        pytest.fail("Could not reserve a local SSH forwarding port after 20 attempts")
    try:
        pid = int(pidfile.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        pytest.fail(f"QEMU returned success without a usable pid file: {pidfile}; log tail:\n{_tail(qemu_log)}")
    _LIVE_VMS.add((pid, str(disk), str(work)))
    try:
        _wait_for_guest(key, port, pid, serial, timeout, f"{distro} first boot")
    except BaseException:
        _stop_qemu(pid, disk, work)
        raise
    return pid, port, serial, qemu_log


def _stop_qemu(pid, disk, work, keep=False):
    if not _pid_alive(pid):
        _LIVE_VMS.discard((pid, str(disk), str(work)))
        return
    # Check the process identity before signaling a potentially recycled PID.
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        cmdline = ""
    if str(disk) not in cmdline and str(work) not in cmdline:
        pytest.fail(f"Refusing to signal PID {pid}: it no longer identifies this cloud VM")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 30
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.25)
    if _pid_alive(pid):
        os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 5
        while _pid_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
    _LIVE_VMS.discard((pid, str(disk), str(work)))


def _cleanup_live_vms():
    for pid, disk, work in list(_LIVE_VMS):
        try:
            _stop_qemu(pid, Path(disk), Path(work))
        except (OSError, pytest.fail.Exception) as error:
            print(f"Could not clean up cloud VM PID {pid}: {error}")


atexit.register(_cleanup_live_vms)


def _prepare_image(distro, image, official_checksum, checksum_algorithm, image_sha256, key, public_key):
    packages = " ".join(GUEST_PACKAGES)
    finalization_recipe = None
    if distro.startswith("debian-"):
        finalization_recipe = "cloud-init clean --logs --machine-id; install empty /etc/machine-id for systemd first boot"
    seed_template = _quiet_config() + "users:\n  - name: user\n    groups: [kvm, sudo]\n    shell: /bin/bash\n    sudo: 'ALL=(ALL) NOPASSWD:ALL'\n    ssh_authorized_keys:\n      - '@SSH_KEY@'\nssh_pwauth: false\n"
    actual_user_data = seed_template.replace("@SSH_KEY@", public_key.read_text(encoding="utf-8").strip())
    seed_unique = f"prepared-{distro}"
    metadata = f"instance-id: zaigr-{distro}-{seed_unique}\nlocal-hostname: zaigr-{distro.replace('.', '-')}-{seed_unique[:8]}\n"
    seed_hash = hashlib.sha256((actual_user_data + "\n" + metadata).encode()).hexdigest()
    cache_material = official_checksum + "\n" + packages + "\n" + seed_hash
    if finalization_recipe:
        cache_material += "\n" + finalization_recipe
    cache_key = hashlib.sha256(cache_material.encode()).hexdigest()
    cache_root = _external_sources() / "cloud-images" / "prepared" / distro / cache_key
    prepared = cache_root / "prepared.qcow2"
    cache_root.mkdir(parents=True, exist_ok=True)
    with open(cache_root.parent / f".{cache_key}.lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        metadata_path = cache_root / "metadata.json"
        expected_metadata = {
            "image_checksum": official_checksum,
            "image_checksum_algorithm": checksum_algorithm,
            "image_sha256": image_sha256,
            "packages": list(GUEST_PACKAGES),
            "seed_sha256": seed_hash,
        }
        if finalization_recipe:
            expected_metadata["finalization_recipe"] = finalization_recipe
        if prepared.is_file() and metadata_path.is_file():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata == expected_metadata:
                return prepared
            prepared.unlink(missing_ok=True)
        prep_root = _harness_root() / f"prepare-{distro}-{uuid.uuid4().hex}"
        prep_root.mkdir(parents=True)
        overlay = prep_root / "prepare.qcow2"
        _checked(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(overlay), "20G"], timeout=60)
        seed = _write_seed(prep_root, distro, public_key, seed_template, seed_unique)
        pid = None
        try:
            pid, port, serial, _qemu_log = _start_qemu(distro, overlay, seed, key, prep_root, timeout=900)
            finalize_command = "sudo cloud-init status --wait && sudo cloud-init clean --logs --machine-id"
            if finalization_recipe:
                finalize_command += " && sudo install -o root -g root -m 0444 /dev/null /etc/machine-id"
            command = _ssh_base(key, port) + [finalize_command]
            stdout, stderr, rc = run(command, timeout=1200, context=f"cloudvm prepare guest ({distro})")
            if rc != 0:
                pytest.fail(f"Could not finalize prepared {distro} image:\n{err_msg(stdout, stderr)}\nserial log tail:\n{_tail(serial)}")
            shutdown_command = _ssh_base(key, port) + ["sudo shutdown -h now"]
            stdout, stderr, rc = run(shutdown_command, timeout=30, context=f"cloudvm shutdown prepared guest ({distro})")
            if rc not in (0, 255):
                pytest.fail(f"Could not request shutdown for prepared {distro} image (exit {rc}):\n{err_msg(stdout, stderr)}\nserial log tail:\n{_tail(serial)}")
            deadline = time.monotonic() + 90
            while _pid_alive(pid) and time.monotonic() < deadline:
                time.sleep(0.5)
            if _pid_alive(pid):
                pytest.fail(
                    f"Prepared {distro} guest did not shut down naturally after `sudo shutdown -h now` "
                    f"(SSH exit {rc}); refusing to cache its image.\nserial log tail:\n{_tail(serial)}"
                )
            temporary = cache_root / f"prepared-{os.getpid()}.part.qcow2"
            _checked(["qemu-img", "convert", "-O", "qcow2", str(overlay), str(temporary)], timeout=1800)
            temporary.replace(prepared)
            metadata_path.write_text(json.dumps(expected_metadata, sort_keys=True) + "\n", encoding="utf-8")
        finally:
            if pid is not None:
                _stop_qemu(pid, overlay, prep_root)
            if os.environ.get(KEEP_ENV) == "1":
                print(f"Keeping cloud VM preparation artifacts: {prep_root}")
            else:
                _preserve_logs_then_remove(prep_root)
    return prepared


def _select_artifact(standalone):
    """Select and validate the requested release artifact before VM setup."""
    if standalone:
        artifact = Path(
            os.environ.get("ZAIGR_TEST_BINARY") or (Path(REPO_ROOT) / "release" / "dist" / "zaigr")
        ).expanduser().resolve()
        if not artifact.is_file():
            pytest.fail(f"Standalone binary not found: {artifact}; create a release candidate or set ZAIGR_TEST_BINARY")
        return artifact, artifact.name, "", ""

    deb_override = os.environ.get("ZAIGR_TEST_DEB")
    if deb_override:
        packages = [Path(deb_override).expanduser().resolve()]
    else:
        packages = sorted((Path(REPO_ROOT) / "release" / "dist").glob("zaigr_*.deb"))
    if len(packages) != 1:
        pytest.fail(f"Expected exactly one release/dist/*.deb artifact, found {len(packages)}")
    artifact = packages[0]
    if not artifact.is_file():
        pytest.fail(f"Debian package artifact not found: {artifact}")
    name = artifact.name
    try:
        fields = subprocess.run(
            ["dpkg-deb", "-f", str(artifact), "Package", "Version", "Architecture"],
            check=True, capture_output=True, text=True, timeout=15,
        ).stdout.splitlines()
    except (OSError, subprocess.SubprocessError) as error:
        pytest.fail(f"Could not inspect Debian package metadata for {artifact}: {error}")
    metadata = dict(line.split(":", 1) for line in fields if ":" in line)
    metadata = {key: value.strip() for key, value in metadata.items()}
    if metadata.get("Package") != "zaigr" or metadata.get("Architecture") != "amd64" or not metadata.get("Version"):
        pytest.fail(f"Unexpected Debian package metadata for {artifact}: {fields}")
    try:
        version, build = metadata["Version"].rsplit("-", 1)
    except ValueError:
        pytest.fail(f"Unexpected Debian package Version: {metadata['Version']}")
    if not version or not build.isdigit():
        pytest.fail(f"Unexpected Debian package Version: {metadata['Version']}; expected <version>-<build>")
    return artifact, name, version, build


def _artifact_provenance(standalone, selection=None):
    artifact, package_name, package_version, package_build = selection or _select_artifact(standalone)
    digest = hashlib.sha256()
    with artifact.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    details = [f"path={artifact}", f"sha256:{digest.hexdigest()}"]

    if standalone:
        try:
            output = subprocess.run(
                [str(artifact), "misc", "full-version"],
                check=True, capture_output=True, text=True, timeout=15,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            output = ""
        version_fields = dict(
            line.split(":", 1) for line in output.splitlines() if ":" in line
        )
        for label in ("version", "build", "commit"):
            value = version_fields.get(label)
            details.append(f"{label}={value.strip() if value else 'unavailable'}")
    else:
        details.extend((f"package={package_name}", f"version={package_version}", f"build={package_build}"))
        details.append(f"deb-version={package_version}-{package_build}")
    return "; ".join(details)


class CloudVM:
    def __init__(self, distro, standalone=False):
        self.distro = distro
        self.dist_artifact, self.package_name, self.package_version, self.package_build = _select_artifact(standalone)
        self.artifact_provenance = _artifact_provenance(
            standalone,
            (self.dist_artifact, self.package_name, self.package_version, self.package_build),
        )
        print(f"Selected install artifact: {self.artifact_provenance}", flush=True)
        self.image_path, self.image_checksum, self.image_checksum_algorithm, self.image_sha256 = _image(distro)
        print(
            f"Verified cloud image {distro}: sha256:{self.image_sha256}; "
            f"official {self.image_checksum_algorithm}:{self.image_checksum}",
            flush=True,
        )
        self.key_path, public_key = _keypair(distro)
        self.prepared_image = _prepare_image(distro, self.image_path, self.image_checksum, self.image_checksum_algorithm, self.image_sha256, self.key_path, public_key)
        self.workdir = _harness_root() / f"{distro}-{uuid.uuid4().hex}"
        self.workdir.mkdir(parents=True)
        self.overlay = self.workdir / "disk.qcow2"
        _checked(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(self.prepared_image), str(self.overlay)], timeout=60)
        self.seed = _write_seed(self.workdir, distro, public_key, """#cloud-config
users:
  - name: user
    groups: [kvm, sudo]
    shell: /bin/bash
    sudo: 'ALL=(ALL) NOPASSWD:ALL'
    ssh_authorized_keys:
      - '@SSH_KEY@'
ssh_pwauth: false
""", uuid.uuid4().hex)
        try:
            self.pid, self.port, self.serial_log, self.qemu_log = _start_qemu(distro, self.overlay, self.seed, self.key_path, self.workdir)
        except BaseException:
            if os.environ.get(KEEP_ENV) == "1":
                print(f"Keeping cloud VM startup artifacts: {self.workdir}")
            else:
                _preserve_logs_then_remove(self.workdir)
            raise
        self.ssh = _ssh_base(self.key_path, self.port)
        try:
            if standalone:
                self.copy(self.dist_artifact, "/dist/zaigr")
            else:
                self.copy(self.dist_artifact, "/dist/" + self.package_name)
        except BaseException:
            self.close()
            raise

    def _remote_command(self, command, cwd=None, env=None, user=None):
        account = "root" if user is None else str(user)
        home = "/root" if account == "root" else ("/home/user" if account == "user" else None)
        vars = {"HOME": home or "/tmp", **(env or {})}
        body = []
        if cwd:
            body.append("cd " + shlex.quote(str(cwd)))
        body.append(str(command))
        shell = " && ".join(body)
        env_args = ["env"] + [f"{name}={value}" for name, value in vars.items()]
        if account == "root":
            prefix = ["sudo", "-H", "-u", "root", "--"]
        elif account == "user":
            prefix = []
        elif ":" in account and all(piece.isdigit() for piece in account.split(":", 1)):
            uid, gid = account.split(":", 1)
            prefix = ["sudo", "-u", f"#{uid}", "-g", f"#{gid}", "--"]
        else:
            prefix = ["sudo", "-u", account, "--"]
        return shlex.join(prefix + env_args + ["bash", "-c", shell])

    def run(self, command, cwd=None, env=None, timeout=120, user=None, input=None):
        remote = self._remote_command(command, cwd=cwd, env=env, user=user)
        try:
            return run(self.ssh + [remote], timeout=timeout, input=input, context=f"cloudvm {self.distro} image sha256:{self.image_sha256}")
        except subprocess.TimeoutExpired:
            pytest.fail(f"Timed out after {timeout}s running in {self.distro}: {command}\nserial log tail:\n{_tail(self.serial_log)}")

    def zaigr_path_without_host_tools(self, user="user"):
        """Prepare a product PATH without host SSH or privilege helper tools."""
        path = "/tmp/zaigr-product-path-" + uuid.uuid4().hex
        setup = (
            "set -eu; restricted=" + shlex.quote(path) + "; mkdir -m 0755 \"$restricted\"; "
            "for directory in /home/user/.local/bin /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do "
            "[ -d \"$directory\" ] || continue; for executable in \"$directory\"/*; do "
            "[ -x \"$executable\" ] || continue; name=${executable##*/}; "
            "case \"$name\" in ssh|ssh-keygen|truncate|setpriv|unshare|slirp4netns) continue;; esac; "
            "ln -s \"$executable\" \"$restricted/$name\" 2>/dev/null || true; done; done; "
            "for tool in ssh ssh-keygen truncate setpriv; do "
            "if PATH=\"$restricted\" command -v \"$tool\" >/dev/null 2>&1; then "
            "printf 'unexpected product host tool: %s\\n' \"$tool\" >&2; exit 1; fi; done; "
            "printf '%s\\n' \"$restricted\""
        )
        stdout, stderr, rc = self.run(setup, timeout=45, user=user)
        assert rc == 0, f"could not prepare restricted product PATH:\n{stdout}{stderr}"
        restricted_path = stdout.strip()
        assert restricted_path == path
        return restricted_path

    def ssh_command(self, command="bash -l", timeout=120, user=None, cwd=None, env=None):
        """Run a raw interactive SSH command for tests that explicitly need a live shell."""
        remote = self._remote_command(command, cwd=cwd, env=env, user=user)
        ssh = self.ssh[:-1] + ["-tt", self.ssh[-1], remote]
        return spawn_interactive(shlex.join(ssh), timeout=timeout)

    def copy(self, local, remote):
        local = Path(local).resolve()
        self.run("mkdir -p " + shlex.quote(str(Path(remote).parent)), user="root", timeout=30)
        temporary = "/tmp/zaigr-cloudvm-copy-" + uuid.uuid4().hex
        destination = "user@127.0.0.1:" + temporary
        command = ["scp", "-q", "-i", str(self.key_path), "-P", str(self.port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", str(local), destination]
        stdout, stderr, rc = run(command, timeout=180, context=f"cloudvm artifact copy ({self.distro})")
        if rc != 0:
            pytest.fail(f"Could not copy {local} into {self.distro}:\n{err_msg(stdout, stderr)}\nserial log tail:\n{_tail(self.serial_log)}")
        stdout, stderr, rc = self.run(f"install -m 0644 {shlex.quote(temporary)} {shlex.quote(str(remote))} && rm -f {shlex.quote(temporary)}", user="root", timeout=30)
        if rc != 0:
            pytest.fail(f"Could not install copied artifact at {remote} in {self.distro}:\n{err_msg(stdout, stderr)}\nserial log tail:\n{_tail(self.serial_log)}")

    def collect_failure_diagnostics(self):
        """Save bounded guest process, kernel, and product-log context on failure."""
        if not _pid_alive(self.pid):
            return "guest is already stopped; only serial/QEMU logs are available"
        script = r"""
set +e
printf '%s\n' '=== processes ==='
ps -eo pid,ppid,stat,etime,comm --sort=-etime
printf '%s\n' '=== listening TCP sockets ==='
ss -ltnp
printf '%s\n' '=== project process cgroups ==='
for pid in $(ps -eo pid=,comm= | awk '$2 ~ /^(zaigr|qemu-system-x86.*|virtiofsd|slirp4netns)$/ {print $1}'); do
  printf '\n--- pid %s ---\n' "$pid"
  cat "/proc/$pid/cgroup" 2>&1
done
printf '%s\n' '=== kernel journal tail ==='
journalctl -k -n 100 --no-pager
for base in /home/user/.zaigr /home/uid-host/.zaigr /tmp/zaigr-home/.zaigr; do
  [ -d "$base" ] || continue
  printf '=== product log tails under %s ===\n' "$base"
  find "$base" -type f -name '*.log' -printf '%T@ %p\n' 2>/dev/null \
    | sort -rn | head -n 12 | cut -d' ' -f2- \
    | while IFS= read -r logfile; do
        printf '\n--- %s ---\n' "$logfile"
        tail -n 80 "$logfile" 2>&1
      done
done
"""
        command = "sudo sh -c " + shlex.quote(script)
        diagnostics_started = time.monotonic()
        try:
            stdout, stderr, rc = run(
                self.ssh + [command], timeout=16,
                context=f"cloudvm collect failure diagnostics ({self.distro})",
            )
            content = f"diagnostic command exit: {rc}\n{stdout}\n{stderr}"
        except subprocess.TimeoutExpired as error:
            content = f"diagnostic command timed out after 16 seconds\n{error.stdout or ''}\n{error.stderr or ''}"
        except OSError as error:
            content = f"could not collect guest diagnostics: {error}\n"

        path = self.workdir / "guest-diagnostics.log"
        try:
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
        except OSError as error:
            return f"could not save guest diagnostics before SSH probe ({error})"

        # Use the public CLI for failure-only nested-VM observations. The two
        # known project directories cover the install acceptance workflows;
        # neither probe runs on the success path. Keep the guest command and
        # firewall status query within the remaining diagnostic time budget.
        probe_script = r"""
set +e
product=/home/user/.local/bin/zaigr
[ -x "$product" ] || product=/usr/bin/zaigr
for project in /home/user/project /home/user/zaigr-install-project; do
  [ -x "$product" ] && [ -d "$project" ] || continue
  printf '=== public project vm exec from %s ===\n' "$project"
  cd "$project" || continue
  printf '%s\n' '=== public project firewall show ==='
  timeout 2s "$product" project firewall show 2>&1
  printf 'project firewall show exit: %s\n' "$?"
  timeout 6s "$product" project vm exec -- sh -c \
    'echo "--- guest addresses ---"; ip -brief address; echo "--- guest routes ---"; ip route; echo "--- resolver ---"; cat /etc/resolv.conf; echo "--- deb.debian.org lookup ---"; timeout 2s getent ahostsv4 deb.debian.org; echo "--- guest TCP sockets ---"; ss -tnpi' 2>&1
  printf 'project vm exec exit: %s\n' "$?"
  exit 0
done
printf '%s\n' 'no known install-test project directory is available for public CLI diagnostics'
"""
        try:
            probe_timeout = max(0.1, min(9, 25 - (time.monotonic() - diagnostics_started)))
            probe_out, probe_err, probe_rc = run(
                self.ssh + ["sh -c " + shlex.quote(probe_script)],
                timeout=probe_timeout,
                context=f"cloudvm probe public project CLI ({self.distro})",
            )
            content += f"\n=== public project CLI diagnostics (outer exit {probe_rc}) ===\n{probe_out}\n{probe_err}"
        except subprocess.TimeoutExpired as error:
            content += f"\n=== public project CLI diagnostics timed out after {probe_timeout:.1f} seconds ===\n{error.stdout or ''}\n{error.stderr or ''}"
        except OSError as error:
            content += f"\n=== public project CLI diagnostics unavailable ===\n{error}\n"
        try:
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
        except OSError as error:
            return f"could not save guest diagnostics ({error})"
        if os.environ.get(KEEP_ENV) == "1":
            retained_path = path
        else:
            retained_path = _harness_root() / "logs" / self.workdir.name / path.name
        return f"guest diagnostics saved to {retained_path}"

    def close(self):
        try:
            self.run("shutdown -h now", user="root", timeout=15)
        except (pytest.fail.Exception, subprocess.SubprocessError):
            pass
        deadline = time.monotonic() + 30
        while _pid_alive(self.pid) and time.monotonic() < deadline:
            time.sleep(0.25)
        _stop_qemu(self.pid, self.overlay, self.workdir)
        if os.environ.get(KEEP_ENV) == "1":
            print(f"Keeping cloud VM artifacts: {self.workdir}\nserial log: {self.serial_log}\nQEMU log: {self.qemu_log}")
        else:
            _preserve_logs_then_remove(self.workdir)


@pytest.fixture
def cloudvm_factory(request):
    _prerequisites()
    vms = []

    def factory(distro, standalone=False):
        if distro not in DISTROS:
            pytest.fail(f"Unknown cloud distro {distro!r}; choose from: {', '.join(DISTROS)}")
        vm = CloudVM(distro, standalone=standalone)
        vms.append(vm)
        node_vms = getattr(request.node, "_cloudvms", [])
        node_vms.append(vm)
        request.node._cloudvms = node_vms
        images = getattr(request.node, "_cloudvm_images", {})
        images[distro] = vm.image_sha256
        request.node._cloudvm_images = images
        request.node.user_properties.append((f"cloudvm_image_sha256_{distro}", vm.image_sha256))
        artifacts = getattr(request.node, "_cloudvm_artifacts", {})
        artifacts[distro] = vm.artifact_provenance
        request.node._cloudvm_artifacts = artifacts
        return vm

    yield factory
    for vm in reversed(vms):
        vm.close()
