"""Small Linux resource snapshots shared by the stress acceptance tests.

The leak threshold treats growth as actionable only when post-warmup median RSS
exceeds both 32 MiB and 25% of its baseline and rises across the late samples;
FD growth must exceed baseline by four in at least three late samples.
"""

import json
import os
import shutil
import signal
import statistics
import subprocess
from pathlib import Path


def _proc_stat(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = text[text.rfind(")") + 2 :].split()
        return fields
    except (OSError, IndexError):
        return None


def _process_sample(pid, role):
    fields = _proc_stat(pid)
    if not fields:
        return None
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        rss = next(
            int(line.split()[1]) for line in status.splitlines()
            if line.startswith("VmRSS:")
        )
        fd_count = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        exe = os.stat(f"/proc/{pid}/exe")
    except (OSError, StopIteration, ValueError):
        return None
    return {
        "pid": int(pid),
        "start_time": fields[19],
        "role": role,
        "rss_kib": rss,
        "fd_count": fd_count,
        "exe_device": exe.st_dev,
        "exe_inode": exe.st_ino,
    }


def _read_supervisor(store_path):
    path = store_path / "vm-supervisor.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _owned_processes(record):
    if not record:
        return {}
    result = {}
    for name in (
        "supervisor", "qemu", "workspace_daemon", "agent_state_daemon",
        "workspace_descendant", "agent_state_descendant", "ssh_broker",
    ):
        if record.get(name):
            result[name] = record[name]
    result.update({f"network:{name}": item for name, item in record.get("network_processes", {}).items()})
    return result


def _process_mount_refs(paths):
    refs = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            lines = (entry / "mountinfo").read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            if any(path and path in line for path in paths):
                refs.append(int(entry.name))
                break
    return refs


def _netns_refs(namespace_ids):
    if not namespace_ids:
        return []
    refs = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            namespace = os.readlink(entry / "ns/net")
        except OSError:
            continue
        if namespace in namespace_ids:
            refs.append(int(entry.name))
            continue
        try:
            for fd in (entry / "fd").iterdir():
                if os.readlink(fd) in namespace_ids:
                    refs.append(int(entry.name))
                    break
        except OSError:
            continue
    for directory in (Path("/run/netns"), Path("/var/run/netns")):
        try:
            names = list(directory.iterdir())
        except OSError:
            continue
        for path in names:
            try:
                inode = path.stat().st_ino
                if any(namespace.endswith(f"[{inode}]") for namespace in namespace_ids):
                    refs.append(f"named:{path}")
            except OSError:
                continue
    return refs


def _directory_size(path):
    total = 0
    try:
        for current, _, filenames in os.walk(path):
            for filename in filenames:
                try:
                    total += (Path(current) / filename).lstat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _network_namespace_inventory(record):
    """Read the private helper namespace without retaining an fd or reference."""
    helper = record.get("network_processes", {}).get("hostnet-helper") if record else None
    if not helper:
        return None
    pid = str(helper["pid"])
    ip_command = [
        "nsenter", "--preserve-credentials", "--target", pid, "--user", "--net",
        "--", "ip", "-j", "link", "show",
    ]
    ip_result = subprocess.run(
        ip_command, check=False, capture_output=True, text=True, timeout=15
    )
    assert ip_result.returncode == 0, (
        f"read-only network interface inventory failed for helper pid {pid}: "
        f"rc={ip_result.returncode}; stderr={ip_result.stderr.strip()}"
    )
    try:
        links = json.loads(ip_result.stdout)
    except ValueError as exc:
        raise AssertionError(f"invalid JSON from read-only namespace inventory: {ip_command}") from exc

    nft_command = [
        "nsenter", "--preserve-credentials", "--target", pid, "--user", "--net",
        "--", "nft", "--terse", "list", "tables",
    ]
    nft_result = subprocess.run(
        nft_command, check=False, capture_output=True, text=True, timeout=15
    )
    nft_inventory_error = None
    if nft_result.returncode == 0:
        nft_tables = sorted(
            (parts[1], parts[2])
            for line in nft_result.stdout.splitlines()
            if len(parts := line.split()) == 3 and parts[0] == "table"
        )
        assert ("inet", "zaigr") in nft_tables, nft_tables
    elif (
        nft_result.returncode == -signal.SIGABRT
        and "netlink_delinearize.c:126" in nft_result.stderr
        and "consumed > 0" in nft_result.stderr
        and "failed" in nft_result.stderr
    ):
        # Old Debian nftables aborts while parsing this namespace's ruleset; namespace teardown
        # below remains the authoritative proof that its tables and links were destroyed.
        nft_tables = None
        nft_inventory_error = nft_result.stderr.strip()
    else:
        raise AssertionError(
            f"read-only nft table inventory failed for helper pid {pid}: "
            f"rc={nft_result.returncode}; stderr={nft_result.stderr.strip()}"
        )

    interface_names = sorted(item.get("ifname") for item in links if item.get("ifname"))
    assert {"zgr_gst", "zgr_mnt"}.issubset(interface_names), interface_names
    return {
        "target_pid": int(pid),
        "namespace_id": os.readlink(f"/proc/{pid}/ns/net"),
        "interfaces": interface_names,
        "nft_tables": nft_tables,
        "nft_inventory_error": nft_inventory_error,
    }


def sample_resources(projects, include_network_inventory=False):
    """Capture machine and per-project managed-process/resource metadata."""
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        boot_id = None
    disk = shutil.disk_usage(Path.home())
    project_samples = []
    namespace_ids = set()
    proc_entries = [entry.name for entry in Path("/proc").iterdir() if entry.name.isdecimal()]

    for project in projects:
        store_path = Path(project.store_dir).resolve()
        workspace_path = Path(project.cwd).resolve()
        record = _read_supervisor(store_path)
        roles = {}
        for role, identity in _owned_processes(record).items():
            pid = identity.get("pid")
            if pid:
                roles[int(pid)] = role
        processes = []
        project_namespace_ids = set()
        owned = _owned_processes(record)
        expected_by_pid = {item["pid"]: item for item in owned.values()}
        network_inventory = _network_namespace_inventory(record) if include_network_inventory else None
        for pid in set(proc_entries) | {str(pid) for pid in roles}:
            numeric_pid = int(pid)
            role = roles.get(numeric_pid)
            paths = [str(workspace_path), str(store_path)]
            if record:
                paths.extend(value for value in (record.get("runtime_dir"), record.get("socket_dir")) if value)
            if role is None and _process_references_paths(paths, pid):
                role = "unrecorded-orphan-candidate"
            if role is None:
                continue
            sample = _process_sample(pid, role)
            expected = expected_by_pid.get(numeric_pid)
            if expected:
                fields = _proc_stat(pid)
                if fields and fields[19] == str(expected.get("start_time")):
                    assert sample, (
                        f"cannot read /proc resource data for live recorded process "
                        f"{role} pid={pid}; run the stress suite with readable /proc"
                    )
            if sample:
                if expected:
                    sample["recorded_start_time"] = str(expected.get("start_time"))
                    assert sample["start_time"] == str(expected.get("start_time")), sample
                    assert sample["exe_device"] == expected.get("exe_device"), sample
                    assert sample["exe_inode"] == expected.get("exe_inode"), sample
                    sample["identity_matches"] = True
                processes.append(sample)
                try:
                    namespace = os.readlink(f"/proc/{pid}/ns/net")
                    if namespace != os.readlink("/proc/self/ns/net"):
                        namespace_ids.add(namespace)
                        project_namespace_ids.add(namespace)
                except OSError:
                    pass
        project_samples.append({
            "workspace": str(workspace_path),
            "store": str(store_path),
            "store_bytes": _directory_size(store_path),
            "runtime_dir": record.get("runtime_dir") if record else None,
            "socket_dir": record.get("socket_dir") if record else None,
            "launch_id": record.get("launch_id") if record else None,
            "processes": processes,
            "namespace_ids": sorted(project_namespace_ids),
            "network_inventory": network_inventory,
            "mount_refs": _process_mount_refs([
                str(value) for value in (record.get("runtime_dir"), record.get("socket_dir"))
                if value
            ] if record else []),
        })
    return {
        "boot_id": boot_id,
        "disk_free_bytes": disk.free,
        "disk_total_bytes": disk.total,
        "namespace_ids": sorted(namespace_ids),
        "namespace_refs": _netns_refs(namespace_ids),
        "projects": project_samples,
    }


def assert_stopped_resources_gone(samples):
    """Require the final chronological snapshot to be stopped and fully cleaned."""
    assert samples, "resource cleanup requires at least one snapshot"
    after = samples[-1]
    count = len(after["projects"])
    for index, current in enumerate(after["projects"]):
        old_project = next((
            snapshot["projects"][index]
            for snapshot in reversed(samples[:-1])
            if len(snapshot["projects"]) == count and snapshot["projects"][index]["processes"]
        ), current)
        identities = {}
        old_namespaces = set()
        inventories = []
        for snapshot in samples[:-1]:
            for proc in snapshot["projects"][index]["processes"]:
                identities[(proc["pid"], proc["start_time"])] = proc["role"]
            old_namespaces.update(snapshot["projects"][index]["namespace_ids"])
            inventory = snapshot["projects"][index].get("network_inventory")
            if inventory:
                inventories.append(inventory)
        workspace = old_project["workspace"]
        live = []
        for (pid, start_time), role in identities.items():
            fields = _proc_stat(pid)
            if fields and fields[19] == start_time:
                live.append((role, pid, start_time))
        paths = [old_project["workspace"], old_project["store"]]
        paths.extend(path for path in (old_project["runtime_dir"], old_project["socket_dir"]) if path)
        for entry in Path("/proc").iterdir():
            if entry.name.isdecimal() and _process_references_paths(paths, entry.name):
                fields = _proc_stat(entry.name)
                if fields:
                    live.append(("path-matched-orphan", int(entry.name), fields[19]))
        assert not live, f"processes remain for stopped project {workspace}: {live}"
        for path in (old_project["runtime_dir"], old_project["socket_dir"]):
            if path:
                assert not Path(path).exists(), f"stopped VM path remains: {path}"
        assert not _process_mount_refs(paths), f"mount references remain for stopped project {workspace}"
        assert not current["processes"], current
        if old_namespaces:
            assert inventories, (
                f"private network namespace inventory was not captured for stopped project {workspace}"
            )
            refs = _netns_refs(old_namespaces)
            assert not refs, f"stopped VM network namespaces remain referenced by PIDs: {refs}"


def _process_references_paths(paths, pid):
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        cwd = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return False
    return any(path and (path in cmdline or cwd == path or cwd.startswith(path + os.sep)) for path in paths)


def summarize_samples(name, samples, timings, iterations, extra=None):
    """Print machine-readable run and resource summary, returning the same data."""
    processes = {}
    for snapshot in samples:
        for project in snapshot["projects"]:
            for proc in project["processes"]:
                key = (proc["pid"], proc["start_time"], proc["role"])
                processes.setdefault(key, []).append(proc)
    growth = []
    for (pid, start, role), observations in processes.items():
        rss = [item["rss_kib"] for item in observations]
        fds = [item["fd_count"] for item in observations]
        growth.append({
            "pid": pid,
            "start_time": start,
            "role": role,
            "samples": len(observations),
            "rss_first_kib": rss[0],
            "rss_max_kib": max(rss),
            "rss_peak_growth_kib": max(rss) - rss[0],
            "rss_late_median_kib": int(statistics.median(rss[2:])) if len(rss) > 2 else rss[-1],
            "fd_first": fds[0],
            "fd_max": max(fds),
            "fd_late_median": int(statistics.median(fds[2:])) if len(fds) > 2 else fds[-1],
        })
    ordered = sorted(timings)
    summary = {
        "scenario": name,
        "iterations": iterations,
        "timing_seconds_median": statistics.median(ordered) if ordered else None,
        "timing_seconds_worst": max(ordered) if ordered else None,
        "sample_count": len(samples),
        "boot_ids": sorted({snapshot["boot_id"] for snapshot in samples if snapshot["boot_id"]}),
        "disk_free_bytes": [snapshot["disk_free_bytes"] for snapshot in samples],
        "store_bytes": [project["store_bytes"] for snapshot in samples for project in snapshot["projects"]],
        "network_inventory": [
            project["network_inventory"]
            for snapshot in samples
            for project in snapshot["projects"]
            if project.get("network_inventory")
        ],
        "process_resources": growth,
    }
    if extra:
        summary.update(extra)
    print("STRESS_SUMMARY " + json.dumps(summary, sort_keys=True))
    return summary


def assert_resource_growth_bounded(samples):
    """Fail only on repeated late growth in an unchanged managed process."""
    observations = {}
    for snapshot in samples:
        for project in snapshot["projects"]:
            for proc in project["processes"]:
                if (
                    proc["role"] in {"unrecorded-orphan-candidate", "qemu"}
                    or not proc.get("identity_matches", True)
                ):
                    continue
                observations.setdefault((proc["pid"], proc["start_time"], proc["role"]), []).append(proc)
    for key, readings in observations.items():
        if len(readings) < 5:
            continue
        baseline = readings[1]
        late = readings[2:]
        rss_late = [item["rss_kib"] for item in late]
        rss_growth = int(statistics.median(rss_late)) - baseline["rss_kib"]
        rss_limit = max(32 * 1024, int(baseline["rss_kib"] * 0.25))
        assert not (rss_growth > rss_limit and rss_late[-1] > rss_late[0]), (
            f"sustained RSS growth for {key}: baseline={baseline['rss_kib']} KiB, "
            f"late={rss_late}, growth={rss_growth} KiB, limit={rss_limit} KiB"
        )
        fd_baseline = baseline["fd_count"]
        late_fds = [item["fd_count"] for item in late]
        assert not (sum(value > fd_baseline + 4 for value in late_fds) >= 3), (
            f"sustained FD growth for {key}: baseline={fd_baseline}, late={late_fds}"
        )
