"""Long workspace, multi-project, and resource-pressure stress workloads."""

import concurrent.futures
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from ..conftest import err_msg
from ..conftest import run as _run
from .stress_resources import (
    assert_resource_growth_bounded,
    assert_stopped_resources_gone,
    sample_resources,
    summarize_samples,
)


def _tiny_mode():
    return os.environ.get("ZAIGR_STRESS_TINY") == "1"


def _command(project, command, env=None, **kwargs):
    stdout, stderr, rc = _run(
        command,
        cwd=project.cwd,
        env=env if env is not None else project.env,
        **kwargs,
    )
    return stdout, stderr, rc


def _checked(project, command, env=None, **kwargs):
    stdout, stderr, rc = _command(project, command, env=env, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _settled_samples(projects, count=5, delay=2):
    samples = []
    for index in range(count):
        samples.append(sample_resources(projects))
        if index + 1 < count:
            time.sleep(delay)
    return samples


def _make_project_env(project, disk="8G", ram="512", cpu="1"):
    env = project.env
    env.update(
        {
            "ZAIGR_DISK_SIZE": disk,
            "ZAIGR_VM_RAM": ram,
            "ZAIGR_VM_CPU": cpu,
        }
    )
    return env


def _add_summary_finalizer(request, record_property, name, samples, state):
    def emit_summary():
        summary = summarize_samples(
            name,
            samples,
            state["timings"],
            state["iterations"],
            extra=state["extra"],
        )
        record_property("stress_summary", json.dumps(summary))

    request.addfinalizer(emit_summary)


@pytest.mark.stress
@pytest.mark.timeout(7200)
def test_stress_several_projects_exec_and_global_rebuild(
    project_factory, record_property, request
):
    """Four busy projects keep their workspaces isolated through batch rebuild."""
    tiny = _tiny_mode()
    duration = 3 if tiny else 600
    projects = [
        project_factory(f"stress-multiproject-{index}") for index in range(1, 5)
    ]
    envs = [_make_project_env(project) for project in projects]
    zaigr = projects[0].zaigr_bin
    samples = [sample_resources(projects)]
    starts = []
    timings = []
    summary_state = {
        "timings": timings,
        "iterations": 0,
        "extra": {"project_count": 4, "ram_mib_each": 512, "tiny_mode": tiny},
    }
    _add_summary_finalizer(
        request, record_property, "several-projects", samples, summary_state
    )

    for project, env in zip(projects, envs):
        start_began = time.monotonic()
        start_output = _checked(
            project,
            [zaigr, "project", "vm", "start", "--ram", "512", "--cpu", "1"],
            env=env,
            input="y\n",
            timeout=240,
        )
        assert "the vm stopped" not in start_output.lower(), start_output
        starts.append(time.monotonic() - start_began)
        samples.append(sample_resources(projects))

    outputs = [[] for _ in projects]
    exec_samples = [sample_resources(projects)]
    samples.append(exec_samples[-1])
    next_resource_sample = time.monotonic()
    for project, env in zip(projects, envs):
        _checked(
            project,
            [
                zaigr,
                "project",
                "vm",
                "exec",
                "--",
                "rm",
                "-f",
                "/home/user/workspace/stress-exec-loop.txt",
            ],
            env=env,
            timeout=60,
        )
    exec_started = time.monotonic()
    exec_deadline = exec_started + duration
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        while (tiny and len(outputs[0]) < 3) or (
            not tiny and time.monotonic() < exec_deadline
        ):
            pending = []
            for index, (project, env) in enumerate(zip(projects, envs)):
                label = project.cwd.name
                iteration = len(outputs[index])
                command = [
                    zaigr,
                    "project",
                    "vm",
                    "exec",
                    "--",
                    "bash",
                    "-c",
                    f"printf '%s\\n' '{label}:{iteration}' | tee -a /home/user/workspace/stress-exec-loop.txt",
                ]
                pending.append(
                    (
                        index,
                        label,
                        iteration,
                        executor.submit(
                            _checked, project, command, env=env, timeout=90
                        ),
                    )
                )
            for index, label, iteration, future in pending:
                output = future.result()
                assert output.rstrip("\n") == f"{label}:{iteration}", output
                outputs[index].append(f"{label}:{iteration}")
            summary_state["iterations"] = sum(len(items) for items in outputs)
            summary_state["extra"]["exec_iterations_by_project"] = {
                project.cwd.name: len(items)
                for project, items in zip(projects, outputs)
            }
            if tiny or time.monotonic() >= next_resource_sample:
                exec_samples.append(sample_resources(projects))
                samples.append(exec_samples[-1])
                next_resource_sample = time.monotonic() + 30
            if not tiny and time.monotonic() < exec_deadline:
                time.sleep(1)
    exec_seconds = time.monotonic() - exec_started
    timings.extend([exec_seconds] * len(projects))
    assert_resource_growth_bounded(exec_samples)
    for project, iterations in zip(projects, outputs):
        label = project.cwd.name
        assert iterations, f"no public exec iterations completed for {label}"
        assert iterations == [f"{label}:{index}" for index in range(len(iterations))]

    # Leave exactly two VMs running for the public --all batch-rebuild path.
    partial_stop_before = sample_resources(projects[2:], include_network_inventory=True)
    samples.append(sample_resources(projects, include_network_inventory=True))
    for project, env in zip(projects[2:], envs[2:]):
        stop_output = _checked(
            project, [zaigr, "project", "vm", "stop"], env=env, timeout=90
        )
        assert "stop reason" not in stop_output.lower(), stop_output
        samples.append(sample_resources(projects))
    partial_stop_after = sample_resources(projects[2:])
    assert_stopped_resources_gone([partial_stop_before, partial_stop_after])

    rebuild_started = time.monotonic()
    rebuild_before = sample_resources(projects, include_network_inventory=True)
    rebuild_output = _checked(
        projects[0],
        [zaigr, "global", "projects", "rebuild", "--all", "--yes"],
        env=envs[0],
        timeout=1200,
    )
    rebuild_seconds = time.monotonic() - rebuild_started
    assert "4 projects selected; 4 eligible, 0 skipped." in rebuild_output, (
        rebuild_output
    )
    assert rebuild_output.count(": rebuilt, VM off") == 4, rebuild_output
    samples.append(sample_resources(projects))
    assert_stopped_resources_gone([rebuild_before, samples[-1]])

    # Reboot each rebuilt image and prove its own loop output survived intact.
    for project, env, expected in zip(projects, envs, outputs):
        start_began = time.monotonic()
        start_output = _checked(
            project,
            [zaigr, "project", "vm", "start", "--ram", "512", "--cpu", "1"],
            env=env,
            input="y\n",
            timeout=240,
        )
        assert "the vm stopped" not in start_output.lower(), start_output
        starts.append(time.monotonic() - start_began)
        samples.append(sample_resources(projects))
        readback = _checked(
            project,
            [
                zaigr,
                "project",
                "vm",
                "exec",
                "--",
                "cat",
                "/home/user/workspace/stress-exec-loop.txt",
            ],
            env=env,
            timeout=60,
        ).splitlines()
        assert readback == expected, (
            f"workspace output crossed projects at {project.cwd}"
        )
    samples.extend(_settled_samples(projects))
    settled = samples[-5:]
    assert_resource_growth_bounded(settled)

    before_stop = sample_resources(projects, include_network_inventory=True)
    for project, env in zip(projects, envs):
        stop_output = _checked(
            project, [zaigr, "project", "vm", "stop"], env=env, timeout=90
        )
        assert "stop reason" not in stop_output.lower(), stop_output
    after_stop = sample_resources(projects)
    samples.extend([before_stop, after_stop])
    assert_stopped_resources_gone([before_stop, after_stop])

    summary_state["timings"].append(rebuild_seconds)
    summary_state["iterations"] = sum(len(items) for items in outputs)
    summary_state["extra"].update(
        {
            "exec_loop_seconds_each": exec_seconds,
            "global_rebuild_seconds": rebuild_seconds,
            "start_seconds_median": statistics.median(starts),
            "start_seconds_worst": max(starts),
        }
    )


def _host_workspace_editor(workspace, stop_event, edits, errors):
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        count = 0
        while not stop_event.is_set():
            path = workspace / f"host-edit-{count % edits}.txt"
            path.write_text(f"host-edit-{count}\n", encoding="utf-8")
            count += 1
            time.sleep(0.02)
        (workspace / "host-edit-count.txt").write_text(str(count), encoding="ascii")
    except OSError as exc:
        errors.append(exc)


def _host_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            block = source.read(8 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


@pytest.mark.stress
@pytest.mark.timeout(7200)
def test_stress_workspace_io_checksums_and_concurrent_host_edits(
    project, record_property, request
):
    """Large shared-workspace reads and writes preserve data during host edits."""
    tiny = _tiny_mode()
    file_count = 3 if tiny else 100_000
    binary_mib = 2 if tiny else 2_048
    host_edit_files = 3 if tiny else 100
    workspace_io = project.cwd / "workspace-io-stress"
    host_workspace = project.cwd / "host-edits-during-guest-io"
    binary_path = workspace_io / "large-random.bin"
    guest_workspace_io = "/home/user/workspace/workspace-io-stress"
    guest_binary_path = f"{guest_workspace_io}/large-random.bin"
    env = _make_project_env(project)
    zaigr = project.zaigr_bin
    start_began = time.monotonic()
    start_output = _checked(
        project,
        [zaigr, "project", "vm", "start", "--ram", "512", "--cpu", "1"],
        env=env,
        input="y\n",
        timeout=240,
    )
    assert "the vm stopped" not in start_output.lower(), start_output
    start_seconds = time.monotonic() - start_began
    samples = [sample_resources([project])]
    summary_state = {
        "timings": [start_seconds],
        "iterations": 0,
        "extra": {
            "small_files": file_count,
            "binary_mib": binary_mib,
            "tiny_mode": tiny,
        },
    }
    _add_summary_finalizer(
        request, record_property, "workspace-io", samples, summary_state
    )
    _checked(
        project,
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "mkdir",
            "-p",
            f"{guest_workspace_io}/small",
        ],
        env=env,
        timeout=30,
    )

    stop_editor = threading.Event()
    editor_errors = []
    editor = threading.Thread(
        target=_host_workspace_editor,
        args=(host_workspace, stop_editor, host_edit_files, editor_errors),
        daemon=True,
    )
    editor.start()
    small_script = (
        "set -eu; "
        f"for index in $(seq 1 {file_count}); do "
        "printf 'small-%s\\n' \"$index\" "
        f"> {guest_workspace_io}/small/$index; done; "
        f"printf 'SMALL_FILE_COUNT=%s\\n' \"$(find {guest_workspace_io}/small -type f | wc -l)\"; "
        "printf 'VISIBLE_HOST_EDITS=%s\\n' "
        "\"$(find /home/user/workspace/host-edits-during-guest-io -name 'host-edit-*.txt' -type f | wc -l)\""
    )
    small_started = time.monotonic()
    try:
        small_stdout = _checked(
            project,
            [zaigr, "project", "vm", "exec", "--", "bash", "-c", small_script],
            env=env,
            timeout=3600,
        )
        small_file_seconds = time.monotonic() - small_started
        summary_state["timings"].append(small_file_seconds)
        binary_started = time.monotonic()
        _checked(
            project,
            [
                zaigr,
                "project",
                "vm",
                "exec",
                "--",
                "dd",
                "if=/dev/urandom",
                f"of={guest_binary_path}",
                "bs=1M",
                f"count={binary_mib}",
                "conv=fsync",
                "status=none",
            ],
            env=env,
            timeout=1800,
        )
        binary_seconds = time.monotonic() - binary_started
        summary_state["timings"].append(binary_seconds)
        guest_hash = _checked(
            project,
            [zaigr, "project", "vm", "exec", "--", "sha256sum", guest_binary_path],
            env=env,
            timeout=600,
        ).split()[0]
    finally:
        stop_editor.set()
        editor.join(timeout=10)
    assert not editor.is_alive(), "host workspace editor failed to stop"
    assert not editor_errors, editor_errors
    guest_file_count = next(
        int(line.split("=", 1)[1])
        for line in small_stdout.splitlines()
        if line.startswith("SMALL_FILE_COUNT=")
    )
    visible_host_edits = int(
        next(
            line.split("=", 1)[1]
            for line in small_stdout.splitlines()
            if line.startswith("VISIBLE_HOST_EDITS=")
        )
    )
    assert guest_file_count == file_count, small_stdout
    summary_state["iterations"] = guest_file_count
    assert visible_host_edits > 0, small_stdout
    assert host_workspace.joinpath("host-edit-count.txt").is_file()
    assert _host_sha256(binary_path) == guest_hash
    summary_state["extra"].update(
        {
            "sha256": guest_hash,
            "host_edits_visible": visible_host_edits,
            "guest_small_files_seconds": round(small_file_seconds, 3),
            "guest_write_mib_per_second": round(binary_mib / binary_seconds, 2),
        }
    )

    # The host writes a file in the shared workspace; verify it from the guest,
    # then remove all generated guest data before measuring settled resources.
    host_marker = project.cwd / "host-edit-visible-from-guest.txt"
    host_marker.write_text("host-to-guest-check\n", encoding="utf-8")
    marker_readback = _checked(
        project,
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "cat",
            "/home/user/workspace/host-edit-visible-from-guest.txt",
        ],
        env=env,
        timeout=30,
    )
    assert marker_readback == "host-to-guest-check\n"
    _checked(
        project,
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "rm",
            "-rf",
            "/home/user/workspace/workspace-io-stress",
        ],
        env=env,
        timeout=1800,
    )
    host_marker.unlink()
    for path in host_workspace.iterdir():
        path.unlink()
    host_workspace.rmdir()

    before_restart_stop = sample_resources([project], include_network_inventory=True)
    stop_output = _checked(
        project, [zaigr, "project", "vm", "stop"], env=env, timeout=90
    )
    assert "stop reason" not in stop_output.lower(), stop_output
    after_restart_stop = sample_resources([project])
    samples.extend([before_restart_stop, after_restart_stop])
    assert_stopped_resources_gone([before_restart_stop, after_restart_stop])
    restart_began = time.monotonic()
    restart_output = _checked(
        project,
        [zaigr, "project", "vm", "start", "--ram", "512", "--cpu", "1"],
        env=env,
        input="y\n",
        timeout=240,
    )
    assert "the vm stopped" not in restart_output.lower(), restart_output
    restart_seconds = time.monotonic() - restart_began
    assert (
        _checked(
            project,
            [zaigr, "project", "vm", "exec", "--", "printf", "IO_VM_RESTARTED"],
            env=env,
            timeout=45,
        )
        == "IO_VM_RESTARTED"
    )
    samples.extend(_settled_samples([project]))
    assert_resource_growth_bounded(samples[-5:])
    before_stop = sample_resources([project], include_network_inventory=True)
    stop_output = _checked(
        project, [zaigr, "project", "vm", "stop"], env=env, timeout=90
    )
    assert "stop reason" not in stop_output.lower(), stop_output
    after_stop = sample_resources([project])
    samples.extend([before_stop, after_stop])
    assert_stopped_resources_gone([before_stop, after_stop])

    summary_state["extra"]["restart_seconds"] = restart_seconds


def _oom_probe_source():
    return r"""#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    FILE *meminfo = fopen("/proc/meminfo", "r");
    if (meminfo == NULL) return 70;
    unsigned long long total_kib = 0;
    char line[256];
    while (fgets(line, sizeof(line), meminfo) != NULL) {
        if (sscanf(line, "MemTotal: %llu kB", &total_kib) == 1) break;
    }
    fclose(meminfo);
    if (total_kib == 0) return 71;
    FILE *score = fopen("/proc/self/oom_score_adj", "w");
    if (score != NULL) { fputs("500\n", score); fclose(score); }
    size_t bytes = (size_t)(total_kib * 1024ULL + 128ULL * 1024ULL * 1024ULL);
    fprintf(stderr, "OOM_PROBE_ALLOCATING_BYTES=%zu\n", bytes);
    fflush(stderr);
    volatile unsigned char *memory = malloc(bytes);
    if (memory == NULL) return errno == ENOMEM ? 77 : 78;
    for (size_t offset = 0; offset < bytes; offset += 4096) memory[offset] = 1;
    fputs("OOM_PROBE_SURVIVED_ALLOCATION\n", stderr);
    fflush(stderr);
    sleep(30);
    return 79;
}
"""


def _outer_boot_guard():
    current_boot = (
        Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    )
    expected_outer = os.environ.get("ZAIGR_STRESS_OUTER_BOOT_ID", "").strip()
    main_boot = os.environ.get("ZAIGR_STRESS_MAIN_BOOT_ID", "").strip()
    assert expected_outer, (
        "ZAIGR_STRESS_OUTER_BOOT_ID must identify the verified outer VM boot"
    )
    assert current_boot == expected_outer, (
        "host pressure is allowed only in the verified outer VM: "
        f"expected boot {expected_outer}, found {current_boot}"
    )
    assert main_boot, (
        "ZAIGR_STRESS_MAIN_BOOT_ID must identify the main development VM boot"
    )
    assert current_boot != main_boot, (
        "refusing host pressure on the main development VM"
    )
    return current_boot


def _available_memory_bytes():
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise AssertionError("host does not report MemAvailable")


@pytest.mark.stress
@pytest.mark.timeout(1500)
def test_stress_oom_cpu_and_disk_pressure_keeps_vm_usable(
    project, record_property, request
):
    """Guest OOM/disk-full and bounded host pressure leave the VM responsive."""
    outer_boot_id = _outer_boot_guard()
    tiny = _tiny_mode()
    duration = 3 if tiny else 600
    disk_size = "1G" if tiny else "2G"
    cpu_count = "2"
    env = _make_project_env(project, disk=disk_size, cpu=cpu_count)
    probe_source = project.cwd / "stress-oom-probe.c"
    probe_binary = project.cwd / "stress-oom-probe"
    probe_source.write_text(_oom_probe_source(), encoding="utf-8")
    _checked(
        project,
        [
            "gcc",
            "-static",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            probe_binary,
            probe_source,
        ],
        timeout=60,
    )

    start_began = time.monotonic()
    start_output = _checked(
        project,
        [
            project.zaigr_bin,
            "project",
            "vm",
            "start",
            "--ram",
            "512",
            "--cpu",
            cpu_count,
        ],
        env=env,
        input="y\n",
        timeout=240,
    )
    assert "the vm stopped" not in start_output.lower(), start_output
    start_seconds = time.monotonic() - start_began
    samples = [sample_resources([project])]
    iteration_timings = []
    workers = []
    available_before = None
    host_memory_bytes = 0
    reserve_bytes = 1024 * 1024 * 1024
    safety_margin_bytes = 256 * 1024 * 1024
    guest_oom_process_killed = False
    guest_oom_exec_rc = None
    guest_oom_exec_stdout = ""
    guest_oom_exec_stderr = ""
    guest_disk_fill_recovered = False
    guest_disk_free_bytes = 0

    def emit_partial_summary():
        summary = summarize_samples(
            "pressure",
            samples,
            [start_seconds] + iteration_timings,
            len(iteration_timings),
            extra={
                "guest_oom_process_killed": guest_oom_process_killed,
                "guest_oom_exec_rc": guest_oom_exec_rc,
                "guest_oom_exec_stdout": guest_oom_exec_stdout,
                "guest_oom_exec_stderr": guest_oom_exec_stderr,
                "guest_disk_fill_recovered": guest_disk_fill_recovered,
                "guest_disk_free_after_fill_bytes": guest_disk_free_bytes,
                "guest_cpu_load_seconds": duration,
                "host_pressure_seconds": duration,
                "outer_boot_id": outer_boot_id,
                "host_cpu_workers": len(workers),
                "host_available_bytes_before_load": available_before,
                "host_reserved_bytes": reserve_bytes,
                "host_memory_pressure_bytes": host_memory_bytes,
                "host_memory_safety_margin_bytes": safety_margin_bytes,
                "tiny_mode": tiny,
            },
        )
        record_property("stress_summary", json.dumps(summary))

    request.addfinalizer(emit_partial_summary)
    original_overcommit = _checked(
        project,
        [
            project.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "sysctl",
            "-n",
            "vm.overcommit_memory",
        ],
        env=env,
        input="y\n",
        timeout=45,
    ).strip()
    assert original_overcommit in {"0", "1", "2"}, original_overcommit
    try:
        _checked(
            project,
            [
                project.zaigr_bin,
                "project",
                "vm",
                "exec",
                "--root",
                "--",
                "sysctl",
                "-w",
                "vm.overcommit_memory=1",
            ],
            env=env,
            input="y\n",
            timeout=45,
        )
        oom_stdout, oom_stderr, oom_rc = _command(
            project,
            [
                project.zaigr_bin,
                "project",
                "vm",
                "exec",
                "--",
                "/home/user/workspace/stress-oom-probe",
            ],
            env=env,
            timeout=180,
        )
        guest_oom_exec_rc = oom_rc
        guest_oom_exec_stdout = oom_stdout
        guest_oom_exec_stderr = oom_stderr
    finally:
        _checked(
            project,
            [
                project.zaigr_bin,
                "project",
                "vm",
                "exec",
                "--root",
                "--",
                "sysctl",
                "-w",
                f"vm.overcommit_memory={original_overcommit}",
            ],
            env=env,
            input="y\n",
            timeout=45,
        )
    oom_output = guest_oom_exec_stdout + guest_oom_exec_stderr
    assert guest_oom_exec_rc != 0, (
        "allocation probe unexpectedly returned success instead of being killed; "
        f"stdout={guest_oom_exec_stdout!r}; stderr={guest_oom_exec_stderr!r}"
    )
    oom_kernel_log = _checked(
        project,
        [
            project.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "dmesg",
            "--color=never",
        ],
        env=env,
        input="y\n",
        timeout=45,
    )
    assert re.search(r"Killed process \d+ \(stress-oom-prob\)", oom_kernel_log), (
        "guest kernel did not confirm OOM kill; "
        f"exec rc={guest_oom_exec_rc}; output={oom_output!r}; dmesg:\n{oom_kernel_log}"
    )
    guest_oom_process_killed = True
    alive = _checked(
        project,
        [
            project.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--",
            "printf",
            "GUEST_ALIVE_AFTER_OOM",
        ],
        env=env,
        timeout=45,
    )
    assert alive == "GUEST_ALIVE_AFTER_OOM", alive

    disk_fill_script = r"""set +e
dd if=/dev/zero of=/var/tmp/zaigr-stress-disk-fill bs=4M status=none
fill_status=$?
printf 'DISK_FILL_EXIT=%s\n' "$fill_status"
df -P / | tail -n 1
rm -f /var/tmp/zaigr-stress-disk-fill
sync
touch /var/tmp/zaigr-stress-disk-usable
printf 'DISK_SPACE_USABLE=%s\n' "$(test -w /var/tmp/zaigr-stress-disk-usable && echo yes)"
rm -f /var/tmp/zaigr-stress-disk-usable
"""
    disk_fill_stdout, disk_fill_stderr, disk_fill_rc = _command(
        project,
        [
            project.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "bash",
            "-c",
            disk_fill_script,
        ],
        env=env,
        input="y\n",
        timeout=600,
    )
    disk_fill = disk_fill_stdout + disk_fill_stderr
    assert disk_fill_rc == 0, err_msg(disk_fill_stdout, disk_fill_stderr)
    assert "DISK_FILL_EXIT=1" in disk_fill, disk_fill
    assert "No space left on device" in disk_fill, disk_fill
    assert "DISK_SPACE_USABLE=yes" in disk_fill, disk_fill
    guest_disk_fill_recovered = True
    guest_disk_free = (
        _checked(
            project,
            [
                project.zaigr_bin,
                "project",
                "vm",
                "exec",
                "--",
                "df",
                "-B1",
                "--output=avail",
                "/",
            ],
            env=env,
            timeout=30,
        )
        .splitlines()[-1]
        .strip()
    )
    assert int(guest_disk_free) > 0, guest_disk_free
    guest_disk_free_bytes = int(guest_disk_free)

    # Run all configured guest CPUs at full load in a concurrent exec while
    # the host load below continues to issue independent public exec commands.
    guest_stop_marker = project.cwd / "stress-stop-guest-cpu"
    guest_stop_marker.unlink(missing_ok=True)
    guest_cpu_script = (
        "set -u; pids=''; "
        'for index in $(seq 1 "$(nproc)"); do yes >/dev/null & pids="$pids $!"; done; '
        f"deadline=$((SECONDS + {duration})); "
        "while (( SECONDS < deadline )) && "
        "[ ! -e /home/user/workspace/stress-stop-guest-cpu ]; do sleep 1; done; "
        "kill $pids 2>/dev/null || true; "
        "for pid in $pids; do wait $pid 2>/dev/null || true; done; "
        "printf 'GUEST_CPU_LOAD_COMPLETE\\n'"
    )
    pressure_samples = [sample_resources([project])]
    host_memory = None
    guest_cpu_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    guest_cpu_future = guest_cpu_executor.submit(
        _command,
        project,
        [
            project.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-c",
            guest_cpu_script,
        ],
        env,
        timeout=duration + 120,
    )
    try:
        time.sleep(1 if tiny else 5)
        available_before = _available_memory_bytes()
        reserve_bytes = 1024 * 1024 * 1024
        safety_margin_bytes = 256 * 1024 * 1024
        host_memory_bytes = available_before - reserve_bytes - safety_margin_bytes
        assert host_memory_bytes > 256 * 1024 * 1024, (
            "outer VM has too little available memory to apply host pressure while "
            "preserving the required 1 GiB reserve plus safety margin"
        )
        host_memory = bytearray(host_memory_bytes)
        page_size = os.sysconf("SC_PAGE_SIZE")
        for offset in range(0, host_memory_bytes, page_size):
            host_memory[offset] = 1
        assert _available_memory_bytes() >= reserve_bytes, (
            "touching host pressure allocation consumed the reserved 1 GiB"
        )
        deadline = time.monotonic() + duration
        for _ in range(os.cpu_count() or 1):
            worker = subprocess.Popen(
                [sys.executable, "-c", "while True: pass"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            workers.append(worker)

        iteration = 0
        while time.monotonic() < deadline:
            command_started = time.monotonic()
            output = _checked(
                project,
                [
                    project.zaigr_bin,
                    "project",
                    "vm",
                    "exec",
                    "--",
                    "printf",
                    f"HOST_PRESSURE_EXEC_{iteration}",
                ],
                env=env,
                timeout=90,
            )
            assert output == f"HOST_PRESSURE_EXEC_{iteration}", output
            iteration_timings.append(time.monotonic() - command_started)
            pressure_samples.append(sample_resources([project]))
            iteration += 1
            time.sleep(1 if tiny else 5)
    finally:
        guest_stop_marker.touch()
        for worker in workers:
            if worker.poll() is None:
                worker.terminate()
        for worker in workers:
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)
        guest_cpu_executor.shutdown(wait=True, cancel_futures=True)
        if host_memory is not None:
            del host_memory
        guest_stop_marker.unlink(missing_ok=True)
        samples.extend(pressure_samples)

    guest_cpu_stdout, guest_cpu_stderr, guest_cpu_rc = guest_cpu_future.result()
    assert guest_cpu_rc == 0, err_msg(guest_cpu_stdout, guest_cpu_stderr)
    assert "GUEST_CPU_LOAD_COMPLETE" in guest_cpu_stdout, guest_cpu_stdout
    assert iteration_timings, (
        "host pressure interval did not run any public exec commands"
    )
    assert (
        _checked(
            project,
            [
                project.zaigr_bin,
                "project",
                "vm",
                "exec",
                "--",
                "printf",
                "GUEST_ALIVE_AFTER_PRESSURE",
            ],
            env=env,
            timeout=45,
        )
        == "GUEST_ALIVE_AFTER_PRESSURE"
    )

    before_restart_stop = sample_resources([project], include_network_inventory=True)
    stop_output = _checked(
        project, [project.zaigr_bin, "project", "vm", "stop"], env=env, timeout=90
    )
    assert "stop reason" not in stop_output.lower(), stop_output
    after_restart_stop = sample_resources([project])
    samples.extend([before_restart_stop, after_restart_stop])
    assert_stopped_resources_gone([before_restart_stop, after_restart_stop])
    restart_began = time.monotonic()
    restart_output = _checked(
        project,
        [
            project.zaigr_bin,
            "project",
            "vm",
            "start",
            "--ram",
            "512",
            "--cpu",
            cpu_count,
        ],
        env=env,
        input="y\n",
        timeout=240,
    )
    assert "the vm stopped" not in restart_output.lower(), restart_output
    restart_seconds = time.monotonic() - restart_began
    assert (
        _checked(
            project,
            [
                project.zaigr_bin,
                "project",
                "vm",
                "exec",
                "--",
                "printf",
                "GUEST_ALIVE_AFTER_RESTART",
            ],
            env=env,
            timeout=45,
        )
        == "GUEST_ALIVE_AFTER_RESTART"
    )
    iteration_timings.append(restart_seconds)

    settled = _settled_samples([project])
    samples.extend(settled)
    assert_resource_growth_bounded(settled)
    before_stop = sample_resources([project], include_network_inventory=True)
    stop_output = _checked(
        project, [project.zaigr_bin, "project", "vm", "stop"], env=env, timeout=90
    )
    assert "stop reason" not in stop_output.lower(), stop_output
    after_stop = sample_resources([project])
    samples.extend([before_stop, after_stop])
    assert_stopped_resources_gone([before_stop, after_stop])
