"""Long-running VM soak coverage; run only with ``make test-stress``."""

import json
import os
import time

import pexpect
import pytest

from tests.conftest import run, spawn_interactive

from .stress_resources import (
    assert_resource_growth_bounded,
    assert_stopped_resources_gone,
    sample_resources,
    summarize_samples,
)


def _checked(command, project, timeout=30, input=None):
    stdout, stderr, code = run(
        command, cwd=project.cwd, env=project.env, input=input, timeout=timeout
    )
    assert code == 0, f"command failed ({code}): {command}\n{stdout}\n{stderr}"
    return stdout


@pytest.mark.stress
@pytest.mark.live_network
@pytest.mark.timeout(5 * 60 * 60)
def test_four_hour_vm_soak(project_factory, record_property, monkeypatch):
    """Keep one VM useful through exec, shell, firewall, and network activity."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")
    project = project_factory()
    tiny = os.environ.get("ZAIGR_STRESS_TINY") == "1"
    duration = 20 if tiny else 4 * 60 * 60
    activity_interval = 2 if tiny else 60
    shell_interval = 6 if tiny else 10 * 60
    firewall_interval = 6 if tiny else 15 * 60
    burst_interval = 6 if tiny else 30 * 60
    sample_interval = 3 if tiny else 5 * 60
    # Each counted item performs one allowed and one blocked request.
    burst_count = 2 if tiny else 50
    samples = []
    timings = []
    started = None
    iteration = 0
    shell_count = 0
    firewall_cycle_count = 0
    dns_lookup_count = 0
    https_fetch_count = 0
    summary_written = False
    shells = []

    try:
        _checked(
            [project.zaigr_bin, "project", "vm", "start"],
            project,
            timeout=180,
            input="y\n",
        )
        allowed = "deb.debian.org"
        blocked = "example.com"
        _checked([project.zaigr_bin, "project", "firewall", "allow", allowed], project)
        started = time.monotonic()
        next_activity = started
        next_shell = started + shell_interval
        next_firewall = started + firewall_interval
        next_burst = started + burst_interval
        next_sample = started
        while time.monotonic() - started < duration:
            now = time.monotonic()
            if now >= next_sample:
                samples.append(sample_resources([project]))
                next_sample = now + sample_interval
            if now >= next_activity:
                tick = time.monotonic()
                output = _checked(
                    [
                        project.zaigr_bin,
                        "project",
                        "vm",
                        "exec",
                        "--",
                        "printf",
                        "SOAK_EXEC_OK",
                    ],
                    project,
                    timeout=60,
                )
                assert "SOAK_EXEC_OK" in output
                timings.append(time.monotonic() - tick)
                iteration += 1
                next_activity = now + activity_interval
            if now >= next_shell:
                shell = spawn_interactive(
                    f"{project.zaigr_bin} shell",
                    cwd=project.cwd,
                    env=project.env,
                    timeout=60,
                )
                shell.expect(r"\$ ", timeout=60)
                shells.append(shell)
                shell.sendline("printf 'SOAK_SHELL_OK\\n'")
                shell.expect(r"SOAK_SHELL_OK\r?\n", timeout=20)
                shell.expect(r"\$ ", timeout=20)
                shell.sendline("exit")
                shell.expect(pexpect.EOF, timeout=20)
                shell.close()
                assert shell.exitstatus == 0, "periodic shell exited unsuccessfully"
                shells.remove(shell)
                shell_count += 1
                next_shell = now + shell_interval
            if now >= next_firewall:
                _checked(
                    [project.zaigr_bin, "project", "firewall", "remove", allowed],
                    project,
                )
                _checked(
                    [project.zaigr_bin, "project", "firewall", "allow", allowed],
                    project,
                )
                firewall_cycle_count += 1
                next_firewall = now + firewall_interval
            if now >= next_burst:
                # DNS permission is checked through guest resolution; HTTPS confirms
                # the resulting firewall grant admits a real connection.
                lookup_loop = (
                    "command -v getent >/dev/null || exit 20; "
                    f"i=0; while [ $i -lt {burst_count} ]; do "
                    f"getent ahostsv4 {allowed} >/dev/null || exit 21; "
                    f"if getent ahostsv4 {blocked} >/dev/null; then exit 22; fi; "
                    "i=$((i+1)); done; echo DNS_BURST_OK"
                )
                dns = _checked(
                    [
                        project.zaigr_bin,
                        "project",
                        "vm",
                        "exec",
                        "--",
                        "sh",
                        "-c",
                        lookup_loop,
                    ],
                    project,
                    timeout=180,
                )
                assert "DNS_BURST_OK" in dns
                dns_lookup_count += burst_count * 2
                fetch_loop = (
                    "command -v curl >/dev/null || exit 30; "
                    f"done_count=0; while [ $done_count -lt {burst_count} ]; do "
                    "pids=''; batch=0; "
                    f"while [ $batch -lt 10 ] && "
                    f"[ $((done_count + batch)) -lt {burst_count} ]; do "
                    f"(curl --noproxy '*' -4fsS --connect-timeout 5 --max-time 10 "
                    f"https://{allowed}/ -o /dev/null || exit 31; "
                    f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 3 "
                    f"https://{blocked}/ -o /dev/null; then exit 32; fi) & "
                    'pids="$pids $!"; batch=$((batch+1)); done; '
                    "for pid in $pids; do wait $pid || exit 33; done; "
                    "done_count=$((done_count+batch)); done; echo HTTPS_BURST_OK"
                )
                https = _checked(
                    [
                        project.zaigr_bin,
                        "project",
                        "vm",
                        "exec",
                        "--",
                        "sh",
                        "-c",
                        fetch_loop,
                    ],
                    project,
                    timeout=1800 if not tiny else 60,
                )
                assert "HTTPS_BURST_OK" in https
                https_fetch_count += burst_count * 2
                next_burst = now + burst_interval
            upcoming = min(
                next_activity, next_shell, next_firewall, next_burst, next_sample
            )
            time.sleep(min(5, max(0.01, upcoming - time.monotonic())))
        samples.append(sample_resources([project]))
        _checked([project.zaigr_bin, "project", "vm", "exec", "--", "true"], project)
        before_stop = sample_resources([project], include_network_inventory=True)
        samples.append(before_stop)
        _checked([project.zaigr_bin, "project", "vm", "stop"], project, timeout=90)
        samples.append(sample_resources([project]))
        restart_output = _checked(
            [project.zaigr_bin, "project", "vm", "start"],
            project,
            timeout=180,
            input="y\n",
        )
        assert "the vm stopped" not in restart_output.lower(), restart_output
        samples.append(sample_resources([project], include_network_inventory=True))
        _checked([project.zaigr_bin, "project", "vm", "stop"], project, timeout=90)
        samples.append(sample_resources([project]))
        summary = summarize_samples(
            "soak",
            samples,
            timings,
            iteration,
            extra={
                "host_boot_id_stable": len({item["boot_id"] for item in samples}) == 1,
                "shell_count": shell_count,
                "firewall_cycle_count": firewall_cycle_count,
                "dns_lookup_count": dns_lookup_count,
                "https_fetch_count": https_fetch_count,
            },
        )
        record_property("stress_summary", json.dumps(summary, sort_keys=True))
        summary_written = True
        assert_stopped_resources_gone(samples)
        assert len({item["boot_id"] for item in samples}) == 1
        assert_resource_growth_bounded(samples)
    finally:
        # A final sample captures resource state after the activity window, and
        # fixture teardown owns the VM stop even if an assertion fails.
        if started is not None:
            if not samples or samples[-1]["projects"][0]["processes"]:
                samples.append(sample_resources([project]))
            if not summary_written:
                summary = summarize_samples(
                    "soak",
                    samples,
                    timings,
                    iteration,
                    extra={
                        "incomplete": True,
                        "shell_count": shell_count,
                        "firewall_cycle_count": firewall_cycle_count,
                        "dns_lookup_count": dns_lookup_count,
                        "https_fetch_count": https_fetch_count,
                    },
                )
                record_property("stress_summary", json.dumps(summary, sort_keys=True))
        for shell in locals().get("shells", []):
            if shell.isalive():
                shell.close(force=True)
