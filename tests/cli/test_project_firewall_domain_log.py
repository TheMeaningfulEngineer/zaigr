"""Public CLI coverage for DNS and direct-IP firewall decision logging."""

import re
import shlex
import time
import uuid
from pathlib import Path

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run


@pytest.fixture(autouse=True)
def small_vm_resources(monkeypatch):
    """Keep the isolated acceptance VM economical."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


def checked_run(command, project, **kwargs):
    """Run a visible public CLI command and return its successful stdout."""
    stdout, stderr, rc = _run(
        command, cwd=project.cwd, env=project.env, **kwargs
    )
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def expect_domain_event(log, pattern, timeout=10):
    """Wait for one public event line and return the consumed transcript text."""
    log.expect(pattern, timeout=timeout)
    return log.after


def drain_matching_events(log, pattern, duration=1.5):
    """Collect matching records emitted during a short finite packet burst."""
    matches = []
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            log.expect(pattern, timeout=min(0.2, deadline - time.monotonic()))
            matches.append(log.after)
        except pexpect.TIMEOUT:
            continue
    return matches


def service_counts(endpoint):
    """Return only received service requests, excluding ongoing stream attempts."""
    counts = endpoint["request_counts"]()
    return counts["tcp"], counts["udp"]


@pytest.fixture
def interactive_udp_probe(project):
    """Build the real datagram client used for persistent allow/revoke probes."""
    output = project.cwd / "interactive-udp-probe"
    source = Path(__file__).with_name("host_network_fixture") / "udp_probe.c"
    stdout, stderr, rc = _run(
        ["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", output, source],
        cwd=project.cwd,
        env=project.env,
    )
    assert rc == 0, err_msg(stdout, stderr)
    return output


def test_domain_log_help_describes_dns_and_packet_verdicts(project):
    """Help distinguishes packet-filter outcomes from application success."""
    output = checked_run(
        [project.zaigr_bin, "project", "firewall", "domain-log", "--help"],
        project,
        timeout=10,
    ).lower()
    assert "dns" in output, output
    assert "firewall packet verdicts" in output, output
    assert "not remote connection or application success" in output, output
    assert "-v" in output, output


@pytest.mark.timeout(240)
def test_domain_log_collapses_dns_repeats_by_default_and_verbose_shows_types(
    project, host_network_dns, request
):
    """One real blocked lookup is concise by default and detailed with -v."""
    zaigr = project.zaigr_bin
    name = "verbosity-log-" + uuid.uuid4().hex[:12] + ".test"
    checked_run(
        [zaigr, "project", "vm", "start"], project, input="y\n", timeout=180
    )

    default_log = spawn_interactive(
        shlex.quote(str(zaigr)) + " project firewall domain-log",
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    request.addfinalizer(
        lambda: default_log.close(force=True) if default_log.isalive() else None
    )
    default_log.expect("Firewall packet events coalesce", timeout=10)
    verbose_log = spawn_interactive(
        shlex.quote(str(zaigr)) + " -v project firewall domain-log",
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    request.addfinalizer(
        lambda: verbose_log.close(force=True) if verbose_log.isalive() else None
    )
    verbose_log.expect("Firewall packet events coalesce", timeout=10)
    time.sleep(0.2)

    blocked_lookup = _run(
        [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
         "-sS", "--connect-timeout", "2", "--max-time", "10",
         f"http://{name}/"],
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    assert blocked_lookup[2] == 6, err_msg(blocked_lookup[0], blocked_lookup[1])

    observed_types = set()
    while observed_types != {"A", "AAAA"}:
        verbose_log.expect(rf"DNS blocked\s+{re.escape(name)} \((A|AAAA)\)", timeout=10)
        observed_types.add(verbose_log.match.group(1))
    # Let the guest's additional attempts reach both live event readers before
    # interrupting them; every verbose query remains a separate transcript line.
    time.sleep(0.6)
    default_log.sendintr()
    default_log.expect(pexpect.EOF, timeout=10)
    default_log.close()
    verbose_log.sendintr()
    verbose_log.expect(pexpect.EOF, timeout=10)
    verbose_log.close()

    default_transcript = default_log.transcript.getvalue()
    default_lines = re.findall(
        rf"^DNS blocked\s+{re.escape(name)}(?:\s+\([^\r\n]+\))?\r?$",
        default_transcript,
        re.MULTILINE,
    )
    assert len(default_lines) == 1, default_transcript

    verbose_transcript = verbose_log.transcript.getvalue()
    verbose_types = re.findall(
        rf"^DNS blocked\s+{re.escape(name)} \((A|AAAA)\)\r?$",
        verbose_transcript,
        re.MULTILINE,
    )
    assert "A" in verbose_types, verbose_transcript
    assert "AAAA" in verbose_types, verbose_transcript
    assert verbose_types.count("A") >= 2, verbose_transcript
    assert verbose_types.count("AAAA") >= 2, verbose_transcript


def assert_stream_cut_off(stream, endpoint):
    """Drain queued bytes, then observe a fixed quiet interval while the server pushes."""
    quiet_since = None
    deadline = time.monotonic() + 4
    ended = False
    while time.monotonic() < deadline:
        try:
            stream.read_nonblocking(size=4096, timeout=0.1)
        except pexpect.TIMEOUT:
            if quiet_since is None:
                quiet_since = time.monotonic()
            if time.monotonic() - quiet_since >= 0.5:
                break
        except pexpect.EOF:
            ended = True
            break
        else:
            quiet_since = None
    else:
        pytest.fail("established TCP stream continued delivering data after firewall removal")

    pushes_before = endpoint["request_counts"]()["stream_pushes"]
    observation_deadline = time.monotonic() + 0.5
    while time.monotonic() < observation_deadline and not ended:
        try:
            stream.read_nonblocking(
                size=4096, timeout=min(0.1, observation_deadline - time.monotonic())
            )
        except pexpect.TIMEOUT:
            pass
        except pexpect.EOF:
            ended = True
        else:
            pytest.fail("established TCP stream delivered data after the quiet drain")
    if ended:
        time.sleep(max(0, observation_deadline - time.monotonic()))
    pushes_after = endpoint["request_counts"]()["stream_pushes"]
    assert pushes_after > pushes_before, "controlled endpoint stopped pushing during the cutoff observation"
    return ended


@pytest.mark.timeout(420)
def test_domain_log_covers_tcp_udp_verdict_transitions_and_dns_without_payloads(
    project, host_network_endpoints, host_network_dns, dns_probe_binary,
    interactive_udp_probe, request
):
    """Log real direct-IP verdicts, preserve DNS output, and keep payloads private."""
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    resolver = host_network_dns["resolver"]
    assert dns_probe_binary.is_file()
    resolver.set_answer("log-allowed.test", "93.184.216.34", 30)

    checked_run(
        [zaigr, "project", "vm", "start"], project, input="y\n", timeout=180
    )

    log = spawn_interactive(
        shlex.quote(str(zaigr)) + " project firewall domain-log",
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    request.addfinalizer(lambda: log.close(force=True) if log.isalive() else None)
    time.sleep(0.2)

    blocked_dns = checked_run(
        [zaigr, "project", "vm", "exec", "--", "./dns_probe", "udp", "log-blocked.test"],
        project,
        timeout=20,
    )
    assert "rcode=5" in blocked_dns, blocked_dns
    expect_domain_event(log, r"DNS blocked\s+log-blocked\.test")

    checked_run(
        [zaigr, "project", "firewall", "domain", "allow", "log-allowed.test"],
        project,
        timeout=30,
    )
    allowed_dns = checked_run(
        [zaigr, "project", "vm", "exec", "--", "./dns_probe", "udp", "log-allowed.test"],
        project,
        timeout=20,
    )
    assert "rcode=0" in allowed_dns and "a=93.184.216.34" in allowed_dns, allowed_dns
    expect_domain_event(log, r"DNS allowed\s+log-allowed\.test")
    checked_run(
        [zaigr, "project", "firewall", "domain", "remove", "log-allowed.test"],
        project,
        timeout=30,
    )

    tcp_port = endpoint["tcp_port"]
    udp_port = endpoint["udp_port"]
    tcp_url = f"http://10.0.2.2:{tcp_port}/"
    tcp_event = rf"FIREWALL blocked TCP \S+:\d+ -> 10\.0\.2\.2:{tcp_port}\b"
    udp_event = rf"FIREWALL blocked UDP \S+:\d+ -> 10\.0\.2\.2:{udp_port}\b"
    counts_before_denials = service_counts(endpoint)

    blocked_tcp = _run(
        [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
         "--connect-timeout", "2", "--max-time", "4", tcp_url],
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    assert blocked_tcp[2] in (7, 28), err_msg(blocked_tcp[0], blocked_tcp[1])
    assert endpoint["token"] not in blocked_tcp[0]
    expect_domain_event(log, tcp_event)

    payload_marker = "domain-log-payload-" + uuid.uuid4().hex
    udp_session = spawn_interactive(
        shlex.join([
            str(zaigr), "project", "vm", "exec", "--", "timeout", "90",
            "./interactive-udp-probe", "--interactive", "10.0.2.2", str(udp_port),
        ]),
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    request.addfinalizer(
        lambda: udp_session.close(force=True) if udp_session.isalive() else None
    )
    udp_session.expect_exact("UDP_PROBE_READY", timeout=10)
    udp_session.sendline(payload_marker)
    udp_session.expect_exact("UDP_RESULT=DENIED", timeout=5)
    blocked_udp_line = expect_domain_event(log, udp_event)
    udp_tuple = re.search(
        r"FIREWALL blocked UDP (\S+:\d+) -> 10\.0\.2\.2:", blocked_udp_line
    )
    assert udp_tuple, blocked_udp_line

    udp_session.sendline("BURST:" + payload_marker)
    udp_session.expect_exact("UDP_BURST_SENT=16", timeout=5)
    repeated_blocked_events = drain_matching_events(log, udp_event, duration=0.5)
    assert len(repeated_blocked_events) < 16, repeated_blocked_events
    assert service_counts(endpoint) == counts_before_denials

    checked_run(
        [zaigr, "project", "firewall", "allow", "10.0.2.2"], project, timeout=30
    )
    allowed_tcp = checked_run(
        [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
         "--request", "GET", "--data-binary", payload_marker, "--max-time", "4",
         f"http://10.0.2.2:{tcp_port}/{payload_marker}"],
        project,
        timeout=20,
    )
    assert allowed_tcp.strip() == endpoint["token"], allowed_tcp
    allowed_tcp_event = rf"FIREWALL allowed TCP \S+:\d+ -> 10\.0\.2\.2:{tcp_port}\b"
    expect_domain_event(log, allowed_tcp_event)

    udp_session.sendline(payload_marker)
    udp_session.expect_exact(f"UDP_RESULT={endpoint['token']}:udp", timeout=5)
    allowed_udp_event = rf"FIREWALL allowed UDP {re.escape(udp_tuple.group(1))} -> 10\.0\.2\.2:{udp_port}\b"
    expect_domain_event(log, allowed_udp_event)

    stream = spawn_interactive(
        f"{shlex.quote(str(zaigr))} project vm exec -- curl --noproxy '*' -4fsSN "
        f"--keepalive-time 1 --max-time 180 http://10.0.2.2:{tcp_port}/stream",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    request.addfinalizer(lambda: stream.close(force=True) if stream.isalive() else None)
    stream.expect_exact(endpoint["token"], timeout=10)
    stream.expect_exact(endpoint["token"], timeout=5)
    allowed_stream_event = rf"FIREWALL allowed TCP (\S+:\d+) -> 10\.0\.2\.2:{tcp_port}\b"
    stream_event = expect_domain_event(log, allowed_stream_event)
    stream_tuple = re.search(
        rf"FIREWALL allowed TCP (\S+:\d+) -> 10\.0\.2\.2:{tcp_port}\b",
        stream_event,
    )
    assert stream_tuple, stream_event

    checked_run(
        [zaigr, "project", "firewall", "remove", "10.0.2.2"], project, timeout=20
    )
    blocked_stream_event = rf"FIREWALL blocked TCP {re.escape(stream_tuple.group(1))} -> 10\.0\.2\.2:{tcp_port}\b"
    expect_domain_event(log, blocked_stream_event)
    stream_ended = assert_stream_cut_off(stream, endpoint)
    if not stream_ended:
        stream.sendintr()
        stream.expect(pexpect.EOF, timeout=5)
    stream.close()

    counts_before_retest = service_counts(endpoint)
    revoked_tcp = _run(
        [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
         "--connect-timeout", "2", "--max-time", "4", tcp_url],
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    assert revoked_tcp[2] in (7, 28), err_msg(revoked_tcp[0], revoked_tcp[1])
    expect_domain_event(log, tcp_event)
    udp_session.sendline(payload_marker)
    udp_session.expect_exact("UDP_RESULT=DENIED", timeout=5)
    revoked_udp_event = rf"FIREWALL blocked UDP {re.escape(udp_tuple.group(1))} -> 10\.0\.2\.2:{udp_port}\b"
    expect_domain_event(log, revoked_udp_event)
    assert service_counts(endpoint) == counts_before_retest

    checked_run(
        [zaigr, "project", "firewall", "allow", "10.0.2.2"], project, timeout=30
    )
    udp_session.sendline(payload_marker)
    udp_session.expect_exact(f"UDP_RESULT={endpoint['token']}:udp", timeout=5)
    reallowed_udp_event = rf"FIREWALL allowed UDP {re.escape(udp_tuple.group(1))} -> 10\.0\.2\.2:{udp_port}\b"
    expect_domain_event(log, reallowed_udp_event)
    checked_run(
        [zaigr, "project", "firewall", "remove", "10.0.2.2"], project, timeout=30
    )

    udp_session.sendintr()
    udp_session.expect(pexpect.EOF, timeout=5)
    udp_session.close()

    log.sendintr()
    log.expect(pexpect.EOF, timeout=10)
    log.close()
    assert log.exitstatus == 0
    transcript = log.transcript.getvalue()
    assert "repeated identical decisions" in transcript, transcript
    assert endpoint["token"] not in transcript
    assert payload_marker not in transcript

    # Pause a second real logger while a guest emits actual UDP packet events.
    # Remove policy through the independent public control command during the
    # burst, then interrupt the unread logger and require clean cancellation.
    checked_run(
        [zaigr, "project", "firewall", "allow", "10.0.2.2"], project, timeout=30
    )
    slow_log = spawn_interactive(
        shlex.quote(str(zaigr)) + " project firewall domain-log",
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    request.addfinalizer(
        lambda: slow_log.close(force=True) if slow_log.isalive() else None
    )
    slow_log.expect("repeated identical decisions", timeout=10)
    flood = spawn_interactive(
        shlex.join([
            str(zaigr), "project", "vm", "exec", "--", "bash", "-c",
            (f"for attempt in $(seq 1 500); do "
             f"printf '%s\\n' 'firewall-log-flood' >/dev/udp/10.0.2.2/{udp_port}; "
             "if [ \"$attempt\" = 1 ]; then printf 'UDP_FLOOD_STARTED\\n'; fi; "
             "sleep 0.005; done; printf 'UDP_FLOOD_COMPLETED=500\\n'"),
        ]),
        cwd=project.cwd,
        env=project.env,
        timeout=15,
    )
    request.addfinalizer(lambda: flood.close(force=True) if flood.isalive() else None)
    flood.expect_exact("UDP_FLOOD_STARTED", timeout=10)
    udp_requests_before_flood = service_counts(endpoint)[1]
    endpoint_deadline = time.monotonic() + 2
    while time.monotonic() < endpoint_deadline:
        if service_counts(endpoint)[1] > udp_requests_before_flood:
            break
        time.sleep(0.05)
    else:
        pytest.fail("the allowed UDP flood did not reach the controlled endpoint")
    checked_run(
        [zaigr, "project", "firewall", "remove", "10.0.2.2"], project, timeout=20
    )
    flood.expect_exact("UDP_FLOOD_COMPLETED=500", timeout=15)
    flood.close()
    slow_log.sendintr()
    slow_log.expect(pexpect.EOF, timeout=10)
    slow_log.close()
    assert slow_log.exitstatus == 0


@pytest.mark.timeout(240)
def test_domain_log_starts_empty_unless_history_is_requested(
    project, host_network_dns, request
):
    """A new log follows only new traffic; --history replays earlier events."""
    zaigr = project.zaigr_bin
    earlier = "earlier-log-" + uuid.uuid4().hex[:12] + ".test"
    later = "later-log-" + uuid.uuid4().hex[:12] + ".test"
    checked_run(
        [zaigr, "project", "vm", "start"], project, input="y\n", timeout=180
    )

    def blocked_lookup(name):
        result = _run(
            [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
             "-sS", "--connect-timeout", "2", "--max-time", "10",
             f"http://{name}/"],
            cwd=project.cwd,
            env=project.env,
            timeout=20,
        )
        assert result[2] == 6, err_msg(result[0], result[1])

    blocked_lookup(earlier)

    def start_log(arguments):
        log = spawn_interactive(
            shlex.quote(str(zaigr)) + " project firewall domain-log" + arguments,
            cwd=project.cwd,
            env=project.env,
            timeout=20,
        )
        request.addfinalizer(lambda: log.close(force=True) if log.isalive() else None)
        log.expect("Firewall packet events coalesce", timeout=10)
        return log

    fresh_log = start_log("")
    history_log = start_log(" --history")
    history_log.expect(rf"DNS blocked\s+{re.escape(earlier)}", timeout=10)
    time.sleep(0.2)

    blocked_lookup(later)
    fresh_log.expect(rf"DNS blocked\s+{re.escape(later)}", timeout=10)
    history_log.expect(rf"DNS blocked\s+{re.escape(later)}", timeout=10)
    assert earlier not in fresh_log.before, fresh_log.before

    for log in (fresh_log, history_log):
        log.sendintr()
        log.expect(pexpect.EOF, timeout=10)
        log.close()
