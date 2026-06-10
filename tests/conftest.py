"""Fixtures and shared helpers for all test suites."""

import os
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import shlex
import threading
import time

import pexpect
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--interactive-transcript",
        action="store_true",
        default=False,
        help="Stream command transcripts in real time",
    )

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VM_PREP = os.path.join(REPO_ROOT, "vm_prep")
ZAIGR_BIN = os.path.join(REPO_ROOT, "zaigr")

# Base image artifacts (vm_data/ is the single source of truth — go:embed reads from here)
VM_DATA = os.path.join(REPO_ROOT, "cmd", "zaigr", "vm_data")
TESTS_DATA_ROOT = Path("/var/tmp/zaigr-tests")

# -- Timeouts ---------------------------------------------------------------
HOST_BUILD_TIMEOUT = 600  # host-side builds (kernel compile, clone)


_COMMAND_TRANSCRIPTS = []

_TRANSCRIPT_TAIL_CHARS = 12000


_C_FIX = "\033[38;5;214m"  # amber
_C_OFF = "\033[0m"
_C_RUN = "\033[38;5;110m"   # pastel blue
_C_TEST = "\033[38;5;147m"  # lavender


def pytest_runtest_setup(item):
    """Emit fixture setup boundary."""
    global _COMMAND_TRANSCRIPTS
    _COMMAND_TRANSCRIPTS = []
    print(f"{_C_TEST}:: TEST {item.nodeid}{_C_OFF}")
    print(f"{_C_FIX}:: Preparing fixtures{_C_OFF}")


def pytest_runtest_call(item):
    """Emit readiness boundary after fixture setup."""
    print(f"{_C_FIX}:: Fixtures prepared{_C_OFF}")


def pytest_runtest_teardown(item, nextitem):
    """Keep teardown command transcripts from sharing pytest's progress line."""
    if _should_stream_transcripts():
        print()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Attach command transcript tails to failing test reports."""
    outcome = yield
    report = outcome.get_result()
    if report.failed and _COMMAND_TRANSCRIPTS:
        report.sections.append(
            ("Captured command transcripts", _format_command_transcripts())
        )


def _check_kvm():
    """Fail fast if KVM is not available."""
    if not os.path.exists("/dev/kvm"):
        pytest.fail("KVM not available (/dev/kvm not found) — zaigr requires hardware virtualization")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        pytest.fail("KVM not usable (/dev/kvm is not readable and writable by this user)")


TESTS_DATA_ROOT.mkdir(parents=True, exist_ok=True)


@dataclass
class ProjectTestEnv:
    """Describe one isolated project workspace for tests."""

    cwd: Path
    zaigr_bin: Path
    home: Path

    @property
    def env(self):
        env = os.environ.copy()
        env["HOME"] = str(self.home)
        return env

    @property
    def store_dir(self):
        stdout, stderr, rc = run(
            [str(self.zaigr_bin), "misc", "test-helpers", "project-store-dir"],
            timeout=2,
            cwd=self.cwd,
            env=self.env,
        )
        if rc != 0:
            raise RuntimeError(
                "failed to resolve project store directory:\n"
                f"stdout:\n{stdout}\n"
                f"stderr:\n{stderr}"
            )
        return Path(stdout.strip())

    @property
    def root_ssh_key_path(self):
        return self.home / ".zaigr" / "root-ssh.key"


def _normalize_script(script):
    script = script.rstrip() + "\n"
    if not script.startswith("#!/"):
        return "#!/bin/bash\nset -eu\n" + script
    return script


@dataclass
class SetupFactory:
    """Create test-local setups and presets in an isolated `.zaigr` home."""

    home: Path

    @property
    def zaigr_dir(self):
        return self.home / ".zaigr"

    def __call__(self, setup_name, script_content, firewall=None):
        setups_dir = self.zaigr_dir / "setups"
        setups_dir.mkdir(parents=True, exist_ok=True)

        setup_dir = setups_dir / setup_name
        setup_dir.mkdir(parents=True, exist_ok=True)

        script_path = setup_dir / "setup.script"
        script_path.write_text(_normalize_script(script_content), encoding="utf-8")

        if firewall is not None:
            firewall_path = setup_dir / "setup.firewall"
            if isinstance(firewall, str):
                firewall_text = firewall.rstrip() + "\n"
            else:
                firewall_text = "\n".join(firewall).rstrip() + "\n"
            firewall_path.write_text(firewall_text, encoding="utf-8")

        return setup_name

    def preset(self, name, run, setups):
        preset_dir = self.zaigr_dir / "presets" / name
        (preset_dir / "setups").mkdir(parents=True, exist_ok=True)
        (preset_dir / "run").write_text(_normalize_script(run), encoding="utf-8")
        for setup_name in setups:
            (preset_dir / "setups" / f"{setup_name}.script").write_text("", encoding="utf-8")
        return name


def _host_ram_mb():
    """Return total host RAM in MB, or None if unavailable."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return None


def _should_stream_transcripts():
    return any(
        opt in sys.argv
        for opt in ("-s", "--capture=no", "--capture=tee-sys", "--interactive-transcript")
    )


def _new_transcript(kind, cmd, mirror=None):
    transcript = _TranscriptBuffer(
        mirror=_should_stream_transcripts() if mirror is None else mirror
    )
    _COMMAND_TRANSCRIPTS.append({"kind": kind, "cmd": cmd, "buffer": transcript})
    return transcript


def _format_command_transcripts():
    chunks = []
    for transcript in _COMMAND_TRANSCRIPTS:
        text = transcript["buffer"].tail(_TRANSCRIPT_TAIL_CHARS)
        if not text:
            continue
        if len(transcript["buffer"].getvalue()) > _TRANSCRIPT_TAIL_CHARS:
            text = (
                f"[transcript truncated to last {_TRANSCRIPT_TAIL_CHARS} chars]\n"
                + text
            )
        chunks.append(f":: {transcript['kind']} {transcript['cmd']}\n{text}")
    return "\n\n".join(chunks)


def run(cmd, cwd=None, env=None, input=None, timeout=30, context=None):
    """Run a command string or argv list and return (stdout, stderr, returncode)."""
    args = shlex.split(cmd) if isinstance(cmd, str) else [str(part) for part in cmd]
    shown_cmd = cmd if isinstance(cmd, str) else shlex.join(args)
    transcript_cmd = f"[{context}] {shown_cmd}" if context else shown_cmd
    transcript = _new_transcript("command", transcript_cmd)
    transcript.write(_host_shell_prompt(shown_cmd, cwd=cwd, env=env))

    process = subprocess.Popen(
        args,
        stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        env=env,
    )

    stdout_parts = []
    stderr_parts = []

    def read_stream(stream, stream_name, parts, mirror_stream):
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                parts.append(chunk)
                transcript.write_labeled(stream_name, chunk, mirror_stream)
        finally:
            stream.close()

    stdout_thread = threading.Thread(
        target=read_stream,
        args=(process.stdout, "stdout", stdout_parts, sys.stdout),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=read_stream,
        args=(process.stderr, "stderr", stderr_parts, sys.stderr),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    if input is not None:
        if transcript.mirror:
            sys.stdout.write(f"{_C_RUN}:: stdin{_C_OFF}\n")
            sys.stdout.flush()
        transcript.write_labeled("stdin", input, sys.stdout)
        try:
            process.stdin.write(input)
            process.stdin.close()
        except BrokenPipeError:
            pass

    started = time.monotonic()
    try:
        rc = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        rc = process.wait()
        stdout_thread.join()
        stderr_thread.join()
        duration = time.monotonic() - started
        transcript.write(
            f"\n:: timeout after {timeout}s; killed process with exit {rc}"
            f" ({duration:.2f}s)\n"
        )
        raise subprocess.TimeoutExpired(
            args,
            timeout,
            output="".join(stdout_parts),
            stderr="".join(stderr_parts),
        )

    stdout_thread.join()
    stderr_thread.join()
    duration = time.monotonic() - started
    transcript.write(f"\n:: exit {rc} ({duration:.2f}s)\n")

    return "".join(stdout_parts), "".join(stderr_parts), rc


def err_msg(stdout, stderr):
    """Format stdout/stderr for assertion messages."""
    return f"--- stdout ---\n{stdout[-2000:]}\n--- stderr ---\n{stderr[-2000:]}"


def _host_shell_prompt(cmd, cwd=None, env=None):
    """Render the launch directory and command for transcript logs."""
    prompt_cwd = Path(cwd or os.getcwd())
    return f"{prompt_cwd}$ {cmd}\n"


class _TranscriptBuffer:
    """Capture a command transcript and optionally mirror it live."""

    def __init__(self, mirror=False):
        self.parts = []
        self.mirror = mirror
        self._lock = threading.Lock()
        self._label = None

    def _append(self, text):
        if not text:
            return
        with self._lock:
            self.parts.append(text)

    def write(self, text):
        self._append(text)
        if self.mirror:
            sys.stdout.write(text)
            sys.stdout.flush()

    def write_labeled(self, label, text, mirror_stream):
        if not text:
            return
        with self._lock:
            if self._label != label:
                self.parts.append(f"\n--- {label} ---\n")
                self._label = label
            self.parts.append(text)
        if self.mirror:
            mirror_stream.write(text)
            mirror_stream.flush()

    def flush(self):
        if self.mirror:
            sys.stdout.flush()

    def getvalue(self):
        with self._lock:
            return "".join(self.parts)

    def tail(self, limit):
        return self.getvalue()[-limit:]


def spawn_interactive(cmd, cwd=None, env=None, timeout=30):
    """Spawn an interactive command with pexpect."""
    args = shlex.split(cmd)
    child = pexpect.spawn(
        args[0],
        args[1:],
        cwd=cwd,
        env=env,
        timeout=timeout,
        encoding="utf-8",
    )
    transcript = _new_transcript("interactive", cmd)
    transcript.write(_host_shell_prompt(cmd, cwd=cwd, env=env))
    child.logfile_read = transcript
    child.logfile_send = transcript
    child.transcript = transcript
    return child


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def zaigr_bin():
    """Ensure zaigr binary is built, return its path."""
    if not os.path.isfile(ZAIGR_BIN):
        stdout, stderr, rc = run(
            ["make", "build"],
            timeout=HOST_BUILD_TIMEOUT,
            cwd=REPO_ROOT,
        )
        if rc != 0:
            pytest.fail(
                f"make build failed (exit {rc}):\n"
                f"--- stdout ---\n{stdout[-2000:]}\n"
                f"--- stderr ---\n{stderr[-2000:]}"
            )
    assert os.path.isfile(ZAIGR_BIN), "zaigr binary not produced"
    return ZAIGR_BIN


def _free_disk_gb(path="/"):
    """Return free disk space in GB at the given path, or None if unavailable."""
    try:
        st = os.statvfs(path)
        return (st.f_bavail * st.f_frsize) / (1024**3)
    except OSError:
        return None


def _check_disk_space(path, need_gb, context=""):
    """Fail early if there isn't enough disk space.

    This is a hard failure, not a skip — if the VM was started with too
    little disk, the tests will waste minutes building before hitting
    cryptic 'No space left on device' errors.
    """
    free = _free_disk_gb(path)
    if free is not None and free < need_gb:
        hint = (
            f"Need {need_gb} GB free on {path} but only {free:.1f} GB available."
            f" The dev VM was likely started with too small a disk (--disk)."
        )
        if context:
            hint += f"\n{context}"
        pytest.fail(hint)


def _new_disk_backed_dir(prefix):
    """Create a test directory under the shared disk-backed root."""
    return Path(tempfile.mkdtemp(prefix=prefix, dir=TESTS_DATA_ROOT))


@pytest.fixture()
def test_root():
    """Return a single disk-backed root for all state created by one test."""
    root = _new_disk_backed_dir("test-")
    yield root
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture()
def zaigr_home(test_root, monkeypatch):
    """Return an isolated HOME for test-local `.zaigr` state."""
    home = test_root / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    yield home


@pytest.fixture()
def project_factory(test_root, zaigr_bin, zaigr_home):
    """Create one or more project test environments in the same isolated HOME."""
    _check_kvm()

    projects_root = test_root / "projects"
    projects_root.mkdir()
    created = 0
    created_projects = []

    def factory(name=None):
        nonlocal created
        created += 1
        project_name = name or f"project-{created}"
        project_dir = projects_root / project_name
        project_dir.mkdir()
        project = ProjectTestEnv(
            cwd=project_dir,
            zaigr_bin=Path(zaigr_bin),
            home=Path(zaigr_home),
        )
        created_projects.append(project)
        return project

    yield factory

    for project in reversed(created_projects):
        stdout, stderr, rc = run(
            f"{project.zaigr_bin} project vm stop --abrupt",
            cwd=project.cwd,
            env=project.env,
            timeout=30,
        )
        text = stdout + stderr
        if rc != 0 and "project VM is not running" not in text and "requires a project" not in text:
            print(err_msg(stdout, stderr))


@pytest.fixture()
def project(project_factory):
    """Convenience fixture for the common one-project case."""
    return project_factory()


@pytest.fixture()
def setup_factory(zaigr_home):
    """Create test-local setups and presets in the isolated `.zaigr` tree."""
    return SetupFactory(Path(zaigr_home))
