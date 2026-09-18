import os
import shlex
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, err_msg, run

_DIST_DIR = Path(REPO_ROOT) / "release" / "dist"


def _require_prerequisites():
    if not shutil.which("podman"):
        pytest.fail("podman is required to run install tests")


def _find_unique_deb_package():
    packages = sorted(_DIST_DIR.glob("zaigr_*.deb"))
    if not packages:
        pytest.fail("No .deb artifact found in release/dist/; run `./release/release candidate <version>` first")
    if len(packages) != 1:
        names = ", ".join(str(path) for path in packages)
        pytest.fail(
            "Expected exactly one release/dist/*.deb artifact for install tests, found "
            f"{len(packages)}: {names}"
        )

    return packages[0]


def _parse_package_version(path: Path):
    expected_suffix = "_amd64.deb"
    if not path.name.startswith("zaigr_") or not path.name.endswith(expected_suffix):
        pytest.fail(f"Unexpected .deb filename format: {path}")

    base = path.name[len("zaigr_") : -len(expected_suffix)]
    if "-" not in base:
        pytest.fail(f"Unexpected .deb filename format: {path}")

    version, build = base.rsplit("-", 1)
    if not version or not build.isdigit():
        pytest.fail(
            f"Unexpected .deb filename format: {path};"
            f" expected zaigr_<version>-<build>_amd64.deb with numeric build"
        )
    return version, build


@dataclass
class PodmanContainer:
    image: str
    name: str
    dist_artifact: Path
    package_build: str
    package_version: str

    @property
    def package_name(self):
        return self.dist_artifact.name

    def _shell_command(self, command, cwd=None, env=None):
        env = {"HOME": "/tmp/zaigr-home", **(env or {})}
        parts = [
            f"export {key}={shlex.quote(str(value))}"
            for key, value in env.items()
        ]
        if cwd:
            parts.append(f"cd {shlex.quote(str(cwd))}")
        parts.append(command)
        return "; ".join(parts)

    def run(self, command, cwd=None, env=None, timeout=120, user=None, input=None):
        shell_command = self._shell_command(command, cwd=cwd, env=env)
        args = ["podman", "exec", "-i"]
        if user is not None:
            args.extend(["--user", str(user)])
        stdout, stderr, rc = run(
            [
                *args,
                self.name,
                "bash",
                "-lc",
                shell_command,
            ],
            timeout=timeout,
            input=input,
        )
        return stdout, stderr, rc


@pytest.fixture
def container_factory():
    _require_prerequisites()
    containers = []

    def _factory(image, standalone=False):
        runtime_args = []
        if standalone:
            artifact = Path(
                os.environ.get("ZAIGR_TEST_BINARY") or _DIST_DIR / "zaigr"
            ).expanduser().resolve()
            if not artifact.is_file():
                pytest.fail(
                    f"Standalone binary not found: {artifact}; create a release candidate "
                    "or set ZAIGR_TEST_BINARY to the real binary to install"
                )
            if not os.access("/dev/kvm", os.R_OK | os.W_OK):
                pytest.fail("Standalone install tests require read/write access to /dev/kvm")
            runtime = shutil.which("crun")
            if runtime is None:
                pytest.fail(
                    "crun is required for standalone install tests to preserve KVM group access"
                )
            runtime_args = [
                "--runtime", runtime,
                "--device", "/dev/kvm",
                "--group-add", "keep-groups",
            ]
            mount = f"{artifact}:/dist/zaigr:ro"
            package_version, package_build = "", ""
        else:
            artifact = _find_unique_deb_package()
            package_version, package_build = _parse_package_version(artifact)
            mount = f"{artifact.parent}:/dist:ro"

        container_name = f"zaigr-install-{uuid.uuid4().hex[:12]}"
        _, stderr, rc = run(
            [
                "podman",
                "run",
                *runtime_args,
                "-d",
                "--rm",
                "--network",
                "host",
                "--name",
                container_name,
                "-v",
                mount,
                image,
                "sleep",
                "infinity",
            ],
            timeout=600,
        )
        if rc != 0:
            pytest.fail(f"Failed to start container {container_name} from {image}: {stderr}")
        containers.append(container_name)

        setup_stdout, setup_stderr, setup_rc = run(
            [
                "podman",
                "exec",
                "-i",
                container_name,
                "bash",
                "-lc",
                (
                    "mkdir -p /tmp/zaigr-home /tmp/zaigr-project /etc/apt/apt.conf.d && "
                    "printf 'Acquire::ForceIPv4 \"true\";\\n' > /etc/apt/apt.conf.d/99zaigr-install-test-ipv4"
                ),
            ],
            timeout=30,
        )
        if setup_rc != 0:
            pytest.fail(
                f"Failed to prepare container directories for {container_name}: "
                f"{err_msg(setup_stdout, setup_stderr)}"
            )

        container = PodmanContainer(
            image=image,
            name=container_name,
            dist_artifact=artifact,
            package_build=package_build,
            package_version=package_version,
        )
        return container

    yield _factory

    cleanup_errors = []
    for container_name in reversed(containers):
        stdout, stderr, rc = run(
            ["podman", "rm", "--force", "--time", "0", container_name], timeout=30
        )
        if rc != 0:
            cleanup_errors.append(f"{container_name}: {err_msg(stdout, stderr)}")
    if cleanup_errors:
        pytest.fail("Install container cleanup failed:\n" + "\n".join(cleanup_errors))
