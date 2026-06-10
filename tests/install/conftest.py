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
    dist_package: Path
    package_build: str
    package_version: str

    @property
    def package_name(self):
        return self.dist_package.name

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

    def run(self, command, cwd=None, env=None, timeout=120):
        shell_command = self._shell_command(command, cwd=cwd, env=env)
        stdout, stderr, rc = run(
            [
                "podman",
                "exec",
                "-i",
                self.name,
                "bash",
                "-lc",
                shell_command,
            ],
            timeout=timeout,
        )
        return stdout, stderr, rc


@pytest.fixture
def container_factory():
    _require_prerequisites()
    package = _find_unique_deb_package()
    package_version, package_build = _parse_package_version(package)
    containers = []

    def _factory(image):
        container_name = f"zaigr-install-{uuid.uuid4().hex[:12]}"
        _, stderr, rc = run(
            [
                "podman",
                "run",
                "-d",
                "--rm",
                "--network",
                "host",
                "--name",
                container_name,
                "-v",
                f"{package.parent}:/dist:ro",
                image,
                "sleep",
                "infinity",
            ],
            timeout=600,
        )
        if rc != 0:
            pytest.fail(f"Failed to start container {container_name} from {image}: {stderr}")

        setup_stdout, setup_stderr, setup_rc = run(
            [
                "podman",
                "exec",
                "-i",
                container_name,
                "bash",
                "-lc",
                "mkdir -p /tmp/zaigr-home /tmp/zaigr-project /etc/apt/apt.conf.d && "
                "printf 'Acquire::ForceIPv4 \"true\";\\n' > /etc/apt/apt.conf.d/99zaigr-install-test-ipv4",
            ],
            timeout=30,
        )
        if setup_rc != 0:
            run(["podman", "rm", "-f", container_name], timeout=30)
            pytest.fail(
                f"Failed to prepare container directories for {container_name}: "
                f"{err_msg(setup_stdout, setup_stderr)}"
            )

        container = PodmanContainer(
            image=image,
            name=container_name,
            dist_package=package,
            package_build=package_build,
            package_version=package_version,
        )
        containers.append(container)
        return container

    yield _factory

    for container in reversed(containers):
        stdout, stderr, rc = run(["podman", "rm", "-f", container.name], timeout=30)
        if rc != 0:
            print(err_msg(stdout, stderr))
