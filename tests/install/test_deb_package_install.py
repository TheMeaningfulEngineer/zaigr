import pytest

DEBIAN_IMAGES = [
    "docker.io/library/debian:bookworm",
    "docker.io/library/debian:trixie",
    "docker.io/library/ubuntu:22.04",
    "docker.io/library/ubuntu:24.04",
]


@pytest.mark.parametrize("image", DEBIAN_IMAGES)
def test_install_deb_and_run_cli(container_factory, image):
    """Install zaigr .deb package and run a packaged CLI smoke check."""
    container = container_factory(image)

    stdout, stderr, rc = container.run("apt-get update", timeout=180)
    assert rc == 0, "apt-get update failed:\n" + stdout + stderr
    if "Failed to fetch" in stdout + stderr:
        pytest.skip(f"apt package indexes unavailable for {image}")

    stdout, stderr, rc = container.run(
        f"DEBIAN_FRONTEND=noninteractive apt-get install -y /dist/{container.package_name}",
        timeout=240,
    )
    assert rc == 0, "installing zaigr .deb failed:\n" + stdout + stderr

    stdout, stderr, rc = container.run(
        "zaigr --version",
        cwd="/tmp/zaigr-project",
        timeout=30,
    )
    assert rc == 0, "zaigr --version failed:\n" + stdout + stderr
    assert stdout.strip() == container.package_version
