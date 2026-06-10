"""Base image version-hash tests."""

from pathlib import Path
import shutil

from ..conftest import REPO_ROOT, VM_DATA, VM_PREP, err_msg, run


MINICONFIG = Path(VM_DATA) / "miniconfig"
ALLOWED_HOSTS = Path(VM_PREP) / "base-image-building-blocks" / "allowed-hosts.txt"
ZAIGR_INSIDE = Path(VM_PREP) / "base-image-building-blocks" / "zaigr-inside"
APT_FORCE_IPV4_CONF = (
    Path(VM_PREP)
    / "base-image-building-blocks"
    / "etc"
    / "apt"
    / "apt.conf.d"
    / "99zaigr-force-ipv4"
)
DEBIAN_FASTLY_DNS_HOST = "debian.map.fastlydns.net"


def _parse_versions(stdout):
    versions = {}
    for line in stdout.splitlines():
        key, _, value = line.partition(":")
        versions[key.strip()] = value.strip()
    return versions


def test_versions_stable():
    """Same inputs produce the same version hashes."""
    stdout, stderr, rc = run("./vm_prep/base-image-version.sh .", cwd=REPO_ROOT)
    assert rc == 0, err_msg(stdout, stderr)
    first = _parse_versions(stdout)

    stdout, stderr, rc = run("./vm_prep/base-image-version.sh .", cwd=REPO_ROOT)
    assert rc == 0, err_msg(stdout, stderr)
    second = _parse_versions(stdout)

    assert first == second


def test_miniconfig_change():
    """Changing miniconfig changes miniconfig and base-image versions."""
    stdout, stderr, rc = run("./vm_prep/base-image-version.sh .", cwd=REPO_ROOT)
    assert rc == 0, err_msg(stdout, stderr)
    before = _parse_versions(stdout)

    backup = MINICONFIG.with_name(MINICONFIG.name + ".bak")
    shutil.copy2(MINICONFIG, backup)
    try:
        with open(MINICONFIG, "a") as f:
            f.write("\n# test change\n")

        stdout, stderr, rc = run("./vm_prep/base-image-version.sh .", cwd=REPO_ROOT)
        assert rc == 0, err_msg(stdout, stderr)
        after = _parse_versions(stdout)
        assert after["miniconfig"] != before["miniconfig"], "miniconfig version should change"
        assert after["building-blocks"] == before["building-blocks"], (
            "building-blocks version should not change"
        )
        assert after["base-image"] != before["base-image"], (
            "base-image version should include miniconfig"
        )
    finally:
        shutil.move(backup, MINICONFIG)


def test_building_block_change():
    """Changing a building block changes building-blocks version but not miniconfig."""
    stdout, stderr, rc = run("./vm_prep/base-image-version.sh .", cwd=REPO_ROOT)
    assert rc == 0, err_msg(stdout, stderr)
    before = _parse_versions(stdout)

    backup = ALLOWED_HOSTS.with_name(ALLOWED_HOSTS.name + ".bak")
    shutil.copy2(ALLOWED_HOSTS, backup)
    try:
        with open(ALLOWED_HOSTS, "a") as f:
            f.write("\n# test change\n")

        stdout, stderr, rc = run("./vm_prep/base-image-version.sh .", cwd=REPO_ROOT)
        assert rc == 0, err_msg(stdout, stderr)
        after = _parse_versions(stdout)
        assert after["building-blocks"] != before["building-blocks"], (
            "building-blocks version should change"
        )
        assert after["miniconfig"] == before["miniconfig"], (
            "miniconfig version should not change"
        )
        assert after["base-image"] != before["base-image"], (
            "base-image version should include building-blocks"
        )
    finally:
        shutil.move(backup, ALLOWED_HOSTS)


def test_zaigr_inside_change_is_base_image_building_block_coupled():
    """Changing zaigr-inside changes building-blocks version but not miniconfig."""
    assert ZAIGR_INSIDE.is_file(), "zaigr-inside must be a base-image building block"

    stdout, stderr, rc = run("./vm_prep/base-image-version.sh .", cwd=REPO_ROOT)
    assert rc == 0, err_msg(stdout, stderr)
    before = _parse_versions(stdout)

    backup = ZAIGR_INSIDE.with_name(ZAIGR_INSIDE.name + ".bak")
    shutil.copy2(ZAIGR_INSIDE, backup)
    try:
        with open(ZAIGR_INSIDE, "a") as f:
            f.write("\n# test change\n")

        stdout, stderr, rc = run("./vm_prep/base-image-version.sh .", cwd=REPO_ROOT)
        assert rc == 0, err_msg(stdout, stderr)
        after = _parse_versions(stdout)
        assert after["building-blocks"] != before["building-blocks"], (
            "zaigr-inside changes must invalidate the base-image building-blocks version"
        )
        assert after["miniconfig"] == before["miniconfig"], (
            "zaigr-inside changes must not change miniconfig version"
        )
        assert after["base-image"] != before["base-image"], (
            "zaigr-inside changes must invalidate the combined base-image version"
        )
    finally:
        shutil.move(backup, ZAIGR_INSIDE)


def test_base_image_allows_debian_fastly_dns_and_does_not_force_ipv4():
    """The base image keeps IPv6 enabled and allows Debian's Fastly DNS mapping host."""
    allowed_hosts = ALLOWED_HOSTS.read_text(encoding="utf-8").splitlines()

    assert DEBIAN_FASTLY_DNS_HOST in allowed_hosts
    assert not APT_FORCE_IPV4_CONF.exists(), (
        "/etc/apt/apt.conf.d/99zaigr-force-ipv4 must not be present; apt should not force IPv4"
    )
