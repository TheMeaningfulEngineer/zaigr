"""Development and base image version tests."""

import shutil
from functools import partial
from pathlib import Path

import pytest

from ..conftest import REPO_ROOT, VM_DATA, VM_PREP, err_msg, run

MINICONFIG = Path(VM_DATA) / "miniconfig"
BASE_IMAGE_BUILD = Path(VM_PREP) / "base-image-building-blocks" / "build.sh"


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


def _checked_run(command, cwd):
    """Run a command in the test repository and return successful stdout."""
    stdout, stderr, rc = run(command, cwd=cwd)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


@pytest.fixture
def development_repo(tmp_path):
    """Create an isolated repository with the development build helpers."""
    repo = tmp_path / "repo"
    repo.mkdir()
    script = Path(REPO_ROOT) / "release" / "dev-version.sh"
    (repo / "release").mkdir()
    shutil.copy2(script, repo / "release" / "dev-version.sh")
    shutil.copy2(Path(REPO_ROOT) / "Makefile", repo / "Makefile")
    shutil.copy2(Path(REPO_ROOT) / "deps.lock", repo / "deps.lock")
    (repo / "tracked.txt").write_text("original\n", encoding="utf-8")
    (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")

    run = partial(_checked_run, cwd=repo)
    run("git init")
    run("git config user.name Test")
    run("git config user.email test@example.com")
    run("git add .")
    run("git commit -m initial")
    return repo


def test_development_version_hashes_only_git_visible_changes(development_repo):
    """Keep the existing fingerprint for tracked and non-ignored local changes."""
    repo = development_repo
    run = partial(_checked_run, cwd=repo)
    commit = run("git rev-parse --short HEAD").strip()
    clean = run("./release/dev-version.sh").strip()
    assert clean == f"{commit}-dev-e3b0c44298fc"

    (repo / "ignored.txt").write_text("ignored change\n", encoding="utf-8")
    assert run("./release/dev-version.sh").strip() == clean

    (repo / "tracked.txt").write_text("tracked change\n", encoding="utf-8")
    tracked = run("./release/dev-version.sh").strip()
    assert tracked.startswith(f"{commit}-dev-")
    assert len(tracked.rsplit("-", 1)[1]) == 12
    assert tracked != clean

    run("git add tracked.txt")
    assert run("./release/dev-version.sh").strip() == tracked
    run("git reset HEAD tracked.txt")

    (repo / "tracked.txt").write_text("original\n", encoding="utf-8")
    assert run("./release/dev-version.sh").strip() == clean

    (repo / "untracked.txt").write_text("first change\n", encoding="utf-8")
    untracked = run("./release/dev-version.sh").strip()
    assert untracked.startswith(f"{commit}-dev-")
    assert untracked != clean

    (repo / "untracked.txt").write_text("different change\n", encoding="utf-8")
    assert run("./release/dev-version.sh").strip() != untracked


@pytest.mark.parametrize("annotated", [False, True], ids=["lightweight", "annotated"])
def test_development_version_describes_release_ancestry(development_repo, annotated):
    """Show the release base and commit distance, including builds at the tag."""
    run = partial(_checked_run, cwd=development_repo)
    if annotated:
        run("git tag -a v1.2.3 -m release")
    else:
        run("git tag v1.2.3")

    commit = run("git rev-parse --short HEAD").strip()
    assert run("./release/dev-version.sh").strip() == f"v1.2.3-0-g{commit}-dev-e3b0c44298fc"

    (development_repo / "tracked.txt").write_text("committed change\n", encoding="utf-8")
    run("git commit -am change")
    commit = run("git rev-parse --short HEAD").strip()
    assert run("./release/dev-version.sh").strip() == f"v1.2.3-1-g{commit}-dev-e3b0c44298fc"

    run("git commit --allow-empty -m another")
    commit = run("git rev-parse --short HEAD").strip()
    assert run("./release/dev-version.sh").strip() == f"v1.2.3-2-g{commit}-dev-e3b0c44298fc"

    run("git tag v1.2.4")
    assert run("./release/dev-version.sh").strip() == f"v1.2.4-0-g{commit}-dev-e3b0c44298fc"


def test_development_version_ignores_nonrelease_tags(development_repo):
    """Prerelease and unrelated tags cannot replace the released version base."""
    run = partial(_checked_run, cwd=development_repo)
    run("git tag v1.2.3")
    run("git commit --allow-empty -m development")
    run("git tag -a v2.0.0-rc.1 -m prerelease")
    run("git tag -a nightly -m nightly")
    run("git tag v2.0.0preview")
    run("git tag v2.0.0.1")
    run("git tag v02.0.0")

    commit = run("git rev-parse --short HEAD").strip()
    assert run("./release/dev-version.sh").strip() == f"v1.2.3-1-g{commit}-dev-e3b0c44298fc"


def test_development_version_without_reachable_release(development_repo, tmp_path):
    """An unrelated release branch cannot supply the base version."""
    run = partial(_checked_run, cwd=development_repo)
    commit = run("git rev-parse --short HEAD").strip()
    run("git checkout --orphan unrelated")
    run("git commit -m unrelated")
    run("git tag v9.0.0")
    run(f"git checkout --detach {commit}")

    # Also exercise the repository argument from outside the checkout.
    stdout = _checked_run(
        [str(development_repo / "release/dev-version.sh"), str(development_repo)],
        cwd=tmp_path,
    )
    assert stdout.strip() == f"{commit}-dev-e3b0c44298fc"


def test_make_uses_development_version_and_preserves_overrides(development_repo):
    """The build embeds the development version unless VERSION is supplied."""
    run = partial(_checked_run, cwd=development_repo)
    run("git tag v1.2.3")
    commit = run("git rev-parse --short HEAD").strip()
    output = run("make --dry-run build BUILD=7 BUILD_TIME=20260925-120000")
    assert f"-X main.version=v1.2.3-0-g{commit}-dev-e3b0c44298fc " in output
    assert "-X main.build=7 " in output
    assert f"-X main.commit={commit} " in output
    assert "-X main.buildTime=20260925-120000" in output

    output = run("make --dry-run build VERSION=1.2.4")
    assert "-X main.version=1.2.4 " in output


def test_make_development_version_without_git_metadata(tmp_path):
    """A source directory without Git metadata retains the unknown fallback."""
    (tmp_path / "release").mkdir()
    shutil.copy2(Path(REPO_ROOT) / "Makefile", tmp_path / "Makefile")
    shutil.copy2(Path(REPO_ROOT) / "deps.lock", tmp_path / "deps.lock")
    shutil.copy2(
        Path(REPO_ROOT) / "release/dev-version.sh", tmp_path / "release/dev-version.sh"
    )
    stdout, stderr, rc = run("make --dry-run build", cwd=tmp_path)
    assert rc == 0, err_msg(stdout, stderr)
    assert "-X main.version=dev-unknown " in stdout


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
    """Changing the rootfs builder changes building-blocks version but not miniconfig."""
    stdout, stderr, rc = run("./vm_prep/base-image-version.sh .", cwd=REPO_ROOT)
    assert rc == 0, err_msg(stdout, stderr)
    before = _parse_versions(stdout)

    backup = BASE_IMAGE_BUILD.with_name(BASE_IMAGE_BUILD.name + ".bak")
    shutil.copy2(BASE_IMAGE_BUILD, backup)
    try:
        with open(BASE_IMAGE_BUILD, "a") as f:
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
        shutil.move(backup, BASE_IMAGE_BUILD)


def test_debian_suite_change_invalidates_base_image_version(tmp_path):
    """Changing only the locked Debian suite changes the base image version."""
    repo = tmp_path / "repo"
    (repo / "vm_prep").mkdir(parents=True)
    (repo / "cmd/zaigr/vm_data").mkdir(parents=True)
    shutil.copy2(Path(VM_PREP) / "base-image-version.sh", repo / "vm_prep")
    shutil.copytree(
        Path(VM_PREP) / "base-image-building-blocks",
        repo / "vm_prep/base-image-building-blocks",
    )
    shutil.copy2(Path(REPO_ROOT) / "deps.lock", repo / "deps.lock")
    shutil.copy2(MINICONFIG, repo / "cmd/zaigr/vm_data/miniconfig")

    stdout, stderr, rc = run(
        "./vm_prep/base-image-version.sh .", cwd=repo
    )
    assert rc == 0, err_msg(stdout, stderr)
    before = _parse_versions(stdout)

    lock = repo / "deps.lock"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            "DEBIAN_SUITE=trixie", "DEBIAN_SUITE=bookworm"
        ),
        encoding="utf-8",
    )
    stdout, stderr, rc = run(
        "./vm_prep/base-image-version.sh .", cwd=repo
    )
    assert rc == 0, err_msg(stdout, stderr)
    after = _parse_versions(stdout)

    assert after["miniconfig"] == before["miniconfig"]
    assert after["building-blocks"] != before["building-blocks"]
    assert after["base-image"] != before["base-image"]
