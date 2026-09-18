"""Metadata-only edge coverage for global project selectors and disk inspection.

These fixtures deliberately seed project-store metadata rather than booting VMs:
the cases exercise name/ID resolution, completion presentation, bounded host
traversal, and capture-marker handling. VM lifecycle behavior remains covered by
the real-VM global recovery and rebuild tests.
"""

import os
from pathlib import Path

import pytest

from ..conftest import ProjectTestEnv, err_msg
from ..conftest import run as _run


def _seed_store(project, project_path=None):
    project_path = project_path or project.cwd
    store = project.store_dir
    store.mkdir(parents=True, exist_ok=True)
    (store / "project-path").write_text(f"{project_path}\n", encoding="utf-8")
    (store / "ram").write_text("512\n", encoding="utf-8")
    (store / "cpus").write_text("1\n", encoding="utf-8")
    (store / "config").write_text("disk=100G\n", encoding="utf-8")
    (store / "image-format").write_text("direct-base-v1\n", encoding="utf-8")
    return store


def _new_project(test_root, zaigr_bin, zaigr_home, name):
    cwd = test_root / name
    cwd.mkdir(parents=True, exist_ok=True)
    project = ProjectTestEnv(cwd, Path(zaigr_bin), Path(zaigr_home))
    store = _seed_store(project)
    return project, store


def test_exact_id_wins_over_identical_basename_and_completion_describes_id(
    test_root, zaigr_bin, zaigr_home, tmp_path
):
    first, first_store = _new_project(test_root, zaigr_bin, zaigr_home, "friendly")
    second, _second_store = _new_project(test_root, zaigr_bin, zaigr_home, first_store.name)

    stdout, stderr, rc = _run(
        [first.zaigr_bin, "global", "projects", "details", first_store.name],
        cwd=tmp_path,
        env=first.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert f"project: {first.cwd}" in stdout
    assert f"project: {second.cwd}" not in stdout

    stdout, stderr, rc = _run(
        [first.zaigr_bin, "__complete", "global", "projects", "details", ""],
        cwd=tmp_path,
        env=first.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    id_line = next(line for line in stdout.splitlines() if line.startswith(first_store.name + "\t"))
    assert str(first.cwd) in id_line
    assert first_store.name in id_line
    assert str(second.cwd) not in id_line
    # The basename equal to a persisted ID is reserved for the ID and is not
    # emitted as a second, potentially misleading name completion.
    assert sum(line.startswith(first_store.name + "\t") for line in stdout.splitlines()) == 1


def test_names_with_spaces_and_repeated_name_id_selectors_are_usable(
    test_root, zaigr_bin, zaigr_home, tmp_path
):
    project, store = _new_project(test_root, zaigr_bin, zaigr_home, "name with spaces")

    stdout, stderr, rc = _run(
        [project.zaigr_bin, "global", "projects", "details", project.cwd.name],
        cwd=tmp_path,
        env=project.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert f"project: {project.cwd}" in stdout

    stdout, stderr, rc = _run(
        [
            project.zaigr_bin,
            "global",
            "projects",
            "details",
            project.cwd.name,
            store.name,
            project.cwd.name,
        ],
        cwd=tmp_path,
        env=project.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert stdout.count("project-label:") == 1

    stdout, stderr, rc = _run(
        [
            project.zaigr_bin,
            "global",
            "projects",
            "kill",
            project.cwd.name,
            store.name,
            project.cwd.name,
        ],
        cwd=tmp_path,
        env=project.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert stdout.count(store.name + ": already off") == 1


def test_ambiguous_name_is_not_offered_but_each_id_is(
    test_root, zaigr_bin, zaigr_home, tmp_path
):
    first, first_store = _new_project(test_root / "one", zaigr_bin, zaigr_home, "same name")
    _second, second_store = _new_project(test_root / "two", zaigr_bin, zaigr_home, "same name")

    stdout, stderr, rc = _run(
        [first.zaigr_bin, "__complete", "global", "projects", "details", ""],
        cwd=tmp_path,
        env=first.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert first_store.name in stdout
    assert second_store.name in stdout
    assert not any(line.startswith("same name\t") for line in stdout.splitlines())


def test_unreadable_subtree_and_nonregular_capture_keep_other_rows_usable(
    test_root, zaigr_bin, zaigr_home, tmp_path
):
    if os.geteuid() == 0:
        pytest.skip("permission-denied traversal requires a nonroot test user")

    broken, broken_store = _new_project(test_root, zaigr_bin, zaigr_home, "broken disk")
    healthy, _healthy_store = _new_project(test_root, zaigr_bin, zaigr_home, "healthy disk")
    unreadable = broken_store / "unreadable"
    unreadable.mkdir()
    (unreadable / "payload").write_bytes(b"payload")
    capture = broken_store / "setup-capture.json"
    os.mkfifo(capture)
    unreadable.chmod(0)
    try:
        stdout, stderr, rc = _run(
            [broken.zaigr_bin, "global", "projects", "list"],
            cwd=tmp_path,
            env=broken.env,
            timeout=10,
        )
        assert rc == 0, err_msg(stdout, stderr)
        broken_row = next(line for line in stdout.splitlines() if line.startswith(broken.cwd.name))
        healthy_row = next(line for line in stdout.splitlines() if line.startswith(healthy.cwd.name))
        assert "?" in broken_row
        assert "?" not in healthy_row
        assert "capture" in broken_row
        assert broken_store.name in stderr
        assert "capture metadata is not a regular file" in stderr
    finally:
        unreadable.chmod(0o700)
        capture.unlink(missing_ok=True)
