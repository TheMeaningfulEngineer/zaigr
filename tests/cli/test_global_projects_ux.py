"""Acceptance coverage for global project presentation and selectors."""

import re
from pathlib import Path

import pytest

from ..conftest import ProjectTestEnv, err_msg
from ..conftest import run as _run


@pytest.fixture
def metadata_projects(test_root, zaigr_bin, zaigr_home):
    projects = []
    for name in ("damaged", "healthy"):
        cwd = test_root / name
        cwd.mkdir()
        project = ProjectTestEnv(cwd, Path(zaigr_bin), Path(zaigr_home))
        projects.append((project, _seed_store(project)))
    return projects


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


def test_global_projects_list_help_and_empty_inventory(zaigr_bin, zaigr_home, tmp_path):
    env = {"HOME": str(zaigr_home)}

    stdout, stderr, rc = _run(
        [zaigr_bin, "global", "projects", "list", "--help"],
        cwd=tmp_path,
        env=env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "--full-paths" in stdout
    assert "--show-base-image" in stdout
    assert "List projects and their VM resources" in stdout

    stdout, stderr, rc = _run(
        [zaigr_bin, "global", "projects", "list"],
        cwd=tmp_path,
        env=env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "PROJECT" in stdout
    assert "STATUS" in stdout
    assert "DISK USED" in stdout


def test_global_projects_list_shows_base_runtime_and_continues_after_unknown_metadata(
    metadata_projects, test_root, zaigr_bin, zaigr_home, tmp_path
):
    """The optional base columns expose known versions and preserve unknown rows."""
    (matching, matching_store), (outdated, outdated_store) = metadata_projects
    unknown_dir = test_root / "unknown"
    unreadable_dir = test_root / "unreadable"
    unknown_dir.mkdir()
    unreadable_dir.mkdir()
    unknown = ProjectTestEnv(unknown_dir, Path(zaigr_bin), Path(zaigr_home))
    unreadable = ProjectTestEnv(unreadable_dir, Path(zaigr_bin), Path(zaigr_home))
    _seed_store(unknown)
    unreadable_store = _seed_store(unreadable)

    version_output, stderr, rc = _run(
        [zaigr_bin, "misc", "full-version"],
        cwd=tmp_path,
        env={"HOME": str(zaigr_home)},
        timeout=10,
    )
    assert rc == 0, err_msg(version_output, stderr)
    required_base = next(
        line.split(": ", 1)[1]
        for line in version_output.splitlines()
        if line.startswith("base-image: ")
    )
    (matching_store / "base-image-version").write_text(
        f"{required_base}\n", encoding="utf-8"
    )
    (outdated_store / "base-image-version").write_text("older-runtime\n", encoding="utf-8")
    (unreadable_store / "base-image-version").mkdir()

    regular, stderr, rc = _run(
        [zaigr_bin, "global", "projects", "list"],
        cwd=tmp_path,
        env={"HOME": str(zaigr_home)},
        timeout=10,
    )
    assert rc == 0, err_msg(regular, stderr)
    assert regular.splitlines()[0].split() == [
        "PROJECT", "STATUS", "CPU", "RAM", "DISK", "USED", "ID"
    ]
    outdated_row = next(line for line in regular.splitlines() if line.startswith(outdated.cwd.name))
    assert outdated_row.split()[1:3] == ["off,", "outdated"]
    assert "BASE IMAGE" not in regular

    shown, stderr, rc = _run(
        [
            zaigr_bin,
            "global",
            "projects",
            "list",
            "--full-paths",
            "--show-base-image",
        ],
        cwd=tmp_path,
        env={"HOME": str(zaigr_home)},
        timeout=10,
    )
    assert rc == 0, err_msg(shown, stderr)
    assert shown.splitlines()[0].split() == [
        "PROJECT",
        "STATUS",
        "CPU",
        "RAM",
        "DISK",
        "USED",
        "BASE",
        "IMAGE",
        "REQUIRED",
        "BASE",
        "ID",
    ]
    assert str(matching.cwd) in shown
    rows = {
        project.cwd.name: next(
            line.split()
            for line in shown.splitlines()
            if line.startswith(str(project.cwd))
        )
        for project in (matching, outdated, unknown, unreadable)
    }
    assert rows[matching.cwd.name][-3:-1] == [required_base, required_base]
    assert rows[outdated.cwd.name][-3:-1] == ["older-runtime", required_base]
    assert rows[unknown.cwd.name][-3:-1] == ["?", required_base]
    assert rows[unreadable.cwd.name][-3:-1] == ["?", required_base]
    assert rows[matching.cwd.name][1] == "off"
    assert rows[unknown.cwd.name][1] == "off"
    assert rows[unreadable.cwd.name][1] == "off"
    assert "recorded base image version" in stderr
    assert unreadable_store.name in stderr


def test_global_projects_details_resolves_name_and_id_and_documents_selector_rule(
    metadata_projects, tmp_path
):
    (project, first), _ = metadata_projects
    first_name = project.cwd.name
    run_env = project.env
    zaigr = project.zaigr_bin

    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "details", "--help"],
        cwd=tmp_path,
        env=run_env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "Show details about one project" in stdout

    by_name, stderr, rc = _run(
        [zaigr, "global", "projects", "details", first_name],
        cwd=tmp_path,
        env=run_env,
        timeout=10,
    )
    assert rc == 0, err_msg(by_name, stderr)
    by_id, stderr, rc = _run(
        [zaigr, "global", "projects", "details", first.name],
        cwd=tmp_path,
        env=run_env,
        timeout=10,
    )
    assert rc == 0, err_msg(by_id, stderr)
    assert "project:" in by_name
    assert "status:" in by_name
    assert "disk usage:" in by_name or "disk:" in by_name
    assert by_id == by_name


def test_global_projects_ambiguous_name_reports_ids_without_mutation(
    test_root, zaigr_bin, zaigr_home, tmp_path
):
    first_dir = test_root / "one" / "same-name"
    second_dir = test_root / "two" / "same-name"
    first_dir.mkdir(parents=True)
    second_dir.mkdir(parents=True)
    first = ProjectTestEnv(first_dir, Path(zaigr_bin), Path(zaigr_home))
    second = ProjectTestEnv(second_dir, Path(zaigr_bin), Path(zaigr_home))
    first_store = _seed_store(first)
    second_store = _seed_store(second)
    before = {
        first_store: sorted(
            path.relative_to(first_store).as_posix() for path in first_store.rglob("*")
        ),
        second_store: sorted(
            path.relative_to(second_store).as_posix() for path in second_store.rglob("*")
        ),
    }

    stdout, stderr, rc = _run(
        [zaigr_bin, "global", "projects", "details", "same-name"],
        cwd=tmp_path,
        env=first.env,
        timeout=10,
    )
    assert rc != 0
    combined = stdout + stderr
    assert "ambiguous" in combined.lower()
    assert first_store.name in combined
    assert second_store.name in combined
    assert before[first_store] == sorted(
        path.relative_to(first_store).as_posix() for path in first_store.rglob("*")
    )
    assert before[second_store] == sorted(
        path.relative_to(second_store).as_posix() for path in second_store.rglob("*")
    )


def test_global_projects_list_reports_allocated_store_usage_not_virtual_capacity(
    project, tmp_path
):
    store = _seed_store(project)
    sparse_image = store / "project.qcow2"
    with sparse_image.open("wb") as image:
        image.truncate(100 * 1024 * 1024 * 1024)
    agent_state = store / "agent-state"
    logs = store / "logs"
    agent_state.mkdir()
    logs.mkdir()
    (agent_state / "state").write_bytes(b"state" * 4096)
    (logs / "run.log").write_bytes(b"log" * 4096)
    outside = tmp_path / "outside-data"
    outside.write_bytes(b"outside" * 4096)
    (store / "outside-link").symlink_to(outside)
    (store / "hard-link").hardlink_to(agent_state / "state")

    expected, stderr, rc = _run(
        ["du", "-sx", "--block-size=1024", str(store)],
        cwd=tmp_path,
        env=project.env,
        timeout=10,
    )
    assert rc == 0, err_msg(expected, stderr)
    expected_blocks = int(expected.split()[0])

    stdout, stderr, rc = _run(
        [project.zaigr_bin, "global", "projects", "list"],
        cwd=tmp_path,
        env=project.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    row = next(line for line in stdout.splitlines() if line.startswith(project.cwd.name))
    assert "100G" not in row
    fields = row.split()
    assert fields[-1] == store.name
    disk_value = fields[-2]
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMGT]iB|B)", disk_value)
    assert match, row
    units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    displayed_bytes = float(match.group(1)) * units[match.group(2)]
    oracle_bytes = expected_blocks * 1024
    rounding_unit = units[match.group(2)]
    assert abs(displayed_bytes - oracle_bytes) <= rounding_unit / 2 + rounding_unit


@pytest.mark.parametrize("command", ["details", "kill", "rebuild"])
def test_global_projects_completion_includes_names_and_ids(metadata_projects, tmp_path, command):
    (project, first), (other_project, second) = metadata_projects
    stdout, stderr, rc = _run(
        [project.zaigr_bin, "__complete", "global", "projects", command, ""],
        cwd=tmp_path,
        env=project.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert first.name in stdout
    assert second.name in stdout
    assert project.cwd.name in stdout
    assert other_project.cwd.name in stdout
