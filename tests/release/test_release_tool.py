import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, err_msg, run

RELEASE = Path(REPO_ROOT) / "release" / "release"


def _init_git_repo(path):
    path.mkdir()
    out, err, rc = run(["git", "init"], cwd=path, timeout=10)
    assert rc == 0, err_msg(out, err)
    out, err, rc = run(["git", "config", "user.name", "zaigr tests"], cwd=path, timeout=10)
    assert rc == 0, err_msg(out, err)
    out, err, rc = run(
        ["git", "config", "user.email", "zaigr-tests@example.invalid"],
        cwd=path,
        timeout=10,
    )
    assert rc == 0, err_msg(out, err)
    (path / ".gitignore").write_text(
        "/zaigr\n/release/dist/\n/release/state/\n/release/RELEASE_NOTES.md\n",
        encoding="utf-8",
    )
    (path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    out, err, rc = run(["git", "add", ".gitignore", "tracked.txt"], cwd=path, timeout=10)
    assert rc == 0, err_msg(out, err)
    out, err, rc = run(["git", "commit", "-m", "chore: seed"], cwd=path, timeout=10)
    assert rc == 0, err_msg(out, err)


def _release_env(tmp_path):
    env = os.environ.copy()
    env["PATH"] = f"{tmp_path / 'bin'}:{env['PATH']}"
    return env


def _fake_command(bin_dir, name, body):
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / name
    path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _fake_script(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _write_fake_candidate_primitives(repo, tmp_path, go_body):
    build_kernel = _fake_script(
        repo / "vm_prep" / "build-kernel.sh",
        "printf 'build-kernel\\n' >> \"$PWD/release/state/commands.log\"\n",
    )
    build_rootfs = _fake_script(
        repo / "vm_prep" / "build-base-rootfs.sh",
        "printf 'build-base-rootfs\\n' >> \"$PWD/release/state/commands.log\"\n",
    )
    out, err, rc = run(["git", "add", build_kernel, build_rootfs], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)
    out, err, rc = run(["git", "commit", "-m", "test: fake release primitives"], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)
    bin_dir = tmp_path / "bin"
    _fake_command(bin_dir, "go", go_body)
    _fake_command(
        bin_dir,
        "git-cliff",
        """
printf 'git-cliff %s\\n' "$*" >> "$PWD/release/state/commands.log"
output=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    output="$1"
  fi
  shift || true
done
[ -n "$output" ] || exit 2
printf '# Changelog\\n' > "$output"
""",
    )
    _fake_command(
        bin_dir,
        "nfpm",
        """
printf 'VERSION=%s BUILD=%s nfpm %s\\n' "${VERSION-}" "${BUILD-}" "$*" >> "$PWD/release/state/commands.log"
target=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--target" ]; then
    shift
    target="$1"
  fi
  shift || true
done
[ -n "$target" ] || exit 2
mkdir -p "$(dirname "$target")"
printf 'artifact\\n' > "$target"
""",
    )


def _write_candidate(repo, version, build, status="verified"):
    candidate = repo / "release/state" / "candidates" / f"{version}-{build}"
    (candidate / "dist").mkdir(parents=True)
    (candidate / "transcripts").mkdir()
    (candidate / "test-results").mkdir()
    (candidate / "changelog.md").write_text("release notes\n", encoding="utf-8")
    artifact = candidate / "dist" / f"zaigr_{version}-{build}_amd64.deb"
    artifact.write_text("artifact\n", encoding="utf-8")
    binary = _fake_script(candidate / "zaigr", "printf 'candidate binary\\n'\n")
    out, err, rc = run(["git", "rev-parse", "--short", "HEAD"], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)
    commit = out.strip()
    release = {
        "version": version,
        "build": build,
        "tag": f"v{version}",
        "commit": commit,
        "dirty": False,
        "candidate_id": f"{version}-{build}+{commit}",
        "status": status,
        "schema": 1,
        "verified": status == "verified",
        "steps": [],
        "artifacts": [{
            "path": str(artifact),
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }],
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    (candidate / "release.json").write_text(
        json.dumps(release, indent=2) + "\n",
        encoding="utf-8",
    )
    publish = {
        "asset_uploads": [],
        "github_release_created": False,
        "local_tag_created": False,
        "publish_complete": False,
        "remote_tag_pushed": False,
        "schema": 1,
    }
    (candidate / "publish.json").write_text(
        json.dumps(publish, indent=2) + "\n",
        encoding="utf-8",
    )
    return candidate


def _write_active_candidate(repo, version, build):
    active = {
        "build": build,
        "candidate": f"{version}-{build}",
        "schema": 1,
        "version": version,
    }
    path = repo / "release/state" / "active.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(active, indent=2) + "\n", encoding="utf-8")


@pytest.mark.parametrize("version", ["v1.0.0", "1.0", "1.0.0-rc1", "latest"])
def test_candidate_rejects_bad_versions(tmp_path, version):
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    out, err, rc = run(
        [RELEASE, "candidate", version],
        cwd=repo,
        env=_release_env(tmp_path),
        timeout=10,
    )

    assert rc != 0
    combined = out + err
    assert "invalid release version" in combined
    assert "MAJOR.MINOR.PATCH" in combined
    assert not (repo / "release/state").exists()


def test_candidate_summary_derives_tag_and_first_build(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go %s\\n' "$*" >> "$PWD/release/state/commands.log"
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
""",
    )

    out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "Release candidate created" in out
    assert "version:" in out and "1.0.0" in out
    assert "build:" in out and "1" in out
    assert "tag:" in out and "v1.0.0" in out
    assert "Plan" not in out
    assert "Release candidate" in err
    assert "version:" in err and "1.0.0" in err
    assert "build:" in err and "1" in err
    assert "Continue with dirty worktree?" not in err
    assert "Do you want to proceed with releasing version 1.0.0, build 1?" in err
    assert "Old builds will be wiped." in err
    assert err.index("Release candidate") < err.index("Do you want to proceed")
    assert ":: Build zaigr binary" in err
    assert "Artifacts" in out
    assert "zaigr_1.0.0-1_amd64.deb" in out
    release = json.loads(
        (repo / "release/state" / "candidates" / "1.0.0-1" / "release.json").read_text(
            encoding="utf-8"
        )
    )
    assert release["status"] == "candidate"
    assert release["dirty"] is False
    assert any(artifact["path"].endswith("_amd64.deb") for artifact in release["artifacts"])
    candidate = repo / "release/state" / "candidates" / "1.0.0-1"
    standalone = candidate / "dist" / "zaigr"
    assert standalone.read_bytes() == b"#!/bin/sh\nexit 0\n"
    assert standalone.read_bytes() == (candidate / "zaigr").read_bytes()
    assert os.access(standalone, os.X_OK)
    artifact = next(item for item in release["artifacts"] if Path(item["path"]) == standalone)
    digest = hashlib.sha256(standalone.read_bytes()).hexdigest()
    assert artifact["sha256"] == digest == release["binary_sha256"]
    checksums = (candidate / "checksums.txt").read_text(encoding="utf-8")
    assert f"{digest}  release/dist/zaigr\n" in checksums

    out, err, rc = run([standalone], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)

    active = json.loads((repo / "release/state" / "active.json").read_text(encoding="utf-8"))
    assert active["candidate"] == "1.0.0-1"


def test_candidate_records_plain_commit_when_worktree_is_dirty(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go %s\\n' "$*" >> "$PWD/release/state/commands.log"
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
""",
    )
    (repo / "tracked.txt").write_text("tracked\nlocal change\n", encoding="utf-8")
    out, err, rc = run(["git", "rev-parse", "--short", "HEAD"], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)
    head = out.strip()

    out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\ny\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "Worktree is dirty for candidate 1.0.0-1." in err
    assert "artifacts may include uncommitted changes" in err
    assert "Continue with dirty worktree? [y/N]" in err
    assert err.index("Continue with dirty worktree") < err.index("Do you want to proceed")
    release = json.loads(
        (repo / "release/state" / "candidates" / "1.0.0-1" / "release.json").read_text(
            encoding="utf-8"
        )
    )
    assert release["commit"] == head
    assert release["dirty"] is True


def test_candidate_dirty_cancel_refuses_before_creating_state_or_wiping_outputs(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go %s\\n' "$*" >> "$PWD/release/state/commands.log"
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
""",
    )
    (repo / "tracked.txt").write_text("tracked\nlocal change\n", encoding="utf-8")
    (repo / "release" / "dist").mkdir(parents=True)
    (repo / "release" / "dist" / "old.deb").write_text("old artifact\n", encoding="utf-8")
    (repo / "release" / "RELEASE_NOTES.md").write_text("old notes\n", encoding="utf-8")

    _out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="n\n",
        timeout=10,
    )

    assert rc != 0
    assert "Worktree is dirty for candidate 1.0.0-1." in err
    assert "dirty release candidate creation cancelled" in err
    assert "Do you want to proceed with releasing version 1.0.0, build 1?" not in err
    assert not (repo / "release/state" / "candidates" / "1.0.0-1").exists()
    assert (repo / "release" / "dist" / "old.deb").read_text(encoding="utf-8") == "old artifact\n"
    assert (repo / "release" / "RELEASE_NOTES.md").read_text(encoding="utf-8") == "old notes\n"


def test_candidate_prompts_for_version_when_omitted(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go %s\\n' "$*" >> "$PWD/release/state/commands.log"
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
""",
    )

    out, err, rc = run(
        [RELEASE, "candidate"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="1.2.3\ny\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "Release candidate version:" in err
    assert "Do you want to proceed with releasing version 1.2.3, build 1?" in err
    assert "version:" in out and "1.2.3" in out
    assert (repo / "release/state" / "candidates" / "1.2.3-1" / "release.json").exists()


def test_candidate_cancel_refuses_before_creating_state_or_wiping_outputs(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "release" / "dist").mkdir(parents=True)
    (repo / "release" / "dist" / "existing.deb").write_text("existing\n", encoding="utf-8")
    (repo / "release" / "RELEASE_NOTES.md").write_text("existing notes\n", encoding="utf-8")
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go should not run\\n' >&2
exit 99
""",
    )

    out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="n\n",
        timeout=10,
    )

    assert rc != 0
    assert out == ""
    assert "Do you want to proceed with releasing version 1.0.0, build 1?" in err
    assert "release candidate creation cancelled" in err
    assert not (repo / "release/state" / "candidates" / "1.0.0-1").exists()
    assert (repo / "release" / "dist" / "existing.deb").read_text(encoding="utf-8") == "existing\n"
    assert (repo / "release" / "RELEASE_NOTES.md").read_text(encoding="utf-8") == "existing notes\n"


def test_candidate_build_increments_from_existing_candidates(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    _write_candidate(repo, "1.0.0", 1)
    _write_candidate(repo, "1.0.0", 2)
    _write_candidate(repo, "1.0.1", 9)
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go %s\\n' "$*" >> "$PWD/release/state/commands.log"
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
""",
    )

    out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "version:" in out and "1.0.0" in out
    assert "build:" in out and "3" in out
    assert "tag:" in out and "v1.0.0" in out
    assert "Do you want to proceed with releasing version 1.0.0, build 3?" in err
    release = json.loads(
        (repo / "release/state" / "candidates" / "1.0.0-3" / "release.json").read_text(
            encoding="utf-8"
        )
    )
    assert release["status"] == "candidate"
    active = json.loads((repo / "release/state" / "active.json").read_text(encoding="utf-8"))
    assert active["candidate"] == "1.0.0-3"


def test_candidate_failure_marks_release_failed_and_keeps_transcript(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go %s\\n' "$*" >> "$PWD/release/state/commands.log"
printf 'candidate command started\\n'
exit 42
""",
    )

    out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc != 0
    combined = out + err
    assert "command failed with exit code 42" in combined
    assert ":: Build zaigr binary" in err
    assert "go build" in combined
    assert "-X main.version=1.0.0" in combined
    assert "-X main.build=1" in combined

    candidate = repo / "release/state" / "candidates" / "1.0.0-1"
    release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    transcript_path = candidate / "transcripts" / "candidate.log"
    failure = release["failure"]
    active = json.loads((repo / "release/state" / "active.json").read_text(encoding="utf-8"))

    assert release["status"] == "failed"
    assert release["failed"] is True
    assert active["candidate"] == "1.0.0-1"
    assert failure["stage"] == "candidate"
    assert "command failed with exit code 42" in failure["error"]
    assert failure["command_display"] == "Build zaigr binary"
    assert Path(failure["transcript_path"]) == transcript_path
    assert transcript_path.is_file()
    transcript = transcript_path.read_text(encoding="utf-8")
    assert ":: Checking release tools" in transcript
    assert f"{repo}$ go build" in transcript
    assert "candidate command started" in transcript
    assert "git-cliff --config release/cliff.toml --tag v1.0.0 --output release/RELEASE_NOTES.md" not in transcript


def test_candidate_after_failed_candidate_reports_failure_and_creates_next_build(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  *main.build=1*)
    printf 'build 1 failed\\n'
    exit 42
    ;;
esac
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
""",
    )

    out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )
    assert rc != 0
    assert "command failed with exit code 42" in out + err
    failed_candidate = repo / "release/state" / "candidates" / "1.0.0-1"
    failed_release = json.loads(
        (failed_candidate / "release.json").read_text(encoding="utf-8")
    )
    failed_transcript = Path(failed_release["failure"]["transcript_path"])

    out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    next_candidate = repo / "release/state" / "candidates" / "1.0.0-2"
    next_release = json.loads(
        (next_candidate / "release.json").read_text(encoding="utf-8")
    )

    assert "Previous failed candidate" in err
    assert "candidate:  1.0.0-1" in err
    assert f"transcript: {failed_transcript}" in err
    assert err.index("Previous failed candidate") < err.index("Release candidate")
    assert err.index("Release candidate") < err.index("Do you want to proceed")
    assert "build:" in out and "2" in out
    assert f"candidate_dir: {next_candidate}" in out
    assert "Do you want to proceed with releasing version 1.0.0, build 2?" in err
    assert ":: Build zaigr binary" in err
    assert ":: Generate release notes" in err
    assert ":: Build Debian package" in err
    assert next_release["status"] == "candidate"


def test_candidate_reports_candidate_local_transcript_when_failed_metadata_is_stale(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    failed_candidate = _write_candidate(repo, "1.0.0", 1, status="failed")
    failed_transcript = failed_candidate / "transcripts" / "candidate.log"
    failed_transcript.write_text("failed transcript\n", encoding="utf-8")
    failed_release_path = failed_candidate / "release.json"
    failed_release = json.loads(failed_release_path.read_text(encoding="utf-8"))
    failed_release["failed"] = True
    failed_release["failure"] = {
        "command_display": "Old release tooling",
        "error": "old failure",
        "stage": "candidate",
        "transcript_path": "/old/worktree/.release/candidates/1.0.0-1/transcripts/candidate.log",
    }
    failed_release_path.write_text(json.dumps(failed_release, indent=2) + "\n", encoding="utf-8")
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go %s\\n' "$*" >> "$PWD/release/state/commands.log"
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
""",
    )

    out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "Previous failed candidate" in err
    assert f"transcript: {failed_transcript}" in err
    assert "/old/worktree/.release" not in err


def test_verify_refuses_missing_active_candidate(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    out, err, rc = run(
        [RELEASE, "verify"],
        cwd=repo,
        env=_release_env(tmp_path),
        timeout=10,
    )

    assert rc != 0
    assert "missing state file" in out + err
    assert "release/state/active.json" in out + err


def test_verify_replaces_running_candidate_binary_without_writing_to_it(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="candidate")
    _write_active_candidate(repo, "1.0.0", 1)
    saved_binary = (candidate / "zaigr").read_bytes()
    shutil.copy2("/bin/sleep", repo / "zaigr")
    _fake_command(
        tmp_path / "bin",
        "make",
        "printf 'make %s\\n' \"$*\" >> \"$PWD/release/state/commands.log\"\n",
    )
    # Keep an actual executable inode busy while verify replaces its path.
    running = subprocess.Popen(
        [repo / "zaigr", "30"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        out, err, rc = run(
            [RELEASE, "verify"],
            cwd=repo,
            env=_release_env(tmp_path),
            input="y\n",
            timeout=10,
        )
        assert running.poll() is None
    finally:
        running.terminate()
        running.wait(timeout=5)

    combined = out + err
    assert rc == 0, err_msg(out, err)
    assert "Candidate verified:" in combined
    assert (repo / "zaigr").read_bytes() == saved_binary
    release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    assert release["status"] == "verified"
    assert "Traceback" not in combined


def test_verify_uses_active_candidate_and_records_verification(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="candidate")
    _write_active_candidate(repo, "1.0.0", 1)
    (repo / "release" / "RELEASE_NOTES.md").write_text("stale notes\n", encoding="utf-8")
    (candidate / "transcripts" / "verify.log").write_text("stale transcript\n", encoding="utf-8")
    _fake_command(
        tmp_path / "bin",
        "make",
        """
test "$ZAIGR_TEST_BINARY" = "$PWD/release/state/candidates/1.0.0-1/zaigr"
"$ZAIGR_TEST_BINARY"
printf 'make %s\\n' "$*" >> "$PWD/release/state/commands.log"
""",
    )

    out, err, rc = run(
        [RELEASE, "verify"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "Active release candidate" in err
    assert "version:" in err and "1.0.0" in err
    assert "build:" in err and "1" in err
    assert "status:" in err and "candidate" in err
    assert "Detected active candidate 1.0.0-1." in err
    assert "Do you want to proceed with verifying version 1.0.0, build 1?" in err
    assert "Verifying candidate:" in err
    assert "make test-all" in err
    assert "Candidate verified:" in out
    release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    assert release["status"] == "verified"
    assert release["verified"] is True
    assert "verified_at" in release
    evidence = json.loads((candidate / "verification.json").read_text(encoding="utf-8"))
    assert evidence["status"] == "passed"
    assert evidence["inputs"]["binary_sha256"] == hashlib.sha256(
        (candidate / "zaigr").read_bytes()
    ).hexdigest()
    assert evidence["inputs"]["test_commit"] == release["commit"]
    assert evidence["environment"]["ZAIGR_TEST_BINARY"] == str(candidate / "zaigr")
    transcript = (candidate / "transcripts" / "verify.log").read_text(encoding="utf-8")
    assert "stale transcript" not in transcript
    assert "make test-all" in transcript
    assert (repo / "release" / "RELEASE_NOTES.md").read_text(encoding="utf-8") == "release notes\n"
    assert (repo / "release" / "dist" / "zaigr_1.0.0-1_amd64.deb").read_text(encoding="utf-8") == "artifact\n"


@pytest.mark.parametrize("change", ["binary", "artifact", "tracked-source", "new-test", "failure"])
def test_verify_rejects_changed_inputs_and_failed_suite(tmp_path, change):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="candidate")
    _write_active_candidate(repo, "1.0.0", 1)
    actions = {
        "binary": 'printf changed >> "$ZAIGR_TEST_BINARY"\n',
        "artifact": 'printf changed >> release/dist/zaigr_1.0.0-1_amd64.deb\n',
        "tracked-source": "printf changed >> tracked.txt\n",
        "new-test": "mkdir -p tests; printf changed > tests/new_test.py\n",
        "failure": "exit 17\n",
    }
    _fake_command(tmp_path / "bin", "make", actions[change])

    out, err, rc = run(
        [RELEASE, "verify"], cwd=repo, env=_release_env(tmp_path), input="y\n", timeout=10
    )

    assert rc != 0, err_msg(out, err)
    release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    assert release["status"] == "candidate"
    assert release["verified"] is False
    evidence = json.loads((candidate / "verification.json").read_text(encoding="utf-8"))
    assert evidence["status"] == "failed"
    assert evidence["error"]
    assert (candidate / "transcripts" / "verify.log").is_file()


def test_verify_cancel_leaves_active_candidate_unverified(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="candidate")
    _write_active_candidate(repo, "1.0.0", 1)
    _fake_command(
        tmp_path / "bin",
        "make",
        "printf 'make should not run\\n' >&2\nexit 99\n",
    )

    out, err, rc = run(
        [RELEASE, "verify"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="n\n",
        timeout=10,
    )

    assert rc != 0
    assert out == ""
    assert "Detected active candidate 1.0.0-1." in err
    assert "verifying cancelled" in err
    release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    assert release["status"] == "candidate"
    assert release["verified"] is False
    assert not (candidate / "transcripts" / "verify.log").exists()


def test_publish_refuses_missing_active_candidate(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        timeout=10,
    )

    assert rc != 0
    assert "missing state file" in out + err
    assert "release/state/active.json" in out + err


def test_publish_uses_active_candidate_and_records_progress(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="verified")
    _write_active_candidate(repo, "1.0.0", 1)
    original_release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    commit = original_release["commit"]
    bin_dir = tmp_path / "bin"
    _fake_command(
        bin_dir,
        "git",
        """
printf 'git %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "ls-remote --tags origin refs/tags/v1.0.0 refs/tags/v1.0.0^{}") exit 0 ;;
  "tag v1.0.0 "*) exit 0 ;;
  "push origin v1.0.0") exit 0 ;;
  *) exec /usr/bin/git "$@" ;;
esac
""",
    )
    _fake_command(
        bin_dir,
        "gh",
        """
printf 'gh %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "release view v1.0.0 --json isDraft,isPrerelease,assets") exit 1 ;;
  "release create v1.0.0 "*) exit 0 ;;
  *) exit 64 ;;
esac
""",
    )

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "Active release candidate" in err
    assert "version:" in err and "1.0.0" in err
    assert "build:" in err and "1" in err
    assert "status:" in err and "verified" in err
    assert "Detected active candidate 1.0.0-1." in err
    assert "Do you want to proceed with publishing version 1.0.0, build 1?" in err
    assert "Publishing candidate:" in err
    assert f"git tag v1.0.0 {commit}" in err
    assert "gh release create v1.0.0" in err
    assert "Published: v1.0.0" in out
    release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    publish = json.loads((candidate / "publish.json").read_text(encoding="utf-8"))
    assert release["status"] == "published"
    assert publish["local_tag_created"] is True
    assert publish["remote_tag_pushed"] is True
    assert publish["github_release_created"] is True
    assert publish["publish_complete"] is True
    assert publish["asset_uploads"] == ["zaigr_1.0.0-1_amd64.deb"]


def test_publish_resumes_when_local_tag_already_exists(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="verified")
    release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    _write_active_candidate(repo, "1.0.0", 1)
    out, err, rc = run(["git", "tag", "v1.0.0", release["commit"]], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)
    bin_dir = tmp_path / "bin"
    _fake_command(
        bin_dir,
        "git",
        """
printf 'git %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "ls-remote --tags origin refs/tags/v1.0.0 refs/tags/v1.0.0^{}") exit 0 ;;
  "tag v1.0.0 "*) exit 64 ;;
  "push origin v1.0.0") exit 0 ;;
  *) exec /usr/bin/git "$@" ;;
esac
""",
    )
    _fake_command(
        bin_dir,
        "gh",
        """
printf 'gh %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "release view v1.0.0 --json isDraft,isPrerelease,assets") exit 1 ;;
  "release create v1.0.0 "*) exit 0 ;;
  *) exit 64 ;;
esac
""",
    )

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "Local tag v1.0.0 already exists" in err
    assert f"git tag v1.0.0 {release['commit']}" not in err
    assert "git push origin v1.0.0" in err
    assert "Published: v1.0.0" in out


def test_publish_refuses_existing_local_tag_for_different_commit(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="verified")
    _write_active_candidate(repo, "1.0.0", 1)
    (repo / "tracked.txt").write_text("tracked\nother commit\n", encoding="utf-8")
    out, err, rc = run(["git", "add", "tracked.txt"], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)
    out, err, rc = run(["git", "commit", "-m", "test: conflicting tag"], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)
    out, err, rc = run(["git", "tag", "v1.0.0", "HEAD"], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc != 0
    combined = out + err
    assert "local tag v1.0.0 points to" in combined
    assert "expected" in combined
    assert "git push origin v1.0.0" not in err
    release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    assert release["status"] == "verified"


def test_publish_resumes_when_remote_tag_already_exists(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="verified")
    release = json.loads((candidate / "release.json").read_text(encoding="utf-8"))
    _write_active_candidate(repo, "1.0.0", 1)
    out, err, rc = run(["git", "rev-parse", release["commit"]], cwd=repo, timeout=10)
    assert rc == 0, err_msg(out, err)
    full_commit = out.strip()
    bin_dir = tmp_path / "bin"
    _fake_command(
        bin_dir,
        "git",
        f"""
printf 'git %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "ls-remote --tags origin refs/tags/v1.0.0 refs/tags/v1.0.0^{{}}")
    printf '{full_commit}\\trefs/tags/v1.0.0\\n'
    exit 0
    ;;
  "tag v1.0.0 "*) exit 0 ;;
  "push origin v1.0.0") exit 64 ;;
  *) exec /usr/bin/git "$@" ;;
esac
""",
    )
    _fake_command(
        bin_dir,
        "gh",
        """
printf 'gh %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "release view v1.0.0 --json isDraft,isPrerelease,assets") exit 1 ;;
  "release create v1.0.0 "*) exit 0 ;;
  *) exit 64 ;;
esac
""",
    )

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "Remote tag v1.0.0 already exists" in err
    assert "git push origin v1.0.0" not in err
    assert "Published: v1.0.0" in out


def test_publish_resumes_when_github_release_already_exists(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="verified")
    _write_active_candidate(repo, "1.0.0", 1)
    bin_dir = tmp_path / "bin"
    _fake_command(
        bin_dir,
        "git",
        """
printf 'git %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "ls-remote --tags origin refs/tags/v1.0.0 refs/tags/v1.0.0^{}") exit 0 ;;
  "tag v1.0.0 "*) exit 0 ;;
  "push origin v1.0.0") exit 0 ;;
  *) exec /usr/bin/git "$@" ;;
esac
""",
    )
    _fake_command(
        bin_dir,
        "gh",
        """
printf 'gh %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "release view v1.0.0 --json isDraft,isPrerelease,assets")
    printf 'warning: using cached GitHub credentials\\n' >&2
    printf '{"isDraft":false,"isPrerelease":false,"assets":[{"name":"zaigr_1.0.0-1_amd64.deb"}]}\\n'
    exit 0
    ;;
  "release edit v1.0.0 --title v1.0.0 --notes-file "*) exit 0 ;;
  "release upload v1.0.0 "*) exit 64 ;;
  "release create v1.0.0 "*) exit 64 ;;
  *) exit 64 ;;
esac
""",
    )

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "warning: using cached GitHub credentials" in err
    assert "gh release edit v1.0.0 --title v1.0.0 --notes-file" in err
    assert "GitHub release v1.0.0 already has all expected assets" in err
    assert "gh release create v1.0.0" not in err
    assert "gh release upload v1.0.0" not in err
    publish = json.loads((candidate / "publish.json").read_text(encoding="utf-8"))
    assert publish["publish_complete"] is True


def test_publish_uploads_missing_assets_to_existing_github_release(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="verified")
    _write_active_candidate(repo, "1.0.0", 1)
    bin_dir = tmp_path / "bin"
    _fake_command(
        bin_dir,
        "git",
        """
printf 'git %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "ls-remote --tags origin refs/tags/v1.0.0 refs/tags/v1.0.0^{}") exit 0 ;;
  "tag v1.0.0 "*) exit 0 ;;
  "push origin v1.0.0") exit 0 ;;
  *) exec /usr/bin/git "$@" ;;
esac
""",
    )
    _fake_command(
        bin_dir,
        "gh",
        """
printf 'gh %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "release view v1.0.0 --json isDraft,isPrerelease,assets")
    printf '{"isDraft":false,"isPrerelease":false,"assets":[]}\\n'
    exit 0
    ;;
  "release edit v1.0.0 --title v1.0.0 --notes-file "*) exit 0 ;;
  "release upload v1.0.0 "*) exit 0 ;;
  "release create v1.0.0 "*) exit 64 ;;
  *) exit 64 ;;
esac
""",
    )

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert "gh release edit v1.0.0 --title v1.0.0 --notes-file" in err
    assert "gh release upload v1.0.0" in err
    assert "zaigr_1.0.0-1_amd64.deb" in err
    assert "gh release create v1.0.0" not in err
    publish = json.loads((candidate / "publish.json").read_text(encoding="utf-8"))
    assert publish["publish_complete"] is True


def test_publish_tags_clean_commit_from_legacy_dirty_candidate(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = _write_candidate(repo, "1.0.0", 1, status="verified")
    release_path = candidate / "release.json"
    release = json.loads(release_path.read_text(encoding="utf-8"))
    clean_commit = release["commit"]
    release["commit"] = f"{clean_commit}-dirty"
    release["dirty"] = True
    release_path.write_text(json.dumps(release, indent=2) + "\n", encoding="utf-8")
    _write_active_candidate(repo, "1.0.0", 1)
    bin_dir = tmp_path / "bin"
    _fake_command(
        bin_dir,
        "git",
        """
printf 'git %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "ls-remote --tags origin refs/tags/v1.0.0 refs/tags/v1.0.0^{}") exit 0 ;;
  tag\\ v1.0.0\\ *-dirty) exit 64 ;;
  tag\\ v1.0.0\\ *) exit 0 ;;
  "push origin v1.0.0") exit 0 ;;
  *) exec /usr/bin/git "$@" ;;
esac
""",
    )
    _fake_command(
        bin_dir,
        "gh",
        """
printf 'gh %s\\n' "$*" >> "$PWD/release/state/commands.log"
case "$*" in
  "release view v1.0.0 --json isDraft,isPrerelease,assets") exit 1 ;;
  "release create v1.0.0 "*) exit 0 ;;
  *) exit 64 ;;
esac
""",
    )

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert f"git tag v1.0.0 {clean_commit}" in err
    assert f"git tag v1.0.0 {clean_commit}-dirty" not in err
    assert "Published: v1.0.0" in out


def test_publish_refuses_unverified_candidate(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    _write_candidate(repo, "1.0.0", 1, status="created")
    _write_active_candidate(repo, "1.0.0", 1)

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        timeout=10,
    )

    assert rc != 0
    combined = out + err
    assert "Active release candidate" in err
    assert "version:" in err and "1.0.0" in err
    assert "build:" in err and "1" in err
    assert "unverified candidate" in combined
    assert "created" in combined


def test_publish_refuses_corrupt_candidate(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    candidate = repo / "release/state" / "candidates" / "1.0.0-1"
    candidate.mkdir(parents=True)
    (candidate / "release.json").write_text("not json", encoding="utf-8")
    _write_active_candidate(repo, "1.0.0", 1)

    out, err, rc = run(
        [RELEASE, "publish"],
        cwd=repo,
        env=_release_env(tmp_path),
        timeout=10,
    )

    assert rc != 0
    assert "corrupt release state" in out + err


def test_candidate_transcript_reads_like_shell_commands(tmp_path):
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    _write_fake_candidate_primitives(
        repo,
        tmp_path,
        """
printf 'go %s\\n' "$*" >> "$PWD/release/state/commands.log"
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
""",
    )

    out, err, rc = run(
        [RELEASE, "candidate", "1.0.0"],
        cwd=repo,
        env=_release_env(tmp_path),
        input="y\n",
        timeout=10,
    )

    assert rc == 0, err_msg(out, err)
    assert ":: Checking release tools" in err
    assert ":: Build base kernel" in err
    assert ":: Build base rootfs" in err
    assert ":: Build zaigr binary" in err
    assert ":: Generate release notes" in err
    assert ":: Build Debian package" in err
    assert ":: Writing checksums" in err
    assert "go build -ldflags" not in out
    assert "nfpm package --config" not in out
    assert "Artifacts" in out
    assert "zaigr_1.0.0-1_amd64.deb" in out
    candidate = repo / "release/state" / "candidates" / "1.0.0-1"
    assert (candidate / "release.json").exists()
    transcript = (candidate / "transcripts" / "candidate.log").read_text(encoding="utf-8")
    assert ":: Checking release tools" in transcript
    assert f"{repo}$ vm_prep/build-kernel.sh" in transcript
    assert f"{repo}$ go build" in transcript
    assert "-X main.version=1.0.0" in transcript
    assert "git-cliff --config release/cliff.toml --tag v1.0.0 --output release/RELEASE_NOTES.md" in transcript
    assert ":: Writing checksums" in transcript
    checksums = (candidate / "checksums.txt").read_text(encoding="utf-8")
    assert "release/dist/zaigr_1.0.0-1_amd64.deb" in checksums
    assert "release/dist/zaigr-1.0.0-1.x86_64.rpm" in checksums
    assert "release/dist/zaigr-1.0.0-1-x86_64.pkg.tar.zst" in checksums
