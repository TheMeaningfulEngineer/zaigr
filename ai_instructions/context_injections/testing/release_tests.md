Release tests must not require real release tools or package builds. Use fake
commands in a temporary PATH for `go`, `git-cliff`, `nfpm`, `gh`, and similar
external tools.

Release tests should run `release/release` through `tests.conftest.run()` so the
command, stdin, stdout, stderr, cwd, and exit status are transcripted.

Use temporary git repositories for release scenarios. Configure local test git
identity in the temp repo before committing.

Candidate tests should assert prompt order, cancellation behavior, build number
selection, active candidate state, artifacts, checksums, and failure metadata
through the release tool's user-visible output and documented `release/state/` files.

Failure tests must assert that the candidate is marked failed, the transcript is
kept, and the next candidate preview reports the previous failed candidate.

Verify and publish tests should use the active candidate. Verification marks a
candidate verified after running fake pytest commands; publishing refuses
unverified candidates and records publish progress.

Canonical examples:

- Release test file: `tests/release/test_release_tool.py`
- Release workflow docs: `docs/releasing.md`
- Release tool state handling: `release/release`

Canonical helpers in `tests/release/test_release_tool.py`:

- `_init_git_repo()` creates an isolated temp git repo with local identity.
- `_release_env()` prepends the temp fake-command directory to PATH.
- `_fake_command()` and `_fake_script()` create executable shell fakes.
- `_write_fake_candidate_primitives()` replaces candidate build primitives with
  fast transcript-friendly commands.
- `_write_candidate()` and `_write_active_candidate()` seed documented release
  state when the test subject is verify or publish behavior.
