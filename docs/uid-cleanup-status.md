# UID cleanup implementation and evidence

This document records the bounded removal of the old host-UID image rewrite.
The implementation keeps the manifest field as a backward-compatible
tombstone and leaves guest identity discovery and virtiofs translation intact.

## Pre-deletion gate

The translation test passed on unchanged production source revision
`18f313664ab95bf6830f860c3024b9dc332864f9`, with an empty production diff.
The test-only acceptance run passed 4/4 cases in 249.40 seconds, covering
`namespace` and `none` sandbox modes with host identities `1001:1000` and
`2000:2300` against guest identity `1000:1001`. On both workspace and
agent-state, it verified host-created `0600` files could be read and
overwritten by the guest, and guest-created replies were readable by the host
with host UID/GID ownership.

Evidence is under `/var/tmp/zaigr-uid-cleanup-evidence/`: the unchanged binary
is `zaigr-before`, its SHA-256 is recorded in `baseline.sha256`, its source
revision is in `baseline.revision`, and `baseline-production.diff` is empty.
The passing run's command transcript and XML are `pre-deletion.log` and
`pre-deletion.xml`. The initially failed setup attempt is retained separately
as `pre-deletion-attempt1.log` and `pre-deletion-attempt1.xml`; it failed
before the behavior under test because the project had not been initialized.

## Manifest decisions

- `UserUID` range validation remains because the serialized field is retained
  as a compatibility tombstone.
- A runtime-mismatched manifest with no applied setup records selects the
  current factory image. The manifest loader already validates that firewall
  groups refer to applied setup names and that their union matches the
  top-level firewall list. The old revision remains available to projects
  pinned to it.
- Status reports factory mode when no custom manifest exists or when the
  manifest has no applied setup records.
- Publishing a descendant custom base copies `previous.UserUID` unchanged.
  A new factory-derived base does not write the caller's UID. This preserves
  readable same-account downgrade metadata without claiming cross-account
  downgrade support.

## Test disposition

`tests/install/test_uid_matched_base.py` is replaced by
`tests/install/test_virtiofs_uid_identity.py`; the focused replacement
translation test is `tests/install/test_uid_translation.py`.

- `test_root_caller_uses_factory_guest_identity_for_both_shares` is retained
  in the renamed identity file. It continues to cover root-invoked shared
  mounts, guest-root writes, and host-visible ownership.
- `test_restricted_namespace_requires_consent_and_remembers_project_choice`
  is retained as `test_namespace_consent_survives_restarts_and_rebuilds`.
  Its guest identity assertion now expects the image's UID 1000 rather than
  the old migration target 2000.
- `test_uid_matched_base_workspace_state_restart_and_reset` is removed because
  it centered on automatic UID preparation and its four host UID/GID matrix.
  The replacement translation acceptance covers private host-created files,
  guest overwrite, guest-created replies, and host UID/GID ownership on both
  shared mounts. The removed test's symlink-specific identity assertions do
  not have a replacement in this focused suite. Independent recovery tests in
  `tests/cli/test_virtiofs_recovery.py` check workspace and agent-state
  preservation during refused cleanup, and workspace persistence across VM
  restart. Those checks do not exercise the removed host-UID matrix.
- `test_global_setup_automatically_prepares_account_first` and
  `test_automatic_preparation_collision_keeps_factory_selection` are removed
  with the preparation workflow they exercised.
- The factory-preparation branch of
  `test_runtime_upgrade_reprepares_only_factory_base` is removed. Its
  independent custom-base runtime-mismatch and pinned-project behavior is
  retained as `test_runtime_upgrade_rejects_custom_base_and_preserves_pinned_project`.
- `test_old_runtime_with_empty_manifest_selects_factory` covers omitted,
  explicit zero, and nonzero tombstone `user_uid` values on a runtime-mismatched
  manifest with no applied setups. The test documents that this metadata fixture
  intentionally uses a nonexistent source path because the runtime fallback
  must happen before image stat; it then starts a project against the factory
  image and confirms there is no UID-preparation warning.
- `test_fresh_nonroot_project_uses_factory_identity_without_uid_preparation`
  checks a first project from a non-root host UID 2000:GID 2300. It confirms the
  factory guest identity stays 1000:1001, no custom base manifest or
  preparation warning is produced, and both workspace and agent-state support
  host-created private files and guest-created replies with host ownership.
- Existing install, rebuild, capture, host-access, global-base chaos, and
  virtiofs lifecycle coverage remains in its existing files.

## Runtime compatibility probe

`/var/tmp/zaigr-uid-cleanup-evidence/verify-upgrade.sh` is a standalone probe
for the real old-migrated-image upgrade path. It creates the migrated base and
project with the preserved old binary, changes only host storage ownership to
a different non-root UID, and runs the new binary against that project. It
checks the stored guest UID, warning-free start, both shared mounts, and
preservation of the old manifest UID when deriving a further custom base.
The probe passed with exit code 0 on 2026-10-15. It created the migrated base
and project with the preserved old binary at guest UID:GID 1001:1001, then ran
the new candidate under host UID:GID 2000:2300. The project started without
rebuild confirmation or UID-preparation warning; workspace and agent-state
both passed host-created `0600` read/overwrite, guest reply, and host UID/GID
ownership checks. The manifest stayed unchanged through the upgrade, and
deriving a further custom base retained the legacy `user_uid` value 1001.
Command transcript: `/var/tmp/zaigr-uid-cleanup-evidence/upgrade-command.log`;
per-run logs are in that evidence directory. The compatibility probe also
passed against the current candidate `0.2.1-5`; its transcript is
`repair/upgrade-command.log`.

## Validation status

The original full CLI validation observed one successful guest request to an
exact IP after its permission had been removed and the firewall status no
longer listed it. This intermittent enforcement issue is documented separately
in `KNOWN_ISSUES.md`; it is not attributed to UID cleanup, and no root cause or
relationship to the separate domain-removal issue has been established.
Ten focused diagnostic repeats, a 100-turn stress run, and the restored
three-turn test passed, but passing retries do not prove the behavior is fixed.
The user accepts this documented firewall issue as a validation exception for
this cleanup review; the issue remains open. The requested combined post-split
rerun is recorded under
`/var/tmp/zaigr-uid-cleanup-evidence/review-rerun/`; its
`validation-summary.json` records the final disposition.

Before the split, all 345 unique tests had been exercised. The full CLI run had
197 passes and one exact-IP revocation failure; its remaining 60 tests passed
in a follow-up run. Install (19), built-in (5, including the later passing
OpenCode rerun), release (51), and versioning (12) tests passed. The final
candidate's `make build`, `make lint`, Ruff, and isolated-environment mypy
checks passed. Detailed logs, reports, and artifact hashes remain outside the
repository under `/var/tmp/zaigr-uid-cleanup-evidence/repair/`.
