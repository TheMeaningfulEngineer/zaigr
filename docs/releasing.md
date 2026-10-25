# Releasing zaigr

Before each release, run `make deps-check` and review the **bugfix updates
channel** and **feature updates channel** for every bundled dependency. Decide
manually whether to update the pinned dependencies. The report includes the
Debian base rootfs release and direct Go module requirements as well as the
bundled tools; the rootfs and Go module rows have no release notes.

Commit the release changes first. Run commands from the repository root and
replace `0.1.0` with the version you want to release.

## Development versions

`make build` names development builds using `git describe` and the existing
12-character worktree fingerprint, for example:

```text
v0.2.1-3-g1b5a8ce-dev-64574dfae435
```

This identifies a build three commits after release `v0.2.1`, at commit
`1b5a8ce`. The final hash fingerprints tracked changes and non-ignored untracked
files, so different local changes still produce different development versions.
Ignored files do not affect it. Build number, commit, and build time remain
available through `zaigr misc full-version`.

The nearest reachable `vMAJOR.MINOR.PATCH` tag supplies the release base;
lightweight and annotated tags are supported, and prerelease or unrelated tags
are ignored. A development build at the release tag still includes `-0-g<commit>`
and `-dev-<worktree-hash>`. Without a reachable release tag (including shallow
clones without that history), the format is `<commit>-dev-<worktree-hash>`.
Without usable Git metadata, `make build` falls back to `dev-unknown`.
An explicit `VERSION=...` override and release candidate versions are unchanged.

## Release notes

Release notes are generated from commit subjects using `release/cliff.toml`.
Write subjects as concise descriptions of the final behavior:

- `feat:` adds an entry under Added.
- `fix:` adds an entry under Fixed.
- `change:` or `perf:` adds an entry under Changed.
- Routine `refactor:`, `docs:`, `test:`, `build:`, `ci:`, and `chore:` commits
  are omitted. Use `change:` when that work deserves a release note.

Scopes are supported, for example `fix(setups): ...`. Subjects marked with `!`
are retained even for otherwise omitted commit types. Other subjects appear
under Changed.

Keep related corrections together so the notes describe the completed change
rather than intermediate regressions. For example:

```text
fix: stop overwriting setup customizations when starting a VM or opening a shell
```

Preview the unreleased notes without creating a candidate or replacing its files:

```sh
git-cliff --config release/cliff.toml --unreleased
```

## Build and verify

On the host, enter the development VM (adjust resources for your machine):

```sh
zaigr shell --preset zaigr-dev --ram 24000 --cpu 12
```

Inside the VM:

```sh
./release/release candidate 0.1.0
./release/release verify
```

After verification succeeds, run `exit` to return to the host.

Verification runs release and versioning tests first, then runs the CLI suite at
eight workers, the install suite serially, and builtin tests at two workers. The
install suite boots official Ubuntu 22.04, 24.04, and 26.04 and Debian 12 and 13
cloud images. It verifies each image checksum and prepares a package-equipped
image cache; every test uses its own disposable overlay. Set
`CLOUDVM_DISTROS=ubuntu-24.04,debian-13` to run a subset. Set
`PYTEST_XDIST_WORKERS` to adjust CLI concurrency (default eight).

`make test-all` uses this schedule; `make test-cli-install` runs the CLI and
install suites in sequence. Install tests need KVM, QEMU, and `cloud-localds`;
they fail clearly when a prerequisite is unavailable. The install suite also
needs a matching `zaigr` binary and amd64 `.deb`: it uses the active candidate
artifacts in `release/dist/` by default, or accepts explicit
`ZAIGR_TEST_BINARY=/path/to/zaigr` and `ZAIGR_TEST_DEB=/path/to/package.deb`
overrides. Cloud images, checksum manifests, and prepared-image caches live in
`~/.zaigr/external-sources/cloud-images` by default; set
`ZAIGR_EXTERNAL_SOURCES=/path/to/cache` to use another location. Disposable VM
overlays and logs live under `.local/cloudvm-verification/harness`; set
`ZAIGR_KEEP_CLOUDVM=1` to retain them for inspection. The image cache is retained
automatically, so repeating a run with it warm avoids image preparation.

## Publish

Requirements on the host:

- GitHub CLI (`gh`). On Debian/Ubuntu amd64, download the `.deb` from
  [GitHub CLI releases](https://github.com/cli/cli/releases/latest) and install it
  with `apt`, for example:

  ```sh
  curl -fLO https://github.com/cli/cli/releases/download/v2.101.0/gh_2.101.0_linux_amd64.deb
  sudo apt install ./gh_2.101.0_linux_amd64.deb
  ```

- The candidate available in the same checkout.
- Git authentication and permission to push tags to `origin`.
- GitHub CLI authentication with permission to create releases and upload assets.
  Use [`gh auth login`](https://cli.github.com/manual/gh_auth_login), or supply a
  GitHub PAT through `GH_TOKEN`. A PAT is not required when using `gh auth login`.

### Publish the candidate

On the host, with GitHub authentication configured:

```sh
./release/release publish
```

If the candidate has not passed verification, publishing first asks
`Publish this unverified candidate anyway? [y/N]`. Answer `y` to continue to the
normal publishing confirmation. Any other response except `yes`, including
empty input, cancels. Publishing this way leaves verification metadata unchanged
and records the explicit confirmation in the publish transcript.
