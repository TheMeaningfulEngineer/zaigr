# Releasing zaigr

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

Verification runs release and versioning tests first, then overlaps the CLI
tests at four workers with serial install tests. Builtin tests run afterward
at two workers. Both overlapping groups must finish successfully before
verification continues. Set `PYTEST_OVERLAP_WORKERS` to adjust CLI concurrency
during verification; `PYTEST_XDIST_WORKERS` still controls standalone
`make test-cli` runs (default eight).

`make test-all` uses the same schedule; `make test-cli-install` runs just the
overlapping group. UID install tests prepare their system dependencies once per
pytest session/worker in a temporary image. Each case still installs the selected
zaigr binary and creates its own container, caller, and VMs. The image is removed
after the session. Distro package and standalone installation tests continue to
start from pristine distro images.

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
