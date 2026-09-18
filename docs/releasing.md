# Releasing zaigr

Commit the release changes first. Run commands from the repository root and
replace `0.1.0` with the version you want to release.

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

## Publish

Requirements on the host:

- GitHub CLI (`gh`). On Debian/Ubuntu amd64, download the `.deb` from
  [GitHub CLI releases](https://github.com/cli/cli/releases/latest) and install it
  with `apt`, for example:

  ```sh
  curl -fLO https://github.com/cli/cli/releases/download/v2.101.0/gh_2.101.0_linux_amd64.deb
  sudo apt install ./gh_2.101.0_linux_amd64.deb
  ```

- The verified candidate available in the same checkout.
- Git authentication and permission to push tags to `origin`.
- GitHub CLI authentication with permission to create releases and upload assets.
  Use [`gh auth login`](https://cli.github.com/manual/gh_auth_login), or supply a
  GitHub PAT through `GH_TOKEN`. A PAT is not required when using `gh auth login`.

### Publish the candidate

On the host, with GitHub authentication configured:

```sh
./release/release publish
```
