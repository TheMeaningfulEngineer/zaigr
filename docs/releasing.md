# Releasing

Run releases from a zaigr release VM:

```sh
zaigr shell --preset zaigr-dev
  --ram 24000 \
  --cpu 12
```

## Build Candidate

```sh
./release/release candidate 1.0.0
```

This creates a local release candidate under `release/state/candidates/`, records it
as the active release candidate, derives the build number, generates transient
release notes, builds packages, and writes checksums.

If the version is omitted, the tool prompts for it. Before creating the
candidate, it prints any previous failed candidate, the candidate version,
build, tag, commit, and candidate directory, then asks for confirmation because
existing build outputs are wiped during the candidate build.

## Verify Candidate

```sh
./release/release verify
```

This detects the active release candidate, prints its version, build, tag,
commit, status, and candidate directory, then asks for confirmation before
running verification. It does not rebuild the candidate silently. Without an
active candidate, verification fails.

## Publish

```sh
./release/release publish
```

Publishing detects the active release candidate and asks for confirmation before
publishing it. It requires that active candidate to be verified. The release tool
records publish progress in the active candidate directory.
