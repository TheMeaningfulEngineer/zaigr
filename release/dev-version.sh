#!/usr/bin/env bash
set -euo pipefail

repo="${1:-.}"

(
    cd "$repo"

    # Only published-release tag names qualify; ignore prereleases and other tags.
    tag_matches=(--match '')
    while IFS= read -r tag; do
        if [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
            tag_matches+=(--match "$tag")
        fi
    done < <(git tag --list 'v*')
    description=$(git describe --tags --long --always "${tag_matches[@]}")

    worktree_hash=$({
        git diff --binary --no-ext-diff HEAD --
        git ls-files --others --exclude-standard -z \
            | sort -z \
            | while IFS= read -r -d '' path; do
                printf 'untracked %s\n' "$path"
                git hash-object --no-filters -- "$path"
            done
    } | sha256sum | cut -c1-12)

    printf '%s-dev-%s\n' "$description" "$worktree_hash"
)
