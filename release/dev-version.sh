#!/usr/bin/env bash
set -euo pipefail

repo="${1:-.}"

(
    cd "$repo"
    {
        git diff --binary --no-ext-diff HEAD --
        git ls-files --others --exclude-standard -z \
            | sort -z \
            | while IFS= read -r -d '' path; do
                printf 'untracked %s\n' "$path"
                git hash-object --no-filters -- "$path"
            done
    } | sha256sum | cut -c1-12
)
