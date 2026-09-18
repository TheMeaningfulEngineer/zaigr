The release tool is a simple one line python script with a simple CLI.
It doesn't need a deliberate library structure and multi directory structure.

Release state lives under `release/state/`. Active candidate resolution goes through
`release/state/active.json`; candidate metadata lives under
`release/state/candidates/<version>-<build>/`.

Release candidate creation prompts before it creates candidate state or wipes
outputs. Cancellation must leave existing `release/dist/` and `release/RELEASE_NOTES.md`
untouched.

Release commands must log shell-like transcripts to stderr. 

Candidate failures must mark `release.json` as failed, keep the transcript, and
record enough failure metadata for the next candidate preview to show the
previous failed candidate.

Verification uses the active candidate, restores saved candidate outputs, runs
the release verification steps, then marks the candidate verified. Publishing
must refuse unverified candidates.

