CLI tests exercise public `zaigr` workflows through the `zaigr` binary, not
internal Go functions or VM implementation details.

Keep the command under test visible in the test body. Use helpers for workspace
setup, fixture setup, and repeated assertions only when they do not hide the
CLI behavior being tested.

Assert behavior through user-visible output, exit status, or documented files.
Read project-store metadata directly only when the test subject is metadata
handling itself, such as status rendering from seeded metadata, migration,
cleanup, or corruption handling.

Use `tests.conftest.run()` for non-interactive CLI commands so transcripts
capture command, stdin, stdout, stderr, cwd, and exit status.

Prefer `zaigr project vm exec -- ...` for ordinary commands inside a running
project VM. This keeps guest-command tests readable and avoids using a shell
session as a command transport.

Use interactive helpers for shell/session behavior that needs prompt matching,
streaming interaction, setup capture command recording, root confirmation, active
session behavior, or a command running in an already-open live shell. Do not use
raw SSH or `project vm exec` to bypass product semantics under test.

Tests using `project` or `project_factory` fixtures should let fixture teardown
stop project VMs. Do not stop VMs in `finally` blocks unless shutdown behavior
is the behavior under test.
