The purpose of a fixture is to allow the test to be readable and minimize the infrastructure noise in the testing codebase.

All fixtures need to be written for parallel execution.


Use `tests.conftest.run()` for normal command execution in tests. It returns
`(stdout, stderr, returncode)` and records stdout, stderr, stdin, command, cwd,
and exit status in the test transcript.

It is fine for a test file to define a tiny wrapper around `run()` that binds
fixture `cwd`/`env`, asserts return code zero, and returns stdout. Do not put
the actual product workflow inside that wrapper.

Use interactive helpers when testing interactive CLI behavior. They attach the
same transcript buffers and can stream through `--interactive-transcript`.

Do not use interactive helpers just to run ordinary commands in a VM. Prefer
`project vm exec -- ...` unless the live session, prompt, or command recording
is the behavior being tested.

Canonical examples:

- Transcript storage and failure attachment: `tests/conftest.py`
- `run()` command helper: `tests/conftest.py`
- Logged test target: `Makefile`
