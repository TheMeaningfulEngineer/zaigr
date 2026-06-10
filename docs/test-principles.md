Every command used by a test must have a human-readable transcript. 
The transcript must be streamable in real time during logged runs and available when the test fails.

Tests must exercise VM behavior through public `zaigr` CLI commands such
as `zaigr shell`; do not SSH into project VMs or scrape VM ports/runtime
internals unless the feature under test is explicitly SSH or runtime-
port management.

Tests that exercise public `zaigr` workflows must assert resulting behavior
through public user-visible interfaces, such as CLI output or documented files.
Direct project-store metadata reads or writes are allowed only when the test
subject is metadata handling itself, such as status rendering from seeded
metadata, migration, cleanup, or corruption handling.

Project VM shutdown for tests using the `project` or `project_factory`
fixtures is handled by fixture teardown. Tests should not stop VMs in `finally`
blocks unless stopping or transitioning the VM is the behavior under test.

The command under test should be visible in the test body.

Helpers are allowed only for mechanical test infrastructure that does not hide product behavior.

A good test does not mix test infrastructure with the command under test.
Test infrastructure is unavoidable noise and should be hidden only when that improves readability without obscuring what behavior is being tested.

Use the Makefile test targets.

Run one focused test with logs through `make test-logged`, for example:

```bash
make test-logged TEST_PATH=tests/builtin/test_presets.py::test_codex_preset_installs_codex_and_launches
```
