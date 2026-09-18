Tests must make every command under test visible in the test body. Use helpers
only for mechanical setup that would otherwise hide noise, not for product
behavior.

Small local wrappers around `tests.conftest.run()` are encouraged when they only
bind `cwd`/`env` and assert a zero return code. They should return stdout and
leave the actual product command visible at the call site.

Tests are testing end to end behaviour, do not introduce complicated mocks that attempt to replicate product behaviour, we test for end results.

Workflows for the software under test are exercised through public CLI commands and
asserted through user-visible output or documented files.

Prefer a sequence of small commands with clear assertions over one large shell
script. Split setup steps such as `mkdir`, `tee`, `build`, `run`, and final
verification so a failure points at the operation that broke.

When a test needs files inside a VM, prefer `project vm exec -- tee path` with
`input=` over heredocs embedded in a large shell command.

Use `project vm exec -- ...` for ordinary guest commands when the shell session
itself is not the behavior under test.

Do not replace an interactive shell with `project vm exec` when the interaction is
the product behavior. Keep the interactive helper for interactive prompts.

Tests that need to confirm firewall related behaviour do so by testing the tool that needed the firewall rule works not by string matching firewall rules in the config.

VM tests may assert multiple related outcomes when avoiding extra VM boots.
Do not reimplement production algorithms in tests; assert observable outputs or independent fixtures.
When tests write fake metadata, keep it realistic or state exactly what behavior it represents.

Do not write any go unit tests ever. 

Don't use types for python tests ever.

Examples of good tests:

- VM/container acceptance test structure: `tests/builtin/test_container_runtimes.py`
