# Known issues

## Host and guest user IDs can differ on shared files

The factory guest user has UID `1000`. When the host user has a different UID,
the guest user can be unable to write to host-owned workspace files, even when
the host user can access them normally.

**Automatic workaround (implemented):** For non-root host accounts, Zaigr
automatically prepares a factory-derived base image with the guest user's UID
matched to the host user's UID when needed. A warning explains the extra
preparation time; no additional command or configuration is required.

Existing projects and legacy custom base images are not silently migrated.
The workaround gives other host UIDs the same shared-file usability as UID
`1000`; it does not provide independent guest root or service-user ownership
mapping on shared host files.

## Captured setup can run before its prerequisite during rebuild

Observed in version `0.1.0`.

A captured [setup](docs/terminology.md) can replay before a previously applied
project-local setup that it depends on. This can make `project rebuild` fail even
though the capture worked when it was recorded.

Example:

1. Apply a project-local setup that installs `my-tool`.
2. Start a capture and run `my-tool` successfully.
3. Accept the capture, stop the VM, and run `zaigr project rebuild --force`.
4. The captured setup runs before the project-local setup and fails with
   `my-tool: command not found`.

The observed failure aborted safely: the original project image and workspace
files remained intact, and the existing environment worked after restarting.

**Workaround:** Keep captured recipes self-contained rather than relying on tools
installed by another project setup. If this rebuild failure occurs, choose abort
and run `zaigr project vm start` to continue using the existing environment. This
recovers the working environment but does not fix the captured recipe's replay
order.

## Removing a domain may not block access immediately

Observed in version `0.1.0`.

`zaigr-inside firewall remove pypi.org` reported success, and
`zaigr project firewall show` no longer listed the domain. However, two fresh
HTTP requests from the ordinary guest user still succeeded approximately
0-1 seconds after removal.

In a separate trial, a request about 11 seconds after removal was blocked. This
is not evidence of a permanent bypass, and the maximum enforcement delay is
unknown. Exact-IP host-access removal worked in the trials, including stopping
an active stream; this finding concerns domain removal specifically.

**Workaround:** If access must stop immediately, stop the VM with
`zaigr project vm stop`. Do not treat a successful removal or the domain's absence
from the firewall list as confirmation that requests are already blocked.

## Stale runtime socket after rapid stop/start cycles

Observed in version `0.2.1` during automated chaos testing on 2026-10-13.

After three consecutive `project vm start` / `project vm stop` cycles on the
same project, one stale file remained under the project's runtime directory
(`~/.zaigr/projects/<hash>/runtime/`). The specific artifact was not
identified in the sample (likely the QMP monitor socket or SSH-port marker).
The behavior was not deterministic across all three cycles.

The next `project vm start` after the leak succeeded, but
`detectRunningProjectVM` has a stale-socket recovery path specifically for
this condition — the leak itself is latent and only observable by inspecting
the runtime directory between cycles.

**Workaround:** none required for correctness; subsequent starts recover.
If `project status` reports an unexpected state after rapid cycling, run
`project vm stop` once more before the next start.

## Project rebuild does not block or discard a pending setup capture

Observed in version `0.2.1` during automated chaos testing on 2026-10-13.
This finding has not been reproduced manually and benefits from
confirmation.

Reported behavior: when a setup capture is pending (started with
`project setup capture start` but not yet accepted or discarded) and
`project rebuild` runs, the rebuild proceeds without warning and the
pending capture state is cleared.

Expected behavior: the capture lifecycle should either block the rebuild
until it is explicitly accepted or discarded, or the rebuild should warn
that the pending capture will be lost before clearing it.

**Workaround:** before running `project rebuild`, explicitly run
`project setup capture accept` or `project setup capture discard` so that
captured commands are either saved or intentionally dropped.
