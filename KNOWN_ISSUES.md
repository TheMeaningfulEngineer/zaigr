# Known issues

## Secondary guest accounts and host-side UID inspection are not mapped

Virtiofs translates ownership on the shared workspace and agent-state mounts
between the invoking host UID/GID and the selected guest user's UID/GID. The
guest user can read and write host-owned shared files when the numeric host and
guest IDs differ. Zaigr reads the guest identity from the selected image; it
does not rewrite the image or ask for a rebuild to match host IDs.

The translation covers the selected guest user and guest root. A service or
secondary guest account still has no corresponding host identity on shared
mounts. Host tools that inspect guest-disk files outside virtiofs, such as
recovery tools that read a qcow2 image directly, also see the image's baked-in
numeric IDs rather than a translated host identity.

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

## Exact-IP permission removal allowed a request

Intermittently observed in candidate `0.2.1-5` on 2026-10-15 by
`test_live_mutations_and_vm_reuse_never_restore_removed_permissions`.
During a full CLI run, removal of an exact-IP permission reported success and
the project firewall status no longer listed the IP, but a subsequent fresh
guest HTTP request to that IP succeeded and returned the test endpoint token.
This happened once. Ten focused diagnostic repeats, a 100-turn stress run, and
the restored three-turn test passed; those passes do not prove the issue is
fixed. The root cause is unknown. No connection between this event and the
separate domain-removal behavior above has been established, and no relationship
to the UID cleanup has been established.

Evidence: `/var/tmp/zaigr-uid-cleanup-evidence/repair/cli.log` and
`cli.xml`; follow-up results are in `cli-remaining.log` and `cli-remaining.xml`,
and focused records are in `cli-ip-chaos-diagnostic-1..10.log/xml`,
`cli-ip-chaos-100turn-logs-redirected.log/xml`, and
`cli-ip-chaos-final-3turn.log/xml`.

**Workaround:** Stop the project VM if access must be cut immediately. This
workaround does not assert that a later restart guarantees correct enforcement;
verify firewall behavior before relying on access removal.

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
