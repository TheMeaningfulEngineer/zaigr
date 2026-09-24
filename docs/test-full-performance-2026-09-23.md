# Full test performance comparison — 2026-09-23

The complete before/after runs executed **274 cases each**. Observed elapsed
time fell from **1h26m35s to 1h12m20s**, saving **14m15s (16.5%)** with the two
implemented optimizations. Both runs had **272 passes and 2 failures**, including
the same builtin Codex timeout. The other failures differed, and the baseline
also had a snapshot preparation error. These are observed timings of complete
coverage runs, **not a validated speedup between two passing suites**.

## Complete run results

Both runs finished on September 23, UTC. The baseline ran from 20:30:00 to
21:56:35; the optimized run ran from 21:57:34 to 23:09:54.

| Phase | Cases | Baseline elapsed | Optimized elapsed | Results in each run |
| --- | ---: | ---: | ---: | --- |
| Release | 50 | 8.3s | 8.1s | 50 passed |
| Versioning | 6 | 1.7s | 1.7s | 6 passed |
| CLI, 8 → 4 workers | 198 | 2235.6s (37m16s) | 2917.2s (48m37s) | 197 passed, 1 failed; different failures |
| Builtin, 2 workers | 4 | 1418.6s (23m39s) | 1412.1s (23m32s) | 3 passed, 1 timeout |
| Installation, serial | 16 | 1530.2s (25m30s) | 2270.1s (37m50s) | 16 passed |
| Whole configuration | 274 | **5195.2s (1h26m35s)** | **4339.8s (1h12m20s)** | **272 passed, 2 failed** |

CLI and installation overlap in the optimized run, so their elapsed times must
not be added. Together they took **3765.8s before and 2917.2s after**, an observed
**848.6s (22.5%) reduction**. This accounts for almost all of the whole-run
855.5s saving. The unchanged builtin phase took about 23.5 minutes in both runs.

The tradeoff is visible: CLI alone took 30.5% longer with fewer workers and
overlap, and installation took 48.4% longer during overlap. Their concurrent
execution still shortened the complete run. This pair measures the two changes
together; it cannot isolate the full-suite contribution of the shared UID
dependency image. The earlier selected-case result was 28.2%; the observed
whole-run reduction is smaller and should replace that estimate for this
workload, subject to the failures below.

The coverage audit found every collected node ID exactly once in each run,
with no skips, teardown errors, missing cases, unexpected cases, duplicate
cases, or stale JUnit artifacts. Both commands returned a nonzero status because
of test failures. Cleanup at the end of each run found no containers or live
QEMU processes.

| Sampled resource | Baseline | Optimized |
| --- | ---: | ---: |
| Peak live QEMU processes | 15 | 10 |
| Peak combined QEMU RSS | 4.89 GiB | 4.65 GiB |
| Minimum host available memory | 17.51 GiB | 17.71 GiB |

## Failures in the complete runs

- **Both:** `test_codex_preset_installs_codex_and_launches` reached pytest's
  **1200s timeout** while waiting for the expected terminal startup marker.
  The Mistral and Claude preset tests and the builtin coexistence test passed.
  The Codex failure's cause remains unresolved; no assertion or timeout was
  changed.
- **Baseline only:** `test_misc_full_version_command` failed because the
  benchmark copy lacked ignored Go embed inputs. This was a benchmark setup
  error, described below. The isolated recheck and the optimized full run passed
  after those inputs were restored. The baseline failure remains in its totals.
- **Optimized only:** `test_projects_own_grants_independently_in_one_home`
  unexpectedly reached an HTTP endpoint from a sibling project without its own
  grant. Curl returned **0**, where the test requires **7 or 28**. It failed after
  50.4s; the baseline passed in 73.7s. This is an unresolved firewall isolation
  failure, not an accepted performance tradeoff. The two runs do not establish
  whether overlap exposed it or whether it is intermittent independently of
  the schedule.

An unchanged isolated recheck of the optimized run's firewall failure passed
on September 24 in **37.3s including pytest startup**. That recheck is excluded
from both full-run timers and does not erase the failure or establish its cause.

Failures can truncate the work within an individual case even when all case IDs
execute. Therefore the observed reduction must not be treated as a clean
passing-suite acceptance result.

## Initial default gate

The baseline `make -f baseline.Makefile test-all` stopped after **1540.6s
(25m41s)**. Release tests passed 50/50, versioning passed 6/6, and the CLI phase
reported 133 passed, 1 failed, and 1 related teardown error in 1530.1s. The
remaining 64 CLI cases, builtin tests, and installation tests did not run.

`test_project_setup_capture_firewall_allowance_does_not_leak_to_parallel_shell`
observed `NORMAL_AFTER_STATUS=0` after exiting the capture shell, where the
assertion expected a blocked request.
Teardown then failed because setup capture remained active. The orphaned QEMU
process from that exact test was identified by its deleted test directory and
terminated before further testing. This failure occurred with the original
scheduling and fixture settings. It is not evidence of a regression from the
two optimizations, and this aborted run is not a performance baseline.

An unchanged isolated rerun of the failing case **passed in 31.75s**, including
teardown. This suggests timing or load sensitivity; it does not establish the
cause or erase the original failure. The isolated result is excluded from both
complete configuration timings.

## Snapshot input correction

The complete baseline exposed an error in the benchmark copy:
`test_misc_full_version_command` performs its own `go build`, and the copy
initially lacked the ignored `bzImage`, `base-rootfs.img.zst`, and
`base-rootfs.version` inputs. The original workspace artifacts were copied
unchanged into the snapshot after that failure; their hashes and the repair
timestamp are saved in `embedded-input-repair.json`. The selected executable
and package were unchanged. Searches found no other acceptance case that
builds against these host artifacts.

The affected case passed when rechecked separately after the baseline:
**4.60s in pytest, 5.02s including process startup**, outside both configuration
timers. Its original failure remains in the baseline evidence.
This means the baseline is not a clean passing-suite benchmark: the metadata
test omitted its normal build work, and the optimized run includes that work.
The complete run timings remain useful observations, but must not be presented
as a validated comparison of two passing full suites.

## Method

The comparison uses one frozen source snapshot, with the input correction above,
and all **274 current test cases**: 50 release, 6 versioning, 198 CLI, 4 builtin,
and 16 installation cases.
The snapshot preserves the existing uncommitted release changes. Test execution
is delegated to a cheaper model; inputs and results are checked independently.

The complete baseline uses the saved original Makefile through `make -f ...`
and the original UID fixture, which installs dependencies for each case. Its
phase order is release, versioning, CLI with eight workers, builtin with two
workers, and serial installation tests.

The optimized run uses the implemented schedule: release, versioning,
CLI with four workers overlapping serial installation, then builtin with two
workers. UID cases share a temporary dependency image while retaining fresh
containers and their original VM assertions. No APT mirror or download cache
is introduced.

Both configurations run the current test corpus, including the new fast
orchestration tests. The snapshot's `Makefile` remains the implemented version
for those tests to inspect; the baseline gate itself reads the original
Makefile using `-f`. This isolates scheduling and UID fixture changes without
changing the number of test cases between runs.

After the initial default gate stopped, both complete coverage runs invoke each
Make phase in the documented order and append `--maxfail=0` to pytest arguments.
The optimized CLI/install phase still uses the real `make test-cli-install`
target. This permits subsequent cases and phases to run after failures while
preserving assertions, timeouts, worker counts, and test selection. The initial
default-gate evidence is archived separately. Any cleanup needed for failed
fixture teardown is recorded and included in the complete run's elapsed time.

The selected executable is the existing `dev-56c9de651ce5` binary, SHA-256
`d8a31794438fa218fd9ae1b7ab767472e2b799e47222f51d9a568e4c0360f5ec`.
Package installation cases use the existing `zaigr_0.2.1-2_amd64.deb` artifact.
Both artifacts are copied once and used unchanged for both configurations.
Preparing the selected binary is excluded; builds explicitly performed by test
bodies are part of test execution. These are acceptance-test performance measurements, not
verification of a newly built release candidate.

The runs execute consecutively on the same 12-CPU, approximately 24-GiB host,
with GNU Make 4.4.1, pytest 8.3.5, KVM, and rootless Podman. Existing distro
images are retained. A local `crun` wrapper provides the KVM group access
required by the standalone installation tests. Host caches are not flushed.
Network downloads remain part of the test workloads, so a single before/after
pair does not establish a variance estimate or eliminate run-order effects.

An outer monotonic timer includes Make startup, every test phase, fixture
setup, and teardown. A pytest wrapper adds per-suite JUnit output and duration
reporting without selecting cases or changing assertions. Phase timings are
reported separately; overlapping phase times must not be added to obtain
total elapsed time. Failures, skips, and incomplete coverage are retained in
the evidence and considered before reporting any speedup.

## Evidence

The local archive is
[`.tmp/full-test-performance-20260923/`](../.tmp/full-test-performance-20260923/).
It contains the frozen source snapshot, baseline Makefile and UID fixture,
optimized fixture, input hashes, original worktree diff, environment metadata,
the 274 collected node IDs, and the execution logs and JUnit results.
Raw artifacts are ignored by Git; this report retains the final measurements.

- [Audited comparison and per-case outcomes](../.tmp/full-test-performance-20260923/comparison.json)
- [Baseline timing and commands](../.tmp/full-test-performance-20260923/baseline.result.json)
  and [optimized timing and commands](../.tmp/full-test-performance-20260923/optimized.result.json)
- [Baseline suite logs and JUnit](../.tmp/full-test-performance-20260923/run-baseline/)
  and [optimized suite logs and JUnit](../.tmp/full-test-performance-20260923/run-optimized/)
- [Optimized firewall recheck](../.tmp/full-test-performance-20260923/isolated-ip-firewall.log)
- [Snapshot input repair](../.tmp/full-test-performance-20260923/embedded-input-repair.json)
  and [metadata build recheck](../.tmp/full-test-performance-20260923/repaired-version.log)
- [Archived initial fail-fast attempt](../.tmp/full-test-performance-20260923/initial-fail-fast/)

The [final source and cleanup audit](../.tmp/full-test-performance-20260923/final-audit.json)
matched all 174 recorded file hashes in the restored optimized snapshot.
The original workspace matched as well, except for the intentional report
cross-link added to `docs/test-performance-2026-09-23.md`. The selected executable
and package were included in that audit. No live QEMU processes, containers, or
temporary dependency images remained after the isolated recheck. Test assertions
and timeouts were not edited for these measurements.

An independent read-only review verified the timing arithmetic, complete case
coverage, failure caveats, and final audit, with no material findings.
