**Focused test performance experiments — 2026-09-23**

The two winning changes are now implemented. The final section records their
combined validation; the earlier sections preserve the prototype measurements.

The subsequent [full 274-case comparison](test-full-performance-2026-09-23.md)
recorded **1h26m35s → 1h12m20s (16.5% less elapsed time)**. Both full runs had
two failures; see that report for the results and benchmark limitations.

Bounded overlap was the strongest measured improvement: the selected CLI and UID
install work completed in **6m29s**, compared with **8m44s** from the current
sequential phase means, a **25.7% reduction**. Preparing UID container dependencies
once saved **5.3%** on its three-case sample. Increasing CLI workers caused timeouts.

These were real acceptance tests using the existing binary, fresh test state, and
unchanged assertions and timeouts. No full suite was run. The experiments covered
27 distinct cases, with repeated comparisons of the same selected cases.

| Approach | Baseline | Experimental result | Assessment |
| --- | --- | --- | --- |
| Overlap CLI at 4 workers with one serial UID install process | Current CLI at 8 workers + UID, sequential phase means: 523.6s | 388.9s; all 24 CLI + 3 UID cases passed | Best result: 134.7s saved, 25.7%; one overlap trial |
| Prepare UID dependencies once per pytest worker | 270.3s mean for 3 cases | 256.1s mean; all cases passed in both repeats | Modest win: 14.2s saved, 5.3% |
| Reduce CLI workers from 8 to 4 | 253.3s mean for 24 cases | 273.0s mean; all cases passed in both repeats | 7.8% slower when CLI runs alone |
| Increase CLI workers from 8 to 12 | Both 8-worker runs passed | 4 timed-out cases, 16 passed, 3 teardown errors; 4 selected cases did not execute | Reject for this workload; incomplete run is not a speedup |

**What was measured**

The host exposed 12 CPUs and 23.9 GiB RAM, with KVM available. Repository revision
was `e5c80dd`. Every run used the same existing `zaigr` binary, SHA256
`d8a31794438fa218fd9ae1b7ab767472e2b799e47222f51d9a568e4c0360f5ec`.
Pytest was 8.3.5, xdist 3.6.1, and Podman 5.4.2. Debian's existing `trixie` image
was present before measurement. A local crun 1.21 copy supplied the install tests'
KVM prerequisite; obtaining that tool was outside the measured runs.

The 24 CLI cases cover initial boot, systemd readiness, restart, setup execution
and forced reruns, interactive shells, cleanup, resource configuration, and
multiple projects. The three UID cases cover UID 1001 workspace/restart/reset,
automatic account preparation during global setup, and UID 1 collision handling.
Exact selections are in [cli-nodes.json](../.tmp/test-performance-20260923/cli-nodes.json)
and [uid-nodes.json](../.tmp/test-performance-20260923/uid-nodes.json).

All timings use a monotonic clock around the entire pytest subprocess, including
collection, fixture setup, test execution, and teardown. Successful comparisons
require the exact selected node IDs, a zero exit status, and no skips or failures.
The same `--maxschedchunk=1` option was used for every CLI run.

| Configuration | First run | Second run | Mean |
| --- | ---: | ---: | ---: |
| CLI, 8 workers | 247.0s | 259.6s | 253.3s |
| CLI, 4 workers | 266.6s | 279.4s | 273.0s |
| UID, original fixture | 271.3s | 269.4s | 270.3s |
| UID, prepared dependencies | 255.1s | 257.2s | 256.1s |

The CLI execution order was 8, failed 12, 4, 4, 8. After the failed 12-worker
probe, three VMs left by failed fixture teardown were identified by their exact
test paths and terminated before continuing. The next measurement verified that
no live QEMU processes remained. UID comparisons ran baseline, prepared, prepared,
baseline. Other than the deliberate overlap experiment, benchmark groups ran
sequentially.

**Dependency preparation prototype**

The [prototype patch](../.tmp/test-performance-20260923/uid-dependencies.patch)
installs only `coreutils`, `e2fsprogs`, `openssh-client`, `qemu-system-x86`, and
`qemu-utils` in a uniquely named preparation container, commits its filesystem,
and removes the preparation container. Each test starts an independent container
from that image and still installs the selected zaigr binary, creates its caller
and home, and performs all original VM work. All test bodies and parameter sets
were checked for exact AST equality. The pristine distro installation tests are
not changed by this patch.

The image is recreated for every pytest session/worker and removed afterward.
Thus the measurements include preparation and image removal; they do not assume
an image prepared before timing. Setup across the three cases fell from about
27.8s to 14.7s. Subsequent case setup fell from about 9.2s to 1.1s, while the first
case paid the shared preparation cost. More install workers would each pay that
cost, so this result applies to the current serial install phase.

The repository-required independent review accepted coverage preservation,
parallel safety, and the final cleanup design. The candidate passed
`ruff check tests release/release` and the focused
`mypy --follow-imports=skip --ignore-missing-imports --check-untyped-defs tests/install/test_uid_matched_base.py`.
The original fixture was restored after the experiments; the patch is retained
as a reviewable prototype.

**Overlap result and limits**

Two pytest processes ran concurrently: the same 24 CLI cases at four workers,
and the same three UID cases with the original fixture and serial execution.
There was no dependency caching in this comparison. CLI finished in 307.8s and
UID in 388.9s; one outer timer measured **388.9s until both teardowns finished**.

Against the sum of sequential means with the same four-worker setting
(`273.0 + 270.3 = 543.3s`), overlap saved **28.4%**. Against the current eight-worker
CLI setting plus serial UID (`253.3 + 270.3 = 523.6s`), the complete configuration
change saved **25.7%**. These baselines are sums of separately measured phase means,
not an additional combined sequential trial. Individual phases became slower
under overlap, but total elapsed time decreased.

One-second sampling found at most six live QEMU processes, 1.48 GiB combined QEMU
RSS, and at least 21.11 GiB host memory available. These are combined workload
samples, not separate resource budgets to add together. The failed 12-worker
probe still had at least 19.42 GiB available, so memory exhaustion does not explain
its observed timeouts. The experiments do not identify the precise source of
contention.

Prioritize bounded CLI/install overlap while preserving serialization for
versioning and other phases that mutate shared inputs. Keep eight workers for an
isolated CLI phase; use the measured four-worker limit for this overlap prototype.
Treat dependency preparation as a smaller secondary improvement. The single
overlap trial and these selected workloads do not establish the same gain for
the full CLI suite, builtin coexistence/preset tests, or the complete distro
installation matrix. Default test and release orchestration were not changed.

**Saved evidence and reproduction**

The local archive at `.tmp/test-performance-20260923/` contains the
[validated summary](../.tmp/test-performance-20260923/summary.json), JUnit files,
per-run commands/logs, sampled resources, original and candidate UID sources,
source hashes, the prototype patch, and cleanup results. These are local ignored
artifacts; this report retains the principal measurements.

From the repository root, a single CLI comparison can be repeated with a new
output label:

```sh
python3 .tmp/test-performance-20260923/measure.py cli cli-recheck-n8 8
python3 .tmp/test-performance-20260923/measure.py cli cli-recheck-n4 4
```

`uid_series.py` runs the three-case comparison in both orders, temporarily
switching only the UID fixture and restoring its original source afterward.
`overlap.py` runs the selected unchanged CLI and UID groups together. These
experiment helpers are outside the default test targets and use the selected
existing binary without rebuilding it.

Final cleanup confirmed no live benchmark QEMU processes, no containers, and no
prepared dependency images. Existing unrelated release edits were left intact.

**Implemented follow-up**

`make test-all` and release verification now run release tests, versioning tests,
the overlapping CLI/install group, then builtin tests. `make test-cli-install`
uses four CLI workers and serial install execution; standalone `make test-cli`
keeps eight workers. `PYTEST_OVERLAP_WORKERS` controls the overlapping CLI count
and is recorded in release verification evidence. Sequential recursive Make
recipes preserve phase ordering on both GNU Make 4.3 and 4.4.1, including `-j`
invocations. The selected binary is prepared once and reused.

UID tests now prepare a unique dependency image once per pytest session/worker.
Every case creates a fresh child container, installs the selected binary, creates
its own caller, and performs all original VM assertions. Distro package and
standalone installation fixtures remain unchanged. Builders and prepared images
are removed explicitly. No APT mirror or download cache was introduced.

The implemented `make test-cli-install` target completed the same **24 CLI +
3 UID cases in 375.9s (6m16s)**, including fixture preparation and cleanup, with
no failures or skips. Compared with the earlier sequential phase means of
523.6s, this is **147.7s less elapsed time, or 28.2%**. This is one combined
validation run, not a full-suite result or an assumption that the two individual
percentage gains add together. Peak sampled live QEMU count was six.

The Make target was exercised through a local selector that replaced the suite
paths with the saved node IDs and then executed real pytest with the original
flags. Source AST comparison confirmed all UID test bodies and parametrizations
were unchanged. The complete distro/builtin matrix was not rerun.

Nineteen focused orchestration and release-verification checks passed. They cover
overlap, phase ordering, failures from either parallel group, earlier-phase
failures, worker defaults/overrides, selected-binary validation, building once,
and verification metadata. The nine Make orchestration checks also passed using
an extracted GNU Make 4.3 executable. Ruff over `tests` and `release/release`,
focused mypy over the four changed Python sources, and independent review passed.

The follow-up evidence lives in `.tmp/test-improvements-20260923/`, including
`validated-overlap.json`, per-suite JUnit XML, source snapshots, logs, and the
selector. Cleanup confirmed no remaining benchmark VMs, containers, or dependency
images; the original distro images were retained.
