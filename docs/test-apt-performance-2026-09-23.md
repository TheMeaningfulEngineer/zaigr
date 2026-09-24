**APT contribution to test time — 2026-09-23**

A local package mirror is a secondary optimization for the measured workloads.
The host dependency downloads are a small part of the earlier CLI/UID sample;
inside a real VM, unpacking and configuring hundreds of packages costs much more
than downloading them. Ubuntu installation containers have a larger download
cost and showed one slow transfer.

These are focused phase probes, not a full suite run or a measured mirror rollout.
The product and test-suite sources were unchanged.

**Host container measurements**

Fresh containers used the same images and dependency commands as the install
tests. Each workload ran normal, split, split, normal, sequentially. Split runs
performed `apt-get update`, `apt-get install --download-only`, then
`apt-get install --no-download`. All requested packages were verified installed,
and all eight containers were removed.

| Workload | Index update | Download-only phase | Install from cached archives | Normal update + install |
| --- | ---: | ---: | ---: | ---: |
| Debian trixie UID dependencies, 63 new packages / 28.9 MB | 1.84s | 3.60s | 3.57s | 8.19s |
| Ubuntu 24.04 standalone dependencies, 298 new packages / 166 MB | 3.97s | 17.20s, 37.91s | 13.87s | 34.51s |

Values are means except the two Ubuntu download observations. The last column
uses only the two normal runs. Debian uses `--no-install-recommends`; Ubuntu
retains recommendations, matching the respective tests. Both install
`coreutils e2fsprogs openssh-client qemu-system-x86 qemu-utils`.

APT's own transfer summaries reported 3s for Debian packages, and 16s or 37s
for Ubuntu packages. The separately timed download-only commands also include
dependency resolution and command overhead. Splitting invokes APT twice, so its
two install phases should not be added and treated as an exact normal baseline.
Normal installation minus installation from cached archives was 2.77s for Debian
and 16.55s for Ubuntu; these differences include timing and filesystem-cache
effects as well as avoided network work. Ubuntu's slow download remains in the
evidence and is not averaged into a claimed normal-run improvement.

**Real guest measurements**

Fresh factory VMs used the existing `zaigr` binary, an isolated HOME and project
on `/var/tmp`, 2 vCPUs, 2048 MB RAM, and the public `project vm start/exec/stop`
commands. The dependency list was the builtin Codex setup's APT command:
`nodejs npm ripgrep python3-yaml`, with `--no-install-recommends`.
This measures the preset's APT portion; it does not install the npm-distributed
agent or exercise its interactive launch.

The guest order was split, normal, split. Each installed 379 new packages and
3 upgrades, fetching 51.2 MB. APT reported **5s** for package transfer in all
three runs. Node and npm version commands and installed-package status checks
succeeded in all three.

| Run | Index update | Download-only | Install with downloads disabled | Combined download + install |
| --- | ---: | ---: | ---: | ---: |
| Split A | 12.41s | 6.24s | 117.01s | — |
| Normal | 13.52s | — | — | 120.47s |
| Split B | 12.92s | 6.74s | 115.54s | — |

Installation from cached archives averaged **116.27s**; the download-only phase
averaged **6.49s**, including APT resolution and public-CLI overhead.

A separate fresh VM using an ordinary combined installation took 13.52s for
index update and 120.47s for download plus installation, **133.99s total APT
time**. Its transfer summary also reported 5s for 51.2 MB: roughly **4% of this
APT workload** was attributed to package retrieval. This is not a measurement
of a complete preset test or a local mirror. The index update retrieved and
processed 16.3 MB; moving those files nearby would still leave local processing.

**Implication for the earlier baseline**

The earlier [27-case experiment](test-performance-2026-09-23.md) had a sequential
baseline of 523.6s and contained three fresh UID dependency installations.
Applying the host measurements to that workload gives:

| Scenario | Estimated seconds | Share of earlier baseline |
| --- | ---: | ---: |
| All host APT work, including installation | 24.6s | 4.7% |
| Normal installation minus installation from cached packages | 8.3s | 1.6% |
| Above difference plus eliminating all index-update time | 13.9s | 2.6% |

These are estimates applied to the earlier run, not observed suite speedups.
The final scenario uses `3 × (normal update+install mean − cached-install mean)`:
`3 × (8.188877 − 3.567200) = 13.865033s`. It uses normal-run update timings,
whereas the first table's update column averages all four runs.
The last row is an optimistic elimination scenario: a real mirror still transfers
data, and APT still authenticates, decompresses, and processes indexes. Ubuntu
and builtin guest probes are outside that earlier sample. No full-suite savings
percentage can be established from these probes.

The repository's own `.deb` artifact is mounted locally in the package-install
tests already. A Debian/Ubuntu package mirror also would not cache the npm, pip,
Go, container-image, or other non-APT downloads used by builtin setups.

For speed alone, these results do not justify prioritizing a full mirror over
the previously measured phase-overlap improvement. If avoiding repeated transfers
and their variability is useful, a small on-demand caching proxy is a better next
experiment. [APT-Cacher NG](https://manpages.debian.org/trixie/apt-cacher-ng/apt-cacher-ng.8.en.html)
provides that package-download caching function. Its actual incremental benefit
would still need a warm-cache comparison on this network.

**Evidence and limits**

Raw commands, timings, output, package-archive manifests, and provenance are saved
locally under `.tmp/apt-performance-20260923/`. `container_probe.py` reproduces
the host measurements; `guest_probe.py` reproduces the public-CLI guest probes.
The binary SHA256 is
`d8a31794438fa218fd9ae1b7ab767472e2b799e47222f51d9a568e4c0360f5ec`.
The host has 12 CPUs and approximately 24 GiB RAM. Container and guest groups ran
sequentially, with no other benchmark running concurrently. The probes retain
normal APT signature checking. The
[APT manual](https://manpages.debian.org/trixie/apt/apt-get.8.en.html)
documents the download-only and no-download modes used to separate the phases.

All eleven probes completed successfully. Final validation confirmed that all
three guest directories were removed and no benchmark containers or live VMs
remained. The experiment scripts passed Ruff and focused mypy checks. Independent
repository-principles review found no material issues; its two minor reporting
corrections were incorporated.
