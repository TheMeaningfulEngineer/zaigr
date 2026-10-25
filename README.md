# zaigr

Run AI coding agents without approval prompts in a [VM](docs/terminology.md#project-vm)
for each [project](docs/terminology.md#project).

## Installation

Requires Linux x86-64 with usable KVM and `/dev/vhost-vsock` access (normally
provided by membership in the `kvm` group).

### Standalone binary

Download the `zaigr` binary from
[Releases](https://github.com/TheMeaningfulEngineer/zaigr/releases). From the
download directory, install it under your home directory without sudo:

```sh
mkdir -p "$HOME/.local/bin"
install -m 0755 ./zaigr "$HOME/.local/bin/zaigr"
export PATH="$HOME/.local/bin:$PATH"
```

Add the `export PATH` line to your shell's startup file, such as `~/.bashrc`, to
keep it for new terminals.

The guest kernel and base filesystem are bundled in the binary. Install the
host dependencies separately from your distribution's repositories. On Debian
or Ubuntu:

```sh
sudo apt install coreutils e2fsprogs qemu-system-x86 qemu-utils
```

Firewall enforcement now runs on the host, outside the VM. Older installations
may need these host tools before starting a VM or rebuilding/applying setups;
the guest's packages cannot provide them. `zaigr misc check` aggregates missing
tools, QEMU/KVM, filesystem sandbox, disk-space and host-networking failures.
It prints only the missing Debian/Ubuntu packages and a suggested install
command. Zaigr never installs packages or changes host policy automatically.

The host must expose a usable `/dev/vhost-vsock` device. If it is missing,
enable the host's vhost-vsock support; if it is not accessible to your account,
add yourself to the `kvm` group. The host kernel must support nftables conntrack marks
(`CONFIG_NF_CONNTRACK_MARK`). The bundled kernel enables this option. When
running Zaigr inside an older Zaigr VM, boot that VM with the updated bundled
kernel before using the new firewall. `zaigr misc check` verifies rule setup.

The bundled static virtiofs daemon serves the workspace and agent-state mounts.
By default, each file server uses a namespace sandbox. This requires permission
to create user, mount, PID and network namespaces and configure sandbox mounts.
Run `zaigr misc check` as the account that will run zaigr. It checks host tools,
QEMU/KVM, disk space, the host namespace/network prerequisites, and QEMU
virtiofs support. It starts the bundled daemon against an empty temporary
export and starts/stops a disposable host-network namespace with no VM, grants,
or forwarded ports. It does not modify a project; it may populate the normal
daemon cache. The disposable network probe verifies namespace, TAP, nftables
controller and slirp startup, but it cannot predict every later runtime or
host-policy failure.
It detects the host distribution and kernel. On failure it diagnoses known
namespace restrictions, including Ubuntu's AppArmor policy and container
restrictions, and reports the required host change. It automatically reads
available kernel logs and correlates denials with the probe's processes.
Confirmed audit findings are distinguished from likely causes inferred from
host settings and the failure. If kernel logs are inaccessible, it reports that
limit and still gives the available diagnosis. A successful check covers the temporary
export; individual project paths can still have different access restrictions.
The namespace sandbox is required by host-enforced networking to verify the
identity of exported directories. If the host cannot start it, startup and
rebuild fail with diagnostic guidance before launching a VM. Run
`zaigr misc check` and resolve the reported host restriction. There is no
`unsafe` fallback; `virtiofs-sandbox=none` is no longer supported.

VM creation, stopped-image setup/rebuild and batch rebuild run the same host
preflight before changing project images or stopping a VM. Operations that
attach to an already-running VM use its existing host network runtime and do
not recheck cold-start requirements. The check includes exact namespace and
disposable runtime probe errors, distinguishes observed host settings from
likely causes, and leaves package installation and host-policy changes to the
administrator. For an older project, run `zaigr misc check` first. Resolve all
reported host requirements, rerun the check until it passes, then stop the VM
and run `zaigr project rebuild` before reopening it. This catches known host
requirements before rebuild work begins; it cannot predict every later runtime
failure.

Zaigr creates namespaces directly, so it does not require the `unshare` command.
For Ubuntu AppArmor restrictions, see the [Ubuntu security documentation](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/).

For an existing, stopped project with the old `none` preference, restore the
supported setting after resolving the host restriction:

```sh
zaigr project vm show-config
zaigr project vm set-config --virtiofs-sandbox namespace
```

The sandbox contains the file server and protects files outside the selected
shares. It does not guarantee protection against every escape. Guest access to
the selected shares remains intentional.

The workspace must not overlap Zaigr's host store, private data, or runtime
directories. A project rooted at `$HOME` normally contains `~/.zaigr` and is
therefore refused: exporting it would expose authoritative policy and private
host management state. Put project files in a separate directory such as
`~/projects/my-project` that does not contain those protected directories.
Symlink aliases do not bypass this check.

On Ubuntu with AppArmor user-namespace restrictions, `misc check` prints commands
to generate, review and load a path-scoped profile for Zaigr and its cached
virtiofs daemon using `zaigr misc apparmor-profile`. This does not disable the
global restriction or install a service. The generated policy applies to both
executable paths, which are path permissions rather than verified code identities;
subprocesses inherit the profile, and other code running as your account could
replace either executable and obtain the same permission. Regenerate the profile
when either path changes. The check always tests namespace sandbox availability, even when
an existing project has an obsolete preference. Debian and other hosts are probed in the same
way; zaigr does not assume a distribution is exempt from host restrictions.

If startup fails, inspect the project's
`vm-supervisor.log`, `virtiofsd-workspace.log`, and
`virtiofsd-agent-state.log` under `~/.zaigr/store/<project-id>/`.

Your account also needs read/write access to `/dev/kvm`, usually through the
`kvm` group. Installing dependencies or setting up KVM access may require an
administrator; installing and running zaigr itself does not require sudo.

### Debian package

Alternatively, download the Debian package from
[Releases](https://github.com/TheMeaningfulEngineer/zaigr/releases) and install
it with its host dependencies:

```sh
sudo apt install ./zaigr_*.deb
```

After either installation method, check your host:

```sh
zaigr misc check
```

The check reports whether KVM access, QEMU virtiofs support, host tools, the
virtiofs sandbox, and free disk space are ready.

## Examples to get you started

Run these commands in a terminal **on the host**. For the agent and environment
examples, use the directory you want the agent to work in.

### I want Tab completion in Bash

Run this as your normal user:

```sh
zaigr misc autocomplete
```

Answer `y` to add completion to `~/.bashrc`. It will load in new Bash terminals.
To enable it in your current Bash session too:

```bash
source ~/.zaigr/autocomplete/zaigr.bash
```

Type `zaigr ` and press Tab to discover commands and options.

### I want to run an agent in this directory

Choose a [preset](docs/terminology.md#preset) to launch your agent:

```sh
zaigr shell --preset codex
```

Or, for Claude Code:

```sh
zaigr shell --preset claude
```

Or, to use hosted models through OpenCode:

```sh
zaigr shell --preset opencode
```

Use `/connect` and `/models` inside OpenCode to choose your provider and model.
See the [OpenCode guide](docs/opencode.md) for European hosting options, saved
state, and updates.

Or, for Google's Antigravity CLI:

```sh
zaigr shell --preset antigravity
```

The preset keeps Antigravity's private state on the project's agent-state share
and automatically approves tool requests inside the VM.

The first run initializes this directory as a
[project](docs/terminology.md#project) for the following examples.

### I need Python or Node.js available to the agent

Add the [setups](docs/terminology.md#setup) you need when starting the agent:

```sh
zaigr shell --preset codex --setup python --setup nodejs
```

### I need to update Codex

Exit the running agent, then rerun its [setup](docs/terminology.md#setup) from the
host and start Codex again:

```sh
zaigr project setup run codex --force
zaigr shell --preset codex
```

`--force` reruns the installer even when the
[setup](docs/terminology.md#setup) is already recorded as applied, installing the
current Codex package.

Setup installation in a running project VM uses a private network namespace.
Installer processes get temporary broad networking; existing model processes
and services keep their normal network policy. The host revokes the temporary
access when installation ends; the setup's declared exact domains remain
available afterward. Dedicated image-building VMs still use a temporary
VM-wide grant, with no concurrent model session.

### I need the agent to access another domain

Allow the exact hostnames from the host:

```sh
zaigr project firewall allow docs.python.org pypi.org
zaigr project firewall show
```

Each name is allowed exactly, not its subdomains. The same command also takes
an IPv4 address, such as `zaigr project firewall allow 192.168.2.11`.

The host enforces this permission for the entire VM, including root processes.
The grant is saved outside the guest image and applies to the running VM.
Remove it from the host with `zaigr project firewall remove docs.python.org`.

### I need an unrestricted network shell

Run this command on the host:

```sh
zaigr shell --root --full-network
```

It opens a root maintenance shell in the VM's shared maintenance network
namespace, with temporary broad IPv4 TCP/UDP access, including private networks
and host data services. Existing model processes and ordinary shells retain
their normal network policy. Concurrent maintenance sessions share the same
network namespace; a process left running after one session exits keeps access
while another maintenance session remains active.

The filesystem is shared, so tools you install remain available afterward.
Access ends when the last maintenance session exits or its host-kernel lease
expires. `--root` alone keeps restricted networking. `--full-network` requires
`--root` and cannot be combined with `--preset` or `--setup`.

Maintenance requires that the model cannot become guest root. The built-in
`docker` and `k3s` setups give the model root-equivalent access, so images with
those setups cannot open isolated maintenance networking, even after the
foreground model stops. This also applies to inherited setups, attached setup,
and capture. Use a separate clean image without those privileges, or grant
specific destinations through the host firewall. Failed or interrupted setup
history must be resolved by replacing the image before maintenance is allowed.
Stop the VM with `zaigr project vm stop`, inspect `zaigr project setup list
--applied`, then run `zaigr project rebuild`. A successful rebuild clears the
failed-setup restriction; a failed rebuild or successful retry against the
same image does not. Rebuilt images containing Docker/k3s remain restricted.
Use `zaigr project clean` if you want to discard the applied setups instead.
Custom scripts and manually granted privileges remain the administrator's
responsibility; setup names are not a general privilege detector.

To install Docker/k3s, stop the project VM and run the setup against its image,
then start the project again. Subsequent setups on that image also require the
stopped-image workflow. This uses a dedicated image-building VM with no
concurrent model session; it does not grant the running model maintenance access.
Image building trusts the existing image and setup scripts. Stopping a VM does
not remove services or boot hooks left by a previously privileged model; use a
fresh trusted image if that history is suspect.

Existing shared services stay in their original network namespace even when
invoked from maintenance.

### I need a custom [setup](docs/terminology.md#setup) for this [project](docs/terminology.md#project)

Create the editable files with the skeleton command:

```sh
zaigr project setup local-skeleton
```

Edit `.zaigr/setups/local/setup.script` with your installation commands. For
example, the file could contain:

```sh
#!/bin/bash
set -eu
apt-get update
apt-get install -y jq
```

Put any hostnames the installed tool needs in
`.zaigr/setups/local/setup.firewall`, one per line. Then apply the
[setup](docs/terminology.md#setup) from the host:

```sh
zaigr project setup run local
```

Keep `.zaigr/setups/local/` with your code. If it already exists, edit those files
and rerun the last command.

### I want to turn an experiment into a reusable [setup](docs/terminology.md#setup)

Stop the project VM, then start a [capture](docs/terminology.md#setup-capture)
from the host:

```sh
zaigr project vm stop
zaigr project setup capture start
```

With a stopped project, capture uses a temporary overlay VM. It can also attach
to an already-running project VM. The capture shell uses a private maintenance
network namespace; other processes keep their normal network restrictions.
Accepting or discarding a running-VM capture leaves its shell open and prints
a reminder that its temporary network access ends when the shell exits.

Inside the [capture](docs/terminology.md#setup-capture) shell, install and try the
tools you need. For example:

```sh
apt-get update
apt-get install -y jq
jq --version
exit
```

Back in the same host terminal, review the recorded commands and observed
domains:

```sh
zaigr project setup capture review
```

Accept the proposal to create a reusable [setup](docs/terminology.md#setup):

```sh
zaigr project setup capture accept
```

Or discard the [capture](docs/terminology.md#setup-capture) instead:

```sh
zaigr project setup capture discard
```

Accepting promotes the capture image; discarding removes the capture overlay.
Changes to shared workspace files are not undone by discarding an image.

### I want to add tools to my [base image](docs/terminology.md#base-image)

Zaigr automatically prepares the factory base image for your account when needed.
A warning explains any extra wait; no additional command or configuration is
required.

Install Python and Go once so new [projects](docs/terminology.md#project) inherit
them:

```sh
zaigr global base-image setup run python go
zaigr global base-image status
```

Existing [projects](docs/terminology.md#project) keep their current
[base image](docs/terminology.md#base-image). To adopt the new default here and
reapply this [project](docs/terminology.md#project)'s recorded
[setups](docs/terminology.md#setup):

```sh
zaigr project rebuild
```

Rebuilding replaces the [project image](docs/terminology.md#project-image).
Preserve manual changes that are not recorded in
[setups](docs/terminology.md#setup) before rebuilding.

### I want to open a project server in my host browser

Start the server inside your project, listening on `0.0.0.0:3000`, then run on
the host:

```sh
zaigr project host-access allow 8080 --vm-port 3000
zaigr project host-access show
```

Open `http://127.0.0.1:8080`. Omitting `--vm-port` uses the host port inside the
project too. Forwarding is TCP over IPv4 and binds only to host `127.0.0.1`.
Allow and remove take effect on a running VM. Removing a forward prevents new
connections; existing connections may finish.

```sh
zaigr project host-access remove 8080
```

### I need a host serial device inside the project

```sh
zaigr project host-access allow /dev/ttyUSB0
zaigr project vm stop
zaigr project vm start
zaigr project host-access show
```

The device appears at the same absolute path for project shells and presets.
Up to two serial TTYs are supported. Your host account needs read/write access.
New device grants need a VM restart; stop the VM before removing an exposed
device with `zaigr project host-access remove /dev/ttyUSB0`.

Grants survive stop/start, clean, and rebuild. A device remains reserved to its
project while stopped or unplugged; remove its grant or delete the stopped
project to release it. A changed device identity requires explicit removal and
authorization of the replacement. Grants are not inherited by reusable setups.

`show` observes listeners and open device descriptors inside the VM without
connecting to your services or opening devices. `Available` means sharing is
active with no guest consumer; `Attached` means a guest listener or device user
is present. It also reports stopped, pending, unavailable, and unknown states.

Serial byte transfer and baud changes have automated PTY coverage. Physical
USB reconnect, modem-control lines, and board-specific flashing tools remain
unverified. This feature does not provide generic USB or arbitrary-device
passthrough. See the [transport notes](docs/project-host-access-transport.md).

### I need to access a server running on the host

Inside the [VM](docs/terminology.md#project-vm), the host is reachable at
`10.0.2.2`. For a server listening on the host's `127.0.0.1:8000`:

```sh
zaigr project firewall allow 10.0.2.2
zaigr project vm exec -- curl --noproxy '*' http://10.0.2.2:8000
```

Replace `8000` with your server's port. The agent can then use that same address;
`localhost` inside the [VM](docs/terminology.md#project-vm) refers to the guest.

This permission allows **all ports** at that address for this
[project](docs/terminology.md#project), and persists until removed:

```sh
zaigr project firewall remove 10.0.2.2
```

### I want to SSH from the VM into a Docker container on my host

This example requires Docker running on the host. It creates an SSH server
with username `user` and password `user`; no SSH keys need to be configured.
Run the following in a host terminal:

```sh
mkdir zaigr-ssh-demo
cd zaigr-ssh-demo
cat > Dockerfile <<'EOF'
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/sh user \
    && echo 'user:user' | chpasswd \
    && mkdir -p /run/sshd \
    && rm -f /etc/ssh/ssh_host_*
EXPOSE 22
CMD ["sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -e -o PasswordAuthentication=yes -o PermitRootLogin=no"]
EOF
docker build -t zaigr-ssh-demo .
docker run -d --rm --name zaigr-ssh-demo \
    -p 127.0.0.1:2222:22 zaigr-ssh-demo
```

Docker [publishes the container's SSH port on host loopback](https://docs.docker.com/engine/network/port-publishing/).
Wait up to 30 seconds for SSH to become ready, then connect from the host:

```sh
timeout 30s sh -c 'until docker exec zaigr-ssh-demo ssh-keyscan -T 1 127.0.0.1 >/dev/null 2>&1; do sleep 1; done' &&
    ssh -o PubkeyAuthentication=no -p 2222 user@127.0.0.1
```

If the readiness check times out, inspect `docker logs zaigr-ssh-demo` before
continuing.

Accept the host-key prompt on this first connection and enter `user` at the
password prompt. Inside the container, check the login and note its hostname,
then return to the host:

```sh
whoami
hostname
exit
```

`whoami` prints `user`; `hostname` prints the container's ID. From the same host
directory, start the project VM, answer `y` to initialization, and grant it
access to the host:

```sh
zaigr project vm start
zaigr project firewall allow 10.0.2.2
zaigr shell
```

Now **inside the VM**, connect to the same container through the host gateway:

```sh
ssh -o PubkeyAuthentication=no -p 2222 user@10.0.2.2
```

Accept the first host-key prompt and enter password `user` again. Run `whoami`
and `hostname`: they should print `user` and the same container ID as before.
Run `exit` twice to return through the VM shell to the host.

The firewall grant persists for this project and permits **all ports** at
`10.0.2.2`. To finish the demo, run on the host:

```sh
zaigr project firewall remove 10.0.2.2
docker stop zaigr-ssh-demo
zaigr project vm stop
```

### I want to see what is running and stop something

From any host directory:

```sh
zaigr global projects list
```

Use a name or ID from the list to inspect or stop its
[VM](docs/terminology.md#project-vm):

```sh
zaigr global projects details my-project
zaigr global projects kill my-project
```

Replace `my-project` with the name or ID you chose.

## Building from source

`make build` builds the guest kernel and root filesystem, compiles the pinned
virtiofsd version as a static musl executable, downloads upstream's static
slirp4netns release binary and verifies it against `deps.lock`, then embeds the
guest assets and both host tools in the Go binary. Zaigr extracts slirp4netns under
`~/.zaigr/` and does not depend on a system slirp4netns package. It needs Go
1.24, Rust 1.82.0 with the `x86_64-unknown-linux-musl` target installed,
`x86_64-linux-musl-gcc`, `gperf`, `pkg-config`, `make`, `binutils`, `git`,
`curl`, `tar`, and Linux headers. The daemon build script downloads the
checksum-pinned libcap-ng and libseccomp sources from `deps.lock` and builds
their static musl libraries; host development copies of those libraries are not used. The
kernel build additionally needs GCC, flex, bison, and bc. The rootfs build
needs mmdebstrap, fakeroot, zstd, openssl, and e2fsprogs. See
[`vm_prep/build-virtiofsd.sh`](vm_prep/build-virtiofsd.sh) for exact source
revisions, checksums, and validation.

The virtiofs integrity acceptance test additionally needs host `gcc`,
`libsqlite3-dev` (headers and static archive), and Python test dependencies.

An older project image may require `zaigr project rebuild` after upgrading
the bundled guest runtime. A customized global base image may require
`zaigr global base-image reset` and reapplying its setups. The CLI reports
the appropriate action when it finds a runtime mismatch. Host workspace
and agent-state files remain in their existing directories.

When upgrading from a Zaigr version that used TCP management SSH, stop any
running VM with the version that started it. Then use the new version to run
`zaigr project rebuild` before starting the project again.

## More help

See [terminology](docs/terminology.md) for definitions. For commands and flags,
run `zaigr --help` or add `--help` to a command.

See [known issues](KNOWN_ISSUES.md) for current limitations and workarounds, and
the [roadmap](ROADMAP.md) for planned improvements.

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
