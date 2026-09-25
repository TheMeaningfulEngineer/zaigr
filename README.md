# zaigr

Run AI coding agents without approval prompts in a [VM](docs/terminology.md#project-vm)
for each [project](docs/terminology.md#project).

## Installation

Requires Linux x86-64 with usable KVM.

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
sudo apt install coreutils e2fsprogs openssh-client qemu-system-x86 qemu-utils
```

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

The check reports whether KVM access, QEMU, and free disk space are ready.

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

### I need the agent to access another domain

Open a root shell in the [VM](docs/terminology.md#project-vm):

```sh
zaigr shell --root
```

Inside that shell, allow the hostname you need. For example:

```sh
zaigr-inside firewall allow docs.python.org
zaigr-inside firewall list
exit
```

The agent can now access that domain. This leaves the
[project image](docs/terminology.md#project-image)
[dirty](docs/terminology.md#dirty-project-image), which is expected for manual
changes. The permission is an ad hoc runtime change.

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

Start a [capture](docs/terminology.md#setup-capture) from the host:

```sh
zaigr project setup capture start
```

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

Discarding a [capture](docs/terminology.md#setup-capture) attached to an already
running [VM](docs/terminology.md#project-vm) does not undo the changes you made.

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

## More help

See [terminology](docs/terminology.md) for definitions. For commands and flags,
run `zaigr --help` or add `--help` to a command.

See [known issues](KNOWN_ISSUES.md) for current limitations and workarounds, and
the [roadmap](ROADMAP.md) for planned improvements.

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
