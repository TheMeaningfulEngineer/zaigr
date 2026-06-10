# zaigr

Run AI coding agents without approval prompts inside a per-project minimal VM with restricted workspace and network access.

## Quickstart

Install the Debian package from a release:

```sh
sudo apt install ./zaigr_<version>-<build>_amd64.deb
```

Check that the host can run `zaigr`:

```sh
zaigr misc check
```

Start an AI agent in a new project:

```sh
mkdir my-project
cd my-project
zaigr shell --preset codex
# or
zaigr shell --preset claude
```

### What does this do?

`zaigr` creates project metadata for the current directory, boots a project VM, mounts that directory as the workspace, and starts the selected agent.

### What can the agent access?

The project workspace is the directory where you started `zaigr shell`.

### Does it have full network access?

No. Runtime network access is restricted by what is defined in the base image plus what you allowed through the installed 'setups'.

Run `zaigr project firewall show` to see what is whitelisted.

### How do I allow the same domain for every project?

Use the global firewall allowlist for exact hostnames that are acceptable across
all projects:

```bash
zaigr global firewall allow github.com api.github.com
zaigr global firewall list
zaigr global firewall remove github.com
```

When global firewall entries exist, project VM startup prints a warning and
applies them in addition to setup firewall entries.

### How do I make temporary firewall changes inside a VM?

From inside the project VM, root can use `zaigr-inside`:

```bash
sudo zaigr-inside firewall allow example.com
sudo zaigr-inside firewall list
sudo zaigr-inside firewall remove example.com
```

These are ad hoc runtime changes. They are useful for experimentation, but they
are not a replacement for committed setup firewall files.

### How do I turn an experiment into a setup?

Use setup capture when you do not know the commands or firewall entries yet:

```bash
zaigr project setup capture start
zaigr project setup capture review
zaigr project setup capture accept
```

Capture records the commands you ran and the observed domains, then proposes a
reusable setup with a `setup.script` and `setup.firewall`. Use
`zaigr project setup capture discard` to drop the capture instead.


### What's a setup?

A setup is a named installation step for the project image, plus the firewall allowlist it needs.

For example, the `python` setup has:

- `setups/python/setup.script`
- `setups/python/setup.firewall`

It's a way to customise the image in a reproducible way.

You add setups to an image individually:

```bash
zaigr project setup run python
zaigr project setup run go
zaigr project setup run nodejs
```


by applying implicitly  throgh a 'preset' dependency.

```bash
zaigr shell --preset codex
```

or as convenience flag when starting a shell or a preset

```bash
zaigr shell --setup go --setup python
```

### What's a preset?

A preset is a way to starts a shell of an interactive tool.
It has dependencies set to start the installation of the needed setups.

Built-in presets:

- `codex`
- `claude`
- `zaigr-dev`

## [Experimental] AI instruction hooks

This repository can inject path-specific context into supported agents when they
read or edit files. Install the hook config explicitly from the project root:

```bash
ai_instructions/scripts/install_hooks.sh codex
ai_instructions/scripts/install_hooks.sh claude
```

Use `all` to install both. The installer writes Codex hooks to
`$CODEX_HOME/hooks.json` or `~/.codex/hooks.json`, and Claude hooks to
`$CLAUDE_CONFIG_DIR/settings.json` or `~/.claude/settings.json`. Existing files
are left untouched unless you pass `--force`.

The descriptions in `ai_instructions` is specific for zaigr development at the moment. If they end up improving the inference quality the plan is to incorporate them into zaigr flow so they can be used for project.
