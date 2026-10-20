# Terminology

[Back to the examples](../README.md#examples-to-get-you-started)

## Project

The directory containing the files you want an agent to work on. Zaigr gives it
its own [VM](#project-vm) and saved environment.

Moving or renaming the directory makes zaigr treat it as a new project.

## Project VM

The virtual machine where the agent and its tools run. It uses the
[project image](#project-image) and can edit your [project](#project)'s files.

Stopping the VM keeps the saved environment and your working files for later use.

## Setup

A reusable recipe for adding tools and their network permissions to the
environment. For example, the `python` setup adds Python tooling.

Global setup definitions live in `~/.zaigr/setups/<name>/` and can be edited.
Built-in defaults populate a setup only when its directory is absent. A
`project rebuild` or `global projects rebuild` that replays an applied global
built-in setup replaces it with the default shipped in the current zaigr
binary before replay. This also removes files that are no longer part of that
recipe. Custom global setups and project-local setups are preserved. Other
entry points such as `project vm start`, `zaigr shell`, and `project setup
run` continue to preserve an existing extracted copy and warn if it differs
from the bundled default. The refreshed default remains installed if a later
replay step fails; projects sharing the global setup directory see the adopted
recipe as well. Use a project-local setup for per-project changes to a built-in
recipe.

Once applied, its tools and permissions remain available on later VM starts.
A **project-local setup** is kept with one [project](#project)'s code so it can
be shared with that code.

During a rebuild, project-applied setups run in their recorded order. Inherited
setups come from the base image and are not replayed. Reapplying an existing
project setup keeps its place; applying a new setup adds it to the end.

A setup version hashes the relative filenames and contents of every top-level
`*.script` and `*.firewall` file in its recipe. It identifies the recipe source;
it does not promise that repeated runs install the same app versions. Pin an
app version only when a specific version matters.

For reusable setups (built-ins and setups shared through preset markers):

1. Each setup installs its own prerequisites. It may rely on tools in the
   factory base image, but not on another setup running first; preset order is
   not a contract.
2. Install prerequisites with apt. If Debian lacks a dependency or its package
   is too old, use the vendor's apt repository. Use a non-apt installer for the
   setup's headline tool, or when no suitable apt channel is available.

These are authoring rules for reusable setups. Captures and deliberately
ordered, non-shared project-local recipes keep their recorded-order contract;
explicit setup batches keep the order given on the command line. Two reusable
setups should not install conflicting versions of the same global npm, pip, or
cargo package. Use a virtual environment or a dedicated prefix when isolation
matters. Zaigr does not detect or enforce this convention.

Older versions alphabetized project setup histories. An upgrade retains that
stored order; it cannot reconstruct the original application order. Captured
recipes in affected histories may still need to be self-contained. If replay
fails, abort the rebuild and run `zaigr project vm start` to continue using the
existing environment. Running an older binary can alphabetize the history again.

## Preset

A named way to launch an agent or shell with the [setups](#setup) it needs.
For example, the `codex` preset prepares and starts Codex.

## Base image

The starting environment used to create a [project image](#project-image).

- **Factory base image:** the default environment supplied with zaigr.
- **Global base image:** the default for new [projects](#project). It can be the
  factory environment or one you have customized with [setups](#setup).

Changing the global default does not change existing projects. They adopt it
when you explicitly clean or rebuild them.

## Project image

The saved operating system, installed tools, and system changes for one
[project](#project). It persists between [VM](#project-vm) starts.

Your working files stay in the project directory, separate from this image.

## Dirty project image

An image marked as possibly containing manual changes that zaigr cannot recreate
from [setups](#setup). Opening a root shell marks it dirty, even if you make no
changes.

Dirty is normal for manual work. Rebuilding a dirty image requires `--force` and
discards any manual changes that are not recorded in setups.

## Setup capture

A recording of shell commands and host-observed DNS domains while you experiment
in an isolated capture [VM](#project-vm). The project VM must be stopped before
capture starts. Accepting it saves a reusable [setup](#setup).
Only activity during the capture is recorded; earlier manual changes are not
reconstructed.

A capture does not include prerequisites from earlier project-local setups.
It may rely on project state that will not travel with it, so reusing it in
another project can fail unless those prerequisites are applied there too.

Discarding a capture removes its image overlay but does not undo edits to your
shared project files.

## Project store

Where zaigr keeps a [project](#project)'s saved environment, settings, and agent
state, separate from your working files.
