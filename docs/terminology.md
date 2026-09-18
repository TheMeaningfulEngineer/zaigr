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

Once applied, its tools and permissions remain available on later VM starts.
A **project-local setup** is kept with one [project](#project)'s code so it can
be shared with that code.

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

A recording of shell commands and observed network domains while you experiment
in a [VM](#project-vm). Accepting it saves a reusable [setup](#setup).
Only activity during the capture is recorded; earlier manual changes are not
reconstructed.

Discarding a capture does not undo edits to your project files. If it used an
already-running VM, changes inside that VM remain too.

## Project store

Where zaigr keeps a [project](#project)'s saved environment, settings, and agent
state, separate from your working files.
