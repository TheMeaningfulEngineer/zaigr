# Terminology

## Project

A project starts as a directory containing the work a user wants to do.

A directory becomes a zaigr project once zaigr creates a project store for it.

The project directory is the user workspace. Zaigr-owned project state lives in
the project store, not in the project directory.

## Project store

The `project store` is zaigr's per-project state directory under
`~/.zaigr/store/<hash>/`.

The `<hash>` is derived from the canonical absolute project path.

Moving or renaming a project directory creates a new project identity and a new project store.

It contains the project metadata and project images associated with a project.

## Project metadata

`project metadata` is zaigr-owned non-image records inside the project store
that describe or track the project.

Project metadata does not include project image disk contents or user workspace
files.

## Base image

The `base image` is the small bootable virtual machine image built into the `zaigr` binary.
It serves as the starting point for every project image.

## Project image

A `project image` is the saved VM disk state that project VMs boot from.
It is stored in the project store.

A project image starts from the base image and changes when setups are committed
for that project.

## Dirty project image

A `dirty project image` contains VM disk changes that are not represented by committed setups.

These are ad-hoc changes, usually made manually in a root shell.
They may be useful for experimentation, but zaigr cannot recreate them from setup metadata until they are turned into a setup or otherwise captured explicitly.

## Project VM

A `project VM` is a running VM booted from a project image.

While the VM runs, disk changes are written to a writable layer separate from the project image.
Those changes are not part of the project image until they are committed.


## Setup

A `setup` adds a reusable capability to a project VM.

A setup bundles the installation steps and firewall requirements for a category of work i.e Python, Go, Node.js...

Once a setup is committed for a project, future project VMs can start with that capability already available.

A setup can also be applied to a running project VM first and committed later.

Implementation wise, a setup is a folder named after the setup, containing script files and optional firewall rule files.


## Preset

A `preset` starts a project VM in a ready-to-use mode.

A preset uses setups as building blocks, then runs the command or tool the user actually wants to use inside the project VM.

Implementation wise , a preset is a folder named after the preset, containing a run script
and optional setup dependencies.

Use setups for reusable capabilities. Use presets for complete entry points.
