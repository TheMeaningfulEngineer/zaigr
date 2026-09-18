# Detect Parent Project

## User Story

As a zaigr user, I want `zaigr shell` to notice an initialized parent project
from a child directory, so I can choose the intended project root.

## Acceptance Criteria

- If the current directory is not initialized and a parent project is,
  `zaigr shell` prompts before creating a new project.
- The prompt offers cancel, run parent project, and proceed with new project.
- The prompt follows the existing CLI prompt format used elsewhere.
- Cancel exits without creating project metadata or starting a VM.
- Run parent project starts the shell for the detected parent project.
- Proceed with new project continues the current new-project flow.
- If the current directory is initialized, no parent-project prompt is shown.

## Docs Example

```bash
cd /home/mydir/project/bob
zaigr shell
```

When `/home/mydir/project` is already initialized, zaigr prompts:

```text
:: A zaigr project is already initialized for a parent directory.
   parent project: /home/mydir/project
   current directory: /home/mydir/project/bob
   [c] cancel       Exit without starting a shell
   [p] parent       Run the parent project
   [n] new project  Proceed with a new project here
Action [c/p/n]:
```

## Gherkin

Feature: Shell startup detects an initialized parent project

  Scenario: Nested shell can run the parent project
    Given a zaigr project is initialized at "/home/mydir/project"
    And no zaigr project is initialized at "/home/mydir/project/bob"
    When the user runs "zaigr shell" from "/home/mydir/project/bob"
    Then zaigr prompts that a parent zaigr project already exists
    And the prompt offers cancel, run parent project, and proceed with new project
    When the user chooses run parent project
    Then the shell starts with "/home/mydir/project" mounted as the workspace
    And the shell does not use "/home/mydir/project/bob" as the project root
    And no project metadata is created at "/home/mydir/project/bob"
