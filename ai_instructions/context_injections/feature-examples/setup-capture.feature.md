# Create A Setup From A Project Capture

## User Story

As a zaigr user, I want to experiment in a project VM and turn the working
result into a reusable setup, so I do not have to write setup files before I
know what works.

## CLI

```bash
zaigr project setup capture start
zaigr project setup capture review
zaigr project setup capture accept
zaigr project setup capture discard
```

## Acceptance Criteria

- Only one setup capture can be active for a project.
- A new capture cannot start while another capture is active.
- An active capture must be accepted or discarded before another can start.
- Capture starts from the current project image and writes changes to a capture overlay when no VM is running.
- Capture can attach to an already-running project VM after warning that discard will not undo VM changes.
- Accepting a capture creates or updates the global setup definition.
- Accepting a capture promotes the capture overlay so the user can keep working.
- Discarding a capture removes the project capture without changing global setups.
- Discarding a capture does not promise to undo VM changes.

## Docs Example

Use capture when the setup commands or firewall entries are not known yet.

```bash
zaigr project setup capture start
```

In the capture shell, make the environment work:

```bash
apt-get update
apt-get install -y podman pipx
pipx install kas
podman info
```

During capture, zaigr tracks runtime endpoints used by the workflow.

Review and accept the candidate:

```bash
zaigr project setup capture review
zaigr project setup capture accept
```

Review shows the observed endpoints and the proposed `setup.firewall` entries.

Accept writes the global setup definition:

```text
~/.zaigr/setups/<setup-name>/
```

Verify from a clean non-root runtime:

```bash
zaigr project clean
zaigr shell --setup <setup-name> --preset claude
```

Discard instead of accepting:

```bash
zaigr project setup capture discard
```

Discard removes the capture record. It does not undo changes made inside the VM.


## Gherkin

Feature: Setup capture firewall allowance is scoped to the capture session

  User story:
    As a zaigr user, I want setup capture to allow network access only for
    commands I run inside the capture session, so a parallel project shell
    cannot gain network access because capture is active.

  Scenario: Setup capture does not relax firewall policy for a parallel project shell
    Given a project VM is initialized
    And "download.docker.com" is not in the project firewall allow list
    And a normal non-capture project shell is active
    When the normal project shell connects to "download.docker.com"
    Then the connection is blocked by the normal project firewall policy
    When a setup capture shell is started in parallel
    And the capture shell connects to "download.docker.com"
    Then the capture shell connection succeeds
    And setup capture records "download.docker.com" as an observed endpoint
    When the normal project shell connects to "download.docker.com" while capture is active
    Then the connection is still blocked by the normal project firewall policy
    When the setup capture shell exits
    And the normal project shell connects to "download.docker.com"
    Then the connection is still blocked by the normal project firewall policy

  Test requirements:
    The test must run the setup capture shell and normal shell at the same time.
    The test must verify the normal project shell is blocked before capture starts,
    while capture is active, and after capture exits.
    Before asserting firewall behavior, the test harness must prove
    "download.docker.com" resolves from inside the project VM.
    The test must distinguish a blocked connection from DNS failure or missing tooling.
    The test must verify the observed endpoint appears in setup capture review.
    The test must not grant a manual firewall allow rule for the target domain.
