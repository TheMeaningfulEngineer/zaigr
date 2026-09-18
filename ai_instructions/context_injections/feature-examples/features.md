# Feature File Guidance

Use `ai_instructions/context_injections/feature-examples/setup-capture.feature.md`
as the concrete reference.

Describe user-visible behavior before implementation detail. Keep the first
draft short, then reread it with: "Am I overcomplicating this? Can it be
shorter?" Delete anything that does not help implementation or verification.

Use only the sections the feature needs:

1. Title
`# <behavior>` in plain product language.

2. User Story
One short statement of user, goal, and reason.

3. CLI or Interface
Include this only when the feature adds or changes commands, routes, UI
     actions, or APIs.
Do not add a CLI section just to list an existing command.

4. Acceptance Criteria
Acceptance criteria are the minimum, testable conditions that must be true for this specific backlog item to be accepted as complete.

5. Docs Example
A realistic user flow, only if it clarifies the behavior.
Don't apply if it's obvious from usage.
If in doubt, ask for clerification.

6. Gherkin
One focused `Feature:` and scenario.
Add `Test requirements:` only for harness constraints or ambiguity guards.
