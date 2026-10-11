# OpenCode preset implementation design

Design and implementation notes, researched October 11, 2026. The builtin
preset targets OpenCode 2.0.26. See [the user guide](opencode.md) for onboarding;
the validation record below distinguishes completed checks from remaining work.

## Intended experience

Launch OpenCode in the current project using the same workflow as the existing
Codex, Claude Code, and Mistral Vibe presets:

```sh
zaigr shell --preset opencode
```

On first use, create a hosted-provider account and API key in the host browser.
Inside OpenCode, use `/connect` to save the key and `/models` to choose a model.
Subsequent launches retain accounts, settings, and conversations. Switching
between the supported hosts or models requires no new Zaigr command.
[OpenCode account workflow](https://opencode.ai/v2/docs/cli/providers/)

Zaigr supplies installation, the project VM, persistent agent state, and outbound
network permissions. OpenCode supplies the agent, provider authentication,
endpoint configuration, and model selection. The selected provider hosts the
model and handles billing. There is no GPU or inference deployment in this
feature, and Zaigr gains no model catalog, credential manager, or billing layer.

Recommend Scaleway first and OVHcloud second for trying models hosted in Europe.
Keep other providers available for comparisons. This is a recommendation about
hosting and integration, not a coding-quality benchmark.

## Integration with the repository

| File | Change |
| --- | --- |
| `cmd/zaigr/builtin/setups/opencode/setup.script` | Install a pinned OpenCode 2 CLI and its system dependencies. |
| `cmd/zaigr/builtin/setups/opencode/setup.firewall` | Exact hostnames for installation, required metadata, and the provider shortlist below. |
| `cmd/zaigr/builtin/presets/opencode/run` | Check the state mount, establish OpenCode paths and initial settings, launch the private server and TUI. |
| `cmd/zaigr/builtin/presets/opencode/setups/opencode` | Reference the `opencode` setup. |
| `cmd/zaigr/builtin/presets/zaigr-dev/setups/opencode` | Include OpenCode in the development preset's complete setup list. |
| `tests/builtin/test_opencode.py` | Real installation, concurrent launch, persistence, and lifecycle acceptance coverage. |
| `tests/cli/test_preset_isolation.py` | Existing isolation regression coverage, unchanged. |
| `README.md` and a new `docs/opencode.md` | Launch/update examples, provider onboarding, European endpoint configuration, troubleshooting. |

`builtin_resources.go` already embeds and discovers these directory structures.
`loadPresetPlan` already applies preset setup references. No new Zaigr commands
or provider-specific Go implementation are expected.

Leave the existing `mistral` preset available: it launches Mistral Vibe, whereas
selecting Mistral within OpenCode changes the model provider while retaining the
OpenCode harness.

## Installation and version policy

Target OpenCode **2**, explicitly. Its documented npm package is `@opencode/cli`;
the older `opencode-ai` package and V1 configuration examples must not be mixed
into this implementation. The npm installer selects a native platform binary.
[OpenCode 2 installation](https://opencode.ai/v2/docs/)

Use the existing standalone-setup pattern: install `nodejs`, `npm`,
`ca-certificates`, `git`, and `ripgrep` as needed, then install an exact tested
`@opencode/cli` version globally. The implementation pins **2.0.26**. npm fetches
the CLI and its native platform packages from the registry; the postinstall
script selects the binary for the guest. There is no automatic fallback to V1.

Installation must work without provider credentials. It must not create root's
OpenCode session or start a background service. Run version/help checks only.
Avoid copying host configuration or credentials into the image.

Disable OpenCode's update checks in the initial global config. Updates go through
the versioned Zaigr setup:

```sh
zaigr project setup run opencode --force
zaigr shell --preset opencode
```

This reinstalls the version bundled with the installed Zaigr release; upgrading
Zaigr can advance that pin. Exit active OpenCode sessions before updating.
Database migrations require a stopped-state backup and a tested restore path
before introducing a version that changes the persistent format.

## Process lifecycle and persistence

Launch `opencode --standalone --auto` as the normal guest user, inside Zaigr's existing
isolated preset launcher. It creates a private OpenCode server for the terminal
client instead of joining a shared background service. Do not install a systemd
service or create a host-access port grant.
[OpenCode server lifecycle](https://opencode.ai/v2/docs/cli/#background-service)

```text
Zaigr project VM
  isolated preset session
    OpenCode terminal <-> private OpenCode server
                                |
                                +--> allowed hosted-model API
```

Use `/home/user/.zaigr-agent-state/opencode` as the persistent root. Check the
parent mount before creating anything, matching the existing presets, and use
`umask 077`. XDG layout:

| Environment variable | Value relative to that root |
| --- | --- |
| `XDG_CONFIG_HOME` | `config` |
| `XDG_DATA_HOME` | `data` |
| `XDG_STATE_HOME` | `state` |
| `XDG_CACHE_HOME` | `cache` |

OpenCode appends its own application directory. Verify the complete resolved
layout with `opencode debug paths` under the pinned release. The expected config
is `config/opencode/opencode.json`; the usual release database would become
`data/opencode/opencode.db`. V2 stores saved provider credentials in that SQLite
database, so preserving only a legacy `auth.json` would be insufficient.
[OpenCode credential storage](https://opencode.ai/v2/docs/cli/providers/#storage)

Keep `HOME=/home/user`. Runtime sockets, process markers, and temporary files
belong in a private, ephemeral guest runtime directory, not the persistent 9p
share. The pinned release uses `os.tmpdir()`, so the preset supplies a unique
`TMPDIR` and removes it on exit. The wrapper forwards termination signals while
waiting for the client. Upstream standalone mode uses a random 32-byte password
and a stdin pipe lease that closes when its client exits; it does not register a
shared service or persist the server password.
The launcher clears inherited environment variables, so onboarding should use
OpenCode's credential UI rather than promising that an API key exported on the
host will reach the agent.

Two compatibility checks come before the final launcher implementation:

1. **Database storage.** `runtime-setup` mounts agent state using 9p with
   `cache=mmap`. Exercise actual OpenCode database creation, writes, restart,
   interruption recovery, and two simultaneous sessions. Check for locking or
   mmap errors and lost credentials/history. If this fails, revise the storage
   design before shipping; do not silently put credentials in the disposable
   project image or copy a live database on exit.
2. **Server isolation.** The existing launcher isolates mounts and PIDs, but
   shares the VM's network namespace. A loopback listener alone does not isolate
   one preset from another. Verify private-server transport/authentication and
   that another preset cannot access its session or credential APIs. Prefer the
   upstream private transport; do not invent a Zaigr server protocol. Normal
   exit, interruption, and terminal disconnection must leave no usable backend.

These are release gates, not claims of defects. Existing PID-namespace teardown
is useful but must be checked with the actual OpenCode process tree.

## Initial configuration

Create initial global settings atomically when neither a JSON nor JSONC global
config already exists. Never rewrite the user's settings on every launch, and
never generate credential files or configuration in the workspace automatically.

Start with the Build agent and permissive tool execution, consistent with
Zaigr's other agent presets. Use the pinned CLI's `--auto` flag, which approves
tool requests unless explicitly denied by user policy. The initial V2 config is:

```json
{
  "default_agent": "build",
  "update": "disable",
  "providers": {
    "mistral": {
      "settings": { "baseURL": "https://api.eu.mistral.ai/v1" }
    },
    "togetherai": {
      "settings": { "baseURL": "https://api.together.ai/v1" }
    }
  }
}
```

Validate this against the pinned release, including the Mistral provider's base
URL convention. Explicit project or agent policies can still impose restrictions;
preserve those choices. Tool approval is separate from firewall policy, which
remains exact-hostname based. Leave the model unset; OpenCode may select a free
Zen model initially, so onboarding must tell the user to choose the intended
provider before submitting a task. Do not configure fallback providers or
background model warming. Together's override is necessary because this pinned
release otherwise uses `api.together.xyz`.
[V2 config](https://opencode.ai/v2/docs/config/),
[permission rules](https://opencode.ai/v2/docs/permissions/),
[provider endpoint overrides](https://opencode.ai/v2/docs/providers/#endpoint)

Prefer integrations already present in the pinned OpenCode catalog. Where an
integration is absent, document OpenCode's own custom-provider configuration;
do not add a Zaigr adapter. Any example must specify a current model ID, actual
context/output limits, streaming and tool-call support. API compatibility alone
does not establish that a model can complete an agent workflow.

## Hosted providers and firewall plan

The following is a practical compatibility shortlist, not a measured popularity
ranking. All listed hostnames are candidates for the single OpenCode setup's
default allowlist, subject to validation with the pinned CLI. This keeps normal
provider switching inside OpenCode. No provider is contacted merely because its
hostname is allowed.

### European options to document first

| Provider | Exact inference hostname and base path | Hosting evidence and integration notes |
| --- | --- | --- |
| **Scaleway Generative APIs** | `api.scaleway.ai` — `/v1` | Recommended starting point. Scaleway documents serverless inference in Paris, France, and an OpenAI-compatible API with tool calling. Use its OpenCode integration or the compatible-provider configuration. [Location](https://www.scaleway.com/en/docs/generative-apis/faq/), [API](https://www.scaleway.com/en/developers/api/generative-apis). |
| **OVHcloud AI Endpoints** | `oai.endpoints.kepler.ai.cloud.ovh.net` — `/v1` | OVHcloud explicitly states that AI Endpoints is hosted and runs in the EU. Its common endpoint avoids allowing a wildcard for individual model hosts. [Hosting](https://www.ovhcloud.com/en/public-cloud/ai-endpoints/), [endpoint example](https://www.ovhcloud.com/en-gb/public-cloud/ai-endpoints/catalog/qwen3-embedding-8b/), [OpenCode integration](https://opencode.ai/docs/providers/#ovhcloud-ai-endpoints). |
| **Mistral regional inference** | `api.eu.mistral.ai` — `/v1` | Use the regional endpoint explicitly. Documentation describes EU/EFTA infrastructure, a 10% regional surcharge, and model/feature limitations. The global `api.mistral.ai` endpoint makes no location commitment. Control-plane metadata is outside the inference-location guarantee. Verify the selected coding model and tool workflow on the regional endpoint. [Regional inference](https://docs.mistral.ai/inference/regional-inference). |

The OVHcloud integration link describes V1; use it as evidence of the existing
integration, then verify catalog availability and behavior in the pinned V2
release. Do the same for Scaleway. Avoid importing V1 configuration syntax.

### Common alternatives for model comparisons

| Provider | Exact inference hostname | API base path / purpose |
| --- | --- | --- |
| Fireworks | `api.fireworks.ai` | `/inference/v1`; direct hosted inference. [API](https://docs.fireworks.ai/tools-sdks/openai-compatibility). |
| Together AI | `api.together.ai` | `/v1`; use the current documented hostname rather than assuming the older `.xyz` endpoint. [API](https://docs.together.ai/docs/inference/openai-compatibility). |
| Groq | `api.groq.com` | `/openai/v1`; direct hosted inference. [API](https://console.groq.com/docs/openai). |
| Cerebras | `api.cerebras.ai` | `/v1`; direct hosted inference. [API](https://inference-docs.cerebras.ai/resources/openai). |
| OpenRouter | `openrouter.ai` | `/api/v1`; a router to upstream providers. [API](https://openrouter.ai/docs/quickstart). |
| Nebius Token Factory | `api.tokenfactory.nebius.com` | `/v1`; officially documented OpenCode integration. The reviewed material does not establish an EU-only guarantee for this endpoint; do not label it as such. [Integration](https://dev.nebius.com/cookbook/opencode-nebius-token-factory). |
| OpenCode Go | `opencode.ai` | `/zen/go/v1`; optional subscription access, selected like another provider. [Service and endpoints](https://opencode.ai/docs/go/). |

There is no European processing guarantee for the alternative routes in this
design. OpenRouter's single allowed hostname also does not constrain its upstream
routing. OpenCode/provider catalogs can include closed models; the guide should
explain how to choose an open-weight model and check its license.

### Firewall boundaries

Keep literal hostnames in `setup.firewall`, following the existing setup format.
Do not put schemes, URL paths, IP ranges, parent-domain wildcards, or all of
OpenCode's provider catalog into the file. The base paths above configure the
client; Zaigr's hostname rules cannot restrict URL paths.

Account creation, API-key creation, and payment happen in the host browser.
Provider console/login domains are therefore not included automatically. If a
supported OpenCode authentication method actually contacts another host from
the guest, capture and justify that exact hostname before adding it.

Installer/runtime candidates, separate from inference hosts:

| Hostname | Reason and validation |
| --- | --- |
| `registry.npmjs.org` | npm package and platform dependency downloads. Inspect the selected package's install behavior for additional downloads. |
| `models.opencode.ai` | The pinned V2 release refreshes its bundled provider/model catalog here. Earlier research identified `models.dev`; source inspection established this separate exact hostname. [Pinned catalog implementation](https://github.com/anomalyco/opencode/blob/v2.0.26/packages/core/src/models-dev.ts). |

Use the base image's existing Debian repository access for apt. Do not add
GitHub, release CDNs, telemetry, web-search providers, MCP services, or language
server download hosts speculatively. Install/first-launch traces determine any
additional necessary exact hosts. User-enabled tools can use the existing local
setup/firewall workflow.

Inspect traffic using `zaigr project firewall domain-log`. Exercise installation
and the normal user launch with the effective firewall active; successful
installation alone does not prove the agent can reach its provider. Reconcile
actual requests with this table, including any old hostname still embedded in
the chosen OpenCode catalog.

This default supports European providers but is **not an EU-only egress policy**.
Firewall permissions accumulate at project/VM scope; other installed setups and
manual/global grants also matter. Enforcing only European routes would require
reviewing that full policy and provider configuration, not merely selecting the
OpenCode preset. No new geographic-policy feature is proposed here.

## Acceptance and implementation order

1. **Resolve compatibility first.** Select the exact V2 package version; inspect
   installation hosts, guest compatibility, resolved paths, SQLite behavior on
   9p, private-server isolation, and shutdown. Record results beside the design.
   If a gate fails, revise the relevant design section before implementing a
   workaround.
2. **Add the four builtin files.** Check discoverability, initial setup, launch,
   missing-state-mount failure, and repeat launch. Do not change the existing
   preset launcher unless the compatibility work establishes a concrete need.
3. **Exercise persistence and concurrency.** Create a real OpenCode session and
   a disposable test account through supported interfaces. Reopen after normal
   exit, interruption, VM stop/start, project clean, and rebuild. Confirm the
   account and session remain visible and no secrets appear in the workspace.
   An inert test key may be used for storage tests without sending inference.
   Confirm simultaneous sessions neither attach to each other's server nor
   corrupt the shared database.
4. **Verify network and coding behavior.** With test credentials when available,
   use the actual OpenCode client on Scaleway first, OVHcloud next, then other
   advertised providers. A small scratch task must read a file, edit it, run a
   command, consume a tool result, and finish with a streamed response. Record
   provider, endpoint, model ID, CLI version, date, and result. A model list or
   HTTP 401 proves reachability at most, not working agent support. Report
   untested providers explicitly. Keep paid inference out of mandatory CI.
5. **Document and run focused checks.** Add user-facing onboarding and update
   instructions, then run the affected builtin/preset acceptance tests and
   existing isolation regressions. Use the repository's normal test transcript
   tooling; no new Go unit tests or elaborate provider mocks.

Use public `zaigr` commands visibly in test bodies. Interactive helpers cover
the actual shell/TUI experience; `project vm exec` covers ordinary guest
inspection. Assert observable behavior rather than matching firewall-file text.
Network restrictions should also prevent an unlisted destination during the
tested workflow. Keep provider credentials out of command arguments and recorded
test transcripts; credentialed checks need a secret-safe input path.

End-to-end provider validation means a fresh project can launch OpenCode,
connect a documented European provider, perform an agent task, and reopen its
saved state while the existing VM and preset isolation properties hold.

## Validation record

The implementation installs `@opencode/cli@2.0.26` and preserves all four XDG
directories. A Linux compatibility probe confirmed the version, resolved paths,
TUI launch/exit, session creation, and saving an inert Scaleway credential.
Inspection of the pinned upstream implementation confirmed standalone server
authentication and pipe ownership, and identified Together's hostname override.
[Standalone source](https://github.com/anomalyco/opencode/blob/v2.0.26/packages/cli/src/services/standalone.ts),
[server process](https://github.com/anomalyco/opencode/blob/v2.0.26/packages/cli/src/server-process.ts),
[Together provider](https://github.com/anomalyco/opencode/blob/v2.0.26/packages/ai/src/providers/togetherai.ts).

Verified on October 11, 2026 with the pinned release in a 2 GiB, two-CPU Zaigr VM:

- Fresh installation and TUI launch with the Build agent and `auto` mode displayed.
- Two independent loopback servers; another preset receives HTTP 401 from each
  server's `/api/session` and `/api/credential` endpoints.
- Concurrent session creation on the shared SQLite database, followed by normal
  exit and terminal disconnection with no remaining OpenCode listeners.
- Both sessions and the exact inert credential survive VM restart, project
  rebuild, and project clean followed by reinstallation.
- Existing JSONC settings remain unchanged, and the reopened model picker lists
  Scaleway models. An unlisted destination is blocked by the runtime firewall.

`tests/builtin/test_opencode.py` passed in 834 seconds. All five existing
`tests/cli/test_preset_isolation.py` tests and the development-preset dependency
test also passed. `make build`, Bash syntax checks, Ruff on the changed tests,
and `git diff --check` passed. Independent review found no remaining material
issues after strengthening the API and concurrency assertions.

Real provider inference is untested: no paid-provider credentials were supplied,
and no model prompts have been sent. The provider shortlist documents allowed
routes and onboarding, not a completed compatibility or coding-quality
benchmark. The acceptance run does not establish successful live inference on
every allowed provider.
