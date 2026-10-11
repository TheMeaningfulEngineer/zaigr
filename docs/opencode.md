# OpenCode

Run this from your project directory on the host:

```sh
zaigr shell --preset opencode
```

Zaigr installs OpenCode **2.0.26** in the project VM and launches its terminal
interface. The preset starts the Build agent with automatic approval of tools
that your OpenCode configuration does not explicitly deny. Zaigr's VM and
firewall remain the execution boundary.

## Connect a provider

1. Create an account and API key on your provider's website in the host browser.
2. In OpenCode, enter `/connect`, select the provider, and paste the API key.
3. Enter `/models` and select a model from that provider before sending a task.

Check the selected provider and model in the terminal footer. OpenCode can
initially select a free OpenCode Zen model; launching the preset does not itself
select European hosting. Provider catalogs also include proprietary models.
Choose an open-weight model with tool calling and check its license if that
matters for your work.

Provider authentication, model selection, and billing belong to OpenCode and
the provider. Zaigr does not host the model or copy API keys from your host
environment. Saved connections and conversations are retained for this project.
See [OpenCode's provider guide](https://opencode.ai/v2/docs/cli/providers/).

## European hosting options

| Provider | Endpoint | Notes |
| --- | --- | --- |
| Scaleway | `https://api.scaleway.ai/v1` | Suggested starting point. Scaleway documents serverless inference in Paris, France. [Location](https://www.scaleway.com/en/docs/generative-apis/faq/). |
| OVHcloud AI Endpoints | `https://oai.endpoints.kepler.ai.cloud.ovh.net/v1` | OVHcloud documents hosting and execution in the EU. [Service](https://www.ovhcloud.com/en/public-cloud/ai-endpoints/). |
| Mistral | `https://api.eu.mistral.ai/v1` | The initial OpenCode configuration uses the regional endpoint. It has model/feature restrictions and a regional surcharge; the documented location covers EU/EFTA infrastructure. [Regional inference](https://docs.mistral.ai/inference/regional-inference). |

Scaleway and OVHcloud are included in the pinned CLI's provider catalog. Choose
a currently available coding model that supports tools; catalog presence alone
does not guarantee a successful agent task. The separate `mistral` Zaigr preset
continues to launch Mistral Vibe.

The OpenCode setup also allows Fireworks, Together AI, Groq, Cerebras, OpenRouter,
Nebius Token Factory, and OpenCode's hosted services for comparisons. Those
routes have no European processing guarantee from Zaigr. This preset is not an
EU-only network policy: permissions apply to the project VM and accumulate with
other setups and manual grants.

## Saved state and settings

Inside the preset, state lives under `/home/user/.zaigr-agent-state/opencode`:

| Relative path | Contents |
| --- | --- |
| `config/opencode/opencode.json` or `.jsonc` | Global settings |
| `data/opencode/opencode.db` | OpenCode database, including saved credentials and sessions |
| `state/opencode` | Application state |
| `cache/opencode` | Downloaded metadata and caches |

Zaigr backs this directory with the project's host agent-state storage. It is
separate from your source tree and survives VM restarts, project clean, and
rebuild. Back it up only after exiting OpenCode and stopping the VM; include the
whole directory. Treat backups as credentials.

The preset creates initial settings only when neither global config file
exists. Your subsequent edits are preserved. The initial settings disable
automatic updates, set Mistral's regional base URL, and use Together's current
API hostname instead of the older hostname embedded in this CLI release:

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

Existing or project-local OpenCode settings can change the effective provider
endpoint. See [V2 configuration](https://opencode.ai/v2/docs/config/) for the
current format.

## Updates and troubleshooting

Exit OpenCode, then run on the host:

```sh
zaigr project setup run opencode --force
zaigr shell --preset opencode
```

This installs the version pinned by your Zaigr release. Upgrade Zaigr to receive
a newer tested pin. After `zaigr project clean`, launching the preset reinstalls
the CLI while keeping saved agent state.

OpenCode uses a private authenticated loopback server per terminal session.
There is no service to start or host port to expose. Use `/exit` to finish.

If a provider or optional tool cannot connect, inspect requested domains:

```sh
zaigr project firewall domain-log
```

Add only the required hostname through a local setup's `setup.firewall`.
Provider console sites, arbitrary model hosts, MCP servers, and language-server
downloads are not automatically allowed. An authentication error can indicate
a missing or invalid key even when networking works.

No paid provider inference has been validated for this preset yet. The
acceptance tests exercise the real CLI without sending model prompts; provider
accounts are still needed to verify coding quality and tool support.
