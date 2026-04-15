# APG - Agent Policy Gateway

**Cedar-based intent execution control for LLMs and agents.**

APG is an authorization service that sits between [AgentGateway](https://github.com/agentgateway/agentgateway) and your MCP tool servers, enforcing [Cedar](https://www.cedarpolicy.com/) policies on every tool call an agent makes. It classifies what agents are trying to do (read, write, execute, delete), assesses risk from the arguments, and evaluates Cedar policies before allowing or blocking the call.

APG integrates with AgentGateway via the [External Authorization](https://agentgateway.dev/docs/standalone/latest/configuration/security/external-authz/) (ExtAuthz) HTTP interface. AgentGateway handles MCP transport, tool federation, and protocol negotiation. APG handles intent classification, policy evaluation, and audit.

## How It Works

Every MCP tool call flows through four stages:

1. **Identity Resolution** - Who is asking? (JWT claims, API key, or header)
2. **Semantic Normalization** - What are they trying to do? (tool name + arguments mapped to a canonical action type, resource path, and risk level)
3. **Cedar Evaluation** - Are they allowed? (Cedar policies evaluated against the normalized request)
4. **Enforcement** - Forward or block. (Decision returned to AgentGateway, audit event logged)

The semantic normalizer is the key piece. It takes a raw MCP `tools/call` like `{"name": "bash", "arguments": {"command": "rm -rf /tmp"}}` and classifies it as `action_type: execute, resource_path: shell:rm -rf /tmp, risk_level: critical`. Cedar policies then reason about those canonical fields rather than raw tool names and arguments.

Tool-to-action mappings are configured in YAML, not code. Adding a new MCP server is a config change, not a deployment.

## Three Operating Modes

**Enforce** evaluates Cedar policies and returns allow/deny to AgentGateway. This is the production mode.

**Audit** evaluates policies and logs the decision, but always returns allow. Deploy this to see what *would* be blocked before enforcing.

**Observe** captures every tool call into a per-agent behavioral profile, then generates Cedar policies from the observed behavior. This is a calibration tool, not an operating mode. Run it for a defined window, generate policies, review them, and switch to enforce.

## Observe Mode

Observe mode watches agent behavior and synthesizes least-privilege Cedar policies from what it sees. The entire pipeline is deterministic (no NLP, no model inference):

1. **Capture** tool calls as structured observation records
2. **Classify** each call using the same normalizer enforce mode uses
3. **Aggregate** into per-agent behavioral profiles (action counts, resource paths, risk distribution)
4. **Generalize** paths using trie-based collapsing (e.g., 7 files in `src/auth/` collapse to `src/auth/*.py`)
5. **Generate** Cedar policy text with inline provenance comments

In delta mode (default when policies already exist), observe only captures calls that would have been denied, so the generated policy is purely additive.

Generated policies go to a staging directory for review before promotion to the active policy set.

## Quick Start

### Install

```bash
pip install -e ".[dev]"
```

### Configure

Edit `config/apg.yaml` for your environment. Edit `config/tool_mappings.yaml` to add your MCP servers' tools.

### Run

```bash
# Start the server
apg serve

# Or with uvicorn directly
uvicorn apg.server:build_app --factory --host 0.0.0.0 --port 9001
```

### Point AgentGateway at APG

In your AgentGateway config:

```yaml
binds:
  - port: 3000
    listeners:
      - routes:
          - policies:
              extAuthz:
                host: localhost:9001
                protocol:
                  http:
                    requestTimeout: "5s"
```

### CLI Commands

```bash
apg status                    # Show current config and mode
apg mode enforce              # Switch to enforce mode
apg mode audit                # Switch to audit mode
apg mode observe              # Switch to observe mode (with disclaimer)

apg observe stats             # Show observation collection stats
apg observe generate          # Generate Cedar policies from observations
apg observe clear             # Clear observation data

apg policy list               # List active policy files
apg policy validate file.cedar  # Validate Cedar syntax
apg policy diff               # Diff staged vs active policies
apg policy promote            # Promote staged policies to active
```

## Project Structure

```
apg/
├── apg/
│   ├── identity/         # JWT/header identity resolution
│   ├── normalizer/       # Semantic normalization + risk classification
│   ├── policy/           # Cedar evaluation engine + policy loader
│   ├── observe/          # Observation collector, profiler, generalizer, generator
│   ├── extauthz/         # ExtAuthz HTTP service (AgentGateway integration)
│   ├── audit/            # JSONL audit logger with secret redaction
│   ├── server.py         # FastAPI application
│   ├── cli.py            # Management CLI
│   ├── config.py         # Configuration loading
│   └── models.py         # Core data models
├── config/
│   ├── apg.yaml          # Main configuration
│   ├── tool_mappings.yaml  # Tool-to-action mappings
│   └── policies/         # Cedar policy files
├── tests/
│   ├── unit/             # Unit tests
│   └── integration/      # Integration tests
├── Dockerfile
└── pyproject.toml
```

## License

Apache 2.0
