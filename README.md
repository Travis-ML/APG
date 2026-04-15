# APG - Agent Policy Gateway

Cedar-based intent execution control for LLMs and agents.

APG is an authorization service that classifies what AI agents are trying to accomplish with each tool call, evaluates Cedar policies against that classification, and enforces allow or deny decisions in real time. It integrates with AgentGateway via the External Authorization (ExtAuthz) HTTP interface, meaning AgentGateway continues to handle MCP transport, tool federation, and protocol negotiation while APG handles the intent-aware authorization layer that AgentGateway's built-in CEL rules cannot provide.

---

## The Problem APG Solves

Every MCP gateway available today evaluates authorization against the tool name. AgentGateway's CEL-based authorization can express rules like `mcp.tool.name == "bash"`, which means you either allow an agent to use the bash tool or you don't. There is no middle ground.

The problem is that a single tool name can cover wildly different operations. When an LLM calls `bash` with `{"command": "pytest tests/"}` and calls `bash` with `{"command": "rm -rf /"}`, the gateway sees the same tool in both cases. The first call runs a test suite. The second destroys the filesystem. They have the same tool name, the same action surface from the gateway's perspective, and the same authorization decision under any rule that operates on tool name alone.

APG fills the gap between "which tool was called" and "what is the tool call actually trying to do." It inspects the tool arguments, classifies the call into a canonical action type (read, write, execute, delete), extracts the target resource, assesses the risk level, and passes all of that context to Cedar for policy evaluation. Cedar policies can then express rules like "allow this agent to execute commands that start with pytest, but deny any command classified as critical risk" instead of the binary "allow bash or deny bash."

The second problem APG solves is the cold-start problem for agent policy authoring. Writing least-privilege policies for agents requires knowing in advance what tools they will call, what arguments they will pass, and what resources they will touch. In practice, most teams either write overly broad policies that defeat the purpose of access control, or overly narrow policies that constantly break agent workflows, leading to the policy being disabled entirely. APG's observe mode addresses this by watching real agent behavior and synthesizing Cedar policies from the observations, giving teams a concrete starting point to review and refine.

---

## How It Works

Every tool call that an agent makes through AgentGateway flows through a four-stage pipeline inside APG before a decision is returned.

### Stage 1: Identity Resolution

The first stage determines who is making the request. When AgentGateway forwards a tool call to APG's ExtAuthz endpoint, it includes the JWT claims, request headers, and session metadata that were present on the original request. APG's identity resolver extracts the agent's identity from this context.

Three identity methods are supported. JWT mode extracts agent identity from the decoded JWT claims that AgentGateway has already validated and forwarded. The resolver reads fields like `sub` (agent ID), `owner`, `team`, and `runtime` from the claims. Header mode reads the agent identity from a configurable request header, which is useful when agents authenticate through an API key or mTLS and the identity is passed as a header value. Passthrough mode accepts whatever agent ID is present on the request without additional validation, which is appropriate for development and testing.

The output of this stage is an AgentIdentity object that carries the agent's ID, owner, team, runtime type, and the environment context. This identity is available to every subsequent stage and becomes part of the Cedar evaluation context, meaning policies can make decisions based on which specific agent is requesting access, which team owns it, or which runtime is driving it.

### Stage 2: Semantic Normalization

The second stage is the core of what makes APG different from tool-name-based authorization. The semantic normalizer takes the raw MCP tool call (a tool name string and a JSON arguments object) and produces a canonical classification consisting of three fields: an action type, a resource path, and a risk level.

The classification is driven entirely by a YAML configuration file called `tool_mappings.yaml`. There is no natural language processing, no machine learning model, and no inference of any kind. The normalizer performs an exact string match on the tool name against the mappings and reads the pre-configured values.

Each entry in the mappings file specifies four things. The `action_type` is the canonical action that this tool represents: read, write, execute, delete, list, or unknown. The `resource_field` names which key in the tool's JSON arguments contains the resource identifier (for example, `path` for filesystem tools, `command` for shell tools, `url` for browser tools). The `resource_prefix` is prepended to the extracted value to create a typed resource URI like `file:src/main.py` or `shell:pytest tests/`. The `category` groups the tool into a functional domain (filesystem, shell, browser, api, data) which Cedar policies can use for broad-scope rules.

When a tool call arrives for a tool name that is not in the mappings file, the normalizer classifies it as `action_type: unknown` with `risk_level: medium` and logs a warning identifying the unmapped tool. This unknown classification will not match any typical permit rule in Cedar, so the call is denied by default. The warning makes the unmapped tool visible to the operator so they can add a mapping before legitimate calls are blocked in production.

The action type comes from the tool name, not from the arguments. The tool `bash` is always classified as `execute` regardless of what command is passed. The tool `read_file` is always classified as `read` regardless of which file path is targeted. The arguments affect only the resource path extraction and the risk classification, never the action type. This keeps the system deterministic: you can read the mappings file and know exactly how every tool call will be classified without running any code.

### Stage 3: Risk Classification

Risk classification happens as a sub-step of normalization but is significant enough to warrant its own explanation. After the action type and resource path are determined, the risk classifier evaluates the specific arguments to assign a risk level of low, medium, high, or critical.

Risk is computed from three sources, and the highest applicable level is used. First, every action type has a base risk: reads are low, writes are medium, executes are medium, deletes are high, and unknowns are medium. Second, tool-specific escalation rules in the mappings file define regex patterns that elevate risk when matched against the resource path. For the `bash` tool, patterns like `rm -rf` escalate to critical, `sudo` escalates to high, and `curl .* | sh` escalates to critical. Third, a set of built-in sensitive path patterns checks whether the resource path matches known dangerous targets like `.env` files, `.pem` certificates, `.ssh` directories, or `/etc/shadow`.

Additionally, any tool call made in a production environment has its risk floor elevated by one level. A read that would be low risk in dev becomes medium risk in prod. This reflects the reality that even read operations in production carry more consequence than the same operations in development.

The risk level becomes part of the Cedar evaluation context, so policies can use it directly. A policy like `forbid when context.risk_level == "critical"` blocks any tool call that the risk classifier determines to be critically dangerous, regardless of which tool or agent is involved.

### Stage 4: Cedar Policy Evaluation

The final stage evaluates the normalized request against the loaded Cedar policies. APG maps its internal data model to Cedar's authorization model as follows: the principal is `Agent::"<agent_id>"`, the action is always `Action::"toolCall"` (since APG uses context fields rather than Cedar action types to differentiate operations), and the resource is `Tool::"<category>"` where category is the functional domain from the mapping (filesystem, shell, browser, etc.).

The Cedar context object carries all the classification data: action_type, resource_path, risk_level, environment, tool_name, category, session_id, agent_id, owner, team, and runtime. Policies can match on any combination of these fields.

Cedar uses a deny-by-default model. If no permit rule matches the request, the request is denied. If a forbid rule matches, the request is denied regardless of any matching permit rules. This means policies are additive: you explicitly permit what should be allowed, and everything else is automatically blocked.

APG fails closed on evaluation errors. If the Cedar engine encounters a malformed policy, a syntax error, or any exception during evaluation, the result is a deny. The error is logged but the request is never allowed through on the basis of an engine failure.

The policy loader reads all `.cedar` files from the configured policy directory and concatenates them for evaluation. Hot reload is supported: when enabled, APG periodically checks for changes to the policy files and reloads them without requiring a restart.

---

## Tool Discovery

Populating the tool mappings file by hand requires knowing every tool name, every argument field, and the appropriate classification for each. For a single MCP server with five tools, this is straightforward. For a production environment with a dozen MCP servers exposing hundreds of tools, it becomes impractical.

APG includes an auto-discovery system that reads MCP tool definitions and generates a draft `tool_mappings.yaml` automatically. Tool definitions come either from a JSON file containing the response of an MCP `tools/list` call, or by connecting directly to a running AgentGateway instance and fetching the federated tool catalog.

Discovery classifies each tool through three tiers of signal, applied in priority order.

### Tier 1: ToolAnnotations

The MCP specification defines optional annotation fields on tool definitions: `readOnlyHint`, `destructiveHint`, and `idempotentHint`. These are boolean flags that tool authors set to describe the behavior of their tools. The reference MCP servers maintained by the protocol authors set these annotations on every tool they expose.

When annotations are present, the classification is unambiguous. A tool with `readOnlyHint: true` is classified as a read. A tool with `destructiveHint: true` is classified as a delete. A tool with `idempotentHint: true` and `readOnlyHint: false` is classified as a write (it mutates state, but doing so is safe to retry). A tool with `readOnlyHint: false` and no other hints is conservatively classified as a write. These mappings are assigned high confidence, meaning they are applied without a review flag.

### Tier 2: Name Keyword Matching

When ToolAnnotations are absent, the discovery system falls back to analyzing the tool name. The name is tokenized by splitting on underscores, hyphens, dots, and camelCase boundaries. The token `readTextFile` becomes `[read, text, file]`. The token `delete-user-data` becomes `[delete, user, data]`.

Each token is checked against four keyword sets: delete keywords (delete, remove, destroy, purge, erase), execute keywords (run, execute, bash, shell, command, invoke, deploy), write keywords (create, update, edit, modify, save, push, commit), and read keywords (read, get, fetch, list, search, find, view, query).

The keyword sets are checked in descending order of risk: delete first, then execute, then write, then read. This priority order is a deliberate safety decision. If a tool name contains tokens from multiple sets (for example, `read_and_delete_logs`), the most dangerous classification wins. Misclassifying a destructive operation as a read would result in an overly permissive policy, which is a security failure. Misclassifying a read as a delete results in an overly restrictive policy, which the operator will notice and correct during review.

Tools classified through name keywords are assigned medium confidence.

### Tier 3: Fallback

When neither annotations nor name keywords produce a match, the tool is classified as unknown and flagged for manual review. The generated YAML file includes a comment explaining why the tool could not be classified and what information the operator should provide. If the input schema contains a field named `command` or `shell`, the fallback infers execute as a reasonable guess and assigns the shell category, but still marks it for review.

### Input Schema Analysis

Independent of the three classification tiers, discovery also analyzes the tool's input schema to determine which argument field contains the resource identifier and what type of resource it represents. A field named `path`, `file`, or `filepath` is mapped to the `file:` resource prefix with the filesystem category. A field named `command` or `cmd` maps to `shell:`. A field named `url` or `uri` maps to `url:`. A field named `query` or `sql` maps to `sql:`.

This analysis runs for all tools regardless of which tier classified them. It populates the `resource_field` and `resource_prefix` values in the generated mapping, which the normalizer uses at runtime to extract the correct value from the tool arguments.

### Generated Output

The discovery system produces a complete `tool_mappings.yaml` file with provenance comments on every entry showing which tier classified it, what keyword or annotation matched, and whether the entry needs review. A summary at the top counts how many tools were classified at each confidence level.

The `--merge` flag allows incremental discovery: when new MCP servers are added, discovery classifies only tools that don't already have mappings, leaving existing (potentially hand-tuned) entries untouched.

---

## Operating Modes

APG supports three operating modes that control how policy decisions affect traffic.

### Enforce Mode

In enforce mode, the Cedar policy decision is authoritative. If a tool call is permitted by policy, APG returns HTTP 200 to AgentGateway, and AgentGateway forwards the call to the upstream MCP server. If the call is denied, APG returns HTTP 403, and AgentGateway blocks the call and returns an error to the agent. Every decision, whether allow or deny, is recorded in the audit log.

Enforce mode is the production operating mode. It is the only mode in which APG actually prevents unauthorized actions.

### Audit Mode

In audit mode, APG evaluates Cedar policies exactly as it does in enforce mode, but always returns HTTP 200 to AgentGateway regardless of the policy decision. The actual decision (what would have happened in enforce mode) is recorded in the audit log with a `mode: audit` marker and a reason field like `audit:passthrough (would_deny)`.

Audit mode exists to answer the question "what would happen if I turned on enforcement?" without affecting live traffic. It is the recommended first step when deploying APG into an existing environment. Run in audit mode for a period, review the audit log for false denials, adjust policies, and then switch to enforce when the deny rate is acceptable.

### Observe Mode

Observe mode is a policy generation tool, not an operating mode for continuous use. Like audit mode, it always returns allow to AgentGateway and never blocks traffic. Unlike audit mode, it also captures detailed observation records for each tool call and stores them in per-agent profiles that can be used to generate Cedar policies.

When observe mode is activated, APG prints a disclaimer reminding the operator that observe is intended for a bounded calibration window, not for permanent use. A configurable auto-disable timer can be set to automatically switch to audit mode after a specified duration. While observe mode is active, APG logs a periodic reminder that it is running without enforcement.

Observe mode is described in detail in the next section.

---

## Observe Mode

Observe mode is APG's answer to the cold-start problem for agent policies. It watches what agents actually do and produces Cedar policies that permit exactly that behavior and nothing else. The entire pipeline is deterministic. No NLP, no model inference, no stochastic components. The same set of observations always produces the same policy output.

### Full vs. Delta Mode

Observe mode operates in one of two sub-modes. Full mode captures every tool call regardless of whether it would be allowed or denied by current policies. This is appropriate when no policies exist yet and you are generating them from scratch.

Delta mode captures only tool calls that would have been denied by the current policy set. On each incoming call, APG runs the Cedar evaluation and checks the result. If the result is allow, the call is not profiled (it is already covered by existing policy). If the result is deny, the call is added to the observation profile. The resulting generated policy is purely additive, containing only new permit rules for behavior that the current policies do not cover. Delta mode is the default when active policies already exist.

The sub-mode can be set explicitly in the configuration or left on auto, in which case APG uses delta when the policy directory contains `.cedar` files and full when it does not.

### Stage 1: Capture

Every tool call that passes through APG during an observe window is recorded as a structured observation record. The record contains the timestamp, agent ID, tool name, classified action type, resource path, risk level, category, environment, session ID, and a flag indicating whether Cedar would have denied the call. These records are stored as JSONL files in the observation data directory, one file per agent.

Sensitive values in tool arguments are redacted at capture time using the same key-based redaction rules that the audit logger uses. Fields whose names match patterns like password, token, secret, and key have their values replaced with a redaction placeholder.

### Stage 2: Aggregate

When the operator runs `apg observe generate`, APG reads the observation records for each agent and builds a behavioral profile. The profile is a data structure that summarizes what the agent did during the observation window: the total number of calls, the distribution across action types (how many reads, writes, executes), the set of unique resource paths per action type, the tool names used, the environments observed in, and the risk level distribution.

The profile is not a narrative or a description. It is a structured aggregation that the next stage consumes directly.

### Stage 3: Generalize

The generalization stage converts the sets of observed resource paths and commands into patterns suitable for Cedar policy rules. This is where raw observations become actionable policy, and it is also where the most important configuration knobs live.

For file paths, APG uses a trie (prefix tree) data structure. All observed file paths for a given action type and agent are inserted into the trie, segmented by directory. At each directory node, if the number of distinct files exceeds the configured collapse threshold, the directory is represented as a wildcard pattern instead of listing each file individually.

For example, if an agent read seven files under `src/auth/` and the collapse threshold is set to five, the generated policy uses `src/auth/*.py` instead of listing all seven files. If the agent read only two files under `src/models/`, those two files are listed individually because two is below the threshold. The threshold is configurable (default is 5) and can be adjusted to trade off between policy precision and policy verbosity.

When extension grouping is enabled (the default), collapsed directories are further refined by file extension. If all seven files under `src/auth/` were `.py` files, the pattern is `src/auth/*.py` rather than `src/auth/*`. If there were a mix of `.py` and `.md` files, separate patterns are emitted for each extension.

The `max_wildcard_depth` setting controls how far up the directory tree wildcards can propagate. With the default of 1, wildcards are scoped to a single directory level. Even if every subdirectory under `src/` was individually collapsed, the generator emits `src/auth/*.py`, `src/models/*.py`, and `src/api/*.py` as separate rules rather than collapsing to `src/**/*.py`. The operator can manually broaden these during review.

For shell commands, generalization uses token-based prefix extraction. Commands are split on whitespace and grouped by their first token (the binary name). All invocations of `pytest` (whether `pytest tests/`, `pytest --cov`, or `pytest tests/test_auth.py`) collapse to a single pattern `pytest*`. For known compound commands (like `pip install`, `python -m`, `docker build`), the first two tokens are kept as the prefix, so `pip install requests` and `pip install flask` collapse to `pip install *` rather than `pip *`.

Certain paths and commands are never auto-permitted regardless of how often they were observed. Paths matching the `never_wildcard` list (such as `.env`, `.key`, and `.pem` files) are flagged in the output but not included as permit rules. Commands matching the `never_permit_commands` list (such as `rm -rf`, `sudo`, and `curl | sh`) are similarly flagged. These appear in the generated policy file as comments explaining that the behavior was observed but not auto-permitted, with the specific pattern and the reason for the flag. If the operator determines that the access is legitimate, they can uncomment the rule manually.

### Stage 4: Generate

The final stage templates the generalized rules into Cedar policy text. The output is a complete `.cedar` file with a header identifying the agent, the observation window, the total call count, and whether the policy is a full or delta generation. Each rule includes inline provenance comments showing how many observations drove it and which specific files or commands were collapsed.

In delta mode, the header explicitly states that the rules cover tool calls that were denied by current policy and instructs the reviewer to approve legitimate access and investigate unexpected access.

The generator also emits recommended forbid rules based on absence of behavior. If the agent was never observed operating in production, a forbid rule blocking all production access is included. If the agent never performed delete actions, a forbid rule for deletes is included. If the agent never triggered critical risk levels, a forbid rule for critical risk is included. These are recommendations, not requirements, and the operator can remove them during review.

Generated policy files are written to a staging directory, not the active policy directory. The operator reviews them using `apg policy diff` (which shows a unified diff between staged and active policies), makes any needed edits, and then runs `apg policy promote` to copy them into the active directory where Cedar hot-reload picks them up.

### Generalization Configuration

The generalization thresholds are exposed in the configuration file under `observe.generalization`. The defaults are conservative, favoring tighter policies over broader ones.

`file_collapse_threshold` (default: 5) sets how many files in a single directory must be observed before the directory is wildcarded. Lower values produce broader policies. Higher values produce more specific policies with longer rule lists.

`max_wildcard_depth` (default: 1) limits how far up the directory tree wildcards can propagate. A value of 1 means wildcards stay within a single directory. A value of 2 would allow `src/**/*.py` if both `src/auth/*.py` and `src/models/*.py` were individually collapsed.

`extension_grouping` (default: true) controls whether collapsed directories are split by file extension. When enabled, `src/auth/*.py` and `src/auth/*.md` are separate rules. When disabled, both collapse to `src/auth/*`.

`command_prefix_tokens` (default: 1) sets how many whitespace-delimited tokens form the command prefix. The `compound_command_prefixes` list overrides this for specific commands that need two or more tokens (like `pip install`).

`never_wildcard` and `never_permit_commands` are the safety rails that prevent the most dangerous patterns from being auto-permitted regardless of observation data.

---

## AgentGateway Integration

APG integrates with AgentGateway through the External Authorization (ExtAuthz) HTTP interface. AgentGateway already supports delegating authorization decisions to external services using this interface, which is API-compatible with the Envoy ExtAuthz specification.

The integration requires two configuration changes. On the AgentGateway side, the route or listener configuration adds an `extAuthz` policy block pointing at APG's address:

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

On the APG side, the server is started with the appropriate configuration for identity resolution, tool mappings, and Cedar policies.

When a tool call arrives at AgentGateway, it forwards the request context (headers, JWT claims, MCP tool metadata) to APG's `/v1/check` endpoint as an HTTP POST. APG runs the four-stage pipeline, makes a decision, and returns either HTTP 200 (allow) or HTTP 403 (deny). AgentGateway enforces that decision by either forwarding the tool call to the upstream MCP server or returning an error to the agent.

APG also returns response headers with the decision metadata (`x-apg-decision`, `x-apg-reason`, `x-apg-action-type`, `x-apg-risk-level`) which AgentGateway can forward downstream or use in its own access logging and CEL expressions. This means AgentGateway's logging can include APG's classification data even though the classification happens externally.

The `/v1/health` endpoint provides a basic health check that AgentGateway or a load balancer can poll. The `/v1/status` endpoint returns the current operating mode, whether policies are loaded, and observation statistics if observe mode is active. The `/v1/policies/reload` endpoint triggers an immediate policy reload without restarting the server.

---

## Audit Logging

Every policy decision is recorded to an append-only JSONL (JSON Lines) file. Each line is a complete JSON object containing the timestamp, operating mode (enforce, audit, or observe), agent identity fields, session ID, tool name, classified action type, resource path, risk level, category, environment, decision result (allow or deny), decision reason, and the tool arguments.

Tool arguments are recorded with automatic redaction. Any argument key whose name matches a configurable list of sensitive patterns (password, token, secret, key, credential, api_key) has its value replaced with a `[REDACTED]` placeholder. Redaction is recursive: it applies to nested objects and arrays within the arguments.

The audit log serves three purposes. For security operations, it provides a forensic trail of every tool call an agent made, what APG classified it as, and whether it was permitted. For compliance, it provides evidence that access controls were evaluated on every operation. For policy tuning, it provides data on deny rates, risk distributions, and classification accuracy that inform policy adjustments.

---

## Cedar Policies

Policies are written in Cedar, the policy language created by AWS, and stored as `.cedar` files in the configured policy directory. All files in the directory are loaded and evaluated together. Cedar uses a deny-by-default model: if no permit rule matches, the request is denied. Forbid rules override permit rules unconditionally.

APG maps its normalized request to Cedar's authorization model with a consistent structure. The principal is always `Agent::"<agent_id>"`. The action is always `Action::"toolCall"`. The resource is `Tool::"<category>"`. All differentiation happens through the context object, which carries action_type, resource_path, risk_level, environment, tool_name, category, session_id, agent_id, owner, team, and runtime.

A simple policy that allows reads in dev and blocks everything in prod looks like this:

```cedar
permit(
  principal,
  action == Action::"toolCall",
  resource
) when {
  context.action_type == "read" &&
  context.environment == "dev"
};

forbid(
  principal,
  action == Action::"toolCall",
  resource
) when {
  context.environment == "prod"
};
```

A more granular policy that allows a specific agent to execute test commands but blocks destructive operations:

```cedar
permit(
  principal == Agent::"claude-dev-001",
  action == Action::"toolCall",
  resource == Tool::"shell"
) when {
  context.action_type == "execute" &&
  context.environment == "dev" &&
  context.risk_level in ["low", "medium"] &&
  (
    context.resource_path like "shell:pytest*" ||
    context.resource_path like "shell:python -m pytest*"
  )
};

forbid(
  principal,
  action == Action::"toolCall",
  resource
) when {
  context.risk_level == "critical"
};
```

Policy validation is available through the CLI. The `apg policy validate` command runs the Cedar syntax checker against a policy file and reports any errors before the file is deployed.

---

## CLI Reference

APG includes a management CLI for server operation, mode switching, policy management, observation control, and tool discovery.

`apg serve` starts the APG server using the configuration file specified by the `--config` flag or the `APG_CONFIG` environment variable.

`apg status` displays the current configuration including operating mode, listen address, policy directory, identity method, and audit output path.

`apg mode enforce`, `apg mode audit`, and `apg mode observe` switch the operating mode by updating the configuration file. The server must be restarted for the change to take effect. The observe subcommand displays a disclaimer and requires confirmation before enabling.

`apg observe stats` shows how many agents have been observed and how many observations have been collected for each. `apg observe generate` reads the observation data, builds behavioral profiles, and generates Cedar policy files in the staging directory. The `--agent` flag limits generation to a specific agent. The `--output-dir` flag overrides the default staging directory. `apg observe clear` removes observation data, with an optional `--agent` flag to clear a single agent's data.

`apg policy list` shows all `.cedar` files in the active policy directory. `apg policy validate` checks a Cedar file for syntax errors. `apg policy diff` displays a unified diff between staged and active policies. `apg policy promote` copies staged policy files to the active directory after confirmation.

`apg discover from-file` reads an MCP `tools/list` JSON file and generates a `tool_mappings.yaml` with classified mappings. The `--merge` flag adds only new tools to an existing mappings file. The `--output` flag writes to a file instead of stdout. `apg discover from-gateway` connects to a running AgentGateway instance, fetches the federated tool catalog, and generates mappings from the live tool definitions.

---

## Configuration

APG is configured through a YAML file, by default located at `config/apg.yaml`. The file is organized into sections.

The `gateway` section sets the listen address, port, operating mode, and default decision (deny is the only production-appropriate default).

The `identity` section configures the identity resolution method, the header name for header-based identity, the path to a JWT secret file, and the list of accepted JWT algorithms.

The `cedar` section specifies the policy directory path, an optional schema file, whether hot-reload is enabled, and the reload check interval.

The `normalizer` section points to the tool mappings YAML file.

The `observe` section configures observe mode behavior: the sub-mode (full, delta, or auto), the data directory for observation storage, an optional auto-disable timer, the reminder interval for logging warnings that observe mode is active, and the full set of generalization thresholds described in the observe mode section above.

The `audit` section controls whether audit logging is enabled, the output format (JSONL), the log file path, and the list of argument key names to redact.

---

## Project Structure

```
apg/
    __init__.py             Package root with version string
    models.py               Core data models used across all components:
                            AgentIdentity, NormalizedRequest, PolicyDecision,
                            CheckRequest, CheckResponse, and the enums for
                            ActionType, RiskLevel, GatewayMode, DecisionResult
    config.py               Configuration loading from YAML with dataclass
                            models for each config section
    server.py               FastAPI application factory that wires all
                            components together and exposes management endpoints
    cli.py                  Click-based CLI with command groups for serve,
                            mode, observe, policy, and discover
    discover.py             Auto-discovery module with three-tier classification,
                            schema analysis, and YAML generation

    identity/
        resolver.py         Identity resolution from JWT, headers, or passthrough

    normalizer/
        engine.py           Semantic normalizer that loads YAML mappings and
                            classifies tool calls into action/resource/risk
        risk.py             Deterministic risk classifier with base risk,
                            escalation rules, and sensitive path detection

    policy/
        engine.py           Cedar evaluation engine wrapping cedarpy with
                            fail-closed error handling
        loader.py           Policy file loader that reads and concatenates
                            .cedar files with change detection for hot-reload

    observe/
        collector.py        Observation capture with full and delta modes,
                            per-agent JSONL storage, and statistics
        profile.py          Behavioral profile builder that aggregates raw
                            observations into structured per-agent summaries
        generalize.py       Trie-based path generalization and token-based
                            command prefix extraction with configurable
                            thresholds and safety rails
        generator.py        Cedar policy text generator with provenance
                            comments, flagged items, and recommended forbids

    extauthz/
        service.py          ExtAuthz HTTP service implementing the four-stage
                            pipeline as a FastAPI router with /v1/check and
                            /v1/health endpoints

    audit/
        logger.py           Append-only JSONL audit logger with recursive
                            secret redaction

config/
    apg.yaml                Main configuration file
    tool_mappings.yaml      Tool-to-action mapping definitions
    policies/
        example.cedar       Example Cedar policy for reference

tests/
    unit/                   Unit tests for normalizer, risk classifier,
                            generalization, and discovery
    integration/            Integration tests for the full ExtAuthz pipeline
                            and the observe-to-policy flow
```

---

## Quick Start

Install APG with development dependencies:

```bash
pip install -e ".[dev]"
```

Start the server:

```bash
apg serve
```

Or with uvicorn directly:

```bash
uvicorn apg.server:build_app --factory --host 0.0.0.0 --port 9001
```

Point AgentGateway at APG by adding the ExtAuthz policy to your AgentGateway configuration, then add your Cedar policies to the policy directory and your tool mappings to the mappings file. Use `apg discover from-file` or `apg discover from-gateway` to generate an initial mappings file from your MCP servers, and use `apg mode observe` followed by `apg observe generate` to bootstrap policies from real traffic.

---

## License

Apache 2.0
