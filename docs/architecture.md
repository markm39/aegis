# Aegis Architecture

Aegis is a zero-trust runtime for AI agents. It wraps agent processes in OS-level sandboxes, evaluates every action against Cedar authorization policies, and records all activity in a tamper-evident audit ledger.

## Crate Dependency Diagram

```
aegis-types          (foundation: config, errors, shared types)
  |
  +-- aegis-policy   (Cedar policy engine)
  |
  +-- aegis-ledger   (SQLite audit store, sessions, SIEM export)
  |
  +-- aegis-sandbox  (Seatbelt / Docker / process sandbox)
  |
  +-- aegis-observer (FSEvents filesystem monitoring)
  |
  +-- aegis-proxy    (action logging, policy evaluation bridge)
  |
  +-- aegis-pilot    (PTY supervision, prompt detection, stall detection)
  |
  +-- aegis-control  (command protocol, Unix socket + HTTP servers)
  |
  +-- aegis-alert    (webhook alert dispatching)
  |
  +-- aegis-channel  (bidirectional Telegram / Slack / Discord messaging)
  |
  +-- aegis-daemon   (fleet orchestration, agent lifecycle, restart policies)
  |
  +-- aegis-monitor  (audit TUI dashboard, ratatui)
  |
  +-- aegis-cli      (binary entry point: hub TUI, all commands, wizard)
```

Every crate depends on `aegis-types` for shared types. Higher-level crates compose the lower ones -- for example, `aegis-daemon` uses `aegis-pilot` for PTY supervision, `aegis-policy` for authorization, and `aegis-ledger` for audit logging.

## Crate Responsibilities

### aegis-types

Foundation crate. Defines `AegisConfig`, `Action`, `ActionKind`, `Verdict`, `Decision`, error types (`AegisError`), and all configuration structs (`IsolationConfig`, `ObserverConfig`, `PilotConfig`, `DaemonConfig`, `AgentSlotConfig`, etc.). Every other crate depends on this.

### aegis-policy

Cedar policy engine. Wraps the Cedar `PolicySet`, `Schema`, and `Authorizer` behind a single `PolicyEngine` struct. Converts Aegis `Action` values into Cedar authorization requests and returns `Verdict` results. Includes built-in policies:

- `default-deny` -- forbids everything
- `allow-read-only` -- permits FileRead and DirList
- `allow-read-write` -- permits file I/O and process lifecycle
- `permit-all` -- allows everything (observe-only mode)
- `ci-runner` -- tuned for CI pipelines
- `data-science` -- permits file I/O and network access

Also provides `evaluate_with_depth()` for subagent isolation: agents at depth >= 2 cannot write files, delete files, or spawn processes.

### aegis-ledger

SQLite-backed, append-only, hash-chained audit ledger. The `AuditStore` records every action and its verdict with a SHA-256 hash chain linking each entry to the previous one. Provides:

- Session tracking (begin/end sessions, action counters)
- Integrity verification (`verify_integrity()` walks the full chain)
- Query API (by time range, principal, decision, action kind)
- Alert integration (pushes `AlertEvent` values to an async channel)
- Policy snapshot storage for compliance audits
- Filesystem audit log (file change hashes)
- Channel audit log (messaging activity)

### aegis-sandbox

OS-level process isolation. Three backends:

- **Seatbelt** (macOS): Generates SBPL profiles from `AegisConfig` and runs commands inside `sandbox-exec`. Default-deny stance with selective allows for the sandbox directory, system paths, and optionally network access. The Cedar-to-SBPL compiler translates loaded Cedar policies into native Seatbelt rules for kernel-level enforcement.
- **Docker**: Runs commands in hardened containers with `--cap-drop ALL`, `--no-new-privileges`, read-only rootfs, PID limits, memory limits, and tmpfs-only scratch space. Configurable network mode (default: none).
- **Process**: Lightweight isolation using filesystem observation and policy enforcement without OS-level sandboxing. Suitable for Linux or environments where Seatbelt/Docker are unavailable.

### aegis-observer

Filesystem observation using macOS FSEvents. Monitors the sandbox directory for file creations, modifications, deletions, and renames. Supports pre/post snapshot diffing to catch rapid events and reads. Feeds observed events into the audit pipeline as `Action` values.

### aegis-proxy

Action logging and policy evaluation bridge. Sits between the observer/pilot and the policy engine. Intercepts actions, evaluates them against the loaded Cedar policies, logs the verdict to the audit store, and returns the decision. Also includes the API usage tracking reverse proxy that intercepts AI tool API traffic and extracts token/model usage data from responses.

### aegis-pilot

PTY-based agent supervision. Spawns an agent process in a pseudo-terminal and monitors its output for permission prompts. Adapters parse agent-specific prompt formats:

- **ClaudeCode**: Parses Claude Code permission prompts
- **Codex**: Parses OpenAI Codex permission prompts
- **Generic**: User-defined regex patterns for any agent
- **Passthrough**: No prompt detection (autonomous tools)

Also handles stall detection (nudges agents that stop producing output) and remote command injection via the control plane.

### aegis-control

Command protocol and servers. Defines `DaemonCommand` and `DaemonResponse` types for controlling the daemon. Provides two server implementations:

- **Unix socket**: Low-latency local communication for the TUI and CLI
- **HTTP**: Optional remote access with API key authentication

Supports commands: ApproveRequest, DenyRequest, NudgeAgent, ListPending, AddAgent, RemoveAgent, FleetGoal, AgentContext, and more.

### aegis-alert

Webhook alert dispatching. Evaluates audit events against configured `AlertRule` filters (decision, action kind, path glob, principal) and POSTs JSON payloads to webhook URLs. Features cooldown timers to prevent alert storms.

### aegis-channel

Bidirectional messaging. Connects Aegis to external communication platforms for remote monitoring and control. The primary implementation is Telegram (with inline keyboard buttons for approve/deny), but the architecture supports Slack, Discord, Matrix, and many more backends. Receives fleet events outbound and forwards user commands inbound.

### aegis-daemon

Multi-agent fleet orchestration. Manages a fleet of AI agent processes with:

- Agent drivers (ClaudeCode, Codex, OpenClaw, Custom)
- Lifecycle management (start, stop, restart)
- Restart policies (never, on-failure, always) with configurable max restarts
- Fleet state persistence to disk
- Control protocol wired over Unix socket
- Orchestrator agents that review and direct other agents
- Execution lanes with configurable concurrency limits

### aegis-monitor

Audit TUI dashboard built with ratatui. Displays a real-time view of the audit ledger with filtering by principal, decision, and action kind.

### aegis-cli

The binary entry point. Running `aegis` with no arguments launches the fleet TUI hub. Running `aegis <subcommand>` accesses specific functionality:

- `aegis init` -- create a new configuration (interactive wizard)
- `aegis daemon start/stop` -- manage the fleet daemon
- `aegis pilot` -- supervised agent execution
- `aegis wrap` -- observe any command
- `aegis monitor` -- live audit dashboard
- `aegis log` -- view audit trail
- `aegis policy` -- inspect loaded policies
- `aegis report` -- compliance reports
- `aegis diff` -- compare sessions

The fleet TUI hub features a vim-style command bar (`:`) with tab completion for 30+ commands, agent status tables, pending prompt panels, and terminal spawning for interactive commands.

## Data Flow

The core data path follows this sequence:

```
Agent Process
  |  (PTY output)
  v
aegis-pilot (adapter parses permission prompt)
  |  (Action)
  v
aegis-proxy (builds Action, sends to policy engine)
  |
  v
aegis-policy (Cedar authorization: permit/forbid)
  |  (Verdict)
  v
aegis-ledger (append to hash-chained audit log)
  |
  +----> aegis-alert (webhook dispatch if rules match)
  |
  +----> aegis-channel (Telegram/Slack notification)
  |
  v
aegis-pilot (approve or deny the agent's prompt)
  |
  v
Agent Process (receives y/n response via PTY)
```

1. The **agent process** runs inside a PTY managed by the pilot.
2. When the agent requests permission (e.g., to write a file), the **pilot adapter** parses the prompt and constructs an `Action` with the appropriate `ActionKind`.
3. The **proxy** forwards the action to the **policy engine**, which evaluates it against loaded Cedar policies.
4. The resulting `Verdict` (Allow or Deny) is recorded in the **audit ledger** as a hash-chained entry.
5. If alert rules match, the **alert dispatcher** POSTs to configured webhooks.
6. If a messaging channel is configured, the **channel** sends a notification (with inline approve/deny buttons for Telegram).
7. The pilot sends the appropriate response back to the agent's PTY stdin.

Concurrently, the **observer** monitors filesystem activity and logs file-level changes independently of the agent's permission prompts.

## Security Architecture

### Cedar Policy Engine

Aegis uses [Cedar](https://www.cedarpolicy.com/) as its authorization language. Cedar was created by Amazon and formally verified for correctness. Key properties:

- **Default-deny**: If no `permit` policy matches, the action is denied.
- **Explicit forbid wins**: A `forbid` policy always overrides a `permit` for the same action.
- **Typed schema**: The Aegis Cedar schema defines entity types (`Aegis::Agent`, `Aegis::Resource`) and action types (`FileRead`, `FileWrite`, `FileDelete`, `DirCreate`, `DirList`, `NetConnect`, `ToolCall`, `ProcessSpawn`, `ProcessExit`, `ApiUsage`, and more).
- **Hot reloading**: Policies can be reloaded from disk at runtime without restarting the daemon.

Policy files are stored as `.cedar` files in the configuration's `policies/` directory.

### Hash-Chained Audit Ledger

Every action and verdict is recorded in a SQLite database as an `AuditEntry`. Each entry contains:

- A unique entry ID (UUID)
- Timestamp
- The action that was evaluated (serialized `ActionKind`)
- The agent principal
- The authorization decision (Allow/Deny)
- The reason and determining policy ID
- A SHA-256 hash of the previous entry (`prev_hash`)
- A SHA-256 hash of the current entry's contents (`entry_hash`)

The hash chain makes the ledger tamper-evident. `verify_integrity()` walks the full chain, recomputing each entry's hash and checking linkage. If any entry is modified after the fact, the chain breaks and verification reports the exact point of tampering.

The genesis entry uses the sentinel value `"genesis"` as its `prev_hash`.

### Seatbelt Sandbox (macOS)

On macOS, Aegis generates a Seatbelt profile in SBPL (Seatbelt Profile Language) and runs agent processes under `sandbox-exec`. The profile enforces:

- **Default-deny**: All operations are denied unless explicitly allowed.
- **Sandbox directory access**: Read/write access only within the configured sandbox directory.
- **System reads**: Read-only access to `/usr`, `/bin`, `/sbin`, `/Library`, `/System` for program execution.
- **Network control**: Network access is denied by default and only enabled when `allowed_network` rules are present.
- **Process execution**: `process-exec` and `process-fork` are allowed so the agent can run commands.

The Cedar-to-SBPL compiler translates Cedar policies into native Seatbelt rules, providing kernel-level enforcement that the agent process cannot bypass.

### Docker Sandbox

For containerized isolation, Docker containers are configured with security-hardened defaults that cannot be disabled through configuration:

- `--cap-drop ALL` -- drops all Linux capabilities
- `--no-new-privileges` -- prevents privilege escalation
- Read-only root filesystem
- PID limit (default: 256) to prevent fork bombs
- Memory limit (default: 512 MB)
- tmpfs for `/tmp` (default: 100 MB)
- Network mode `none` by default

### Subagent Isolation

When agents spawn subagents (nested execution), depth-based guardrails are enforced:

- **Depth >= 2**: ProcessSpawn, FileWrite, and FileDelete are unconditionally denied.
- **Depth >= depth_limit**: SubagentSpawn ToolCalls are denied, preventing unbounded recursion.

This is enforced in `PolicyEngine::evaluate_with_depth()` as a hard guardrail independent of Cedar policies.

### Non-UTF-8 Path Rejection

Paths containing non-UTF-8 bytes are denied during policy evaluation. This prevents attackers from crafting paths that might bypass Cedar string-based policy rules.
