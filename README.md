# Aegis -- Zero-Trust Runtime for AI Agents

Zero-trust runtime for AI agents with per-file observability and enterprise governance. Default-deny stance. Written in Rust. Single binary. Zero external dependencies on macOS.

Every file access is observed via FSEvents, governed by Cedar policies, and logged to a tamper-evident audit ledger with SHA-256 hash chains. Optionally enforced at the kernel level via Seatbelt profiles. Agents are supervised in a PTY with auto-approval, stall detection, and an interactive TUI dashboard.

## Why Aegis

AI agent sandboxes (Claude Code, OpenClaw, etc.) enforce permissions but provide no visibility into what the agent actually did. You know it was sandboxed, but not what files it read, wrote, or deleted. And there's no way to supervise an autonomous agent's permission prompts without sitting and watching.

Aegis adds the missing layers:

| Capability | Built-in Sandbox | Aegis |
|---|---|---|
| File access enforcement | Yes | Yes (Seatbelt) |
| Per-file audit trail | No | Yes (FSEvents observer) |
| Tamper-evident hash chain | No | Yes (SHA-256) |
| Auto-approve/deny via policy | No | Yes (Cedar + PTY pilot) |
| Stall detection and nudging | No | Yes |
| Interactive TUI dashboard | No | Yes |
| Remote control (socket + HTTP) | No | Yes |
| Webhook alerts | No | Yes |
| Session tracking | No | Yes (per-invocation sessions) |
| SIEM export | No | Yes (JSON, JSONL, CSV, CEF) |
| Compliance reporting | No | Yes |
| Multi-agent fleet management | No | Yes (daemon) |

## Quick Start

```bash
# Build from source
git clone https://github.com/markm39/aegis.git
cd aegis
cargo build --release
# Binary: ./target/release/aegis

# Interactive setup wizard
aegis init

# Or just go -- zero config needed
aegis wrap -- claude
aegis run -- echo hello

# View what happened
aegis log claude
aegis report claude
aegis status claude
```

Three commands. Full audit trail.

## Pilot: Autonomous Agent Supervision

`aegis pilot` is the main way to run an agent autonomously. It spawns the agent in a PTY, monitors its output for permission prompts, auto-approves or denies them based on Cedar policy, detects stalls, and presents everything in an interactive TUI dashboard.

```bash
# Supervise Claude Code with auto-approval
aegis pilot -- claude

# Use a read-only policy (deny writes, approve reads)
aegis pilot --policy allow-read-only -- claude

# Point at a specific project
aegis pilot --dir ~/my-project -- claude

# Enable remote HTTP control
aegis pilot --listen 0.0.0.0:8443 --api-key secret -- claude
```

The TUI shows live agent output, pilot decisions (approved/denied), statistics, and pending permission requests. Keybindings:

| Key | Action |
|---|---|
| `q` | Quit |
| `j`/`k` | Scroll output up/down |
| `G`/`g` | Jump to bottom/top |
| `i` | Enter input mode (type text to send to agent) |
| `n` | Send nudge to stalled agent |
| `Tab` | Switch focus between output and pending panels |
| `a` | Approve selected pending request |
| `d` | Deny selected pending request |

A Unix socket server starts automatically at `~/.aegis/pilot/<session-id>.sock` for programmatic control. If `--listen` is specified, an HTTP REST API is also available:

```bash
# Query status
curl http://localhost:8443/v1/status -H "Authorization: Bearer secret"

# Get recent output
curl http://localhost:8443/v1/output?lines=50 -H "Authorization: Bearer secret"

# Send input to the agent
curl -X POST http://localhost:8443/v1/input \
  -H "Authorization: Bearer secret" \
  -d '{"text": "yes"}'

# Approve a pending request
curl -X POST http://localhost:8443/v1/pending/<uuid>/approve \
  -H "Authorization: Bearer secret"
```

## Wrapping Agent Tools

`aegis wrap` is the fastest way to add observability to any agent without supervision:

```bash
# Observe Claude Code (permit-all policy = log everything, block nothing)
aegis wrap -- claude

# Observe with a specific project directory
aegis wrap --dir ~/my-project -- claude

# Observe OpenClaw
aegis wrap -- openclaw run task.md

# Use a read-only policy (block writes, log everything)
aegis wrap --policy allow-read-only -- python3 agent.py
```

Config is stored at `~/.aegis/wraps/<name>/` and reused across invocations, so sessions accumulate in the same ledger.

## Full Sandbox Mode

For maximum control, use `init` + `run` with Cedar policies and Seatbelt enforcement:

```bash
# Interactive setup wizard (choose security mode, directory, etc.)
aegis init

# Or quick init with a name
aegis init my-agent --policy allow-read-only

# Point at an existing project directory
aegis init my-agent --policy allow-read-only --dir ~/my-project

# Run a command inside the sandbox
aegis run --config my-agent -- python3 agent.py

# Or just run -- config auto-created from command name
aegis run -- python3 agent.py

# Query the audit log
aegis audit query my-agent --last 20

# Verify audit log integrity
aegis audit verify my-agent

# Launch the real-time TUI dashboard
aegis monitor my-agent

# Check health
aegis status my-agent
```

## Webhook Alerts

Configure webhook-based alerts that fire on policy violations, stalls, or other events:

```bash
# List configured alert rules
aegis alerts list

# Test webhook connectivity
aegis alerts test

# View dispatch history
aegis alerts history --last 10
```

Alert rules are defined in the config TOML and can target Slack, PagerDuty, or arbitrary HTTP endpoints.

## Background Watching

`aegis watch` runs a persistent filesystem observer in the background:

```bash
# Watch the current directory
aegis watch --dir ~/my-project

# Stop a running watch
aegis watch --name my-project --stop
```

Sessions rotate automatically after idle periods. Events flow to the same audit ledger.

## Daemon: Multi-Agent Fleet Management

The daemon manages multiple agent processes as a fleet, with restart policies, per-agent configuration, and centralized control:

```bash
# Create a default daemon config
aegis daemon init
# Edit ~/.aegis/daemon/daemon.toml to define your agent fleet

# Start the daemon
aegis daemon start

# Check status
aegis daemon status

# List agents and their state
aegis daemon agents

# View agent output
aegis daemon output claude-1 --lines 50

# Send input to an agent
aegis daemon send claude-1 "implement the login page"

# Stop a specific agent
aegis daemon stop-agent claude-1

# Stop the daemon
aegis daemon stop
```

## Architecture

```
Cedar Policies (.cedar files)
        |
        v
Cedar-to-SBPL Compiler -----> Seatbelt Profile (kernel-level)
        |
        v
aegis pilot -- CMD                aegis run -- CMD
        |                                 |
        +---> PTY spawn + supervisor      +---> sandbox-exec (macOS kernel sandbox)
        |         |                       |         |
        |         +--> Prompt detection   |         +--> Process spawn/exit audit
        |         +--> Auto-approve/deny  |         +--> Seatbelt violation harvesting
        |         +--> Stall nudging      |
        |         +--> TUI dashboard      +---> FSEvents observer (per-file monitoring)
        |                                 |         |
        +---> Control plane               |         +--> Real-time file event logging
        |         |                       |         +--> Pre/post snapshot diffing
        |         +--> Unix socket        |
        |         +--> HTTP REST API      v
        |                           Audit Ledger (SQLite, SHA-256 hash-chained)
        +---> FSEvents observer           |
                  |                       +--> Session tracking
                  v                       +--> Policy snapshots
            Audit Ledger                  +--> SIEM export (JSON, JSONL, CSV, CEF)
                                          +--> Compliance reporting
                                          +--> Webhook alerts
                                          +--> TUI dashboard (ratatui)
```

Six layers:
1. **Policy Engine** -- Cedar 4.x policies define what agents can do (default-deny)
2. **Cedar-to-SBPL Compiler** -- Translates Cedar policies into macOS Seatbelt profiles at launch
3. **Isolation Boundary** -- macOS Seatbelt (`sandbox-exec`) enforces at the kernel level
4. **Pilot Supervisor** -- PTY-based agent supervision with prompt detection, auto-approval, and stall nudging
5. **Observer** -- FSEvents filesystem monitoring with snapshot diffing for complete coverage
6. **Audit Ledger** -- Append-only, SHA-256 hash-chained SQLite log with session tracking

## CLI Reference

| Command | Description |
|---|---|
| `aegis setup` | Check system requirements, prepare environment |
| `aegis init [NAME] [--policy TPL] [--dir PATH]` | Create config (omit NAME for wizard) |
| `aegis run [--config NAME] [--policy TPL] -- CMD [ARGS]` | Run command in sandboxed environment |
| `aegis wrap [--dir PATH] [--policy TPL] [--name NAME] -- CMD [ARGS]` | Wrap command with observability |
| `aegis pilot [--dir PATH] [--policy TPL] [--listen ADDR] -- CMD [ARGS]` | Supervise agent with TUI dashboard |
| `aegis watch [--dir PATH] [--name NAME] [--stop]` | Background filesystem watcher |
| `aegis monitor [NAME]` | Launch real-time TUI dashboard |
| `aegis log [NAME] [--last N]` | Show recent audit entries |
| `aegis diff SESSION1 SESSION2` | Compare two sessions for forensic analysis |
| `aegis status [NAME]` | Show health status |
| `aegis list` | List all configurations |
| `aegis use [NAME]` | Set or show the active configuration |
| `aegis report [NAME] [--format text\|json]` | Generate compliance report |
| `aegis policy validate --path FILE` | Validate a Cedar policy file |
| `aegis policy list [NAME]` | List active policies |
| `aegis policy generate --template NAME` | Print built-in policy template |
| `aegis audit query NAME [--last N] [--action KIND] [--decision D]` | Query audit entries |
| `aegis audit verify NAME` | Verify hash chain integrity |
| `aegis audit sessions NAME` | List recent sessions |
| `aegis audit session NAME --id UUID` | Show session details |
| `aegis audit policy-history NAME` | Show policy change history |
| `aegis audit export NAME --format FMT [--follow]` | Export (json/jsonl/csv/cef) |
| `aegis alerts list` | List configured alert rules |
| `aegis alerts test` | Test webhook connectivity |
| `aegis alerts history [--last N]` | Show alert dispatch history |
| `aegis config show [NAME]` | Show full configuration |
| `aegis daemon init` | Create default daemon config |
| `aegis daemon start` | Start the daemon in background |
| `aegis daemon stop` | Stop the daemon |
| `aegis daemon status` | Show daemon health |
| `aegis daemon agents` | List agent slots and status |

## Cedar Policy Reference

Aegis uses [Cedar](https://www.cedarpolicy.com/) for authorization. Policies are `.cedar` files in `~/.aegis/NAME/policies/`.

### Entity Types

- **Principal**: `Aegis::Agent` -- the agent identity (derived from config name)
- **Actions**: `Aegis::Action::` followed by one of:
  - `FileRead`, `FileWrite`, `FileDelete`
  - `DirCreate`, `DirList`
  - `NetConnect`, `ToolCall`
  - `ProcessSpawn`, `ProcessExit`
- **Resource**: `Aegis::Resource` -- the target path or resource

### Built-in Policy Templates

| Template | Description |
|---|---|
| `default-deny` | `forbid(principal, action, resource);` -- blocks everything |
| `allow-read-only` | Permits `FileRead`, `DirList`, `ProcessSpawn`, `ProcessExit` |
| `permit-all` | `permit(principal, action, resource);` -- allows everything (observe-only) |

### Example Policy

```cedar
// Allow reading files and listing directories
permit(
    principal,
    action == Aegis::Action::"FileRead",
    resource
);

permit(
    principal,
    action == Aegis::Action::"DirList",
    resource
);

// Deny everything else (implicit -- Aegis is default-deny)
```

## Configuration Reference

`~/.aegis/NAME/aegis.toml`:

```toml
name = "my-agent"
sandbox_dir = "/Users/me/.aegis/my-agent/sandbox"
policy_paths = ["/Users/me/.aegis/my-agent/policies"]
ledger_path = "/Users/me/.aegis/my-agent/audit.db"
allowed_network = []

[isolation]
# Options: "Seatbelt" (kernel enforcement), "Process" (no enforcement), "None"
Seatbelt = { profile_overrides = null }

[observer]
# Options: "None", { FsEvents = { enable_snapshots = true } }, "EndpointSecurity"
FsEvents = { enable_snapshots = true }

[pilot]
# Optional: pilot supervision settings
[pilot.stall]
timeout_secs = 120
nudge_message = "Continue working on the task."
max_nudges = 5

[pilot.control]
http_listen = ""           # e.g., "0.0.0.0:8443"
api_key = ""               # Required for HTTP access

# Alert rules (optional)
[[alerts]]
name = "deny-alert"
event = "deny"
webhook_url = "https://hooks.slack.com/services/..."
```

## Crate Structure

| Crate | Description |
|---|---|
| `aegis-types` | Shared types, errors, config (foundation for all crates) |
| `aegis-policy` | Cedar policy engine, schema, builtin templates |
| `aegis-ledger` | Append-only hash-chained audit log, sessions, SIEM export |
| `aegis-sandbox` | Seatbelt backend, Cedar-to-SBPL compiler, process backend |
| `aegis-proxy` | Process audit logging, Seatbelt violation harvesting |
| `aegis-observer` | FSEvents filesystem observer with snapshot diffing |
| `aegis-pilot` | PTY supervisor: prompt detection, adapters, stall detection |
| `aegis-control` | Control plane: Unix socket + HTTP servers, command protocol |
| `aegis-alert` | Webhook alert dispatching |
| `aegis-channel` | Bidirectional messaging (Telegram, etc.) |
| `aegis-daemon` | Multi-agent fleet orchestration |
| `aegis-monitor` | Real-time ratatui TUI dashboard |
| `aegis-cli` | Binary entry point, all CLI commands, pilot TUI |

## Building from Source

### Prerequisites

- macOS 12+ (Monterey or later)
- Rust 1.75+ (install via [rustup](https://rustup.rs))

No kernel extensions. No system extension approvals. No reboots.

### Build

```bash
git clone https://github.com/markm39/aegis.git
cd aegis
cargo build --release
```

### Install

```bash
cargo install --path crates/aegis-cli
```

### Test

```bash
# Unit + integration tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# E2E smoke test (builds binary, runs full lifecycle)
cargo test --test test_smoke
```

## License

MIT OR Apache-2.0
