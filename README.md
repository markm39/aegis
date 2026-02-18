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
| Remote control (Telegram) | No | Yes |
| Multi-agent fleet management | No | Yes (daemon + orchestrator) |

## Install

macOS 12+ (Monterey or later). No kernel extensions. No reboots.

### One-line install (recommended)

```bash
curl -sSf https://raw.githubusercontent.com/markm39/aegis/main/install.sh | sh
```

### Homebrew

```bash
brew install markm39/tap/aegis
```

### Cargo (from crates.io)

```bash
cargo install aegis-cli
```

### Download binary

Pre-built macOS binaries (universal, arm64, x86_64) are available on the [Releases](https://github.com/markm39/aegis/releases) page.

### Build from source

See [Building from Source](#building-from-source) below.

## Quick Start

One command:

```bash
aegis
```

First run launches a setup wizard that walks you through configuring your first agent. After that, you land in the hub -- a full-screen TUI where everything is managed. You never need to leave it.

For a quick one-off without the hub:

```bash
aegis wrap -- claude
```

This wraps Claude Code with full observability (audit trail, file monitoring, session tracking) and zero config. When it's done, check what happened with `:log` from the hub, or `aegis log claude` from the shell.

## The Hub

The hub is the primary interface. Run `aegis` and you're in. Everything else in this README is accessible from inside the hub via the `:` command bar -- you don't need to memorize any subcommands.

Type `:` and start typing. Tab completion and 30+ commands are available. Here's what you can do without ever leaving the hub:

### Manage agents

```
:add                  Add a new agent (interactive wizard)
:remove claude-1      Remove an agent
:start claude-1       Start an agent
:stop claude-1        Stop an agent
:restart claude-1     Restart an agent
:enable claude-1      Re-enable a disabled agent
:disable claude-2     Disable (stops + prevents restart)
```

### Interact with agents

```
:send claude-1 fix the login bug     Send input to an agent
:approve claude-1                    Approve pending permission request
:deny claude-1                       Deny pending permission request
:nudge claude-1                      Nudge a stalled agent
:follow claude-1                     Stream output in a new terminal
:pop claude-1                        Pop agent into a separate terminal window
:pending                             Show all pending prompts across the fleet
```

### Fleet coordination

```
:goal Ship v2 by Friday              Set fleet-wide goal
:context claude-1                    View/edit agent role, goal, and task
:status                              Fleet health overview
```

### Audit and compliance

```
:log claude-1                        View audit log
:monitor claude-1                    Open audit TUI dashboard in new terminal
:report claude-1                     Generate compliance report
:diff UUID1 UUID2                    Compare two sessions
```

### Configuration

```
:config                              Edit daemon.toml in your editor
:telegram                            Configure Telegram notifications
:daemon start                        Start/stop the background daemon
:help                                Full command reference
```

### Keybindings

| Key | Action |
|---|---|
| `j`/`k` | Navigate agent list |
| `Enter` | View agent detail / output |
| `Tab` | Jump to next agent needing attention |
| `i` | Send input to selected agent |
| `a` | Approve pending request |
| `d` | Deny pending request |
| `n` | Nudge stalled agent |
| `?` | Help |
| `q` | Quit |

### Remote control

When you're away from the terminal, Aegis forwards pending prompts, stall alerts, and agent exits to Telegram with inline [Approve] / [Deny] buttons. See [Telegram](#telegram-remote-control) below.

## How It Works

Under the hood, Aegis has three modes of running agents. You choose the mode when adding an agent (or the hub picks the right one for you).

### Pilot supervision

The most common mode. Aegis spawns your agent in a PTY, monitors output for permission prompts, auto-approves or denies them based on Cedar policy, detects stalls, and logs everything to the audit ledger.

From the hub: `:add` walks you through this. Or from the shell:

```bash
aegis pilot -- claude
aegis pilot --policy allow-read-only -- claude
aegis pilot --dir ~/my-project -- claude
```

### Wrap (observe-only)

Lightweight observability without prompt supervision. Wraps any command with file monitoring and audit logging:

```bash
aegis wrap -- claude
aegis wrap --dir ~/my-project -- python3 agent.py
```

### Full sandbox

Maximum isolation. Cedar policies compiled to macOS Seatbelt profiles for kernel-level enforcement:

```bash
aegis init my-agent --policy allow-read-only --dir ~/my-project
aegis run --config my-agent -- python3 agent.py
```

## Fleet Management

The daemon runs in the background and manages your agents as a fleet -- starting them, restarting on crash, coordinating context. The hub connects to it automatically.

### Fleet goals and agent context

Give agents roles and direction so they coordinate without stepping on each other:

```toml
# ~/.aegis/daemon/daemon.toml
fleet_goal = "Ship the v2 auth system by Friday"

[agents.claude-1]
tool = "ClaudeCode"
working_dir = "~/my-project"
role = "Backend engineer"
agent_goal = "Implement OAuth2 provider"
task = "Add token refresh endpoint"

[agents.claude-2]
tool = "ClaudeCode"
working_dir = "~/my-project"
role = "Frontend engineer"
agent_goal = "Build the settings UI"
task = "Add OAuth callback page"
```

These fields are persisted and included in autonomy prompts when agents request interactive input. Update them at runtime from the hub (`:goal`, `:context`) or the shell (`aegis daemon goal`, `aegis daemon context`).

### Orchestrator agents

An orchestrator is a special agent that periodically reviews the fleet and directs other agents:

```toml
[agents.lead]
tool = "ClaudeCode"
working_dir = "~/my-project"
role = "Tech lead"

[agents.lead.orchestrator]
review_interval_secs = 300
managed_agents = []  # empty = manage all non-orchestrator agents
```

The orchestrator receives a fleet snapshot (agent status, recent output, attention flags, pending counts) at each review interval and can issue commands to redirect the team.

### Crash recovery

The daemon is resilient to crashes and restarts:

- **Exponential backoff** for crash loops -- agents that crash within 30 seconds get increasing delays (2, 4, 8... up to 60s) before restart
- **State persistence** -- session IDs and restart counts survive daemon restarts via `~/.aegis/daemon/state.json`
- **Graceful shutdown** -- SIGTERM with 5-second timeout, escalating to SIGKILL
- **Atomic config writes** -- temp file + fsync + rename prevents corruption on power loss

## Telegram Remote Control

Connect Aegis to a Telegram bot for bidirectional remote control when you're away from the terminal:

```toml
# In daemon.toml
[channel]
type = "telegram"
bot_token = "123456:ABC..."
chat_id = 987654321
```

The daemon forwards notable events -- pending permission prompts, stall nudges, attention alerts, and agent exits. Pending permission requests include inline [Approve] / [Deny] buttons for one-tap responses.

Available Telegram commands:

| Command | Action |
|---|---|
| `/status` | Check fleet/agent status |
| `/approve <id>` | Approve a pending request |
| `/deny <id>` | Deny a pending request |
| `/output [N]` | View recent agent output |
| `/input <text>` | Send text to agent stdin |
| `/nudge` | Nudge a stalled agent |
| `/goal [text]` | Get or set fleet-wide goal |
| `/context <agent>` | View agent context |
| `/stop` | Stop an agent |
| `/help` | List all commands |

## Cedar Policies

Aegis uses [Cedar](https://www.cedarpolicy.com/) for authorization. Policies are `.cedar` files in `~/.aegis/NAME/policies/`. Default-deny: anything not explicitly permitted is blocked.

### Entity types

- **Principal**: `Aegis::Agent` -- the agent identity (derived from config name)
- **Actions**: `Aegis::Action::` followed by one of:
  - `FileRead`, `FileWrite`, `FileDelete`
  - `DirCreate`, `DirList`
  - `NetConnect`, `ToolCall`
  - `ProcessSpawn`, `ProcessExit`
- **Resource**: `Aegis::Resource` -- the target path or resource

### Built-in templates

| Template | Description |
|---|---|
| `default-deny` | `forbid(principal, action, resource);` -- blocks everything |
| `allow-read-only` | Permits `FileRead`, `DirList`, `ProcessSpawn`, `ProcessExit` |
| `permit-all` | `permit(principal, action, resource);` -- allows everything (observe-only) |

### Example policy

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

## Webhook Alerts

Alert rules are defined in the agent config TOML and can target Slack, PagerDuty, or arbitrary HTTP endpoints:

```toml
[[alerts]]
name = "deny-alert"
event = "deny"
webhook_url = "https://hooks.slack.com/services/..."
```

Manage from the hub with `:alerts` or from the shell with `aegis alerts list`, `aegis alerts test`, `aegis alerts history`.

## Configuration Reference

### Agent config: `~/.aegis/NAME/aegis.toml`

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

# Telegram remote control (optional)
[channel]
type = "telegram"
bot_token = "123456:ABC-DEF..."
chat_id = 987654321
```

### Daemon config: `~/.aegis/daemon/daemon.toml`

```toml
# Fleet-wide goal (optional)
fleet_goal = "Ship the v2 auth system by Friday"

[agents.claude-1]
tool = "ClaudeCode"
working_dir = "~/my-project"
role = "Backend engineer"
agent_goal = "Implement OAuth2 provider"
context = "Using axum web framework, PostgreSQL"
task = "Add token refresh endpoint"

[agents.claude-2]
tool = "ClaudeCode"
working_dir = "~/my-project"
role = "Frontend engineer"
agent_goal = "Build the settings UI"
task = "Add OAuth callback page"

# Optional: designate an agent as fleet orchestrator
[agents.lead]
tool = "ClaudeCode"
working_dir = "~/my-project"
role = "Tech lead"

[agents.lead.orchestrator]
review_interval_secs = 300    # How often to review fleet state
managed_agents = []           # Empty = manage all non-orchestrator agents

# Telegram notifications (optional)
[channel]
type = "telegram"
bot_token = "123456:ABC-DEF..."
chat_id = 987654321
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

Seven layers:
1. **Policy Engine** -- Cedar 4.x policies define what agents can do (default-deny)
2. **Cedar-to-SBPL Compiler** -- Translates Cedar policies into macOS Seatbelt profiles at launch
3. **Isolation Boundary** -- macOS Seatbelt (`sandbox-exec`) enforces at the kernel level
4. **Pilot Supervisor** -- PTY-based agent supervision with prompt detection, auto-approval, and stall nudging
5. **Fleet Daemon** -- Multi-agent orchestration with crash recovery, exponential backoff, and orchestrator agents
6. **Observer** -- FSEvents filesystem monitoring with snapshot diffing for complete coverage
7. **Audit Ledger** -- Append-only, SHA-256 hash-chained SQLite log with session tracking

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
| `aegis-daemon` | Multi-agent fleet orchestration with crash recovery |
| `aegis-monitor` | Real-time ratatui TUI dashboard |
| `aegis-harness` | PTY-based TUI integration test harness |
| `aegis-cli` | Binary entry point, all CLI commands, pilot TUI |

## CLI Reference

Every command below is also available from the hub's `:` command bar. The CLI exists for scripting and automation.

<details>
<summary>Full CLI reference (click to expand)</summary>

| Command | Description |
|---|---|
| `aegis` | Open the hub (primary interface) |
| `aegis init [NAME] [--policy TPL] [--dir PATH]` | Create config (omit NAME for wizard) |
| `aegis setup` | Check system requirements |
| `aegis wrap [--dir PATH] [--policy TPL] [--name NAME] -- CMD` | Wrap command with observability |
| `aegis pilot [--dir PATH] [--policy TPL] [--listen ADDR] -- CMD` | Supervise agent in standalone mode |
| `aegis run [--config NAME] [--policy TPL] -- CMD` | Run in sandboxed environment |
| `aegis watch [--dir PATH] [--name NAME] [--stop]` | Background filesystem watcher |
| `aegis monitor [NAME]` | Standalone audit TUI dashboard |
| `aegis log [NAME] [--last N]` | Show recent audit entries |
| `aegis diff SESSION1 SESSION2` | Compare two sessions |
| `aegis status [NAME]` | Show health status |
| `aegis list` | List all configurations |
| `aegis use [NAME]` | Set or show active configuration |
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
| `aegis daemon start` | Start the daemon |
| `aegis daemon stop` | Stop the daemon |
| `aegis daemon status` | Show daemon health |
| `aegis daemon agents` | List agent slots and status |
| `aegis daemon output <name> [--lines N]` | View agent output |
| `aegis daemon follow <name>` | Stream agent output in real time |
| `aegis daemon send <name> <text>` | Send input to agent |
| `aegis daemon approve <name> <request-id>` | Approve pending prompt |
| `aegis daemon deny <name> <request-id>` | Deny pending prompt |
| `aegis daemon nudge <name> [message]` | Nudge stalled agent |
| `aegis daemon pending <name>` | List pending prompts |
| `aegis daemon enable <name>` | Enable a disabled agent |
| `aegis daemon disable <name>` | Disable an agent (stops if running) |
| `aegis daemon restart <name>` | Restart a specific agent |
| `aegis daemon stop-agent <name>` | Stop a specific agent |
| `aegis daemon goal [text]` | Get or set fleet-wide goal |
| `aegis daemon context <name> [--role R] [--goal G] [--context C] [--task T]` | Get or set agent context |

</details>

## Building from Source

For contributors and those who prefer building locally.

### Prerequisites

- macOS 12+ (Monterey or later)
- Rust 1.75+ (install via [rustup](https://rustup.rs))

### Build and install

```bash
git clone https://github.com/markm39/aegis.git
cd aegis
make install
```

Or manually:

```bash
cargo build --release
cargo install --path crates/aegis-cli
```

### Test

```bash
# Lint + test
make check

# Or individually:
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## License

MIT OR Apache-2.0
