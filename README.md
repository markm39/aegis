# Aegis

[![CI](https://github.com/markm39/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/markm39/aegis/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust: 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

Autonomous coding agent and zero-trust runtime. Chat with LLMs, execute tools, manage multi-agent fleets -- all from a single terminal binary. Written in Rust.

Aegis is a chat-centric coding assistant (like Claude Code or OpenClaw) built on a zero-trust foundation: every file access is observed, governed by Cedar policies, and logged to a tamper-evident audit ledger. Agents run in a PTY with auto-approval, stall detection, and optional kernel-level Seatbelt enforcement on macOS.

---

## Table of Contents

- [Install](#install)
- [Quick Start](#quick-start)
- [Chat TUI](#chat-tui)
- [Slash Commands](#slash-commands)
- [Approval Modes](#approval-modes)
- [Workspace Context](#workspace-context)
- [Tools](#tools)
- [Agent Modes](#agent-modes)
- [Fleet Management](#fleet-management)
- [Telegram Remote Control](#telegram-remote-control)
- [Cedar Policies](#cedar-policies)
- [Webhook Alerts](#webhook-alerts)
- [Sessions](#sessions)
- [Skills & Plugins](#skills--plugins)
- [Configuration Reference](#configuration-reference)
- [Architecture](#architecture)
- [Crate Structure](#crate-structure)
- [CLI Reference](#cli-reference)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)

---

## Install

macOS 12+ or Linux. No kernel extensions. No reboots.

### One-line install (recommended)

```bash
curl -sSf https://raw.githubusercontent.com/markm39/aegis/main/install.sh | sh
```

### Homebrew

```bash
brew install markm39/tap/aegis
```

### Cargo

```bash
cargo install aegis-cli
```

### Download binary

Pre-built binaries (macOS universal/arm64/x86_64, Linux x86_64) are available on the [Releases](https://github.com/markm39/aegis/releases) page.

### Build from source

See [Building from Source](#building-from-source) below.

## Quick Start

```bash
aegis
```

First run launches a setup wizard: pick your LLM provider, configure credentials, and you're in the chat TUI. That's it.

For observe-only wrapping of an existing agent:

```bash
aegis wrap -- claude
```

## Chat TUI

The chat TUI is the primary interface. Run `aegis` and start typing. Aegis calls your configured LLM, streams responses, executes tools (file edits, shell commands, subagents), and renders markdown -- all in the terminal.

### Key features

- **Streaming responses** from OpenAI, Anthropic, and other LLM providers
- **Tool execution** with sandbox/policy enforcement (reads, writes, shell commands, patches)
- **Subagent spawning** for parallel, complex tasks via the `task` tool
- **Markdown rendering** with syntax highlighting in the terminal
- **Conversation persistence** -- resume where you left off
- **Session forking and branching** -- explore different approaches without losing context
- **Context compaction** -- long conversations are automatically summarized to stay within context limits
- **Hooks** -- run custom scripts before/after tool calls for validation or side effects

### Auto mode

Control how much autonomy Aegis has:

```bash
aegis --auto off      # Ask before every tool call (default)
aegis --auto edits    # Auto-approve reads, ask for writes
aegis --auto high     # Auto-approve most actions, ask for destructive ones
aegis --auto full     # Full autonomy, no prompts
```

## Slash Commands

Type `/` in the chat to access built-in skill commands:

| Command | Description |
|---|---|
| `/debug <error>` | Diagnose and fix an error |
| `/doc <file or area>` | Generate documentation |
| `/explain <code>` | Explain code or concepts |
| `/refactor <target>` | Refactor code |
| `/test <target>` | Write or fix tests |
| `/review` | Code review |
| `/security` | Security audit |
| `/perf` | Performance analysis |
| `/panel-review` | Multi-perspective code review |
| `/link-worktree` | Link a git worktree |

## Approval Modes

Aegis enforces a Cedar policy engine on all tool calls. The `--auto` flag controls the interactive approval threshold:

| Mode | Behavior |
|---|---|
| `off` | Prompt for every tool call |
| `edits` | Auto-approve reads and listings; prompt for writes, deletes, shell commands |
| `high` | Auto-approve most safe actions; prompt for destructive operations |
| `full` | Auto-approve everything (full autonomy) |

## Workspace Context

Aegis loads persistent context files from `~/.aegis/workspace/` on every session:

| File | Purpose |
|---|---|
| `SOUL.md` | Agent persona and tone |
| `IDENTITY.md` | Agent name and identity |
| `USER.md` | Information about you (preferences, environment) |
| `TOOLS.md` | Environment and tooling notes |
| `MEMORY.md` | Persistent notes across sessions (agent-updated) |
| `HEARTBEAT.md` | Session startup checklist |

Project-level context (`AGENTS.md`, `CLAUDE.md`, `.aegis/AGENTS.md`) is also loaded from the current working directory.

## Tools

Aegis exposes tools to the LLM via the standard tool-use protocol:

- **`read_file`** -- Read files from disk
- **`write_file`** -- Create new files
- **`apply_patch`** -- Edit existing files with structured patches (vendored from Codex)
- **`bash`** -- Execute shell commands
- **`task`** -- Spawn subagents for parallel work
- **`list_dir`** -- List directory contents
- **MCP servers** -- Connect external tool servers via the Model Context Protocol

Tool execution is routed through the daemon for sandbox and policy enforcement. Every invocation is logged to the audit ledger.

## Agent Modes

Aegis supports three modes for running agents, from lightweight to maximum isolation:

### Chat (default)

The full coding agent experience. Run `aegis` and chat. LLM calls stream directly; tool calls go through the daemon for policy enforcement.

### Pilot supervision

Wraps any CLI agent (Claude Code, Codex, etc.) in a PTY with prompt detection, auto-approval via Cedar policy, stall detection, and nudging:

```bash
aegis pilot -- claude
aegis pilot --policy allow-read-only -- claude
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

The daemon manages multiple agents as a fleet -- starting them, restarting on crash, coordinating context. The chat TUI connects to it automatically.

### Fleet goals and agent context

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

Update at runtime with `:goal` and `:context` from the fleet TUI, or `aegis daemon goal` / `aegis daemon context` from the shell.

### Fleet TUI

Access the fleet dashboard with `aegis fleet`. Keybindings:

| Key | Action |
|---|---|
| `j`/`k` | Navigate agent list |
| `Enter` | View agent detail / output |
| `Tab` | Jump to next agent needing attention |
| `i` | Send input to selected agent |
| `a` | Approve pending request |
| `d` | Deny pending request |
| `n` | Nudge stalled agent |
| `:` | Command bar (30+ commands with tab completion) |
| `?` | Help |
| `q` | Quit |

### Orchestrator agents

A special agent that periodically reviews the fleet and directs other agents:

```toml
[agents.lead]
tool = "ClaudeCode"
working_dir = "~/my-project"
role = "Tech lead"

[agents.lead.orchestrator]
review_interval_secs = 300
managed_agents = []  # empty = manage all non-orchestrator agents
```

### Crash recovery

- **Exponential backoff** for crash loops (2, 4, 8... up to 60s)
- **State persistence** via `~/.aegis/daemon/state.json`
- **Graceful shutdown** -- SIGTERM with 5-second timeout, escalating to SIGKILL
- **Atomic config writes** -- temp file + fsync + rename

## Telegram Remote Control

Bidirectional Telegram bot for remote control when you're away from the terminal:

```toml
# In daemon.toml
[channel]
type = "telegram"
bot_token = "123456:ABC..."
chat_id = 987654321
```

Pending permission requests include inline [Approve] / [Deny] buttons for one-tap responses.

| Command | Action |
|---|---|
| `/status` | Fleet/agent status |
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

[Cedar](https://www.cedarpolicy.com/) authorization engine with default-deny. Policies are `.cedar` files in `~/.aegis/NAME/policies/`.

### Entity types

- **Principal**: `Aegis::Agent`
- **Actions**: `FileRead`, `FileWrite`, `FileDelete`, `DirCreate`, `DirList`, `NetConnect`, `ToolCall`, `ProcessSpawn`, `ProcessExit`
- **Resource**: `Aegis::Resource`

### Built-in templates

| Template | Description |
|---|---|
| `default-deny` | `forbid(principal, action, resource);` |
| `allow-read-only` | Permits `FileRead`, `DirList`, `ProcessSpawn`, `ProcessExit` |
| `permit-all` | `permit(principal, action, resource);` (observe-only) |

### Example

```cedar
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
```

## Webhook Alerts

```toml
[[alerts]]
name = "deny-alert"
event = "deny"
webhook_url = "https://hooks.slack.com/services/..."
```

Manage with `aegis alerts list`, `aegis alerts test`, `aegis alerts history`.

## Sessions

Aegis tracks every agent invocation as a session with full audit trails.

```bash
aegis sessions list                    # List recent sessions
aegis sessions show <uuid>             # Session details
aegis sessions chain <group-id>        # Conversation chain
aegis sessions resume <agent> <uuid>   # Resume a previous session
aegis sessions fork <uuid>             # Branch a conversation
aegis sessions tree <uuid>             # Display session tree
```

Sessions are stored in the SQLite audit ledger with SHA-256 hash chains for tamper evidence. Export in JSON, JSONL, CSV, or CEF format for SIEM integration.

## Skills & Plugins

Aegis has a plugin system for extending agent capabilities:

```bash
aegis skills install <name>    # Install a skill plugin
aegis skills list              # List installed skills
aegis skills search <query>    # Search available skills
aegis skills update            # Update all skills
aegis skills remove <name>     # Remove a skill
```

Skills support hot-reloading, conditional activation, and SDK-based development.

## Configuration Reference

### Agent config: `~/.aegis/NAME/aegis.toml`

```toml
name = "my-agent"
sandbox_dir = "/Users/me/.aegis/my-agent/sandbox"
policy_paths = ["/Users/me/.aegis/my-agent/policies"]
ledger_path = "/Users/me/.aegis/my-agent/audit.db"
allowed_network = []

[isolation]
Seatbelt = { profile_overrides = null }

[observer]
FsEvents = { enable_snapshots = true }

[pilot]
[pilot.stall]
timeout_secs = 120
nudge_message = "Continue working on the task."
max_nudges = 5

[pilot.control]
http_listen = ""
api_key = ""

[[alerts]]
name = "deny-alert"
event = "deny"
webhook_url = "https://hooks.slack.com/services/..."

[channel]
type = "telegram"
bot_token = "123456:ABC-DEF..."
chat_id = 987654321
```

### Daemon config: `~/.aegis/daemon/daemon.toml`

```toml
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

[agents.lead]
tool = "ClaudeCode"
working_dir = "~/my-project"
role = "Tech lead"

[agents.lead.orchestrator]
review_interval_secs = 300
managed_agents = []

[channel]
type = "telegram"
bot_token = "123456:ABC-DEF..."
chat_id = 987654321
```

## Architecture

```
                         aegis (chat TUI)
                              |
              +---------------+---------------+
              |                               |
         LLM Providers                   Daemon (fleet)
    (OpenAI, Anthropic, ...)           /       |       \
              |                   Agent 1  Agent 2  Agent N
              v                       |
         Tool Calls  <----------------+
              |
    +---------+---------+
    |         |         |
  Policy   Sandbox   Observer
  (Cedar)  (Seatbelt) (FSEvents)
    |         |         |
    v         v         v
         Audit Ledger
    (SQLite, SHA-256 hash-chained)
              |
    +---------+---------+
    |    |    |    |    |
  SIEM  TUI  API  Alerts  Telegram
```

Layers:
1. **Chat TUI** -- Streaming LLM conversations with tool execution
2. **Tool System** -- Extensible tool registry with MCP server support
3. **Policy Engine** -- Cedar 4.x policies (default-deny)
4. **Sandbox** -- macOS Seatbelt kernel-level enforcement (optional)
5. **Pilot Supervisor** -- PTY-based agent supervision with prompt detection and stall nudging
6. **Fleet Daemon** -- Multi-agent orchestration with crash recovery and orchestrator agents
7. **Observer** -- FSEvents filesystem monitoring with snapshot diffing
8. **Audit Ledger** -- Append-only, SHA-256 hash-chained SQLite log with session tracking

## Crate Structure

| Crate | Description |
|---|---|
| `aegis-types` | Shared types, errors, config, LLM abstractions, provider definitions |
| `aegis-policy` | Cedar policy engine, schema, builtin templates |
| `aegis-ledger` | Append-only hash-chained audit log, sessions, SIEM export |
| `aegis-sandbox` | Seatbelt backend, Cedar-to-SBPL compiler, process backend |
| `aegis-proxy` | Process audit logging, Seatbelt violation harvesting |
| `aegis-observer` | FSEvents filesystem observer with snapshot diffing |
| `aegis-pilot` | PTY supervisor: prompt detection, adapters, stall detection |
| `aegis-control` | Control plane: Unix socket + HTTP servers, command protocol |
| `aegis-alert` | Webhook alert dispatching |
| `aegis-channel` | Bidirectional messaging (Telegram bot with inline keyboards) |
| `aegis-daemon` | Multi-agent fleet orchestration with crash recovery |
| `aegis-monitor` | Real-time ratatui audit TUI dashboard |
| `aegis-tools` | Tool definitions, executor, MCP server integration |
| `aegis-skills` | Skill plugin system with hot-reload and SDK |
| `aegis-hooks` | Event-driven hook system for tool call validation |
| `aegis-toolkit` | Browser automation toolkit (CDP, page snapshots, screenshots) |
| `aegis-browser` | Browser driver (Chrome DevTools Protocol) |
| `aegis-canvas` | Canvas rendering and visual output |
| `aegis-tts` | Text-to-speech (OpenAI, ElevenLabs, Edge TTS) |
| `aegis-voice` | Voice input, speech-to-text, wake word detection |
| `aegis-harness` | PTY-based TUI integration test harness |
| `aegis-cli` | Binary entry point: chat TUI, fleet TUI, wizard, all CLI commands |

## CLI Reference

<details>
<summary>Full CLI reference (click to expand)</summary>

### Core

| Command | Description |
|---|---|
| `aegis` | Open chat TUI (primary interface) |
| `aegis fleet` | Open fleet dashboard TUI |
| `aegis setup` | Check system requirements |
| `aegis doctor [--fix]` | Diagnose and fix configuration issues |

### Agent Execution

| Command | Description |
|---|---|
| `aegis wrap [--dir PATH] [--policy TPL] -- CMD` | Wrap command with observability |
| `aegis pilot [--dir PATH] [--policy TPL] [--listen ADDR] -- CMD` | Supervise agent with auto-approval |
| `aegis run [--config NAME] [--policy TPL] -- CMD` | Run in sandboxed environment |
| `aegis watch [--dir PATH] [--name NAME] [--stop]` | Background filesystem watcher |

### Configuration

| Command | Description |
|---|---|
| `aegis init [NAME] [--policy TPL] [--dir PATH]` | Create config (omit NAME for wizard) |
| `aegis config show [NAME]` | Show full configuration |
| `aegis config edit [NAME]` | Open config in $EDITOR |
| `aegis config get <key>` | Read a config value (dot-notation) |
| `aegis config set <key> <value>` | Write a config value |
| `aegis config list` | Show all effective key-value pairs |
| `aegis config layers` | Show config file priority |
| `aegis list` | List all configurations |
| `aegis use [NAME]` | Set or show active configuration |

### Authentication

| Command | Description |
|---|---|
| `aegis auth list` | List configured auth profiles |
| `aegis auth add <provider>` | Add or update an auth profile |
| `aegis auth remove <profile>` | Remove an auth profile |
| `aegis auth test [profile]` | Test auth connectivity |

### Audit & Sessions

| Command | Description |
|---|---|
| `aegis log [NAME] [--last N]` | Show recent audit entries |
| `aegis monitor [NAME]` | Standalone audit TUI dashboard |
| `aegis diff SESSION1 SESSION2` | Compare two sessions |
| `aegis status [NAME]` | Show health status |
| `aegis report [NAME] [--format text\|json]` | Generate compliance report |
| `aegis audit query [--last N] [--action KIND] [--decision D]` | Query audit entries |
| `aegis audit verify` | Verify hash chain integrity |
| `aegis audit export [--format FMT] [--follow]` | Export (json/jsonl/csv/cef) |
| `aegis audit purge <older_than> --confirm` | Purge old entries |
| `aegis sessions list` | List recent sessions |
| `aegis sessions show <uuid>` | Session details |
| `aegis sessions resume <agent> <uuid>` | Resume a session |
| `aegis sessions fork <uuid>` | Fork a session |
| `aegis sessions tree <uuid>` | Display session tree |

### Policy

| Command | Description |
|---|---|
| `aegis policy validate <path>` | Validate a .cedar policy file |
| `aegis policy list [NAME]` | List active policies |
| `aegis policy generate <template>` | Print builtin policy template |
| `aegis policy import <path>` | Import a policy into a config |
| `aegis policy test <action> <resource>` | Dry-run policy evaluation |

### Fleet & Daemon

| Command | Description |
|---|---|
| `aegis daemon init` | Create default daemon config |
| `aegis daemon start` | Start the daemon |
| `aegis daemon stop` | Stop the daemon |
| `aegis daemon status` | Show daemon health |
| `aegis daemon agents` | List agent slots and status |
| `aegis daemon output <name> [--lines N]` | View agent output |
| `aegis daemon follow <name>` | Stream agent output |
| `aegis daemon send <name> <text>` | Send input to agent |
| `aegis daemon approve <name> <id>` | Approve pending prompt |
| `aegis daemon deny <name> <id>` | Deny pending prompt |
| `aegis daemon nudge <name> [message]` | Nudge stalled agent |
| `aegis daemon goal [text]` | Get or set fleet-wide goal |
| `aegis daemon context <name> [--role R] [--goal G] [--task T]` | Get or set agent context |

### Alerts & Notifications

| Command | Description |
|---|---|
| `aegis alerts list` | List configured alert rules |
| `aegis alerts test` | Test webhook connectivity |
| `aegis alerts history [--last N]` | Show alert dispatch history |
| `aegis telegram setup` | Interactive Telegram bot setup |
| `aegis telegram status` | Show Telegram configuration |

### Skills & Hooks

| Command | Description |
|---|---|
| `aegis skills install <name>` | Install a skill plugin |
| `aegis skills list` | List installed skills |
| `aegis skills search <query>` | Search available skills |
| `aegis skills remove <name>` | Remove a skill |
| `aegis hook install` | Install Claude Code policy hooks |
| `aegis hook status` | Show hook installation status |

### Utilities

| Command | Description |
|---|---|
| `aegis completions <shell>` | Generate shell completions (bash/zsh/fish) |
| `aegis manpage` | Generate man page |
| `aegis parity status` | Feature parity matrix |

</details>

## Building from Source

### Prerequisites

- macOS 12+ or Linux
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
make check    # clippy + tests

# Or individually:
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

### Vendored dependencies

Aegis vendors the Codex `apply-patch` tool and a coding runtime snapshot:

```bash
make sync-coding-runtime      # Refresh from upstream
make check-coding-runtime     # CI-safe drift check
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding conventions, and how to submit changes.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
