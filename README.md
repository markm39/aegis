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
- [Skills](#skills)
- [Configuration Reference](#configuration-reference)
- [Architecture](#architecture)
- [Crate Structure](#crate-structure)
- [CLI Reference](#cli-reference)
- [Docker](#docker)
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
- **Extended thinking** -- configurable thinking budget (`/think low|medium|high|<tokens>`)
- **Model and provider switching** -- change models on the fly via `/model` overlay
- **Conversation persistence** -- resume where you left off with `/resume`
- **Session forking and branching** -- explore different approaches without losing context
- **Context compaction** -- long conversations are automatically summarized to stay within context limits, or manually via `/compact`
- **Shell integration** -- run shell commands inline with `!<cmd>` or pipe output to the LLM with `|`
- **Overlays** -- modal UIs for model picker, session picker, login/credentials, and settings
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

Type `/` in the chat to enter command mode. All commands:

### Session

| Command | Description |
|---|---|
| `/quit` | Exit (auto-saves conversation) |
| `/clear` | Clear conversation |
| `/new` | Start fresh session (auto-saves current) |
| `/save` | Manually save current conversation |
| `/resume <id>` | Resume a previous conversation |
| `/sessions` | Open session picker overlay |
| `/compact` | Compress conversation history via LLM |

### Model and provider

| Command | Description |
|---|---|
| `/model [name]` | Open model picker, or switch directly to a named model |
| `/provider` | Show available providers and auth status |
| `/login [provider]` | Open login overlay to manage credentials |
| `/mode [auto\|chat\|code]` | Switch agent mode |
| `/engine [auto\|provider\|native]` | Switch inference engine |

### Approval and thinking

| Command | Description |
|---|---|
| `/auto [off\|edits\|high\|full]` | Show or change auto-approval mode |
| `/think [off\|low\|medium\|high\|N]` | Set extended thinking budget (tokens) |

### Daemon

| Command | Description |
|---|---|
| `/daemon start` | Start the daemon in background |
| `/daemon stop` | Stop running daemon |
| `/daemon restart` | Stop and restart |
| `/daemon reload` | Reload config without restart |
| `/daemon status` | Show daemon status |
| `/daemon init` | Create default daemon.toml |

### Other

| Command | Description |
|---|---|
| `/abort` | Abort current LLM request |
| `/usage` | Show token usage and cost for session |
| `/settings` | Open settings panel overlay |
| `/help` | Display all commands |

### Shell integration

| Prefix | Description |
|---|---|
| `!<cmd>` | Execute a shell command (output shown in chat) |
| `\|` | Pipe command output into the LLM |

### Skill commands

| Command | Description |
|---|---|
| `/debug <error>` | Diagnose and fix an error |
| `/doc <file or area>` | Generate documentation |
| `/explain <code>` | Explain code or concepts |
| `/refactor <target>` | Refactor code |
| `/test <target>` | Write or fix tests |
| `/review [file]` | Code review |
| `/security <target>` | Security audit |
| `/perf <target>` | Performance analysis |
| `/panel-review <topic>` | Multi-perspective expert review |
| `/link-worktree <path>` | Link .env files into a git worktree |

## Approval Modes

Aegis enforces a Cedar policy engine on all tool calls. The `--auto` flag (or `/auto` in chat) controls the interactive approval threshold:

| Mode | Behavior |
|---|---|
| `off` | Prompt for every tool call |
| `edits` | Auto-approve reads and listings; prompt for writes, deletes, shell commands |
| `high` | Auto-approve most safe actions; prompt for destructive operations |
| `full` | Auto-approve everything (full autonomy) |

### Risk tiers

Tool calls are classified by risk level:

| Risk | Examples | Auto-approved at |
|---|---|---|
| Informational | `read_file`, `glob_search`, `grep_search`, `file_search` | `edits` and above |
| Medium | `write_file`, `apply_patch`, safe bash (`ls`, `git status`, `cargo test`) | `edits` and above |
| High | Destructive bash (`rm -rf`, `git push --force`, `sudo`), unknown tools | `high` and above |

Safe tools (`read_file`, `glob_search`, `grep_search`, `file_search`, `task`) are always auto-approved, even in `off` mode.

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
- **Skills** -- 64 bundled skill tools (see [Skills](#skills))

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
aegis pilot --adapter ClaudeCode --stall-timeout 120 -- claude
```

The pilot TUI shows live agent output, pending approval requests, and stats. Keybindings:

| Key | Action |
|---|---|
| `Up`/`Down` | Scroll output |
| `Tab` | Switch focus between output and pending panels |
| `i` | Send input to agent |
| `y` | Approve pending request |
| `n` | Deny pending request |
| `N` | Nudge stalled agent |
| `Esc` | Exit |

Remote control via HTTP is available with `--listen 0.0.0.0:8443 --api-key SECRET`.

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

The daemon manages multiple agents as a fleet -- starting them, restarting on crash, coordinating context. The chat TUI connects to it automatically and exposes fleet operations via `/daemon` commands.

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

Update at runtime with `aegis daemon goal` / `aegis daemon context` from the shell, or `/daemon` commands from the chat TUI.

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

### Launchd auto-start (macOS)

```bash
aegis daemon install --start    # Install launchd plist and start
aegis daemon uninstall          # Remove launchd plist
```

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
aegis sessions inspect <uuid>          # Full details with entry counts
aegis sessions reset <uuid>            # Clear context, mark non-resumable
aegis sessions delete <uuid> --confirm # Delete session and audit entries
```

Sessions are stored in the SQLite audit ledger with SHA-256 hash chains for tamper evidence. Export in JSON, JSONL, CSV, or CEF format for SIEM integration.

## Skills

Aegis ships with 64 bundled skill plugins that are compiled in at build time and exposed to the LLM as tool-use definitions. Each skill is a shell script with a `manifest.toml` declaring its commands, parameters, and descriptions.

Skills are also surfaced as `/slash` commands in the chat TUI. Dynamic skills can override bundled ones and support hot-reloading.

### Bundled skill categories

- **Development** -- calculator, code-review, coding-agent, git-operations, json-tools, shell-exec, summarize
- **Productivity** -- apple-notes, apple-reminders, bear-notes, things-mac, obsidian, notion, trello, clipboard-manager
- **Communication** -- slack-skill, discord-skill, himalaya (email), imsg, reddit
- **Media** -- audio-record, openai-whisper, openai-whisper-api, sherpa-onnx-tts, spotify-player, video-frames, camsnap, gifgrep, canvas, openai-image-gen
- **Web** -- web-search, web-scraper, xurl, http-client
- **Integrations** -- 1password, github, gh-issues, tmux, weather, blucli, openhue, sonoscli
- **AI providers** -- gemini, openai-image-gen, oracle
- **Utilities** -- system-info, file-manager, text-transform, peekaboo, session-logs, model-usage, healthcheck-skill, skill-creator

### Managing skills

```bash
aegis skills list                 # List installed skills
aegis skills search <query>       # Search the registry
aegis skills install <name>       # Install a skill
aegis skills uninstall <name>     # Remove a skill
aegis skills update [name]        # Update all or one skill
aegis skills info <name>          # Show skill details
aegis skills reload [name]        # Reload from disk
aegis skills commands             # List slash commands from skills
```

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
    +---------+---------+---------+
    |         |         |         |
  Policy   Sandbox   Observer   Skills
  (Cedar)  (Seatbelt) (FSEvents) (64 tools)
    |         |         |         |
    v         v         v         v
         Audit Ledger
    (SQLite, SHA-256 hash-chained)
              |
    +---------+---------+---------+
    |    |    |    |    |    |    |
  SIEM  TUI  API  Alerts  Telegram  Voice  Browser
```

Layers:
1. **Chat TUI** -- Streaming LLM conversations with tool execution
2. **Tool System** -- Extensible tool registry with MCP server support and 64 bundled skills
3. **Policy Engine** -- Cedar 4.x policies (default-deny)
4. **Sandbox** -- macOS Seatbelt kernel-level enforcement, Docker isolation, or process-level (optional)
5. **Pilot Supervisor** -- PTY-based agent supervision with prompt detection, adapters (ClaudeCode, Codex, Generic), and stall nudging
6. **Fleet Daemon** -- Multi-agent orchestration with crash recovery, orchestrator agents, and launchd integration
7. **Observer** -- FSEvents filesystem monitoring with snapshot diffing
8. **Audit Ledger** -- Append-only, SHA-256 hash-chained SQLite log with session tracking
9. **Channels** -- Bidirectional messaging (Telegram, Slack, Discord, and more)
10. **Toolkit** -- Computer-use automation (CDP browser, screen capture, input injection)
11. **Voice** -- Text-to-speech (OpenAI, ElevenLabs, Edge TTS) and speech-to-text (Whisper, wake word detection)

## Crate Structure

| Crate | Description |
|---|---|
| `aegis-types` | Shared types, errors, config, LLM abstractions, provider definitions |
| `aegis-policy` | Cedar policy engine, schema, builtin templates |
| `aegis-ledger` | Append-only hash-chained audit log, sessions, SIEM export |
| `aegis-sandbox` | Seatbelt backend, Cedar-to-SBPL compiler, Docker backend, process backend |
| `aegis-proxy` | Process audit logging, Seatbelt violation harvesting, API usage tracking |
| `aegis-observer` | FSEvents filesystem observer with snapshot diffing |
| `aegis-pilot` | PTY supervisor: prompt detection, adapters (ClaudeCode/Codex/Generic), stall detection |
| `aegis-control` | Control plane: Unix socket + HTTP servers, command protocol, WebSocket |
| `aegis-alert` | Webhook alert dispatching with rate limiting and cooldown |
| `aegis-channel` | Bidirectional messaging (Telegram, Slack, Discord, and 13+ more channels) |
| `aegis-daemon` | Multi-agent fleet orchestration with crash recovery, memory, scheduling |
| `aegis-monitor` | Real-time ratatui audit TUI dashboard |
| `aegis-tools` | Tool definitions, executor, MCP server integration |
| `aegis-skills` | Skill plugin system with hot-reload |
| `aegis-hooks` | Event-driven hook system for tool call validation |
| `aegis-toolkit` | Computer-use toolkit (CDP browser, screen capture, input injection) |
| `aegis-browser` | Browser driver (Chrome DevTools Protocol) |
| `aegis-canvas` | Canvas rendering and visual output |
| `aegis-tts` | Text-to-speech (OpenAI, ElevenLabs, Edge TTS) |
| `aegis-voice` | Voice input, speech-to-text, wake word detection |
| `aegis-harness` | PTY-based TUI integration test harness |
| `aegis-cli` | Binary entry point: chat TUI, pilot TUI, onboard wizard, init wizard, all CLI commands |

## CLI Reference

<details>
<summary>Full CLI reference (click to expand)</summary>

### Core

| Command | Description |
|---|---|
| `aegis` | Open chat TUI (primary interface) |
| `aegis setup` | Check system requirements |
| `aegis doctor [--fix] [--config NAME]` | Diagnose and fix configuration issues |
| `aegis onboard` | First-run setup wizard |

### Agent Execution

| Command | Description |
|---|---|
| `aegis wrap [--dir PATH] [--policy TPL] [--seatbelt] -- CMD` | Wrap command with observability |
| `aegis pilot [--dir PATH] [--policy TPL] [--adapter NAME] [--listen ADDR] [--api-key KEY] [--stall-timeout SECS] -- CMD` | Supervise agent in PTY with auto-approval |
| `aegis run [--config NAME] [--policy TPL] [--tag TAG] -- CMD` | Run in sandboxed environment |
| `aegis watch [--dir PATH] [--name NAME] [--idle-timeout SECS] [--stop]` | Background filesystem watcher |

### Configuration

| Command | Description |
|---|---|
| `aegis init [NAME] [--policy TPL] [--dir PATH]` | Create config (omit NAME for interactive wizard) |
| `aegis config show [NAME]` | Show full configuration |
| `aegis config path [NAME]` | Print config file path (for scripting) |
| `aegis config edit [NAME]` | Open config in $EDITOR |
| `aegis config get <key>` | Read a config value (dot-notation) |
| `aegis config set <key> <value>` | Write a config value (auto-detected type) |
| `aegis config list` | Show all effective key-value pairs with sources |
| `aegis config layers` | Show config file priority |
| `aegis list` | List all configurations |
| `aegis use [NAME]` | Set or show active configuration |

### Authentication

| Command | Description |
|---|---|
| `aegis auth list` | List configured auth profiles |
| `aegis auth add <provider> [--method M] [--profile P] [--credential-env VAR] [--set-default]` | Add or update an auth profile |
| `aegis auth login <provider> [--method M] [--profile P]` | Run login guidance |
| `aegis auth test [target]` | Test auth readiness |
| `aegis auth logout <provider>` | Remove profile and stored tokens |
| `aegis auth status` | Show all profiles and token status |
| `aegis auth refresh <provider>` | Manually refresh OAuth token |

### Audit

| Command | Description |
|---|---|
| `aegis log [NAME] [--last N]` | Show recent audit entries |
| `aegis monitor [NAME]` | Standalone audit TUI dashboard |
| `aegis diff SESSION1 SESSION2 [--config NAME]` | Compare two sessions |
| `aegis status [NAME]` | Show health status |
| `aegis report [NAME] [--format text\|json]` | Generate compliance report |
| `aegis audit query [--last N] [--from T] [--to T] [--action KIND] [--decision D] [--principal P] [--search TEXT]` | Query audit entries |
| `aegis audit verify [NAME]` | Verify hash chain integrity |
| `aegis audit export [NAME] [--format FMT] [--limit N] [--follow]` | Export (json/jsonl/csv/cef) |
| `aegis audit purge <older_than> [--config NAME] --confirm` | Purge old entries |
| `aegis audit sessions [NAME] [--last N]` | List recent sessions |
| `aegis audit session <id> [--config NAME]` | Show session details |
| `aegis audit tag <id> <tag> [--config NAME]` | Tag a session |
| `aegis audit watch [NAME] [--decision D]` | Tail audit events in real-time |
| `aegis audit policy-history [NAME] [--last N]` | Show policy change history |

### Sessions

| Command | Description |
|---|---|
| `aegis sessions list [--sender S] [--channel C] [--resumable] [--limit N]` | List sessions with filters |
| `aegis sessions show <uuid>` | Session details |
| `aegis sessions chain <group-id>` | Conversation chain |
| `aegis sessions resume <agent> <uuid>` | Resume a session |
| `aegis sessions inspect <uuid>` | Full details with entry counts and child links |
| `aegis sessions reset <uuid>` | Clear context, mark non-resumable |
| `aegis sessions delete <uuid> --confirm` | Delete session and audit entries |
| `aegis sessions fork <uuid>` | Fork a conversation branch |
| `aegis sessions tree <uuid>` | Display session tree |

### Policy

| Command | Description |
|---|---|
| `aegis policy validate <path>` | Validate a .cedar policy file |
| `aegis policy list [NAME]` | List active policies |
| `aegis policy generate <template>` | Print builtin policy template |
| `aegis policy import <path> [--config NAME]` | Import a policy into a config |
| `aegis policy test <action> <resource> [--config NAME]` | Dry-run policy evaluation |

### Fleet and Daemon

| Command | Description |
|---|---|
| `aegis daemon init` | Create default daemon config |
| `aegis daemon run [--launchd]` | Run daemon in foreground |
| `aegis daemon start` | Start daemon in background |
| `aegis daemon stop` | Stop the daemon |
| `aegis daemon restart` | Stop and restart |
| `aegis daemon reload` | Reload config without restart |
| `aegis daemon status` | Show daemon health (uptime, agent count) |
| `aegis daemon agents` | List all agent slots and status |
| `aegis daemon add` | Add a new agent interactively |
| `aegis daemon remove <name>` | Remove an agent |
| `aegis daemon start-agent <name>` | Start a specific agent |
| `aegis daemon stop-agent <name>` | Stop a specific agent |
| `aegis daemon restart-agent <name>` | Restart a specific agent |
| `aegis daemon enable <name>` | Enable an agent slot |
| `aegis daemon disable <name>` | Disable an agent slot |
| `aegis daemon output <name> [--lines N]` | View agent output |
| `aegis daemon follow <name>` | Stream agent output in real time |
| `aegis daemon send <name> <text>` | Send input to agent stdin |
| `aegis daemon approve <name> <id>` | Approve pending prompt |
| `aegis daemon deny <name> <id>` | Deny pending prompt |
| `aegis daemon pending <name>` | List pending prompts |
| `aegis daemon nudge <name> [message]` | Nudge stalled agent |
| `aegis daemon goal [text]` | Get or set fleet-wide goal |
| `aegis daemon context <name> [field] [value]` | Get or set agent context (role, goal, task) |
| `aegis daemon capabilities <name>` | Show agent runtime capabilities |
| `aegis daemon subagent <parent> [--name N] [--role R] [--task T]` | Spawn constrained subagent |
| `aegis daemon config show\|edit\|path` | Daemon config management |
| `aegis daemon install [--start]` | Install launchd plist for auto-start |
| `aegis daemon uninstall` | Remove launchd plist |
| `aegis daemon logs [--follow]` | Show daemon log output |
| `aegis daemon dashboard [--open] [--url-only]` | Open web dashboard UI |
| `aegis daemon orchestrator-status [agents...] [--lines N]` | Bulk fleet status for review |
| `aegis daemon compat-status [--format F]` | Secure-runtime compatibility status |
| `aegis daemon compat-diff [--format F]` | Compatibility delta impact |
| `aegis daemon compat-verify [--format F]` | Verify compatibility controls |
| `aegis daemon tool <name> <action-json>` | Execute a computer-use action |
| `aegis daemon tool-batch <name> <actions-json>` | Execute a batch of computer-use actions |
| `aegis daemon capture-start <name> [--fps N]` | Start screen capture session |
| `aegis daemon capture-stop <name> <session-id>` | Stop screen capture session |
| `aegis daemon latest-frame <name> [--x X --y Y --width W --height H]` | Fetch latest capture frame |
| `aegis daemon browser-profile <name> <session-id> [--headless] [--url U]` | Start managed browser |
| `aegis daemon browser-profile-stop <name> <session-id>` | Stop managed browser |

### Alerts and Notifications

| Command | Description |
|---|---|
| `aegis alerts list [NAME]` | List configured alert rules |
| `aegis alerts test [NAME] [--rule R]` | Test webhook connectivity |
| `aegis alerts history [NAME] [--last N]` | Show alert dispatch history |
| `aegis telegram setup` | Interactive Telegram bot setup |
| `aegis telegram status` | Show Telegram configuration |
| `aegis telegram disable` | Remove Telegram from config |

### Skills

| Command | Description |
|---|---|
| `aegis skills list` | List installed skills |
| `aegis skills search <query>` | Search the registry |
| `aegis skills install <name> [--version V] [--from PATH]` | Install a skill |
| `aegis skills uninstall <name>` | Remove a skill |
| `aegis skills update [name]` | Update all or one skill |
| `aegis skills info <name>` | Show skill details |
| `aegis skills reload [name]` | Reload from disk |
| `aegis skills commands` | List slash commands from skills |

### Hooks (Claude Code integration)

| Command | Description |
|---|---|
| `aegis hook install [--dir PATH]` | Install aegis hook into .claude/settings.json |
| `aegis hook show-settings` | Print settings JSON for manual registration |
| `aegis hook pre-tool-use` | Handle PreToolUse hook (stdin/stdout) |
| `aegis hook post-tool-use` | Handle PostToolUse hook (stdin/stdout) |
| `aegis hook session-end` | Handle Stop hook (lifecycle event) |

### Feature Parity

| Command | Description |
|---|---|
| `aegis parity status [--format text\|json]` | Parity summary by domain |
| `aegis parity diff [--format text\|json]` | Features not yet at parity |
| `aegis parity verify [--format text\|json]` | Verify completion requirements |

### Utilities

| Command | Description |
|---|---|
| `aegis completions <shell>` | Generate shell completions (bash/zsh/fish/elvish/powershell) |
| `aegis manpage` | Generate man page |

</details>

## Docker

Aegis includes a multi-stage Dockerfile and docker-compose configuration:

```bash
docker compose up -d
```

The container mounts `~/.aegis` for persistent state, runs as a non-root user, and exposes ports 8080 (HTTP control) and 9090 (dashboard gateway). Environment variables (`AEGIS_*`) override config values.

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
