# Aegis Configuration Reference

Aegis uses two main configuration files:

- **`aegis.toml`** -- per-agent configuration stored at `~/.aegis/<name>/aegis.toml`
- **`daemon.toml`** -- fleet-wide daemon configuration stored at `~/.aegis/daemon/daemon.toml`

## aegis.toml (Per-Agent Configuration)

Created by `aegis init <name>`. Controls sandbox paths, policies, isolation, observer, and alerts for a single agent.

### Full Example

```toml
name = "my-agent"
sandbox_dir = "/home/user/my-project"
policy_paths = ["/home/user/.aegis/my-agent/policies"]
ledger_path = "/home/user/.aegis/my-agent/audit.db"

[[allowed_network]]
host = "api.openai.com"
port = 443
protocol = "Https"

[[allowed_network]]
host = "api.anthropic.com"
port = 443
protocol = "Https"

[isolation]
type = "Seatbelt"

[observer]
type = "FsEvents"
enable_snapshots = true

[pilot]
output_buffer_lines = 200
uncertain_action = "Deny"

[pilot.adapter]
type = "ClaudeCode"

[pilot.stall]
timeout_secs = 120
max_nudges = 5
nudge_message = "continue"

[[alerts]]
name = "deny-alert"
webhook_url = "https://hooks.slack.com/services/T/B/xxx"
decision = "Deny"
cooldown_secs = 30

[[alerts]]
name = "sensitive-write"
webhook_url = "https://events.pagerduty.com/v2/enqueue"
action_kinds = ["FileWrite", "FileDelete"]
path_glob = "**/.env*"
cooldown_secs = 60
```

### Field Reference

#### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Agent name (also the Cedar principal). Alphanumeric, hyphens, underscores, dots. |
| `sandbox_dir` | Path | Yes | Directory the sandboxed process operates within. |
| `policy_paths` | \[Path\] | Yes | Directories containing `.cedar` policy files. |
| `schema_path` | Path | No | Path to a Cedar schema file for policy validation. |
| `ledger_path` | Path | Yes | Path to the SQLite audit ledger database. |
| `allowed_network` | \[NetworkRule\] | No | Network access rules. Empty means no network access. |
| `isolation` | IsolationConfig | Yes | OS-level isolation backend. |
| `observer` | ObserverConfig | No | Filesystem monitoring mode. Default: FsEvents with snapshots. |
| `alerts` | \[AlertRule\] | No | Webhook alert rules evaluated against audit events. |
| `pilot` | PilotConfig | No | PTY supervisor settings. |
| `channel` | ChannelConfig | No | Messaging channel (Telegram, Slack, etc.). |
| `usage_proxy` | UsageProxyConfig | No | API usage tracking proxy settings. |

#### NetworkRule

```toml
[[allowed_network]]
host = "api.openai.com"    # Hostname or IP address
port = 443                  # Port number (omit for any port)
protocol = "Https"          # "Tcp", "Udp", "Http", or "Https"
```

#### IsolationConfig

Seatbelt (macOS default):
```toml
[isolation]
type = "Seatbelt"
# Optional: path to a hand-written SBPL override file
# profile_overrides = "/path/to/custom.sb"
```

Docker:
```toml
[isolation]
type = "Docker"

[isolation.Docker]
image = "ubuntu:22.04"         # Container image
network = "none"                # "none", "bridge", or custom network
memory = "512m"                 # Memory limit
cpus = 1.0                      # CPU limit
pids_limit = 256                # PID limit (fork bomb protection)
tmpfs_size = "100m"             # /tmp tmpfs size
workspace_writable = false      # Whether workspace mount is read-write
extra_mounts = []               # Additional read-only bind mounts
timeout_secs = 300              # Container execution timeout (0 = none)
```

Process (no OS-level sandbox):
```toml
[isolation]
type = "Process"
```

None (completely unsandboxed):
```toml
[isolation]
type = "None"
```

#### ObserverConfig

```toml
# FSEvents-based observation (default)
[observer]
type = "FsEvents"
enable_snapshots = true    # Pre/post snapshot diffing

# Endpoint Security (requires root + Full Disk Access)
[observer]
type = "EndpointSecurity"

# No observation
[observer]
type = "None"
```

#### PilotConfig

```toml
[pilot]
output_buffer_lines = 200     # Rolling output buffer size
uncertain_action = "Deny"     # "Deny", "Allow", or "Alert"

[pilot.adapter]
type = "ClaudeCode"           # "ClaudeCode", "Codex", "Passthrough", "Auto"

# Or use a generic adapter with custom regex patterns:
# [pilot.adapter]
# type = "Generic"
# [[pilot.adapter.patterns]]
# regex = "Allow tool call: (?P<tool>\\w+)\\((?P<args>.*)\\)"
# approve = "y"
# deny = "n"

[pilot.stall]
timeout_secs = 120            # Seconds of silence before nudging
max_nudges = 5                # Max nudges before alerting
nudge_message = "continue"    # Text sent to agent PTY

[pilot.control]
http_listen = ""              # HTTP listen address (empty = disabled)
api_key = ""                  # API key for HTTP auth
poll_endpoint = ""            # URL to poll for commands
poll_interval_secs = 5        # Polling interval
```

#### AlertRule

```toml
[[alerts]]
name = "deny-alert"                        # Unique rule name
webhook_url = "https://hooks.slack.com/..." # POST target
decision = "Deny"                           # Filter: "Allow" or "Deny" (optional)
action_kinds = ["FileWrite", "FileDelete"]  # Filter: action types (optional, empty = all)
path_glob = "**/.env*"                      # Filter: glob on file path (optional)
principal = "my-agent"                      # Filter: exact agent name (optional)
cooldown_secs = 60                          # Minimum seconds between fires (default: 60)
```

#### UsageProxyConfig

```toml
[usage_proxy]
enabled = true    # Whether usage tracking is enabled
port = 0          # Proxy port (0 = OS-assigned random port)
```

## daemon.toml (Fleet Configuration)

Created by `aegis daemon init`. Controls the fleet of supervised agents, daemon behavior, and global settings.

Location: `~/.aegis/daemon/daemon.toml`

### Full Example

```toml
goal = "Build and ship the v2.0 release"

[persistence]
launchd = false        # Register as macOS LaunchAgent
prevent_sleep = false  # Run caffeinate while agents are active

[control]
socket_path = "/home/user/.aegis/daemon/daemon.sock"
http_listen = ""       # HTTP listen address (empty = disabled)
api_key = ""           # API key for HTTP auth

[dashboard]
enabled = true
listen = "127.0.0.1:9845"

[[agents]]
name = "claude-1"
working_dir = "/home/user/my-project"
role = "Backend engineer"
task = "Implement the REST API endpoints"
restart = "on_failure"
max_restarts = 5
enabled = true

[agents.tool]
type = "claude_code"
skip_permissions = false
one_shot = false

[[agents]]
name = "codex-1"
working_dir = "/home/user/my-project"
role = "Test writer"
task = "Write unit tests for all new code"

[agents.tool]
type = "codex"
approval_mode = "suggest"

[channel]
type = "telegram"
bot_token = "123456:ABC-DEF..."
chat_id = 987654321
poll_timeout_secs = 30
```

### Field Reference

#### Top-Level Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `goal` | String | None | Fleet-wide mission shared by all agents. |
| `persistence` | PersistenceConfig | -- | OS integration settings. |
| `control` | DaemonControlConfig | -- | Unix socket and HTTP server settings. |
| `dashboard` | DashboardConfig | -- | Local dashboard server settings. |
| `alerts` | \[AlertRule\] | \[\] | Global alert rules applied to all agents. |
| `agents` | \[AgentSlotConfig\] | \[\] | Fleet agent definitions. |
| `channel` | ChannelConfig | None | Messaging channel for remote notifications. |
| `channel_routing` | ChannelRoutingConfig | None | Per-channel command routing. |
| `toolkit` | ToolkitConfig | -- | Computer-use runtime settings. |
| `memory` | MemoryConfig | -- | Agent memory store settings. |
| `session_files` | SessionFilesConfig | -- | Session-scoped file storage. |
| `cron` | CronConfig | -- | Scheduled job configuration. |
| `plugins` | PluginConfig | -- | Plugin system settings. |
| `aliases` | Map | {} | TUI command bar aliases. |
| `lanes` | \[LaneConfig\] | \[\] | Execution lanes with concurrency limits. |

#### AgentSlotConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | String | Required | Unique agent name. |
| `tool` | AgentToolConfig | Required | Which AI tool to run. |
| `working_dir` | Path | Required | Working directory for the agent. |
| `role` | String | None | Short description of the agent's role. |
| `agent_goal` | String | None | Strategic goal for this agent. |
| `context` | String | None | Additional context or constraints. |
| `task` | String | None | Initial task/prompt injected after spawn. |
| `pilot` | PilotConfig | None | Override pilot settings for this agent. |
| `restart` | RestartPolicy | `on_failure` | When to restart: `never`, `on_failure`, `always`. |
| `max_restarts` | u32 | 5 | Max restarts before giving up (0 = unlimited). |
| `enabled` | bool | true | Whether this slot is active. |
| `orchestrator` | OrchestratorConfig | None | Configure this agent as a fleet orchestrator. |
| `security_preset` | SecurityPresetKind | None | Security level: `observe_only`, `read_only`, `full_lockdown`, `custom`. |
| `policy_dir` | Path | None | Per-agent Cedar policy directory. |
| `isolation` | IsolationConfig | None | Per-agent isolation override. |
| `lane` | String | None | Execution lane name. |

#### AgentToolConfig

Claude Code:
```toml
[agents.tool]
type = "claude_code"
skip_permissions = false    # Use --dangerously-skip-permissions
one_shot = false            # Use -p "prompt" for single-run mode
extra_args = []             # Additional CLI arguments
```

Codex:
```toml
[agents.tool]
type = "codex"
approval_mode = "suggest"   # "suggest", "auto-edit", or "full-auto"
one_shot = false
extra_args = []
```

OpenClaw:
```toml
[agents.tool]
type = "open_claw"
agent_name = "builder"      # Named agent to run (optional)
extra_args = []
```

Custom command:
```toml
[agents.tool]
type = "custom"
command = "my-agent"
args = ["--mode", "auto"]
env = [["API_KEY", "secret"]]

[agents.tool.adapter]
type = "Generic"
[[agents.tool.adapter.patterns]]
regex = "Allow (?P<tool>\\w+)?"
approve = "y"
deny = "n"
```

#### RestartPolicy

| Value | Description |
|-------|-------------|
| `never` | Do not restart after exit. |
| `on_failure` | Restart only on non-zero exit code (default). |
| `always` | Restart regardless of exit code. |

#### PersistenceConfig

```toml
[persistence]
launchd = false        # Register as macOS LaunchAgent for auto-start
prevent_sleep = false  # Run caffeinate to prevent system sleep
```

#### DaemonControlConfig

```toml
[control]
socket_path = "~/.aegis/daemon/daemon.sock"  # Unix socket path
http_listen = ""                              # HTTP listen address (empty = disabled)
api_key = ""                                  # API key for HTTP auth
```

#### DashboardConfig

```toml
[dashboard]
enabled = true
listen = "127.0.0.1:9845"   # Local-only dashboard
api_key = ""                  # Static API token (empty = random per boot)
rate_limit_burst = 20         # Token bucket capacity
rate_limit_per_sec = 5.0      # Sustained request rate
```

#### ChannelConfig (Telegram)

```toml
[channel]
type = "telegram"
bot_token = "123456:ABC-DEF..."    # From @BotFather
chat_id = 987654321                 # Target chat ID
poll_timeout_secs = 30              # Long-poll timeout
allow_group_commands = false        # Accept commands from groups
webhook_mode = false                # Use webhooks instead of polling
```

#### MemoryConfig

```toml
[memory]
enabled = false
db_path = "~/.aegis/daemon/memory.db"
decay_enabled = false
default_half_life_hours = 168.0    # 1 week

[memory.auto_recall]
enabled = false
max_tokens = 1024
relevance_threshold = 0.65

[memory.auto_capture]
enabled = false
categories = ["preference", "decision", "fact", "entity", "instruction"]
confidence_threshold = 0.7
max_per_turn = 5
```

#### LaneConfig

```toml
[[lanes]]
name = "fast-lane"
max_concurrent = 2    # Max concurrent agents (0 = unlimited)
priority = 10         # Higher = more important
```

#### CronConfig

```toml
[cron]
enabled = false

[[cron.jobs]]
name = "nightly-report"
schedule = "daily 02:00"
enabled = true
command = { "type": "FleetGoal", "goal": "Generate nightly report" }
```

#### OrchestratorConfig

```toml
[[agents]]
name = "orchestrator"
working_dir = "/home/user/project"

[agents.tool]
type = "claude_code"

[agents.orchestrator]
review_interval_secs = 300
backlog_path = "/home/user/project/BACKLOG.md"
managed_agents = ["claude-1", "codex-1"]
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AEGIS_TELEGRAM_BOT_TOKEN` | Telegram bot token (alternative to config file). |
| `AEGIS_AGENT_NAME` | Agent name for hook commands. Set by the daemon when spawning agents. |
| `AEGIS_SOCKET_PATH` | Unix socket path for hook commands to reach the daemon. |
| `AEGIS_HOOK_FAIL_OPEN` | Set to `"1"` to allow hooks to pass when the daemon is unreachable. |
| `AEGIS_BROWSER_BIN` | Override the browser binary path for computer-use toolkit. |
| `AEGIS_CDP_WS` | WebSocket URL for Chrome DevTools Protocol connections. |
| `AEGIS_SEARCH_API_KEY` | API key for web search tool integration. |
| `AEGIS_PARITY_DIR` | Directory for parity check data. |
| `AEGIS_INSTALL_DIR` | Install directory for the install script (default: `/usr/local/bin`). |
| `AEGIS_VERSION` | Version to install via the install script. |
| `AEGIS_MACOS_HELPER` | Override path to the macOS helper binary for toolkit. |

## Cedar Policy File Format

Cedar policy files use the `.cedar` extension and contain one or more `permit` or `forbid` statements. Files are loaded from all directories listed in `policy_paths`.

### Minimal Policy (Deny All)

```cedar
forbid(principal, action, resource);
```

### Read-Only Access

```cedar
permit(principal, action == Aegis::Action::"FileRead", resource);
permit(principal, action == Aegis::Action::"DirList", resource);
```

### Full Access for a Specific Agent

```cedar
permit(
    principal == Aegis::Agent::"trusted-agent",
    action,
    resource
);
```

### Deny Writes to Sensitive Paths

```cedar
forbid(
    principal,
    action == Aegis::Action::"FileWrite",
    resource
)
when { resource.path like "*/.env*" };

forbid(
    principal,
    action == Aegis::Action::"FileWrite",
    resource
)
when { resource.path like "*/credentials*" };
```

### Allow Network to Specific Hosts

```cedar
permit(
    principal,
    action == Aegis::Action::"NetConnect",
    resource
)
when {
    resource.path == "api.openai.com" ||
    resource.path == "api.anthropic.com"
};
```

Note: For `NetConnect` actions, the `resource.path` attribute contains the hostname, not a file path.

## Per-Agent Configuration via Daemon

Each agent in `daemon.toml` can override settings that would normally come from `aegis.toml`:

```toml
[[agents]]
name = "restricted-agent"
working_dir = "/home/user/project"
security_preset = "read_only"           # Uses allow-read-only policy
policy_dir = "/home/user/.aegis/restricted-agent/policies"  # Custom policies
isolation = { type = "Seatbelt" }       # Override isolation

[agents.tool]
type = "claude_code"

[agents.pilot]
uncertain_action = "Deny"

[agents.pilot.stall]
timeout_secs = 60
max_nudges = 3
```

When both `daemon.toml` and `aegis.toml` specify settings for the same agent, the daemon configuration takes precedence.
