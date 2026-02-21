# Getting Started with Aegis

Aegis is a security-first agent supervision platform. It wraps AI agent processes in sandboxes, evaluates every action against Cedar policies, and records all activity in a tamper-evident audit ledger.

## Prerequisites

- **Rust toolchain** (1.75 or later): Install via [rustup](https://rustup.rs/)
- **macOS** (primary target) or **Linux**
- **SQLite** (usually pre-installed on macOS and most Linux distributions)
- An AI agent to supervise (e.g., Claude Code, Codex, or any CLI tool)

## Installation

### From Source

Clone the repository and build:

```bash
git clone https://github.com/markm39/aegis.git
cd aegis
cargo build --release
```

The binary will be at `target/release/aegis`. Copy it to a directory on your PATH:

```bash
cp target/release/aegis /usr/local/bin/
```

### Using the Install Script

```bash
curl -fsSL https://raw.githubusercontent.com/markm39/aegis/main/install.sh | bash
```

The install script supports these environment variables:

- `AEGIS_INSTALL_DIR` -- where to place the binary (default: `/usr/local/bin`)
- `AEGIS_VERSION` -- specific version to install (default: latest release)

### From Cargo

```bash
cargo install --path crates/aegis-cli
```

## Quick Start

### 1. Initialize a Configuration

Create a named configuration with an interactive wizard:

```bash
aegis init
```

The wizard walks you through selecting a policy template, choosing an isolation backend, and pointing the sandbox at your project directory.

For non-interactive setup:

```bash
aegis init my-agent --policy allow-read-only --dir /path/to/project
```

Available policy templates:

| Template | Description |
|----------|-------------|
| `permit-all` | Logs everything, enforces nothing. Good for initial observation. |
| `allow-read-only` | Permits file reads and directory listings. Blocks writes and network. |
| `allow-read-write` | Permits file I/O and process lifecycle. Blocks network and tool calls. |
| `ci-runner` | Same as allow-read-write. Tuned for CI pipelines. |
| `data-science` | Permits file I/O, network, and process lifecycle. Blocks tool calls. |
| `default-deny` | Blocks everything. Start here for maximum security. |

This creates a directory at `~/.aegis/my-agent/` containing:

```
~/.aegis/my-agent/
  aegis.toml           # Agent configuration
  policies/
    default.cedar      # Cedar policy file
  sandbox/             # Sandboxed working directory (or symlink to --dir)
```

### 2. Set Up the Daemon

Initialize the daemon configuration:

```bash
aegis daemon init
```

This creates `~/.aegis/daemon/daemon.toml` with a minimal fleet configuration. Add your first agent:

```bash
aegis daemon init
```

Or edit `~/.aegis/daemon/daemon.toml` directly:

```toml
[[agents]]
name = "claude-1"
working_dir = "/path/to/your/project"

[agents.tool]
type = "claude_code"
```

Start the daemon:

```bash
aegis daemon start
```

The daemon manages agent lifecycles, restarts crashed processes, and exposes a Unix socket for control.

### 3. Launch the Hub TUI

```bash
aegis
```

Running `aegis` with no arguments opens the fleet hub -- a unified terminal UI for managing all your agents. From here you can:

- See agent statuses, pending permission prompts, and output
- Approve or deny actions with single keystrokes
- Type `:` for a command bar with tab completion
- Use `:add` to configure new agents
- Use `:follow <agent>` to stream agent output
- Use `:pop <agent>` to open agent output in a separate terminal window

### 4. Observe a Command (Without the Daemon)

If you want to observe a single command without setting up the daemon:

```bash
aegis wrap my-agent -- claude
```

This runs the command inside the configured sandbox, evaluating every action against the Cedar policies and logging all activity to the audit ledger.

### 5. Supervised Agent Execution

For interactive agent supervision with PTY prompt detection:

```bash
aegis pilot my-agent -- claude
```

The pilot detects when the agent requests permission (e.g., to write a file), evaluates the action against policy, and automatically approves or denies based on the loaded Cedar rules.

## First Agent Setup

Here is a complete example of setting up Aegis to supervise Claude Code on a project:

```bash
# 1. Create a configuration for your project
aegis init my-project --policy allow-read-write --dir ~/code/my-project

# 2. Edit the daemon config to add the agent
cat >> ~/.aegis/daemon/daemon.toml << 'EOF'

[[agents]]
name = "claude-1"
working_dir = "/Users/you/code/my-project"
task = "Review the codebase and fix any bugs"

[agents.tool]
type = "claude_code"
EOF

# 3. Start the daemon
aegis daemon start

# 4. Open the hub
aegis
```

From the hub TUI, you will see `claude-1` listed with its status. Press Enter to view its output, or `i` to send it input.

## Viewing the Audit Trail

After running agents, inspect what happened:

```bash
# View recent audit entries
aegis log my-agent

# Live monitoring dashboard
aegis monitor my-agent

# Compliance report
aegis report my-agent

# Compare two sessions
aegis diff SESSION_UUID_1 SESSION_UUID_2
```

## Setting Up Remote Notifications

Aegis can notify you via Telegram when agents need approval:

```bash
aegis telegram setup
```

This walks you through connecting a Telegram bot. Once configured, you receive real-time notifications with inline Approve/Deny buttons, and can issue commands like `/status`, `/approve`, and `/stop` from your phone.

## Directory Layout

```
~/.aegis/
  daemon/
    daemon.toml        # Fleet configuration
    daemon.sock        # Unix socket for control
    daemon.pid         # PID file
    state.json         # Persisted fleet state
  my-agent/
    aegis.toml         # Agent-level configuration
    policies/
      default.cedar    # Cedar policy files
    audit.db           # SQLite audit ledger
    sandbox/           # Sandboxed working directory
  wraps/
    <name>/            # Auto-generated configs from `aegis wrap`
```

## Next Steps

- Read [Configuration Reference](configuration.md) for daemon.toml and aegis.toml options
- Read [Security Model](security.md) for Cedar policy authoring and threat model
- Read [Architecture](architecture.md) for crate-level design details
