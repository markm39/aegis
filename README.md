# Aegis -- Zero-Trust Runtime for AI Agents

Zero-trust runtime for AI agents with per-file observability and enterprise governance. Default-deny stance. Written in Rust. Single binary. Zero external dependencies on macOS.

Every file access is observed via FSEvents, governed by Cedar policies, and logged to a tamper-evident audit ledger with SHA-256 hash chains. Optionally enforced at the kernel level via Seatbelt profiles.

## Why Aegis

AI agent sandboxes (Claude Code, OpenClaw, etc.) enforce permissions but provide no visibility into what the agent actually did. You know it was sandboxed, but not what files it read, wrote, or deleted.

Aegis adds the missing layer:

| Capability | Built-in Sandbox | Aegis |
|---|---|---|
| File access enforcement | Yes | Yes (Seatbelt) |
| Per-file audit trail | No | Yes (FSEvents observer) |
| Tamper-evident hash chain | No | Yes (SHA-256) |
| Session tracking | No | Yes (per-invocation sessions) |
| SIEM export | No | Yes (JSON, JSONL, CSV, CEF) |
| Cedar policy language | No | Yes |
| Compliance reporting | No | Yes |
| Real-time TUI dashboard | No | Yes |

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
aegis audit query claude --last 20
aegis report claude
aegis status claude
```

Three commands. Full audit trail.

## Wrapping Agent Tools

`aegis wrap` is the fastest way to add observability to any agent:

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

## Architecture

```
Cedar Policies (.cedar files)
        |
        v
Cedar-to-SBPL Compiler -----> Seatbelt Profile (kernel-level)
        |
        v
aegis run --config NAME -- CMD
        |
        +---> sandbox-exec (macOS kernel sandbox)
        |         |
        |         +--> Process spawn/exit audit logging
        |         +--> Seatbelt violation harvesting (log show)
        |
        +---> FSEvents observer (per-file monitoring)
        |         |
        |         +--> Real-time file event logging
        |         +--> Pre/post snapshot diffing (catches reads)
        |
        v
Audit Ledger (SQLite, SHA-256 hash-chained)
        |
        +--> Session tracking (per-invocation grouping)
        +--> Policy snapshots (change history)
        +--> SIEM export (JSON, JSONL, CSV, CEF)
        +--> Compliance reporting
        +--> TUI dashboard (ratatui)
```

Five layers:
1. **Policy Engine** -- Cedar 4.x policies define what agents can do (default-deny)
2. **Cedar-to-SBPL Compiler** -- Translates Cedar policies into macOS Seatbelt profiles at launch
3. **Isolation Boundary** -- macOS Seatbelt (`sandbox-exec`) enforces at the kernel level
4. **Observer** -- FSEvents filesystem monitoring with snapshot diffing for complete coverage
5. **Audit Ledger** -- Append-only, SHA-256 hash-chained SQLite log with session tracking

## CLI Reference

| Command | Description |
|---|---|
| `aegis setup` | Check system requirements, prepare environment |
| `aegis init [NAME] [--policy TPL] [--dir PATH]` | Create config (omit NAME for wizard) |
| `aegis run [--config NAME] [--policy TPL] -- CMD [ARGS]` | Run command in sandboxed environment |
| `aegis wrap [--dir PATH] [--policy TPL] [--name NAME] -- CMD [ARGS]` | Wrap command with observability |
| `aegis monitor NAME` | Launch real-time TUI dashboard |
| `aegis policy validate --path FILE` | Validate a Cedar policy file |
| `aegis policy list NAME` | List active policies |
| `aegis policy generate --template NAME` | Print built-in policy template |
| `aegis audit query NAME [--last N] [--action KIND] [--decision D]` | Query audit entries |
| `aegis audit verify NAME` | Verify hash chain integrity |
| `aegis audit sessions NAME` | List recent sessions |
| `aegis audit session NAME --id UUID` | Show session details |
| `aegis audit policy-history NAME` | Show policy change history |
| `aegis audit export NAME --format FMT [--follow]` | Export (json/jsonl/csv/cef) |
| `aegis report NAME [--format text\|json]` | Generate compliance report |
| `aegis status NAME` | Show health status |

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
| `aegis-monitor` | Real-time ratatui TUI dashboard |
| `aegis-cli` | Binary entry point, all CLI commands |

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
