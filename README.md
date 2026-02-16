# Aegis -- Zero-Trust Runtime for AI Agents

Aegis wraps AI agents in sandboxed, policy-enforced, audited environments. Default-deny stance. Written in Rust. Single binary. Zero external dependencies on macOS.

Every action -- file access, network connection, tool invocation -- is governed by Cedar policies compiled into kernel-level Seatbelt profiles, with all decisions logged to a tamper-evident audit ledger.

## Why

AI agents are powerful but uncontrolled. They read files they shouldn't, make network calls without oversight, and leave no audit trail. 73% of organizations cannot deploy agents at scale because of trust and governance gaps. Aegis fixes this.

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
        v
Audit Ledger (SQLite, SHA-256 hash-chained)
```

Four layers:
1. **Policy Engine** -- Cedar 4.x policies define what agents can do (default-deny)
2. **Cedar-to-SBPL Compiler** -- Translates Cedar policies into macOS Seatbelt profiles at launch time
3. **Isolation Boundary** -- macOS Seatbelt (`sandbox-exec`) enforces permissions at the kernel level
4. **Audit Ledger** -- Append-only, SHA-256 hash-chained SQLite log for tamper detection

## Install

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

The binary is at `./target/release/aegis`.

## Quickstart

```bash
# Verify system requirements
aegis setup

# Initialize a sandbox with default-deny policy
aegis init --name my-agent --policy default-deny

# Write a read-only policy (allows FileRead + DirList)
aegis policy generate --template allow-read-only > ~/.aegis/my-agent/policies/default.cedar

# Run a command inside the sandbox
aegis run --config my-agent -- cat ~/.aegis/my-agent/sandbox/hello.txt

# Query the audit log
aegis audit query --config my-agent --last 10

# Verify audit log integrity (hash chain)
aegis audit verify --config my-agent

# Launch the live TUI dashboard
aegis monitor --config my-agent

# Check health
aegis status --config my-agent
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `aegis setup` | Check system requirements and prepare environment |
| `aegis init --name NAME [--policy TEMPLATE]` | Create sandbox at `~/.aegis/NAME/` |
| `aegis run --config NAME -- CMD [ARGS]` | Run command in sandboxed environment |
| `aegis monitor --config NAME` | Launch terminal dashboard |
| `aegis policy validate --path FILE` | Validate a Cedar policy file |
| `aegis policy list --config NAME` | List active policies |
| `aegis policy generate --template NAME` | Print built-in policy template |
| `aegis audit query --config NAME --last N` | Query recent audit entries |
| `aegis audit verify --config NAME` | Verify hash chain integrity |
| `aegis audit export --config NAME --format FMT` | Export audit log (json/csv) |
| `aegis status --config NAME` | Show sandbox health summary |

## Writing Cedar Policies

Aegis uses [Cedar](https://www.cedarpolicy.com/) for authorization. Policies are `.cedar` files in `~/.aegis/NAME/policies/`.

```cedar
// Allow an agent to read files and list directories
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

Available actions: `FileRead`, `FileWrite`, `FileDelete`, `DirCreate`, `DirList`, `NetConnect`, `ToolCall`, `ProcessSpawn`, `ProcessExit`.

## Crate Structure

```
aegis-types     Shared types, errors, config (foundation)
aegis-policy    Cedar policy engine + policy inspection
aegis-ledger    Append-only hash-chained audit log
aegis-sandbox   Seatbelt backend + Cedar-to-SBPL compiler
aegis-proxy     Process audit logging + Seatbelt violation harvesting
aegis-monitor   ratatui terminal dashboard
aegis-cli       Binary entry point
```

## Testing

```bash
# Run all tests
cargo test --workspace

# Run with lint checks
cargo clippy --workspace -- -D warnings
```

## License

MIT OR Apache-2.0
