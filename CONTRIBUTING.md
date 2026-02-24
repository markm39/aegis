# Contributing to Aegis

## Getting Started

```bash
git clone https://github.com/markm39/aegis.git
cd aegis
cargo build
cargo test --workspace
```

### Prerequisites

- macOS 12+ or Linux
- Rust 1.75+ (install via [rustup](https://rustup.rs))

## Development Workflow

### Build and test

```bash
# Full workspace build
cargo build

# Lint (zero warnings policy)
cargo clippy --workspace -- -D warnings

# Test
cargo test --workspace

# Both (what CI runs)
make check
```

### Working on a single crate

```bash
cargo clippy -p aegis-ledger -- -D warnings
cargo test -p aegis-ledger
```

### Before committing

Always run these against the full workspace:

```bash
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Architecture

See the [Crate Structure](README.md#crate-structure) section in the README for an overview of all crates and their relationships.

### Crate dependency flow

```
aegis-types (foundation: config, errors, shared types)
  -> aegis-policy (Cedar policy engine)
  -> aegis-ledger (audit store, sessions, SIEM export)
  -> aegis-sandbox (Seatbelt/process sandbox)
  -> aegis-observer (FSEvents filesystem monitoring)
  -> aegis-proxy (action logging, policy evaluation bridge)
  -> aegis-pilot (PTY supervision, prompt detection, stall detection)
  -> aegis-control (command protocol, Unix socket + HTTP servers)
  -> aegis-alert (webhook alert dispatching)
  -> aegis-channel (bidirectional Telegram messaging)
  -> aegis-tools (tool definitions, executor, MCP)
  -> aegis-skills (skill plugin system)
  -> aegis-hooks (event-driven hooks)
  -> aegis-daemon (fleet orchestration, agent lifecycle)
  -> aegis-monitor (audit TUI dashboard)
  -> aegis-cli (binary: chat TUI, fleet TUI, all commands, wizard)
```

## Code Conventions

- Follow Rust idioms: iterators over indexing, `Result`/`Option` over panicking.
- Use `anyhow::Context` for error context in CLI commands.
- Keep functions small and focused.
- Zero warnings policy: `cargo clippy --workspace -- -D warnings` must pass.

### Shared structs

If you add a field to a shared struct (e.g., `AegisConfig`, `AlertEvent`, `AuditEntry`), you **must** update all construction sites across the entire workspace. Use `cargo clippy --workspace -- -D warnings` to find them all.

Common shared structs and where they're constructed:
- **`AegisConfig`**: `aegis-cli/src/commands/run.rs`, `aegis-cli/src/commands/wrap.rs`, `aegis-cli/src/commands/config.rs` (tests), `aegis-types/src/config.rs` (tests), `aegis-cli/src/wizard/app.rs`
- **`AlertEvent`**: `aegis-ledger/src/store.rs`
- **`AegisError`**: `aegis-types/src/error.rs` (variant enum -- update match arms)

### Adding new crates

1. Add the crate to `Cargo.toml` workspace members list
2. Run `cargo build --workspace` to verify the full workspace compiles
3. Run `cargo test --workspace` to verify no regressions

### UX rules

- **CLI**: Positional arguments for required inputs. Flags only for optional/modifier behavior. Sensible defaults everywhere.
- **TUI**: Full cursor support on all text inputs. Consistent back-navigation (Esc). Tab for next field.
- **Errors**: Include what went wrong AND what the user should do about it.

### TUI command bar

When adding a new CLI subcommand, you **must** also add a corresponding TUI command bar entry in `fleet_tui/command.rs`. The TUI is the primary interface.

## Multi-Agent Development

Multiple agents may work on this codebase concurrently. Follow these rules:

- Check which branch you're on before committing: `git branch --show-current`
- Don't switch branches without stashing or committing first
- If you find uncommitted changes from another agent, don't discard them
- If another agent's code causes compilation failures, fix the immediate issue rather than reverting

## CI

CI runs on every push to `main` and on all pull requests. The pipeline includes:

- **Format** -- `cargo fmt --all -- --check`
- **Clippy** -- `cargo clippy --workspace --all-targets` on macOS and Ubuntu
- **Test** -- `cargo test --workspace` on macOS and Ubuntu
- **Build** -- Release build of `aegis-cli` binary
- **Docs** -- `cargo doc --workspace --no-deps` with warnings as errors
- **MSRV** -- Verify minimum supported Rust version (1.75) compiles
- **Security audit** -- `cargo audit` for known vulnerabilities
- **Dependency checks** -- `cargo deny` for license compliance, advisory checks, banned crates
- **Unused dependencies** -- `cargo udeps` (advisory, non-blocking)

## License

By contributing, you agree that your contributions will be dual-licensed under MIT OR Apache-2.0, consistent with the project license.
