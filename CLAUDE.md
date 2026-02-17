# Aegis Project Guidelines

## Build & Test

- Build: `cargo build` (workspace root)
- Clippy: `cargo clippy -p <crate> -- -D warnings`
- Test single crate: `cargo test -p <crate>`
- Test all: `cargo test --workspace`
- The workspace has many crates under `crates/`. Always run clippy and tests for affected crates after changes.

## Architecture

- `aegis-types`: Shared types and config (`AegisConfig`, `IsolationConfig`, `ObserverConfig`, etc.)
- `aegis-policy`: Cedar policy engine
- `aegis-ledger`: SQLite audit store (`AuditStore`)
- `aegis-sandbox`: Seatbelt/process sandbox backends
- `aegis-observer`: Filesystem observation (FSEvents)
- `aegis-proxy`: Action logging and policy evaluation bridge
- `aegis-alert`: Webhook alerting on audit events
- `aegis-monitor`: TUI dashboard (ratatui)
- `aegis-sidecar`: PTY-based agent wrapping with prompt detection
- `aegis-cli`: Main CLI binary with all commands

## Multi-Agent Integration Rules

Multiple agents work on this codebase concurrently. Follow these rules to avoid breaking each other.

### When Adding Fields to Shared Structs

If you add a field to a shared struct (e.g., `AegisConfig`, `AlertEvent`, `AuditEntry`), you MUST update ALL construction sites across the entire workspace -- not just the crate you're working in. Use `cargo clippy --workspace -- -D warnings` to find them all.

Common shared structs and where they're constructed:
- **`AegisConfig`**: `aegis-cli/src/commands/run.rs`, `aegis-cli/src/commands/wrap.rs`, `aegis-cli/src/commands/config.rs` (tests), `aegis-cli/src/commands/list.rs` (tests), `aegis-types/src/config.rs` (tests), `aegis-cli/src/wizard/app.rs`
- **`AlertEvent`**: `aegis-ledger/src/store.rs`
- **`AegisError`**: `aegis-types/src/error.rs` (variant enum -- update match arms)

### When Adding New Crates

1. Add the crate to `Cargo.toml` workspace members list
2. Run `cargo build --workspace` to verify the full workspace compiles
3. Run `cargo test --workspace` to verify no regressions

### Before Committing

Always run these checks against the full workspace, not just your crate:
```
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

If another agent's code causes compilation failures in your build, fix the immediate issue (add missing fields, fix type mismatches) rather than reverting their work. Then note what you fixed in your commit message.

### Branch Discipline

- Check which branch you're on before committing: `git branch --show-current`
- Don't switch branches without stashing or committing your work first
- If you find uncommitted changes from another agent, don't discard them -- commit your work separately

## UX Rules

These rules are mandatory for all CLI and TUI work. The goal: everything must be frictionless.

### CLI Commands

- **Positional arguments for required inputs.** If a user must provide a value, it should be positional -- never hidden behind a `--flag`. Example: `aegis diff UUID1 UUID2`, not `aegis diff --session1 UUID1 --session2 UUID2`.
- **Flags only for optional/modifier behavior.** Use `--flag` for things that change behavior (e.g., `--confirm`, `--follow`, `--format csv`) or for optional context (e.g., `--config NAME` to override the default config).
- **`config` is `#[arg(long)]` when other positionals exist.** If a command has required positional arguments, `config` must be a `--config` flag to avoid clap ambiguity. If `config` is the only argument, it stays positional as `[CONFIG]`.
- **Sensible defaults everywhere.** Commands should work with zero flags when possible. Derive names from context (current directory, current config).
- **No walls of required flags.** If a command needs 3+ pieces of information, consider a TUI wizard or interactive prompt instead.

### TUI (ratatui)

- **Full cursor support on all text inputs.** Every text input must support: Left, Right, Home, End, Backspace (at cursor), character insert (at cursor). Use `build_cursor_spans()` in `wizard/ui.rs` for consistent rendering.
- **Consistent back-navigation.** Esc should always go to the immediately preceding step in the wizard flow, never skip steps.
- **Tab for next field, Shift+Tab for previous** in multi-field screens.
- **Visual feedback.** Show the cursor block (inverted colors), highlight the active field, use color to distinguish states.

### General

- Prefer progressive disclosure: show the simple path first, offer advanced options only when asked.
- Error messages must include what went wrong AND what the user should do about it.
- Help text should show real examples, not just flag descriptions.

## Code Conventions

- Follow Rust idioms: iterators over indexing, Result/Option over panicking
- Use `anyhow::Context` for error context in CLI commands
- Keep functions small and focused
- Run `cargo clippy -p <crate> -- -D warnings` before committing -- zero warnings policy
