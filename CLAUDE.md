# Aegis Project Guidelines

## Build & Test

- Build: `cargo build` (workspace root)
- Clippy: `cargo clippy -p <crate> -- -D warnings`
- Test single crate: `cargo test -p <crate>`
- Test all: `cargo test --workspace`
- The workspace has many crates under `crates/`. Always run clippy and tests for affected crates after changes.

## Product Vision: The Aegis Hub

The north star: running `aegis` opens a unified interactive hub -- like running `claude`. Everything is accessible from one place.

- **Fleet dashboard:** See all agents, their status, pending permission prompts, and attention indicators. Approve/deny prompts, send input, nudge stalled agents -- all with single keystrokes.
- **Command bar:** Type `:` for a vim-style command palette with tab completion. `:approve claude-1`, `:stop agent-2`, `:follow claude-1`, `:help`.
- **Pop-out terminals:** From the hub, `:pop` any agent's output into a separate terminal window (tmux split, iTerm tab, Terminal.app window). Pop out the audit monitor too.
- **Remote control:** When away from the terminal, Telegram notifies you of pending approvals with inline [Approve]/[Deny] buttons. Send `/status`, `/approve`, `/stop` commands from your phone.
- **Single binary:** Every feature is accessible from `aegis`. Standalone subcommands (`aegis pilot`, `aegis wrap`, `aegis daemon`) still work for scripting, but the hub is the primary interface.

When making design decisions, optimize for the hub experience first. New features should be accessible from the TUI and command bar, not just as CLI subcommands.

### Mandatory: Everything Configurable from the TUI

Every setting, configuration, and management action MUST be accessible from the fleet TUI command bar (`:` mode). If a user can do it with `aegis <subcommand>`, they must also be able to do it from the TUI without exiting. The TUI should be like Claude Code -- one place to do everything. This includes:

- **Agent lifecycle:** `:add`, `:remove`, `:start`, `:stop`, `:restart`
- **Agent interaction:** `:send`, `:approve`, `:deny`, `:nudge`, `:follow`, `:pop`, `:pending`
- **Configuration:** `:config` (edit daemon.toml), `:telegram` (manage notifications), `:use` (switch config), `:hook` (install hooks)
- **Monitoring:** `:status`, `:monitor`, `:logs` (daemon logs), `:log` (audit log), `:alerts`
- **Sandbox/supervision:** `:wrap` (observe command), `:run` (sandboxed command), `:pilot` (supervised agent)
- **Audit/compliance:** `:policy` (policy info), `:report` (compliance report), `:diff` (session comparison)
- **System:** `:list` (all configs), `:watch` (directory monitoring), `:help`, `:quit`

Interactive and streaming commands spawn in a new terminal via `crate::terminal::spawn_in_terminal()`. Quick-info commands show results in the status bar.

When adding a new CLI subcommand, you MUST also add a corresponding TUI command bar entry in `fleet_tui/command.rs`. No exceptions. The TUI is the primary interface -- CLI subcommands exist for scripting, not as the main way to interact with Aegis.

## Architecture

Crate dependency flow:

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
  -> aegis-daemon (fleet orchestration, agent lifecycle, restart policies)
  -> aegis-monitor (audit TUI dashboard)
  -> aegis-cli (binary: hub TUI, fleet management, all commands, wizard)
```

Crate summary:

- `aegis-types`: Shared types and config (`AegisConfig`, `IsolationConfig`, `ObserverConfig`, etc.)
- `aegis-policy`: Cedar policy engine
- `aegis-ledger`: SQLite audit store (`AuditStore`)
- `aegis-sandbox`: Seatbelt/process sandbox backends
- `aegis-observer`: Filesystem observation (FSEvents)
- `aegis-proxy`: Action logging and policy evaluation bridge
- `aegis-pilot`: PTY-based agent supervision with prompt detection and stall nudging
- `aegis-control`: Control plane: Unix socket + HTTP servers, command protocol
- `aegis-alert`: Webhook alerting on audit events
- `aegis-channel`: Bidirectional messaging (Telegram bot with inline keyboards)
- `aegis-daemon`: Multi-agent fleet orchestration with agent drivers and lifecycle
- `aegis-monitor`: Audit TUI dashboard (ratatui)
- `aegis-cli`: Binary entry point: hub TUI, fleet management, all CLI commands, wizard

## Current Status

### Implemented and Working

- **Daemon fleet (aegis-daemon):** Multi-agent orchestration with agent drivers (ClaudeCode, Generic), lifecycle management, fleet state persistence, restart policies. Control protocol (`DaemonCommand`/`DaemonResponse`) fully wired over Unix socket including ApproveRequest, DenyRequest, NudgeAgent, ListPending, AddAgent, RemoveAgent, FleetGoal, and AgentContext commands.
- **Fleet TUI hub (aegis-cli/fleet_tui):** Unified hub accessible via bare `aegis` command. Works in offline mode (auto-reconnects when daemon starts). Features: agent table with pending count and attention indicators, detail view with output streaming, input mode (`i`), pending prompts panel with approve/deny/nudge keys, vim-style command bar (`:`) with tab completion for 30+ commands and agent names, scrollable help view, add-agent wizard (works offline), daemon control (`:daemon start/stop/init`).
- **Terminal spawning:** `:pop`, `:follow`, `:monitor`, `:wrap`, `:pilot`, `:log`, `:config` and more spawn commands in new terminal windows. Detection of tmux/iTerm2/Terminal.app with macOS fallback.
- **Telegram channel (aegis-channel):** Bidirectional Telegram bot with inline keyboard buttons for approve/deny. Fleet-level `/status`, `/goal`, `/context`, `/approve`, `/deny` commands.
- **Onboarding wizard (aegis-cli/onboard_tui):** First-run ratatui TUI wizard that configures an agent, sets up Telegram, writes daemon.toml, and seamlessly transitions to the fleet TUI.

### In Progress

- **Packaging:** install.sh, Makefile, CI/CD (GitHub Actions), Homebrew formula, license files. Partially done.

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
