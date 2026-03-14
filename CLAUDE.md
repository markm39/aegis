# Aegis Project Guidelines

## Build & Test

- Build: `cargo build` (workspace root)
- Build probe CLI: `cargo build --release -p aegis-probe`
- Clippy: `cargo clippy --workspace -- -D warnings`
- Test single crate: `cargo test -p <crate>`
- Test all: `cargo test --workspace`
- Run probe validation: `./target/release/aegis-probe validate --probes-dir probes`

## Product Vision: AI Agent Security Testing

Aegis is a pure agent security testing product. The only supported public binary is `aegis-probe` -- a CLI that tests what coding agents and model-backed runtimes actually do when exposed to adversarial inputs.

- **Security testing:** Spawn target agents in sandboxed environments, feed adversarial inputs, and monitor actions via Cedar policies, filesystem observation, and audit logs
- **Adversarial probe packs:** Prompt injection, data exfiltration, privilege escalation, malicious execution, supply chain, social engineering, and credential harvesting
- **Enterprise outputs:** terminal, JSON, HTML, Markdown, JUnit XML, and SARIF
- **Derived-only registry bundles:** Local export and optional upload of fingerprints, verdicts, timings, and summary statistics without raw prompts or raw agent output by default
- **CI/CD integration:** GitHub Action, gating flags, and machine-readable report metadata for pipeline enforcement

## Architecture

Default workspace crates:

```
aegis-types (foundation: config, errors, shared types)
  -> aegis-policy (Cedar policy engine -- define expected/forbidden agent behavior)
  -> aegis-ledger (tamper-evident audit log with hash chain)
  -> aegis-sandbox (Seatbelt/Docker isolation for safe test execution)
  -> aegis-observer (filesystem monitoring -- detect unauthorized access)
  -> aegis-pilot (PTY supervision -- spawn agents, feed inputs, monitor actions)
  -> aegis-alert (webhook alert dispatching)
  -> aegis-harness (PTY integration test framework)
  -> aegis-probe (binary: security test runner CLI)
```

Crate summary:

- `aegis-types`: Shared types and config (`AegisConfig`, `IsolationConfig`, `ObserverConfig`, etc.)
- `aegis-policy`: Cedar policy engine for defining expected vs. forbidden behavior
- `aegis-ledger`: SQLite audit store with tamper-evident hash chain
- `aegis-sandbox`: Seatbelt/process sandbox backends for test isolation
- `aegis-observer`: Filesystem observation (FSEvents) for detecting unauthorized access
- `aegis-pilot`: PTY-based agent supervision with prompt detection and stall nudging
- `aegis-alert`: Webhook alerting on security findings
- `aegis-harness`: PTY integration test framework for test execution
- `aegis-probe`: Binary entry point: adversarial probe runner, reporting, analytics, and registry bundles

Legacy runtime and orchestration crates may still exist in the repo, but they are no longer part of the default product workspace.

## Shared Struct Rules

If you add a field to a shared struct (e.g., `AegisConfig`, `AlertEvent`), you MUST update ALL construction sites across the entire workspace. Use `cargo clippy --workspace -- -D warnings` to find them all.

## Before Committing

Always run these checks against the full workspace:
```
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## UX Rules

### CLI Commands

- **Positional arguments for required inputs.** Example: `aegis-probe run`, not `aegis-probe --action run`.
- **Flags only for optional/modifier behavior.** Use `--flag` for things that change behavior (e.g., `--dry-run`, `--format json`, `--category prompt_injection`).
- **Sensible defaults everywhere.** Commands should work with zero flags when possible.
- Error messages must include what went wrong AND what the user should do about it.

## Code Conventions

- Follow Rust idioms: iterators over indexing, Result/Option over panicking
- Use `anyhow::Context` for error context in CLI commands
- Keep functions small and focused
- Run `cargo clippy --workspace -- -D warnings` before committing -- zero warnings policy
- All serde-serialized enums use `#[serde(rename_all = "snake_case")]`
