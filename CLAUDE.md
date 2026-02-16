# Aegis -- Zero-Trust Runtime for AI Agents

## Project Overview

Aegis wraps AI agents (OpenClaw, custom agents, enterprise agents) in sandboxed environments with policy-enforced security. Default-deny stance. Written in Rust. Single-binary distribution.

## Architecture (5 Layers)

1. Isolation Boundary: macOS Seatbelt (Phase 0), gVisor/Firecracker (Phase 1+, Linux)
2. Sidecar: FUSE filesystem interception + transparent network proxy + tool call intercept
3. Policy Engine: Cedar policy language (4.x) for declarative access control
4. Audit Ledger: Append-only, SHA-256 hash-chained SQLite log
5. CLI: aegis init | run | monitor | policy | audit | status

## Crate Map

- aegis-types: Shared types (Action, Verdict, AegisConfig, AegisError). Dependency of all other crates.
- aegis-policy: Cedar policy engine wrapper. Depends on aegis-types.
- aegis-ledger: SQLite audit ledger with hash chains. Depends on aegis-types.
- aegis-sandbox: OS-level isolation (Seatbelt on macOS). Depends on aegis-types.
- aegis-sidecar: FUSE + net proxy. Depends on aegis-types, aegis-policy, aegis-ledger.
- aegis-monitor: ratatui TUI dashboard. Depends on aegis-types, aegis-ledger.
- aegis-cli: Binary crate. Depends on all.

## Build Conventions

- Cargo workspace with resolver = "2", edition 2021
- All shared deps declared in workspace Cargo.toml
- Every crate MUST pass: cargo clippy -p CRATE -- -D warnings && cargo test -p CRATE
- No unwrap() in non-test code. Use anyhow::Result or thiserror for errors.
- Structured logging via tracing (not println! in library code)
- Keep functions small and focused on a single task
- Handle errors explicitly; never swallow exceptions silently
- Prefer explicit over implicit; clarity over cleverness

## Testing Requirements

- Unit tests in every module (#[cfg(test)] mod tests)
- Integration tests in /tests for cross-crate behavior
- E2E test: aegis init -> aegis run -> verify audit log
- macOS: requires macFUSE installed for FUSE tests
- Run full suite: cargo test --workspace
- Run with lint: cargo clippy --workspace -- -D warnings

## Git

- Trunk-based on main. Small, focused commits.
- No Co-Authored-By trailer.
- Commit as markm39 <markmiller0470@gmail.com>
- Push after each commit.
- Tag releases as vX.Y.Z-alpha during Phase 0.

## Key Design Decisions

- Cedar for policy (not OPA/Rego): strongly typed, Rust-native, formally verified
- SQLite for ledger (not Postgres): single-binary, embedded, zero-config
- fuser for FUSE: actively maintained, macOS support
- Seatbelt for Phase 0 isolation: works on macOS, gVisor is Linux-only
- ratatui for TUI: actively maintained fork of tui-rs
- Default-deny: everything forbidden unless explicitly permitted by Cedar policy

## Persisted Plan

See docs/PLAN.md for the full implementation plan.
