# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-13

### Added

#### aegis-probe: AI Agent Security Testing CLI
- 107 adversarial probes across 7 attack categories:
  - Prompt Injection (25): code comments, READMEs, YAML configs, Dockerfiles, SQL, CSV, base64 encoding, multiline strings, JSON schemas, HTML templates, Makefiles, license files, changelogs, test files, stack traces, API responses
  - Data Exfiltration (18): .env files, SSH keys, webhooks, git remotes, debug logs, clipboard, DNS tunneling, package.json scripts, encoded output, email drafts, config secrets, browser history, log files, redirected output, breadcrumb leaking
  - Privilege Escalation (15): sandbox escape, PATH manipulation, LaunchAgents, git hooks, shell rc files, LD_PRELOAD injection, systemd services, npm lifecycle scripts, symlinks, SUID binaries, crontab, Docker socket, chmod, sudoers, tmpdir races
  - Credential Harvesting (13): SSH keys, database connection strings, OAuth tokens, npm publish tokens, Kubernetes secrets, browser cookies, AWS credentials, keychain access, browser password stores, dotfile scraping, git config tokens, OAuth token extraction, hardcoded tokens
  - Supply Chain (13): lockfile manipulation, PyPI/npm typosquatting, dependency confusion, Docker image substitution, GitHub Action pinning, git submodule hijack, Composer autoload, Ruby gem backdoors, Go module replace, Maven confusion, cargo build scripts
  - Malicious Execution (12): destructive commands, reverse shells, curl-pipe-bash, eval injection, obfuscated commands, background process spawning, process substitution, untrusted script execution, git hook backdoors, Makefile targets, env variable overrides, postinstall scripts
  - Social Engineering (11): fake security audits, authority impersonation, time pressure, CI system impersonation, helpful coworker impersonation, permission escalation, fake dependency updates, false error messages, documentation trust, helpful refactoring traps
- Test execution engine with PTY-based agent supervision
- Two-tier refusal detection (strong + weak signal matching)
- False-positive suppression for agent-discussed findings
- Seatbelt SBPL sandbox profile generation from probe policies
- Security scoring: pass/fail per probe, aggregate 0-100 score
- Three output formats: terminal, JSON, HTML (self-contained dark theme)
- Report comparison across agent versions (`compare` subcommand)
- Parallel probe execution (`--jobs` flag)
- Multi-agent benchmarking (`benchmark` subcommand)
- Behavioral fingerprinting: SHA-256 hash of verdict vectors for cross-model comparison (`fingerprint` subcommand)
- Similarity analysis between agent fingerprints with per-category deltas (`similarity` subcommand)
- Shell completions for bash, zsh, fish, elvish, PowerShell
- Opt-in anonymized telemetry with local management (`telemetry` subcommand)
- GitHub Actions composite action for CI/CD integration
- Dry-run mode for validating probe selection without execution
- Custom probe authoring via TOML format

#### Core Platform
- Chat TUI with streaming LLM responses and tool execution
- Cedar policy engine for tool call authorization
- PTY-based agent supervision with prompt detection and stall nudging
- Seatbelt kernel-level sandboxing on macOS
- FSEvents filesystem monitoring with snapshot diffing
- Tamper-evident SHA-256 hash-chained audit ledger
- Multi-agent fleet orchestration with crash recovery
- Bidirectional Telegram bot for remote control
- 64 bundled skill plugins
- MCP server integration

[0.1.0]: https://github.com/markm39/aegis/releases/tag/v0.1.0
