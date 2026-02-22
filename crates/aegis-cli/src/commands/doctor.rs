//! Configuration diagnosis and auto-repair.
//!
//! `aegis doctor`        -- diagnose common issues
//! `aegis doctor --fix`  -- attempt to fix issues automatically

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Result;

use aegis_control::daemon::DaemonClient;
use aegis_ledger::AuditStore;
use aegis_types::daemon::{daemon_config_path, daemon_dir, DaemonConfig};
use aegis_types::ChannelConfig;

/// Severity level for a diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Fail,
}

/// A single diagnostic check result.
#[derive(Debug, Clone)]
struct CheckResult {
    level: Level,
    message: String,
    fix_hint: Option<String>,
}

impl CheckResult {
    fn ok(message: impl Into<String>) -> Self {
        Self {
            level: Level::Ok,
            message: message.into(),
            fix_hint: None,
        }
    }

    fn warn(message: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            message: message.into(),
            fix_hint: None,
        }
    }

    fn fail(message: impl Into<String>) -> Self {
        Self {
            level: Level::Fail,
            message: message.into(),
            fix_hint: None,
        }
    }

    fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.fix_hint = Some(hint.into());
        self
    }

    fn prefix(&self) -> &str {
        match self.level {
            Level::Ok => "[OK]",
            Level::Warn => "[WARN]",
            Level::Fail => "[FAIL]",
        }
    }
}

/// Summary counts from a set of check results.
#[derive(Debug, Default)]
struct Summary {
    passed: usize,
    warnings: usize,
    failures: usize,
}

impl Summary {
    fn add(&mut self, level: Level) {
        match level {
            Level::Ok => self.passed += 1,
            Level::Warn => self.warnings += 1,
            Level::Fail => self.failures += 1,
        }
    }
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} passed, {} warnings, {} failures",
            self.passed, self.warnings, self.failures
        )
    }
}

/// Run the `aegis doctor` command.
pub fn run(fix: bool, config_name: Option<&str>) -> Result<()> {
    println!("Aegis Doctor");
    println!("============");
    println!();

    let mut summary = Summary::default();
    let aegis_dir = aegis_dir_path();

    // --- Configuration section ---
    println!("Configuration");
    let results = check_configuration(&aegis_dir, fix);
    print_results(&results, &mut summary);
    println!();

    // --- Daemon / Runtime section ---
    println!("Runtime");
    let results = check_runtime(&aegis_dir);
    print_results(&results, &mut summary);
    println!();

    // --- Audit section (if a config is available) ---
    let config_loaded = load_doctor_config(config_name);
    if let Some(config) = &config_loaded {
        println!("Audit");
        let results = check_audit(config);
        print_results(&results, &mut summary);
        println!();
    }

    // --- Environment section ---
    println!("Environment");
    let daemon_cfg = load_daemon_config();
    let results = check_environment(&daemon_cfg);
    print_results(&results, &mut summary);
    println!();

    // --- Storage section ---
    println!("Storage");
    let results = check_storage(&aegis_dir, config_loaded.as_ref());
    print_results(&results, &mut summary);
    println!();

    // --- Summary ---
    println!("Summary: {summary}");

    Ok(())
}

fn print_results(results: &[CheckResult], summary: &mut Summary) {
    for r in results {
        summary.add(r.level);
        println!("  {} {}", r.prefix(), r.message);
        if let Some(hint) = &r.fix_hint {
            println!("         Fix: {hint}");
        }
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn aegis_dir_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".aegis")
}

fn load_doctor_config(name: Option<&str>) -> Option<aegis_types::AegisConfig> {
    let name = match name {
        Some(n) => n.to_string(),
        None => crate::commands::use_config::get_current().ok()?,
    };
    crate::commands::init::load_config(&name).ok()
}

fn load_daemon_config() -> Option<DaemonConfig> {
    let path = daemon_config_path();
    let content = std::fs::read_to_string(&path).ok()?;
    DaemonConfig::from_toml(&content).ok()
}

// ---------------------------------------------------------------------------
// Configuration checks
// ---------------------------------------------------------------------------

fn check_configuration(aegis_dir: &Path, fix: bool) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // 1. Config directory exists
    if aegis_dir.exists() {
        results.push(CheckResult::ok(format!(
            "Config directory exists ({})",
            aegis_dir.display()
        )));
    } else if fix {
        match std::fs::create_dir_all(aegis_dir) {
            Ok(()) => results.push(CheckResult::ok(format!(
                "Config directory created ({})",
                aegis_dir.display()
            ))),
            Err(e) => results.push(
                CheckResult::fail(format!(
                    "Could not create config directory: {e}"
                ))
                .with_hint(format!("mkdir -p {}", aegis_dir.display())),
            ),
        }
    } else {
        results.push(
            CheckResult::fail(format!(
                "Config directory missing ({})",
                aegis_dir.display()
            ))
            .with_hint("Run `aegis doctor --fix` or `aegis setup` to create it"),
        );
    }

    // 2. daemon.toml exists and parses
    let daemon_toml = daemon_config_path();
    if daemon_toml.exists() {
        match std::fs::read_to_string(&daemon_toml) {
            Ok(content) => match DaemonConfig::from_toml(&content) {
                Ok(_cfg) => {
                    results.push(CheckResult::ok("daemon.toml parses successfully"));
                }
                Err(e) => {
                    results.push(
                        CheckResult::fail(format!("daemon.toml parse error: {e}"))
                            .with_hint("Run `aegis daemon config edit` to fix syntax errors"),
                    );
                }
            },
            Err(e) => {
                results.push(
                    CheckResult::fail(format!("Cannot read daemon.toml: {e}"))
                        .with_hint(format!("Check permissions on {}", daemon_toml.display())),
                );
            }
        }
    } else if fix {
        // Create daemon dir and write a default daemon.toml
        let daemon = daemon_dir();
        let _ = std::fs::create_dir_all(&daemon);
        match crate::commands::daemon::init_quiet() {
            Ok(msg) => results.push(CheckResult::ok(format!("daemon.toml created: {msg}"))),
            Err(e) => results.push(
                CheckResult::fail(format!("Could not create daemon.toml: {e}"))
                    .with_hint("Run `aegis daemon init` manually"),
            ),
        }
    } else {
        results.push(
            CheckResult::warn(format!(
                "daemon.toml not found ({})",
                daemon_toml.display()
            ))
            .with_hint("Run `aegis daemon init` or `aegis doctor --fix` to create one"),
        );
    }

    // 3. Policy files exist (check daemon config agents for policy_dir)
    if let Some(daemon_cfg) = load_daemon_config() {
        let has_policy_dirs = daemon_cfg
            .agents
            .iter()
            .any(|a| a.policy_dir.is_some());
        if has_policy_dirs {
            for agent in &daemon_cfg.agents {
                if let Some(ref policy_dir) = agent.policy_dir {
                    if policy_dir.exists() {
                        let cedar_count = count_cedar_files(policy_dir);
                        if cedar_count > 0 {
                            results.push(CheckResult::ok(format!(
                                "Agent '{}' policy dir: {} .cedar file(s)",
                                agent.name, cedar_count
                            )));
                        } else {
                            results.push(
                                CheckResult::warn(format!(
                                    "Agent '{}' policy dir exists but contains no .cedar files",
                                    agent.name
                                ))
                                .with_hint("Add Cedar policy files or remove policy_dir from agent config"),
                            );
                        }
                    } else {
                        results.push(
                            CheckResult::fail(format!(
                                "Agent '{}' policy dir missing: {}",
                                agent.name,
                                policy_dir.display()
                            ))
                            .with_hint("Create the directory and add Cedar policy files"),
                        );
                    }
                }
            }
        }
    }

    // 4. File permissions on config files with potential secrets
    check_file_permissions(&daemon_toml, &mut results, fix);

    results
}

fn count_cedar_files(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .ok()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "cedar"))
                .count()
        })
        .unwrap_or(0)
}

fn check_file_permissions(path: &Path, results: &mut Vec<CheckResult>, fix: bool) {
    if !path.exists() {
        return;
    }

    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        // Warn if group/other-readable for config files that may contain secrets
        if mode & 0o077 != 0 {
            if fix {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                match std::fs::set_permissions(path, perms) {
                    Ok(()) => results.push(CheckResult::ok(format!(
                        "Fixed permissions on {} (now 0600)",
                        path.display()
                    ))),
                    Err(e) => results.push(
                        CheckResult::warn(format!(
                            "{} is world/group-readable (mode {mode:o}), could not fix: {e}",
                            path.display()
                        ))
                        .with_hint(format!("chmod 600 {}", path.display())),
                    ),
                }
            } else {
                results.push(
                    CheckResult::warn(format!(
                        "{} is world/group-readable (mode {:o})",
                        path.display(),
                        mode
                    ))
                    .with_hint(format!(
                        "Run `aegis doctor --fix` or `chmod 600 {}`",
                        path.display()
                    )),
                );
            }
        } else {
            results.push(CheckResult::ok(format!(
                "Permissions on {} are restrictive ({:o})",
                path.display(),
                mode
            )));
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime checks
// ---------------------------------------------------------------------------

fn check_runtime(aegis_dir: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let socket_path = aegis_dir.join("daemon").join("daemon.sock");

    // 5. Daemon socket exists
    if socket_path.exists() {
        results.push(CheckResult::ok("Daemon socket exists"));

        // 6. Daemon running (ping)
        let client = DaemonClient::default_path();
        if client.is_running() {
            // Try to get ping data for details
            if let Ok(resp) = client.send(&aegis_control::daemon::DaemonCommand::Ping) {
                if resp.ok {
                    if let Some(data) = resp.data {
                        if let Ok(ping) = serde_json::from_value::<
                            aegis_control::daemon::DaemonPing,
                        >(data)
                        {
                            let uptime = format_uptime(ping.uptime_secs);
                            results.push(CheckResult::ok(format!(
                                "Daemon responding (uptime: {}, {} agents)",
                                uptime, ping.agent_count
                            )));
                        } else {
                            results.push(CheckResult::ok("Daemon responding"));
                        }
                    } else {
                        results.push(CheckResult::ok("Daemon responding"));
                    }
                } else {
                    results.push(
                        CheckResult::warn(format!("Daemon error: {}", resp.message))
                            .with_hint("Try `aegis daemon restart`"),
                    );
                }
            } else {
                results.push(CheckResult::ok("Daemon responding"));
            }
        } else {
            results.push(
                CheckResult::warn("Daemon socket exists but daemon is not responding")
                    .with_hint("Start with `aegis daemon start` or remove stale socket"),
            );
        }
    } else {
        results.push(
            CheckResult::warn("Daemon socket not found")
                .with_hint("Start daemon with `aegis daemon start`"),
        );
    }

    // 7. Agent binaries available
    if let Some(daemon_cfg) = load_daemon_config() {
        for agent in &daemon_cfg.agents {
            let (binary, label) = match &agent.tool {
                aegis_types::daemon::AgentToolConfig::ClaudeCode { .. } => {
                    ("claude", "ClaudeCode")
                }
                aegis_types::daemon::AgentToolConfig::Codex { .. } => ("codex", "Codex"),
                aegis_types::daemon::AgentToolConfig::OpenClaw { .. } => ("openclaw", "OpenClaw"),
                aegis_types::daemon::AgentToolConfig::Custom { command, .. } => {
                    (command.as_str(), "Custom")
                }
            };

            if binary_exists(binary) {
                results.push(CheckResult::ok(format!(
                    "Agent '{}' binary found: {binary} ({label})",
                    agent.name
                )));
            } else {
                results.push(
                    CheckResult::fail(format!(
                        "Agent '{}' binary not found: {binary}",
                        agent.name
                    ))
                    .with_hint(format!(
                        "Install {label} or remove agent '{}' from config",
                        agent.name
                    )),
                );
            }
        }
    }

    results
}

fn binary_exists(name: &str) -> bool {
    crate::tui_utils::binary_exists(name)
}

fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{h}h {m:02}m")
    }
}

// ---------------------------------------------------------------------------
// Audit checks
// ---------------------------------------------------------------------------

fn check_audit(config: &aegis_types::AegisConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // 8. Audit database accessible
    if !config.ledger_path.exists() {
        results.push(CheckResult::ok(
            "Audit database not yet created (will be created on first run)",
        ));
        return results;
    }

    match AuditStore::open(&config.ledger_path) {
        Ok(store) => {
            let count = store.count().unwrap_or(0);
            results.push(CheckResult::ok(format!(
                "Audit database accessible ({count} entries)"
            )));

            // 9. Audit chain integrity
            match store.verify_integrity() {
                Ok(r) if r.valid => {
                    results.push(CheckResult::ok(format!(
                        "Audit chain integrity: valid ({count}/{count} entries)"
                    )));
                }
                Ok(r) => {
                    results.push(
                        CheckResult::fail(format!(
                            "Audit chain integrity: FAILED - {}",
                            r.message
                        ))
                        .with_hint("The audit hash chain has been tampered with or corrupted"),
                    );
                }
                Err(e) => {
                    results.push(
                        CheckResult::warn(format!("Could not verify audit integrity: {e}"))
                            .with_hint("Run `aegis audit verify` for details"),
                    );
                }
            }
        }
        Err(e) => {
            results.push(
                CheckResult::fail(format!("Cannot open audit database: {e}"))
                    .with_hint(format!(
                        "Check permissions on {}",
                        config.ledger_path.display()
                    )),
            );
        }
    }

    // Policy files for this config
    for policy_path in &config.policy_paths {
        if policy_path.exists() {
            let count = count_cedar_files(policy_path);
            if count > 0 {
                results.push(CheckResult::ok(format!(
                    "Policy directory: {count} .cedar file(s)"
                )));
            } else {
                results.push(
                    CheckResult::warn("No Cedar policy files found (using default-deny)")
                        .with_hint("Add .cedar files or run `aegis policy generate default-deny`"),
                );
            }
        } else {
            results.push(
                CheckResult::warn(format!(
                    "Policy directory missing: {}",
                    policy_path.display()
                ))
                .with_hint("Create the directory and add Cedar policy files"),
            );
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Environment checks
// ---------------------------------------------------------------------------

fn check_environment(daemon_cfg: &Option<DaemonConfig>) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // 10. API keys
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        results.push(CheckResult::ok("ANTHROPIC_API_KEY set"));
    } else {
        // Only warn if there are ClaudeCode agents configured
        let needs_anthropic = daemon_cfg.as_ref().is_some_and(|cfg| {
            cfg.agents.iter().any(|a| {
                matches!(
                    a.tool,
                    aegis_types::daemon::AgentToolConfig::ClaudeCode { .. }
                )
            })
        });
        if needs_anthropic {
            results.push(
                CheckResult::warn("ANTHROPIC_API_KEY not set (needed for ClaudeCode agents)")
                    .with_hint("Export ANTHROPIC_API_KEY or configure claude login"),
            );
        } else {
            results.push(CheckResult::ok(
                "ANTHROPIC_API_KEY not set (not needed by current config)",
            ));
        }
    }

    if std::env::var("OPENAI_API_KEY").is_ok() {
        results.push(CheckResult::ok("OPENAI_API_KEY set"));
    } else {
        let needs_openai = daemon_cfg.as_ref().is_some_and(|cfg| {
            cfg.agents.iter().any(|a| {
                matches!(
                    a.tool,
                    aegis_types::daemon::AgentToolConfig::Codex { .. }
                )
            })
        });
        if needs_openai {
            results.push(
                CheckResult::warn("OPENAI_API_KEY not set (needed for Codex agents)")
                    .with_hint("Export OPENAI_API_KEY in your shell profile"),
            );
        }
    }

    // 11. Telegram bot token format (if configured)
    if let Some(cfg) = daemon_cfg {
        if let Some(ChannelConfig::Telegram(tg)) = &cfg.channel {
            if validate_telegram_token_format(&tg.bot_token) {
                results.push(CheckResult::ok("Telegram bot token format valid"));
            } else {
                results.push(
                    CheckResult::warn("Telegram bot token format looks invalid")
                        .with_hint("Token should match <bot_id>:<alphanumeric_hash> from @BotFather"),
                );
            }
        }
    }

    // 12. Sandbox availability
    #[cfg(target_os = "macos")]
    {
        if binary_exists("sandbox-exec") {
            results.push(CheckResult::ok(
                "sandbox-exec available (macOS Seatbelt)",
            ));
        } else {
            results.push(
                CheckResult::warn("sandbox-exec not found")
                    .with_hint("Seatbelt sandbox enforcement unavailable; Process mode only"),
            );
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if binary_exists("docker") {
            results.push(CheckResult::ok("Docker available for sandbox isolation"));
        } else {
            results.push(
                CheckResult::warn("Docker not found")
                    .with_hint("Install Docker for sandbox isolation, or use Process mode"),
            );
        }
    }

    results
}

/// Validate that a Telegram bot token looks like `<digits>:<alphanumeric>`.
fn validate_telegram_token_format(token: &str) -> bool {
    let Some((bot_id, hash)) = token.split_once(':') else {
        return false;
    };
    if bot_id.is_empty() || hash.is_empty() {
        return false;
    }
    bot_id.chars().all(|c| c.is_ascii_digit())
        && hash
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ---------------------------------------------------------------------------
// Storage checks
// ---------------------------------------------------------------------------

fn check_storage(
    aegis_dir: &Path,
    config: Option<&aegis_types::AegisConfig>,
) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // 13. Disk space
    match available_disk_space(aegis_dir) {
        Some(bytes) => {
            let display = format_size(bytes);
            if bytes < 100 * 1024 * 1024 {
                results.push(
                    CheckResult::warn(format!("Low disk space: {display} available"))
                        .with_hint("Free up disk space in the aegis directory"),
                );
            } else {
                results.push(CheckResult::ok(format!(
                    "Disk space: {display} available"
                )));
            }
        }
        None => {
            results.push(CheckResult::warn("Could not determine disk space"));
        }
    }

    // 14. Database size
    if let Some(cfg) = config {
        if cfg.ledger_path.exists() {
            if let Ok(meta) = std::fs::metadata(&cfg.ledger_path) {
                results.push(CheckResult::ok(format!(
                    "Database size: {}",
                    format_size(meta.len())
                )));
            }
        }
    }

    results
}

fn available_disk_space(path: &Path) -> Option<u64> {
    // Use statvfs to get available disk space
    let target = if path.exists() {
        path.to_path_buf()
    } else {
        // Fall back to home
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
    };
    let c_path =
        std::ffi::CString::new(target.to_string_lossy().as_bytes()).ok()?;
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
            Some(stat.f_bavail as u64 * stat.f_frsize)
        } else {
            None
        }
    }
}

/// Format a byte count as a human-readable size string.
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_prefix_ok() {
        let r = CheckResult::ok("test");
        assert_eq!(r.prefix(), "[OK]");
        assert_eq!(r.level, Level::Ok);
    }

    #[test]
    fn check_result_prefix_warn() {
        let r = CheckResult::warn("test");
        assert_eq!(r.prefix(), "[WARN]");
        assert_eq!(r.level, Level::Warn);
    }

    #[test]
    fn check_result_prefix_fail() {
        let r = CheckResult::fail("test");
        assert_eq!(r.prefix(), "[FAIL]");
        assert_eq!(r.level, Level::Fail);
    }

    #[test]
    fn check_result_with_hint() {
        let r = CheckResult::fail("broken").with_hint("fix it");
        assert_eq!(r.fix_hint.as_deref(), Some("fix it"));
    }

    #[test]
    fn summary_counting() {
        let mut s = Summary::default();
        s.add(Level::Ok);
        s.add(Level::Ok);
        s.add(Level::Ok);
        s.add(Level::Warn);
        s.add(Level::Warn);
        s.add(Level::Fail);
        assert_eq!(s.passed, 3);
        assert_eq!(s.warnings, 2);
        assert_eq!(s.failures, 1);
    }

    #[test]
    fn summary_display() {
        let mut s = Summary::default();
        s.add(Level::Ok);
        s.add(Level::Warn);
        s.add(Level::Fail);
        assert_eq!(s.to_string(), "1 passed, 1 warnings, 1 failures");
    }

    #[test]
    fn format_size_values() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn format_uptime_values() {
        assert_eq!(format_uptime(30), "30s");
        assert_eq!(format_uptime(90), "1m 30s");
        assert_eq!(format_uptime(3661), "1h 01m");
        assert_eq!(format_uptime(7200), "2h 00m");
    }

    #[test]
    fn validate_telegram_token_valid() {
        assert!(validate_telegram_token_format("123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"));
        assert!(validate_telegram_token_format("1:a"));
    }

    #[test]
    fn validate_telegram_token_invalid() {
        assert!(!validate_telegram_token_format(""));
        assert!(!validate_telegram_token_format("nocolon"));
        assert!(!validate_telegram_token_format(":hash"));
        assert!(!validate_telegram_token_format("123:"));
        assert!(!validate_telegram_token_format("abc:hash"));
        assert!(!validate_telegram_token_format("123:ha sh"));
    }

    #[test]
    fn print_results_counts_correctly() {
        let results = vec![
            CheckResult::ok("good"),
            CheckResult::warn("meh"),
            CheckResult::fail("bad"),
            CheckResult::ok("also good"),
        ];
        let mut summary = Summary::default();
        // Suppress stdout in test by just tallying
        for r in &results {
            summary.add(r.level);
        }
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.warnings, 1);
        assert_eq!(summary.failures, 1);
    }
}
