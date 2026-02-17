//! List all Aegis configurations.
//!
//! Scans `~/.aegis/` for init configs and `~/.aegis/wraps/` for wrap configs,
//! displaying name, type, policy, isolation mode, session count, and last used.

use std::fs;

use anyhow::Result;
use chrono::{DateTime, Utc};

use aegis_ledger::AuditStore;
use aegis_types::{AegisConfig, CONFIG_FILENAME};

use crate::commands::init::{dirs_from_env, load_config_from_dir};
use crate::commands::DATETIME_SHORT_FMT;

/// Table separator width for config listings.
const CONFIG_TABLE_WIDTH: usize = 90;

/// A discovered configuration entry for display.
struct ConfigEntry {
    name: String,
    config_type: &'static str,
    policy: String,
    isolation: String,
    sessions: usize,
    last_used: Option<DateTime<Utc>>,
}

/// Run `aegis list`.
pub fn run() -> Result<()> {
    let home = dirs_from_env()?;
    let aegis_dir = home.join(".aegis");

    if !aegis_dir.exists() {
        println!("No Aegis configurations found.");
        println!("Run `aegis init` or `aegis wrap -- <command>` to get started.");
        return Ok(());
    }

    let mut entries: Vec<ConfigEntry> = Vec::new();

    // Scan init configs: ~/.aegis/*/aegis.toml (skip "wraps" and "current")
    scan_configs(&aegis_dir, "init", &mut entries, |name| {
        name != "wraps" && name != "current"
    });

    // Scan wrap configs: ~/.aegis/wraps/*/aegis.toml
    let wraps_dir = aegis_dir.join("wraps");
    scan_configs(&wraps_dir, "wrap", &mut entries, |_| true);

    if entries.is_empty() {
        println!("No Aegis configurations found.");
        println!("Run `aegis init` or `aegis wrap -- <command>` to get started.");
        return Ok(());
    }

    // Sort by last used (most recent first), configs with no sessions last
    entries.sort_by(|a, b| b.last_used.cmp(&a.last_used));

    // Print table
    println!(
        "{:<20} {:<6} {:<18} {:<10} {:<10} LAST USED",
        "NAME", "TYPE", "POLICY", "ISOLATION", "SESSIONS"
    );
    let separator = "-".repeat(CONFIG_TABLE_WIDTH);
    println!("{separator}");

    for e in &entries {
        let last_used = e
            .last_used
            .map(|dt| dt.format(DATETIME_SHORT_FMT).to_string())
            .unwrap_or_else(|| "(never)".to_string());

        println!(
            "{:<20} {:<6} {:<18} {:<10} {:<10} {}",
            truncate(&e.name, 20),
            e.config_type,
            truncate(&e.policy, 18),
            truncate(&e.isolation, 10),
            e.sessions,
            last_used,
        );
    }

    println!("\n{} configuration(s) found.", entries.len());

    Ok(())
}

/// Scan a directory for aegis configs, appending discovered entries to `out`.
///
/// Each subdirectory containing `aegis.toml` is treated as a config.
/// The `filter` predicate can skip specific directory names (e.g., "wraps").
fn scan_configs(
    dir: &std::path::Path,
    config_type: &'static str,
    out: &mut Vec<ConfigEntry>,
    filter: impl Fn(&str) -> bool,
) {
    let readdir = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in readdir.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        if !filter(&name) {
            continue;
        }

        if path.join(CONFIG_FILENAME).exists() {
            if let Some(ce) = load_entry(&path, &name, config_type) {
                out.push(ce);
            }
        }
    }
}

/// Load a config entry from a directory, returning None on any error.
fn load_entry(dir: &std::path::Path, name: &str, config_type: &'static str) -> Option<ConfigEntry> {
    let config = load_config_from_dir(dir).ok()?;
    let (policy, isolation) = describe_config(&config);

    let (sessions, last_used) = match AuditStore::open(&config.ledger_path) {
        Ok(store) => {
            let count = store.count_all_sessions().unwrap_or(0);
            let last = store
                .latest_session()
                .ok()
                .flatten()
                .map(|s| s.start_time);
            (count, last)
        }
        Err(_) => (0, None),
    };

    Some(ConfigEntry {
        name: name.to_string(),
        config_type,
        policy,
        isolation,
        sessions,
        last_used,
    })
}

/// Extract human-readable policy and isolation descriptions from a config.
pub fn describe_config(config: &AegisConfig) -> (String, String) {
    let policy = config
        .policy_paths
        .first()
        .and_then(|p| {
            fs::read_dir(p).ok().and_then(|mut entries| {
                entries.find_map(|e| {
                    let path = e.ok()?.path();
                    if path.extension()?.to_str()? == "cedar" {
                        let content = fs::read_to_string(&path).ok()?;
                        Some(identify_policy(&content))
                    } else {
                        None
                    }
                })
            })
        })
        .unwrap_or_else(|| "unknown".to_string());

    let isolation = config.isolation.to_string();

    (policy, isolation)
}

/// Identify a policy by comparing its content against known builtins.
///
/// Trims whitespace before comparison to handle trailing newlines or
/// formatting differences. Falls back to "custom" if no builtin matches.
pub fn identify_policy(content: &str) -> String {
    let trimmed = content.trim();
    for name in aegis_policy::builtin::list_builtin_policies() {
        if let Some(builtin_text) = aegis_policy::builtin::get_builtin_policy(name) {
            if trimmed == builtin_text.trim() {
                return name.to_string();
            }
        }
    }
    "custom".to_string()
}

/// Truncate a string to fit a column width, using char boundaries.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let prefix: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{prefix}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello world test", 10), "hello w...");
    }

    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate("1234567890", 10), "1234567890");
    }

    #[test]
    fn truncate_multibyte_chars() {
        // Should not panic on multi-byte UTF-8 characters
        let s = "cafe\u{0301}"; // "cafe" + combining accent = 5 chars
        let result = truncate(s, 3);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn describe_config_seatbelt() {
        let config = aegis_types::AegisConfig {
            name: "test".into(),
            sandbox_dir: "/tmp".into(),
            policy_paths: vec![],
            schema_path: None,
            ledger_path: "/tmp/audit.db".into(),
            allowed_network: vec![],
            isolation: aegis_types::IsolationConfig::Seatbelt {
                profile_overrides: None,
            },
            observer: aegis_types::ObserverConfig::default(),
            alerts: Vec::new(),
            pilot: None,
        };

        let (_, isolation) = describe_config(&config);
        assert_eq!(isolation, "Seatbelt");
    }

    #[test]
    fn describe_config_process() {
        let config = aegis_types::AegisConfig {
            name: "test".into(),
            sandbox_dir: "/tmp".into(),
            policy_paths: vec![],
            schema_path: None,
            ledger_path: "/tmp/audit.db".into(),
            allowed_network: vec![],
            isolation: aegis_types::IsolationConfig::Process,
            observer: aegis_types::ObserverConfig::default(),
            alerts: Vec::new(),
            pilot: None,
        };

        let (_, isolation) = describe_config(&config);
        assert_eq!(isolation, "Process");
    }

    #[test]
    fn identify_policy_recognizes_all_builtins() {
        // ci-runner is an alias for allow-read-write (identical content), so it
        // will be identified as allow-read-write since that appears first in the
        // list. We test the non-aliased builtins individually.
        for name in ["default-deny", "allow-read-only", "allow-read-write", "data-science", "permit-all"] {
            let text = aegis_policy::builtin::get_builtin_policy(name).unwrap();
            assert_eq!(
                identify_policy(text),
                name.to_string(),
                "should identify {name}"
            );
        }

        // ci-runner has the same content as allow-read-write, so it identifies as allow-read-write
        let ci_text = aegis_policy::builtin::get_builtin_policy("ci-runner").unwrap();
        let result = identify_policy(ci_text);
        assert!(
            result == "allow-read-write" || result == "ci-runner",
            "ci-runner should identify as allow-read-write or ci-runner: got {result}"
        );
    }

    #[test]
    fn identify_policy_handles_whitespace() {
        let text = format!("  {}  \n", aegis_policy::builtin::PERMIT_ALL);
        assert_eq!(identify_policy(&text), "permit-all");
    }

    #[test]
    fn identify_policy_custom_returns_custom() {
        assert_eq!(
            identify_policy("permit(principal, action == Aegis::Action::\"FileRead\", resource);"),
            "custom"
        );
    }

    #[test]
    fn identify_policy_empty_returns_custom() {
        assert_eq!(identify_policy(""), "custom");
    }
}
