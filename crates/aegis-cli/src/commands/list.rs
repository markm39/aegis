/// List all Aegis configurations.
///
/// Scans `~/.aegis/` for init configs and `~/.aegis/wraps/` for wrap configs,
/// displaying name, type, policy, isolation mode, session count, and last used.
use std::fs;

use anyhow::Result;
use chrono::{DateTime, Utc};

use aegis_ledger::AuditStore;
use aegis_types::AegisConfig;

use crate::commands::init::{dirs_from_env, load_config_from_dir};

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

    // Scan init configs: ~/.aegis/*/aegis.toml (skip "wraps" directory)
    if let Ok(readdir) = fs::read_dir(&aegis_dir) {
        for entry in readdir.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            // Skip the wraps directory -- handled separately
            if name == "wraps" {
                continue;
            }

            if path.join("aegis.toml").exists() {
                if let Some(ce) = load_entry(&path, &name, "init") {
                    entries.push(ce);
                }
            }
        }
    }

    // Scan wrap configs: ~/.aegis/wraps/*/aegis.toml
    let wraps_dir = aegis_dir.join("wraps");
    if let Ok(readdir) = fs::read_dir(&wraps_dir) {
        for entry in readdir.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            if path.join("aegis.toml").exists() {
                if let Some(ce) = load_entry(&path, &name, "wrap") {
                    entries.push(ce);
                }
            }
        }
    }

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
    let separator = "-".repeat(90);
    println!("{separator}");

    for e in &entries {
        let last_used = e
            .last_used
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
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
fn describe_config(config: &AegisConfig) -> (String, String) {
    let policy = config
        .policy_paths
        .first()
        .and_then(|p| {
            fs::read_dir(p).ok().and_then(|mut entries| {
                entries.find_map(|e| {
                    let path = e.ok()?.path();
                    if path.extension()?.to_str()? == "cedar" {
                        let content = fs::read_to_string(&path).ok()?;
                        // Detect policy type from content
                        if content.contains("forbid(principal, action, resource)") {
                            Some("default-deny".to_string())
                        } else if content.contains("permit(principal, action, resource)")
                            && !content.contains("action ==")
                        {
                            Some("permit-all".to_string())
                        } else if content.contains("FileRead") && !content.contains("FileWrite") {
                            Some("allow-read-only".to_string())
                        } else {
                            Some("custom".to_string())
                        }
                    } else {
                        None
                    }
                })
            })
        })
        .unwrap_or_else(|| "unknown".to_string());

    let isolation = match &config.isolation {
        aegis_types::IsolationConfig::Seatbelt { .. } => "Seatbelt".to_string(),
        aegis_types::IsolationConfig::Process => "Process".to_string(),
        aegis_types::IsolationConfig::None => "None".to_string(),
    };

    (policy, isolation)
}

/// Truncate a string to fit a column width.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
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
        };

        let (_, isolation) = describe_config(&config);
        assert_eq!(isolation, "Process");
    }
}
