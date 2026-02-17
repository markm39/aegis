//! Default action when `aegis` is invoked with no subcommand.
//!
//! If configurations exist, shows `aegis list`. Otherwise, prints a welcome
//! message and launches the interactive setup wizard.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};

use aegis_ledger::AuditStore;

use crate::commands::init::{dirs_from_env, load_config_from_dir};

/// Run the default action for bare `aegis` invocation.
pub fn run() -> Result<()> {
    let home = dirs_from_env()?;
    let aegis_dir = home.join(".aegis");

    if has_configs(&aegis_dir) {
        crate::commands::list::run()
    } else {
        println!("Welcome to Aegis -- zero-trust runtime for AI agents.\n");
        println!("No configurations found. Let's set one up.\n");
        crate::commands::init::run(None, "default-deny", None)
    }
}

/// Check whether any aegis configurations exist.
fn has_configs(aegis_dir: &std::path::Path) -> bool {
    if !aegis_dir.exists() {
        return false;
    }

    // Check for init configs: ~/.aegis/*/aegis.toml (skip "wraps")
    if let Ok(entries) = std::fs::read_dir(aegis_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default();
                if name != "wraps" && path.join(aegis_types::CONFIG_FILENAME).exists() {
                    return true;
                }
            }
        }
    }

    // Check for wrap configs: ~/.aegis/wraps/*/aegis.toml
    let wraps_dir = aegis_dir.join("wraps");
    if let Ok(entries) = std::fs::read_dir(wraps_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join(aegis_types::CONFIG_FILENAME).exists() {
                return true;
            }
        }
    }

    false
}

/// Find the most recently used config name.
///
/// Scans all configs (init and wrap), checks each ledger for the latest
/// session, and returns the config name with the most recent activity.
pub fn most_recent_config() -> Result<String> {
    let home = dirs_from_env()?;
    let aegis_dir = home.join(".aegis");

    let mut best: Option<(String, DateTime<Utc>)> = None;

    // Scan init configs
    scan_for_recent(&aegis_dir, &mut best, |name| name != "wraps");

    // Scan wrap configs
    let wraps_dir = aegis_dir.join("wraps");
    scan_for_recent(&wraps_dir, &mut best, |_| true);

    match best {
        Some((name, _)) => Ok(name),
        None => bail!("no configurations found; run `aegis init` or `aegis wrap <command>` first"),
    }
}

/// Scan a directory for configs and track the most recently used one.
fn scan_for_recent(
    dir: &std::path::Path,
    best: &mut Option<(String, DateTime<Utc>)>,
    filter: impl Fn(&str) -> bool,
) {
    let readdir = match std::fs::read_dir(dir) {
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

        if !filter(&name) || !path.join(aegis_types::CONFIG_FILENAME).exists() {
            continue;
        }

        if let Ok(config) = load_config_from_dir(&path) {
            if let Ok(store) = AuditStore::open(&config.ledger_path) {
                if let Ok(Some(session)) = store.latest_session() {
                    let ts = session.start_time;
                    if best.as_ref().is_none_or(|(_, best_ts)| ts > *best_ts) {
                        *best = Some((name.clone(), ts));
                    }
                }
            }
        }
    }
}
