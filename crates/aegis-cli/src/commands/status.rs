//! Health check and status display for a named Aegis configuration.

use anyhow::{Context, Result};

use aegis_ledger::{AuditFilter, AuditStore};

use aegis_types::CONFIG_FILENAME;

use crate::commands::init::{load_config, resolve_config_dir};
use crate::commands::DATETIME_SHORT_FMT;

/// Run the `aegis status` command.
///
/// Checks whether the configuration directory, config file, and ledger exist,
/// and prints a health summary. Searches both init and wrap config namespaces.
pub fn run(config_name: &str) -> Result<()> {
    let base_dir = resolve_config_dir(config_name)?;

    println!("Aegis Status: {config_name}");
    println!("{}", "-".repeat(40));

    // Check config directory
    if !base_dir.exists() {
        println!("  Config dir:   MISSING ({})", base_dir.display());
        println!("  Run 'aegis init {config_name}' to create it.");
        return Ok(());
    }
    println!("  Config dir:   OK ({})", base_dir.display());

    // Check config file
    let config_path = base_dir.join(CONFIG_FILENAME);
    if !config_path.exists() {
        println!("  Config file:  MISSING ({})", config_path.display());
        return Ok(());
    }
    println!("  Config file:  OK");

    // Load and display config details
    let config = load_config(config_name)
        .with_context(|| format!("failed to load config '{config_name}'"))?;

    // Check policy directory
    if let Some(policy_dir) = config.policy_paths.first() {
        if policy_dir.exists() {
            let cedar_count = std::fs::read_dir(policy_dir)
                .ok()
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter(|e| {
                            e.path()
                                .extension()
                                .is_some_and(|ext| ext == "cedar")
                        })
                        .count()
                })
                .unwrap_or(0);
            println!("  Policies:     {cedar_count} .cedar file(s)");
        } else {
            println!("  Policies:     MISSING ({})", policy_dir.display());
        }
    }

    // Check sandbox directory
    if config.sandbox_dir.exists() {
        println!("  Sandbox dir:  OK");
    } else {
        println!("  Sandbox dir:  MISSING");
    }

    // Ledger status
    print_ledger_status(&config)?;

    // Isolation mode and observer
    println!("  Isolation:    {}", config.isolation);
    println!("  Observer:     {}", config.observer);

    Ok(())
}

/// Print ledger disk size, entry count, integrity, session info, and denial count.
fn print_ledger_status(config: &aegis_types::AegisConfig) -> Result<()> {
    if !config.ledger_path.exists() {
        println!("  Ledger:       not yet created (will be created on first run)");
        return Ok(());
    }

    // Disk usage
    if let Ok(meta) = std::fs::metadata(&config.ledger_path) {
        let size = meta.len();
        let display = if size < 1024 {
            format!("{size} B")
        } else if size < 1024 * 1024 {
            format!("{:.1} KB", size as f64 / 1024.0)
        } else {
            format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
        };
        println!("  Ledger size:  {display}");
    }

    let store = match AuditStore::open(&config.ledger_path) {
        Ok(s) => s,
        Err(e) => {
            println!("  Ledger:       ERROR - {e}");
            return Ok(());
        }
    };

    match store.count() {
        Ok(count) => println!("  Ledger:       {count} entries"),
        Err(e) => println!("  Ledger:       ERROR counting entries - {e}"),
    }

    // Integrity
    match store.verify_integrity() {
        Ok(r) if r.valid => println!("  Integrity:    OK"),
        Ok(r) => println!("  Integrity:    FAILED - {}", r.message),
        Err(e) => println!("  Integrity:    ERROR - {e}"),
    }

    // Session info
    if let Ok(session_count) = store.count_all_sessions() {
        println!("  Sessions:     {session_count}");
    }
    if let Ok(Some(last)) = store.latest_session() {
        println!(
            "  Last session: {} ({})",
            last.start_time.format(DATETIME_SHORT_FMT),
            last.command
        );
        if let Some(tag) = &last.tag {
            println!("  Last tag:     {tag}");
        }
    }

    // Denial count
    let filter = AuditFilter::default();
    if let Ok(decisions) = store.count_by_decision(&filter) {
        let deny_count = decisions
            .iter()
            .find(|(d, _)| d == "Deny")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        if deny_count > 0 {
            println!("  Denied:       {deny_count} total");
        }
    }

    Ok(())
}
