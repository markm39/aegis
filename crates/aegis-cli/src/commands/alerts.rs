//! Alert management commands: list, test, history.
//!
//! These commands manage the webhook alerting subsystem configured via
//! `[[alerts]]` sections in `aegis.toml`.

use anyhow::{Context, Result, bail};
use rusqlite::Connection;

use crate::commands::DATETIME_FULL_FMT;
use crate::commands::init::open_store;

/// List all configured alert rules for a given config.
pub fn list(config_name: &str) -> Result<()> {
    let (config, _store) = open_store(config_name)?;

    if config.alerts.is_empty() {
        println!("No alert rules configured in {config_name}.");
        println!("Add [[alerts]] sections to aegis.toml to enable webhook alerting.");
        return Ok(());
    }

    println!("Alert rules for {config_name}:");
    println!("{}", "-".repeat(80));

    for (i, rule) in config.alerts.iter().enumerate() {
        println!("  [{}] {}", i + 1, rule.name);
        println!("      URL:       {}", rule.webhook_url);
        if let Some(ref d) = rule.decision {
            println!("      Decision:  {d}");
        }
        if !rule.action_kinds.is_empty() {
            println!("      Actions:   {}", rule.action_kinds.join(", "));
        }
        if let Some(ref g) = rule.path_glob {
            println!("      Path glob: {g}");
        }
        if let Some(ref p) = rule.principal {
            println!("      Principal: {p}");
        }
        println!("      Cooldown:  {}s", rule.cooldown_secs);
        println!();
    }

    println!("{} rule(s) configured.", config.alerts.len());
    Ok(())
}

/// Send a test webhook to verify connectivity for alert rules.
///
/// If `rule_name` is `Some`, tests only that specific rule. Otherwise, tests all rules.
pub fn test(config_name: &str, rule_name: Option<&str>) -> Result<()> {
    let (config, _store) = open_store(config_name)?;

    if config.alerts.is_empty() {
        bail!("No alert rules configured in {config_name}. Add [[alerts]] sections to aegis.toml.");
    }

    let rules_to_test: Vec<_> = match rule_name {
        Some(name) => {
            let rule = config
                .alerts
                .iter()
                .find(|r| r.name == name)
                .ok_or_else(|| {
                    anyhow::anyhow!("no alert rule named {:?} in {config_name}", name)
                })?;
            vec![rule]
        }
        None => config.alerts.iter().collect(),
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    for rule in &rules_to_test {
        print!("Testing {:?} -> {} ... ", rule.name, rule.webhook_url);

        let result = rt.block_on(aegis_alert::dispatcher::send_test_webhook(
            rule,
            &config.name,
        ));

        match result {
            Ok(status) => println!("OK (HTTP {status})"),
            Err(e) => println!("FAILED: {e}"),
        }
    }

    Ok(())
}

/// Show recent alert dispatch history from the alert_log table.
pub fn history(config_name: &str, last: u32) -> Result<()> {
    let (config, _store) = open_store(config_name)?;

    let conn = Connection::open(&config.ledger_path)
        .context("failed to open ledger database for alert history")?;

    // Initialize the alert_log table if it doesn't exist yet.
    aegis_alert::log::init_table(&conn).context("failed to initialize alert_log table")?;

    let entries =
        aegis_alert::log::recent_entries(&conn, last).context("failed to query alert history")?;

    if entries.is_empty() {
        println!("No alert dispatch history for {config_name}.");
        return Ok(());
    }

    println!(
        "{:<20} {:<16} {:<8} {:<8} ENTRY ID",
        "FIRED AT", "RULE", "STATUS", "OK"
    );
    println!("{}", "-".repeat(90));

    for entry in &entries {
        let fired = entry.fired_at.format(DATETIME_FULL_FMT).to_string();
        let status = entry
            .status_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".into());
        let ok = if entry.success { "yes" } else { "no" };

        println!(
            "{:<20} {:<16} {:<8} {:<8} {}",
            fired,
            truncate(&entry.rule_name, 15),
            status,
            ok,
            truncate(&entry.entry_id, 36),
        );

        if let Some(ref err) = entry.error {
            println!("  error: {err}");
        }
    }

    println!();
    println!("{} dispatch(es) shown.", entries.len());
    Ok(())
}

/// Truncate a string to `max_len` characters, appending "..." if needed.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
