/// Compliance reporting for the audit ledger.
///
/// Generates summary reports showing audit statistics, deny rates,
/// action breakdowns, integrity status, and policy change history.
use anyhow::{bail, Context, Result};

use aegis_ledger::{AuditFilter, AuditStore};

use crate::commands::init::load_config;

/// Run `aegis report --config NAME --format text|json`.
pub fn run(config_name: &str, format: &str) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    let stats = store
        .compute_stats(&AuditFilter::default(), config_name)
        .context("failed to compute audit stats")?;

    match format {
        "text" => print_text_report(config_name, &stats),
        "json" => print_json_report(&stats)?,
        _ => bail!("unsupported format '{format}'; valid options: text, json"),
    }

    Ok(())
}

/// Print a human-readable text report.
fn print_text_report(config_name: &str, stats: &aegis_ledger::AuditStats) {
    println!("Aegis Compliance Report");
    println!("=======================");
    println!();
    println!("Configuration: {config_name}");
    println!();

    // Summary
    println!("Summary");
    println!("-------");
    println!("  Total entries:     {}", stats.total_entries);
    println!("  Total sessions:    {}", stats.total_sessions);
    println!("  Allowed:           {}", stats.allow_count);
    println!("  Denied:            {}", stats.deny_count);
    println!("  Deny rate:         {:.1}%", stats.deny_rate * 100.0);
    println!("  Policy changes:    {}", stats.policy_changes);
    println!(
        "  Integrity:         {}",
        if stats.integrity_valid { "VALID" } else { "INVALID" }
    );
    if let (Some(earliest), Some(latest)) = (&stats.earliest_entry, &stats.latest_entry) {
        println!("  Time range:        {} to {}", earliest, latest);
    }
    println!();

    // Action breakdown
    if !stats.entries_by_action.is_empty() {
        println!("Actions by Kind");
        println!("---------------");
        for (kind, count) in &stats.entries_by_action {
            let bar = bar_chart(*count, stats.total_entries, 30);
            println!("  {:<30} {:>5}  {}", kind, count, bar);
        }
        println!();
    }

    // Principal breakdown
    if !stats.entries_by_principal.is_empty() {
        println!("Actions by Principal");
        println!("--------------------");
        for (principal, count) in &stats.entries_by_principal {
            let bar = bar_chart(*count, stats.total_entries, 30);
            println!("  {:<20} {:>5}  {}", principal, count, bar);
        }
        println!();
    }

    // Top resources
    if !stats.top_resources.is_empty() {
        println!("Top Resources");
        println!("-------------");
        for (resource, count) in &stats.top_resources {
            let bar = bar_chart(*count, stats.total_entries, 30);
            println!("  {:<40} {:>5}  {}", resource, count, bar);
        }
        println!();
    }

    if !stats.integrity_valid {
        println!("WARNING: Audit ledger integrity check FAILED. The hash chain may have been tampered with.");
    }
}

/// Print a JSON report.
fn print_json_report(stats: &aegis_ledger::AuditStats) -> Result<()> {
    let json = serde_json::to_string_pretty(stats).context("failed to serialize stats")?;
    println!("{json}");
    Ok(())
}

/// Generate a simple ASCII bar chart segment.
fn bar_chart(count: usize, total: usize, width: usize) -> String {
    if total == 0 {
        return String::new();
    }
    let filled = (count as f64 / total as f64 * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "#".repeat(filled), ".".repeat(width - filled))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_chart_full() {
        let bar = bar_chart(10, 10, 10);
        assert_eq!(bar, "##########");
    }

    #[test]
    fn bar_chart_half() {
        let bar = bar_chart(5, 10, 10);
        assert_eq!(bar, "#####.....");
    }

    #[test]
    fn bar_chart_empty() {
        let bar = bar_chart(0, 10, 10);
        assert_eq!(bar, "..........");
    }

    #[test]
    fn bar_chart_zero_total() {
        let bar = bar_chart(0, 0, 10);
        assert_eq!(bar, "");
    }

    #[test]
    fn bar_chart_count_exceeds_total() {
        // Should not overflow -- clamp to width
        let bar = bar_chart(20, 10, 10);
        assert_eq!(bar, "##########");
    }
}
