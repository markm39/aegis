//! Compliance reporting for the audit ledger.
//!
//! Generates summary reports showing audit statistics, deny rates,
//! action breakdowns, integrity status, and policy change history.

use anyhow::{bail, Context, Result};

use aegis_ledger::AuditFilter;

use crate::commands::init::open_store;

/// Run `aegis report --config NAME --format text|json`.
pub fn run(config_name: &str, format: &str) -> Result<()> {
    let (_config, store) = open_store(config_name)?;

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

    fn sample_stats() -> aegis_ledger::AuditStats {
        aegis_ledger::AuditStats {
            total_entries: 10,
            total_sessions: 2,
            allow_count: 8,
            deny_count: 2,
            deny_rate: 0.2,
            entries_by_action: vec![
                ("FileRead".into(), 6),
                ("FileWrite".into(), 4),
            ],
            entries_by_principal: vec![("test-agent".into(), 10)],
            integrity_valid: true,
            policy_changes: 1,
            top_resources: vec![("/tmp/file.txt".into(), 5)],
            earliest_entry: Some("2026-01-01T00:00:00Z".into()),
            latest_entry: Some("2026-01-01T01:00:00Z".into()),
        }
    }

    #[test]
    fn print_json_report_produces_valid_json() {
        // Verify JSON serialization works and contains expected fields
        let stats = sample_stats();
        let json = serde_json::to_string_pretty(&stats).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should be valid JSON");
        assert_eq!(parsed["total_entries"], 10);
        assert_eq!(parsed["integrity_valid"], true);
        assert_eq!(parsed["deny_count"], 2);
    }

    #[test]
    fn print_text_report_does_not_panic() {
        // Verify the text report doesn't panic with typical data
        let stats = sample_stats();
        print_text_report("test-config", &stats);
    }

    #[test]
    fn print_text_report_empty_stats() {
        // Verify the text report handles zero entries gracefully
        let stats = aegis_ledger::AuditStats {
            total_entries: 0,
            total_sessions: 0,
            allow_count: 0,
            deny_count: 0,
            deny_rate: 0.0,
            entries_by_action: vec![],
            entries_by_principal: vec![],
            integrity_valid: true,
            policy_changes: 0,
            top_resources: vec![],
            earliest_entry: None,
            latest_entry: None,
        };
        print_text_report("empty-config", &stats);
    }

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
