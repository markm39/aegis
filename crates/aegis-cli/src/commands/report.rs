//! Compliance reporting for the audit ledger.
//!
//! Generates summary reports showing audit statistics, deny rates,
//! action breakdowns, integrity status, and policy change history.

use anyhow::{Context, Result, bail};

use aegis_ledger::AuditFilter;
use aegis_types::ActionKind;
use serde::{Deserialize, Serialize};

use aegis_control::daemon::RuntimeAuditProvenance;

use crate::commands::init::open_store;

/// Run `aegis report --config NAME --format text|json`.
pub fn run(config_name: &str, format: &str) -> Result<()> {
    let (_config, store) = open_store(config_name)?;

    let stats = store
        .compute_stats(&AuditFilter::default(), config_name)
        .context("failed to compute audit stats")?;
    let runtime = compute_runtime_summary(&store, stats.total_entries)
        .context("failed to compute runtime compliance summary")?;
    let report = ComplianceReport {
        stats: stats.clone(),
        runtime,
    };

    match format {
        "text" => print_text_report(config_name, &report),
        "json" => print_json_report(&report)?,
        _ => bail!("unsupported format '{format}'; valid options: text, json"),
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComplianceReport {
    #[serde(flatten)]
    stats: aegis_ledger::AuditStats,
    runtime: RuntimeComplianceSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RuntimeComplianceSummary {
    total_runtime_actions: usize,
    allow_count: usize,
    deny_count: usize,
    by_operation: Vec<(String, usize)>,
    by_risk_tag: Vec<(String, usize)>,
    by_agent: Vec<(String, usize)>,
    median_capture_latency_ms: Option<u64>,
    median_input_latency_ms: Option<u64>,
}

/// Print a human-readable text report.
fn print_text_report(config_name: &str, report: &ComplianceReport) {
    let stats = &report.stats;
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
        if stats.integrity_valid {
            "VALID"
        } else {
            "INVALID"
        }
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
        println!(
            "WARNING: Audit ledger integrity check FAILED. The hash chain may have been tampered with."
        );
    }

    if report.runtime.total_runtime_actions > 0 {
        println!();
        println!("Runtime Computer-Use Mediation");
        println!("------------------------------");
        println!(
            "  Runtime actions:   {}",
            report.runtime.total_runtime_actions
        );
        println!("  Runtime allows:    {}", report.runtime.allow_count);
        println!("  Runtime denies:    {}", report.runtime.deny_count);
        if let Some(ms) = report.runtime.median_capture_latency_ms {
            println!("  Median capture:    {ms} ms");
        }
        if let Some(ms) = report.runtime.median_input_latency_ms {
            println!("  Median input:      {ms} ms");
        }

        if !report.runtime.by_risk_tag.is_empty() {
            println!();
            println!("  By risk tag:");
            for (risk, count) in &report.runtime.by_risk_tag {
                println!("    {:<12} {}", risk, count);
            }
        }
        if !report.runtime.by_operation.is_empty() {
            println!();
            println!("  By operation:");
            for (op, count) in &report.runtime.by_operation {
                println!("    {:<20} {}", op, count);
            }
        }
    }
}

/// Print a JSON report.
fn print_json_report(report: &ComplianceReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report).context("failed to serialize stats")?;
    println!("{json}");
    Ok(())
}

fn compute_runtime_summary(
    store: &aegis_ledger::AuditStore,
    total_entries: usize,
) -> Result<RuntimeComplianceSummary> {
    let entries = store
        .query_last(total_entries.max(1))
        .context("failed to query audit entries")?;
    let mut summary = RuntimeComplianceSummary::default();
    let mut by_operation = std::collections::HashMap::<String, usize>::new();
    let mut by_risk = std::collections::HashMap::<String, usize>::new();
    let mut by_agent = std::collections::HashMap::<String, usize>::new();
    let mut capture_latencies = Vec::new();
    let mut input_latencies = Vec::new();

    for entry in entries {
        let kind: ActionKind = match serde_json::from_str(&entry.action_kind) {
            Ok(kind) => kind,
            Err(_) => continue,
        };
        let ActionKind::ToolCall { tool, args } = kind else {
            continue;
        };
        if tool != "RuntimeComputerUse" {
            continue;
        }
        let provenance: RuntimeAuditProvenance = match serde_json::from_value(args) {
            Ok(p) => p,
            Err(_) => continue,
        };

        summary.total_runtime_actions += 1;
        if provenance.decision == "allow" {
            summary.allow_count += 1;
        } else {
            summary.deny_count += 1;
        }

        *by_operation
            .entry(format!("{:?}", provenance.operation).to_ascii_lowercase())
            .or_insert(0) += 1;
        *by_risk
            .entry(format!("{:?}", provenance.risk_tag).to_ascii_lowercase())
            .or_insert(0) += 1;
        *by_agent.entry(provenance.agent.clone()).or_insert(0) += 1;

        if let Some(ms) = provenance.outcome.result.capture_latency_ms {
            capture_latencies.push(ms);
        }
        if let Some(ms) = provenance.outcome.result.input_latency_ms {
            input_latencies.push(ms);
        }
    }

    summary.by_operation = sorted_counts(by_operation);
    summary.by_risk_tag = sorted_counts(by_risk);
    summary.by_agent = sorted_counts(by_agent);
    summary.median_capture_latency_ms = median_u64(&mut capture_latencies);
    summary.median_input_latency_ms = median_u64(&mut input_latencies);
    Ok(summary)
}

fn sorted_counts(map: std::collections::HashMap<String, usize>) -> Vec<(String, usize)> {
    let mut v: Vec<(String, usize)> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

fn median_u64(values: &mut [u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        Some(values[mid])
    } else {
        Some((values[mid - 1] + values[mid]) / 2)
    }
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
            entries_by_action: vec![("FileRead".into(), 6), ("FileWrite".into(), 4)],
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
        let report = ComplianceReport {
            stats,
            runtime: RuntimeComplianceSummary::default(),
        };
        let json = serde_json::to_string_pretty(&report).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should be valid JSON");
        assert_eq!(parsed["total_entries"], 10);
        assert_eq!(parsed["integrity_valid"], true);
        assert_eq!(parsed["deny_count"], 2);
        assert!(parsed["runtime"].is_object());
    }

    #[test]
    fn print_text_report_does_not_panic() {
        // Verify the text report doesn't panic with typical data
        let report = ComplianceReport {
            stats: sample_stats(),
            runtime: RuntimeComplianceSummary::default(),
        };
        print_text_report("test-config", &report);
    }

    #[test]
    fn print_text_report_empty_stats() {
        // Verify the text report handles zero entries gracefully
        let report = ComplianceReport {
            stats: aegis_ledger::AuditStats {
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
            },
            runtime: RuntimeComplianceSummary::default(),
        };
        print_text_report("empty-config", &report);
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
