use anyhow::{bail, Context, Result};
use chrono::DateTime;

use aegis_ledger::{AuditEntry, AuditFilter, AuditStore};

use crate::commands::init::load_config;

/// Run `aegis audit query` with optional filters.
///
/// If `--last N` is provided with no other filters, uses the fast-path `query_last`.
/// Otherwise, builds an `AuditFilter` and uses `query_filtered`.
#[allow(clippy::too_many_arguments)]
pub fn query(
    config_name: &str,
    last: Option<usize>,
    from: Option<String>,
    to: Option<String>,
    action: Option<String>,
    decision: Option<String>,
    principal: Option<String>,
    search: Option<String>,
    page: usize,
    page_size: usize,
) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    // Fast path: --last with no other filters
    let has_filters = from.is_some()
        || to.is_some()
        || action.is_some()
        || decision.is_some()
        || principal.is_some()
        || search.is_some();

    if let Some(n) = last {
        if !has_filters {
            let entries = store.query_last(n).context("failed to query audit entries")?;
            if entries.is_empty() {
                println!("No audit entries found.");
                return Ok(());
            }
            print_table(&entries);
            return Ok(());
        }
    }

    // Build filter
    let filter = AuditFilter {
        from: from
            .map(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.into())
                    .context("invalid --from timestamp (expected RFC 3339)")
            })
            .transpose()?,
        to: to
            .map(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.into())
                    .context("invalid --to timestamp (expected RFC 3339)")
            })
            .transpose()?,
        action_kind: action,
        decision,
        principal,
        reason_contains: search,
        limit: Some(last.unwrap_or(page_size)),
        offset: if last.is_some() {
            None
        } else {
            Some((page.saturating_sub(1)) * page_size)
        },
        ..Default::default()
    };

    let (entries, total) = store
        .query_filtered(&filter)
        .context("failed to query audit entries")?;

    if entries.is_empty() {
        println!("No matching audit entries found.");
        return Ok(());
    }

    print_table(&entries);

    if total > entries.len() {
        let showing_start = filter.offset.unwrap_or(0) + 1;
        let showing_end = filter.offset.unwrap_or(0) + entries.len();
        println!("Showing {showing_start}-{showing_end} of {total} entries (page {page})");
    }

    Ok(())
}

/// Run `aegis audit verify --config NAME`.
///
/// Opens the audit store and verifies the integrity of the hash chain.
pub fn verify(config_name: &str) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    let report = store
        .verify_integrity()
        .context("failed to verify ledger integrity")?;

    println!("Integrity Report:");
    println!("  Total entries: {}", report.total_entries);
    println!(
        "  Valid:         {}",
        if report.valid { "YES" } else { "NO" }
    );
    if let Some(idx) = report.first_invalid_entry {
        println!("  First invalid: entry #{idx}");
    }
    println!("  Message:       {}", report.message);

    if !report.valid {
        std::process::exit(1);
    }

    Ok(())
}

/// Run `aegis audit export --config NAME --format json|csv`.
///
/// Exports all audit entries in the specified format.
pub fn export(config_name: &str, format: &str) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    let entries = store
        .query_last(10_000)
        .context("failed to query audit entries")?;

    match format {
        "json" => export_json(&entries)?,
        "csv" => export_csv(&entries),
        _ => bail!("unsupported format '{format}'; valid options: json, csv"),
    }

    Ok(())
}

/// Print entries in a formatted table to stdout.
fn print_table(entries: &[AuditEntry]) {
    println!(
        "{:<36}  {:<8}  {:<15}  {:<20}  ACTION",
        "ENTRY ID", "DECISION", "PRINCIPAL", "TIMESTAMP"
    );
    let separator = "-".repeat(100);
    println!("{separator}");

    for entry in entries {
        let timestamp = entry.timestamp.format("%Y-%m-%d %H:%M:%S");
        // Truncate the action_kind to fit in the table
        let action_display = if entry.action_kind.len() > 40 {
            format!("{}...", &entry.action_kind[..37])
        } else {
            entry.action_kind.clone()
        };

        println!(
            "{:<36}  {:<8}  {:<15}  {:<20}  {}",
            entry.entry_id, entry.decision, entry.principal, timestamp, action_display
        );
    }
}

/// Export entries as a JSON array.
fn export_json(entries: &[AuditEntry]) -> Result<()> {
    let json_entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "entry_id": e.entry_id.to_string(),
                "timestamp": e.timestamp.to_rfc3339(),
                "action_id": e.action_id.to_string(),
                "action_kind": e.action_kind,
                "principal": e.principal,
                "decision": e.decision,
                "reason": e.reason,
                "policy_id": e.policy_id,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            })
        })
        .collect();

    let output =
        serde_json::to_string_pretty(&json_entries).context("failed to serialize entries")?;
    println!("{output}");
    Ok(())
}

/// Export entries as CSV.
fn export_csv(entries: &[AuditEntry]) {
    println!("entry_id,timestamp,action_id,action_kind,principal,decision,reason,policy_id,prev_hash,entry_hash");
    for e in entries {
        println!(
            "{},{},{},{},{},{},{},{},{},{}",
            e.entry_id,
            e.timestamp.to_rfc3339(),
            e.action_id,
            csv_escape(&e.action_kind),
            csv_escape(&e.principal),
            e.decision,
            csv_escape(&e.reason),
            e.policy_id.as_deref().unwrap_or(""),
            e.prev_hash,
            e.entry_hash,
        );
    }
}

/// Escape a string for CSV output by quoting if it contains commas, quotes, or newlines.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
