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

/// Run `aegis audit sessions --config NAME --last N`.
///
/// Lists recent sessions in a formatted table.
pub fn list_sessions(config_name: &str, last: usize) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    let sessions = store
        .list_sessions(last, 0)
        .context("failed to list sessions")?;

    if sessions.is_empty() {
        println!("No sessions found.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<8}  {:<20}  {:<6}  {:<6}  COMMAND",
        "SESSION ID", "STATUS", "START TIME", "TOTAL", "DENIED"
    );
    let separator = "-".repeat(110);
    println!("{separator}");

    for s in &sessions {
        let status = if s.end_time.is_some() { "ended" } else { "active" };
        let start = s.start_time.format("%Y-%m-%d %H:%M:%S");
        let cmd_display = if s.args.is_empty() {
            s.command.clone()
        } else {
            format!("{} {}", s.command, s.args.join(" "))
        };

        println!(
            "{:<36}  {:<8}  {:<20}  {:<6}  {:<6}  {}",
            s.session_id, status, start, s.total_actions, s.denied_actions, cmd_display
        );
    }

    Ok(())
}

/// Run `aegis audit session --config NAME --id UUID`.
///
/// Shows details of a single session and its audit entries.
pub fn show_session(config_name: &str, session_id_str: &str) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    let session_id: uuid::Uuid = session_id_str
        .parse()
        .context("invalid session UUID")?;

    let session = store
        .get_session(&session_id)
        .context("failed to get session")?
        .context("session not found")?;

    println!("Session:       {}", session.session_id);
    println!("Config:        {}", session.config_name);
    println!("Command:       {} {}", session.command, session.args.join(" "));
    println!("Start time:    {}", session.start_time.format("%Y-%m-%d %H:%M:%S UTC"));
    if let Some(end) = session.end_time {
        println!("End time:      {}", end.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("End time:      (still running)");
    }
    if let Some(code) = session.exit_code {
        println!("Exit code:     {code}");
    }
    println!("Total actions: {}", session.total_actions);
    println!("Denied:        {}", session.denied_actions);

    let entries = store
        .query_by_session(&session_id)
        .context("failed to query session entries")?;

    if !entries.is_empty() {
        println!();
        println!("Entries:");
        print_table(&entries);
    }

    Ok(())
}

/// Run `aegis audit policy-history --config NAME --last N`.
///
/// Shows the history of policy changes for a configuration.
pub fn policy_history(config_name: &str, last: usize) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    let snapshots = store
        .list_policy_snapshots(config_name, last)
        .context("failed to list policy snapshots")?;

    if snapshots.is_empty() {
        println!("No policy snapshots found.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<20}  {:<8}  HASH (first 16)",
        "SNAPSHOT ID", "TIMESTAMP", "FILES"
    );
    let separator = "-".repeat(90);
    println!("{separator}");

    for s in &snapshots {
        let hash_short = if s.policy_hash.len() >= 16 {
            &s.policy_hash[..16]
        } else {
            &s.policy_hash
        };
        let timestamp = s.timestamp.format("%Y-%m-%d %H:%M:%S");

        println!(
            "{:<36}  {:<20}  {:<8}  {}",
            s.snapshot_id,
            timestamp,
            s.policy_files.len(),
            hash_short,
        );
    }

    Ok(())
}

/// Run `aegis audit export --config NAME --format json|jsonl|csv|cef [--follow]`.
///
/// Exports audit entries in the specified format. With `--follow`, polls for
/// new entries every second (like `tail -f`).
pub fn export(config_name: &str, format: &str, follow: bool) -> Result<()> {
    // Validate format up front
    if !matches!(format, "json" | "jsonl" | "csv" | "cef") {
        bail!("unsupported format '{format}'; valid options: json, jsonl, csv, cef");
    }

    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    if follow {
        return export_follow(&store, format);
    }

    let entries = store
        .query_last(10_000)
        .context("failed to query audit entries")?;

    match format {
        "json" => export_json(&entries)?,
        "jsonl" => export_jsonl(&entries),
        "csv" => export_csv(&entries),
        "cef" => export_cef(&entries),
        _ => unreachable!(),
    }

    Ok(())
}

/// Follow mode: poll for new entries and emit them in the given format.
fn export_follow(store: &AuditStore, format: &str) -> Result<()> {
    // Start from the latest entry
    let initial = store.query_after_id(0).context("failed to query entries")?;
    let mut last_id: i64 = initial.last().map(|(id, _)| *id).unwrap_or(0);

    // Print header for CSV
    if format == "csv" {
        println!("entry_id,timestamp,action_id,action_kind,principal,decision,reason,policy_id,prev_hash,entry_hash");
    }

    loop {
        let new_entries = store
            .query_after_id(last_id)
            .context("failed to poll for new entries")?;

        for (row_id, entry) in &new_entries {
            match format {
                "jsonl" => print_jsonl_entry(entry),
                "csv" => print_csv_entry(entry),
                "cef" => print_cef_entry(entry),
                "json" => print_jsonl_entry(entry), // in follow mode, json acts as jsonl
                _ => unreachable!(),
            }
            last_id = *row_id;
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
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

/// Export entries as JSONL (JSON Lines) -- one JSON object per line.
///
/// Standard format for Splunk, Datadog, Elastic, and other log aggregators.
fn export_jsonl(entries: &[AuditEntry]) {
    for e in entries {
        print_jsonl_entry(e);
    }
}

/// Print a single entry as a JSONL line.
fn print_jsonl_entry(e: &AuditEntry) {
    let json = serde_json::json!({
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
    });
    // Compact single-line format
    println!("{}", serde_json::to_string(&json).unwrap_or_default());
}

/// Print a single entry as a CSV row (no header).
fn print_csv_entry(e: &AuditEntry) {
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

/// Export entries in CEF (Common Event Format).
///
/// CEF is a standard log format used by ArcSight, QRadar, and other SIEM
/// platforms. Format: `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions`
fn export_cef(entries: &[AuditEntry]) {
    for e in entries {
        print_cef_entry(e);
    }
}

/// Print a single entry in CEF format.
fn print_cef_entry(e: &AuditEntry) {
    let severity = if e.decision == "Deny" { 7 } else { 3 };
    let signature_id = &e.action_kind;
    let name = format!("{} {}", e.decision, e.action_kind);

    // CEF extensions use key=value pairs separated by spaces
    println!(
        "CEF:0|Aegis|Runtime|0.1.0|{sig}|{name}|{sev}|rt={ts} src={principal} act={action} reason={reason} entryId={eid} policyId={pid}",
        sig = cef_escape(signature_id),
        name = cef_escape(&name),
        sev = severity,
        ts = e.timestamp.to_rfc3339(),
        principal = cef_escape(&e.principal),
        action = cef_escape(&e.action_kind),
        reason = cef_escape(&e.reason),
        eid = e.entry_id,
        pid = e.policy_id.as_deref().unwrap_or("none"),
    );
}

/// Escape a string for CEF format (pipes and backslashes in header,
/// equals and newlines in extensions).
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace('\n', "\\n")
}

/// Escape a string for CSV output by quoting if it contains commas, quotes, or newlines.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
