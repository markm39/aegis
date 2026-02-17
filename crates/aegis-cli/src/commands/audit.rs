//! Audit ledger commands: query, verify, sessions, purge, watch, export.
//!
//! The audit subsystem provides forensic access to the hash-chained ledger,
//! including filtered queries, integrity verification, session management,
//! real-time streaming, and multi-format export (JSON, JSONL, CSV, CEF).

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};

use aegis_ledger::{AuditEntry, AuditFilter, AuditStore};

use crate::commands::init::load_config;

/// Filter options for `aegis audit query`, bundling all CLI filter arguments.
pub struct QueryOptions {
    pub last: Option<usize>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub action: Option<String>,
    pub decision: Option<String>,
    pub principal: Option<String>,
    pub search: Option<String>,
    pub page: usize,
    pub page_size: usize,
}

/// Run `aegis audit query` with optional filters.
///
/// If `--last N` is provided with no other filters, uses the fast-path `query_last`.
/// Otherwise, builds an `AuditFilter` and uses `query_filtered`.
pub fn query(config_name: &str, opts: QueryOptions) -> Result<()> {
    let QueryOptions {
        last,
        from,
        to,
        action,
        decision,
        principal,
        search,
        page,
        page_size,
    } = opts;
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
        "{:<36}  {:<8}  {:<20}  {:<6}  {:<6}  {:<16}  COMMAND",
        "SESSION ID", "STATUS", "START TIME", "TOTAL", "DENIED", "TAG"
    );
    let separator = "-".repeat(130);
    println!("{separator}");

    for s in &sessions {
        let status = if s.end_time.is_some() { "ended" } else { "active" };
        let start = s.start_time.format("%Y-%m-%d %H:%M:%S");
        let cmd_display = if s.args.is_empty() {
            s.command.clone()
        } else {
            format!("{} {}", s.command, s.args.join(" "))
        };
        let tag_display = s.tag.as_deref().unwrap_or("");

        println!(
            "{:<36}  {:<8}  {:<20}  {:<6}  {:<6}  {:<16}  {}",
            s.session_id, status, start, s.total_actions, s.denied_actions, tag_display, cmd_display
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
        .with_context(|| format!("invalid session UUID: '{session_id_str}'"))?;

    let session = store
        .get_session(&session_id)
        .context("failed to get session")?
        .with_context(|| format!("session not found: {session_id_str}"))?;

    println!("Session:       {}", session.session_id);
    println!("Config:        {}", session.config_name);
    if let Some(tag) = &session.tag {
        println!("Tag:           {tag}");
    }
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

/// Run `aegis audit tag NAME --id UUID --tag TAG`.
///
/// Tags an existing session with a human-readable label.
pub fn tag_session(config_name: &str, session_id_str: &str, tag: &str) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    let session_id: uuid::Uuid = session_id_str
        .parse()
        .with_context(|| format!("invalid session UUID: '{session_id_str}'"))?;

    store
        .update_session_tag(&session_id, tag)
        .context("failed to tag session")?;

    println!("Session {} tagged: {tag}", &session_id_str[..8.min(session_id_str.len())]);

    Ok(())
}

/// Run `aegis audit purge NAME --older-than DURATION --confirm`.
///
/// Deletes audit entries older than the specified duration and rebuilds
/// the hash chain for remaining entries.
pub fn purge(config_name: &str, older_than: &str, confirm: bool) -> Result<()> {
    let duration = parse_duration(older_than)?;

    if !confirm {
        // Show a preview of what would be deleted
        let cutoff = Utc::now() - duration;
        let config = load_config(config_name)?;
        let store =
            AuditStore::open(&config.ledger_path).context("failed to open audit store")?;
        let total = store.count().unwrap_or(0);

        // Count entries that would be deleted
        let filter = AuditFilter {
            to: Some(cutoff),
            ..Default::default()
        };
        let (_, would_delete) = store.query_filtered(&filter).unwrap_or((vec![], 0));

        bail!(
            "purge would delete {would_delete} of {total} entries older than {older_than}.\n\
             This is destructive and cannot be undone. Add --confirm to proceed."
        );
    }
    let cutoff = Utc::now() - duration;

    let config = load_config(config_name)?;
    let mut store =
        AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    let deleted = store
        .purge_before(cutoff)
        .context("failed to purge audit entries")?;

    if deleted == 0 {
        println!("No entries older than {older_than} found.");
    } else {
        println!("Purged {deleted} entries older than {older_than}.");
        println!("Hash chain has been rebuilt for remaining entries.");

        // Verify the rebuilt chain
        let report = store
            .verify_integrity()
            .context("failed to verify rebuilt chain")?;
        println!(
            "Integrity check: {} ({} entries remaining)",
            if report.valid { "VALID" } else { "INVALID" },
            report.total_entries
        );
    }

    Ok(())
}

/// Parse a human-readable duration string like "30d", "7d", "24h", "1h".
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        bail!("duration string is empty");
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str
        .parse()
        .with_context(|| format!("invalid duration number: '{num_str}'"))?;

    match unit {
        "d" => Ok(Duration::days(num)),
        "h" => Ok(Duration::hours(num)),
        "m" => Ok(Duration::minutes(num)),
        _ => bail!(
            "unknown duration unit '{unit}'; valid units: d (days), h (hours), m (minutes)"
        ),
    }
}

/// Run `aegis audit watch NAME [--decision Allow|Deny]`.
///
/// Streams audit events to the terminal in real-time, like `tail -f`.
/// Optionally filters by decision.
pub fn watch(config_name: &str, decision_filter: Option<&str>) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    // Start from the latest entry
    let initial = store.query_after_id(0).context("failed to query entries")?;
    let mut last_id: i64 = initial.last().map(|(id, _)| *id).unwrap_or(0);

    println!("Watching audit events for '{}' (Ctrl+C to stop)...", config_name);
    println!();

    loop {
        let new_entries = store
            .query_after_id(last_id)
            .context("failed to poll for new entries")?;

        for (row_id, entry) in &new_entries {
            // Apply decision filter
            if let Some(filter) = decision_filter {
                if entry.decision != filter {
                    last_id = *row_id;
                    continue;
                }
            }

            let timestamp = entry.timestamp.format("%H:%M:%S");
            let decision_marker = if entry.decision == "Deny" {
                "DENY "
            } else {
                "ALLOW"
            };

            // Parse action_kind for display
            let action_display = crate::commands::diff::extract_resource_key(&entry.action_kind);

            println!(
                "[{timestamp}] {decision_marker}  {:<15}  {action_display}",
                entry.principal
            );

            last_id = *row_id;
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Run `aegis audit export --config NAME --format json|jsonl|csv|cef [--limit N] [--follow]`.
///
/// Exports audit entries in the specified format. With `--follow`, polls for
/// new entries every second (like `tail -f`).
pub fn export(config_name: &str, format: &str, limit: usize, follow: bool) -> Result<()> {
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
        .query_last(limit)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_days() {
        let d = parse_duration("30d").unwrap();
        assert_eq!(d.num_days(), 30);
    }

    #[test]
    fn parse_duration_hours() {
        let d = parse_duration("24h").unwrap();
        assert_eq!(d.num_hours(), 24);
    }

    #[test]
    fn parse_duration_minutes() {
        let d = parse_duration("60m").unwrap();
        assert_eq!(d.num_minutes(), 60);
    }

    #[test]
    fn parse_duration_invalid_unit() {
        assert!(parse_duration("30x").is_err());
    }

    #[test]
    fn parse_duration_empty() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn parse_duration_no_number() {
        assert!(parse_duration("d").is_err());
    }

    #[test]
    fn csv_escape_no_special_chars() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn csv_escape_with_comma() {
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
    }

    #[test]
    fn csv_escape_with_quotes() {
        assert_eq!(csv_escape(r#"say "hi""#), r#""say ""hi""""#);
    }

    #[test]
    fn csv_escape_with_newline() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn cef_escape_pipes_and_backslashes() {
        assert_eq!(cef_escape("a|b\\c"), "a\\|b\\\\c");
    }

    #[test]
    fn cef_escape_equals_and_newlines() {
        assert_eq!(cef_escape("key=val\nnext"), "key\\=val\\nnext");
    }

    #[test]
    fn parse_duration_whitespace_trimmed() {
        let d = parse_duration("  7d  ").unwrap();
        assert_eq!(d.num_days(), 7);
    }

    #[test]
    fn parse_duration_single_day() {
        let d = parse_duration("1d").unwrap();
        assert_eq!(d.num_days(), 1);
    }

    #[test]
    fn parse_duration_large_number() {
        let d = parse_duration("365d").unwrap();
        assert_eq!(d.num_days(), 365);
    }

    #[test]
    fn parse_duration_multi_char_unit_fails() {
        // "30dd" -> tries to parse "30d" as number, which fails
        assert!(parse_duration("30dd").is_err());
    }

    #[test]
    fn csv_escape_combined_special_chars() {
        assert_eq!(csv_escape("a,b\"c\nd"), "\"a,b\"\"c\nd\"");
    }

    #[test]
    fn cef_escape_clean_string() {
        assert_eq!(cef_escape("simple"), "simple");
    }
}
