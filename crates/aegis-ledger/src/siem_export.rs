//! SIEM export for audit log entries.
//!
//! Supports exporting audit entries in standard formats for integration with
//! Security Information and Event Management systems:
//!
//! - **CEF** (Common Event Format): `CEF:0|Aegis|AuditLog|1.0|action|desc|severity|ext`
//! - **JSON Lines**: One JSON object per line (newline-delimited JSON).
//!
//! All output is sanitized to prevent injection attacks (e.g., pipe characters
//! in CEF fields, control characters in JSON values).

use chrono::DateTime;
use rusqlite::params;
use serde::Serialize;

use aegis_types::AegisError;

use crate::entry::AuditEntry;
use crate::parse_helpers::{parse_datetime, parse_uuid};
use crate::store::AuditStore;

/// Supported SIEM export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemFormat {
    /// Common Event Format (CEF) -- one CEF line per entry.
    Cef,
    /// JSON Lines (NDJSON) -- one JSON object per line.
    JsonLines,
}

/// CEF severity mapping from audit decision.
///
/// Maps action decisions to CEF severity levels (0-10):
/// - Allow: 1 (informational)
/// - Deny: 7 (high -- a policy violation was blocked)
fn cef_severity(decision: &str) -> u8 {
    match decision {
        "Allow" => 1,
        "Deny" => 7,
        _ => 5, // unknown defaults to medium
    }
}

/// Sanitize a string for use in a CEF field.
///
/// CEF uses pipe (`|`) as a delimiter in the header and backslash (`\`) as
/// an escape character. This function escapes both to prevent field injection.
/// It also strips control characters that could break log parsers.
fn sanitize_cef_field(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '|' => result.push_str("\\|"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            c if c.is_control() => {} // strip other control characters
            c => result.push(c),
        }
    }
    result
}

/// Sanitize a string for use in a CEF extension value.
///
/// CEF extension values use `=` as key-value separator and newlines as
/// field separators. Escape both, plus backslash.
fn sanitize_cef_extension(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '=' => result.push_str("\\="),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            c if c.is_control() => {} // strip other control characters
            c => result.push(c),
        }
    }
    result
}

/// Format a single audit entry as a CEF line.
///
/// Format: `CEF:0|Aegis|AuditLog|1.0|action_kind_variant|reason|severity|extensions`
fn format_cef_entry(entry: &AuditEntry) -> String {
    let action_variant = extract_action_variant(&entry.action_kind);
    let severity = cef_severity(&entry.decision);

    let extensions = format!(
        "src={} act={} outcome={} reason={} entryId={} prevHash={} entryHash={} rt={}",
        sanitize_cef_extension(&entry.principal),
        sanitize_cef_extension(&entry.action_kind),
        sanitize_cef_extension(&entry.decision),
        sanitize_cef_extension(&entry.reason),
        sanitize_cef_extension(&entry.entry_id.to_string()),
        sanitize_cef_extension(&entry.prev_hash),
        sanitize_cef_extension(&entry.entry_hash),
        entry.timestamp.timestamp_millis(),
    );

    format!(
        "CEF:0|Aegis|AuditLog|1.0|{}|{}|{}|{}",
        sanitize_cef_field(&action_variant),
        sanitize_cef_field(&entry.reason),
        severity,
        extensions
    )
}

/// A JSON Lines entry with all audit fields.
#[derive(Serialize)]
struct JsonLinesEntry<'a> {
    entry_id: String,
    timestamp: String,
    action_id: String,
    action_kind: &'a str,
    principal: &'a str,
    decision: &'a str,
    reason: &'a str,
    policy_id: Option<&'a str>,
    prev_hash: &'a str,
    entry_hash: &'a str,
}

/// Format a single audit entry as a JSON Lines record.
fn format_json_lines_entry(entry: &AuditEntry) -> Result<String, AegisError> {
    let jl = JsonLinesEntry {
        entry_id: entry.entry_id.to_string(),
        timestamp: entry.timestamp.to_rfc3339(),
        action_id: entry.action_id.to_string(),
        action_kind: &entry.action_kind,
        principal: &entry.principal,
        decision: &entry.decision,
        reason: &entry.reason,
        policy_id: entry.policy_id.as_deref(),
        prev_hash: &entry.prev_hash,
        entry_hash: &entry.entry_hash,
    };
    serde_json::to_string(&jl)
        .map_err(|e| AegisError::LedgerError(format!("failed to serialize SIEM JSON entry: {e}")))
}

/// Extract the action variant name from a JSON-serialized `ActionKind`.
///
/// Given `{"FileWrite":{"path":"/foo"}}`, returns `"FileWrite"`.
/// Falls back to the full string if parsing fails.
fn extract_action_variant(action_kind_json: &str) -> String {
    let start = action_kind_json.find('"').map(|i| i + 1);
    let end = start.and_then(|s| action_kind_json[s..].find('"').map(|e| s + e));
    match (start, end) {
        (Some(s), Some(e)) => action_kind_json[s..e].to_string(),
        _ => action_kind_json.to_string(),
    }
}

impl AuditStore {
    /// Export audit entries in the specified SIEM format.
    ///
    /// Returns entries created at or after `since` as a single string in
    /// the requested format. Each entry occupies one line.
    ///
    /// # Formats
    ///
    /// - [`SiemFormat::Cef`]: Common Event Format lines, sanitized against
    ///   pipe/backslash injection.
    /// - [`SiemFormat::JsonLines`]: Newline-delimited JSON objects.
    pub fn siem_export(
        &self,
        format: SiemFormat,
        since: DateTime<chrono::Utc>,
    ) -> Result<String, AegisError> {
        let since_str = since.to_rfc3339();

        let mut stmt = self
            .connection()
            .prepare(
                "SELECT entry_id, timestamp, action_id, action_kind, principal, decision, reason, policy_id, prev_hash, entry_hash
                 FROM audit_log WHERE timestamp >= ?1 ORDER BY id ASC",
            )
            .map_err(|e| AegisError::LedgerError(format!("siem_export prepare: {e}")))?;

        let rows = stmt
            .query_map(params![since_str], |row| {
                Ok(AuditEntry {
                    entry_id: parse_uuid(&row.get::<_, String>(0)?, 0)?,
                    timestamp: parse_datetime(&row.get::<_, String>(1)?, 1)?,
                    action_id: parse_uuid(&row.get::<_, String>(2)?, 2)?,
                    action_kind: row.get(3)?,
                    principal: row.get(4)?,
                    decision: row.get(5)?,
                    reason: row.get(6)?,
                    policy_id: row.get(7)?,
                    prev_hash: row.get(8)?,
                    entry_hash: row.get(9)?,
                })
            })
            .map_err(|e| AegisError::LedgerError(format!("siem_export query: {e}")))?;

        let entries: Vec<AuditEntry> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("siem_export read: {e}")))?;

        let mut output = String::new();
        for entry in &entries {
            match format {
                SiemFormat::Cef => {
                    output.push_str(&format_cef_entry(entry));
                    output.push('\n');
                }
                SiemFormat::JsonLines => {
                    output.push_str(&format_json_lines_entry(entry)?);
                    output.push('\n');
                }
            }
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::{Action, ActionKind, Verdict};
    use std::path::PathBuf;

    use crate::test_helpers::test_db_path;

    fn sample_action(principal: &str) -> Action {
        Action::new(
            principal,
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        )
    }

    #[test]
    fn siem_cef_export_format() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let action = sample_action("agent-1");
        let verdict = Verdict::deny(action.id, "blocked by policy", Some("pol-1".into()));
        store.append(&action, &verdict).unwrap();

        let since = chrono::Utc::now() - chrono::Duration::seconds(60);
        let output = store.siem_export(SiemFormat::Cef, since).unwrap();

        assert!(!output.is_empty());
        let line = output.lines().next().unwrap();

        // Verify CEF header structure
        assert!(
            line.starts_with("CEF:0|Aegis|AuditLog|1.0|"),
            "line: {line}"
        );

        // Verify severity mapping for Deny (should be 7)
        let parts: Vec<&str> = line.splitn(8, '|').collect();
        assert_eq!(parts.len(), 8, "CEF should have 8 pipe-delimited fields");
        assert_eq!(parts[0], "CEF:0");
        assert_eq!(parts[1], "Aegis");
        assert_eq!(parts[2], "AuditLog");
        assert_eq!(parts[3], "1.0");
        assert_eq!(parts[4], "FileRead"); // action variant
        assert_eq!(parts[5], "blocked by policy"); // description
        assert_eq!(parts[6], "7"); // severity for Deny

        // Verify extensions contain expected keys
        let extensions = parts[7];
        assert!(extensions.contains("src=agent-1"), "ext: {extensions}");
        assert!(extensions.contains("outcome=Deny"), "ext: {extensions}");
        assert!(
            extensions.contains("reason=blocked by policy"),
            "ext: {extensions}"
        );
    }

    #[test]
    fn siem_cef_export_allow_severity() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let action = sample_action("agent-1");
        let verdict = Verdict::allow(action.id, "permitted", None);
        store.append(&action, &verdict).unwrap();

        let since = chrono::Utc::now() - chrono::Duration::seconds(60);
        let output = store.siem_export(SiemFormat::Cef, since).unwrap();
        let line = output.lines().next().unwrap();

        let parts: Vec<&str> = line.splitn(8, '|').collect();
        assert_eq!(parts[6], "1"); // severity for Allow
    }

    #[test]
    fn siem_json_lines_export() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let action = sample_action("agent-1");
        let verdict = Verdict::allow(action.id, "permitted", None);
        store.append(&action, &verdict).unwrap();

        let action2 = sample_action("agent-2");
        let verdict2 = Verdict::deny(action2.id, "blocked", Some("pol-2".into()));
        store.append(&action2, &verdict2).unwrap();

        let since = chrono::Utc::now() - chrono::Duration::seconds(60);
        let output = store.siem_export(SiemFormat::JsonLines, since).unwrap();

        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("invalid JSON line: {e}\nline: {line}"));
            assert!(parsed.is_object());
            assert!(parsed["entry_id"].is_string());
            assert!(parsed["timestamp"].is_string());
            assert!(parsed["principal"].is_string());
            assert!(parsed["decision"].is_string());
            assert!(parsed["prev_hash"].is_string());
            assert!(parsed["entry_hash"].is_string());
        }

        // Verify content of first entry
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["principal"], "agent-1");
        assert_eq!(first["decision"], "Allow");
        assert_eq!(first["reason"], "permitted");

        // Verify content of second entry
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["principal"], "agent-2");
        assert_eq!(second["decision"], "Deny");
        assert_eq!(second["policy_id"], "pol-2");
    }

    #[test]
    fn siem_export_empty_when_no_entries() {
        let tmp = test_db_path();
        let store = AuditStore::open(tmp.path()).unwrap();

        let since = chrono::Utc::now() - chrono::Duration::seconds(60);
        let cef = store.siem_export(SiemFormat::Cef, since).unwrap();
        assert!(cef.is_empty());

        let jsonl = store.siem_export(SiemFormat::JsonLines, since).unwrap();
        assert!(jsonl.is_empty());
    }

    #[test]
    fn siem_cef_sanitizes_pipe_injection() {
        // Security test: verify that pipe characters in user-controlled
        // fields are escaped to prevent CEF field injection.
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let action = Action::new(
            "agent|injected",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let verdict = Verdict::deny(action.id, "reason|with|pipes", None);
        store.append(&action, &verdict).unwrap();

        let since = chrono::Utc::now() - chrono::Duration::seconds(60);
        let output = store.siem_export(SiemFormat::Cef, since).unwrap();
        let line = output.lines().next().unwrap();

        // Verify the raw CEF line contains escaped pipes in the header's
        // Name field (the reason). The reason "reason|with|pipes" must
        // appear as "reason\|with\|pipes" to prevent field injection.
        assert!(
            line.contains("reason\\|with\\|pipes"),
            "CEF output must escape pipes in the reason field: {line}"
        );

        // Verify the CEF header prefix is intact
        assert!(
            line.starts_with("CEF:0|Aegis|AuditLog|1.0|FileRead|"),
            "CEF header prefix must be intact: {line}"
        );

        // Verify the extensions contain the principal (pipes in extension
        // values are not delimiters, so they don't need escaping there).
        assert!(
            line.contains("src=agent|injected"),
            "principal should appear in extensions: {line}"
        );
    }

    #[test]
    fn siem_export_since_filter() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        // Insert an entry
        let action = sample_action("agent-1");
        let verdict = Verdict::allow(action.id, "ok", None);
        store.append(&action, &verdict).unwrap();

        // Export with a future timestamp should return nothing
        let future = chrono::Utc::now() + chrono::Duration::seconds(60);
        let output = store.siem_export(SiemFormat::JsonLines, future).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn sanitize_cef_field_escapes_correctly() {
        assert_eq!(sanitize_cef_field("normal text"), "normal text");
        assert_eq!(sanitize_cef_field("pipe|here"), "pipe\\|here");
        assert_eq!(sanitize_cef_field("back\\slash"), "back\\\\slash");
        assert_eq!(sanitize_cef_field("new\nline"), "new\\nline");
        assert_eq!(sanitize_cef_field("cr\rreturn"), "cr\\rreturn");
        assert_eq!(sanitize_cef_field("tab\there"), "tabhere"); // control chars stripped
    }

    #[test]
    fn sanitize_cef_extension_escapes_correctly() {
        assert_eq!(sanitize_cef_extension("normal text"), "normal text");
        assert_eq!(sanitize_cef_extension("key=value"), "key\\=value");
        assert_eq!(sanitize_cef_extension("back\\slash"), "back\\\\slash");
        assert_eq!(sanitize_cef_extension("new\nline"), "new\\nline");
    }

    #[test]
    fn cef_severity_mapping() {
        assert_eq!(cef_severity("Allow"), 1);
        assert_eq!(cef_severity("Deny"), 7);
        assert_eq!(cef_severity("Unknown"), 5);
    }
}
