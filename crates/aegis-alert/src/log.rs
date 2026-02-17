//! Alert dispatch history recording in SQLite.
//!
//! The `alert_log` table records every webhook dispatch attempt, including
//! whether it succeeded and the HTTP status code. This provides an audit
//! trail for alert reliability and is queryable via `aegis alerts history`.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

/// SQL to create the alert_log table.
pub const CREATE_TABLE_SQL: &str = "
    CREATE TABLE IF NOT EXISTS alert_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id    TEXT NOT NULL,
        rule_name   TEXT NOT NULL,
        entry_id    TEXT NOT NULL,
        fired_at    TEXT NOT NULL,
        webhook_url TEXT NOT NULL,
        status_code INTEGER,
        success     INTEGER NOT NULL DEFAULT 0,
        error       TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
";

/// A single alert dispatch record from the log.
#[derive(Debug, Clone)]
pub struct AlertLogEntry {
    /// Auto-incrementing row ID.
    pub id: i64,
    /// Unique alert dispatch ID.
    pub alert_id: String,
    /// Name of the rule that fired.
    pub rule_name: String,
    /// Audit entry ID that triggered the alert.
    pub entry_id: String,
    /// When the alert was dispatched.
    pub fired_at: DateTime<Utc>,
    /// Webhook URL that was called.
    pub webhook_url: String,
    /// HTTP status code from the webhook response, if any.
    pub status_code: Option<i32>,
    /// Whether the dispatch was considered successful.
    pub success: bool,
    /// Error message if the dispatch failed.
    pub error: Option<String>,
}

/// Initialize the alert_log table in the given connection.
pub fn init_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(CREATE_TABLE_SQL)
}

/// Record an alert dispatch in the log.
#[allow(clippy::too_many_arguments)]
pub fn record_dispatch(
    conn: &Connection,
    alert_id: &str,
    rule_name: &str,
    entry_id: &str,
    fired_at: DateTime<Utc>,
    webhook_url: &str,
    status_code: Option<i32>,
    success: bool,
    error: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO alert_log (alert_id, rule_name, entry_id, fired_at, webhook_url, status_code, success, error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            alert_id,
            rule_name,
            entry_id,
            fired_at.to_rfc3339(),
            webhook_url,
            status_code,
            success as i32,
            error,
        ],
    )?;
    Ok(())
}

/// Query the most recent N alert log entries, ordered newest first.
pub fn recent_entries(conn: &Connection, limit: u32) -> rusqlite::Result<Vec<AlertLogEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, alert_id, rule_name, entry_id, fired_at, webhook_url, status_code, success, error
         FROM alert_log
         ORDER BY id DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![limit], |row| {
        let fired_at_str: String = row.get(4)?;
        let fired_at = DateTime::parse_from_rfc3339(&fired_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(AlertLogEntry {
            id: row.get(0)?,
            alert_id: row.get(1)?,
            rule_name: row.get(2)?,
            entry_id: row.get(3)?,
            fired_at,
            webhook_url: row.get(5)?,
            status_code: row.get(6)?,
            success: row.get::<_, i32>(7)? != 0,
            error: row.get(8)?,
        })
    })?;

    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_table(&conn).unwrap();
        conn
    }

    #[test]
    fn init_creates_table() {
        let conn = setup_db();
        // Table exists -- selecting from it should not error.
        let count: i32 = conn
            .query_row("SELECT COUNT(*) FROM alert_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn record_and_query_dispatch() {
        let conn = setup_db();
        let now = Utc::now();

        record_dispatch(
            &conn,
            "alert-001",
            "deny-alert",
            "entry-abc",
            now,
            "https://hooks.slack.com/test",
            Some(200),
            true,
            None,
        )
        .unwrap();

        let entries = recent_entries(&conn, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alert_id, "alert-001");
        assert_eq!(entries[0].rule_name, "deny-alert");
        assert_eq!(entries[0].status_code, Some(200));
        assert!(entries[0].success);
        assert!(entries[0].error.is_none());
    }

    #[test]
    fn record_failed_dispatch() {
        let conn = setup_db();
        let now = Utc::now();

        record_dispatch(
            &conn,
            "alert-002",
            "net-alert",
            "entry-def",
            now,
            "https://example.com/hook",
            None,
            false,
            Some("connection refused"),
        )
        .unwrap();

        let entries = recent_entries(&conn, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].success);
        assert_eq!(entries[0].error.as_deref(), Some("connection refused"));
        assert!(entries[0].status_code.is_none());
    }

    #[test]
    fn recent_entries_respects_limit_and_order() {
        let conn = setup_db();
        let now = Utc::now();

        for i in 0..5 {
            record_dispatch(
                &conn,
                &format!("alert-{i:03}"),
                "rule",
                "entry",
                now,
                "https://example.com",
                Some(200),
                true,
                None,
            )
            .unwrap();
        }

        let entries = recent_entries(&conn, 3).unwrap();
        assert_eq!(entries.len(), 3);
        // Newest first
        assert_eq!(entries[0].alert_id, "alert-004");
        assert_eq!(entries[1].alert_id, "alert-003");
        assert_eq!(entries[2].alert_id, "alert-002");
    }

    #[test]
    fn init_table_is_idempotent() {
        let conn = setup_db();
        // Calling init again should not error.
        init_table(&conn).unwrap();
    }
}
