//! Session tracking for the audit ledger.
//!
//! Each `aegis run` invocation is a session. Sessions group audit entries
//! and provide lifecycle metadata (start/end time, command, exit code,
//! action counts).

use chrono::{DateTime, Utc};
use rusqlite::params;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aegis_types::AegisError;

use crate::entry::AuditEntry;
use crate::parse_helpers::{parse_datetime, parse_uuid};
use crate::store::AuditStore;

/// Column list for session queries (must match `row_to_session` field order).
const SESSION_COLUMNS: &str = "session_id, config_name, command, args, start_time, end_time, exit_code, policy_hash, total_actions, denied_actions, tag";

/// A session represents one `aegis run` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: Uuid,
    pub config_name: String,
    pub command: String,
    pub args: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub policy_hash: Option<String>,
    pub total_actions: usize,
    pub denied_actions: usize,
    /// Optional human-readable tag (e.g., "deploy-v2.1").
    pub tag: Option<String>,
}

impl AuditStore {
    /// Begin a new session, inserting a row into the sessions table.
    ///
    /// Returns the session UUID. Call `end_session()` when the process exits.
    /// The optional `tag` is a human-readable label for the session.
    pub fn begin_session(
        &mut self,
        config_name: &str,
        command: &str,
        args: &[String],
        tag: Option<&str>,
    ) -> Result<Uuid, AegisError> {
        let session_id = Uuid::new_v4();
        let start_time = Utc::now();
        let args_json = serde_json::to_string(args)
            .map_err(|e| AegisError::LedgerError(format!("failed to serialize session args: {e}")))?;

        self.connection()
            .execute(
                "INSERT INTO sessions (session_id, config_name, command, args, start_time, tag)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    session_id.to_string(),
                    config_name,
                    command,
                    args_json,
                    start_time.to_rfc3339(),
                    tag,
                ],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to begin session: {e}")))?;

        tracing::info!(
            session_id = %session_id,
            command,
            ?tag,
            "session started"
        );

        Ok(session_id)
    }

    /// End a session, recording the end time and exit code.
    ///
    /// Also updates the final action counts from the sessions counter.
    pub fn end_session(
        &mut self,
        session_id: &Uuid,
        exit_code: i32,
    ) -> Result<(), AegisError> {
        let end_time = Utc::now();

        self.connection()
            .execute(
                "UPDATE sessions SET end_time = ?1, exit_code = ?2 WHERE session_id = ?3",
                params![
                    end_time.to_rfc3339(),
                    exit_code,
                    session_id.to_string(),
                ],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to end session: {e}")))?;

        tracing::info!(
            session_id = %session_id,
            exit_code,
            "session ended"
        );

        Ok(())
    }

    /// List sessions ordered by start_time DESC.
    pub fn list_sessions(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Session>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                &format!("SELECT {SESSION_COLUMNS} FROM sessions ORDER BY id DESC LIMIT ?1 OFFSET ?2"),
            )
            .map_err(|e| AegisError::LedgerError(format!("list_sessions prepare: {e}")))?;

        let rows = stmt
            .query_map(params![limit as i64, offset as i64], row_to_session)
            .map_err(|e| AegisError::LedgerError(format!("list_sessions query: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("list_sessions read: {e}")))
    }

    /// Return the total number of sessions across all configs.
    pub fn count_all_sessions(&self) -> Result<usize, AegisError> {
        self.connection()
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|c| c as usize)
            .map_err(|e| AegisError::LedgerError(format!("count_all_sessions failed: {e}")))
    }

    /// Return the most recent session (by start_time DESC), if any.
    pub fn latest_session(&self) -> Result<Option<Session>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                &format!("SELECT {SESSION_COLUMNS} FROM sessions ORDER BY id DESC LIMIT 1"),
            )
            .map_err(|e| AegisError::LedgerError(format!("latest_session prepare: {e}")))?;

        let result = stmt
            .query_row([], row_to_session)
            .optional()
            .map_err(|e| AegisError::LedgerError(format!("latest_session query: {e}")))?;

        Ok(result)
    }

    /// Get a single session by its UUID.
    pub fn get_session(
        &self,
        session_id: &Uuid,
    ) -> Result<Option<Session>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                &format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE session_id = ?1"),
            )
            .map_err(|e| AegisError::LedgerError(format!("get_session prepare: {e}")))?;

        let result = stmt
            .query_row(params![session_id.to_string()], row_to_session)
            .optional()
            .map_err(|e| AegisError::LedgerError(format!("get_session query: {e}")))?;

        Ok(result)
    }

    /// Update the tag for a session.
    pub fn update_session_tag(
        &self,
        session_id: &Uuid,
        tag: &str,
    ) -> Result<(), AegisError> {
        let rows_affected = self
            .connection()
            .execute(
                "UPDATE sessions SET tag = ?1 WHERE session_id = ?2",
                params![tag, session_id.to_string()],
            )
            .map_err(|e| AegisError::LedgerError(format!("update_session_tag failed: {e}")))?;

        if rows_affected == 0 {
            return Err(AegisError::LedgerError(format!(
                "session {session_id} not found"
            )));
        }

        Ok(())
    }

    /// Get all audit entries for a specific session, ordered by id ASC.
    pub fn query_by_session(
        &self,
        session_id: &Uuid,
    ) -> Result<Vec<AuditEntry>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                &format!("SELECT {} FROM audit_log WHERE session_id = ?1 ORDER BY id ASC", crate::query::ENTRY_COLUMNS),
            )
            .map_err(|e| AegisError::LedgerError(format!("query_by_session prepare: {e}")))?;

        let rows = stmt
            .query_map(params![session_id.to_string()], crate::query::row_to_entry)
            .map_err(|e| AegisError::LedgerError(format!("query_by_session query: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("query_by_session read: {e}")))
    }
}

/// Map a SQLite row to a Session.
fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<Session> {
    let args_json: String = row.get(3)?;
    let args: Vec<String> = serde_json::from_str(&args_json).unwrap_or_default();

    let end_time = row
        .get::<_, Option<String>>(5)?
        .map(|s| parse_datetime(&s, 5))
        .transpose()?;

    Ok(Session {
        session_id: parse_uuid(&row.get::<_, String>(0)?, 0)?,
        config_name: row.get(1)?,
        command: row.get(2)?,
        args,
        start_time: parse_datetime(&row.get::<_, String>(4)?, 4)?,
        end_time,
        exit_code: row.get(6)?,
        policy_hash: row.get(7)?,
        total_actions: row.get::<_, i64>(8).map(|v| v as usize)?,
        denied_actions: row.get::<_, i64>(9).map(|v| v as usize)?,
        tag: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::{Action, ActionKind, Verdict};
    use std::path::PathBuf;

    use crate::test_helpers::test_db;

    #[test]
    fn begin_and_end_session() {
        let (_tmp, mut store) = test_db();

        let session_id = store
            .begin_session("test-config", "echo", &["hello".into()], None)
            .expect("begin_session should succeed");

        let session = store.get_session(&session_id).unwrap().unwrap();
        assert_eq!(session.config_name, "test-config");
        assert_eq!(session.command, "echo");
        assert_eq!(session.args, vec!["hello"]);
        assert!(session.end_time.is_none());
        assert!(session.exit_code.is_none());
        assert!(session.tag.is_none());

        store.end_session(&session_id, 0).expect("end_session should succeed");

        let session = store.get_session(&session_id).unwrap().unwrap();
        assert!(session.end_time.is_some());
        assert_eq!(session.exit_code, Some(0));
    }

    #[test]
    fn append_with_session_increments_counters() {
        let (_tmp, mut store) = test_db();

        let session_id = store
            .begin_session("test", "cat", &["/tmp/f".into()], None)
            .unwrap();

        // Append an Allow entry
        let a1 = Action::new("agent", ActionKind::FileRead { path: PathBuf::from("/a") });
        let v1 = Verdict::allow(a1.id, "ok", None);
        store.append_with_session(&a1, &v1, &session_id).unwrap();

        // Append a Deny entry
        let a2 = Action::new("agent", ActionKind::FileWrite { path: PathBuf::from("/b") });
        let v2 = Verdict::deny(a2.id, "nope", None);
        store.append_with_session(&a2, &v2, &session_id).unwrap();

        let session = store.get_session(&session_id).unwrap().unwrap();
        assert_eq!(session.total_actions, 2);
        assert_eq!(session.denied_actions, 1);
    }

    #[test]
    fn query_by_session_returns_session_entries() {
        let (_tmp, mut store) = test_db();

        let s1 = store.begin_session("test", "cmd1", &[], None).unwrap();
        let s2 = store.begin_session("test", "cmd2", &[], None).unwrap();

        // Append to session 1
        let a1 = Action::new("agent", ActionKind::FileRead { path: PathBuf::from("/a") });
        let v1 = Verdict::allow(a1.id, "ok", None);
        store.append_with_session(&a1, &v1, &s1).unwrap();

        let a2 = Action::new("agent", ActionKind::FileRead { path: PathBuf::from("/b") });
        let v2 = Verdict::allow(a2.id, "ok", None);
        store.append_with_session(&a2, &v2, &s1).unwrap();

        // Append to session 2
        let a3 = Action::new("agent", ActionKind::FileRead { path: PathBuf::from("/c") });
        let v3 = Verdict::allow(a3.id, "ok", None);
        store.append_with_session(&a3, &v3, &s2).unwrap();

        let s1_entries = store.query_by_session(&s1).unwrap();
        assert_eq!(s1_entries.len(), 2);

        let s2_entries = store.query_by_session(&s2).unwrap();
        assert_eq!(s2_entries.len(), 1);
    }

    #[test]
    fn list_sessions_returns_ordered() {
        let (_tmp, mut store) = test_db();

        store.begin_session("test", "cmd1", &[], None).unwrap();
        store.begin_session("test", "cmd2", &[], None).unwrap();
        store.begin_session("test", "cmd3", &[], None).unwrap();

        let sessions = store.list_sessions(10, 0).unwrap();
        assert_eq!(sessions.len(), 3);
        // Most recent first (DESC)
        assert_eq!(sessions[0].command, "cmd3");
        assert_eq!(sessions[1].command, "cmd2");
        assert_eq!(sessions[2].command, "cmd1");
    }

    #[test]
    fn list_sessions_with_pagination() {
        let (_tmp, mut store) = test_db();

        for i in 0..5 {
            store.begin_session("test", &format!("cmd{i}"), &[], None).unwrap();
        }

        let page1 = store.list_sessions(2, 0).unwrap();
        assert_eq!(page1.len(), 2);

        let page2 = store.list_sessions(2, 2).unwrap();
        assert_eq!(page2.len(), 2);

        let page3 = store.list_sessions(2, 4).unwrap();
        assert_eq!(page3.len(), 1);
    }

    #[test]
    fn begin_session_with_tag() {
        let (_tmp, mut store) = test_db();

        let session_id = store
            .begin_session("test", "deploy", &[], Some("deploy-v2.1"))
            .unwrap();

        let session = store.get_session(&session_id).unwrap().unwrap();
        assert_eq!(session.tag, Some("deploy-v2.1".to_string()));
    }

    #[test]
    fn update_session_tag() {
        let (_tmp, mut store) = test_db();

        let session_id = store
            .begin_session("test", "cmd", &[], None)
            .unwrap();

        // Initially no tag
        let session = store.get_session(&session_id).unwrap().unwrap();
        assert!(session.tag.is_none());

        // Update tag
        store.update_session_tag(&session_id, "deploy-v2").unwrap();

        let session = store.get_session(&session_id).unwrap().unwrap();
        assert_eq!(session.tag, Some("deploy-v2".to_string()));
    }

    #[test]
    fn update_session_tag_nonexistent_fails() {
        let (_tmp, store) = test_db();
        let result = store.update_session_tag(&Uuid::new_v4(), "test");
        assert!(result.is_err());
    }

    #[test]
    fn get_nonexistent_session_returns_none() {
        let (_tmp, store) = test_db();
        let result = store.get_session(&Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn count_all_sessions_returns_correct_count() {
        let (_tmp, mut store) = test_db();
        assert_eq!(store.count_all_sessions().unwrap(), 0);

        store.begin_session("test", "cmd1", &[], None).unwrap();
        assert_eq!(store.count_all_sessions().unwrap(), 1);

        store.begin_session("test", "cmd2", &[], None).unwrap();
        store.begin_session("test", "cmd3", &[], None).unwrap();
        assert_eq!(store.count_all_sessions().unwrap(), 3);
    }

    #[test]
    fn latest_session_returns_most_recent() {
        let (_tmp, mut store) = test_db();

        assert!(store.latest_session().unwrap().is_none());

        store.begin_session("test", "cmd1", &[], None).unwrap();
        store.begin_session("test", "cmd2", &[], None).unwrap();
        store.begin_session("test", "cmd3", &[], Some("latest-tag")).unwrap();

        let latest = store.latest_session().unwrap().unwrap();
        assert_eq!(latest.command, "cmd3");
        assert_eq!(latest.tag, Some("latest-tag".to_string()));
    }

    #[test]
    fn session_hash_chain_unaffected() {
        let (_tmp, mut store) = test_db();

        let session_id = store.begin_session("test", "cmd", &[], None).unwrap();

        // Append entries with session
        for i in 0..10 {
            let action = Action::new(
                "agent",
                ActionKind::FileRead { path: PathBuf::from(format!("/f{i}")) },
            );
            let verdict = Verdict::allow(action.id, format!("ok-{i}"), None);
            store.append_with_session(&action, &verdict, &session_id).unwrap();
        }

        // Verify hash chain integrity -- session_id is NOT in the hash
        let report = store.verify_integrity().unwrap();
        assert!(report.valid, "hash chain should be valid: {}", report.message);
        assert_eq!(report.total_entries, 10);
    }
}
