//! Session tracking for the audit ledger.
//!
//! Each `aegis run` invocation is a session. Sessions group audit entries
//! and provide lifecycle metadata (start/end time, command, exit code,
//! action counts). Sessions support persistent resume, per-sender isolation,
//! and conversation chain tracking via group IDs.

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
const SESSION_COLUMNS: &str = "session_id, config_name, command, args, start_time, end_time, exit_code, policy_hash, total_actions, denied_actions, tag, parent_id, group_id, sender_id, channel_type, thread_id, resumable, context_snapshot";

/// A session represents one `aegis run` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique identifier for this session.
    pub session_id: Uuid,
    /// Configuration name used for this session.
    pub config_name: String,
    /// The command that was executed.
    pub command: String,
    /// Command-line arguments passed to the command.
    pub args: Vec<String>,
    /// When the session began.
    pub start_time: DateTime<Utc>,
    /// When the session ended (None if still running).
    pub end_time: Option<DateTime<Utc>>,
    /// Exit code of the process (None if still running or signal-terminated).
    pub exit_code: Option<i32>,
    /// SHA-256 hash of the policy configuration at session start.
    pub policy_hash: Option<String>,
    /// Total number of actions recorded during this session.
    pub total_actions: usize,
    /// Number of actions that were denied during this session.
    pub denied_actions: usize,
    /// Optional human-readable tag (e.g., "deploy-v2.1").
    pub tag: Option<String>,
    /// Parent session ID (for resumed/forked sessions).
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    /// Session group ID (links all sessions in a conversation chain).
    #[serde(default)]
    pub group_id: Option<Uuid>,
    /// Channel/sender context for per-sender isolation.
    #[serde(default)]
    pub sender_id: Option<String>,
    /// Channel type (telegram, slack, etc.) for routing.
    #[serde(default)]
    pub channel_type: Option<String>,
    /// Thread ID for thread-bound sessions.
    #[serde(default)]
    pub thread_id: Option<String>,
    /// Whether this session can be resumed.
    #[serde(default)]
    pub resumable: bool,
    /// Conversation context snapshot (serialized agent state for resume).
    #[serde(default)]
    pub context_snapshot: Option<String>,
}

/// Filters for querying sessions with optional criteria.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionFilter {
    /// Filter by sender ID.
    pub sender_id: Option<String>,
    /// Filter by channel type (telegram, slack, etc.).
    pub channel_type: Option<String>,
    /// Filter by thread ID.
    pub thread_id: Option<String>,
    /// Filter by configuration name.
    pub config_name: Option<String>,
    /// Only return resumable sessions.
    pub resumable_only: bool,
    /// Maximum number of results to return.
    pub limit: usize,
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
        let args_json = serde_json::to_string(args).map_err(|e| {
            AegisError::LedgerError(format!("failed to serialize session args: {e}"))
        })?;

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
    pub fn end_session(&mut self, session_id: &Uuid, exit_code: i32) -> Result<(), AegisError> {
        let end_time = Utc::now();

        self.connection()
            .execute(
                "UPDATE sessions SET end_time = ?1, exit_code = ?2 WHERE session_id = ?3",
                params![end_time.to_rfc3339(), exit_code, session_id.to_string(),],
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
    pub fn list_sessions(&self, limit: usize, offset: usize) -> Result<Vec<Session>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions ORDER BY id DESC LIMIT ?1 OFFSET ?2"
            ))
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
            .prepare(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions ORDER BY id DESC LIMIT 1"
            ))
            .map_err(|e| AegisError::LedgerError(format!("latest_session prepare: {e}")))?;

        let result = stmt
            .query_row([], row_to_session)
            .optional()
            .map_err(|e| AegisError::LedgerError(format!("latest_session query: {e}")))?;

        Ok(result)
    }

    /// Get a single session by its UUID.
    pub fn get_session(&self, session_id: &Uuid) -> Result<Option<Session>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions WHERE session_id = ?1"
            ))
            .map_err(|e| AegisError::LedgerError(format!("get_session prepare: {e}")))?;

        let result = stmt
            .query_row(params![session_id.to_string()], row_to_session)
            .optional()
            .map_err(|e| AegisError::LedgerError(format!("get_session query: {e}")))?;

        Ok(result)
    }

    /// Update the tag for a session.
    pub fn update_session_tag(&self, session_id: &Uuid, tag: &str) -> Result<(), AegisError> {
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
    pub fn query_by_session(&self, session_id: &Uuid) -> Result<Vec<AuditEntry>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(&format!(
                "SELECT {} FROM audit_log WHERE session_id = ?1 ORDER BY id ASC",
                crate::query::ENTRY_COLUMNS
            ))
            .map_err(|e| AegisError::LedgerError(format!("query_by_session prepare: {e}")))?;

        let rows = stmt
            .query_map(params![session_id.to_string()], crate::query::row_to_entry)
            .map_err(|e| AegisError::LedgerError(format!("query_by_session query: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("query_by_session read: {e}")))
    }

    /// Resume a previous session, creating a new session linked to the parent.
    ///
    /// The new session inherits the parent's `group_id` (or creates a new one
    /// if the parent had none). The parent's `sender_id`, `channel_type`, and
    /// `thread_id` are carried forward.
    pub fn resume_session(
        &mut self,
        parent_id: Uuid,
        config_name: &str,
        command: &str,
        args: &[String],
    ) -> Result<Session, AegisError> {
        let parent = self
            .get_session(&parent_id)?
            .ok_or_else(|| {
                AegisError::LedgerError(format!("parent session {parent_id} not found"))
            })?;

        if !parent.resumable {
            return Err(AegisError::LedgerError(format!(
                "session {parent_id} is not resumable"
            )));
        }

        let session_id = Uuid::new_v4();
        let start_time = Utc::now();
        let group_id = parent.group_id.unwrap_or(parent_id);
        let args_json = serde_json::to_string(args).map_err(|e| {
            AegisError::LedgerError(format!("failed to serialize session args: {e}"))
        })?;

        self.connection()
            .execute(
                "INSERT INTO sessions (session_id, config_name, command, args, start_time, parent_id, group_id, sender_id, channel_type, thread_id, resumable)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    session_id.to_string(),
                    config_name,
                    command,
                    args_json,
                    start_time.to_rfc3339(),
                    parent_id.to_string(),
                    group_id.to_string(),
                    parent.sender_id,
                    parent.channel_type,
                    parent.thread_id,
                    1i64,
                ],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to resume session: {e}")))?;

        tracing::info!(
            session_id = %session_id,
            parent_id = %parent_id,
            group_id = %group_id,
            "session resumed"
        );

        self.get_session(&session_id)?
            .ok_or_else(|| AegisError::LedgerError("resumed session not found after insert".into()))
    }

    /// Find the most recent resumable session for a sender/channel pair.
    pub fn find_resumable_session(
        &self,
        sender_id: &str,
        channel_type: &str,
    ) -> Result<Option<Session>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions
                 WHERE sender_id = ?1 AND channel_type = ?2 AND resumable = 1
                 ORDER BY id DESC LIMIT 1"
            ))
            .map_err(|e| {
                AegisError::LedgerError(format!("find_resumable_session prepare: {e}"))
            })?;

        let result = stmt
            .query_row(params![sender_id, channel_type], row_to_session)
            .optional()
            .map_err(|e| AegisError::LedgerError(format!("find_resumable_session query: {e}")))?;

        Ok(result)
    }

    /// Find the most recent resumable session for a thread.
    pub fn find_thread_session(&self, thread_id: &str) -> Result<Option<Session>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions
                 WHERE thread_id = ?1 AND resumable = 1
                 ORDER BY id DESC LIMIT 1"
            ))
            .map_err(|e| AegisError::LedgerError(format!("find_thread_session prepare: {e}")))?;

        let result = stmt
            .query_row(params![thread_id], row_to_session)
            .optional()
            .map_err(|e| AegisError::LedgerError(format!("find_thread_session query: {e}")))?;

        Ok(result)
    }

    /// List all sessions in a group (conversation chain), ordered by start time ASC.
    pub fn list_session_group(&self, group_id: Uuid) -> Result<Vec<Session>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions
                 WHERE group_id = ?1 OR session_id = ?1
                 ORDER BY id ASC"
            ))
            .map_err(|e| AegisError::LedgerError(format!("list_session_group prepare: {e}")))?;

        let rows = stmt
            .query_map(params![group_id.to_string()], row_to_session)
            .map_err(|e| AegisError::LedgerError(format!("list_session_group query: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("list_session_group read: {e}")))
    }

    /// Save a context snapshot for later resume.
    pub fn save_context_snapshot(
        &self,
        session_id: Uuid,
        snapshot: &str,
    ) -> Result<(), AegisError> {
        let rows_affected = self
            .connection()
            .execute(
                "UPDATE sessions SET context_snapshot = ?1 WHERE session_id = ?2",
                params![snapshot, session_id.to_string()],
            )
            .map_err(|e| AegisError::LedgerError(format!("save_context_snapshot failed: {e}")))?;

        if rows_affected == 0 {
            return Err(AegisError::LedgerError(format!(
                "session {session_id} not found"
            )));
        }

        Ok(())
    }

    /// Load a context snapshot for resume.
    pub fn load_context_snapshot(&self, session_id: Uuid) -> Result<Option<String>, AegisError> {
        self.connection()
            .query_row(
                "SELECT context_snapshot FROM sessions WHERE session_id = ?1",
                params![session_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AegisError::LedgerError(format!("load_context_snapshot failed: {e}")))?
            .ok_or_else(|| AegisError::LedgerError(format!("session {session_id} not found")))
    }

    /// List recent sessions with optional filters.
    pub fn list_sessions_filtered(
        &self,
        filter: &SessionFilter,
    ) -> Result<Vec<Session>, AegisError> {
        let mut conditions = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(ref sender) = filter.sender_id {
            conditions.push(format!("sender_id = ?{idx}"));
            param_values.push(Box::new(sender.clone()));
            idx += 1;
        }
        if let Some(ref channel) = filter.channel_type {
            conditions.push(format!("channel_type = ?{idx}"));
            param_values.push(Box::new(channel.clone()));
            idx += 1;
        }
        if let Some(ref thread) = filter.thread_id {
            conditions.push(format!("thread_id = ?{idx}"));
            param_values.push(Box::new(thread.clone()));
            idx += 1;
        }
        if let Some(ref config) = filter.config_name {
            conditions.push(format!("config_name = ?{idx}"));
            param_values.push(Box::new(config.clone()));
            idx += 1;
        }
        if filter.resumable_only {
            conditions.push("resumable = 1".to_string());
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit = if filter.limit == 0 { 20 } else { filter.limit };

        let sql = format!(
            "SELECT {SESSION_COLUMNS} FROM sessions {where_clause} ORDER BY id DESC LIMIT ?{idx}"
        );
        param_values.push(Box::new(limit as i64));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self
            .connection()
            .prepare(&sql)
            .map_err(|e| {
                AegisError::LedgerError(format!("list_sessions_filtered prepare: {e}"))
            })?;

        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_session)
            .map_err(|e| AegisError::LedgerError(format!("list_sessions_filtered query: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("list_sessions_filtered read: {e}")))
    }

    /// Mark a session as resumable or not.
    pub fn mark_resumable(&self, session_id: Uuid, resumable: bool) -> Result<(), AegisError> {
        let rows_affected = self
            .connection()
            .execute(
                "UPDATE sessions SET resumable = ?1 WHERE session_id = ?2",
                params![resumable as i64, session_id.to_string()],
            )
            .map_err(|e| AegisError::LedgerError(format!("mark_resumable failed: {e}")))?;

        if rows_affected == 0 {
            return Err(AegisError::LedgerError(format!(
                "session {session_id} not found"
            )));
        }

        Ok(())
    }
}

/// Map a SQLite row to a Session.
fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<Session> {
    let args_json: String = row.get(3)?;
    let args: Vec<String> = serde_json::from_str(&args_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;

    let end_time = row
        .get::<_, Option<String>>(5)?
        .map(|s| parse_datetime(&s, 5))
        .transpose()?;

    let parent_id = row
        .get::<_, Option<String>>(11)?
        .map(|s| parse_uuid(&s, 11))
        .transpose()?;

    let group_id = row
        .get::<_, Option<String>>(12)?
        .map(|s| parse_uuid(&s, 12))
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
        parent_id,
        group_id,
        sender_id: row.get(13)?,
        channel_type: row.get(14)?,
        thread_id: row.get(15)?,
        resumable: row.get::<_, i64>(16).unwrap_or(0) != 0,
        context_snapshot: row.get(17)?,
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

        store
            .end_session(&session_id, 0)
            .expect("end_session should succeed");

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

        let a1 = Action::new(
            "agent",
            ActionKind::FileRead {
                path: PathBuf::from("/a"),
            },
        );
        let v1 = Verdict::allow(a1.id, "ok", None);
        store.append_with_session(&a1, &v1, &session_id).unwrap();

        let a2 = Action::new(
            "agent",
            ActionKind::FileWrite {
                path: PathBuf::from("/b"),
            },
        );
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

        let a1 = Action::new(
            "agent",
            ActionKind::FileRead {
                path: PathBuf::from("/a"),
            },
        );
        let v1 = Verdict::allow(a1.id, "ok", None);
        store.append_with_session(&a1, &v1, &s1).unwrap();

        let a2 = Action::new(
            "agent",
            ActionKind::FileRead {
                path: PathBuf::from("/b"),
            },
        );
        let v2 = Verdict::allow(a2.id, "ok", None);
        store.append_with_session(&a2, &v2, &s1).unwrap();

        let a3 = Action::new(
            "agent",
            ActionKind::FileRead {
                path: PathBuf::from("/c"),
            },
        );
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
        assert_eq!(sessions[0].command, "cmd3");
        assert_eq!(sessions[1].command, "cmd2");
        assert_eq!(sessions[2].command, "cmd1");
    }

    #[test]
    fn list_sessions_with_pagination() {
        let (_tmp, mut store) = test_db();

        for i in 0..5 {
            store
                .begin_session("test", &format!("cmd{i}"), &[], None)
                .unwrap();
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

        let session_id = store.begin_session("test", "cmd", &[], None).unwrap();

        let session = store.get_session(&session_id).unwrap().unwrap();
        assert!(session.tag.is_none());

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
        store
            .begin_session("test", "cmd3", &[], Some("latest-tag"))
            .unwrap();

        let latest = store.latest_session().unwrap().unwrap();
        assert_eq!(latest.command, "cmd3");
        assert_eq!(latest.tag, Some("latest-tag".to_string()));
    }

    #[test]
    fn session_hash_chain_unaffected() {
        let (_tmp, mut store) = test_db();

        let session_id = store.begin_session("test", "cmd", &[], None).unwrap();

        for i in 0..10 {
            let action = Action::new(
                "agent",
                ActionKind::FileRead {
                    path: PathBuf::from(format!("/f{i}")),
                },
            );
            let verdict = Verdict::allow(action.id, format!("ok-{i}"), None);
            store
                .append_with_session(&action, &verdict, &session_id)
                .unwrap();
        }

        let report = store.verify_integrity().unwrap();
        assert!(
            report.valid,
            "hash chain should be valid: {}",
            report.message
        );
        assert_eq!(report.total_entries, 10);
    }

    // --- New persistent session tests ---

    #[test]
    fn new_session_fields_default_to_none() {
        let (_tmp, mut store) = test_db();
        let session_id = store
            .begin_session("test", "echo", &["hello".into()], None)
            .unwrap();

        let session = store.get_session(&session_id).unwrap().unwrap();
        assert!(session.parent_id.is_none());
        assert!(session.group_id.is_none());
        assert!(session.sender_id.is_none());
        assert!(session.channel_type.is_none());
        assert!(session.thread_id.is_none());
        assert!(!session.resumable);
        assert!(session.context_snapshot.is_none());
    }

    #[test]
    fn mark_resumable_and_query() {
        let (_tmp, mut store) = test_db();
        let session_id = store
            .begin_session("test", "echo", &[], None)
            .unwrap();

        let session = store.get_session(&session_id).unwrap().unwrap();
        assert!(!session.resumable);

        store.mark_resumable(session_id, true).unwrap();
        let session = store.get_session(&session_id).unwrap().unwrap();
        assert!(session.resumable);

        store.mark_resumable(session_id, false).unwrap();
        let session = store.get_session(&session_id).unwrap().unwrap();
        assert!(!session.resumable);
    }

    #[test]
    fn mark_resumable_nonexistent_fails() {
        let (_tmp, store) = test_db();
        let result = store.mark_resumable(Uuid::new_v4(), true);
        assert!(result.is_err());
    }

    #[test]
    fn resume_session_creates_linked_child() {
        let (_tmp, mut store) = test_db();
        let parent_id = store
            .begin_session("test", "claude", &["--chat".into()], None)
            .unwrap();

        store.mark_resumable(parent_id, true).unwrap();

        let child = store
            .resume_session(parent_id, "test", "claude", &["--resume".into()])
            .unwrap();

        assert_eq!(child.parent_id, Some(parent_id));
        assert_eq!(child.group_id, Some(parent_id));
        assert_eq!(child.config_name, "test");
        assert_eq!(child.command, "claude");
        assert!(child.resumable);
    }

    #[test]
    fn resume_non_resumable_session_fails() {
        let (_tmp, mut store) = test_db();
        let parent_id = store
            .begin_session("test", "cmd", &[], None)
            .unwrap();

        let result = store.resume_session(parent_id, "test", "cmd", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not resumable"));
    }

    #[test]
    fn resume_nonexistent_session_fails() {
        let (_tmp, mut store) = test_db();
        let result = store.resume_session(Uuid::new_v4(), "test", "cmd", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn session_group_chain() {
        let (_tmp, mut store) = test_db();
        let parent_id = store
            .begin_session("test", "claude", &[], None)
            .unwrap();
        store.mark_resumable(parent_id, true).unwrap();

        let child1 = store
            .resume_session(parent_id, "test", "claude", &[])
            .unwrap();
        store.mark_resumable(child1.session_id, true).unwrap();

        let child2 = store
            .resume_session(child1.session_id, "test", "claude", &[])
            .unwrap();

        assert_eq!(child1.group_id, Some(parent_id));
        assert_eq!(child2.group_id, Some(parent_id));

        let group = store.list_session_group(parent_id).unwrap();
        assert!(
            group.len() >= 2,
            "expected at least 2 sessions in group, got {}",
            group.len()
        );

        for i in 1..group.len() {
            assert!(group[i].start_time >= group[i - 1].start_time);
        }
    }

    #[test]
    fn context_snapshot_save_and_load() {
        let (_tmp, mut store) = test_db();
        let session_id = store
            .begin_session("test", "claude", &[], None)
            .unwrap();

        let snapshot = store.load_context_snapshot(session_id).unwrap();
        assert!(snapshot.is_none());

        let ctx = r#"{"messages":[{"role":"user","content":"hello"}]}"#;
        store.save_context_snapshot(session_id, ctx).unwrap();

        let loaded = store.load_context_snapshot(session_id).unwrap();
        assert_eq!(loaded, Some(ctx.to_string()));
    }

    #[test]
    fn context_snapshot_save_nonexistent_fails() {
        let (_tmp, store) = test_db();
        let result = store.save_context_snapshot(Uuid::new_v4(), "data");
        assert!(result.is_err());
    }

    #[test]
    fn find_resumable_session_by_sender() {
        let (_tmp, mut store) = test_db();

        let s1 = store
            .begin_session("test", "claude", &[], None)
            .unwrap();
        store
            .connection()
            .execute(
                "UPDATE sessions SET sender_id = ?1, channel_type = ?2, resumable = 1 WHERE session_id = ?3",
                params!["user-42", "telegram", s1.to_string()],
            )
            .unwrap();

        let s2 = store
            .begin_session("test", "claude", &[], None)
            .unwrap();
        store
            .connection()
            .execute(
                "UPDATE sessions SET sender_id = ?1, channel_type = ?2, resumable = 1 WHERE session_id = ?3",
                params!["user-42", "telegram", s2.to_string()],
            )
            .unwrap();

        let found = store
            .find_resumable_session("user-42", "telegram")
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().session_id, s2);

        let not_found = store
            .find_resumable_session("user-99", "telegram")
            .unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn find_thread_session() {
        let (_tmp, mut store) = test_db();

        let s1 = store
            .begin_session("test", "claude", &[], None)
            .unwrap();
        store
            .connection()
            .execute(
                "UPDATE sessions SET thread_id = ?1, resumable = 1 WHERE session_id = ?2",
                params!["thread-abc", s1.to_string()],
            )
            .unwrap();

        let found = store.find_thread_session("thread-abc").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().session_id, s1);

        let not_found = store.find_thread_session("thread-xyz").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn list_sessions_filtered_resumable_only() {
        let (_tmp, mut store) = test_db();

        let s1 = store.begin_session("test", "cmd1", &[], None).unwrap();
        store.mark_resumable(s1, true).unwrap();
        store.begin_session("test", "cmd2", &[], None).unwrap();
        let s3 = store.begin_session("test", "cmd3", &[], None).unwrap();
        store.mark_resumable(s3, true).unwrap();

        let filter = SessionFilter {
            resumable_only: true,
            limit: 10,
            ..Default::default()
        };

        let sessions = store.list_sessions_filtered(&filter).unwrap();
        assert_eq!(sessions.len(), 2);
        for s in &sessions {
            assert!(s.resumable);
        }
    }

    #[test]
    fn list_sessions_filtered_by_sender() {
        let (_tmp, mut store) = test_db();

        let s1 = store.begin_session("test", "cmd1", &[], None).unwrap();
        store
            .connection()
            .execute(
                "UPDATE sessions SET sender_id = 'alice' WHERE session_id = ?1",
                params![s1.to_string()],
            )
            .unwrap();

        store.begin_session("test", "cmd2", &[], None).unwrap();

        let filter = SessionFilter {
            sender_id: Some("alice".into()),
            limit: 10,
            ..Default::default()
        };

        let sessions = store.list_sessions_filtered(&filter).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].sender_id.as_deref(), Some("alice"));
    }

    #[test]
    fn list_sessions_filtered_empty_returns_all() {
        let (_tmp, mut store) = test_db();

        store.begin_session("test", "cmd1", &[], None).unwrap();
        store.begin_session("test", "cmd2", &[], None).unwrap();
        store.begin_session("test", "cmd3", &[], None).unwrap();

        let filter = SessionFilter {
            limit: 10,
            ..Default::default()
        };

        let sessions = store.list_sessions_filtered(&filter).unwrap();
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn list_sessions_filtered_combined() {
        let (_tmp, mut store) = test_db();

        let s1 = store.begin_session("prod", "claude", &[], None).unwrap();
        store
            .connection()
            .execute(
                "UPDATE sessions SET sender_id = 'bob', channel_type = 'telegram', resumable = 1 WHERE session_id = ?1",
                params![s1.to_string()],
            )
            .unwrap();

        let s2 = store.begin_session("prod", "claude", &[], None).unwrap();
        store
            .connection()
            .execute(
                "UPDATE sessions SET sender_id = 'bob', channel_type = 'slack', resumable = 1 WHERE session_id = ?1",
                params![s2.to_string()],
            )
            .unwrap();

        let filter = SessionFilter {
            sender_id: Some("bob".into()),
            channel_type: Some("telegram".into()),
            resumable_only: true,
            limit: 10,
            ..Default::default()
        };

        let sessions = store.list_sessions_filtered(&filter).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, s1);
    }

    #[test]
    fn schema_migration_safe_on_reopen() {
        let tmp = crate::test_helpers::test_db_path();
        {
            let _store = AuditStore::open(tmp.path()).unwrap();
        }
        {
            let store = AuditStore::open(tmp.path()).unwrap();
            let sessions = store.list_sessions(10, 0).unwrap();
            assert!(sessions.is_empty());
        }
    }
}
