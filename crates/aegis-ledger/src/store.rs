//! AuditStore: SQLite-backed append-only hash-chained audit ledger.

use std::path::Path;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use chrono::DateTime;
use rusqlite::{params, Connection, OptionalExtension};
use tracing::{info, warn};
use uuid::Uuid;

use aegis_alert::AlertEvent;
use aegis_types::{Action, AegisError, Verdict};

use crate::channel_audit::ChannelAuditEntry;
use crate::entry::AuditEntry;
use crate::fs_audit::FsAuditEntry;
use crate::integrity::IntegrityReport;
use crate::middleware::AuditMiddleware;
use crate::query::row_to_entry;

/// The sentinel value used as prev_hash for the very first entry.
const GENESIS_HASH: &str = "genesis";

/// SQL schema for the audit ledger database (tables + indices).
const SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entry_id TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL,
        action_id TEXT NOT NULL,
        action_kind TEXT NOT NULL,
        principal TEXT NOT NULL,
        decision TEXT NOT NULL,
        reason TEXT NOT NULL,
        policy_id TEXT,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_principal ON audit_log(principal);
    CREATE INDEX IF NOT EXISTS idx_decision ON audit_log(decision);
    CREATE INDEX IF NOT EXISTS idx_action_kind ON audit_log(action_kind);
    CREATE INDEX IF NOT EXISTS idx_policy_id ON audit_log(policy_id);

    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL UNIQUE,
        config_name TEXT NOT NULL,
        command TEXT NOT NULL,
        args TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT,
        exit_code INTEGER,
        policy_hash TEXT,
        total_actions INTEGER DEFAULT 0,
        denied_actions INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_session_start ON sessions(start_time);

    CREATE TABLE IF NOT EXISTS policy_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL,
        policy_hash TEXT NOT NULL,
        policy_files TEXT NOT NULL,
        policy_content TEXT NOT NULL,
        session_id TEXT,
        config_name TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_policy_config ON policy_snapshots(config_name);
";

/// Migrations applied after initial schema creation.
const MIGRATIONS: &[&str] = &[
    // Migration 1: Add session_id column to audit_log
    "ALTER TABLE audit_log ADD COLUMN session_id TEXT;
     CREATE INDEX IF NOT EXISTS idx_session_id ON audit_log(session_id);",
    // Migration 2: Add tag column to sessions
    "ALTER TABLE sessions ADD COLUMN tag TEXT;",
    // Migration 3: Create alert_log table for webhook dispatch history
    "CREATE TABLE IF NOT EXISTS alert_log (
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
    );",
    // Migration 4: Create channel_audit_log table for messaging channel audit
    "CREATE TABLE IF NOT EXISTS channel_audit_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        entry_id        TEXT NOT NULL UNIQUE,
        channel_name    TEXT NOT NULL,
        direction       TEXT NOT NULL,
        message_hash    TEXT NOT NULL,
        recipient_count INTEGER NOT NULL DEFAULT 0,
        has_buttons     INTEGER NOT NULL DEFAULT 0,
        timestamp       TEXT NOT NULL,
        prev_hash       TEXT NOT NULL,
        entry_hash      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_channel_audit_timestamp ON channel_audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_channel_audit_channel ON channel_audit_log(channel_name);
    CREATE INDEX IF NOT EXISTS idx_channel_audit_direction ON channel_audit_log(direction);",
    // Migration 5: Create fs_audit_log table for filesystem change audit
    "CREATE TABLE IF NOT EXISTS fs_audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        entry_id    TEXT NOT NULL UNIQUE,
        path        TEXT NOT NULL,
        before_hash TEXT,
        after_hash  TEXT,
        size_delta  INTEGER NOT NULL DEFAULT 0,
        operation   TEXT NOT NULL,
        timestamp   TEXT NOT NULL,
        prev_hash   TEXT NOT NULL,
        entry_hash  TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_fs_audit_timestamp ON fs_audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_fs_audit_path ON fs_audit_log(path);
    CREATE INDEX IF NOT EXISTS idx_fs_audit_operation ON fs_audit_log(operation);",
];

/// An append-only, hash-chained audit store backed by SQLite.
pub struct AuditStore {
    conn: Connection,
    latest_hash: String,
    alert_tx: Option<SyncSender<AlertEvent>>,
    middleware: Vec<Arc<dyn AuditMiddleware>>,
}

impl AuditStore {
    /// Open (or create) the audit ledger at the given path.
    ///
    /// Enables WAL mode, creates the `audit_log` table and indices if they
    /// do not exist, and reads the latest entry hash (or uses "genesis").
    pub fn open(path: &Path) -> Result<Self, AegisError> {
        let conn = Connection::open(path).map_err(|e| {
            AegisError::LedgerError(format!("failed to open database '{}': {e}", path.display()))
        })?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| {
                AegisError::LedgerError(format!(
                    "failed to set WAL mode on '{}': {e}",
                    path.display()
                ))
            })?;

        conn.execute_batch(SCHEMA_SQL).map_err(|e| {
            AegisError::LedgerError(format!(
                "failed to create schema in '{}': {e}",
                path.display()
            ))
        })?;

        // Apply migrations (each is idempotent -- ALTER fails silently if already applied).
        for migration in MIGRATIONS {
            if let Err(e) = conn.execute_batch(migration) {
                tracing::debug!(error = %e, "migration already applied or not needed");
            }
        }

        let latest_hash: String = conn
            .query_row(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| {
                AegisError::LedgerError(format!(
                    "failed to read latest hash from '{}': {e}",
                    path.display()
                ))
            })?
            .unwrap_or_else(|| GENESIS_HASH.to_string());

        info!(latest_hash = %latest_hash, "audit store opened");

        Ok(Self {
            conn,
            latest_hash,
            alert_tx: None,
            middleware: Vec::new(),
        })
    }

    /// Set the alert channel sender for real-time webhook alerting.
    ///
    /// When set, every successful `insert_entry()` will push an [`AlertEvent`]
    /// to this channel via non-blocking `try_send`. If the channel is full,
    /// the event is silently dropped (the audit record is still persisted).
    pub fn set_alert_sender(&mut self, tx: SyncSender<AlertEvent>) {
        self.alert_tx = Some(tx);
    }

    /// Register an audit middleware.
    ///
    /// Middleware hooks are called synchronously after each insert. Multiple
    /// middleware are invoked in registration order. Each receives an immutable
    /// reference to the entry -- middleware cannot alter the audit trail.
    pub fn add_middleware(&mut self, mw: Arc<dyn AuditMiddleware>) {
        self.middleware.push(mw);
    }

    /// Notify all registered middleware about a standard audit entry.
    pub(crate) fn notify_action_middleware(&self, entry: &AuditEntry) {
        for mw in &self.middleware {
            mw.on_action(entry);
        }
    }

    /// Notify all registered middleware about a channel audit entry.
    pub(crate) fn notify_channel_middleware(&self, entry: &ChannelAuditEntry) {
        for mw in &self.middleware {
            mw.on_channel_action(entry);
        }
    }

    /// Notify all registered middleware about a filesystem audit entry.
    pub(crate) fn notify_fs_middleware(&self, entry: &FsAuditEntry) {
        for mw in &self.middleware {
            mw.on_fs_action(entry);
        }
    }

    /// Append a new entry to the ledger recording the given action and verdict.
    ///
    /// The new entry's `prev_hash` is set to the current chain tip. After
    /// insertion, `self.latest_hash` is updated to the new entry's hash.
    pub fn append(&mut self, action: &Action, verdict: &Verdict) -> Result<AuditEntry, AegisError> {
        self.insert_entry(action, verdict, None)
    }

    /// Verify the integrity of the entire hash chain.
    ///
    /// Reads all entries in insertion order and checks:
    /// 1. Each entry's hash matches its recomputed value.
    /// 2. Each entry's `prev_hash` equals the preceding entry's `entry_hash`
    ///    (or "genesis" for the first entry).
    #[must_use = "integrity report must be checked to detect ledger tampering"]
    pub fn verify_integrity(&self) -> Result<IntegrityReport, AegisError> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {} FROM audit_log ORDER BY id ASC",
                crate::query::ENTRY_COLUMNS
            ))
            .map_err(|e| AegisError::LedgerError(format!("failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], row_to_entry)
            .map_err(|e| AegisError::LedgerError(format!("failed to query entries: {e}")))?;

        let entries: Vec<AuditEntry> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("failed to read entry: {e}")))?;

        let total_entries = entries.len();
        if total_entries == 0 {
            return Ok(IntegrityReport {
                total_entries: 0,
                valid: true,
                first_invalid_entry: None,
                message: "ledger is empty".to_string(),
            });
        }

        let mut expected_prev_hash = GENESIS_HASH.to_string();

        for (i, entry) in entries.iter().enumerate() {
            // Check chain linkage
            if entry.prev_hash != expected_prev_hash {
                return Ok(IntegrityReport {
                    total_entries,
                    valid: false,
                    first_invalid_entry: Some(i),
                    message: format!(
                        "chain broken at entry {i}: expected prev_hash '{expected_prev_hash}', found '{}'",
                        entry.prev_hash
                    ),
                });
            }

            // Recompute and verify entry hash
            let recomputed = entry.recompute_hash();
            if entry.entry_hash != recomputed {
                return Ok(IntegrityReport {
                    total_entries,
                    valid: false,
                    first_invalid_entry: Some(i),
                    message: format!(
                        "hash mismatch at entry {i}: stored '{}', computed '{recomputed}'",
                        entry.entry_hash
                    ),
                });
            }

            expected_prev_hash = entry.entry_hash.clone();
        }

        Ok(IntegrityReport {
            total_entries,
            valid: true,
            first_invalid_entry: None,
            message: format!("all {total_entries} entries verified successfully"),
        })
    }

    /// Append a new entry to the ledger with a session ID attached.
    ///
    /// Like `append()`, but also sets the `session_id` column and increments
    /// the session's action/denied counters.
    pub fn append_with_session(
        &mut self,
        action: &Action,
        verdict: &Verdict,
        session_id: &Uuid,
    ) -> Result<AuditEntry, AegisError> {
        let entry = self.insert_entry(action, verdict, Some(session_id))?;

        // Update session counters in a single query
        let denied_incr: i64 = if entry.decision == "Deny" { 1 } else { 0 };
        self.conn
            .execute(
                "UPDATE sessions SET total_actions = total_actions + 1, denied_actions = denied_actions + ?1 WHERE session_id = ?2",
                params![denied_incr, session_id.to_string()],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to update session counters for {session_id}: {e}")))?;

        Ok(entry)
    }

    /// Internal helper: create an AuditEntry, insert it, and update the chain tip.
    fn insert_entry(
        &mut self,
        action: &Action,
        verdict: &Verdict,
        session_id: Option<&Uuid>,
    ) -> Result<AuditEntry, AegisError> {
        let entry = AuditEntry::new(action, verdict, self.latest_hash.clone())?;

        self.conn
            .execute(
                "INSERT INTO audit_log (entry_id, timestamp, action_id, action_kind, principal, decision, reason, policy_id, prev_hash, entry_hash, session_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    entry.entry_id.to_string(),
                    entry.timestamp.to_rfc3339(),
                    entry.action_id.to_string(),
                    entry.action_kind,
                    entry.principal,
                    entry.decision,
                    entry.reason,
                    entry.policy_id,
                    entry.prev_hash,
                    entry.entry_hash,
                    session_id.map(|s| s.to_string()),
                ],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to insert entry: {e}")))?;

        self.latest_hash = entry.entry_hash.clone();

        // Notify the alert dispatcher (non-blocking, best-effort).
        if let Some(ref tx) = self.alert_tx {
            let alert_event = AlertEvent {
                entry_id: entry.entry_id,
                timestamp: entry.timestamp,
                action_kind: extract_action_variant(&entry.action_kind),
                action_detail: entry.action_kind.clone(),
                principal: entry.principal.clone(),
                decision: entry.decision.clone(),
                reason: entry.reason.clone(),
                policy_id: entry.policy_id.clone(),
                session_id: session_id.copied(),
                pilot_context: None,
            };
            if tx.try_send(alert_event).is_err() {
                warn!("alert channel full or disconnected, dropping alert event");
            }
        }

        // Notify registered middleware (synchronous, after persist).
        self.notify_action_middleware(&entry);

        Ok(entry)
    }

    /// Purge audit entries older than the given timestamp.
    ///
    /// Deletes all entries with a timestamp before `before`, then rebuilds
    /// the hash chain for remaining entries so integrity verification still
    /// passes. Returns the number of entries deleted.
    ///
    /// This is a destructive operation -- the old hash chain is intentionally
    /// broken and rebuilt.
    pub fn purge_before(&mut self, before: DateTime<chrono::Utc>) -> Result<usize, AegisError> {
        let before_str = before.to_rfc3339();

        // Count entries to delete
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE timestamp < ?1",
                params![before_str],
                |row| row.get(0),
            )
            .map_err(|e| {
                AegisError::LedgerError(format!("purge count failed (before {before_str}): {e}"))
            })?;

        if count == 0 {
            return Ok(0);
        }

        // Wrap delete + rebuild in a savepoint so they're atomic.
        // If the rebuild fails, the delete is rolled back too.
        self.conn
            .execute_batch("SAVEPOINT purge_entries")
            .map_err(|e| AegisError::LedgerError(format!("begin purge savepoint: {e}")))?;

        let result = (|| {
            self.conn
                .execute(
                    "DELETE FROM audit_log WHERE timestamp < ?1",
                    params![before_str],
                )
                .map_err(|e| {
                    AegisError::LedgerError(format!(
                        "purge delete failed (before {before_str}): {e}"
                    ))
                })?;

            self.rebuild_hash_chain()?;
            Ok::<(), AegisError>(())
        })();

        match result {
            Ok(()) => {
                self.conn
                    .execute_batch("RELEASE purge_entries")
                    .map_err(|e| {
                        AegisError::LedgerError(format!("release purge savepoint: {e}"))
                    })?;
                Ok(count as usize)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK TO purge_entries");
                let _ = self.conn.execute_batch("RELEASE purge_entries");
                Err(e)
            }
        }
    }

    /// Rebuild the hash chain from scratch for all remaining entries.
    ///
    /// Reads all entries in order, recomputes prev_hash and entry_hash for
    /// each one, and updates the database. The first remaining entry gets
    /// "genesis" as its prev_hash.
    fn rebuild_hash_chain(&mut self) -> Result<(), AegisError> {
        /// A raw row from the audit_log table for hash chain rebuilding.
        struct RawRow {
            row_id: i64,
            entry_id: String,
            timestamp: String,
            action_id: String,
            action_kind: String,
            principal: String,
            decision: String,
            reason: String,
        }

        // Read all remaining entries in order
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, entry_id, timestamp, action_id, action_kind, principal, decision, reason
                 FROM audit_log ORDER BY id ASC",
            )
            .map_err(|e| AegisError::LedgerError(format!("rebuild prepare failed: {e}")))?;

        let rows: Vec<RawRow> = stmt
            .query_map([], |row| {
                Ok(RawRow {
                    row_id: row.get(0)?,
                    entry_id: row.get(1)?,
                    timestamp: row.get(2)?,
                    action_id: row.get(3)?,
                    action_kind: row.get(4)?,
                    principal: row.get(5)?,
                    decision: row.get(6)?,
                    reason: row.get(7)?,
                })
            })
            .map_err(|e| AegisError::LedgerError(format!("rebuild query failed: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("rebuild read failed: {e}")))?;

        drop(stmt);

        // Wrap all updates in a savepoint so a failure mid-rebuild
        // doesn't leave a partially-rewritten hash chain.
        self.conn
            .execute_batch("SAVEPOINT rebuild_chain")
            .map_err(|e| AegisError::LedgerError(format!("begin rebuild savepoint: {e}")))?;

        let mut prev_hash = GENESIS_HASH.to_string();

        let result = (|| {
            for row in &rows {
                let entry_id: Uuid = row
                    .entry_id
                    .parse()
                    .map_err(|e| AegisError::LedgerError(format!("invalid entry_id: {e}")))?;
                let timestamp: DateTime<chrono::Utc> = DateTime::parse_from_rfc3339(&row.timestamp)
                    .map_err(|e| AegisError::LedgerError(format!("invalid timestamp: {e}")))?
                    .into();
                let action_id: Uuid = row
                    .action_id
                    .parse()
                    .map_err(|e| AegisError::LedgerError(format!("invalid action_id: {e}")))?;

                let new_hash = crate::entry::compute_hash(
                    &entry_id,
                    &timestamp,
                    &action_id,
                    &row.action_kind,
                    &row.principal,
                    &row.decision,
                    &row.reason,
                    &prev_hash,
                );

                self.conn
                    .execute(
                        "UPDATE audit_log SET prev_hash = ?1, entry_hash = ?2 WHERE id = ?3",
                        params![prev_hash, new_hash, row.row_id],
                    )
                    .map_err(|e| AegisError::LedgerError(format!("rebuild update failed: {e}")))?;

                prev_hash = new_hash;
            }
            Ok::<(), AegisError>(())
        })();

        match result {
            Ok(()) => {
                self.conn
                    .execute_batch("RELEASE rebuild_chain")
                    .map_err(|e| {
                        AegisError::LedgerError(format!("release rebuild savepoint: {e}"))
                    })?;
                self.latest_hash = prev_hash;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK TO rebuild_chain");
                let _ = self.conn.execute_batch("RELEASE rebuild_chain");
                Err(e)
            }
        }
    }

    /// Provide read access to the underlying connection (for query extensions).
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// Extract the action variant name from a JSON-serialized `ActionKind`.
///
/// Given `{"FileWrite":{"path":"/foo"}}`, returns `"FileWrite"`.
/// Falls back to the full string if parsing fails.
fn extract_action_variant(action_kind_json: &str) -> String {
    // The JSON is always `{"VariantName":{...}}` -- find the first quoted key.
    let start = action_kind_json.find('"').map(|i| i + 1);
    let end = start.and_then(|s| action_kind_json[s..].find('"').map(|e| s + e));
    match (start, end) {
        (Some(s), Some(e)) => action_kind_json[s..e].to_string(),
        _ => action_kind_json.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::ActionKind;
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
    fn open_creates_db_and_table() {
        let tmp = test_db_path();
        let store = AuditStore::open(tmp.path()).expect("open should succeed");
        assert_eq!(store.latest_hash, GENESIS_HASH);
    }

    #[test]
    fn append_and_readback() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let action = sample_action("agent-1");
        let verdict = Verdict::allow(action.id, "ok", None);
        let entry = store.append(&action, &verdict).unwrap();

        assert_eq!(entry.prev_hash, GENESIS_HASH);
        assert_eq!(entry.principal, "agent-1");
        assert_eq!(entry.decision, "Allow");

        let results = store.query_last(1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, entry.entry_id);
    }

    #[test]
    fn hash_chain_continuity_100_entries() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        for i in 0..100 {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, format!("reason-{i}"), None);
            store.append(&action, &verdict).unwrap();
        }

        let report = store.verify_integrity().unwrap();
        assert!(report.valid, "integrity check failed: {}", report.message);
        assert_eq!(report.total_entries, 100);
        assert!(report.first_invalid_entry.is_none());
    }

    #[test]
    fn tamper_detection() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        for i in 0..5 {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, "ok", None);
            store.append(&action, &verdict).unwrap();
        }

        // Tamper with the third entry's action_kind
        store
            .connection()
            .execute(
                "UPDATE audit_log SET action_kind = 'TAMPERED' WHERE id = 3",
                [],
            )
            .unwrap();

        let report = store.verify_integrity().unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid_entry, Some(2)); // 0-indexed: row id=3 is index 2
    }

    #[test]
    fn genesis_first_entry() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let action = sample_action("agent");
        let verdict = Verdict::allow(action.id, "first entry", None);
        let entry = store.append(&action, &verdict).unwrap();

        assert_eq!(entry.prev_hash, "genesis");
    }

    #[test]
    fn empty_ledger_integrity() {
        let tmp = test_db_path();
        let store = AuditStore::open(tmp.path()).unwrap();
        let report = store.verify_integrity().unwrap();
        assert!(report.valid);
        assert_eq!(report.total_entries, 0);
    }

    #[test]
    fn purge_before_removes_old_entries() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        // Add 5 entries
        for i in 0..5 {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, format!("reason-{i}"), None);
            store.append(&action, &verdict).unwrap();
        }

        // Purge everything before "now + 1 second" (should delete all)
        let future = chrono::Utc::now() + chrono::Duration::seconds(1);
        let deleted = store.purge_before(future).unwrap();
        assert_eq!(deleted, 5);

        let entries = store.query_last(100).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn purge_before_rebuilds_hash_chain() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        // Add entries with a slight delay
        for i in 0..5 {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, format!("reason-{i}"), None);
            store.append(&action, &verdict).unwrap();
        }

        // Purge entries in the far past (none deleted)
        let past = chrono::Utc::now() - chrono::Duration::days(365);
        let deleted = store.purge_before(past).unwrap();
        assert_eq!(deleted, 0);

        // Hash chain should still be valid
        let report = store.verify_integrity().unwrap();
        assert!(report.valid, "chain should be valid: {}", report.message);
        assert_eq!(report.total_entries, 5);
    }

    #[test]
    fn second_entry_links_to_first() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let a1 = sample_action("agent");
        let v1 = Verdict::allow(a1.id, "first", None);
        let e1 = store.append(&a1, &v1).unwrap();

        let a2 = sample_action("agent");
        let v2 = Verdict::deny(a2.id, "second", Some("pol-1".into()));
        let e2 = store.append(&a2, &v2).unwrap();

        assert_eq!(e2.prev_hash, e1.entry_hash);
    }

    #[test]
    fn tamper_detection_prev_hash_chain_break() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        for i in 0..5 {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, "ok", None);
            store.append(&action, &verdict).unwrap();
        }

        // Break the chain by modifying prev_hash of the 4th entry
        store
            .connection()
            .execute(
                "UPDATE audit_log SET prev_hash = 'corrupted' WHERE id = 4",
                [],
            )
            .unwrap();

        let report = store.verify_integrity().unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid_entry, Some(3)); // 0-indexed
        assert!(report.message.contains("chain broken"));
    }

    #[test]
    fn purge_partial_rebuilds_valid_chain() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        // Insert entries with known timestamps via raw SQL so we can
        // control which ones get purged.
        let old_time = "2020-01-01T00:00:00+00:00";
        let now = chrono::Utc::now();

        // 3 old entries
        for i in 0..3 {
            let action = sample_action(&format!("old-agent-{i}"));
            let verdict = Verdict::allow(action.id, "old", None);
            store.append(&action, &verdict).unwrap();
        }
        // Force old timestamps
        store
            .connection()
            .execute_batch(&format!(
                "UPDATE audit_log SET timestamp = '{old_time}' WHERE id <= 3"
            ))
            .unwrap();

        // 2 new entries (current timestamp, will survive purge)
        for i in 0..2 {
            let action = sample_action(&format!("new-agent-{i}"));
            let verdict = Verdict::allow(action.id, "new", None);
            store.append(&action, &verdict).unwrap();
        }

        // Purge entries before "now - 1 second"
        let cutoff = now - chrono::Duration::seconds(1);
        let deleted = store.purge_before(cutoff).unwrap();
        assert_eq!(deleted, 3);

        // Remaining entries should have a valid rebuilt chain
        let report = store.verify_integrity().unwrap();
        assert!(
            report.valid,
            "chain should be valid after partial purge: {}",
            report.message
        );
        assert_eq!(report.total_entries, 2);
    }

    #[test]
    fn reopen_preserves_chain_continuity() {
        let tmp = test_db_path();

        // Scope 1: create entries
        {
            let mut store = AuditStore::open(tmp.path()).unwrap();
            for i in 0..3 {
                let action = sample_action(&format!("agent-{i}"));
                let verdict = Verdict::allow(action.id, "ok", None);
                store.append(&action, &verdict).unwrap();
            }
        }

        // Scope 2: reopen and add more entries
        {
            let mut store = AuditStore::open(tmp.path()).unwrap();
            let action = sample_action("agent-3");
            let verdict = Verdict::allow(action.id, "after reopen", None);
            store.append(&action, &verdict).unwrap();

            // Full chain should be valid
            let report = store.verify_integrity().unwrap();
            assert!(
                report.valid,
                "chain broken after reopen: {}",
                report.message
            );
            assert_eq!(report.total_entries, 4);
        }
    }

    #[test]
    fn count_returns_total_entries() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        assert_eq!(store.count().unwrap(), 0);

        for i in 0..3 {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, "ok", None);
            store.append(&action, &verdict).unwrap();
        }

        assert_eq!(store.count().unwrap(), 3);
    }

    #[test]
    fn alert_sender_receives_events_on_append() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let (tx, rx) = std::sync::mpsc::sync_channel::<AlertEvent>(16);
        store.set_alert_sender(tx);

        let action = sample_action("alert-agent");
        let verdict = Verdict::deny(action.id, "forbidden", Some("pol-1".into()));
        store.append(&action, &verdict).unwrap();

        let event = rx.try_recv().expect("should receive an alert event");
        assert_eq!(event.principal, "alert-agent");
        assert_eq!(event.decision, "Deny");
        assert_eq!(event.reason, "forbidden");
        assert_eq!(event.policy_id, Some("pol-1".into()));
        assert_eq!(event.action_kind, "FileRead");
        assert!(event.action_detail.contains("\"path\""));
    }

    #[test]
    fn alert_sender_with_session_id() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        let session_id = store
            .begin_session("test-config", "echo", &["hello".into()], None)
            .unwrap();

        let (tx, rx) = std::sync::mpsc::sync_channel::<AlertEvent>(16);
        store.set_alert_sender(tx);

        let action = sample_action("agent");
        let verdict = Verdict::allow(action.id, "ok", None);
        store
            .append_with_session(&action, &verdict, &session_id)
            .unwrap();

        let event = rx.try_recv().expect("should receive an alert event");
        assert_eq!(event.session_id, Some(session_id));
    }

    #[test]
    fn no_alert_sender_does_not_panic() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        // No set_alert_sender call -- should work fine.
        let action = sample_action("agent");
        let verdict = Verdict::allow(action.id, "ok", None);
        store.append(&action, &verdict).unwrap();
    }

    #[test]
    fn extract_action_variant_file_write() {
        assert_eq!(
            extract_action_variant(r#"{"FileWrite":{"path":"/tmp/f.txt"}}"#),
            "FileWrite"
        );
    }

    #[test]
    fn extract_action_variant_net_connect() {
        assert_eq!(
            extract_action_variant(r#"{"NetConnect":{"host":"evil.com","port":443}}"#),
            "NetConnect"
        );
    }

    #[test]
    fn extract_action_variant_fallback() {
        assert_eq!(extract_action_variant("not json"), "not json");
    }
}
