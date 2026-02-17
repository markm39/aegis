/// AuditStore: SQLite-backed append-only hash-chained audit ledger.
use std::path::Path;

use chrono::DateTime;
use rusqlite::{params, Connection};
use tracing::info;
use uuid::Uuid;

use aegis_types::{Action, AegisError, Verdict};

use crate::entry::{compute_hash, AuditEntry};
use crate::integrity::IntegrityReport;

/// The sentinel value used as prev_hash for the very first entry.
const GENESIS_HASH: &str = "genesis";

/// An append-only, hash-chained audit store backed by SQLite.
pub struct AuditStore {
    conn: Connection,
    latest_hash: String,
}

impl AuditStore {
    /// Open (or create) the audit ledger at the given path.
    ///
    /// Enables WAL mode, creates the `audit_log` table and indices if they
    /// do not exist, and reads the latest entry hash (or uses "genesis").
    pub fn open(path: &Path) -> Result<Self, AegisError> {
        let conn = Connection::open(path)
            .map_err(|e| AegisError::LedgerError(format!("failed to open database: {e}")))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| AegisError::LedgerError(format!("failed to set WAL mode: {e}")))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
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
            CREATE INDEX IF NOT EXISTS idx_policy_config ON policy_snapshots(config_name);",
        )
        .map_err(|e| AegisError::LedgerError(format!("failed to create schema: {e}")))?;

        // Add session_id column if it does not already exist (migration).
        // This is a nullable column for backward compatibility with existing ledgers.
        let _ = conn.execute_batch(
            "ALTER TABLE audit_log ADD COLUMN session_id TEXT;
             CREATE INDEX IF NOT EXISTS idx_session_id ON audit_log(session_id);",
        );

        let latest_hash: String = conn
            .query_row(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| GENESIS_HASH.to_string());

        info!(latest_hash = %latest_hash, "audit store opened");

        Ok(Self { conn, latest_hash })
    }

    /// Append a new entry to the ledger recording the given action and verdict.
    ///
    /// The new entry's `prev_hash` is set to the current chain tip. After
    /// insertion, `self.latest_hash` is updated to the new entry's hash.
    pub fn append(
        &mut self,
        action: &Action,
        verdict: &Verdict,
    ) -> Result<AuditEntry, AegisError> {
        let entry = AuditEntry::new(action, verdict, self.latest_hash.clone());

        self.conn
            .execute(
                "INSERT INTO audit_log (entry_id, timestamp, action_id, action_kind, principal, decision, reason, policy_id, prev_hash, entry_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
                ],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to insert entry: {e}")))?;

        self.latest_hash = entry.entry_hash.clone();
        Ok(entry)
    }

    /// Verify the integrity of the entire hash chain.
    ///
    /// Reads all entries in insertion order and checks:
    /// 1. Each entry's hash matches its recomputed value.
    /// 2. Each entry's `prev_hash` equals the preceding entry's `entry_hash`
    ///    (or "genesis" for the first entry).
    pub fn verify_integrity(&self) -> Result<IntegrityReport, AegisError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT entry_id, timestamp, action_id, action_kind, principal, decision, reason, policy_id, prev_hash, entry_hash
                 FROM audit_log ORDER BY id ASC",
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(AuditEntry {
                    entry_id: row
                        .get::<_, String>(0)
                        .map(|s| Uuid::parse_str(&s).unwrap())?,
                    timestamp: row
                        .get::<_, String>(1)
                        .map(|s| DateTime::parse_from_rfc3339(&s).unwrap().into())?,
                    action_id: row
                        .get::<_, String>(2)
                        .map(|s| Uuid::parse_str(&s).unwrap())?,
                    action_kind: row.get(3)?,
                    principal: row.get(4)?,
                    decision: row.get(5)?,
                    reason: row.get(6)?,
                    policy_id: row.get(7)?,
                    prev_hash: row.get(8)?,
                    entry_hash: row.get(9)?,
                })
            })
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
            let recomputed = compute_hash(
                &entry.entry_id,
                &entry.timestamp,
                &entry.action_id,
                &entry.action_kind,
                &entry.principal,
                &entry.decision,
                &entry.reason,
                &entry.prev_hash,
            );
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
        let entry = AuditEntry::new(action, verdict, self.latest_hash.clone());

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
                    session_id.to_string(),
                ],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to insert entry: {e}")))?;

        // Update session counters
        self.conn
            .execute(
                "UPDATE sessions SET total_actions = total_actions + 1 WHERE session_id = ?1",
                params![session_id.to_string()],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to update session total: {e}")))?;

        if entry.decision == "Deny" {
            self.conn
                .execute(
                    "UPDATE sessions SET denied_actions = denied_actions + 1 WHERE session_id = ?1",
                    params![session_id.to_string()],
                )
                .map_err(|e| {
                    AegisError::LedgerError(format!("failed to update session denied: {e}"))
                })?;
        }

        self.latest_hash = entry.entry_hash.clone();
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
    pub fn purge_before(
        &mut self,
        before: DateTime<chrono::Utc>,
    ) -> Result<usize, AegisError> {
        let before_str = before.to_rfc3339();

        // Count entries to delete
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE timestamp < ?1",
                params![before_str],
                |row| row.get(0),
            )
            .map_err(|e| AegisError::LedgerError(format!("purge count failed: {e}")))?;

        if count == 0 {
            return Ok(0);
        }

        // Delete old entries
        self.conn
            .execute(
                "DELETE FROM audit_log WHERE timestamp < ?1",
                params![before_str],
            )
            .map_err(|e| AegisError::LedgerError(format!("purge delete failed: {e}")))?;

        // Rebuild hash chain for remaining entries
        self.rebuild_hash_chain()?;

        Ok(count as usize)
    }

    /// Rebuild the hash chain from scratch for all remaining entries.
    ///
    /// Reads all entries in order, recomputes prev_hash and entry_hash for
    /// each one, and updates the database. The first remaining entry gets
    /// "genesis" as its prev_hash.
    #[allow(clippy::type_complexity)]
    fn rebuild_hash_chain(&mut self) -> Result<(), AegisError> {
        // Read all remaining entries in order
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, entry_id, timestamp, action_id, action_kind, principal, decision, reason
                 FROM audit_log ORDER BY id ASC",
            )
            .map_err(|e| AegisError::LedgerError(format!("rebuild prepare failed: {e}")))?;

        let rows: Vec<(i64, String, String, String, String, String, String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .map_err(|e| AegisError::LedgerError(format!("rebuild query failed: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("rebuild read failed: {e}")))?;

        drop(stmt);

        let mut prev_hash = GENESIS_HASH.to_string();

        for (row_id, entry_id_str, timestamp_str, action_id_str, action_kind, principal, decision, reason) in &rows {
            let entry_id: Uuid = entry_id_str
                .parse()
                .map_err(|e| AegisError::LedgerError(format!("invalid entry_id: {e}")))?;
            let timestamp: DateTime<chrono::Utc> = DateTime::parse_from_rfc3339(timestamp_str)
                .map_err(|e| AegisError::LedgerError(format!("invalid timestamp: {e}")))?
                .into();
            let action_id: Uuid = action_id_str
                .parse()
                .map_err(|e| AegisError::LedgerError(format!("invalid action_id: {e}")))?;

            let new_hash = crate::entry::compute_hash(
                &entry_id,
                &timestamp,
                &action_id,
                action_kind,
                principal,
                decision,
                reason,
                &prev_hash,
            );

            self.conn
                .execute(
                    "UPDATE audit_log SET prev_hash = ?1, entry_hash = ?2 WHERE id = ?3",
                    params![prev_hash, new_hash, row_id],
                )
                .map_err(|e| AegisError::LedgerError(format!("rebuild update failed: {e}")))?;

            prev_hash = new_hash;
        }

        self.latest_hash = prev_hash;
        Ok(())
    }

    /// Provide read access to the underlying connection (for query extensions).
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::ActionKind;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn test_db_path() -> NamedTempFile {
        NamedTempFile::new().expect("failed to create temp file")
    }

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
}
