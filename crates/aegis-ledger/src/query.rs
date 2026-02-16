/// Query interface for audit records.
use chrono::DateTime;
use rusqlite::params;
use uuid::Uuid;

use aegis_types::AegisError;

use crate::entry::AuditEntry;
use crate::store::AuditStore;

impl AuditStore {
    /// Return the last `n` entries, ordered by timestamp descending (most recent first).
    pub fn query_last(&self, n: usize) -> Result<Vec<AuditEntry>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                "SELECT entry_id, timestamp, action_id, action_kind, principal, decision, reason, policy_id, prev_hash, entry_hash
                 FROM audit_log ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| AegisError::LedgerError(format!("query_last prepare failed: {e}")))?;

        let rows = stmt
            .query_map(params![n as i64], row_to_entry)
            .map_err(|e| AegisError::LedgerError(format!("query_last failed: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("query_last read failed: {e}")))
    }

    /// Return all entries for the given principal, ordered by timestamp ascending.
    pub fn query_by_principal(&self, principal: &str) -> Result<Vec<AuditEntry>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                "SELECT entry_id, timestamp, action_id, action_kind, principal, decision, reason, policy_id, prev_hash, entry_hash
                 FROM audit_log WHERE principal = ?1 ORDER BY id ASC",
            )
            .map_err(|e| {
                AegisError::LedgerError(format!("query_by_principal prepare failed: {e}"))
            })?;

        let rows = stmt
            .query_map(params![principal], row_to_entry)
            .map_err(|e| AegisError::LedgerError(format!("query_by_principal failed: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("query_by_principal read failed: {e}")))
    }

    /// Return all entries with the given decision ("Allow" or "Deny"), ordered by timestamp ascending.
    pub fn query_by_decision(&self, decision: &str) -> Result<Vec<AuditEntry>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                "SELECT entry_id, timestamp, action_id, action_kind, principal, decision, reason, policy_id, prev_hash, entry_hash
                 FROM audit_log WHERE decision = ?1 ORDER BY id ASC",
            )
            .map_err(|e| {
                AegisError::LedgerError(format!("query_by_decision prepare failed: {e}"))
            })?;

        let rows = stmt
            .query_map(params![decision], row_to_entry)
            .map_err(|e| AegisError::LedgerError(format!("query_by_decision failed: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("query_by_decision read failed: {e}")))
    }

    /// Return the total number of entries in the ledger.
    pub fn count(&self) -> Result<usize, AegisError> {
        self.connection()
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|c| c as usize)
            .map_err(|e| AegisError::LedgerError(format!("count failed: {e}")))
    }
}

/// Map a SQLite row to an AuditEntry.
fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::{ActionKind, Verdict};
    use aegis_types::Action;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn test_db_path() -> NamedTempFile {
        NamedTempFile::new().expect("failed to create temp file")
    }

    fn make_action(principal: &str, kind: ActionKind) -> Action {
        Action::new(principal, kind)
    }

    #[test]
    fn query_by_principal_filters_correctly() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let a1 = make_action(
            "alice",
            ActionKind::FileRead {
                path: PathBuf::from("/a"),
            },
        );
        let v1 = Verdict::allow(a1.id, "ok", None);
        store.append(&a1, &v1).unwrap();

        let a2 = make_action(
            "bob",
            ActionKind::FileWrite {
                path: PathBuf::from("/b"),
            },
        );
        let v2 = Verdict::deny(a2.id, "nope", None);
        store.append(&a2, &v2).unwrap();

        let a3 = make_action(
            "alice",
            ActionKind::NetConnect {
                host: "example.com".into(),
                port: 443,
            },
        );
        let v3 = Verdict::allow(a3.id, "ok again", None);
        store.append(&a3, &v3).unwrap();

        let alice_entries = store.query_by_principal("alice").unwrap();
        assert_eq!(alice_entries.len(), 2);
        assert!(alice_entries.iter().all(|e| e.principal == "alice"));

        let bob_entries = store.query_by_principal("bob").unwrap();
        assert_eq!(bob_entries.len(), 1);
        assert_eq!(bob_entries[0].principal, "bob");
    }

    #[test]
    fn query_by_decision_filters_correctly() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let a1 = make_action(
            "agent",
            ActionKind::FileRead {
                path: PathBuf::from("/a"),
            },
        );
        let v1 = Verdict::allow(a1.id, "ok", None);
        store.append(&a1, &v1).unwrap();

        let a2 = make_action(
            "agent",
            ActionKind::FileWrite {
                path: PathBuf::from("/b"),
            },
        );
        let v2 = Verdict::deny(a2.id, "nope", None);
        store.append(&a2, &v2).unwrap();

        let a3 = make_action(
            "agent",
            ActionKind::FileRead {
                path: PathBuf::from("/c"),
            },
        );
        let v3 = Verdict::allow(a3.id, "sure", None);
        store.append(&a3, &v3).unwrap();

        let allows = store.query_by_decision("Allow").unwrap();
        assert_eq!(allows.len(), 2);
        assert!(allows.iter().all(|e| e.decision == "Allow"));

        let denies = store.query_by_decision("Deny").unwrap();
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].decision, "Deny");
    }

    #[test]
    fn count_returns_correct_number() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        assert_eq!(store.count().unwrap(), 0);

        for i in 0..7 {
            let action = make_action(
                &format!("agent-{i}"),
                ActionKind::FileRead {
                    path: PathBuf::from("/tmp"),
                },
            );
            let verdict = Verdict::allow(action.id, "ok", None);
            store.append(&action, &verdict).unwrap();
        }

        assert_eq!(store.count().unwrap(), 7);
    }

    #[test]
    fn query_last_returns_most_recent() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let mut entry_ids = Vec::new();
        for i in 0..5 {
            let action = make_action(
                &format!("agent-{i}"),
                ActionKind::FileRead {
                    path: PathBuf::from(format!("/tmp/{i}")),
                },
            );
            let verdict = Verdict::allow(action.id, format!("reason-{i}"), None);
            let entry = store.append(&action, &verdict).unwrap();
            entry_ids.push(entry.entry_id);
        }

        let last3 = store.query_last(3).unwrap();
        assert_eq!(last3.len(), 3);
        // Most recent first
        assert_eq!(last3[0].entry_id, entry_ids[4]);
        assert_eq!(last3[1].entry_id, entry_ids[3]);
        assert_eq!(last3[2].entry_id, entry_ids[2]);
    }

    #[test]
    fn query_nonexistent_principal_returns_empty() {
        let tmp = test_db_path();
        let store = AuditStore::open(tmp.path()).unwrap();
        let results = store.query_by_principal("nobody").unwrap();
        assert!(results.is_empty());
    }
}
