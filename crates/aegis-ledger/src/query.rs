//! Query interface for audit records.

use rusqlite::params;

use aegis_types::AegisError;

use crate::entry::AuditEntry;
use crate::filter::AuditFilter;
use crate::parse_helpers::{parse_datetime, parse_uuid};
use crate::store::AuditStore;

/// Column list for audit entry queries (must match `row_to_entry` field order).
pub(crate) const ENTRY_COLUMNS: &str = "entry_id, timestamp, action_id, action_kind, principal, decision, reason, policy_id, prev_hash, entry_hash";

impl AuditStore {
    /// Return the last `n` entries, ordered by timestamp descending (most recent first).
    pub fn query_last(&self, n: usize) -> Result<Vec<AuditEntry>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                &format!("SELECT {ENTRY_COLUMNS} FROM audit_log ORDER BY id DESC LIMIT ?1"),
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
                &format!("SELECT {ENTRY_COLUMNS} FROM audit_log WHERE principal = ?1 ORDER BY id ASC"),
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
                &format!("SELECT {ENTRY_COLUMNS} FROM audit_log WHERE decision = ?1 ORDER BY id ASC"),
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

    /// Query entries matching the given filter, ordered by id DESC.
    ///
    /// Returns `(matching_entries, total_matching_count)` for pagination.
    /// The total count reflects all entries matching the filter, ignoring
    /// limit/offset.
    pub fn query_filtered(
        &self,
        filter: &AuditFilter,
    ) -> Result<(Vec<AuditEntry>, usize), AegisError> {
        let crate::filter::SqlFragment {
            where_clause,
            mut params,
            limit,
            offset,
        } = filter.to_sql();

        // Count query (ignores limit/offset)
        let count_sql = if where_clause.is_empty() {
            "SELECT COUNT(*) FROM audit_log".to_string()
        } else {
            format!("SELECT COUNT(*) FROM audit_log WHERE {where_clause}")
        };

        let total_count: usize = {
            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            self.connection()
                .query_row(&count_sql, param_refs.as_slice(), |row| {
                    row.get::<_, i64>(0)
                })
                .map(|c| c as usize)
                .map_err(|e| AegisError::LedgerError(format!("query_filtered count failed: {e}")))?
        };

        // Data query with limit/offset
        let mut data_sql = if where_clause.is_empty() {
            format!("SELECT {ENTRY_COLUMNS} FROM audit_log ORDER BY id DESC")
        } else {
            format!(
                "SELECT {ENTRY_COLUMNS} FROM audit_log WHERE {where_clause} ORDER BY id DESC"
            )
        };

        if let Some(lim) = limit {
            let idx = params.len() + 1;
            data_sql.push_str(&format!(" LIMIT ?{idx}"));
            params.push(Box::new(lim as i64));
        }

        if let Some(off) = offset {
            let idx = params.len() + 1;
            data_sql.push_str(&format!(" OFFSET ?{idx}"));
            params.push(Box::new(off as i64));
        }

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self
            .connection()
            .prepare(&data_sql)
            .map_err(|e| AegisError::LedgerError(format!("query_filtered prepare failed: {e}")))?;

        let rows = stmt
            .query_map(param_refs.as_slice(), row_to_entry)
            .map_err(|e| AegisError::LedgerError(format!("query_filtered failed: {e}")))?;

        let entries: Vec<AuditEntry> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("query_filtered read failed: {e}")))?;

        Ok((entries, total_count))
    }

    /// Return aggregate counts grouped by the given column for entries matching the filter.
    pub(crate) fn count_grouped_by(
        &self,
        column: &str,
        filter: &AuditFilter,
    ) -> Result<Vec<(String, usize)>, AegisError> {
        let fragment = filter.to_sql();

        let sql = if fragment.where_clause.is_empty() {
            format!("SELECT {column}, COUNT(*) FROM audit_log GROUP BY {column} ORDER BY COUNT(*) DESC")
        } else {
            format!(
                "SELECT {column}, COUNT(*) FROM audit_log WHERE {} GROUP BY {column} ORDER BY COUNT(*) DESC",
                fragment.where_clause
            )
        };

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            fragment.params.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self
            .connection()
            .prepare(&sql)
            .map_err(|e| AegisError::LedgerError(format!("count_grouped_by({column}) failed: {e}")))?;

        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
            })
            .map_err(|e| AegisError::LedgerError(format!("count_grouped_by({column}) query: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("count_grouped_by({column}) read: {e}")))
    }

    /// Return aggregate counts grouped by action_kind for entries matching the filter.
    pub fn count_by_action_kind(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<(String, usize)>, AegisError> {
        self.count_grouped_by("action_kind", filter)
    }

    /// Return aggregate counts grouped by decision for entries matching the filter.
    pub fn count_by_decision(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<(String, usize)>, AegisError> {
        self.count_grouped_by("decision", filter)
    }

    /// Return entries with row id strictly greater than `after_id`, ordered by id ASC.
    ///
    /// Used for streaming/tailing the ledger (`--follow` mode). Returns tuples
    /// of `(row_id, entry)` so the caller can track the last seen ID.
    pub fn query_after_id(
        &self,
        after_id: i64,
    ) -> Result<Vec<(i64, AuditEntry)>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                &format!(
                    "SELECT {ENTRY_COLUMNS}, id FROM audit_log WHERE id > ?1 ORDER BY id ASC"
                ),
            )
            .map_err(|e| AegisError::LedgerError(format!("query_after_id prepare: {e}")))?;

        let rows = stmt
            .query_map(params![after_id], |row| {
                let entry = row_to_entry(row)?;
                let row_id: i64 = row.get(10)?;
                Ok((row_id, entry))
            })
            .map_err(|e| AegisError::LedgerError(format!("query_after_id failed: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("query_after_id read: {e}")))
    }
}

/// Map a SQLite row to an AuditEntry.
///
/// Expects columns in order: entry_id, timestamp, action_id, action_kind,
/// principal, decision, reason, policy_id, prev_hash, entry_hash (indices 0-9).
pub fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::{Action, ActionKind, Verdict};
    use std::path::PathBuf;

    use crate::test_helpers::test_db_path;

    fn make_action(principal: &str, kind: ActionKind) -> Action {
        Action::new(principal, kind)
    }

    /// Populate a store with varied entries for filter testing.
    fn populate_test_store(store: &mut AuditStore) {
        let actions = vec![
            ("alice", ActionKind::FileRead { path: PathBuf::from("/a") }, "Allow"),
            ("alice", ActionKind::FileWrite { path: PathBuf::from("/b") }, "Deny"),
            ("bob", ActionKind::FileRead { path: PathBuf::from("/c") }, "Allow"),
            ("bob", ActionKind::NetConnect { host: "example.com".into(), port: 443 }, "Deny"),
            ("alice", ActionKind::DirList { path: PathBuf::from("/d") }, "Allow"),
        ];
        for (principal, kind, decision) in actions {
            let action = make_action(principal, kind);
            let verdict = if decision == "Allow" {
                Verdict::allow(action.id, format!("{decision} by test"), None)
            } else {
                Verdict::deny(action.id, format!("{decision} by test"), None)
            };
            store.append(&action, &verdict).unwrap();
        }
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

    #[test]
    fn query_filtered_empty_filter_returns_all() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let filter = AuditFilter::default();
        let (entries, total) = store.query_filtered(&filter).unwrap();
        assert_eq!(total, 5);
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn query_filtered_by_decision() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let filter = AuditFilter {
            decision: Some("Deny".into()),
            ..Default::default()
        };
        let (entries, total) = store.query_filtered(&filter).unwrap();
        assert_eq!(total, 2);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.decision == "Deny"));
    }

    #[test]
    fn query_filtered_by_principal() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let filter = AuditFilter {
            principal: Some("alice".into()),
            ..Default::default()
        };
        let (entries, total) = store.query_filtered(&filter).unwrap();
        assert_eq!(total, 3);
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e.principal == "alice"));
    }

    #[test]
    fn query_filtered_by_action_kind() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let filter = AuditFilter {
            action_kind: Some("FileRead".into()),
            ..Default::default()
        };
        let (entries, total) = store.query_filtered(&filter).unwrap();
        assert_eq!(total, 2);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn query_filtered_combined() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let filter = AuditFilter {
            principal: Some("alice".into()),
            decision: Some("Allow".into()),
            ..Default::default()
        };
        let (entries, total) = store.query_filtered(&filter).unwrap();
        assert_eq!(total, 2); // alice has 2 Allow entries (FileRead + DirList)
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn query_filtered_with_pagination() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let filter = AuditFilter {
            limit: Some(2),
            offset: Some(0),
            ..Default::default()
        };
        let (entries, total) = store.query_filtered(&filter).unwrap();
        assert_eq!(total, 5); // total is unaffected by limit
        assert_eq!(entries.len(), 2);

        // Page 2
        let filter = AuditFilter {
            limit: Some(2),
            offset: Some(2),
            ..Default::default()
        };
        let (entries, _) = store.query_filtered(&filter).unwrap();
        assert_eq!(entries.len(), 2);

        // Page 3 (partial)
        let filter = AuditFilter {
            limit: Some(2),
            offset: Some(4),
            ..Default::default()
        };
        let (entries, _) = store.query_filtered(&filter).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn query_filtered_reason_search() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let filter = AuditFilter {
            reason_contains: Some("Deny".into()),
            ..Default::default()
        };
        let (entries, total) = store.query_filtered(&filter).unwrap();
        assert_eq!(total, 2);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn count_by_action_kind_returns_grouped_counts() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let counts = store
            .count_by_action_kind(&AuditFilter::default())
            .unwrap();
        assert!(!counts.is_empty());
        let total: usize = counts.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn count_by_decision_returns_grouped_counts() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let counts = store
            .count_by_decision(&AuditFilter::default())
            .unwrap();
        let allow_count = counts.iter().find(|(d, _)| d == "Allow").map(|(_, c)| *c).unwrap_or(0);
        let deny_count = counts.iter().find(|(d, _)| d == "Deny").map(|(_, c)| *c).unwrap_or(0);
        assert_eq!(allow_count, 3);
        assert_eq!(deny_count, 2);
    }

    #[test]
    fn query_after_id_returns_newer_entries() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        // Get first 3 entries by querying after id=0
        let all = store.query_after_id(0).unwrap();
        assert_eq!(all.len(), 5);

        // Get entries after the 3rd row
        let third_row_id = all[2].0;
        let remaining = store.query_after_id(third_row_id).unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().all(|(id, _)| *id > third_row_id));
    }

    #[test]
    fn query_after_id_returns_empty_when_none_newer() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();
        populate_test_store(&mut store);

        let all = store.query_after_id(0).unwrap();
        let last_id = all.last().unwrap().0;
        let empty = store.query_after_id(last_id).unwrap();
        assert!(empty.is_empty());
    }
}
