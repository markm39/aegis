/// Policy snapshot tracking for change auditing.
///
/// Records the content and hash of policy files at each session start.
/// If the policy hash hasn't changed since the last snapshot for this config,
/// the snapshot is a no-op. This gives a complete history of when policies
/// changed, enabling compliance audits ("what policy was active at time T?").
use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use aegis_types::AegisError;

use crate::parse_helpers::{parse_datetime, parse_uuid};
use crate::store::AuditStore;

/// A point-in-time snapshot of the policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub snapshot_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub policy_hash: String,
    pub policy_files: BTreeMap<String, String>,
    pub session_id: Option<Uuid>,
    pub config_name: String,
}

/// Compute a deterministic hash of a set of policy files.
///
/// Sorts files by name and hashes `filename + "\n" + content` for each,
/// ensuring the result is independent of filesystem ordering.
pub fn compute_policy_hash(files: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (name, content) in files {
        hasher.update(name.as_bytes());
        hasher.update(b"\n");
        hasher.update(content.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Read all `.cedar` files from a directory into a sorted map.
pub fn read_policy_files(dir: &Path) -> Result<BTreeMap<String, String>, AegisError> {
    let mut files = BTreeMap::new();

    let entries = std::fs::read_dir(dir).map_err(|e| {
        AegisError::PolicyError(format!("failed to read policy dir {}: {e}", dir.display()))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            AegisError::PolicyError(format!("failed to read dir entry: {e}"))
        })?;

        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "cedar") {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let content = std::fs::read_to_string(&path).map_err(|e| {
                AegisError::PolicyError(format!("failed to read {}: {e}", path.display()))
            })?;
            files.insert(name, content);
        }
    }

    Ok(files)
}

impl AuditStore {
    /// Record a policy snapshot if the hash has changed since the last one.
    ///
    /// Returns `Some(snapshot)` if a new snapshot was recorded, or `None` if
    /// the policy hash matches the most recent snapshot (no-op).
    pub fn record_policy_snapshot(
        &mut self,
        config_name: &str,
        policy_files: &BTreeMap<String, String>,
        session_id: Option<&Uuid>,
    ) -> Result<Option<PolicySnapshot>, AegisError> {
        let policy_hash = compute_policy_hash(policy_files);

        // Check if the hash matches the most recent snapshot
        let latest = self.latest_policy_snapshot(config_name)?;
        if let Some(ref prev) = latest {
            if prev.policy_hash == policy_hash {
                tracing::debug!(
                    config_name,
                    hash = %policy_hash,
                    "policy unchanged, skipping snapshot"
                );
                return Ok(None);
            }
        }

        let snapshot_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let files_json = serde_json::to_string(policy_files)
            .unwrap_or_else(|_| "{}".to_string());

        self.connection()
            .execute(
                "INSERT INTO policy_snapshots (snapshot_id, timestamp, policy_hash, policy_files, policy_content, session_id, config_name)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    snapshot_id.to_string(),
                    timestamp.to_rfc3339(),
                    policy_hash,
                    files_json,
                    files_json, // policy_content is the same as policy_files for now
                    session_id.map(|s| s.to_string()),
                    config_name,
                ],
            )
            .map_err(|e| {
                AegisError::LedgerError(format!("failed to record policy snapshot: {e}"))
            })?;

        let snapshot = PolicySnapshot {
            snapshot_id,
            timestamp,
            policy_hash,
            policy_files: policy_files.clone(),
            session_id: session_id.copied(),
            config_name: config_name.to_string(),
        };

        tracing::info!(
            snapshot_id = %snapshot.snapshot_id,
            hash = %snapshot.policy_hash,
            files = snapshot.policy_files.len(),
            "policy snapshot recorded"
        );

        Ok(Some(snapshot))
    }

    /// Get the most recent policy snapshot for a config.
    pub fn latest_policy_snapshot(
        &self,
        config_name: &str,
    ) -> Result<Option<PolicySnapshot>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                "SELECT snapshot_id, timestamp, policy_hash, policy_files, session_id, config_name
                 FROM policy_snapshots WHERE config_name = ?1 ORDER BY id DESC LIMIT 1",
            )
            .map_err(|e| {
                AegisError::LedgerError(format!("latest_policy_snapshot prepare: {e}"))
            })?;

        let result = stmt
            .query_row(params![config_name], row_to_policy_snapshot)
            .optional()
            .map_err(|e| {
                AegisError::LedgerError(format!("latest_policy_snapshot query: {e}"))
            })?;

        Ok(result)
    }

    /// List policy snapshots for a config, ordered by most recent first.
    pub fn list_policy_snapshots(
        &self,
        config_name: &str,
        limit: usize,
    ) -> Result<Vec<PolicySnapshot>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                "SELECT snapshot_id, timestamp, policy_hash, policy_files, session_id, config_name
                 FROM policy_snapshots WHERE config_name = ?1 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(|e| {
                AegisError::LedgerError(format!("list_policy_snapshots prepare: {e}"))
            })?;

        let rows = stmt
            .query_map(params![config_name, limit as i64], row_to_policy_snapshot)
            .map_err(|e| {
                AegisError::LedgerError(format!("list_policy_snapshots query: {e}"))
            })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("list_policy_snapshots read: {e}")))
    }
}

/// Map a SQLite row to a PolicySnapshot.
fn row_to_policy_snapshot(row: &rusqlite::Row<'_>) -> rusqlite::Result<PolicySnapshot> {
    let files_json: String = row.get(3)?;
    let policy_files: BTreeMap<String, String> =
        serde_json::from_str(&files_json).unwrap_or_default();

    let session_id = match row.get::<_, Option<String>>(4)? {
        Some(s) => Some(parse_uuid(&s, 4)?),
        None => None,
    };

    Ok(PolicySnapshot {
        snapshot_id: parse_uuid(&row.get::<_, String>(0)?, 0)?,
        timestamp: parse_datetime(&row.get::<_, String>(1)?, 1)?,
        policy_hash: row.get(2)?,
        policy_files,
        session_id,
        config_name: row.get(5)?,
    })
}

use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AuditStore;
    use tempfile::NamedTempFile;

    fn test_db() -> (NamedTempFile, AuditStore) {
        let tmp = NamedTempFile::new().unwrap();
        let store = AuditStore::open(tmp.path()).unwrap();
        (tmp, store)
    }

    fn sample_files() -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        files.insert(
            "default.cedar".to_string(),
            "permit(principal, action, resource);".to_string(),
        );
        files
    }

    #[test]
    fn compute_policy_hash_is_deterministic() {
        let files = sample_files();
        let h1 = compute_policy_hash(&files);
        let h2 = compute_policy_hash(&files);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_policy_hash_changes_with_content() {
        let mut f1 = BTreeMap::new();
        f1.insert("a.cedar".into(), "permit(principal, action, resource);".into());
        let mut f2 = BTreeMap::new();
        f2.insert("a.cedar".into(), "forbid(principal, action, resource);".into());

        assert_ne!(compute_policy_hash(&f1), compute_policy_hash(&f2));
    }

    #[test]
    fn record_snapshot_creates_entry() {
        let (_tmp, mut store) = test_db();
        let files = sample_files();

        let result = store.record_policy_snapshot("test", &files, None).unwrap();
        assert!(result.is_some());

        let snapshot = result.unwrap();
        assert_eq!(snapshot.config_name, "test");
        assert_eq!(snapshot.policy_files.len(), 1);
        assert!(snapshot.session_id.is_none());
    }

    #[test]
    fn duplicate_hash_is_noop() {
        let (_tmp, mut store) = test_db();
        let files = sample_files();

        let first = store.record_policy_snapshot("test", &files, None).unwrap();
        assert!(first.is_some());

        let second = store.record_policy_snapshot("test", &files, None).unwrap();
        assert!(second.is_none(), "same hash should be a no-op");
    }

    #[test]
    fn changed_policy_creates_new_snapshot() {
        let (_tmp, mut store) = test_db();

        let mut files_v1 = BTreeMap::new();
        files_v1.insert("default.cedar".into(), "permit(principal, action, resource);".into());
        store.record_policy_snapshot("test", &files_v1, None).unwrap();

        let mut files_v2 = BTreeMap::new();
        files_v2.insert("default.cedar".into(), "forbid(principal, action, resource);".into());
        let result = store.record_policy_snapshot("test", &files_v2, None).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn latest_policy_snapshot_returns_most_recent() {
        let (_tmp, mut store) = test_db();

        let mut f1 = BTreeMap::new();
        f1.insert("a.cedar".into(), "v1".into());
        store.record_policy_snapshot("test", &f1, None).unwrap();

        let mut f2 = BTreeMap::new();
        f2.insert("a.cedar".into(), "v2".into());
        store.record_policy_snapshot("test", &f2, None).unwrap();

        let latest = store.latest_policy_snapshot("test").unwrap().unwrap();
        assert_eq!(latest.policy_files["a.cedar"], "v2");
    }

    #[test]
    fn list_policy_snapshots_returns_ordered() {
        let (_tmp, mut store) = test_db();

        for i in 0..3 {
            let mut files = BTreeMap::new();
            files.insert("a.cedar".into(), format!("version-{i}"));
            store.record_policy_snapshot("test", &files, None).unwrap();
        }

        let snapshots = store.list_policy_snapshots("test", 10).unwrap();
        assert_eq!(snapshots.len(), 3);
        // Most recent first
        assert_eq!(snapshots[0].policy_files["a.cedar"], "version-2");
        assert_eq!(snapshots[2].policy_files["a.cedar"], "version-0");
    }

    #[test]
    fn snapshot_with_session_id() {
        let (_tmp, mut store) = test_db();
        let session_id = Uuid::new_v4();
        let files = sample_files();

        let result = store
            .record_policy_snapshot("test", &files, Some(&session_id))
            .unwrap();
        assert!(result.is_some());

        let snapshot = result.unwrap();
        assert_eq!(snapshot.session_id, Some(session_id));
    }

    #[test]
    fn different_configs_have_independent_snapshots() {
        let (_tmp, mut store) = test_db();
        let files = sample_files();

        store.record_policy_snapshot("config-a", &files, None).unwrap();
        store.record_policy_snapshot("config-b", &files, None).unwrap();

        // Same hash for different configs should both be recorded
        let a = store.latest_policy_snapshot("config-a").unwrap();
        let b = store.latest_policy_snapshot("config-b").unwrap();
        assert!(a.is_some());
        assert!(b.is_some());
        assert_ne!(a.unwrap().snapshot_id, b.unwrap().snapshot_id);
    }
}
