//! Filesystem audit logging for file change tracking.
//!
//! Records metadata about filesystem operations observed by aegis-observer
//! or the sandbox, including before/after hashes for tamper detection and
//! change verification. File paths are validated against directory traversal.

use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use aegis_types::AegisError;

use crate::store::AuditStore;

/// The type of filesystem operation recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsOperation {
    /// A new file was created.
    Create,
    /// An existing file was modified.
    Modify,
    /// A file was deleted.
    Delete,
}

impl std::fmt::Display for FsOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsOperation::Create => write!(f, "Create"),
            FsOperation::Modify => write!(f, "Modify"),
            FsOperation::Delete => write!(f, "Delete"),
        }
    }
}

impl std::str::FromStr for FsOperation {
    type Err = AegisError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Create" => Ok(FsOperation::Create),
            "Modify" => Ok(FsOperation::Modify),
            "Delete" => Ok(FsOperation::Delete),
            _ => Err(AegisError::LedgerError(format!(
                "invalid fs operation: {s:?} (expected Create, Modify, or Delete)"
            ))),
        }
    }
}

/// A single entry in the filesystem audit log.
///
/// Records a file operation with before/after content hashes for change
/// verification. Paths are validated to prevent directory traversal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FsAuditEntry {
    /// Unique identifier for this filesystem audit entry.
    pub entry_id: Uuid,
    /// Validated absolute file path (no traversal sequences).
    pub path: String,
    /// SHA-256 hash of the file content before the operation (None for Create).
    pub before_hash: Option<String>,
    /// SHA-256 hash of the file content after the operation (None for Delete).
    pub after_hash: Option<String>,
    /// Change in file size in bytes (positive = grew, negative = shrank).
    pub size_delta: i64,
    /// The type of filesystem operation.
    pub operation: FsOperation,
    /// When this entry was created.
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hash of the previous fs audit entry (hash-chain linkage).
    pub prev_hash: String,
    /// SHA-256 hash of this entry's contents.
    pub entry_hash: String,
}

/// Validate a file path against directory traversal attacks.
///
/// Rejects paths containing `..` components, which could be used to
/// escape intended directories. Also rejects empty paths and paths
/// that are not absolute.
pub fn validate_path(path: &str) -> Result<(), AegisError> {
    if path.is_empty() {
        return Err(AegisError::LedgerError(
            "fs audit path must not be empty".to_string(),
        ));
    }

    // Reject directory traversal sequences
    for component in std::path::Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(AegisError::LedgerError(format!(
                "fs audit path contains directory traversal: {path:?}"
            )));
        }
    }

    // Require absolute paths
    if !std::path::Path::new(path).is_absolute() {
        return Err(AegisError::LedgerError(format!(
            "fs audit path must be absolute: {path:?}"
        )));
    }

    Ok(())
}

/// Compute a SHA-256 hash of file content for audit logging.
pub fn hash_file_content(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Compute the entry hash for a filesystem audit entry.
#[allow(clippy::too_many_arguments)]
fn compute_fs_entry_hash(
    entry_id: &Uuid,
    path: &str,
    before_hash: Option<&str>,
    after_hash: Option<&str>,
    size_delta: i64,
    operation: &FsOperation,
    timestamp: &DateTime<Utc>,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry_id.to_string());
    hasher.update(path);
    hasher.update(before_hash.unwrap_or(""));
    hasher.update(after_hash.unwrap_or(""));
    hasher.update(size_delta.to_string());
    hasher.update(operation.to_string());
    hasher.update(timestamp.to_rfc3339());
    hasher.update(prev_hash);
    hex::encode(hasher.finalize())
}

impl AuditStore {
    /// Insert a new filesystem audit entry.
    ///
    /// The `path` is validated against directory traversal before insertion.
    /// `before_hash` and `after_hash` are SHA-256 hex digests of file content
    /// (use [`hash_file_content`] to compute them).
    pub fn insert_fs_audit(
        &mut self,
        path: &str,
        before_hash: Option<&str>,
        after_hash: Option<&str>,
        size_delta: i64,
        operation: FsOperation,
    ) -> Result<FsAuditEntry, AegisError> {
        validate_path(path)?;

        let entry_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let prev_hash = self
            .latest_fs_hash()
            .unwrap_or_else(|| "genesis".to_string());

        let entry_hash = compute_fs_entry_hash(
            &entry_id,
            path,
            before_hash,
            after_hash,
            size_delta,
            &operation,
            &timestamp,
            &prev_hash,
        );

        self.connection()
            .execute(
                "INSERT INTO fs_audit_log (entry_id, path, before_hash, after_hash, size_delta, operation, timestamp, prev_hash, entry_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    entry_id.to_string(),
                    path,
                    before_hash,
                    after_hash,
                    size_delta,
                    operation.to_string(),
                    timestamp.to_rfc3339(),
                    prev_hash,
                    entry_hash,
                ],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to insert fs audit entry: {e}")))?;

        let entry = FsAuditEntry {
            entry_id,
            path: path.to_string(),
            before_hash: before_hash.map(String::from),
            after_hash: after_hash.map(String::from),
            size_delta,
            operation,
            timestamp,
            prev_hash,
            entry_hash,
        };

        // Notify middleware
        self.notify_fs_middleware(&entry);

        Ok(entry)
    }

    /// Query the last N filesystem audit entries, ordered by id DESC.
    pub fn query_fs_audit_last(&self, n: usize) -> Result<Vec<FsAuditEntry>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                "SELECT entry_id, path, before_hash, after_hash, size_delta, operation, timestamp, prev_hash, entry_hash
                 FROM fs_audit_log ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| AegisError::LedgerError(format!("query_fs_audit_last prepare: {e}")))?;

        let rows = stmt
            .query_map(params![n as i64], |row| {
                let operation_str: String = row.get(5)?;
                let operation: FsOperation = operation_str.parse().map_err(|e: AegisError| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e.to_string(),
                        )),
                    )
                })?;

                Ok(FsAuditEntry {
                    entry_id: crate::parse_helpers::parse_uuid(&row.get::<_, String>(0)?, 0)?,
                    path: row.get(1)?,
                    before_hash: row.get(2)?,
                    after_hash: row.get(3)?,
                    size_delta: row.get(4)?,
                    operation,
                    timestamp: crate::parse_helpers::parse_datetime(&row.get::<_, String>(6)?, 6)?,
                    prev_hash: row.get(7)?,
                    entry_hash: row.get(8)?,
                })
            })
            .map_err(|e| AegisError::LedgerError(format!("query_fs_audit_last failed: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("query_fs_audit_last read: {e}")))
    }

    /// Return the latest fs audit entry hash, or None if the table is empty.
    fn latest_fs_hash(&self) -> Option<String> {
        self.connection()
            .query_row(
                "SELECT entry_hash FROM fs_audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_db_path;

    #[test]
    fn fs_audit_entry_insert_and_query() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let before = hash_file_content(b"old content");
        let after = hash_file_content(b"new content, longer");

        let entry = store
            .insert_fs_audit(
                "/tmp/test.txt",
                Some(&before),
                Some(&after),
                8, // "new content, longer" is 8 bytes longer than "old content"
                FsOperation::Modify,
            )
            .unwrap();

        assert_eq!(entry.path, "/tmp/test.txt");
        assert_eq!(entry.before_hash.as_deref(), Some(before.as_str()));
        assert_eq!(entry.after_hash.as_deref(), Some(after.as_str()));
        assert_eq!(entry.size_delta, 8);
        assert_eq!(entry.operation, FsOperation::Modify);
        assert_eq!(entry.prev_hash, "genesis");

        let results = store.query_fs_audit_last(10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, entry.entry_id);
    }

    #[test]
    fn fs_audit_captures_before_after_hashes() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        // Create: no before_hash
        let after = hash_file_content(b"new file");
        let create_entry = store
            .insert_fs_audit("/tmp/new.txt", None, Some(&after), 8, FsOperation::Create)
            .unwrap();
        assert!(create_entry.before_hash.is_none());
        assert_eq!(create_entry.after_hash.as_deref(), Some(after.as_str()));

        // Delete: no after_hash
        let before = hash_file_content(b"doomed file");
        let delete_entry = store
            .insert_fs_audit(
                "/tmp/doomed.txt",
                Some(&before),
                None,
                -11,
                FsOperation::Delete,
            )
            .unwrap();
        assert_eq!(delete_entry.before_hash.as_deref(), Some(before.as_str()));
        assert!(delete_entry.after_hash.is_none());

        // Modify: both hashes present
        let before2 = hash_file_content(b"before");
        let after2 = hash_file_content(b"after");
        let modify_entry = store
            .insert_fs_audit(
                "/tmp/mod.txt",
                Some(&before2),
                Some(&after2),
                -1,
                FsOperation::Modify,
            )
            .unwrap();
        assert!(modify_entry.before_hash.is_some());
        assert!(modify_entry.after_hash.is_some());
        assert_ne!(modify_entry.before_hash, modify_entry.after_hash);
    }

    #[test]
    fn fs_audit_path_traversal_rejected() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        // Attempt directory traversal
        let result = store.insert_fs_audit(
            "/tmp/../etc/passwd",
            None,
            Some(&hash_file_content(b"evil")),
            4,
            FsOperation::Create,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("directory traversal"), "error: {err}");
    }

    #[test]
    fn fs_audit_relative_path_rejected() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let result = store.insert_fs_audit(
            "relative/path.txt",
            None,
            Some(&hash_file_content(b"data")),
            4,
            FsOperation::Create,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("absolute"), "error: {err}");
    }

    #[test]
    fn fs_audit_empty_path_rejected() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let result = store.insert_fs_audit(
            "",
            None,
            Some(&hash_file_content(b"data")),
            4,
            FsOperation::Create,
        );
        assert!(result.is_err());
    }

    #[test]
    fn fs_audit_hash_chain() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let e1 = store
            .insert_fs_audit(
                "/tmp/f1.txt",
                None,
                Some(&hash_file_content(b"data1")),
                5,
                FsOperation::Create,
            )
            .unwrap();

        let e2 = store
            .insert_fs_audit(
                "/tmp/f2.txt",
                None,
                Some(&hash_file_content(b"data2")),
                5,
                FsOperation::Create,
            )
            .unwrap();

        assert_eq!(e2.prev_hash, e1.entry_hash);
    }

    #[test]
    fn fs_operation_serialization() {
        assert_eq!(FsOperation::Create.to_string(), "Create");
        assert_eq!(FsOperation::Modify.to_string(), "Modify");
        assert_eq!(FsOperation::Delete.to_string(), "Delete");

        assert_eq!(
            "Create".parse::<FsOperation>().unwrap(),
            FsOperation::Create
        );
        assert_eq!(
            "Modify".parse::<FsOperation>().unwrap(),
            FsOperation::Modify
        );
        assert_eq!(
            "Delete".parse::<FsOperation>().unwrap(),
            FsOperation::Delete
        );
        assert!("Invalid".parse::<FsOperation>().is_err());
    }

    #[test]
    fn validate_path_allows_valid_absolute_paths() {
        assert!(validate_path("/tmp/test.txt").is_ok());
        assert!(validate_path("/home/user/file.rs").is_ok());
        assert!(validate_path("/").is_ok());
    }

    #[test]
    fn validate_path_rejects_traversal() {
        assert!(validate_path("/tmp/../etc/passwd").is_err());
        assert!(validate_path("/tmp/foo/../../secret").is_err());
    }
}
