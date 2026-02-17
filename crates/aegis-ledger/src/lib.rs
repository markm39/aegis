//! Append-only, SHA-256 hash-chained audit ledger backed by SQLite.
//!
//! Every action and its policy verdict are recorded as an [`AuditEntry`] linked
//! to the previous entry's hash, forming a tamper-evident chain. Supports
//! sessions, filtered queries, policy snapshots, and compliance statistics.

pub mod entry;
pub mod filter;
pub mod integrity;
pub(crate) mod parse_helpers;
pub mod policy_snapshot;
pub mod query;
pub mod session;
pub mod stats;
pub mod store;

pub use entry::AuditEntry;
pub use filter::AuditFilter;
pub use integrity::IntegrityReport;
pub use policy_snapshot::PolicySnapshot;
pub use query::row_to_entry;
pub use session::Session;
pub use stats::AuditStats;
pub use store::AuditStore;

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::store::AuditStore;
    use tempfile::NamedTempFile;

    /// Create a temporary database file and open an AuditStore on it.
    ///
    /// Returns both the handle (to keep the file alive) and the store.
    pub fn test_db() -> (NamedTempFile, AuditStore) {
        let tmp = NamedTempFile::new().expect("failed to create temp file");
        let store = AuditStore::open(tmp.path()).expect("failed to open store");
        (tmp, store)
    }

    /// Create a temporary database file without opening a store.
    pub fn test_db_path() -> NamedTempFile {
        NamedTempFile::new().expect("failed to create temp file")
    }
}
