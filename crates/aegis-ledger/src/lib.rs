//! Append-only, SHA-256 hash-chained audit ledger backed by SQLite.
//!
//! Every action and its policy verdict are recorded as an [`AuditEntry`] linked
//! to the previous entry's hash, forming a tamper-evident chain. Supports
//! sessions, filtered queries, policy snapshots, and compliance statistics.

pub mod async_pipeline;
pub mod channel_audit;
pub mod entry;
pub mod filter;
pub mod fs_audit;
pub mod integrity;
pub mod middleware;
pub(crate) mod parse_helpers;
pub mod policy_snapshot;
pub mod query;
pub mod session;
pub mod siem_export;
pub mod stats;
pub mod store;

pub use async_pipeline::{AsyncAuditConfig, AsyncAuditWriter, AuditCommand};
pub use channel_audit::{ChannelAuditEntry, ChannelDirection};
pub use entry::AuditEntry;
pub use filter::AuditFilter;
pub use fs_audit::{FsAuditEntry, FsOperation};
pub use integrity::IntegrityReport;
pub use middleware::AuditMiddleware;
pub use policy_snapshot::PolicySnapshot;
pub use query::row_to_entry;
pub use session::Session;
pub use siem_export::SiemFormat;
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
