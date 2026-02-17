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
