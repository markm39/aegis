/// Aegis sidecar: FUSE filesystem interception and transparent network proxy.
///
/// This crate provides the central interception layer for Aegis. It intercepts
/// file operations via a FUSE passthrough filesystem and network connections via
/// a transparent TCP proxy, enforcing Cedar policies and logging all decisions
/// to the audit ledger.
pub mod coordinator;
pub mod fs;
pub mod net;

pub use coordinator::Sidecar;
pub use fs::AegisFuse;
pub use net::NetworkProxy;
