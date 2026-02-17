//! Error types shared across all Aegis crates.

/// Errors that can occur across the Aegis runtime.
///
/// Each variant corresponds to a different subsystem: policy engine,
/// audit ledger, sandbox, filesystem, network, or configuration.
#[derive(Debug, thiserror::Error)]
pub enum AegisError {
    #[error("policy evaluation failed: {0}")]
    PolicyError(String),

    #[error("audit ledger error: {0}")]
    LedgerError(String),

    #[error("sandbox error: {0}")]
    SandboxError(String),

    #[error("filesystem interception error: {0}")]
    FsError(String),

    #[error("network proxy error: {0}")]
    NetError(String),

    #[error("configuration error: {0}")]
    ConfigError(String),
}
