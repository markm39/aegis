//! Error types shared across all Aegis crates.

/// Errors that can occur across the Aegis runtime.
///
/// Each variant corresponds to a different subsystem: policy engine,
/// audit ledger, sandbox, filesystem, or configuration.
#[derive(Debug, thiserror::Error)]
pub enum AegisError {
    /// Cedar policy evaluation or parsing failure.
    #[error("policy evaluation failed: {0}")]
    PolicyError(String),

    /// Audit ledger (SQLite) read/write failure.
    #[error("audit ledger error: {0}")]
    LedgerError(String),

    /// Sandbox execution or preparation failure.
    #[error("sandbox error: {0}")]
    SandboxError(String),

    /// Filesystem observation or interception error.
    #[error("filesystem interception error: {0}")]
    FsError(String),

    /// Configuration loading or validation error.
    #[error("configuration error: {0}")]
    ConfigError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        assert_eq!(
            AegisError::PolicyError("test".into()).to_string(),
            "policy evaluation failed: test"
        );
        assert_eq!(
            AegisError::LedgerError("db locked".into()).to_string(),
            "audit ledger error: db locked"
        );
        assert_eq!(
            AegisError::SandboxError("denied".into()).to_string(),
            "sandbox error: denied"
        );
        assert_eq!(
            AegisError::FsError("not found".into()).to_string(),
            "filesystem interception error: not found"
        );
        assert_eq!(
            AegisError::ConfigError("missing field".into()).to_string(),
            "configuration error: missing field"
        );
    }
}
