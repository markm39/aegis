//! Error types shared across all Aegis crates.

/// Errors that can occur across the Aegis runtime.
///
/// Each variant corresponds to a different subsystem: policy engine,
/// audit ledger, sandbox, filesystem, or configuration.
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
