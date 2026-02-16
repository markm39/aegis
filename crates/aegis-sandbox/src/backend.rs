use aegis_types::{AegisConfig, AegisError};

/// Trait for OS-level sandbox backends.
///
/// Implementations handle environment preparation and command execution
/// within the isolation boundary.
pub trait SandboxBackend: Send + Sync {
    /// Prepare the sandbox environment (create dirs, write profiles, etc.)
    fn prepare(&self, config: &AegisConfig) -> Result<(), AegisError>;

    /// Execute a command inside the sandbox. Returns the exit status.
    fn exec(
        &self,
        command: &str,
        args: &[String],
        config: &AegisConfig,
    ) -> Result<std::process::ExitStatus, AegisError>;
}
