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

    /// Spawn a command inside the sandbox and wait for it to finish.
    ///
    /// Returns the child PID and exit status. Supports passing environment
    /// variables to the spawned process. The default implementation ignores
    /// env vars and delegates to `exec()` with pid=0.
    fn spawn_and_wait(
        &self,
        command: &str,
        args: &[String],
        config: &AegisConfig,
        _env: &[(&str, &str)],
    ) -> Result<(u32, std::process::ExitStatus), AegisError> {
        self.exec(command, args, config).map(|s| (0, s))
    }
}
