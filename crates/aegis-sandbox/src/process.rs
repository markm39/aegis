use aegis_types::{AegisConfig, AegisError};

use crate::backend::SandboxBackend;

/// Fallback backend with no OS-level sandboxing.
///
/// Runs commands directly as child processes. Useful for platforms
/// where Seatbelt or other isolation mechanisms are unavailable.
pub struct ProcessBackend;

impl SandboxBackend for ProcessBackend {
    fn prepare(&self, config: &AegisConfig) -> Result<(), AegisError> {
        // Ensure the sandbox directory exists
        std::fs::create_dir_all(&config.sandbox_dir).map_err(|e| {
            AegisError::SandboxError(format!(
                "failed to create sandbox dir {}: {e}",
                config.sandbox_dir.display()
            ))
        })?;

        tracing::debug!(
            sandbox_dir = %config.sandbox_dir.display(),
            "process backend prepared (no OS-level isolation)"
        );

        Ok(())
    }

    fn exec(
        &self,
        command: &str,
        args: &[String],
        config: &AegisConfig,
    ) -> Result<std::process::ExitStatus, AegisError> {
        tracing::info!(
            command,
            sandbox_dir = %config.sandbox_dir.display(),
            "running command without OS-level sandboxing"
        );

        let status = std::process::Command::new(command)
            .args(args)
            .current_dir(&config.sandbox_dir)
            .status()
            .map_err(|e| {
                AegisError::SandboxError(format!("failed to run command '{command}': {e}"))
            })?;

        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::IsolationConfig;
    use std::path::PathBuf;

    fn test_config(sandbox_dir: PathBuf) -> AegisConfig {
        AegisConfig {
            name: "test-agent".into(),
            sandbox_dir,
            policy_paths: vec![],
            schema_path: None,
            ledger_path: PathBuf::from("/tmp/audit.db"),
            allowed_network: vec![],
            isolation: IsolationConfig::Process,
        }
    }

    #[test]
    fn process_backend_runs_command_successfully() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        let status = backend
            .exec("echo", &["hello".to_string()], &config)
            .expect("failed to run echo");

        assert!(status.success());
    }

    #[test]
    fn process_backend_prepare_creates_sandbox_dir() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let sandbox_dir = dir.path().join("nested").join("sandbox");
        let config = test_config(sandbox_dir.clone());

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        assert!(sandbox_dir.exists());
    }
}
