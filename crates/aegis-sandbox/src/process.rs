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

    fn spawn_and_wait(
        &self,
        command: &str,
        args: &[String],
        config: &AegisConfig,
        env: &[(&str, &str)],
    ) -> Result<(u32, std::process::ExitStatus), AegisError> {
        tracing::info!(
            command,
            sandbox_dir = %config.sandbox_dir.display(),
            "spawning command without OS-level sandboxing"
        );

        let mut cmd = std::process::Command::new(command);
        cmd.args(args).current_dir(&config.sandbox_dir);
        for (key, val) in env {
            cmd.env(key, val);
        }

        let mut child = cmd.spawn().map_err(|e| {
            AegisError::SandboxError(format!("failed to spawn command '{command}': {e}"))
        })?;

        let pid = child.id();

        let status = child.wait().map_err(|e| {
            AegisError::SandboxError(format!("failed to wait for command '{command}': {e}"))
        })?;

        Ok((pid, status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::IsolationConfig;

    #[test]
    fn process_backend_runs_command_successfully() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = crate::test_helpers::test_config(dir.path().to_path_buf(), IsolationConfig::Process);

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        let status = backend
            .exec("echo", &["hello".to_string()], &config)
            .expect("failed to run echo");

        assert!(status.success());
    }

    #[test]
    fn process_backend_spawn_and_wait_returns_real_pid() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = crate::test_helpers::test_config(dir.path().to_path_buf(), IsolationConfig::Process);

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        let (pid, status) = backend
            .spawn_and_wait("echo", &["hello".to_string()], &config, &[])
            .expect("spawn_and_wait failed");

        assert!(pid > 0, "should return a real PID, got {pid}");
        assert!(status.success());
    }

    #[test]
    fn process_backend_spawn_and_wait_passes_env() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = crate::test_helpers::test_config(dir.path().to_path_buf(), IsolationConfig::Process);
        let output_path = dir.path().join("env_output.txt");

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        let output_str = output_path.display().to_string();
        let script = format!("printenv AEGIS_TEST_VAR > {output_str}");

        let (pid, status) = backend
            .spawn_and_wait(
                "sh",
                &["-c".to_string(), script],
                &config,
                &[("AEGIS_TEST_VAR", "test_value_42")],
            )
            .expect("spawn_and_wait failed");

        assert!(pid > 0);
        assert!(status.success());

        let content = std::fs::read_to_string(&output_path).expect("failed to read output");
        assert_eq!(content.trim(), "test_value_42");
    }

    #[test]
    fn process_backend_prepare_creates_sandbox_dir() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let sandbox_dir = dir.path().join("nested").join("sandbox");
        let config = crate::test_helpers::test_config(sandbox_dir.clone(), IsolationConfig::Process);

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        assert!(sandbox_dir.exists());
    }
}
