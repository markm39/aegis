use aegis_types::{AegisConfig, AegisError};
use std::io::Write;

use crate::backend::SandboxBackend;
use crate::profile::generate_seatbelt_profile;

/// macOS Seatbelt sandbox backend.
///
/// Uses `sandbox-exec` with a generated SBPL profile to enforce
/// OS-level isolation on sandboxed processes.
#[cfg(target_os = "macos")]
pub struct SeatbeltBackend;

#[cfg(target_os = "macos")]
impl SandboxBackend for SeatbeltBackend {
    fn prepare(&self, config: &AegisConfig) -> Result<(), AegisError> {
        // Ensure the sandbox directory exists
        std::fs::create_dir_all(&config.sandbox_dir).map_err(|e| {
            AegisError::SandboxError(format!(
                "failed to create sandbox dir {}: {e}",
                config.sandbox_dir.display()
            ))
        })?;

        // Generate and validate the profile by writing it to a temp file
        let profile = generate_seatbelt_profile(config);
        let mut tmp = tempfile::NamedTempFile::new().map_err(|e| {
            AegisError::SandboxError(format!("failed to create temp profile file: {e}"))
        })?;
        tmp.write_all(profile.as_bytes()).map_err(|e| {
            AegisError::SandboxError(format!("failed to write temp profile: {e}"))
        })?;

        tracing::debug!(
            profile_path = %tmp.path().display(),
            "seatbelt profile prepared"
        );

        Ok(())
    }

    fn exec(
        &self,
        command: &str,
        args: &[String],
        config: &AegisConfig,
    ) -> Result<std::process::ExitStatus, AegisError> {
        let profile = generate_seatbelt_profile(config);

        // Write the profile to a temp file that persists for the duration of the command
        let mut tmp = tempfile::NamedTempFile::new().map_err(|e| {
            AegisError::SandboxError(format!("failed to create temp profile file: {e}"))
        })?;
        tmp.write_all(profile.as_bytes()).map_err(|e| {
            AegisError::SandboxError(format!("failed to write temp profile: {e}"))
        })?;
        tmp.flush().map_err(|e| {
            AegisError::SandboxError(format!("failed to flush temp profile: {e}"))
        })?;

        let profile_path = tmp.path();

        tracing::info!(
            command,
            profile_path = %profile_path.display(),
            "running command in seatbelt sandbox"
        );

        let status = std::process::Command::new("sandbox-exec")
            .arg("-f")
            .arg(profile_path)
            .arg(command)
            .args(args)
            .status()
            .map_err(|e| {
                AegisError::SandboxError(format!("failed to run sandbox-exec: {e}"))
            })?;

        Ok(status)
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
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
            isolation: IsolationConfig::Seatbelt {
                profile_overrides: None,
            },
        }
    }

    #[test]
    fn seatbelt_runs_echo_successfully() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        let backend = SeatbeltBackend;
        backend.prepare(&config).expect("prepare failed");

        let status = backend
            .exec("/bin/echo", &["hello".to_string()], &config)
            .expect("failed to run echo in sandbox");

        assert!(status.success());
    }

    #[test]
    fn seatbelt_blocks_write_outside_sandbox() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        let backend = SeatbeltBackend;
        backend.prepare(&config).expect("prepare failed");

        // Attempt to touch a file outside the sandbox directory.
        // The seatbelt profile should deny this write operation.
        let forbidden_path = format!(
            "/tmp/aegis_test_forbidden_{}",
            std::process::id()
        );

        let status = backend
            .exec(
                "/usr/bin/touch",
                &[forbidden_path.clone()],
                &config,
            )
            .expect("sandbox-exec itself should launch successfully");

        assert!(
            !status.success(),
            "touch to {forbidden_path} should have been blocked by seatbelt"
        );

        // Ensure the file was not created
        assert!(
            !std::path::Path::new(&forbidden_path).exists(),
            "file should not exist outside sandbox"
        );
    }
}
