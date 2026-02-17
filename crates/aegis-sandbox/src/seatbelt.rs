use aegis_types::{AegisConfig, AegisError};
use std::io::Write;

use crate::backend::SandboxBackend;
use crate::profile::generate_seatbelt_profile;

/// macOS Seatbelt sandbox backend.
///
/// Uses `sandbox-exec` with a generated SBPL profile to enforce
/// OS-level isolation on sandboxed processes.
///
/// Can be created with a custom SBPL profile string (via `with_profile()`)
/// or fall back to generating one from the config (default constructor).
#[cfg(target_os = "macos")]
pub struct SeatbeltBackend {
    custom_profile: Option<String>,
}

#[cfg(target_os = "macos")]
impl SeatbeltBackend {
    /// Create a new SeatbeltBackend with no custom profile.
    ///
    /// Will generate a profile from the config using `generate_seatbelt_profile()`.
    pub fn new() -> Self {
        Self {
            custom_profile: None,
        }
    }

    /// Create a SeatbeltBackend with a pre-compiled SBPL profile string.
    ///
    /// Used by the Cedar-to-SBPL compiler to pass in a tailored profile
    /// that reflects the loaded Cedar policies.
    pub fn with_profile(profile: String) -> Self {
        Self {
            custom_profile: Some(profile),
        }
    }

    /// Get the SBPL profile to use: custom if set, otherwise generated from config.
    fn resolve_profile(&self, config: &AegisConfig) -> String {
        match &self.custom_profile {
            Some(p) => p.clone(),
            None => generate_seatbelt_profile(config),
        }
    }

    /// Write the profile to a temp file and return the handle (keeps file alive).
    fn write_profile_to_tempfile(
        &self,
        config: &AegisConfig,
    ) -> Result<tempfile::NamedTempFile, AegisError> {
        let profile = self.resolve_profile(config);
        let mut tmp = tempfile::NamedTempFile::new().map_err(|e| {
            AegisError::SandboxError(format!("failed to create temp profile file: {e}"))
        })?;
        tmp.write_all(profile.as_bytes()).map_err(|e| {
            AegisError::SandboxError(format!("failed to write temp profile: {e}"))
        })?;
        tmp.flush().map_err(|e| {
            AegisError::SandboxError(format!("failed to flush temp profile: {e}"))
        })?;
        Ok(tmp)
    }
}

#[cfg(target_os = "macos")]
impl Default for SeatbeltBackend {
    fn default() -> Self {
        Self::new()
    }
}

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

        // Validate the profile by writing it to a temp file
        let tmp = self.write_profile_to_tempfile(config)?;
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
        let tmp = self.write_profile_to_tempfile(config)?;

        tracing::info!(
            command,
            profile_path = %tmp.path().display(),
            "running command in seatbelt sandbox"
        );

        let status = std::process::Command::new("sandbox-exec")
            .arg("-f")
            .arg(tmp.path())
            .arg(command)
            .args(args)
            .status()
            .map_err(|e| {
                AegisError::SandboxError(format!("failed to run sandbox-exec: {e}"))
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
        let tmp = self.write_profile_to_tempfile(config)?;

        tracing::info!(
            command,
            profile_path = %tmp.path().display(),
            "spawning command in seatbelt sandbox"
        );

        let mut cmd = std::process::Command::new("sandbox-exec");
        cmd.arg("-f").arg(tmp.path()).arg(command).args(args);

        for (key, val) in env {
            cmd.env(key, val);
        }

        let mut child = cmd.spawn().map_err(|e| {
            AegisError::SandboxError(format!("failed to spawn sandbox-exec: {e}"))
        })?;

        let pid = child.id();

        let status = child.wait().map_err(|e| {
            AegisError::SandboxError(format!("failed to wait for sandbox-exec: {e}"))
        })?;

        Ok((pid, status))
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
            observer: aegis_types::ObserverConfig::default(),
        }
    }

    #[test]
    fn seatbelt_runs_echo_successfully() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        let backend = SeatbeltBackend::new();
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

        let backend = SeatbeltBackend::new();
        backend.prepare(&config).expect("prepare failed");

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

        assert!(
            !std::path::Path::new(&forbidden_path).exists(),
            "file should not exist outside sandbox"
        );
    }

    #[test]
    fn seatbelt_with_custom_profile() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        // A permissive profile that allows echo to run
        let profile = "(version 1)\n(allow default)\n".to_string();
        let backend = SeatbeltBackend::with_profile(profile);
        backend.prepare(&config).expect("prepare failed");

        let status = backend
            .exec("/bin/echo", &["custom-profile".to_string()], &config)
            .expect("failed to run echo with custom profile");

        assert!(status.success());
    }

    #[test]
    fn spawn_and_wait_returns_pid_and_status() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        let backend = SeatbeltBackend::new();
        backend.prepare(&config).expect("prepare failed");

        let (pid, status) = backend
            .spawn_and_wait("/bin/echo", &["hello".to_string()], &config, &[])
            .expect("spawn_and_wait failed");

        assert!(pid > 0, "should have a real PID");
        assert!(status.success());
    }

    #[test]
    fn spawn_and_wait_passes_env_vars() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        let backend = SeatbeltBackend::new();
        backend.prepare(&config).expect("prepare failed");

        let (_, status) = backend
            .spawn_and_wait(
                "/usr/bin/env",
                &[],
                &config,
                &[("AEGIS_TEST_VAR", "hello")],
            )
            .expect("spawn_and_wait failed");

        assert!(status.success());
    }
}
