//! macOS Seatbelt backend using `sandbox-exec`.

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
    pub fn with_profile(profile: impl Into<String>) -> Self {
        Self {
            custom_profile: Some(profile.into()),
        }
    }

    /// Get the SBPL profile to use: custom if set, otherwise generated from config.
    fn resolve_profile(&self, config: &AegisConfig) -> Result<String, AegisError> {
        match &self.custom_profile {
            Some(p) => Ok(p.clone()),
            None => generate_seatbelt_profile(config),
        }
    }

    /// Write the profile to a temp file and return the handle (keeps file alive).
    fn write_profile_to_tempfile(
        &self,
        config: &AegisConfig,
    ) -> Result<tempfile::NamedTempFile, AegisError> {
        let profile = self.resolve_profile(config)?;
        let mut tmp = tempfile::NamedTempFile::new().map_err(|e| {
            AegisError::SandboxError(format!("failed to create temp profile file: {e}"))
        })?;
        tmp.write_all(profile.as_bytes())
            .map_err(|e| AegisError::SandboxError(format!("failed to write temp profile: {e}")))?;
        tmp.flush()
            .map_err(|e| AegisError::SandboxError(format!("failed to flush temp profile: {e}")))?;
        Ok(tmp)
    }

    /// Apply the sandbox profile to the CURRENT process using the macOS sandbox SPI.
    ///
    /// This must be called after `fork()` but before `exec()` to sandbox the child
    /// process without creating a temporary file or spawning an extra process.
    /// Eliminates the TOCTOU window present in the `sandbox-exec` shell-out approach.
    ///
    /// Internally this calls `sandbox_compile_string()` to compile the SBPL profile
    /// into an opaque handle, then `sandbox_apply()` to apply it to the running process,
    /// then `sandbox_free_profile()` to release the handle. This is the same sequence
    /// used by `/usr/bin/sandbox-exec` itself.
    ///
    /// The existing `exec()` / `spawn_and_wait()` methods are unchanged and remain
    /// available for wrapping external commands where controlling the fork is not
    /// possible.
    pub fn apply_to_current_process(&self, config: &AegisConfig) -> Result<(), AegisError> {
        let profile = self.resolve_profile(config)?;
        apply_sandbox_profile(&profile)
    }
}

// Link libsandbox.1 for the private SPI used by apply_sandbox_profile.
// This library is always present on macOS and is what /usr/bin/sandbox-exec links against.
#[cfg(target_os = "macos")]
#[link(name = "sandbox")]
extern "C" {
    /// Compile an SBPL source string into an opaque sandbox profile handle.
    ///
    /// `params` may be NULL for profiles that use no variable substitutions.
    /// On success returns a non-null profile pointer. On failure returns NULL
    /// and sets `*errorbuf` to a heap-allocated NUL-terminated error string.
    fn sandbox_compile_string(
        src: *const libc::c_char,
        params: *mut libc::c_void,
        errorbuf: *mut *mut libc::c_char,
    ) -> *mut libc::c_void;

    /// Apply a compiled sandbox profile to the current process.
    ///
    /// Returns 0 on success, -1 on failure. Irreversible once applied.
    fn sandbox_apply(profile: *mut libc::c_void) -> libc::c_int;

    /// Release a compiled sandbox profile handle obtained from `sandbox_compile_string`.
    fn sandbox_free_profile(profile: *mut libc::c_void);

    /// Release an error buffer obtained from `sandbox_compile_string`.
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Apply an SBPL profile string to the current process via the macOS sandbox SPI.
///
/// Uses the private-but-stable `sandbox_compile_string` + `sandbox_apply` SPI that
/// `/usr/bin/sandbox-exec` itself calls. The public `sandbox_init()` API only supports
/// named built-in profiles (e.g. `kSBXProfileNoNetwork`) and cannot accept inline SBPL;
/// this SPI is the correct path for inline profile strings.
///
/// The three-step sequence is:
/// 1. `sandbox_compile_string` -- parse and compile the SBPL source into an opaque handle.
/// 2. `sandbox_apply` -- atomically apply the compiled profile to the current process.
/// 3. `sandbox_free_profile` -- release the compiled profile handle.
///
/// # Safety
///
/// Calls into macOS libsandbox via FFI. `CString` conversion guarantees no interior null
/// bytes in the profile. `sandbox_free_error` and `sandbox_free_profile` are called on
/// every non-null pointer to prevent memory leaks.
#[cfg(target_os = "macos")]
pub(crate) fn apply_sandbox_profile(profile: &str) -> Result<(), AegisError> {
    use std::ffi::{CStr, CString};
    use std::ptr;

    let c_profile = CString::new(profile)
        .map_err(|e| AegisError::SandboxError(format!("profile contains null byte: {e}")))?;

    let mut err_buf: *mut libc::c_char = ptr::null_mut();

    // Step 1: compile the SBPL source into an opaque profile handle.
    let compiled =
        unsafe { sandbox_compile_string(c_profile.as_ptr(), ptr::null_mut(), &mut err_buf) };

    if compiled.is_null() {
        let msg = if !err_buf.is_null() {
            let msg = unsafe { CStr::from_ptr(err_buf) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandbox_free_error(err_buf) };
            msg
        } else {
            "sandbox_compile_string returned NULL with no error message".to_string()
        };
        return Err(AegisError::SandboxError(format!(
            "failed to compile sandbox profile: {msg}"
        )));
    }

    // Step 2: apply the compiled profile to the current process.
    let ret = unsafe { sandbox_apply(compiled) };

    // Step 3: free the profile handle regardless of apply result.
    unsafe { sandbox_free_profile(compiled) };

    if ret != 0 {
        return Err(AegisError::SandboxError(
            "sandbox_apply failed: could not apply sandbox to current process".to_string(),
        ));
    }

    Ok(())
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
            .current_dir(&config.sandbox_dir)
            .status()
            .map_err(|e| AegisError::SandboxError(format!("failed to run sandbox-exec: {e}")))?;

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
        cmd.arg("-f")
            .arg(tmp.path())
            .arg(command)
            .args(args)
            .current_dir(&config.sandbox_dir);

        for (key, val) in env {
            cmd.env(key, val);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| AegisError::SandboxError(format!("failed to spawn sandbox-exec: {e}")))?;

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
        crate::test_helpers::test_config(
            sandbox_dir,
            IsolationConfig::Seatbelt {
                profile_overrides: None,
                deny_paths: vec![],
            },
        )
    }

    /// Verify `sandbox_compile_string` + `sandbox_apply` FFI binding works.
    ///
    /// Uses a fully-permissive profile so the test does not restrict the test runner.
    /// Marked `#[ignore]` because `sandbox_apply` is irreversible within the process:
    /// once applied the sandbox cannot be removed, which can interfere with other tests
    /// in the same process if a restrictive profile is ever used. A permissive
    /// `(allow default)` profile is safe here, but the test still requires that the
    /// process is not already sandboxed (which CI runners often are).
    #[test]
    #[ignore = "sandbox_apply is irreversible and may fail inside a sandboxed CI environment"]
    fn test_sandbox_init_basic_profile() {
        // A minimal profile that allows everything -- tests that the FFI binding compiles
        // and that sandbox_compile_string accepts valid SBPL.
        let result = apply_sandbox_profile("(version 1)(allow default)");
        assert!(
            result.is_ok(),
            "sandbox_compile_string + sandbox_apply should succeed with permissive profile: {result:?}"
        );
    }

    /// Verify `apply_to_current_process` routes correctly through `resolve_profile`.
    ///
    /// See `test_sandbox_init_basic_profile` for why this is `#[ignore]`.
    #[test]
    #[ignore = "sandbox_apply is irreversible and may fail inside a sandboxed CI environment"]
    fn test_apply_to_current_process_permissive() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        let backend = SeatbeltBackend::with_profile("(version 1)(allow default)");
        let result = backend.apply_to_current_process(&config);
        assert!(
            result.is_ok(),
            "apply_to_current_process should succeed with permissive profile: {result:?}"
        );
    }

    #[test]
    #[ignore] // Requires sandbox-exec which fails inside another sandbox
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
    #[ignore] // Requires sandbox-exec which fails inside another sandbox
    fn seatbelt_blocks_write_outside_sandbox() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        let backend = SeatbeltBackend::new();
        backend.prepare(&config).expect("prepare failed");

        let forbidden_path = format!("/tmp/aegis_test_forbidden_{}", std::process::id());

        let status = backend
            .exec(
                "/usr/bin/touch",
                std::slice::from_ref(&forbidden_path),
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
    #[ignore] // Requires sandbox-exec which fails inside another sandbox
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
    #[ignore] // Requires sandbox-exec which fails inside another sandbox
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
    #[ignore] // Requires sandbox-exec which fails inside another sandbox
    fn spawn_and_wait_passes_env_vars() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(dir.path().to_path_buf());

        let backend = SeatbeltBackend::new();
        backend.prepare(&config).expect("prepare failed");

        let (_, status) = backend
            .spawn_and_wait("/usr/bin/env", &[], &config, &[("AEGIS_TEST_VAR", "hello")])
            .expect("spawn_and_wait failed");

        assert!(status.success());
    }
}
