//! System environment verification and bootstrapping.
//!
//! `aegis setup` checks macOS version, verifies `sandbox-exec` availability,
//! creates the `~/.aegis/` base directory, and runs a sandbox self-test.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

/// Minimum macOS major version required by Aegis (Monterey).
#[cfg(target_os = "macos")]
const MIN_MACOS_VERSION: u32 = 12;

/// Run the `aegis setup` command.
///
/// Verifies the system environment is ready for Aegis:
/// 1. Checks macOS version >= 12 (Monterey)
/// 2. Verifies sandbox-exec is available
/// 3. Creates the ~/.aegis/ base directory
/// 4. Runs a self-test to confirm sandboxing works
pub fn run() -> Result<()> {
    println!("Aegis Setup");
    println!("===========\n");

    // Create ~/.aegis/ base directory (works on all platforms)
    print!("Creating ~/.aegis/ directory... ");
    let aegis_dir = create_aegis_dir()?;

    // macOS-specific checks
    #[cfg(target_os = "macos")]
    run_macos_checks()?;

    #[cfg(not(target_os = "macos"))]
    {
        println!("Platform: non-macOS (Seatbelt sandbox unavailable)");
        println!("  Aegis will run in Process isolation mode (observation + policy evaluation).");
    }

    println!("\nSetup complete.");
    println!("Aegis data directory: {}", aegis_dir.display());
    println!("\nNext steps:");
    println!("  aegis init                        # interactive setup wizard");
    println!("  aegis init my-agent               # quick init with defaults");
    println!("  aegis wrap claude                  # observe any command");
    println!("  aegis run echo hello               # sandbox a command");

    Ok(())
}

/// Run macOS-specific environment checks: version, sandbox-exec, self-test.
#[cfg(target_os = "macos")]
fn run_macos_checks() -> Result<()> {
    print!("Checking macOS version... ");
    check_macos_version()?;

    print!("Checking sandbox-exec... ");
    check_sandbox_exec()?;

    print!("Running sandbox self-test... ");
    match self_test() {
        Ok(()) => {}
        Err(e) => {
            println!("SKIPPED");
            println!("  Warning: sandbox self-test failed: {e:#}");
            println!("  Seatbelt enforcement may not work in this environment.");
            println!("  Aegis will still function in observe-only (Process) mode.");
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn check_macos_version() -> Result<()> {
    let output = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .context("failed to run sw_vers")?;

    if !output.status.success() {
        bail!("sw_vers failed -- are you running macOS?");
    }

    let version_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let major: u32 = version_str
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("could not parse macOS version from sw_vers output: '{version_str}'"))?;

    if major < MIN_MACOS_VERSION {
        bail!(
            "macOS {} detected, but Aegis requires macOS {MIN_MACOS_VERSION} (Monterey) or later",
            version_str
        );
    }

    println!("OK (macOS {version_str})");
    Ok(())
}

#[cfg(target_os = "macos")]
fn check_sandbox_exec() -> Result<()> {
    let output = std::process::Command::new("which")
        .arg("sandbox-exec")
        .output()
        .context("failed to run `which`")?;

    if !output.status.success() {
        bail!("sandbox-exec not found in PATH -- Aegis requires macOS sandbox-exec");
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("OK ({path})");
    Ok(())
}

fn create_aegis_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    let aegis_dir = PathBuf::from(home).join(".aegis");

    std::fs::create_dir_all(&aegis_dir).with_context(|| {
        format!("failed to create directory: {}", aegis_dir.display())
    })?;

    println!("OK");
    Ok(aegis_dir)
}

#[cfg(target_os = "macos")]
fn self_test() -> Result<()> {
    let profile = "(version 1)\n(deny default)\n(allow process-exec)\n(allow process-fork)\n(allow sysctl-read)\n(allow mach-lookup)\n(allow file-read-metadata)\n(allow file-read-data)\n(allow file-read* (subpath \"/usr\"))\n(allow file-read* (subpath \"/bin\"))\n(allow file-read* (subpath \"/sbin\"))\n(allow file-read* (subpath \"/Library\"))\n(allow file-read* (subpath \"/System\"))\n(allow file-read* (subpath \"/private\"))\n(allow file-read* (subpath \"/dev\"))\n";

    let mut tmp = tempfile::NamedTempFile::new().context("failed to create temp profile")?;
    std::io::Write::write_all(&mut tmp, profile.as_bytes())
        .context("failed to write temp profile")?;
    std::io::Write::flush(&mut tmp).context("failed to flush temp profile")?;

    let status = std::process::Command::new("sandbox-exec")
        .arg("-f")
        .arg(tmp.path())
        .arg("/bin/echo")
        .arg("aegis-self-test")
        .output()
        .context("failed to run sandbox-exec self-test")?;

    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        bail!("sandbox self-test failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&status.stdout).trim().to_string();
    if stdout != "aegis-self-test" {
        bail!("sandbox self-test produced unexpected output: {stdout}");
    }

    println!("OK");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn check_macos_version_succeeds_on_macos() {
        assert!(check_macos_version().is_ok());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn check_sandbox_exec_succeeds_on_macos() {
        assert!(check_sandbox_exec().is_ok());
    }

    #[test]
    fn create_aegis_dir_succeeds_and_returns_valid_path() {
        let path = create_aegis_dir().expect("create_aegis_dir should succeed");
        assert!(path.exists(), "returned path should exist on disk");
        assert!(
            path.ends_with(".aegis"),
            "returned path should end with .aegis, got: {}",
            path.display()
        );
        assert!(path.is_dir(), "returned path should be a directory");
    }

    #[test]
    #[ignore] // Requires sandbox-exec which fails inside another sandbox (e.g. Claude Code)
    #[cfg(target_os = "macos")]
    fn self_test_succeeds_on_macos() {
        assert!(self_test().is_ok());
    }
}
