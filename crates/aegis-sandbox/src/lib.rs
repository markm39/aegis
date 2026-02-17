//! OS-level sandboxing backends for Aegis.
//!
//! Provides [`SandboxBackend`] trait with two implementations:
//! - [`SeatbeltBackend`]: macOS Seatbelt (`sandbox-exec`) with auto-generated SBPL profiles
//! - [`ProcessBackend`]: simple process execution without OS-level isolation

pub mod backend;
#[cfg(target_os = "macos")]
pub mod compiler;
pub mod process;
#[cfg(target_os = "macos")]
pub mod profile;
#[cfg(target_os = "macos")]
pub mod seatbelt;

pub use backend::SandboxBackend;
pub use process::ProcessBackend;
#[cfg(target_os = "macos")]
pub use compiler::compile_cedar_to_sbpl;
#[cfg(target_os = "macos")]
pub use profile::generate_seatbelt_profile;
#[cfg(target_os = "macos")]
pub use seatbelt::SeatbeltBackend;

/// Escape a path string for safe inclusion in an SBPL double-quoted literal.
///
/// SBPL uses Scheme-like syntax where strings are delimited by `"`. Inside a
/// string, `\` and `"` are the only special characters. This function also
/// rejects paths containing `)` or `(` which could break out of the `(subpath ...)`
/// form, and newlines which could inject additional SBPL directives.
///
/// Returns `Err` if the path contains characters that cannot be safely embedded
/// in SBPL (parentheses, newlines, null bytes).
#[cfg(target_os = "macos")]
pub(crate) fn escape_sbpl_path(path: &str) -> Result<String, aegis_types::AegisError> {
    // Reject characters that could break SBPL structure
    for ch in ['(', ')', '\n', '\r', '\0'] {
        if path.contains(ch) {
            return Err(aegis_types::AegisError::SandboxError(format!(
                "sandbox_dir contains invalid character {:?} for SBPL profile: {path:?}",
                ch
            )));
        }
    }
    // Escape backslashes first, then double quotes
    let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(escaped)
}

/// System paths that sandboxed processes need read access to for basic operation.
///
/// On macOS, even simple commands require access to the dyld shared cache,
/// system libraries, and various configuration paths. This constant is shared
/// between the Cedar-to-SBPL compiler and the Seatbelt profile generator.
#[cfg(target_os = "macos")]
pub(crate) const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/Library",
    "/System",
    "/private/var/db",
    "/private/etc",
    "/private/var/folders",
    "/dev",
];

/// Write the common SBPL directives shared by all profile generators.
///
/// Emits the base directives that every Seatbelt profile needs:
/// - Version header and default-deny stance
/// - Global file metadata and data reads (required by dyld)
/// - System path read access
/// - Process execution and forking
/// - Sysctl reads and mach lookups
#[cfg(target_os = "macos")]
pub(crate) fn write_sbpl_base(profile: &mut String) {
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");

    profile.push_str("(allow file-read-metadata)\n");
    profile.push_str("(allow file-read-data)\n");

    for path in SYSTEM_READ_PATHS {
        profile.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
    }

    profile.push_str("(allow process-exec)\n");
    profile.push_str("(allow process-fork)\n");

    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow mach-lookup)\n");
}

#[cfg(test)]
mod escape_tests {
    use super::escape_sbpl_path;

    #[test]
    fn normal_path_passes_through() {
        assert_eq!(escape_sbpl_path("/tmp/sandbox").unwrap(), "/tmp/sandbox");
    }

    #[test]
    fn quotes_are_escaped() {
        assert_eq!(
            escape_sbpl_path(r#"/tmp/my"dir"#).unwrap(),
            r#"/tmp/my\"dir"#
        );
    }

    #[test]
    fn backslashes_are_escaped() {
        assert_eq!(
            escape_sbpl_path(r"/tmp/my\dir").unwrap(),
            r"/tmp/my\\dir"
        );
    }

    #[test]
    fn parentheses_rejected() {
        assert!(escape_sbpl_path("/tmp/evil))\n(allow default").is_err());
        assert!(escape_sbpl_path("/tmp/(bad").is_err());
    }

    #[test]
    fn newlines_rejected() {
        assert!(escape_sbpl_path("/tmp/evil\npath").is_err());
        assert!(escape_sbpl_path("/tmp/evil\rpath").is_err());
    }

    #[test]
    fn null_bytes_rejected() {
        assert!(escape_sbpl_path("/tmp/evil\0path").is_err());
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use aegis_types::{AegisConfig, IsolationConfig};
    use std::path::PathBuf;

    /// Create a test AegisConfig with the given sandbox directory and isolation mode.
    pub fn test_config(sandbox_dir: PathBuf, isolation: IsolationConfig) -> AegisConfig {
        AegisConfig {
            name: "test-agent".into(),
            sandbox_dir,
            policy_paths: vec![],
            schema_path: None,
            ledger_path: PathBuf::from("/tmp/audit.db"),
            allowed_network: vec![],
            isolation,
            observer: aegis_types::ObserverConfig::default(),
            alerts: Vec::new(),
        }
    }
}
