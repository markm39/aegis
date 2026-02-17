//! Seatbelt SBPL profile generation from `AegisConfig`.

use aegis_types::{AegisConfig, AegisError, IsolationConfig};

use crate::{escape_sbpl_path, write_sbpl_base};

/// Generate a macOS Seatbelt profile in SBPL format from the given config.
///
/// The profile starts with a default-deny stance, then selectively allows:
/// - Read access to standard system paths
/// - Read/write access to the sandbox directory
/// - Process execution and forking
/// - Sysctl reads and mach lookups for basic operation
/// - Network access only if `allowed_network` rules are present
/// - Any additional overrides from a profile_overrides file
///
/// Returns an error if the sandbox directory path contains characters
/// that cannot be safely embedded in the SBPL profile.
pub fn generate_seatbelt_profile(config: &AegisConfig) -> Result<String, AegisError> {
    let mut profile = String::new();

    // Common base: version, deny default, system reads, process exec, system primitives
    write_sbpl_base(&mut profile);

    // Allow read and write access to the sandbox directory (escaped for SBPL safety)
    let sandbox_dir = escape_sbpl_path(&config.sandbox_dir.display().to_string())?;
    profile.push_str(&format!("(allow file-read* (subpath \"{sandbox_dir}\"))\n"));
    profile.push_str(&format!(
        "(allow file-write* (subpath \"{sandbox_dir}\"))\n"
    ));

    // Network rules: allow outbound only if rules are present
    if config.allowed_network.is_empty() {
        profile.push_str("(deny network*)\n");
    } else {
        profile.push_str("(allow network-outbound)\n");
    }

    // Append profile overrides if specified (fail hard if the file is configured but unreadable)
    if let IsolationConfig::Seatbelt {
        profile_overrides: Some(ref overrides_path),
    } = config.isolation
    {
        let contents = std::fs::read_to_string(overrides_path).map_err(|e| {
            AegisError::SandboxError(format!(
                "failed to read profile overrides {}: {e}",
                overrides_path.display()
            ))
        })?;
        profile.push_str(&contents);
        if !contents.ends_with('\n') {
            profile.push('\n');
        }
    }

    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::{IsolationConfig, NetworkRule, Protocol};
    use std::path::PathBuf;

    fn base_config() -> AegisConfig {
        crate::test_helpers::test_config(
            PathBuf::from("/tmp/aegis-test-sandbox"),
            IsolationConfig::Seatbelt { profile_overrides: None },
        )
    }

    #[test]
    fn profile_contains_expected_sections() {
        let config = base_config();
        let profile = generate_seatbelt_profile(&config).unwrap();

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow file-read-metadata)"));
        assert!(profile.contains("(allow file-read-data)"));
        assert!(profile.contains("(allow file-read* (subpath \"/usr\"))"));
        assert!(profile.contains("(allow file-read* (subpath \"/bin\"))"));
        assert!(profile.contains("(allow file-read* (subpath \"/sbin\"))"));
        assert!(profile.contains("(allow file-read* (subpath \"/Library\"))"));
        assert!(profile.contains("(allow file-read* (subpath \"/System\"))"));
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow process-fork)"));
        assert!(profile.contains("(allow sysctl-read)"));
        assert!(profile.contains("(allow mach-lookup)"));
    }

    #[test]
    fn profile_includes_sandbox_dir() {
        let config = base_config();
        let profile = generate_seatbelt_profile(&config).unwrap();

        assert!(profile.contains("(allow file-read* (subpath \"/tmp/aegis-test-sandbox\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/tmp/aegis-test-sandbox\"))"));
    }

    #[test]
    fn profile_denies_network_when_no_rules() {
        let config = base_config();
        let profile = generate_seatbelt_profile(&config).unwrap();

        assert!(profile.contains("(deny network*)"));
        assert!(!profile.contains("(allow network-outbound)"));
    }

    #[test]
    fn profile_allows_network_when_rules_present() {
        let mut config = base_config();
        config.allowed_network.push(NetworkRule {
            host: "api.openai.com".into(),
            port: Some(443),
            protocol: Protocol::Https,
        });

        let profile = generate_seatbelt_profile(&config).unwrap();

        assert!(profile.contains("(allow network-outbound)"));
        assert!(!profile.contains("(deny network*)"));
    }

    #[test]
    fn profile_includes_overrides_from_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let overrides_path = dir.path().join("overrides.sb");
        std::fs::write(&overrides_path, "(allow file-read* (literal \"/custom/path\"))\n")
            .expect("failed to write overrides");

        let mut config = base_config();
        config.isolation = IsolationConfig::Seatbelt {
            profile_overrides: Some(overrides_path),
        };

        let profile = generate_seatbelt_profile(&config).unwrap();

        assert!(profile.contains("(allow file-read* (literal \"/custom/path\"))"));
    }
}
