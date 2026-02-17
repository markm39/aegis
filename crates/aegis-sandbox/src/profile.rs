use aegis_types::{AegisConfig, IsolationConfig};

/// System paths that sandboxed processes need read access to for basic operation.
///
/// On macOS, even simple commands require access to the dyld shared cache,
/// system libraries, and various configuration paths.
const SYSTEM_READ_PATHS: &[&str] = &[
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

/// Generate a macOS Seatbelt profile in SBPL format from the given config.
///
/// The profile starts with a default-deny stance, then selectively allows:
/// - Read access to standard system paths
/// - Read/write access to the sandbox directory
/// - Process execution and forking
/// - Sysctl reads and mach lookups for basic operation
/// - Network access only if `allowed_network` rules are present
/// - Any additional overrides from a profile_overrides file
pub fn generate_seatbelt_profile(config: &AegisConfig) -> String {
    let mut profile = String::new();

    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");

    // Allow reading file metadata and data globally (needed for dyld, path resolution,
    // and symlink traversal on macOS)
    profile.push_str("(allow file-read-metadata)\n");
    profile.push_str("(allow file-read-data)\n");

    // Allow read access to system paths (includes subdirectory traversal)
    for path in SYSTEM_READ_PATHS {
        profile.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
    }

    // Allow read and write access to the sandbox directory
    let sandbox_dir = config.sandbox_dir.display();
    profile.push_str(&format!("(allow file-read* (subpath \"{sandbox_dir}\"))\n"));
    profile.push_str(&format!(
        "(allow file-write* (subpath \"{sandbox_dir}\"))\n"
    ));

    // Allow process execution and forking
    profile.push_str("(allow process-exec)\n");
    profile.push_str("(allow process-fork)\n");

    // Allow sysctl-read and mach-lookup for basic process operation
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow mach-lookup)\n");

    // Network rules: allow outbound only if rules are present
    if config.allowed_network.is_empty() {
        profile.push_str("(deny network*)\n");
    } else {
        profile.push_str("(allow network-outbound)\n");
    }

    // Append profile overrides if specified and the file exists
    if let IsolationConfig::Seatbelt {
        profile_overrides: Some(ref overrides_path),
    } = config.isolation
    {
        if overrides_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(overrides_path) {
                profile.push_str(&contents);
                if !contents.ends_with('\n') {
                    profile.push('\n');
                }
            }
        }
    }

    profile
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::{IsolationConfig, NetworkRule, Protocol};
    use std::path::PathBuf;

    fn base_config() -> AegisConfig {
        AegisConfig {
            name: "test-agent".into(),
            sandbox_dir: PathBuf::from("/tmp/aegis-test-sandbox"),
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
    fn profile_contains_expected_sections() {
        let config = base_config();
        let profile = generate_seatbelt_profile(&config);

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
        let profile = generate_seatbelt_profile(&config);

        assert!(profile.contains("(allow file-read* (subpath \"/tmp/aegis-test-sandbox\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/tmp/aegis-test-sandbox\"))"));
    }

    #[test]
    fn profile_denies_network_when_no_rules() {
        let config = base_config();
        let profile = generate_seatbelt_profile(&config);

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

        let profile = generate_seatbelt_profile(&config);

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

        let profile = generate_seatbelt_profile(&config);

        assert!(profile.contains("(allow file-read* (literal \"/custom/path\"))"));
    }
}
