/// Cedar-to-SBPL compiler: translates Cedar policy decisions into macOS Seatbelt profiles.
///
/// Instead of intercepting file operations at runtime (via FUSE), this module
/// probes the Cedar policy engine to determine which action types are permitted,
/// then generates a tailored Seatbelt SBPL profile that enforces those
/// permissions at the kernel level.
use aegis_policy::PolicyEngine;
use aegis_types::AegisConfig;

/// System paths that sandboxed processes need read access to for basic operation.
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

/// Compile Cedar policies into a Seatbelt SBPL profile string.
///
/// Probes the policy engine with `permits_action()` for each action type and
/// generates corresponding SBPL rules:
///
/// - FileRead permitted  -> `(allow file-read* (subpath "<sandbox_dir>"))`
/// - FileWrite permitted -> `(allow file-write* (subpath "<sandbox_dir>"))`
/// - NetConnect permitted -> `(allow network-outbound)`
/// - Otherwise: deny (inherited from `(deny default)`)
///
/// System paths are always readable. Process execution is always allowed
/// (the sandbox runs commands). Mach-lookup and sysctl-read are required
/// for basic process operation on macOS.
pub fn compile_cedar_to_sbpl(config: &AegisConfig, engine: &PolicyEngine) -> String {
    let mut profile = String::new();

    // Base: deny everything by default
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");

    // System-level reads: always needed for dyld, path resolution, symlinks
    profile.push_str("(allow file-read-metadata)\n");

    // System paths: always readable (binaries, libraries, etc.)
    for path in SYSTEM_READ_PATHS {
        profile.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
    }

    let sandbox_dir = config.sandbox_dir.display();

    // File read access: scoped to sandbox dir, only if Cedar permits FileRead or DirList
    if engine.permits_action("FileRead") || engine.permits_action("DirList") {
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{sandbox_dir}\"))\n"
        ));
    }

    // File write access: scoped to sandbox dir, only if Cedar permits FileWrite or DirCreate
    if engine.permits_action("FileWrite")
        || engine.permits_action("DirCreate")
        || engine.permits_action("FileDelete")
    {
        profile.push_str(&format!(
            "(allow file-write* (subpath \"{sandbox_dir}\"))\n"
        ));
    }

    // Process execution: always allowed (we need to run the sandboxed command)
    profile.push_str("(allow process-exec)\n");
    profile.push_str("(allow process-fork)\n");

    // System primitives needed for basic process operation
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow mach-lookup)\n");

    // Network: allow outbound only if Cedar permits NetConnect
    if engine.permits_action("NetConnect") {
        profile.push_str("(allow network-outbound)\n");
    } else {
        profile.push_str("(deny network*)\n");
    }

    // Temp file access for the profile itself and other temp operations
    profile.push_str("(allow file-read* (subpath \"/private/tmp\"))\n");
    profile.push_str("(allow file-read* (subpath \"/tmp\"))\n");
    profile.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
    profile.push_str("(allow file-write* (subpath \"/tmp\"))\n");

    profile
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::IsolationConfig;
    use std::path::PathBuf;

    fn test_config() -> AegisConfig {
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
        }
    }

    #[test]
    fn default_deny_produces_restrictive_profile() {
        let engine = PolicyEngine::from_policies(
            r#"forbid(principal, action, resource);"#,
            None,
        )
        .expect("engine");
        let config = test_config();
        let profile = compile_cedar_to_sbpl(&config, &engine);

        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny network*)"));
        // Should NOT have sandbox dir read/write since everything is denied
        assert!(
            !profile.contains("(allow file-read* (subpath \"/tmp/aegis-test-sandbox\"))"),
            "should not allow sandbox reads when all denied"
        );
        assert!(
            !profile.contains("(allow file-write* (subpath \"/tmp/aegis-test-sandbox\"))"),
            "should not allow sandbox writes when all denied"
        );
        // System paths should still be readable
        assert!(profile.contains("(allow file-read* (subpath \"/usr\"))"));
    }

    #[test]
    fn permit_all_produces_permissive_profile() {
        let engine = PolicyEngine::from_policies(
            r#"permit(principal, action, resource);"#,
            None,
        )
        .expect("engine");
        let config = test_config();
        let profile = compile_cedar_to_sbpl(&config, &engine);

        assert!(profile.contains("(allow file-read* (subpath \"/tmp/aegis-test-sandbox\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/tmp/aegis-test-sandbox\"))"));
        assert!(profile.contains("(allow network-outbound)"));
        assert!(!profile.contains("(deny network*)"));
    }

    #[test]
    fn read_only_produces_read_only_profile() {
        let engine = PolicyEngine::from_policies(
            r#"
            permit(principal, action == Aegis::Action::"FileRead", resource);
            permit(principal, action == Aegis::Action::"DirList", resource);
            "#,
            None,
        )
        .expect("engine");
        let config = test_config();
        let profile = compile_cedar_to_sbpl(&config, &engine);

        assert!(profile.contains("(allow file-read* (subpath \"/tmp/aegis-test-sandbox\"))"));
        assert!(
            !profile.contains("(allow file-write* (subpath \"/tmp/aegis-test-sandbox\"))"),
            "should not allow writes for read-only policy"
        );
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn write_only_no_reads() {
        let engine = PolicyEngine::from_policies(
            r#"
            permit(principal, action == Aegis::Action::"FileWrite", resource);
            "#,
            None,
        )
        .expect("engine");
        let config = test_config();
        let profile = compile_cedar_to_sbpl(&config, &engine);

        assert!(
            !profile.contains("(allow file-read* (subpath \"/tmp/aegis-test-sandbox\"))"),
            "should not allow sandbox reads for write-only"
        );
        assert!(profile.contains("(allow file-write* (subpath \"/tmp/aegis-test-sandbox\"))"));
    }

    #[test]
    fn network_only() {
        let engine = PolicyEngine::from_policies(
            r#"
            permit(principal, action == Aegis::Action::"NetConnect", resource);
            "#,
            None,
        )
        .expect("engine");
        let config = test_config();
        let profile = compile_cedar_to_sbpl(&config, &engine);

        assert!(profile.contains("(allow network-outbound)"));
        assert!(!profile.contains("(deny network*)"));
        // No sandbox file access
        assert!(!profile.contains("(allow file-read* (subpath \"/tmp/aegis-test-sandbox\"))"));
        assert!(!profile.contains("(allow file-write* (subpath \"/tmp/aegis-test-sandbox\"))"));
    }

    #[test]
    fn profile_always_has_system_paths() {
        let engine = PolicyEngine::from_policies(
            r#"forbid(principal, action, resource);"#,
            None,
        )
        .expect("engine");
        let config = test_config();
        let profile = compile_cedar_to_sbpl(&config, &engine);

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(allow file-read-metadata)"));
        assert!(profile.contains("(allow file-read* (subpath \"/usr\"))"));
        assert!(profile.contains("(allow file-read* (subpath \"/bin\"))"));
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow process-fork)"));
        assert!(profile.contains("(allow sysctl-read)"));
        assert!(profile.contains("(allow mach-lookup)"));
    }

    #[test]
    fn dir_create_enables_write() {
        let engine = PolicyEngine::from_policies(
            r#"
            permit(principal, action == Aegis::Action::"DirCreate", resource);
            "#,
            None,
        )
        .expect("engine");
        let config = test_config();
        let profile = compile_cedar_to_sbpl(&config, &engine);

        assert!(profile.contains("(allow file-write* (subpath \"/tmp/aegis-test-sandbox\"))"));
    }

    #[test]
    fn file_delete_enables_write() {
        let engine = PolicyEngine::from_policies(
            r#"
            permit(principal, action == Aegis::Action::"FileDelete", resource);
            "#,
            None,
        )
        .expect("engine");
        let config = test_config();
        let profile = compile_cedar_to_sbpl(&config, &engine);

        assert!(profile.contains("(allow file-write* (subpath \"/tmp/aegis-test-sandbox\"))"));
    }
}
