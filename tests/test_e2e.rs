//! End-to-end integration tests for the complete Aegis flow.
//!
//! Tests the full lifecycle: init directory structure, configure policies,
//! initialize engines, simulate action evaluation, log to audit ledger,
//! and verify integrity.

mod common;

use std::path::PathBuf;

use tempfile::TempDir;

use aegis_ledger::AuditStore;
use aegis_policy::builtin::ALLOW_READ_ONLY;
use aegis_policy::PolicyEngine;
use aegis_types::{
    AegisConfig, Decision, CONFIG_FILENAME, DEFAULT_POLICY_FILENAME, LEDGER_FILENAME,
};

use common::{dir_list_action, file_read_action, file_write_action};

/// Set up a temporary aegis directory structure mimicking `aegis init`.
/// Returns (TempDir, policies_dir, sandbox_dir, ledger_path, config_path).
fn setup_aegis_dir(
    name: &str,
    policy_text: &str,
) -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
    let tmpdir = TempDir::new().expect("should create temp dir for aegis init");
    let base = tmpdir.path().join(name);

    let policies_dir = base.join("policies");
    let sandbox_dir = base.join("sandbox");
    let ledger_path = base.join(LEDGER_FILENAME);
    let config_path = base.join(CONFIG_FILENAME);

    std::fs::create_dir_all(&policies_dir).expect("should create policies dir");
    std::fs::create_dir_all(&sandbox_dir).expect("should create sandbox dir");

    // Write the policy file
    let policy_file = policies_dir.join(DEFAULT_POLICY_FILENAME);
    std::fs::write(&policy_file, policy_text).expect("should write policy file");

    // Generate and write the config
    let config = AegisConfig::default_for(name, &base);
    let toml_str = config.to_toml().expect("should serialize config to TOML");
    std::fs::write(&config_path, &toml_str).expect("should write config file");

    (tmpdir, policies_dir, sandbox_dir, ledger_path, config_path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_full_lifecycle_read_only_policy() {
    // Step 1: Init -- create directory structure with read-only policy
    let read_only_policy = ALLOW_READ_ONLY;
    let (_tmpdir, policies_dir, _sandbox_dir, ledger_path, _config_path) =
        setup_aegis_dir("test-agent", read_only_policy);

    // Step 2: Initialize PolicyEngine and AuditStore
    let engine = PolicyEngine::new(&policies_dir, None)
        .expect("should create policy engine from init dir");
    let mut store = AuditStore::open(&ledger_path).expect("should open audit store");

    // Step 3: Simulate the run flow

    // Action 1: FileRead -> should be allowed
    let read_action = file_read_action("claude-agent", "/sandbox/data/report.csv");
    let read_verdict = engine.evaluate(&read_action);
    assert_eq!(
        read_verdict.decision,
        Decision::Allow,
        "FileRead should be allowed under read-only policy"
    );
    store
        .append(&read_action, &read_verdict)
        .expect("should log read verdict");

    // Action 2: DirList -> should be allowed
    let list_action = dir_list_action("claude-agent", "/sandbox/data");
    let list_verdict = engine.evaluate(&list_action);
    assert_eq!(
        list_verdict.decision,
        Decision::Allow,
        "DirList should be allowed under read-only policy"
    );
    store
        .append(&list_action, &list_verdict)
        .expect("should log list verdict");

    // Action 3: FileWrite -> should be denied
    let write_action = file_write_action("claude-agent", "/sandbox/output/result.txt");
    let write_verdict = engine.evaluate(&write_action);
    assert_eq!(
        write_verdict.decision,
        Decision::Deny,
        "FileWrite should be denied under read-only policy"
    );
    store
        .append(&write_action, &write_verdict)
        .expect("should log write verdict");

    // Step 4: Query the audit log and verify
    let all_entries = store.query_last(10).expect("should query all entries");
    assert_eq!(all_entries.len(), 3, "should have exactly 3 audit entries");

    let allows = store
        .query_by_decision("Allow")
        .expect("should query allow entries");
    assert_eq!(allows.len(), 2, "should have 2 Allow entries");

    let denies = store
        .query_by_decision("Deny")
        .expect("should query deny entries");
    assert_eq!(denies.len(), 1, "should have 1 Deny entry");

    // Step 5: Verify hash chain integrity
    let report = store
        .verify_integrity()
        .expect("should verify integrity");
    assert!(
        report.valid,
        "hash chain should be valid: {}",
        report.message
    );
    assert_eq!(report.total_entries, 3);
}

#[test]
fn test_full_lifecycle_deny_write_allow_read() {
    // Policy: allow FileRead and DirList, deny everything else
    let policy = r#"
permit(
    principal,
    action == Aegis::Action::"FileRead",
    resource
);

permit(
    principal,
    action == Aegis::Action::"DirList",
    resource
);
"#;

    let (_tmpdir, policies_dir, _sandbox_dir, ledger_path, _config_path) =
        setup_aegis_dir("e2e-agent", policy);

    let engine =
        PolicyEngine::new(&policies_dir, None).expect("should create policy engine");
    let mut store = AuditStore::open(&ledger_path).expect("should open audit store");

    // FileRead -> Allow
    let read_action = file_read_action("e2e-agent", "/sandbox/input.txt");
    let read_verdict = engine.evaluate(&read_action);
    assert_eq!(read_verdict.decision, Decision::Allow);
    store
        .append(&read_action, &read_verdict)
        .expect("should log read");

    // FileWrite -> Deny
    let write_action = file_write_action("e2e-agent", "/sandbox/output.txt");
    let write_verdict = engine.evaluate(&write_action);
    assert_eq!(write_verdict.decision, Decision::Deny);
    store
        .append(&write_action, &write_verdict)
        .expect("should log write");

    // Verify
    let entries = store.query_last(10).expect("should query entries");
    assert_eq!(entries.len(), 2);

    let report = store.verify_integrity().expect("should verify");
    assert!(report.valid, "chain should be intact: {}", report.message);
}

#[test]
fn test_config_serialization_roundtrip() {
    let tmpdir = TempDir::new().expect("should create temp dir");
    let base = tmpdir.path().join("roundtrip-agent");

    let original = AegisConfig::default_for("roundtrip-agent", &base);
    let toml_str = original
        .to_toml()
        .expect("should serialize config to TOML");

    let parsed = AegisConfig::from_toml(&toml_str)
        .expect("should deserialize config from TOML");

    assert_eq!(parsed.name, original.name);
    assert_eq!(parsed.sandbox_dir, original.sandbox_dir);
    assert_eq!(parsed.ledger_path, original.ledger_path);
    assert_eq!(parsed.policy_paths, original.policy_paths);
}

#[test]
fn test_config_from_fixture_file() {
    let fixture_content = include_str!("../fixtures/configs/test-config.toml");
    let config = AegisConfig::from_toml(fixture_content)
        .expect("should parse fixture config TOML");

    assert_eq!(config.name, "test-agent");
    assert_eq!(config.sandbox_dir, PathBuf::from("/tmp/aegis-test/sandbox"));
    assert_eq!(config.ledger_path, PathBuf::from("/tmp/aegis-test/audit.db"));
    assert_eq!(
        config.policy_paths,
        vec![PathBuf::from("/tmp/aegis-test/policies")]
    );
}

#[test]
fn test_init_structure_matches_config() {
    let (_tmpdir, policies_dir, sandbox_dir, ledger_path, config_path) =
        setup_aegis_dir("structure-test", "forbid(principal, action, resource);");

    // Verify directory structure was created
    assert!(policies_dir.exists(), "policies dir should exist");
    assert!(sandbox_dir.exists(), "sandbox dir should exist");
    assert!(config_path.exists(), "config file should exist");

    // Verify the policy file was written
    let policy_file = policies_dir.join(DEFAULT_POLICY_FILENAME);
    assert!(policy_file.exists(), "default.cedar should exist");

    // Verify the config can be loaded and points to the right paths
    let config_content =
        std::fs::read_to_string(&config_path).expect("should read config file");
    let config = AegisConfig::from_toml(&config_content)
        .expect("should parse config TOML");

    assert_eq!(config.name, "structure-test");
    // The ledger doesn't exist yet as a file, but the path should match
    assert_eq!(config.ledger_path, ledger_path);
}

#[test]
fn test_e2e_multiple_agents_audit_separation() {
    let (_tmpdir, policies_dir, _sandbox_dir, ledger_path, _config_path) =
        setup_aegis_dir("multi-agent", "permit(principal, action, resource);");

    let engine =
        PolicyEngine::new(&policies_dir, None).expect("should create engine");
    let mut store = AuditStore::open(&ledger_path).expect("should open store");

    // Agent alpha performs 3 actions
    for i in 0..3 {
        let action = file_read_action("agent-alpha", &format!("/data/alpha-{i}.csv"));
        let verdict = engine.evaluate(&action);
        store
            .append(&action, &verdict)
            .expect("should log alpha action");
    }

    // Agent beta performs 2 actions
    for i in 0..2 {
        let action = file_write_action("agent-beta", &format!("/output/beta-{i}.txt"));
        let verdict = engine.evaluate(&action);
        store
            .append(&action, &verdict)
            .expect("should log beta action");
    }

    // Verify separation by principal
    let alpha_entries = store
        .query_by_principal("agent-alpha")
        .expect("should query alpha");
    assert_eq!(alpha_entries.len(), 3);

    let beta_entries = store
        .query_by_principal("agent-beta")
        .expect("should query beta");
    assert_eq!(beta_entries.len(), 2);

    // Verify total count
    assert_eq!(store.count().expect("should count"), 5);

    // Verify chain integrity over all agents' entries
    let report = store.verify_integrity().expect("should verify");
    assert!(report.valid, "chain integrity: {}", report.message);
    assert_eq!(report.total_entries, 5);
}

#[test]
fn test_e2e_policy_reload_mid_session() {
    let tmpdir = TempDir::new().expect("should create temp dir");
    let base = tmpdir.path().join("reload-test");
    let policies_dir = base.join("policies");
    let ledger_path = base.join(LEDGER_FILENAME);

    std::fs::create_dir_all(&policies_dir).expect("should create policies dir");

    // Start with deny-all
    let policy_file = policies_dir.join(DEFAULT_POLICY_FILENAME);
    std::fs::write(&policy_file, "forbid(principal, action, resource);")
        .expect("should write deny-all policy");

    let mut engine =
        PolicyEngine::new(&policies_dir, None).expect("should create deny engine");
    let mut store = AuditStore::open(&ledger_path).expect("should open store");

    // Action under deny-all
    let action1 = file_read_action("agent", "/data/file.txt");
    let verdict1 = engine.evaluate(&action1);
    assert_eq!(verdict1.decision, Decision::Deny);
    store
        .append(&action1, &verdict1)
        .expect("should log deny verdict");

    // Hot-reload to permit-all
    std::fs::write(&policy_file, "permit(principal, action, resource);")
        .expect("should overwrite with permit-all policy");
    engine
        .reload(&policies_dir)
        .expect("should reload policies");

    // Same action under permit-all
    let action2 = file_read_action("agent", "/data/file.txt");
    let verdict2 = engine.evaluate(&action2);
    assert_eq!(verdict2.decision, Decision::Allow);
    store
        .append(&action2, &verdict2)
        .expect("should log allow verdict");

    // Ledger should have one Deny and one Allow
    let denies = store
        .query_by_decision("Deny")
        .expect("should query denies");
    assert_eq!(denies.len(), 1);

    let allows = store
        .query_by_decision("Allow")
        .expect("should query allows");
    assert_eq!(allows.len(), 1);

    // Chain integrity must hold across the policy switch
    let report = store.verify_integrity().expect("should verify");
    assert!(report.valid, "chain integrity: {}", report.message);
}
