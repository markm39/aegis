//! Integration tests for policy + ledger interaction.
//!
//! Verifies that policy evaluation results from aegis-policy flow correctly
//! into the audit ledger from aegis-ledger, and that the hash chain remains
//! intact across all recorded entries.

use std::path::PathBuf;

use tempfile::NamedTempFile;

use aegis_ledger::AuditStore;
use aegis_policy::builtin::DEFAULT_DENY;
use aegis_policy::PolicyEngine;
use aegis_types::{Action, ActionKind, Decision};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_db() -> NamedTempFile {
    NamedTempFile::new().expect("should create temp file for ledger database")
}

fn file_read_action(principal: &str, path: &str) -> Action {
    Action::new(
        principal,
        ActionKind::FileRead {
            path: PathBuf::from(path),
        },
    )
}

fn file_write_action(principal: &str, path: &str) -> Action {
    Action::new(
        principal,
        ActionKind::FileWrite {
            path: PathBuf::from(path),
        },
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_deny_engine_verdicts_stored_in_ledger() {
    let engine =
        PolicyEngine::from_policies(DEFAULT_DENY, None).expect("should create deny-all engine");
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    // Evaluate several actions against deny-all, store each verdict
    let actions = vec![
        file_read_action("agent-1", "/secret/data.csv"),
        file_write_action("agent-1", "/output/result.txt"),
        file_read_action("agent-2", "/config/settings.toml"),
    ];

    for action in &actions {
        let verdict = engine.evaluate(action);
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "deny-all engine should deny {:?}",
            action.kind
        );
        store
            .append(action, &verdict)
            .expect("should append verdict to ledger");
    }

    // Query the ledger and verify all entries have decision "Deny"
    let entries = store
        .query_by_decision("Deny")
        .expect("should query deny entries");
    assert_eq!(
        entries.len(),
        3,
        "all 3 entries should be Deny decisions"
    );
    for entry in &entries {
        assert_eq!(entry.decision, "Deny");
    }

    // No Allow entries should exist
    let allows = store
        .query_by_decision("Allow")
        .expect("should query allow entries");
    assert!(allows.is_empty(), "no Allow entries should exist");
}

#[test]
fn test_permit_engine_verdicts_stored_in_ledger() {
    let engine = PolicyEngine::from_policies("permit(principal, action, resource);", None)
        .expect("should create permit-all engine");
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    let actions = vec![
        file_read_action("agent-1", "/data/report.csv"),
        file_write_action("agent-1", "/output/summary.txt"),
        Action::new(
            "agent-1",
            ActionKind::DirList {
                path: PathBuf::from("/data"),
            },
        ),
    ];

    for action in &actions {
        let verdict = engine.evaluate(action);
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "permit-all engine should allow {:?}",
            action.kind
        );
        store
            .append(action, &verdict)
            .expect("should append verdict to ledger");
    }

    // Query the ledger and verify all entries have decision "Allow"
    let entries = store
        .query_by_decision("Allow")
        .expect("should query allow entries");
    assert_eq!(
        entries.len(),
        3,
        "all 3 entries should be Allow decisions"
    );
    for entry in &entries {
        assert_eq!(entry.decision, "Allow");
    }
}

#[test]
fn test_mixed_engines_both_decisions_in_ledger() {
    let deny_engine =
        PolicyEngine::from_policies(DEFAULT_DENY, None).expect("should create deny-all engine");
    let allow_engine = PolicyEngine::from_policies("permit(principal, action, resource);", None)
        .expect("should create permit-all engine");

    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    // Phase 1: deny-all engine produces Deny verdicts
    for i in 0..4 {
        let action = file_read_action("agent", &format!("/denied/{i}"));
        let verdict = deny_engine.evaluate(&action);
        store
            .append(&action, &verdict)
            .expect("should append deny verdict");
    }

    // Phase 2: permit-all engine produces Allow verdicts
    for i in 0..3 {
        let action = file_read_action("agent", &format!("/allowed/{i}"));
        let verdict = allow_engine.evaluate(&action);
        store
            .append(&action, &verdict)
            .expect("should append allow verdict");
    }

    // Verify counts
    let denies = store
        .query_by_decision("Deny")
        .expect("should query deny entries");
    assert_eq!(denies.len(), 4, "should have 4 Deny entries");

    let allows = store
        .query_by_decision("Allow")
        .expect("should query allow entries");
    assert_eq!(allows.len(), 3, "should have 3 Allow entries");

    assert_eq!(
        store.count().expect("should count"),
        7,
        "total entry count should be 7"
    );
}

#[test]
fn test_full_hash_chain_integrity_across_policy_switch() {
    let deny_engine =
        PolicyEngine::from_policies(DEFAULT_DENY, None).expect("should create deny-all engine");
    let allow_engine = PolicyEngine::from_policies("permit(principal, action, resource);", None)
        .expect("should create permit-all engine");

    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    // Deny phase
    for i in 0..10 {
        let action = file_write_action("agent", &format!("/forbidden/{i}"));
        let verdict = deny_engine.evaluate(&action);
        store
            .append(&action, &verdict)
            .expect("should append deny verdict");
    }

    // Allow phase
    for i in 0..10 {
        let action = file_read_action("agent", &format!("/permitted/{i}"));
        let verdict = allow_engine.evaluate(&action);
        store
            .append(&action, &verdict)
            .expect("should append allow verdict");
    }

    // Verify the entire hash chain is intact
    let report = store
        .verify_integrity()
        .expect("should verify integrity");
    assert!(
        report.valid,
        "hash chain should be valid across policy switch: {}",
        report.message
    );
    assert_eq!(report.total_entries, 20);
    assert!(report.first_invalid_entry.is_none());
}

#[test]
fn test_ledger_entries_preserve_principal_from_action() {
    let engine =
        PolicyEngine::from_policies(DEFAULT_DENY, None).expect("should create deny-all engine");
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    let principals = ["agent-alpha", "agent-beta", "agent-gamma"];

    for principal in &principals {
        let action = file_read_action(principal, "/data/file.txt");
        let verdict = engine.evaluate(&action);
        store
            .append(&action, &verdict)
            .expect("should append entry");
    }

    for principal in &principals {
        let entries = store
            .query_by_principal(principal)
            .expect("should query by principal");
        assert_eq!(
            entries.len(),
            1,
            "principal {principal} should have exactly 1 entry"
        );
        assert_eq!(entries[0].principal, *principal);
    }
}
