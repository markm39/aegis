//! Integration tests for cross-crate ledger integrity.
//!
//! Verifies that the audit ledger (aegis-ledger) correctly integrates with
//! the types crate (aegis-types) for append, query, and tamper detection.

mod common;

use std::path::PathBuf;

use aegis_ledger::AuditStore;
use aegis_types::{Action, ActionKind, Verdict};

use common::temp_db;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_action(principal: &str, kind: ActionKind) -> Action {
    Action::new(principal, kind)
}

fn file_read_kind(path: &str) -> ActionKind {
    ActionKind::FileRead {
        path: PathBuf::from(path),
    }
}

fn file_write_kind(path: &str) -> ActionKind {
    ActionKind::FileWrite {
        path: PathBuf::from(path),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_append_and_query_back_fields_match() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    let action = sample_action("agent-alpha", file_read_kind("/data/report.csv"));
    let verdict = Verdict::allow(action.id, "permitted by policy", Some("policy-1".into()));

    let entry = store
        .append(&action, &verdict)
        .expect("should append entry");

    assert_eq!(entry.principal, "agent-alpha");
    assert_eq!(entry.decision, "Allow");
    assert_eq!(entry.reason, "permitted by policy");
    assert_eq!(entry.policy_id.as_deref(), Some("policy-1"));
    assert_eq!(entry.action_id, action.id);

    // Query it back
    let results = store.query_last(1).expect("should query last entry");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].entry_id, entry.entry_id);
    assert_eq!(results[0].principal, "agent-alpha");
    assert_eq!(results[0].decision, "Allow");
}

#[test]
fn test_append_deny_verdict_and_query_back() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    let action = sample_action(
        "agent-beta",
        ActionKind::NetConnect {
            host: "evil.com".into(),
            port: 443,
        },
    );
    let verdict = Verdict::deny(action.id, "blocked by default-deny", None);

    let entry = store
        .append(&action, &verdict)
        .expect("should append deny entry");

    assert_eq!(entry.principal, "agent-beta");
    assert_eq!(entry.decision, "Deny");
    assert_eq!(entry.reason, "blocked by default-deny");
    assert!(entry.policy_id.is_none());
}

#[test]
fn test_fifty_mixed_entries_integrity_passes() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    for i in 0..50 {
        let (action, verdict) = if i % 2 == 0 {
            let a = sample_action(&format!("agent-{i}"), file_read_kind(&format!("/tmp/{i}")));
            let v = Verdict::allow(a.id, format!("allowed-{i}"), None);
            (a, v)
        } else {
            let a = sample_action(&format!("agent-{i}"), file_write_kind(&format!("/tmp/{i}")));
            let v = Verdict::deny(a.id, format!("denied-{i}"), None);
            (a, v)
        };
        store
            .append(&action, &verdict)
            .expect("should append entry");
    }

    let report = store.verify_integrity().expect("should verify integrity");
    assert!(
        report.valid,
        "integrity check should pass for 50 entries: {}",
        report.message
    );
    assert_eq!(report.total_entries, 50);
    assert!(report.first_invalid_entry.is_none());
}

#[test]
fn test_query_by_principal_correct_filtering() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    // Append entries for different principals
    for i in 0..5 {
        let a = sample_action("alice", file_read_kind(&format!("/data/{i}")));
        let v = Verdict::allow(a.id, "ok", None);
        store.append(&a, &v).expect("should append alice entry");
    }

    for i in 0..3 {
        let a = sample_action("bob", file_write_kind(&format!("/data/{i}")));
        let v = Verdict::deny(a.id, "blocked", None);
        store.append(&a, &v).expect("should append bob entry");
    }

    let alice_entries = store
        .query_by_principal("alice")
        .expect("should query alice entries");
    assert_eq!(alice_entries.len(), 5, "alice should have 5 entries");
    assert!(
        alice_entries.iter().all(|e| e.principal == "alice"),
        "all queried entries should belong to alice"
    );

    let bob_entries = store
        .query_by_principal("bob")
        .expect("should query bob entries");
    assert_eq!(bob_entries.len(), 3, "bob should have 3 entries");
    assert!(
        bob_entries.iter().all(|e| e.principal == "bob"),
        "all queried entries should belong to bob"
    );

    let unknown_entries = store
        .query_by_principal("charlie")
        .expect("should query nonexistent principal");
    assert!(
        unknown_entries.is_empty(),
        "nonexistent principal should return no entries"
    );
}

#[test]
fn test_query_by_decision_correct_filtering() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    // 4 Allow entries
    for i in 0..4 {
        let a = sample_action("agent", file_read_kind(&format!("/safe/{i}")));
        let v = Verdict::allow(a.id, "allowed", None);
        store.append(&a, &v).expect("should append allow entry");
    }

    // 3 Deny entries
    for i in 0..3 {
        let a = sample_action("agent", file_write_kind(&format!("/forbidden/{i}")));
        let v = Verdict::deny(a.id, "denied", None);
        store.append(&a, &v).expect("should append deny entry");
    }

    let allows = store
        .query_by_decision("Allow")
        .expect("should query Allow entries");
    assert_eq!(allows.len(), 4, "should have 4 Allow entries");
    assert!(allows.iter().all(|e| e.decision == "Allow"));

    let denies = store
        .query_by_decision("Deny")
        .expect("should query Deny entries");
    assert_eq!(denies.len(), 3, "should have 3 Deny entries");
    assert!(denies.iter().all(|e| e.decision == "Deny"));
}

#[test]
fn test_count_matches_appended_entries() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).expect("should open audit store");

    assert_eq!(
        store.count().expect("should count"),
        0,
        "empty ledger should have count 0"
    );

    for i in 0..12 {
        let a = sample_action("agent", file_read_kind(&format!("/tmp/{i}")));
        let v = Verdict::allow(a.id, "ok", None);
        store.append(&a, &v).expect("should append entry");
    }

    assert_eq!(
        store.count().expect("should count"),
        12,
        "count should match number of appended entries"
    );
}

#[test]
fn test_tamper_detection_catches_modified_entry() {
    let tmp = temp_db();
    let db_path = tmp.path().to_path_buf();
    let mut store = AuditStore::open(&db_path).expect("should open audit store");

    // Append 5 entries
    for i in 0..5 {
        let a = sample_action(&format!("agent-{i}"), file_read_kind(&format!("/tmp/{i}")));
        let v = Verdict::allow(a.id, format!("reason-{i}"), None);
        store.append(&a, &v).expect("should append entry");
    }

    // Verify integrity passes before tampering
    let report_before = store
        .verify_integrity()
        .expect("should verify integrity before tamper");
    assert!(
        report_before.valid,
        "integrity should pass before tampering"
    );

    // Tamper with the 3rd entry's action_kind via a separate raw SQLite connection
    {
        let tamper_conn =
            rusqlite::Connection::open(&db_path).expect("should open db for tampering");
        tamper_conn
            .execute(
                "UPDATE audit_log SET action_kind = 'TAMPERED' WHERE id = 3",
                [],
            )
            .expect("should execute tamper update");
    }

    // Re-open the store and verify integrity catches the tampering
    let store_after = AuditStore::open(&db_path).expect("should reopen audit store after tamper");
    let report_after = store_after
        .verify_integrity()
        .expect("should verify integrity after tamper");

    assert!(
        !report_after.valid,
        "integrity should fail after tampering: {}",
        report_after.message
    );
    assert_eq!(
        report_after.first_invalid_entry,
        Some(2),
        "first invalid entry should be index 2 (row id=3)"
    );
}

#[test]
fn test_tamper_detection_catches_broken_chain() {
    let tmp = temp_db();
    let db_path = tmp.path().to_path_buf();
    let mut store = AuditStore::open(&db_path).expect("should open audit store");

    for i in 0..4 {
        let a = sample_action("agent", file_read_kind(&format!("/tmp/{i}")));
        let v = Verdict::allow(a.id, "ok", None);
        store.append(&a, &v).expect("should append entry");
    }

    // Break the chain by modifying prev_hash of the 2nd entry
    {
        let tamper_conn =
            rusqlite::Connection::open(&db_path).expect("should open db for chain tampering");
        tamper_conn
            .execute(
                "UPDATE audit_log SET prev_hash = 'corrupted' WHERE id = 2",
                [],
            )
            .expect("should execute chain tamper update");
    }

    let store_after =
        AuditStore::open(&db_path).expect("should reopen audit store after chain tamper");
    let report = store_after
        .verify_integrity()
        .expect("should verify integrity after chain tamper");

    assert!(
        !report.valid,
        "integrity should fail with broken chain link: {}",
        report.message
    );
    assert_eq!(
        report.first_invalid_entry,
        Some(1),
        "first invalid entry should be index 1 (row id=2)"
    );
}
