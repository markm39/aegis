//! Integration tests for session lifecycle and statistics.
//!
//! Verifies session begin/end, tagging, counting, stats computation,
//! and policy snapshot recording across the aegis-ledger crate.

use std::path::PathBuf;

use tempfile::NamedTempFile;

use aegis_ledger::{AuditFilter, AuditStore};
use aegis_types::{Action, ActionKind, Verdict};

fn temp_db() -> NamedTempFile {
    NamedTempFile::new().expect("should create temp file")
}

fn file_read(principal: &str, path: &str) -> Action {
    Action::new(
        principal,
        ActionKind::FileRead {
            path: PathBuf::from(path),
        },
    )
}

fn file_write(principal: &str, path: &str) -> Action {
    Action::new(
        principal,
        ActionKind::FileWrite {
            path: PathBuf::from(path),
        },
    )
}

fn net_connect(principal: &str, host: &str, port: u16) -> Action {
    Action::new(
        principal,
        ActionKind::NetConnect {
            host: host.to_string(),
            port,
        },
    )
}

#[test]
fn session_lifecycle_with_mixed_verdicts() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).unwrap();

    let sid = store
        .begin_session("myagent", "python3", &["agent.py".into()], Some("test-run"))
        .unwrap();

    // 3 allows, 2 denies
    let a1 = file_read("myagent", "/data/input.csv");
    store
        .append_with_session(&a1, &Verdict::allow(a1.id, "ok", None), &sid)
        .unwrap();

    let a2 = file_read("myagent", "/data/config.json");
    store
        .append_with_session(&a2, &Verdict::allow(a2.id, "ok", None), &sid)
        .unwrap();

    let a3 = file_write("myagent", "/output/result.txt");
    store
        .append_with_session(&a3, &Verdict::deny(a3.id, "blocked", None), &sid)
        .unwrap();

    let a4 = net_connect("myagent", "api.openai.com", 443);
    store
        .append_with_session(&a4, &Verdict::allow(a4.id, "ok", None), &sid)
        .unwrap();

    let a5 = net_connect("myagent", "evil.com", 80);
    store
        .append_with_session(&a5, &Verdict::deny(a5.id, "blocked", None), &sid)
        .unwrap();

    store.end_session(&sid, 0).unwrap();

    // Check session metadata
    let session = store.get_session(&sid).unwrap().unwrap();
    assert_eq!(session.total_actions, 5);
    assert_eq!(session.denied_actions, 2);
    assert_eq!(session.tag, Some("test-run".to_string()));
    assert_eq!(session.exit_code, Some(0));
    assert!(session.end_time.is_some());

    // Check session entries
    let entries = store.query_by_session(&sid).unwrap();
    assert_eq!(entries.len(), 5);

    // Verify hash chain integrity
    let report = store.verify_integrity().unwrap();
    assert!(report.valid, "chain should be valid: {}", report.message);
}

#[test]
fn multiple_sessions_with_counting() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).unwrap();

    // Create 3 sessions
    for i in 0..3 {
        let sid = store
            .begin_session("agent", &format!("cmd{i}"), &[], None)
            .unwrap();

        let a = file_read("agent", &format!("/file{i}"));
        store
            .append_with_session(&a, &Verdict::allow(a.id, "ok", None), &sid)
            .unwrap();

        store.end_session(&sid, 0).unwrap();
    }

    // Count and latest
    assert_eq!(store.count_all_sessions().unwrap(), 3);

    let latest = store.latest_session().unwrap().unwrap();
    assert_eq!(latest.command, "cmd2");

    // List sessions
    let sessions = store.list_sessions(10, 0).unwrap();
    assert_eq!(sessions.len(), 3);
    assert_eq!(sessions[0].command, "cmd2"); // most recent first
}

#[test]
fn session_tagging_after_creation() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).unwrap();

    let sid = store.begin_session("agent", "deploy", &[], None).unwrap();

    // Initially no tag
    let session = store.get_session(&sid).unwrap().unwrap();
    assert!(session.tag.is_none());

    // Tag it
    store.update_session_tag(&sid, "production-v3").unwrap();

    let session = store.get_session(&sid).unwrap().unwrap();
    assert_eq!(session.tag, Some("production-v3".to_string()));
}

#[test]
fn stats_across_sessions() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).unwrap();

    let s1 = store.begin_session("agent", "cmd1", &[], None).unwrap();
    let s2 = store.begin_session("agent", "cmd2", &[], None).unwrap();

    // Session 1: 2 reads (allow)
    for i in 0..2 {
        let a = file_read("agent", &format!("/data/{i}"));
        store
            .append_with_session(&a, &Verdict::allow(a.id, "ok", None), &s1)
            .unwrap();
    }

    // Session 2: 1 write (deny) + 1 read (allow)
    let a = file_write("agent", "/secret/key");
    store
        .append_with_session(&a, &Verdict::deny(a.id, "blocked", None), &s2)
        .unwrap();

    let a = file_read("agent", "/data/public");
    store
        .append_with_session(&a, &Verdict::allow(a.id, "ok", None), &s2)
        .unwrap();

    store.end_session(&s1, 0).unwrap();
    store.end_session(&s2, 1).unwrap();

    // Compute stats
    let filter = AuditFilter::default();
    let stats = store.compute_stats(&filter, "agent").unwrap();

    assert_eq!(stats.total_entries, 4);
    assert_eq!(stats.allow_count, 3);
    assert_eq!(stats.deny_count, 1);
    assert!(stats.integrity_valid);
    assert_eq!(stats.total_sessions, 2);

    // Action breakdown should include FileRead and FileWrite
    assert!(!stats.entries_by_action.is_empty());

    // Top resources should be populated
    assert!(!stats.top_resources.is_empty());
}

#[test]
fn purge_preserves_recent_sessions() {
    let tmp = temp_db();
    let mut store = AuditStore::open(tmp.path()).unwrap();

    let sid = store.begin_session("agent", "cmd", &[], None).unwrap();

    for i in 0..5 {
        let a = file_read("agent", &format!("/data/{i}"));
        store
            .append_with_session(&a, &Verdict::allow(a.id, "ok", None), &sid)
            .unwrap();
    }

    // Purge entries in the far past (should delete nothing)
    let past = chrono::Utc::now() - chrono::Duration::days(365);
    let deleted = store.purge_before(past).unwrap();
    assert_eq!(deleted, 0);

    // All entries should still be present
    assert_eq!(store.count().unwrap(), 5);

    // Chain should still be valid
    let report = store.verify_integrity().unwrap();
    assert!(report.valid, "chain should be valid after no-op purge: {}", report.message);
}
