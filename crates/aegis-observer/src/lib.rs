//! Filesystem observer for per-file audit trails.
//!
//! Provides zero-privilege observability by monitoring a sandbox directory
//! using macOS FSEvents (via the `notify` crate) and pre/post directory
//! snapshot diffing. Since Aegis controls the sandbox boundary, process
//! attribution is implicit: any file change within `sandbox_dir` must come
//! from the sandboxed process.
//!
//! # Architecture
//!
//! **Tier 1 (no privileges):**
//! - FSEvents watcher: real-time notification of file creates, modifies,
//!   deletes, renames within the sandbox directory.
//! - Snapshot diffing: captures pre/post state of the sandbox directory tree.
//!   Detects writes missed by FSEvents (rapid create/delete) and reads via
//!   atime changes.
//!
//! **Tier 2 (requires root, optional):**
//! - eslogger: macOS Endpoint Security logger subprocess. Provides per-process
//!   file access events including reads. (Not yet implemented.)
pub(crate) mod event;
pub(crate) mod snapshot;
pub(crate) mod watcher;

use std::path::Path;
use std::sync::{Arc, Mutex};

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_types::AegisError;

use crate::snapshot::DirSnapshot;
use crate::watcher::FsWatcher;

/// Summary of observer activity during a session.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ObserverSummary {
    /// Number of events captured by the FSEvents watcher.
    pub fsevents_count: usize,
    /// Number of read events detected by snapshot diffing.
    pub snapshot_read_count: usize,
    /// Total events logged to the audit store by the observer.
    pub total_logged: usize,
}

/// An active observer session.
///
/// Created by `start_observer()`, consumed by `stop_observer()`.
pub struct ObserverSession {
    watcher: Option<FsWatcher>,
    pre_snapshot: Option<DirSnapshot>,
    sandbox_dir: std::path::PathBuf,
    store: Arc<Mutex<AuditStore>>,
    engine: Arc<Mutex<PolicyEngine>>,
    principal: String,
    session_id: Option<uuid::Uuid>,
    enable_snapshots: bool,
}

/// Start observing a sandbox directory.
///
/// Captures a pre-snapshot of the sandbox directory tree (if `enable_snapshots`
/// is true) and starts the FSEvents watcher. Call `stop_observer()` after the
/// sandboxed process exits to finalize.
pub fn start_observer(
    sandbox_dir: &Path,
    store: Arc<Mutex<AuditStore>>,
    engine: Arc<Mutex<PolicyEngine>>,
    principal: &str,
    session_id: Option<uuid::Uuid>,
    enable_snapshots: bool,
) -> Result<ObserverSession, AegisError> {
    // Capture pre-snapshot before starting the watcher (only if snapshots enabled)
    let pre_snapshot = if enable_snapshots {
        let snap = DirSnapshot::capture(sandbox_dir)?;
        tracing::info!(
            entries = snap.len(),
            path = %sandbox_dir.display(),
            "pre-snapshot captured"
        );
        Some(snap)
    } else {
        tracing::info!("snapshot diffing disabled");
        None
    };

    // Start FSEvents watcher
    let watcher = FsWatcher::start(
        sandbox_dir,
        Arc::clone(&store),
        Arc::clone(&engine),
        principal.to_string(),
        session_id,
    )?;

    Ok(ObserverSession {
        watcher: Some(watcher),
        pre_snapshot,
        sandbox_dir: sandbox_dir.to_path_buf(),
        store,
        engine,
        principal: principal.to_string(),
        session_id,
        enable_snapshots,
    })
}

/// Stop the observer and return a summary.
///
/// Stops the FSEvents watcher, captures a post-snapshot, diffs against the
/// pre-snapshot, and logs any read events detected by the snapshot diff
/// (writes are already captured by the watcher, so we only log reads from
/// the diff to avoid duplicates).
pub fn stop_observer(mut session: ObserverSession) -> Result<ObserverSummary, AegisError> {
    // Stop the watcher and get its event count
    let fsevents_count = if let Some(watcher) = session.watcher.take() {
        watcher.stop()
    } else {
        0
    };

    // Snapshot diff -- only when snapshots are enabled and a pre-snapshot exists.
    let mut snapshot_read_count = 0;
    if session.enable_snapshots {
        if let Some(pre_snapshot) = session.pre_snapshot {
            let post_snapshot = DirSnapshot::capture(&session.sandbox_dir)?;
            tracing::info!(
                entries = post_snapshot.len(),
                path = %session.sandbox_dir.display(),
                "post-snapshot captured"
            );

            // Diff snapshots -- only log FileRead events from the diff.
            // Write/create/delete events are already captured by the watcher.
            let diff_events = pre_snapshot.diff(&post_snapshot);
            let read_events: Vec<_> = diff_events
                .into_iter()
                .filter(|e| matches!(e.kind, crate::event::FsEventKind::FileRead))
                .collect();

            for fs_event in &read_events {
                for action_kind in fs_event.to_actions() {
                    let action = aegis_types::Action::new(&session.principal, action_kind);

                    let verdict = session
                        .engine
                        .lock()
                        .map_err(|e| AegisError::PolicyError(format!("policy lock poisoned: {e}")))?
                        .evaluate(&action);

                    let mut store_guard = session
                        .store
                        .lock()
                        .map_err(|e| AegisError::LedgerError(format!("audit lock poisoned: {e}")))?;

                    match session.session_id {
                        Some(sid) => store_guard.append_with_session(&action, &verdict, &sid)?,
                        None => store_guard.append(&action, &verdict)?,
                    };

                    snapshot_read_count += 1;
                }
            }
        }
    }

    let total_logged = fsevents_count + snapshot_read_count;

    tracing::info!(
        fsevents_count,
        snapshot_read_count,
        total_logged,
        "observer session complete"
    );

    Ok(ObserverSummary {
        fsevents_count,
        snapshot_read_count,
        total_logged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_ledger::AuditStore;
    use aegis_policy::PolicyEngine;
    use std::fs;
    use tempfile::NamedTempFile;

    /// Returns (store, engine, _db_handle). The caller must keep `_db_handle`
    /// alive for the duration of the test so the temp file is not deleted.
    fn test_deps() -> (Arc<Mutex<AuditStore>>, Arc<Mutex<PolicyEngine>>, NamedTempFile) {
        let db = NamedTempFile::new().unwrap();
        let store = AuditStore::open(db.path()).unwrap();
        let engine =
            PolicyEngine::from_policies(r#"permit(principal, action, resource);"#, None).unwrap();
        (Arc::new(Mutex::new(store)), Arc::new(Mutex::new(engine)), db)
    }

    #[test]
    fn start_and_stop_observer_empty_dir() {
        let sandbox = tempfile::tempdir().unwrap();
        let (store, engine, _db) = test_deps();

        let session = start_observer(
            sandbox.path(),
            store,
            engine,
            "test-agent",
            None,
            true,
        )
        .unwrap();

        let summary = stop_observer(session).unwrap();
        assert_eq!(summary.fsevents_count, 0);
        assert_eq!(summary.snapshot_read_count, 0);
        assert_eq!(summary.total_logged, 0);
    }

    #[test]
    fn snapshots_disabled_skips_diffing() {
        let sandbox = tempfile::tempdir().unwrap();
        let (store, engine, _db) = test_deps();

        // Create a file before starting the observer
        fs::write(sandbox.path().join("existing.txt"), "hello").unwrap();

        let session = start_observer(
            sandbox.path(),
            Arc::clone(&store),
            Arc::clone(&engine),
            "test-agent",
            None,
            false, // snapshots disabled
        )
        .unwrap();

        // pre_snapshot should be None
        assert!(!session.enable_snapshots);

        // Modify the file -- with snapshots disabled, no read events from diffing
        fs::write(sandbox.path().join("existing.txt"), "modified").unwrap();

        let summary = stop_observer(session).unwrap();
        assert_eq!(summary.snapshot_read_count, 0, "snapshot diffing should be skipped");
    }

    #[test]
    #[ignore] // Requires FSEvents which may not deliver events inside sandboxed environments
    fn observer_detects_file_write() {
        let sandbox = tempfile::tempdir().unwrap();
        let (store, engine, _db) = test_deps();

        let session = start_observer(
            sandbox.path(),
            Arc::clone(&store),
            Arc::clone(&engine),
            "test-agent",
            None,
            true,
        )
        .unwrap();

        // Write a file while observer is running
        fs::write(sandbox.path().join("test.txt"), "hello observer").unwrap();

        // Give FSEvents time to deliver
        std::thread::sleep(std::time::Duration::from_millis(800));

        let summary = stop_observer(session).unwrap();

        // FSEvents should have detected the write
        let entry_count = store.lock().unwrap().count().unwrap();
        assert!(
            entry_count > 0,
            "expected at least 1 audit entry from observer, got {entry_count}"
        );
        assert!(summary.total_logged > 0);
    }

    #[test]
    #[ignore] // Requires FSEvents which may not deliver events inside sandboxed environments
    fn observer_detects_file_delete() {
        let sandbox = tempfile::tempdir().unwrap();
        let file_path = sandbox.path().join("doomed.txt");
        fs::write(&file_path, "bye").unwrap();

        let (store, engine, _db) = test_deps();

        let session = start_observer(
            sandbox.path(),
            Arc::clone(&store),
            Arc::clone(&engine),
            "test-agent",
            None,
            true,
        )
        .unwrap();

        // Delete the file while observer is running
        fs::remove_file(&file_path).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(800));

        let summary = stop_observer(session).unwrap();
        let entry_count = store.lock().unwrap().count().unwrap();
        assert!(
            entry_count > 0,
            "expected audit entry for deletion, got {entry_count}"
        );
        assert!(summary.total_logged > 0);
    }

    #[test]
    #[ignore] // Requires FSEvents which may not deliver events inside sandboxed environments
    fn observer_detects_directory_creation() {
        let sandbox = tempfile::tempdir().unwrap();
        let (store, engine, _db) = test_deps();

        let session = start_observer(
            sandbox.path(),
            Arc::clone(&store),
            Arc::clone(&engine),
            "test-agent",
            None,
            true,
        )
        .unwrap();

        fs::create_dir(sandbox.path().join("newsubdir")).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(800));

        let summary = stop_observer(session).unwrap();
        let entry_count = store.lock().unwrap().count().unwrap();
        assert!(
            entry_count > 0,
            "expected audit entry for dir creation, got {entry_count}"
        );
        assert!(summary.total_logged > 0);
    }
}
