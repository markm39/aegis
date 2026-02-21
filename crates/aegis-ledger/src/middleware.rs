//! Audit middleware for extensible audit processing.
//!
//! The [`AuditMiddleware`] trait provides a hook that is called after every
//! audit entry is inserted. Middleware receives an immutable reference to the
//! entry and cannot modify it -- this is a deliberate security constraint to
//! prevent middleware from altering the audit trail.
//!
//! Multiple middleware can be registered on an `AuditStore` and all will be
//! invoked for each entry.

use crate::channel_audit::ChannelAuditEntry;
use crate::entry::AuditEntry;
use crate::fs_audit::FsAuditEntry;

/// A hook invoked after an audit entry is persisted.
///
/// Implementations receive an immutable reference to the entry. They cannot
/// modify the entry -- the audit trail is append-only and tamper-evident.
///
/// # Security
///
/// Middleware runs synchronously after the database insert. A panicking
/// middleware will propagate the panic; implementations should catch errors
/// internally and log them rather than panicking.
pub trait AuditMiddleware: Send + Sync {
    /// Called after a standard audit entry is inserted.
    fn on_action(&self, entry: &AuditEntry);

    /// Called after a channel audit entry is inserted.
    ///
    /// Default implementation does nothing.
    fn on_channel_action(&self, _entry: &ChannelAuditEntry) {}

    /// Called after a filesystem audit entry is inserted.
    ///
    /// Default implementation does nothing.
    fn on_fs_action(&self, _entry: &FsAuditEntry) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_audit::{hash_message_content, ChannelDirection};
    use crate::fs_audit::{hash_file_content, FsOperation};
    use crate::test_helpers::test_db_path;
    use crate::store::AuditStore;
    use aegis_types::{Action, ActionKind, Verdict};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A test middleware that counts how many times it was invoked.
    struct CountingMiddleware {
        action_count: AtomicUsize,
        channel_count: AtomicUsize,
        fs_count: AtomicUsize,
    }

    impl CountingMiddleware {
        fn new() -> Self {
            Self {
                action_count: AtomicUsize::new(0),
                channel_count: AtomicUsize::new(0),
                fs_count: AtomicUsize::new(0),
            }
        }
    }

    impl AuditMiddleware for CountingMiddleware {
        fn on_action(&self, _entry: &AuditEntry) {
            self.action_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_channel_action(&self, _entry: &ChannelAuditEntry) {
            self.channel_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_fs_action(&self, _entry: &FsAuditEntry) {
            self.fs_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A test middleware that records the principal of each action entry.
    struct RecordingMiddleware {
        principals: std::sync::Mutex<Vec<String>>,
    }

    impl RecordingMiddleware {
        fn new() -> Self {
            Self {
                principals: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl AuditMiddleware for RecordingMiddleware {
        fn on_action(&self, entry: &AuditEntry) {
            self.principals
                .lock()
                .unwrap()
                .push(entry.principal.clone());
        }
    }

    #[test]
    fn audit_middleware_hook_called() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let counter = Arc::new(CountingMiddleware::new());
        store.add_middleware(counter.clone());

        let action = Action::new(
            "agent-1",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let verdict = Verdict::allow(action.id, "ok", None);
        store.append(&action, &verdict).unwrap();

        assert_eq!(counter.action_count.load(Ordering::SeqCst), 1);

        // Insert another
        let action2 = Action::new(
            "agent-2",
            ActionKind::FileWrite {
                path: PathBuf::from("/tmp/test2.txt"),
            },
        );
        let verdict2 = Verdict::deny(action2.id, "blocked", None);
        store.append(&action2, &verdict2).unwrap();

        assert_eq!(counter.action_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn multiple_middleware_all_invoked() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let counter1 = Arc::new(CountingMiddleware::new());
        let counter2 = Arc::new(CountingMiddleware::new());
        let recorder = Arc::new(RecordingMiddleware::new());

        store.add_middleware(counter1.clone());
        store.add_middleware(counter2.clone());
        store.add_middleware(recorder.clone());

        let action = Action::new(
            "multi-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let verdict = Verdict::allow(action.id, "ok", None);
        store.append(&action, &verdict).unwrap();

        // All three middleware should have been called
        assert_eq!(counter1.action_count.load(Ordering::SeqCst), 1);
        assert_eq!(counter2.action_count.load(Ordering::SeqCst), 1);

        let principals = recorder.principals.lock().unwrap();
        assert_eq!(principals.len(), 1);
        assert_eq!(principals[0], "multi-agent");
    }

    #[test]
    fn middleware_receives_immutable_entry() {
        // This test verifies that middleware cannot modify the entry.
        // The trait method signature enforces this at compile time (&AuditEntry),
        // but we verify the entry is unchanged after middleware runs.
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let recorder = Arc::new(RecordingMiddleware::new());
        store.add_middleware(recorder.clone());

        let action = Action::new(
            "immutable-test",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let verdict = Verdict::allow(action.id, "ok", None);
        let entry = store.append(&action, &verdict).unwrap();

        // The entry returned by append should be unchanged
        assert_eq!(entry.principal, "immutable-test");
        assert_eq!(entry.decision, "Allow");

        // And the middleware saw the same values
        let principals = recorder.principals.lock().unwrap();
        assert_eq!(principals[0], "immutable-test");
    }

    #[test]
    fn middleware_called_for_channel_audit() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let counter = Arc::new(CountingMiddleware::new());
        store.add_middleware(counter.clone());

        let msg_hash = hash_message_content("test message");
        store
            .insert_channel_audit("telegram", ChannelDirection::Outbound, &msg_hash, 1, false)
            .unwrap();

        assert_eq!(counter.channel_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn middleware_called_for_fs_audit() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let counter = Arc::new(CountingMiddleware::new());
        store.add_middleware(counter.clone());

        let after = hash_file_content(b"new content");
        store
            .insert_fs_audit("/tmp/test.txt", None, Some(&after), 11, FsOperation::Create)
            .unwrap();

        assert_eq!(counter.fs_count.load(Ordering::SeqCst), 1);
    }
}
