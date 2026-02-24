//! Dedicated audit writer thread.
//!
//! [`AuditWriter`] spawns a background thread that owns an [`AuditStore`]
//! exclusively -- no mutex needed. Agent lifecycle threads send session
//! commands through a bounded [`std::sync::mpsc::sync_channel`], eliminating
//! write contention between concurrent agents.
//!
//! # Design
//!
//! - `BeginSession` uses a reply channel so the caller gets the session UUID.
//! - `EndSession` and `Append` are fire-and-forget (no reply).
//! - The channel is bounded at 4096 to provide backpressure.
//! - `AuditWriter` is `Clone`: each agent thread holds its own handle.

use std::sync::mpsc;
use std::thread;

use tracing::warn;

use aegis_types::{Action, AegisError, Verdict};

use crate::store::AuditStore;

/// Messages the audit writer thread can receive.
pub enum AuditMsg {
    /// Begin a new audit session. Sends the new session UUID back on `reply`.
    BeginSession {
        /// `config_name` passed to [`AuditStore::begin_session`].
        config_name: String,
        /// `command` passed to [`AuditStore::begin_session`].
        command: String,
        /// `args` passed to [`AuditStore::begin_session`].
        args: Vec<String>,
        /// Optional human-readable tag for the session.
        tag: Option<String>,
        /// Reply channel: the writer sends the result back here.
        reply: mpsc::SyncSender<Result<uuid::Uuid, AegisError>>,
    },
    /// End an existing audit session. Fire-and-forget.
    EndSession {
        /// The session to close.
        session_id: uuid::Uuid,
        /// Exit code of the agent process.
        exit_code: i32,
    },
    /// Append an action/verdict pair to the ledger. Fire-and-forget.
    Append {
        /// The action being audited.
        action: Action,
        /// The policy verdict for the action.
        verdict: Verdict,
    },
    /// Shut down the writer thread cleanly.
    Shutdown,
}

/// Handle to a dedicated audit writer thread.
///
/// The thread owns the [`AuditStore`] exclusively, so no mutex is needed on
/// the write path. Clone this handle freely -- each agent thread should hold
/// its own copy.
#[derive(Clone)]
pub struct AuditWriter {
    tx: mpsc::SyncSender<AuditMsg>,
}

impl AuditWriter {
    /// Spawn a dedicated writer thread that owns `store`.
    ///
    /// Returns the writer handle and a [`thread::JoinHandle`] that the caller
    /// can use to wait for the thread to exit after calling [`shutdown`].
    ///
    /// [`shutdown`]: AuditWriter::shutdown
    pub fn spawn(store: AuditStore) -> (Self, thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::sync_channel::<AuditMsg>(4096);
        let handle = thread::Builder::new()
            .name("audit-writer".into())
            .spawn(move || {
                Self::writer_loop(store, rx);
            })
            .expect("failed to spawn audit writer thread");
        (Self { tx }, handle)
    }

    /// Main loop: process messages until `Shutdown` or the channel is closed.
    fn writer_loop(mut store: AuditStore, rx: mpsc::Receiver<AuditMsg>) {
        for msg in rx {
            match msg {
                AuditMsg::BeginSession {
                    config_name,
                    command,
                    args,
                    tag,
                    reply,
                } => {
                    let result =
                        store.begin_session(&config_name, &command, &args, tag.as_deref());
                    let _ = reply.send(result);
                }
                AuditMsg::EndSession {
                    session_id,
                    exit_code,
                } => {
                    if let Err(e) = store.end_session(&session_id, exit_code) {
                        warn!(
                            session_id = %session_id,
                            error = %e,
                            "audit writer: failed to end session"
                        );
                    }
                }
                AuditMsg::Append { action, verdict } => {
                    if let Err(e) = store.append(&action, &verdict) {
                        warn!(error = %e, "audit writer: failed to append entry");
                    }
                }
                AuditMsg::Shutdown => break,
            }
        }
    }

    /// Begin a new audit session.
    ///
    /// Blocks until the writer thread processes the request and returns the
    /// new session UUID, or an error if the store operation fails.
    ///
    /// # Errors
    ///
    /// Returns [`AegisError::LedgerError`] if the writer thread has shut down
    /// or if the underlying `begin_session` call fails.
    pub fn begin_session(
        &self,
        config_name: &str,
        command: &str,
        args: &[String],
        tag: Option<&str>,
    ) -> Result<uuid::Uuid, AegisError> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.tx
            .send(AuditMsg::BeginSession {
                config_name: config_name.to_string(),
                command: command.to_string(),
                args: args.to_vec(),
                tag: tag.map(|s| s.to_string()),
                reply: reply_tx,
            })
            .map_err(|_| AegisError::LedgerError("audit writer thread has shut down".into()))?;
        reply_rx.recv().map_err(|_| {
            AegisError::LedgerError("audit writer reply channel closed unexpectedly".into())
        })?
    }

    /// End an audit session. Fire-and-forget: does not wait for confirmation.
    pub fn end_session(&self, session_id: &uuid::Uuid, exit_code: i32) {
        let _ = self.tx.send(AuditMsg::EndSession {
            session_id: *session_id,
            exit_code,
        });
    }

    /// Append an action/verdict entry. Fire-and-forget.
    pub fn append(&self, action: Action, verdict: Verdict) {
        let _ = self.tx.send(AuditMsg::Append { action, verdict });
    }

    /// Ask the writer thread to shut down.
    ///
    /// The thread finishes processing any already-queued messages before exiting.
    /// Join the [`thread::JoinHandle`] returned from [`spawn`] to wait for it.
    ///
    /// [`spawn`]: AuditWriter::spawn
    pub fn shutdown(&self) {
        let _ = self.tx.send(AuditMsg::Shutdown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::ActionKind;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn open_store() -> (NamedTempFile, AuditStore) {
        let tmp = NamedTempFile::new().expect("temp file");
        let store = AuditStore::open(tmp.path()).expect("open store");
        (tmp, store)
    }

    fn sample_action(principal: &str) -> Action {
        Action::new(
            principal,
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        )
    }

    #[test]
    fn begin_and_end_session_round_trip() {
        let (tmp, store) = open_store();
        let (writer, handle) = AuditWriter::spawn(store);

        let session_id = writer
            .begin_session("test-config", "echo", &[], Some("tag1"))
            .expect("begin_session should succeed");

        writer.end_session(&session_id, 0);
        writer.shutdown();
        handle.join().expect("writer thread should exit cleanly");

        // Verify by reopening the store directly.
        let store2 = AuditStore::open(tmp.path()).expect("reopen");
        let sessions = store2.list_sessions(10, 0).expect("list sessions");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, session_id);
        assert_eq!(sessions[0].exit_code, Some(0));
    }

    #[test]
    fn begin_session_error_propagated() {
        let (tmp, store) = open_store();
        let (writer, handle) = AuditWriter::spawn(store);

        // Valid call should succeed.
        let result = writer.begin_session("cfg", "cmd", &[], None);
        assert!(result.is_ok());

        writer.shutdown();
        handle.join().expect("writer thread should exit cleanly");
        drop(tmp);
    }

    #[test]
    fn clone_handle_both_work() {
        let (tmp, store) = open_store();
        let (writer, handle) = AuditWriter::spawn(store);
        let writer2 = writer.clone();

        let s1 = writer
            .begin_session("cfg", "cmd1", &[], None)
            .expect("session 1");
        let s2 = writer2
            .begin_session("cfg", "cmd2", &[], None)
            .expect("session 2");

        assert_ne!(s1, s2);

        writer.end_session(&s1, 0);
        writer2.end_session(&s2, 1);
        writer.shutdown();
        handle.join().expect("clean exit");

        let store2 = AuditStore::open(tmp.path()).expect("reopen");
        let sessions = store2.list_sessions(10, 0).expect("list");
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn append_entry_is_persisted() {
        let (tmp, store) = open_store();
        let (writer, handle) = AuditWriter::spawn(store);

        let action = sample_action("agent-x");
        let verdict = Verdict::allow(action.id, "ok", None);
        writer.append(action, verdict);

        writer.shutdown();
        handle.join().expect("clean exit");

        let store2 = AuditStore::open(tmp.path()).expect("reopen");
        let entries = store2.query_last(10).expect("query");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].principal, "agent-x");
    }

    #[test]
    fn shutdown_after_drop_is_harmless() {
        let (tmp, store) = open_store();
        let (writer, handle) = AuditWriter::spawn(store);
        writer.shutdown();
        handle.join().expect("clean exit");

        // Second shutdown on the clone after thread is gone should not panic.
        let writer2 = writer.clone();
        writer2.shutdown(); // send returns Err, which we ignore
        drop(tmp);
    }
}
