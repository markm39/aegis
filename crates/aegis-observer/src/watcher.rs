//! FSEvents-based filesystem watcher (Tier 1, no privileges required).
//!
//! Uses the `notify` crate to watch a directory recursively via macOS FSEvents.
//! Since Aegis controls the sandbox boundary, process attribution is implicit:
//! any file change within `sandbox_dir` must come from the sandboxed process.
//!
//! Events are mapped to `FsEvent`s, evaluated against the Cedar policy engine,
//! and appended to the audit store.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_types::{Action, AegisError};

use crate::event::{FsEvent, FsEventKind, ObserverSource};

/// A filesystem watcher that monitors a sandbox directory.
pub struct FsWatcher {
    _watcher: RecommendedWatcher,
    shutdown_tx: Option<mpsc::Sender<()>>,
    consumer_handle: Option<std::thread::JoinHandle<()>>,
    event_count: Arc<AtomicUsize>,
}

impl FsWatcher {
    /// Start watching `sandbox_dir` for filesystem changes.
    ///
    /// Events are evaluated against the policy engine and logged to the audit
    /// store with the given principal and optional session ID.
    pub fn start(
        sandbox_dir: &Path,
        store: Arc<Mutex<AuditStore>>,
        engine: Arc<Mutex<PolicyEngine>>,
        principal: String,
        session_id: Option<uuid::Uuid>,
    ) -> Result<Self, AegisError> {
        let sandbox_dir = sandbox_dir.canonicalize().map_err(|e| {
            AegisError::LedgerError(format!(
                "failed to canonicalize sandbox dir: {e}"
            ))
        })?;

        let (event_tx, event_rx) = mpsc::channel::<notify::Event>();
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let event_count = Arc::new(AtomicUsize::new(0));

        // Create the notify watcher, forwarding events to our channel
        let tx_clone = event_tx.clone();
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx_clone.send(event);
                }
            },
            Config::default(),
        )
        .map_err(|e| {
            AegisError::LedgerError(format!("failed to create watcher: {e}"))
        })?;

        watcher
            .watch(&sandbox_dir, RecursiveMode::Recursive)
            .map_err(|e| {
                AegisError::LedgerError(format!("failed to watch directory: {e}"))
            })?;

        tracing::info!(
            path = %sandbox_dir.display(),
            "FSEvents watcher started"
        );

        // Spawn consumer thread
        let count_clone = Arc::clone(&event_count);
        let sandbox_clone = sandbox_dir.clone();
        let consumer_handle = std::thread::spawn(move || {
            let ctx = EventContext {
                store: &store,
                engine: &engine,
                principal: &principal,
                session_id: &session_id,
                sandbox_dir: &sandbox_clone,
                event_count: &count_clone,
            };
            consume_events(event_rx, shutdown_rx, &ctx);
        });

        Ok(Self {
            _watcher: watcher,
            shutdown_tx: Some(shutdown_tx),
            consumer_handle: Some(consumer_handle),
            event_count,
        })
    }

    /// Stop the watcher and return the number of events processed.
    pub fn stop(mut self) -> usize {
        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for consumer to finish
        if let Some(handle) = self.consumer_handle.take() {
            let _ = handle.join();
        }

        let count = self.event_count.load(Ordering::SeqCst);
        tracing::info!(events = count, "FSEvents watcher stopped");
        count
    }

    /// Current count of events processed.
    pub fn event_count(&self) -> usize {
        self.event_count.load(Ordering::SeqCst)
    }
}

/// Shared context for event processing functions.
struct EventContext<'a> {
    store: &'a Arc<Mutex<AuditStore>>,
    engine: &'a Arc<Mutex<PolicyEngine>>,
    principal: &'a str,
    session_id: &'a Option<uuid::Uuid>,
    sandbox_dir: &'a Path,
    event_count: &'a AtomicUsize,
}

/// Consumer loop: reads notify events, maps them to FsEvents, evaluates
/// policy, and logs to the audit store.
fn consume_events(
    event_rx: mpsc::Receiver<notify::Event>,
    shutdown_rx: mpsc::Receiver<()>,
    ctx: &EventContext<'_>,
) {
    loop {
        // Check for shutdown signal (non-blocking)
        if shutdown_rx.try_recv().is_ok() {
            // Drain remaining events before exiting
            drain_events(&event_rx, ctx);
            return;
        }

        // Wait for an event with a short timeout so we can check shutdown
        match event_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(notify_event) => {
                process_notify_event(&notify_event, ctx);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Drain any remaining events from the channel.
fn drain_events(event_rx: &mpsc::Receiver<notify::Event>, ctx: &EventContext<'_>) {
    while let Ok(notify_event) = event_rx.try_recv() {
        process_notify_event(&notify_event, ctx);
    }
}

/// Process a single notify event: map to FsEvent(s), evaluate policy, log.
fn process_notify_event(notify_event: &notify::Event, ctx: &EventContext<'_>) {
    let fs_events = map_notify_event(notify_event, ctx.sandbox_dir);

    for fs_event in fs_events {
        for action_kind in fs_event.to_actions() {
            let action = Action::new(ctx.principal, action_kind);

            let verdict = match ctx.engine.lock() {
                Ok(eng) => eng.evaluate(&action),
                Err(e) => {
                    tracing::warn!(error = %e, "policy engine lock poisoned");
                    continue;
                }
            };

            let result = match ctx.store.lock() {
                Ok(mut st) => match ctx.session_id {
                    Some(sid) => st.append_with_session(&action, &verdict, sid),
                    None => st.append(&action, &verdict),
                },
                Err(e) => {
                    tracing::warn!(error = %e, "audit store lock poisoned");
                    continue;
                }
            };

            if let Err(e) = result {
                tracing::warn!(error = %e, "failed to log observed event");
            } else {
                ctx.event_count.fetch_add(1, Ordering::SeqCst);
                tracing::debug!(
                    path = %fs_event.path.display(),
                    kind = ?fs_event.kind,
                    decision = %verdict.decision,
                    "observed filesystem event"
                );
            }
        }
    }
}

/// Map a `notify::Event` to zero or more `FsEvent`s.
///
/// Filters to events within the sandbox directory and maps notify event kinds
/// to our FsEventKind enum.
fn map_notify_event(event: &notify::Event, sandbox_dir: &Path) -> Vec<FsEvent> {
    let now = chrono::Utc::now();
    let kind = match &event.kind {
        EventKind::Create(create_kind) => match create_kind {
            notify::event::CreateKind::File => Some(FsEventKind::FileCreate),
            notify::event::CreateKind::Folder => Some(FsEventKind::DirCreate),
            _ => Some(FsEventKind::FileCreate), // default to file create for Any/Other
        },
        EventKind::Modify(modify_kind) => match modify_kind {
            notify::event::ModifyKind::Data(_) => Some(FsEventKind::FileModify),
            notify::event::ModifyKind::Name(rename_mode) => {
                match rename_mode {
                    notify::event::RenameMode::To => Some(FsEventKind::FileRename { from: None }),
                    notify::event::RenameMode::From => {
                        // "From" means the file is leaving -- we'll see a "To" for the destination
                        Some(FsEventKind::FileDelete)
                    }
                    notify::event::RenameMode::Both => {
                        // Both paths available: paths[0] = from, paths[1] = to
                        if event.paths.len() >= 2 {
                            let from = event.paths[0].strip_prefix(sandbox_dir).ok()
                                .map(|p| p.to_path_buf());
                            return vec![FsEvent {
                                timestamp: now,
                                path: event.paths[1].clone(),
                                kind: FsEventKind::FileRename { from },
                                source: ObserverSource::FsEvents,
                            }]
                            .into_iter()
                            .filter(|e| e.path.starts_with(sandbox_dir))
                            .collect();
                        }
                        Some(FsEventKind::FileModify)
                    }
                    _ => Some(FsEventKind::FileModify),
                }
            }
            _ => Some(FsEventKind::FileModify),
        },
        EventKind::Remove(remove_kind) => match remove_kind {
            notify::event::RemoveKind::File => Some(FsEventKind::FileDelete),
            notify::event::RemoveKind::Folder => Some(FsEventKind::DirDelete),
            _ => Some(FsEventKind::FileDelete),
        },
        EventKind::Access(_) => Some(FsEventKind::FileRead),
        _ => None,
    };

    let Some(kind) = kind else {
        return Vec::new();
    };

    event
        .paths
        .iter()
        .filter(|p| p.starts_with(sandbox_dir))
        .map(|p| FsEvent {
            timestamp: now,
            path: p.clone(),
            kind: kind.clone(),
            source: ObserverSource::FsEvents,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn map_create_file_event() {
        let sandbox = PathBuf::from("/sandbox");
        let event = notify::Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![PathBuf::from("/sandbox/new.txt")],
            attrs: Default::default(),
        };

        let fs_events = map_notify_event(&event, &sandbox);
        assert_eq!(fs_events.len(), 1);
        assert_eq!(fs_events[0].kind, FsEventKind::FileCreate);
    }

    #[test]
    fn map_create_folder_event() {
        let sandbox = PathBuf::from("/sandbox");
        let event = notify::Event {
            kind: EventKind::Create(notify::event::CreateKind::Folder),
            paths: vec![PathBuf::from("/sandbox/subdir")],
            attrs: Default::default(),
        };

        let fs_events = map_notify_event(&event, &sandbox);
        assert_eq!(fs_events.len(), 1);
        assert_eq!(fs_events[0].kind, FsEventKind::DirCreate);
    }

    #[test]
    fn map_remove_file_event() {
        let sandbox = PathBuf::from("/sandbox");
        let event = notify::Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![PathBuf::from("/sandbox/gone.txt")],
            attrs: Default::default(),
        };

        let fs_events = map_notify_event(&event, &sandbox);
        assert_eq!(fs_events.len(), 1);
        assert_eq!(fs_events[0].kind, FsEventKind::FileDelete);
    }

    #[test]
    fn events_outside_sandbox_are_filtered() {
        let sandbox = PathBuf::from("/sandbox");
        let event = notify::Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![PathBuf::from("/other/place/file.txt")],
            attrs: Default::default(),
        };

        let fs_events = map_notify_event(&event, &sandbox);
        assert!(fs_events.is_empty());
    }

}
