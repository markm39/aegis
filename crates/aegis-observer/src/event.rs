//! Filesystem event types and their mapping to Aegis actions.
//!
//! `FsEvent` captures a single observed filesystem change. The `to_actions()`
//! method maps it to one or more `ActionKind` values that can be evaluated
//! against the Cedar policy engine and logged to the audit ledger.

use std::path::PathBuf;

use chrono::{DateTime, Utc};

use aegis_types::ActionKind;

/// The kind of filesystem change observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEventKind {
    /// A new file was created.
    FileCreate,
    /// An existing file's content was modified.
    FileModify,
    /// A file was deleted.
    FileDelete,
    /// A file was renamed/moved. `from` is the old path if known.
    FileRename { from: Option<PathBuf> },
    /// A new directory was created.
    DirCreate,
    /// A directory was deleted.
    DirDelete,
    /// A file was read (detected by atime change or eslogger).
    FileRead,
}

/// How the event was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverSource {
    /// FSEvents watcher (notify crate).
    FsEvents,
    /// Pre/post directory snapshot diffing.
    Snapshot,
}

/// A single observed filesystem event.
#[derive(Debug, Clone)]
pub struct FsEvent {
    #[allow(dead_code)] // set on every event; will be used for event ordering/display
    pub timestamp: DateTime<Utc>,
    pub path: PathBuf,
    pub kind: FsEventKind,
    #[allow(dead_code)] // set on every event; will be used for filtering by source
    pub source: ObserverSource,
}

impl FsEvent {
    /// Map this filesystem event to Aegis `ActionKind` values (borrowing).
    ///
    /// Most events produce a single action. `FileRename` produces two:
    /// a delete of the old path and a write to the new path.
    ///
    /// Use `into_actions()` when the event is owned to avoid path clones.
    pub fn to_actions(&self) -> Vec<ActionKind> {
        match &self.kind {
            FsEventKind::FileCreate | FsEventKind::FileModify => {
                vec![ActionKind::FileWrite {
                    path: self.path.clone(),
                }]
            }
            FsEventKind::FileDelete | FsEventKind::DirDelete => {
                vec![ActionKind::FileDelete {
                    path: self.path.clone(),
                }]
            }
            FsEventKind::FileRename { from } => {
                let mut actions = Vec::with_capacity(2);
                if let Some(old_path) = from {
                    actions.push(ActionKind::FileDelete {
                        path: old_path.clone(),
                    });
                }
                actions.push(ActionKind::FileWrite {
                    path: self.path.clone(),
                });
                actions
            }
            FsEventKind::DirCreate => {
                vec![ActionKind::DirCreate {
                    path: self.path.clone(),
                }]
            }
            FsEventKind::FileRead => {
                vec![ActionKind::FileRead {
                    path: self.path.clone(),
                }]
            }
        }
    }

    /// Consuming variant of `to_actions()` that moves paths instead of cloning.
    pub fn into_actions(self) -> Vec<ActionKind> {
        match self.kind {
            FsEventKind::FileCreate | FsEventKind::FileModify => {
                vec![ActionKind::FileWrite { path: self.path }]
            }
            FsEventKind::FileDelete | FsEventKind::DirDelete => {
                vec![ActionKind::FileDelete { path: self.path }]
            }
            FsEventKind::FileRename { from } => {
                let mut actions = Vec::with_capacity(2);
                if let Some(old_path) = from {
                    actions.push(ActionKind::FileDelete { path: old_path });
                }
                actions.push(ActionKind::FileWrite { path: self.path });
                actions
            }
            FsEventKind::DirCreate => {
                vec![ActionKind::DirCreate { path: self.path }]
            }
            FsEventKind::FileRead => {
                vec![ActionKind::FileRead { path: self.path }]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(kind: FsEventKind, path: &str) -> FsEvent {
        FsEvent {
            timestamp: Utc::now(),
            path: PathBuf::from(path),
            kind,
            source: ObserverSource::FsEvents,
        }
    }

    #[test]
    fn file_create_maps_to_file_write() {
        let event = make_event(FsEventKind::FileCreate, "/sandbox/new.txt");
        let actions = event.to_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            ActionKind::FileWrite { path } if path == &PathBuf::from("/sandbox/new.txt")
        ));
    }

    #[test]
    fn file_modify_maps_to_file_write() {
        let event = make_event(FsEventKind::FileModify, "/sandbox/edit.txt");
        let actions = event.to_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], ActionKind::FileWrite { .. }));
    }

    #[test]
    fn file_delete_maps_to_file_delete() {
        let event = make_event(FsEventKind::FileDelete, "/sandbox/gone.txt");
        let actions = event.to_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], ActionKind::FileDelete { .. }));
    }

    #[test]
    fn dir_delete_maps_to_file_delete() {
        let event = make_event(FsEventKind::DirDelete, "/sandbox/subdir");
        let actions = event.to_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], ActionKind::FileDelete { .. }));
    }

    #[test]
    fn dir_create_maps_to_dir_create() {
        let event = make_event(FsEventKind::DirCreate, "/sandbox/newdir");
        let actions = event.to_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], ActionKind::DirCreate { .. }));
    }

    #[test]
    fn file_read_maps_to_file_read() {
        let event = make_event(FsEventKind::FileRead, "/sandbox/readme.txt");
        let actions = event.to_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], ActionKind::FileRead { .. }));
    }

    #[test]
    fn file_rename_with_old_path_produces_two_actions() {
        let event = FsEvent {
            timestamp: Utc::now(),
            path: PathBuf::from("/sandbox/new_name.txt"),
            kind: FsEventKind::FileRename {
                from: Some(PathBuf::from("/sandbox/old_name.txt")),
            },
            source: ObserverSource::FsEvents,
        };
        let actions = event.to_actions();
        assert_eq!(actions.len(), 2);
        assert!(
            matches!(&actions[0], ActionKind::FileDelete { path } if path == &PathBuf::from("/sandbox/old_name.txt"))
        );
        assert!(
            matches!(&actions[1], ActionKind::FileWrite { path } if path == &PathBuf::from("/sandbox/new_name.txt"))
        );
    }

    #[test]
    fn into_actions_moves_path_without_cloning() {
        let event = make_event(FsEventKind::FileCreate, "/sandbox/moved.txt");
        let actions = event.into_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            ActionKind::FileWrite { path } if path == &PathBuf::from("/sandbox/moved.txt")
        ));
    }

    #[test]
    fn into_actions_rename_produces_two_actions() {
        let event = FsEvent {
            timestamp: Utc::now(),
            path: PathBuf::from("/sandbox/new.txt"),
            kind: FsEventKind::FileRename {
                from: Some(PathBuf::from("/sandbox/old.txt")),
            },
            source: ObserverSource::FsEvents,
        };
        let actions = event.into_actions();
        assert_eq!(actions.len(), 2);
        assert!(
            matches!(&actions[0], ActionKind::FileDelete { path } if path == &PathBuf::from("/sandbox/old.txt"))
        );
        assert!(
            matches!(&actions[1], ActionKind::FileWrite { path } if path == &PathBuf::from("/sandbox/new.txt"))
        );
    }

    #[test]
    fn file_rename_without_old_path_produces_one_action() {
        let event = FsEvent {
            timestamp: Utc::now(),
            path: PathBuf::from("/sandbox/appeared.txt"),
            kind: FsEventKind::FileRename { from: None },
            source: ObserverSource::FsEvents,
        };
        let actions = event.to_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], ActionKind::FileWrite { .. }));
    }
}
