//! Directory snapshot for pre/post diffing.
//!
//! FSEvents cannot reliably detect reads. Snapshot diffing provides a safety
//! net that catches any writes missed by the watcher (rapid create/delete
//! within the FSEvents coalescing window) and detects reads via atime changes.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::Utc;

use aegis_types::AegisError;

use crate::event::{FsEvent, FsEventKind, ObserverSource};

/// Metadata for a single file or directory entry.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub is_dir: bool,
    pub size: u64,
    pub modified: SystemTime,
    pub accessed: SystemTime,
}

/// A snapshot of a directory tree at a point in time.
#[derive(Debug)]
pub struct DirSnapshot {
    entries: HashMap<PathBuf, FileInfo>,
}

impl DirSnapshot {
    /// Capture a snapshot of the directory tree rooted at `base_dir`.
    ///
    /// Walks the tree recursively, collecting metadata for each file and
    /// directory. Symlinks are skipped (uses `symlink_metadata` to detect them).
    pub fn capture(base_dir: &Path) -> Result<Self, AegisError> {
        let mut entries = HashMap::new();
        walk_dir(base_dir, base_dir, &mut entries)?;
        Ok(Self { entries })
    }

    /// Diff this (pre) snapshot against a post snapshot.
    ///
    /// Returns filesystem events representing the changes:
    /// - Files in post but not pre -> FileCreate
    /// - Files in pre but not post -> FileDelete
    /// - Size or mtime changed -> FileModify
    /// - Only atime changed -> FileRead
    /// - Directories in post but not pre -> DirCreate
    /// - Directories in pre but not post -> DirDelete
    pub fn diff(&self, post: &DirSnapshot) -> Vec<FsEvent> {
        let mut events = Vec::new();
        let now = Utc::now();

        // Files/dirs in post but not pre -> created
        for (path, post_info) in &post.entries {
            match self.entries.get(path) {
                None => {
                    let kind = if post_info.is_dir {
                        FsEventKind::DirCreate
                    } else {
                        FsEventKind::FileCreate
                    };
                    events.push(FsEvent {
                        timestamp: now,
                        path: path.clone(),
                        kind,
                        source: ObserverSource::Snapshot,
                    });
                }
                Some(pre_info) if !pre_info.is_dir && !post_info.is_dir => {
                    // Check for modifications (size or mtime changed)
                    if pre_info.size != post_info.size || pre_info.modified != post_info.modified {
                        events.push(FsEvent {
                            timestamp: now,
                            path: path.clone(),
                            kind: FsEventKind::FileModify,
                            source: ObserverSource::Snapshot,
                        });
                    } else if pre_info.accessed != post_info.accessed {
                        // Only atime changed -> read (limited by macOS relatime)
                        events.push(FsEvent {
                            timestamp: now,
                            path: path.clone(),
                            kind: FsEventKind::FileRead,
                            source: ObserverSource::Snapshot,
                        });
                    }
                }
                _ => {}
            }
        }

        // Files/dirs in pre but not post -> deleted
        for (path, pre_info) in &self.entries {
            if !post.entries.contains_key(path) {
                let kind = if pre_info.is_dir {
                    FsEventKind::DirDelete
                } else {
                    FsEventKind::FileDelete
                };
                events.push(FsEvent {
                    timestamp: now,
                    path: path.clone(),
                    kind,
                    source: ObserverSource::Snapshot,
                });
            }
        }

        events
    }

    /// Number of entries in this snapshot.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Recursively walk a directory, collecting metadata.
fn walk_dir(
    current: &Path,
    base: &Path,
    entries: &mut HashMap<PathBuf, FileInfo>,
) -> Result<(), AegisError> {
    let read_dir = match fs::read_dir(current) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!(path = %current.display(), error = %e, "skipping unreadable directory");
            return Ok(());
        }
    };

    for entry in read_dir {
        let entry = entry.map_err(|e| {
            AegisError::FsError(format!("failed to read dir entry: {e}"))
        })?;

        let path = entry.path();

        // Use symlink_metadata to detect symlinks without following them
        let metadata = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable entry");
                continue;
            }
        };

        // Skip symlinks entirely
        if metadata.is_symlink() {
            continue;
        }

        let info = FileInfo {
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            accessed: metadata.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
        };

        // Store path relative to base for consistent comparison
        let rel_path = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
        entries.insert(rel_path, info);

        if metadata.is_dir() {
            walk_dir(&path, base, entries)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn empty_dir_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let snap = DirSnapshot::capture(dir.path()).unwrap();
        assert!(snap.is_empty());
    }

    #[test]
    fn snapshot_captures_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello").unwrap();
        fs::write(dir.path().join("b.txt"), "world").unwrap();

        let snap = DirSnapshot::capture(dir.path()).unwrap();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn snapshot_captures_subdirs() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub").join("file.txt"), "data").unwrap();

        let snap = DirSnapshot::capture(dir.path()).unwrap();
        // sub/ + sub/file.txt
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn diff_detects_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let pre = DirSnapshot::capture(dir.path()).unwrap();

        fs::write(dir.path().join("new.txt"), "created").unwrap();
        let post = DirSnapshot::capture(dir.path()).unwrap();

        let events = pre.diff(&post);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FsEventKind::FileCreate);
        assert_eq!(events[0].source, ObserverSource::Snapshot);
    }

    #[test]
    fn diff_detects_deleted_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("doomed.txt"), "bye").unwrap();
        let pre = DirSnapshot::capture(dir.path()).unwrap();

        fs::remove_file(dir.path().join("doomed.txt")).unwrap();
        let post = DirSnapshot::capture(dir.path()).unwrap();

        let events = pre.diff(&post);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FsEventKind::FileDelete);
    }

    #[test]
    fn diff_detects_modified_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("mod.txt"), "original").unwrap();
        let pre = DirSnapshot::capture(dir.path()).unwrap();

        fs::write(dir.path().join("mod.txt"), "modified content that is longer").unwrap();
        let post = DirSnapshot::capture(dir.path()).unwrap();

        let events = pre.diff(&post);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FsEventKind::FileModify);
    }

    #[test]
    fn diff_detects_new_directory() {
        let dir = tempfile::tempdir().unwrap();
        let pre = DirSnapshot::capture(dir.path()).unwrap();

        fs::create_dir(dir.path().join("newdir")).unwrap();
        let post = DirSnapshot::capture(dir.path()).unwrap();

        let events = pre.diff(&post);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FsEventKind::DirCreate);
    }

    #[test]
    fn diff_detects_deleted_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        let pre = DirSnapshot::capture(dir.path()).unwrap();

        fs::remove_dir(dir.path().join("sub")).unwrap();
        let post = DirSnapshot::capture(dir.path()).unwrap();

        let events = pre.diff(&post);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FsEventKind::DirDelete);
    }

    #[test]
    fn diff_no_changes_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("stable.txt"), "unchanged").unwrap();
        let pre = DirSnapshot::capture(dir.path()).unwrap();
        let post = DirSnapshot::capture(dir.path()).unwrap();

        let events = pre.diff(&post);
        assert!(events.is_empty());
    }

    #[test]
    fn symlinks_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("real.txt"), "content").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                dir.path().join("real.txt"),
                dir.path().join("link.txt"),
            )
            .unwrap();

            let snap = DirSnapshot::capture(dir.path()).unwrap();
            // Only real.txt, not link.txt
            assert_eq!(snap.len(), 1);
        }
    }
}
