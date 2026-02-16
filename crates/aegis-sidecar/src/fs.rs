/// AegisFuse: FUSE passthrough filesystem with policy enforcement and audit logging.
///
/// Intercepts file operations on a mounted directory, evaluates each against the
/// Cedar policy engine, logs verdicts to the audit ledger, and either passes through
/// to the real filesystem or denies with EACCES.
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, FUSE_ROOT_ID,
};

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_types::{Action, ActionKind, Decision};

/// Default TTL for file attribute caching.
const TTL: Duration = Duration::from_secs(1);

/// A FUSE filesystem that intercepts file operations, enforces Cedar policies,
/// and logs all access decisions to the audit ledger.
pub struct AegisFuse {
    policy: Arc<Mutex<PolicyEngine>>,
    store: Arc<Mutex<AuditStore>>,
    passthrough_dir: PathBuf,
    principal: String,
    inodes: HashMap<u64, PathBuf>,
    next_inode: u64,
}

impl AegisFuse {
    /// Create a new AegisFuse instance.
    ///
    /// - `policy`: shared policy engine for authorization decisions
    /// - `store`: shared audit store for logging verdicts
    /// - `passthrough_dir`: the real directory being protected
    /// - `principal`: agent name used as the Action principal
    pub fn new(
        policy: Arc<Mutex<PolicyEngine>>,
        store: Arc<Mutex<AuditStore>>,
        passthrough_dir: PathBuf,
        principal: String,
    ) -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(FUSE_ROOT_ID, passthrough_dir.clone());

        Self {
            policy,
            store,
            passthrough_dir,
            principal,
            inodes,
            next_inode: FUSE_ROOT_ID + 1,
        }
    }

    /// Evaluate the given action against the policy engine and log the verdict.
    ///
    /// Returns `Ok(())` if the action is allowed, or `Err(libc::EACCES)` if denied.
    fn check_and_log(&self, action: Action) -> Result<(), i32> {
        let verdict = match self.policy.lock() {
            Ok(engine) => engine.evaluate(&action),
            Err(e) => {
                tracing::error!(error = %e, "failed to acquire policy lock");
                return Err(libc::EIO);
            }
        };

        if let Ok(mut store) = self.store.lock() {
            if let Err(e) = store.append(&action, &verdict) {
                tracing::error!(error = %e, "failed to append audit entry");
            }
        } else {
            tracing::error!("failed to acquire audit store lock");
        }

        match verdict.decision {
            Decision::Allow => {
                tracing::debug!(
                    action_id = %action.id,
                    principal = %action.principal,
                    "action allowed"
                );
                Ok(())
            }
            Decision::Deny => {
                tracing::info!(
                    action_id = %action.id,
                    principal = %action.principal,
                    reason = %verdict.reason,
                    "action denied"
                );
                Err(libc::EACCES)
            }
        }
    }

    /// Return the passthrough directory path.
    pub fn passthrough_dir(&self) -> &PathBuf {
        &self.passthrough_dir
    }

    /// Resolve an inode to its real filesystem path.
    fn resolve_path(&self, ino: u64) -> Option<&PathBuf> {
        self.inodes.get(&ino)
    }

    /// Allocate a new inode for the given real path and return it.
    fn allocate_inode(&mut self, path: PathBuf) -> u64 {
        // Check if we already have an inode for this path.
        for (&ino, existing) in &self.inodes {
            if *existing == path {
                return ino;
            }
        }
        let ino = self.next_inode;
        self.next_inode += 1;
        self.inodes.insert(ino, path);
        ino
    }

    /// Stat a real filesystem path and return a fuser::FileAttr.
    fn stat_to_attr(ino: u64, metadata: &std::fs::Metadata) -> FileAttr {
        let kind = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };

        FileAttr {
            ino,
            size: metadata.size(),
            blocks: metadata.blocks(),
            atime: metadata
                .accessed()
                .unwrap_or(UNIX_EPOCH),
            mtime: metadata
                .modified()
                .unwrap_or(UNIX_EPOCH),
            ctime: SystemTime::UNIX_EPOCH
                + Duration::from_secs(metadata.ctime() as u64),
            crtime: metadata
                .created()
                .unwrap_or(UNIX_EPOCH),
            kind,
            perm: (metadata.mode() & 0o7777) as u16,
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: metadata.rdev() as u32,
            blksize: metadata.blksize() as u32,
            flags: 0,
        }
    }
}

impl Filesystem for AegisFuse {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_path = match self.resolve_path(parent) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let real_path = parent_path.join(name);

        let metadata = match std::fs::symlink_metadata(&real_path) {
            Ok(m) => m,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let ino = self.allocate_inode(real_path);
        let attr = Self::stat_to_attr(ino, &metadata);
        reply.entry(&TTL, &attr, 0);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let real_path = match self.resolve_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let metadata = match std::fs::symlink_metadata(&real_path) {
            Ok(m) => m,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let attr = Self::stat_to_attr(ino, &metadata);
        reply.attr(&TTL, &attr);
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let real_path = match self.resolve_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let is_write = (flags & libc::O_WRONLY != 0) || (flags & libc::O_RDWR != 0);

        let kind = if is_write {
            ActionKind::FileWrite {
                path: real_path.clone(),
            }
        } else {
            ActionKind::FileRead {
                path: real_path.clone(),
            }
        };

        let action = Action::new(&self.principal, kind);
        if let Err(errno) = self.check_and_log(action) {
            reply.error(errno);
            return;
        }

        // Open the real file and return its fd as the file handle.
        match std::fs::OpenOptions::new()
            .read(true)
            .write(is_write)
            .open(&real_path)
        {
            Ok(file) => {
                use std::os::unix::io::IntoRawFd;
                let fd = file.into_raw_fd();
                reply.opened(fd as u64, 0);
            }
            Err(e) => {
                tracing::error!(path = %real_path.display(), error = %e, "failed to open file");
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let real_path = match self.resolve_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let action = Action::new(
            &self.principal,
            ActionKind::FileRead {
                path: real_path,
            },
        );
        if let Err(errno) = self.check_and_log(action) {
            reply.error(errno);
            return;
        }

        // Use pread via the file handle if available, otherwise read from file.
        use std::io::Read;
        use std::os::unix::io::FromRawFd;

        // Safety: we re-create the File from the raw fd for reading, then forget it
        // so we don't close the fd (it will be closed in release).
        let mut file = unsafe { std::fs::File::from_raw_fd(fh as i32) };

        use std::io::Seek;
        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset as u64)) {
            std::mem::forget(file);
            reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            return;
        }

        let mut buf = vec![0u8; size as usize];
        match file.read(&mut buf) {
            Ok(n) => {
                std::mem::forget(file);
                reply.data(&buf[..n]);
            }
            Err(e) => {
                std::mem::forget(file);
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let real_path = match self.resolve_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let action = Action::new(
            &self.principal,
            ActionKind::FileWrite {
                path: real_path,
            },
        );
        if let Err(errno) = self.check_and_log(action) {
            reply.error(errno);
            return;
        }

        use std::io::Write;
        use std::os::unix::io::FromRawFd;

        let mut file = unsafe { std::fs::File::from_raw_fd(fh as i32) };

        use std::io::Seek;
        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset as u64)) {
            std::mem::forget(file);
            reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            return;
        }

        match file.write(data) {
            Ok(n) => {
                std::mem::forget(file);
                reply.written(n as u32);
            }
            Err(e) => {
                std::mem::forget(file);
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            }
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.resolve_path(parent) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let real_path = parent_path.join(name);

        let action = Action::new(
            &self.principal,
            ActionKind::FileWrite {
                path: real_path.clone(),
            },
        );
        if let Err(errno) = self.check_and_log(action) {
            reply.error(errno);
            return;
        }

        // Create the file.
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&real_path)
        {
            Ok(file) => {
                use std::os::unix::io::IntoRawFd;
                let fd = file.into_raw_fd();
                match std::fs::symlink_metadata(&real_path) {
                    Ok(metadata) => {
                        let ino = self.allocate_inode(real_path);
                        let attr = Self::stat_to_attr(ino, &metadata);
                        reply.created(&TTL, &attr, 0, fd as u64, 0);
                    }
                    Err(e) => {
                        // Close the fd since we can't complete the operation.
                        unsafe { libc::close(fd) };
                        reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                    }
                }
            }
            Err(e) => {
                tracing::error!(path = %real_path.display(), error = %e, "failed to create file");
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            }
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.resolve_path(parent) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let real_path = parent_path.join(name);

        let action = Action::new(
            &self.principal,
            ActionKind::FileDelete {
                path: real_path.clone(),
            },
        );
        if let Err(errno) = self.check_and_log(action) {
            reply.error(errno);
            return;
        }

        match std::fs::remove_file(&real_path) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_path = match self.resolve_path(parent) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let real_path = parent_path.join(name);

        let action = Action::new(
            &self.principal,
            ActionKind::DirCreate {
                path: real_path.clone(),
            },
        );
        if let Err(errno) = self.check_and_log(action) {
            reply.error(errno);
            return;
        }

        match std::fs::create_dir(&real_path) {
            Ok(()) => match std::fs::symlink_metadata(&real_path) {
                Ok(metadata) => {
                    let ino = self.allocate_inode(real_path);
                    let attr = Self::stat_to_attr(ino, &metadata);
                    reply.entry(&TTL, &attr, 0);
                }
                Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
            },
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.resolve_path(parent) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let real_path = parent_path.join(name);

        let action = Action::new(
            &self.principal,
            ActionKind::FileDelete {
                path: real_path.clone(),
            },
        );
        if let Err(errno) = self.check_and_log(action) {
            reply.error(errno);
            return;
        }

        match std::fs::remove_dir(&real_path) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let real_path = match self.resolve_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let action = Action::new(
            &self.principal,
            ActionKind::DirList {
                path: real_path.clone(),
            },
        );
        if let Err(errno) = self.check_and_log(action) {
            reply.error(errno);
            return;
        }

        let entries = match std::fs::read_dir(&real_path) {
            Ok(e) => e,
            Err(e) => {
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                return;
            }
        };

        // Collect entries: ".", "..", and real directory contents.
        let mut all_entries: Vec<(u64, FileType, String)> = Vec::new();

        // Add "." and ".."
        all_entries.push((ino, FileType::Directory, ".".to_string()));
        // For ".." use the parent inode. For root, use root itself.
        all_entries.push((ino, FileType::Directory, "..".to_string()));

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().to_string();
            let file_type = match entry.file_type() {
                Ok(ft) => {
                    if ft.is_dir() {
                        FileType::Directory
                    } else if ft.is_symlink() {
                        FileType::Symlink
                    } else {
                        FileType::RegularFile
                    }
                }
                Err(_) => FileType::RegularFile,
            };
            let child_path = real_path.join(&name);
            let child_ino = self.allocate_inode(child_path);
            all_entries.push((child_ino, file_type, name));
        }

        // Skip entries up to offset and fill reply buffer.
        for (i, (child_ino, file_type, name)) in all_entries.into_iter().enumerate() {
            let entry_offset = (i + 1) as i64;
            if entry_offset <= offset {
                continue;
            }
            if reply.add(child_ino, entry_offset, file_type, &name) {
                // Buffer full.
                break;
            }
        }

        reply.ok();
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let src_parent = match self.resolve_path(parent) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dst_parent = match self.resolve_path(newparent) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let src_path = src_parent.join(name);
        let dst_path = dst_parent.join(newname);

        // Rename requires write permission on the destination path.
        let action = Action::new(
            &self.principal,
            ActionKind::FileWrite {
                path: dst_path.clone(),
            },
        );
        if let Err(errno) = self.check_and_log(action) {
            reply.error(errno);
            return;
        }

        match std::fs::rename(&src_path, &dst_path) {
            Ok(()) => {
                // Update inode mapping for the source path to point to the new path.
                let src_ino = self
                    .inodes
                    .iter()
                    .find(|(_, p)| **p == src_path)
                    .map(|(&ino, _)| ino);
                if let Some(ino) = src_ino {
                    self.inodes.insert(ino, dst_path);
                }
                reply.ok();
            }
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_ledger::AuditStore;
    use aegis_policy::PolicyEngine;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn make_fuse(policy_str: &str) -> AegisFuse {
        let engine =
            PolicyEngine::from_policies(policy_str, None).expect("should create policy engine");
        let db_file = NamedTempFile::new().expect("should create temp file");
        let store = AuditStore::open(db_file.path()).expect("should open audit store");

        AegisFuse::new(
            Arc::new(Mutex::new(engine)),
            Arc::new(Mutex::new(store)),
            PathBuf::from("/tmp"),
            "test-agent".to_string(),
        )
    }

    #[test]
    fn check_and_log_allows_when_permitted() {
        let fuse = make_fuse(r#"permit(principal, action, resource);"#);
        let action = Action::new(
            "test-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let result = fuse.check_and_log(action);
        assert!(result.is_ok());
    }

    #[test]
    fn check_and_log_denies_when_forbidden() {
        let fuse = make_fuse(
            r#"forbid(principal, action, resource);"#,
        );
        let action = Action::new(
            "test-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let result = fuse.check_and_log(action);
        assert_eq!(result, Err(libc::EACCES));
    }

    #[test]
    fn inode_allocation_is_unique() {
        let mut fuse = make_fuse(r#"permit(principal, action, resource);"#);
        let ino1 = fuse.allocate_inode(PathBuf::from("/tmp/a"));
        let ino2 = fuse.allocate_inode(PathBuf::from("/tmp/b"));
        assert_ne!(ino1, ino2);
    }

    #[test]
    fn inode_allocation_is_idempotent() {
        let mut fuse = make_fuse(r#"permit(principal, action, resource);"#);
        let ino1 = fuse.allocate_inode(PathBuf::from("/tmp/same"));
        let ino2 = fuse.allocate_inode(PathBuf::from("/tmp/same"));
        assert_eq!(ino1, ino2);
    }

    #[test]
    fn root_inode_maps_to_passthrough_dir() {
        let fuse = make_fuse(r#"permit(principal, action, resource);"#);
        let root_path = fuse.resolve_path(FUSE_ROOT_ID);
        assert_eq!(root_path, Some(&PathBuf::from("/tmp")));
    }

    #[test]
    fn constructor_initializes_fields() {
        let fuse = make_fuse(r#"permit(principal, action, resource);"#);
        assert_eq!(fuse.principal, "test-agent");
        assert_eq!(fuse.passthrough_dir, PathBuf::from("/tmp"));
        assert!(fuse.inodes.contains_key(&FUSE_ROOT_ID));
    }
}
