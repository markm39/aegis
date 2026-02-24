//! File-based memory scoped to individual daemon sessions.
//!
//! Each session gets an isolated directory under the configured base path
//! (default `~/.aegis/sessions/{session_id}/files/`). Files are stored with
//! SHA-256 integrity hashes and size enforcement. Cross-session sync copies
//! files between session directories with full validation.
//!
//! # Security
//!
//! - Filenames are validated against path traversal (`..`, `/`, `\`, null bytes,
//!   control characters).
//! - Session IDs are validated identically.
//! - Symlinks inside session directories are never followed.
//! - File size limits are enforced before any write (fail-closed).
//! - SHA-256 hashes are computed for every stored file.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Metadata for a stored session file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMetadata {
    /// Original filename (no path components).
    pub filename: String,
    /// File size in bytes.
    pub size: u64,
    /// SHA-256 hex digest of the file contents.
    pub sha256: String,
    /// ISO 8601 timestamp when the file was stored.
    pub created_at: String,
}

/// Configuration for session file storage.
#[derive(Debug, Clone)]
pub struct SessionFilesConfig {
    /// Whether session file storage is enabled.
    pub enabled: bool,
    /// Maximum size of a single file in bytes.
    pub max_file_size_bytes: u64,
    /// Maximum total size of all files in a session directory.
    pub max_total_size_bytes: u64,
    /// Base directory for session file storage.
    pub base_dir: PathBuf,
}

impl Default for SessionFilesConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        Self {
            enabled: false,
            max_file_size_bytes: 10_485_760,   // 10 MB
            max_total_size_bytes: 104_857_600, // 100 MB
            base_dir: PathBuf::from(home).join(".aegis").join("sessions"),
        }
    }
}

/// File-scoped storage for a single session.
///
/// All I/O operations validate filenames against path traversal and enforce
/// configurable size limits. Files are stored flat (no subdirectories) inside
/// `{base_dir}/{session_id}/files/`.
pub struct SessionFileStore {
    /// Directory for this session's files.
    session_dir: PathBuf,
    /// Session identifier (validated at construction).
    session_id: String,
    /// Maximum size of a single file in bytes.
    max_file_size_bytes: u64,
    /// Maximum total size of all files in the session directory.
    max_total_size_bytes: u64,
    /// Base directory (for cross-session sync source resolution).
    base_dir: PathBuf,
}

impl SessionFileStore {
    /// Create a new session file store.
    ///
    /// Validates the session ID and creates the storage directory if it does
    /// not already exist.
    pub fn new(config: &SessionFilesConfig, session_id: &str) -> Result<Self, String> {
        validate_name(session_id, "session ID")?;

        let session_dir = config.base_dir.join(session_id).join("files");
        std::fs::create_dir_all(&session_dir)
            .map_err(|e| format!("failed to create session dir: {e}"))?;

        Ok(Self {
            session_dir,
            session_id: session_id.to_string(),
            max_file_size_bytes: config.max_file_size_bytes,
            max_total_size_bytes: config.max_total_size_bytes,
            base_dir: config.base_dir.clone(),
        })
    }

    /// Store a file in the session directory.
    ///
    /// Validates the filename, enforces size limits (per-file and total), writes
    /// the file atomically (tmp + rename), and returns metadata including the
    /// SHA-256 digest.
    pub fn store(&self, name: &str, bytes: &[u8]) -> Result<FileMetadata, String> {
        validate_name(name, "filename")?;

        let size = bytes.len() as u64;
        if size > self.max_file_size_bytes {
            return Err(format!(
                "file size {size} exceeds maximum allowed {}",
                self.max_file_size_bytes
            ));
        }

        // Compute current total size of the session directory, excluding
        // any existing file with the same name (since we'll overwrite it).
        let current_total = self.total_size_excluding(name)?;
        if current_total + size > self.max_total_size_bytes {
            return Err(format!(
                "total directory size would exceed maximum allowed {} bytes",
                self.max_total_size_bytes
            ));
        }

        let target = self.session_dir.join(name);

        // Reject if target resolves to a symlink (no symlink following).
        reject_symlink(&target)?;

        // Compute SHA-256 hash.
        let sha256 = compute_sha256(bytes);

        // Atomic write: tmp file then rename.
        let tmp_name = format!(".{name}.tmp");
        let tmp_path = self.session_dir.join(&tmp_name);
        std::fs::write(&tmp_path, bytes).map_err(|e| format!("failed to write tmp file: {e}"))?;
        std::fs::rename(&tmp_path, &target)
            .map_err(|e| format!("failed to rename tmp to target: {e}"))?;

        let created_at = chrono::Utc::now().to_rfc3339();

        Ok(FileMetadata {
            filename: name.to_string(),
            size,
            sha256,
            created_at,
        })
    }

    /// Load a file's contents from the session directory.
    ///
    /// Returns `Ok(None)` if the file does not exist.
    pub fn load(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        validate_name(name, "filename")?;

        let path = self.session_dir.join(name);
        reject_symlink(&path)?;

        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("failed to read file: {e}")),
        }
    }

    /// List all files in the session directory with their metadata.
    pub fn list(&self) -> Result<Vec<FileMetadata>, String> {
        let entries = std::fs::read_dir(&self.session_dir)
            .map_err(|e| format!("failed to read session dir: {e}"))?;

        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("failed to read dir entry: {e}"))?;
            let path = entry.path();

            // Skip non-files, hidden files (tmp files), and symlinks.
            if !path.is_file() || is_symlink(&path) {
                continue;
            }
            let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if fname.starts_with('.') {
                continue;
            }

            let bytes =
                std::fs::read(&path).map_err(|e| format!("failed to read file {fname}: {e}"))?;
            let metadata = std::fs::metadata(&path)
                .map_err(|e| format!("failed to stat file {fname}: {e}"))?;

            let sha256 = compute_sha256(&bytes);
            let created_at = metadata
                .created()
                .or_else(|_| metadata.modified())
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                })
                .unwrap_or_else(|_| chrono::Utc::now().to_rfc3339());

            files.push(FileMetadata {
                filename: fname.to_string(),
                size: bytes.len() as u64,
                sha256,
                created_at,
            });
        }

        files.sort_by(|a, b| a.filename.cmp(&b.filename));
        Ok(files)
    }

    /// Delete a file from the session directory.
    ///
    /// Returns `true` if the file existed and was removed, `false` if it did
    /// not exist.
    pub fn delete(&self, name: &str) -> Result<bool, String> {
        validate_name(name, "filename")?;

        let path = self.session_dir.join(name);
        reject_symlink(&path)?;

        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("failed to delete file: {e}")),
        }
    }

    /// Copy files from another session's directory into this one.
    ///
    /// Validates the source session ID against path traversal and checks that
    /// each requested file exists in the source. Returns metadata for all
    /// successfully synced files.
    pub fn sync_from(
        &self,
        source_session_id: &str,
        filenames: &[String],
    ) -> Result<Vec<FileMetadata>, String> {
        validate_name(source_session_id, "source session ID")?;

        if source_session_id == self.session_id {
            return Err("cannot sync from the same session".into());
        }

        let source_dir = self.base_dir.join(source_session_id).join("files");
        if !source_dir.is_dir() {
            return Err(format!(
                "source session directory does not exist: {source_session_id}"
            ));
        }

        let mut results = Vec::new();
        for name in filenames {
            validate_name(name, "filename")?;

            let source_path = source_dir.join(name);
            reject_symlink(&source_path)?;

            let bytes = std::fs::read(&source_path)
                .map_err(|e| format!("failed to read source file {name}: {e}"))?;

            let metadata = self.store(name, &bytes)?;
            results.push(metadata);
        }

        Ok(results)
    }

    /// Compute the total size of all files in the session directory,
    /// excluding one specific filename (for overwrite calculations).
    fn total_size_excluding(&self, exclude: &str) -> Result<u64, String> {
        let entries = std::fs::read_dir(&self.session_dir)
            .map_err(|e| format!("failed to read session dir: {e}"))?;

        let mut total: u64 = 0;
        for entry in entries {
            let entry = entry.map_err(|e| format!("failed to read dir entry: {e}"))?;
            let path = entry.path();

            if !path.is_file() || is_symlink(&path) {
                continue;
            }
            let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // Skip hidden/tmp files and the file being overwritten.
            if fname.starts_with('.') || fname == exclude {
                continue;
            }

            let meta =
                std::fs::metadata(&path).map_err(|e| format!("failed to stat {fname}: {e}"))?;
            total = total.saturating_add(meta.len());
        }

        Ok(total)
    }
}

/// Validate a name (filename or session ID) against path traversal and
/// dangerous characters.
///
/// Rejects names containing:
/// - `..` (parent directory traversal)
/// - `/` or `\` (path separators)
/// - Null bytes
/// - Control characters (ASCII < 0x20)
/// - Empty strings
/// - Names longer than 255 bytes
fn validate_name(name: &str, label: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    if name.len() > 255 {
        return Err(format!("{label} exceeds 255 bytes"));
    }
    if name.contains("..") {
        return Err(format!("{label} must not contain '..' (path traversal)"));
    }
    if name.contains('/') {
        return Err(format!("{label} must not contain '/' (path separator)"));
    }
    if name.contains('\\') {
        return Err(format!("{label} must not contain '\\' (path separator)"));
    }
    if name.bytes().any(|b| b == 0) {
        return Err(format!("{label} must not contain null bytes"));
    }
    if name.bytes().any(|b| b < 0x20) {
        return Err(format!("{label} must not contain control characters"));
    }
    Ok(())
}

/// Reject a path if it is a symlink.
fn reject_symlink(path: &Path) -> Result<(), String> {
    // Use symlink_metadata to check the link itself, not its target.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "refusing to operate on symlink: {}",
            path.display()
        )),
        _ => Ok(()),
    }
}

/// Check if a path is a symlink (without erroring if it doesn't exist).
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Compute the SHA-256 hex digest of a byte slice.
fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(base_dir: &Path) -> SessionFilesConfig {
        SessionFilesConfig {
            enabled: true,
            max_file_size_bytes: 10_485_760,
            max_total_size_bytes: 104_857_600,
            base_dir: base_dir.to_path_buf(),
        }
    }

    #[test]
    fn test_store_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "session-abc").unwrap();

        let data = b"hello world";
        let meta = store.store("test.txt", data).unwrap();
        assert_eq!(meta.filename, "test.txt");
        assert_eq!(meta.size, 11);

        let loaded = store.load("test.txt").unwrap();
        assert_eq!(loaded, Some(data.to_vec()));
    }

    #[test]
    fn test_path_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "session-1").unwrap();

        let result = store.store("../escape.txt", b"data");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(".."));

        let result = store.store("sub/dir.txt", b"data");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("/"));

        let result = store.load("../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_file_size_limit_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config(tmp.path());
        config.max_file_size_bytes = 100; // 100 bytes max

        let store = SessionFileStore::new(&config, "session-limit").unwrap();

        // Under limit: should succeed.
        let small = vec![0u8; 50];
        assert!(store.store("small.bin", &small).is_ok());

        // Over limit: should fail.
        let big = vec![0u8; 101];
        let result = store.store("big.bin", &big);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn test_cross_session_sync() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());

        // Set up source session with a file.
        let source = SessionFileStore::new(&config, "source-session").unwrap();
        source.store("shared.txt", b"shared data").unwrap();
        source.store("other.txt", b"other data").unwrap();

        // Create target session and sync.
        let target = SessionFileStore::new(&config, "target-session").unwrap();
        let synced = target
            .sync_from("source-session", &["shared.txt".to_string()])
            .unwrap();

        assert_eq!(synced.len(), 1);
        assert_eq!(synced[0].filename, "shared.txt");
        assert_eq!(synced[0].size, 11);

        // Verify the file is accessible from the target.
        let loaded = target.load("shared.txt").unwrap();
        assert_eq!(loaded, Some(b"shared data".to_vec()));

        // Verify the file that was NOT synced is absent.
        let not_synced = target.load("other.txt").unwrap();
        assert!(not_synced.is_none());
    }

    #[test]
    fn test_session_file_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "meta-session").unwrap();

        let data = b"metadata test content";
        let meta = store.store("meta.txt", data).unwrap();

        assert_eq!(meta.filename, "meta.txt");
        assert_eq!(meta.size, data.len() as u64);

        // Verify SHA-256 independently.
        let expected_hash = compute_sha256(data);
        assert_eq!(meta.sha256, expected_hash);
        assert!(!meta.sha256.is_empty());
        assert_eq!(meta.sha256.len(), 64); // 256 bits = 64 hex chars

        // Verify created_at is a valid RFC 3339 timestamp.
        assert!(chrono::DateTime::parse_from_rfc3339(&meta.created_at).is_ok());
    }

    #[test]
    fn test_list_returns_all_files() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "list-session").unwrap();

        store.store("alpha.txt", b"aaa").unwrap();
        store.store("beta.bin", b"bbb").unwrap();
        store.store("gamma.json", b"{}").unwrap();

        let files = store.list().unwrap();
        assert_eq!(files.len(), 3);

        let names: Vec<&str> = files.iter().map(|f| f.filename.as_str()).collect();
        assert_eq!(names, vec!["alpha.txt", "beta.bin", "gamma.json"]);
    }

    #[test]
    fn test_delete_removes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "del-session").unwrap();

        store.store("doomed.txt", b"goodbye").unwrap();
        assert!(store.load("doomed.txt").unwrap().is_some());

        let removed = store.delete("doomed.txt").unwrap();
        assert!(removed);

        // File should be gone.
        assert!(store.load("doomed.txt").unwrap().is_none());

        // Deleting again should return false.
        let removed_again = store.delete("doomed.txt").unwrap();
        assert!(!removed_again);
    }

    #[test]
    fn test_null_bytes_in_filename_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "null-session").unwrap();

        let result = store.store("bad\0file.txt", b"data");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("null bytes"));

        let result = store.load("evil\0name");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("null bytes"));
    }

    #[test]
    fn test_backslash_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "bs-session").unwrap();

        let result = store.store("..\\escape.txt", b"data");
        assert!(result.is_err());
        // Should be caught by either ".." or "\\" check.
        let err = result.unwrap_err();
        assert!(err.contains("..") || err.contains("\\"));

        let result = store.store("sub\\dir.txt", b"data");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("\\"));
    }

    #[test]
    fn test_session_id_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());

        let result = SessionFileStore::new(&config, "../escape");
        assert!(result.is_err());

        let result = SessionFileStore::new(&config, "bad/id");
        assert!(result.is_err());

        let result = SessionFileStore::new(&config, "bad\\id");
        assert!(result.is_err());

        let result = SessionFileStore::new(&config, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_total_size_limit_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config(tmp.path());
        config.max_total_size_bytes = 200;
        config.max_file_size_bytes = 200;

        let store = SessionFileStore::new(&config, "total-limit").unwrap();

        // First file: 100 bytes, should succeed.
        store.store("a.bin", &vec![0u8; 100]).unwrap();

        // Second file: 100 bytes, total = 200, should succeed.
        store.store("b.bin", &vec![0u8; 100]).unwrap();

        // Third file: 1 byte, total would be 201, should fail.
        let result = store.store("c.bin", &vec![0u8; 1]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("total directory size"));
    }

    #[test]
    fn test_control_chars_in_filename_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "ctrl-session").unwrap();

        let result = store.store("bad\x01file.txt", b"data");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("control characters"));

        let result = store.store("tab\there.txt", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_from_same_session_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "self-session").unwrap();
        store.store("file.txt", b"data").unwrap();

        let result = store.sync_from("self-session", &["file.txt".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("same session"));
    }

    #[test]
    fn test_overwrite_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "overwrite-session").unwrap();

        store.store("file.txt", b"version 1").unwrap();
        let meta2 = store.store("file.txt", b"version 2").unwrap();

        assert_eq!(meta2.size, 9);
        let loaded = store.load("file.txt").unwrap().unwrap();
        assert_eq!(loaded, b"version 2");
    }

    #[test]
    fn test_load_nonexistent_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let store = SessionFileStore::new(&config, "empty-session").unwrap();

        let result = store.load("does_not_exist.txt").unwrap();
        assert!(result.is_none());
    }
}
