//! Browser download management with size limits, file type validation, and progress tracking.
//!
//! This module provides a [`DownloadManager`] that tracks browser-initiated downloads,
//! enforces file extension blocklists, validates filenames for path safety, and
//! monitors download sizes in real time. It does **not** perform actual HTTP downloads --
//! that responsibility lies with the browser/CDP layer. This module is purely a
//! tracking and validation layer, designed for audit readiness and security enforcement.
//!
//! Security properties:
//! - Executable and script extensions are blocked by default.
//! - Filenames are sanitized: no path separators, `..` components, control characters,
//!   or null bytes.
//! - Download paths are canonicalized and verified to be within the configured directory.
//! - File size is checked during download progress, not just after completion.
//! - Concurrent download count is capped.
//! - No overwrite of existing files by default.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by download management operations.
#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("blocked file extension: {extension}")]
    BlockedExtension { extension: String },

    #[error("invalid filename: {reason}")]
    InvalidFilename { reason: String },

    #[error("download not found: {id}")]
    NotFound { id: String },

    #[error("size limit exceeded: received {received} bytes, limit is {limit}")]
    SizeLimitExceeded { received: u64, limit: u64 },

    #[error("concurrent download limit reached (max {max})")]
    ConcurrentLimitReached { max: usize },

    #[error("download path outside allowed directory: {path}")]
    PathTraversal { path: String },

    #[error("file already exists: {path}")]
    FileExists { path: String },

    #[error("invalid download state transition: {reason}")]
    InvalidState { reason: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// DownloadState
// ---------------------------------------------------------------------------

/// State of a tracked download.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadState {
    /// Registered but not yet started.
    Pending,
    /// Actively receiving bytes.
    InProgress,
    /// Successfully completed.
    Completed,
    /// Failed with an error description.
    Failed(String),
    /// Cancelled by the supervisor or user.
    Cancelled,
}

// ---------------------------------------------------------------------------
// DownloadInfo
// ---------------------------------------------------------------------------

/// Metadata for a single tracked download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadInfo {
    /// Unique identifier for this download.
    pub id: String,
    /// The source URL.
    pub url: String,
    /// The target filename (sanitized).
    pub filename: String,
    /// Bytes received so far.
    pub received_bytes: u64,
    /// Total size if known from Content-Length.
    pub total_bytes: Option<u64>,
    /// Current state.
    pub state: DownloadState,
    /// When this download was registered.
    pub started_at: DateTime<Utc>,
    /// When this download completed (success, failure, or cancellation).
    pub completed_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// DownloadConfig
// ---------------------------------------------------------------------------

/// Default maximum download size: 100 MB.
const DEFAULT_MAX_SIZE: u64 = 100 * 1024 * 1024;

/// Default maximum concurrent downloads.
const DEFAULT_MAX_CONCURRENT: usize = 5;

/// Configuration for the download manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadConfig {
    /// Maximum allowed download size in bytes.
    pub max_size_bytes: u64,
    /// File extensions that are unconditionally blocked (case-insensitive, without leading dot).
    pub blocked_extensions: Vec<String>,
    /// Directory where downloads are placed.
    pub download_dir: PathBuf,
    /// Whether to allow overwriting existing files (default: false).
    pub allow_overwrite: bool,
    /// Maximum number of concurrent (InProgress) downloads.
    pub max_concurrent_downloads: usize,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: DEFAULT_MAX_SIZE,
            blocked_extensions: default_blocked_extensions(),
            download_dir: std::env::temp_dir().join("aegis-downloads"),
            allow_overwrite: false,
            max_concurrent_downloads: DEFAULT_MAX_CONCURRENT,
        }
    }
}

/// Returns the default set of blocked file extensions (executables, scripts, libraries).
fn default_blocked_extensions() -> Vec<String> {
    [
        "exe", "bat", "cmd", "sh", "ps1", "vbs", "msi", "dll", "so", "dylib",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

// ---------------------------------------------------------------------------
// DownloadManager
// ---------------------------------------------------------------------------

/// Tracks browser downloads with security validation and progress monitoring.
///
/// All downloads must be registered before they can be tracked. The manager
/// enforces extension blocklists, size limits, concurrent download caps,
/// and filename safety. It does not perform I/O -- the browser layer is
/// responsible for actual file writing.
pub struct DownloadManager {
    config: DownloadConfig,
    downloads: HashMap<String, DownloadInfo>,
}

impl DownloadManager {
    /// Create a new download manager, ensuring the download directory exists.
    pub fn new(config: DownloadConfig) -> Result<Self, DownloadError> {
        if !config.download_dir.exists() {
            std::fs::create_dir_all(&config.download_dir)?;
        }
        Ok(Self {
            config,
            downloads: HashMap::new(),
        })
    }

    /// Register a new download. Validates the file extension and enforces the
    /// concurrent download limit before accepting.
    pub fn register_download(
        &mut self,
        id: &str,
        url: &str,
        filename: &str,
    ) -> Result<(), DownloadError> {
        // Enforce concurrent limit (count InProgress + Pending as "active slots").
        let active_count = self
            .downloads
            .values()
            .filter(|d| matches!(d.state, DownloadState::Pending | DownloadState::InProgress))
            .count();
        if active_count >= self.config.max_concurrent_downloads {
            return Err(DownloadError::ConcurrentLimitReached {
                max: self.config.max_concurrent_downloads,
            });
        }

        // Validate the filename.
        validate_extension(filename, &self.config.blocked_extensions)?;

        let info = DownloadInfo {
            id: id.to_string(),
            url: url.to_string(),
            filename: filename.to_string(),
            received_bytes: 0,
            total_bytes: None,
            state: DownloadState::Pending,
            started_at: Utc::now(),
            completed_at: None,
        };
        self.downloads.insert(id.to_string(), info);
        Ok(())
    }

    /// Update progress for an active download. Returns `false` if the size limit
    /// has been exceeded (the caller should cancel the download).
    ///
    /// Transitions a Pending download to InProgress on first progress update.
    pub fn update_progress(
        &mut self,
        id: &str,
        received_bytes: u64,
        total_bytes: Option<u64>,
    ) -> Result<bool, DownloadError> {
        let info = self
            .downloads
            .get_mut(id)
            .ok_or_else(|| DownloadError::NotFound { id: id.into() })?;

        match &info.state {
            DownloadState::Pending | DownloadState::InProgress => {}
            other => {
                return Err(DownloadError::InvalidState {
                    reason: format!(
                        "cannot update progress for download in state {:?}",
                        other
                    ),
                });
            }
        }

        info.state = DownloadState::InProgress;
        info.received_bytes = received_bytes;
        if total_bytes.is_some() {
            info.total_bytes = total_bytes;
        }

        // Check size limit.
        if received_bytes > self.config.max_size_bytes {
            return Ok(false);
        }

        // Also reject if the declared total exceeds the limit.
        if let Some(total) = info.total_bytes {
            if total > self.config.max_size_bytes {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Mark a download as completed.
    pub fn complete_download(&mut self, id: &str) -> Result<(), DownloadError> {
        let info = self
            .downloads
            .get_mut(id)
            .ok_or_else(|| DownloadError::NotFound { id: id.into() })?;

        match &info.state {
            DownloadState::Pending | DownloadState::InProgress => {}
            other => {
                return Err(DownloadError::InvalidState {
                    reason: format!("cannot complete download in state {:?}", other),
                });
            }
        }

        info.state = DownloadState::Completed;
        info.completed_at = Some(Utc::now());
        Ok(())
    }

    /// Mark a download as failed with an error description.
    pub fn fail_download(&mut self, id: &str, error: &str) -> Result<(), DownloadError> {
        let info = self
            .downloads
            .get_mut(id)
            .ok_or_else(|| DownloadError::NotFound { id: id.into() })?;

        info.state = DownloadState::Failed(error.to_string());
        info.completed_at = Some(Utc::now());
        Ok(())
    }

    /// Mark a download as cancelled.
    pub fn cancel_download(&mut self, id: &str) -> Result<(), DownloadError> {
        let info = self
            .downloads
            .get_mut(id)
            .ok_or_else(|| DownloadError::NotFound { id: id.into() })?;

        info.state = DownloadState::Cancelled;
        info.completed_at = Some(Utc::now());
        Ok(())
    }

    /// List all tracked downloads.
    pub fn list_downloads(&self) -> Vec<&DownloadInfo> {
        self.downloads.values().collect()
    }

    /// Get a download by ID.
    pub fn get_download(&self, id: &str) -> Option<&DownloadInfo> {
        self.downloads.get(id)
    }

    /// Return only in-progress downloads.
    pub fn active_downloads(&self) -> Vec<&DownloadInfo> {
        self.downloads
            .values()
            .filter(|d| d.state == DownloadState::InProgress)
            .collect()
    }

    /// Remove completed, failed, and cancelled entries older than `max_age_secs`.
    pub fn cleanup_completed(&mut self, max_age_secs: u64) {
        let cutoff = Utc::now()
            - chrono::Duration::seconds(
                i64::try_from(max_age_secs).unwrap_or(i64::MAX),
            );
        self.downloads.retain(|_, info| {
            match &info.state {
                DownloadState::Pending | DownloadState::InProgress => true,
                _ => {
                    // Keep entries that completed after the cutoff.
                    info.completed_at
                        .is_none_or(|completed| completed > cutoff)
                }
            }
        });
    }

    /// Return a reference to the current configuration.
    pub fn config(&self) -> &DownloadConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// File extension validation
// ---------------------------------------------------------------------------

/// Validate that a filename does not use a blocked extension.
///
/// Checks are case-insensitive. Double extensions (e.g., `.tar.gz`) are handled
/// by checking each suffix segment. Filenames with path separators or null bytes
/// are rejected outright.
pub fn validate_extension(filename: &str, blocked: &[String]) -> Result<(), DownloadError> {
    // Reject null bytes.
    if filename.contains('\0') {
        return Err(DownloadError::InvalidFilename {
            reason: "filename contains null byte".into(),
        });
    }

    // Reject path separators (no directory traversal in filenames).
    if filename.contains('/') || filename.contains('\\') {
        return Err(DownloadError::InvalidFilename {
            reason: "filename contains path separator".into(),
        });
    }

    // Reject empty filenames.
    if filename.is_empty() {
        return Err(DownloadError::InvalidFilename {
            reason: "filename is empty".into(),
        });
    }

    // Extract all extensions (handles double extensions like .tar.gz).
    // For "malware.tar.gz" we check both "gz" and "tar.gz".
    let lower = filename.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();

    // Check each suffix segment as a potential extension.
    // For parts ["malware", "tar", "gz"], check "gz" and "tar.gz".
    if parts.len() > 1 {
        for i in 1..parts.len() {
            let ext = parts[i..].join(".");
            // Also check the individual segment.
            let single_ext = parts[i];

            for blocked_ext in blocked {
                let blocked_lower = blocked_ext.to_ascii_lowercase();
                if ext == blocked_lower || single_ext == blocked_lower {
                    return Err(DownloadError::BlockedExtension {
                        extension: blocked_ext.clone(),
                    });
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Download path safety
// ---------------------------------------------------------------------------

/// Produce a safe download path within `download_dir` for the given filename.
///
/// Sanitizes the filename by:
/// - Removing path separators and `..` components
/// - Stripping control characters (bytes < 0x20)
/// - Stripping null bytes
/// - Falling back to "download" if nothing remains
///
/// Verifies the resulting canonical path is within `download_dir`.
/// If `allow_overwrite` is false and a file already exists, appends " (1)", " (2)", etc.
pub fn safe_download_path(
    download_dir: &Path,
    filename: &str,
    allow_overwrite: bool,
) -> Result<PathBuf, DownloadError> {
    let sanitized = sanitize_filename(filename);

    // Build the candidate path.
    let candidate = download_dir.join(&sanitized);

    // Canonicalize download_dir for comparison. If it does not exist yet, use
    // the path as-is (caller should have created it already).
    let canon_dir = download_dir
        .canonicalize()
        .unwrap_or_else(|_| download_dir.to_path_buf());

    // Canonicalize the candidate. Since the file might not exist yet, we
    // canonicalize the parent directory and append the filename.
    let parent = candidate
        .parent()
        .unwrap_or(download_dir)
        .canonicalize()
        .unwrap_or_else(|_| download_dir.to_path_buf());
    let canon_candidate = parent.join(&sanitized);

    // Verify the path is within the download directory.
    if !canon_candidate.starts_with(&canon_dir) {
        return Err(DownloadError::PathTraversal {
            path: canon_candidate.display().to_string(),
        });
    }

    if allow_overwrite {
        return Ok(canon_candidate);
    }

    // Handle collisions.
    if !canon_candidate.exists() {
        return Ok(canon_candidate);
    }

    // Split filename into stem and extension for collision suffixing.
    let stem = canon_candidate
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("download");
    let ext = canon_candidate
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();

    for i in 1..=1000 {
        let new_name = format!("{stem} ({i}){ext}");
        let new_path = canon_dir.join(new_name);
        if !new_path.exists() {
            return Ok(new_path);
        }
    }

    Err(DownloadError::FileExists {
        path: canon_candidate.display().to_string(),
    })
}

/// Sanitize a filename by removing dangerous characters and path components.
fn sanitize_filename(filename: &str) -> String {
    let mut name = filename.to_string();

    // Remove null bytes.
    name = name.replace('\0', "");

    // Remove path separators.
    name = name.replace('/', "");
    name = name.replace('\\', "");

    // Remove ".." components.
    while name.contains("..") {
        name = name.replace("..", "");
    }

    // Remove control characters (bytes < 0x20).
    name = name
        .chars()
        .filter(|c| *c as u32 >= 0x20)
        .collect();

    // Trim leading/trailing whitespace and dots.
    name = name.trim().trim_matches('.').to_string();

    // If nothing remains, use a default.
    if name.is_empty() {
        name = "download".to_string();
    }

    name
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_config(dir: &Path) -> DownloadConfig {
        DownloadConfig {
            download_dir: dir.to_path_buf(),
            ..Default::default()
        }
    }

    // -- Registration tests -------------------------------------------------

    #[test]
    fn test_register_download_succeeds() {
        let dir = std::env::temp_dir().join("aegis-dl-test-register");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();

        let result = mgr.register_download("dl-1", "https://example.com/file.pdf", "file.pdf");
        assert!(result.is_ok());

        let info = mgr.get_download("dl-1").unwrap();
        assert_eq!(info.url, "https://example.com/file.pdf");
        assert_eq!(info.filename, "file.pdf");
        assert_eq!(info.state, DownloadState::Pending);
        assert_eq!(info.received_bytes, 0);
        assert!(info.completed_at.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    // -- Extension blocking tests -------------------------------------------

    #[test]
    fn test_blocked_extension_rejected() {
        let dir = std::env::temp_dir().join("aegis-dl-test-blocked-ext");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();

        let blocked = ["exe", "bat", "cmd", "sh", "ps1", "vbs", "msi", "dll", "so", "dylib"];
        for ext in &blocked {
            let filename = format!("malware.{ext}");
            let result = mgr.register_download(
                &format!("dl-{ext}"),
                &format!("https://evil.com/{filename}"),
                &filename,
            );
            assert!(
                result.is_err(),
                "expected .{ext} to be blocked, but it was accepted"
            );
            match result.unwrap_err() {
                DownloadError::BlockedExtension { extension } => {
                    assert_eq!(extension.to_ascii_lowercase(), ext.to_ascii_lowercase());
                }
                other => panic!("expected BlockedExtension, got: {other:?}"),
            }
        }

        // Non-blocked extensions should succeed.
        assert!(mgr
            .register_download("dl-pdf", "https://example.com/doc.pdf", "doc.pdf")
            .is_ok());
        assert!(mgr
            .register_download("dl-txt", "https://example.com/readme.txt", "readme.txt")
            .is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    // -- Size limit tests ---------------------------------------------------

    #[test]
    fn test_size_limit_signals_cancel() {
        let dir = std::env::temp_dir().join("aegis-dl-test-size-limit");
        let _ = fs::remove_dir_all(&dir);
        let config = DownloadConfig {
            max_size_bytes: 1000,
            download_dir: dir.clone(),
            ..Default::default()
        };
        let mut mgr = DownloadManager::new(config).unwrap();
        mgr.register_download("dl-1", "https://example.com/big.zip", "big.zip")
            .unwrap();

        // Within limit.
        let ok = mgr.update_progress("dl-1", 500, Some(900)).unwrap();
        assert!(ok, "500 bytes should be within 1000 byte limit");

        // At limit.
        let ok = mgr.update_progress("dl-1", 1000, None).unwrap();
        assert!(ok, "1000 bytes should be within 1000 byte limit");

        // Exceeds limit.
        let ok = mgr.update_progress("dl-1", 1001, None).unwrap();
        assert!(!ok, "1001 bytes should exceed 1000 byte limit");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_total_bytes_exceeding_limit_signals_cancel() {
        let dir = std::env::temp_dir().join("aegis-dl-test-total-limit");
        let _ = fs::remove_dir_all(&dir);
        let config = DownloadConfig {
            max_size_bytes: 1000,
            download_dir: dir.clone(),
            ..Default::default()
        };
        let mut mgr = DownloadManager::new(config).unwrap();
        mgr.register_download("dl-1", "https://example.com/big.zip", "big.zip")
            .unwrap();

        // Small received but total declared exceeds limit.
        let ok = mgr.update_progress("dl-1", 10, Some(5000)).unwrap();
        assert!(!ok, "declared total of 5000 should exceed 1000 byte limit");

        let _ = fs::remove_dir_all(&dir);
    }

    // -- Progress tracking tests --------------------------------------------

    #[test]
    fn test_download_progress_tracking() {
        let dir = std::env::temp_dir().join("aegis-dl-test-progress");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();
        mgr.register_download("dl-1", "https://example.com/data.csv", "data.csv")
            .unwrap();

        // First update transitions to InProgress.
        mgr.update_progress("dl-1", 100, Some(500)).unwrap();
        let info = mgr.get_download("dl-1").unwrap();
        assert_eq!(info.state, DownloadState::InProgress);
        assert_eq!(info.received_bytes, 100);
        assert_eq!(info.total_bytes, Some(500));

        // Subsequent update.
        mgr.update_progress("dl-1", 300, None).unwrap();
        let info = mgr.get_download("dl-1").unwrap();
        assert_eq!(info.received_bytes, 300);
        assert_eq!(info.total_bytes, Some(500)); // Preserved from before.

        let _ = fs::remove_dir_all(&dir);
    }

    // -- Lifecycle tests ----------------------------------------------------

    #[test]
    fn test_download_lifecycle() {
        let dir = std::env::temp_dir().join("aegis-dl-test-lifecycle");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();

        // Pending.
        mgr.register_download("dl-1", "https://example.com/report.pdf", "report.pdf")
            .unwrap();
        assert_eq!(
            mgr.get_download("dl-1").unwrap().state,
            DownloadState::Pending
        );

        // InProgress.
        mgr.update_progress("dl-1", 50, Some(200)).unwrap();
        assert_eq!(
            mgr.get_download("dl-1").unwrap().state,
            DownloadState::InProgress
        );

        // Completed.
        mgr.complete_download("dl-1").unwrap();
        let info = mgr.get_download("dl-1").unwrap();
        assert_eq!(info.state, DownloadState::Completed);
        assert!(info.completed_at.is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_download_fail_lifecycle() {
        let dir = std::env::temp_dir().join("aegis-dl-test-fail");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();

        mgr.register_download("dl-1", "https://example.com/file.zip", "file.zip")
            .unwrap();
        mgr.update_progress("dl-1", 50, None).unwrap();
        mgr.fail_download("dl-1", "network timeout").unwrap();

        let info = mgr.get_download("dl-1").unwrap();
        assert!(matches!(info.state, DownloadState::Failed(ref msg) if msg == "network timeout"));
        assert!(info.completed_at.is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_download_cancel_lifecycle() {
        let dir = std::env::temp_dir().join("aegis-dl-test-cancel");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();

        mgr.register_download("dl-1", "https://example.com/file.zip", "file.zip")
            .unwrap();
        mgr.cancel_download("dl-1").unwrap();

        let info = mgr.get_download("dl-1").unwrap();
        assert_eq!(info.state, DownloadState::Cancelled);
        assert!(info.completed_at.is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    // -- Safe download path tests -------------------------------------------

    #[test]
    fn test_safe_download_path_sanitizes() {
        let dir = std::env::temp_dir().join("aegis-dl-test-sanitize");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Normal filename works.
        let path = safe_download_path(&dir, "report.pdf", false).unwrap();
        assert!(path.starts_with(dir.canonicalize().unwrap()));
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "report.pdf");

        // Control characters removed.
        let path = safe_download_path(&dir, "re\x01po\x02rt.pdf", false).unwrap();
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "report.pdf");

        // Path separators removed.
        let path = safe_download_path(&dir, "sub/dir/file.txt", false).unwrap();
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "subdirfile.txt");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_filename_collision_handling() {
        let dir = std::env::temp_dir().join("aegis-dl-test-collision");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create the initial file.
        fs::write(dir.join("report.pdf"), b"existing").unwrap();

        // Without overwrite, should get a numbered variant.
        let path = safe_download_path(&dir, "report.pdf", false).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "report (1).pdf");

        // Create that one too.
        fs::write(&path, b"second").unwrap();
        let path2 = safe_download_path(&dir, "report.pdf", false).unwrap();
        let name2 = path2.file_name().unwrap().to_str().unwrap();
        assert_eq!(name2, "report (2).pdf");

        // With overwrite allowed, returns original path.
        let path3 = safe_download_path(&dir, "report.pdf", true).unwrap();
        let name3 = path3.file_name().unwrap().to_str().unwrap();
        assert_eq!(name3, "report.pdf");

        let _ = fs::remove_dir_all(&dir);
    }

    // -- Security tests -----------------------------------------------------

    #[test]
    fn security_test_traversal_in_filename_rejected() {
        let blocked = default_blocked_extensions();

        // Direct traversal attempts in validate_extension.
        assert!(validate_extension("../../../etc/passwd", &blocked).is_err());
        assert!(validate_extension("..\\..\\windows\\system32\\config", &blocked).is_err());

        // Traversal in safe_download_path.
        let dir = std::env::temp_dir().join("aegis-dl-test-traversal");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // After sanitization, ".." is removed, so we just get a safe name.
        let path = safe_download_path(&dir, "../../../etc/passwd", false).unwrap();
        assert!(path.starts_with(dir.canonicalize().unwrap()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn security_test_null_bytes_rejected() {
        let blocked = default_blocked_extensions();

        // Null bytes in filename should be rejected by validate_extension.
        let result = validate_extension("evil\0.txt", &blocked);
        assert!(result.is_err());
        match result.unwrap_err() {
            DownloadError::InvalidFilename { reason } => {
                assert!(reason.contains("null"), "error should mention null byte");
            }
            other => panic!("expected InvalidFilename, got: {other:?}"),
        }
    }

    #[test]
    fn security_test_max_concurrent_downloads() {
        let dir = std::env::temp_dir().join("aegis-dl-test-concurrent");
        let _ = fs::remove_dir_all(&dir);
        let config = DownloadConfig {
            max_concurrent_downloads: 2,
            download_dir: dir.clone(),
            ..Default::default()
        };
        let mut mgr = DownloadManager::new(config).unwrap();

        mgr.register_download("dl-1", "https://example.com/a.pdf", "a.pdf")
            .unwrap();
        mgr.register_download("dl-2", "https://example.com/b.pdf", "b.pdf")
            .unwrap();

        // Third should be rejected.
        let result = mgr.register_download("dl-3", "https://example.com/c.pdf", "c.pdf");
        assert!(result.is_err());
        match result.unwrap_err() {
            DownloadError::ConcurrentLimitReached { max } => assert_eq!(max, 2),
            other => panic!("expected ConcurrentLimitReached, got: {other:?}"),
        }

        // Complete one and try again.
        mgr.complete_download("dl-1").unwrap();
        let result = mgr.register_download("dl-3", "https://example.com/c.pdf", "c.pdf");
        assert!(result.is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn security_test_double_extension_blocked() {
        let blocked = default_blocked_extensions();

        // .tar.sh should be blocked (the .sh extension).
        let result = validate_extension("archive.tar.sh", &blocked);
        assert!(result.is_err());
        match result.unwrap_err() {
            DownloadError::BlockedExtension { extension } => {
                assert_eq!(extension, "sh");
            }
            other => panic!("expected BlockedExtension, got: {other:?}"),
        }

        // .txt.exe should be blocked.
        let result = validate_extension("document.txt.exe", &blocked);
        assert!(result.is_err());
        match result.unwrap_err() {
            DownloadError::BlockedExtension { extension } => {
                assert_eq!(extension, "exe");
            }
            other => panic!("expected BlockedExtension, got: {other:?}"),
        }

        // .tar.gz should be fine (neither tar nor gz is blocked).
        assert!(validate_extension("archive.tar.gz", &blocked).is_ok());
    }

    #[test]
    fn test_case_insensitive_extension_blocking() {
        let blocked = default_blocked_extensions();

        // Uppercase .EXE.
        let result = validate_extension("malware.EXE", &blocked);
        assert!(result.is_err());

        // Mixed case .Bat.
        let result = validate_extension("script.Bat", &blocked);
        assert!(result.is_err());

        // Mixed case .DyLib.
        let result = validate_extension("library.DyLib", &blocked);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_downloads() {
        let dir = std::env::temp_dir().join("aegis-dl-test-list");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();

        mgr.register_download("dl-1", "https://a.com/a.pdf", "a.pdf")
            .unwrap();
        mgr.register_download("dl-2", "https://b.com/b.txt", "b.txt")
            .unwrap();

        let all = mgr.list_downloads();
        assert_eq!(all.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_active_downloads() {
        let dir = std::env::temp_dir().join("aegis-dl-test-active");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();

        mgr.register_download("dl-1", "https://a.com/a.pdf", "a.pdf")
            .unwrap();
        mgr.register_download("dl-2", "https://b.com/b.txt", "b.txt")
            .unwrap();

        // Neither is active yet (both Pending).
        assert_eq!(mgr.active_downloads().len(), 0);

        // Start one.
        mgr.update_progress("dl-1", 10, None).unwrap();
        assert_eq!(mgr.active_downloads().len(), 1);

        // Complete it.
        mgr.complete_download("dl-1").unwrap();
        assert_eq!(mgr.active_downloads().len(), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_completed() {
        let dir = std::env::temp_dir().join("aegis-dl-test-cleanup");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();

        mgr.register_download("dl-1", "https://a.com/a.pdf", "a.pdf")
            .unwrap();
        mgr.complete_download("dl-1").unwrap();

        mgr.register_download("dl-2", "https://b.com/b.pdf", "b.pdf")
            .unwrap();

        // Cleanup with 0-second max age removes all completed.
        mgr.cleanup_completed(0);

        assert!(mgr.get_download("dl-1").is_none(), "completed should be removed");
        assert!(mgr.get_download("dl-2").is_some(), "pending should remain");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_nonexistent_download() {
        let dir = std::env::temp_dir().join("aegis-dl-test-nonexistent");
        let _ = fs::remove_dir_all(&dir);
        let mgr = DownloadManager::new(test_config(&dir)).unwrap();
        assert!(mgr.get_download("does-not-exist").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_update_progress_nonexistent_fails() {
        let dir = std::env::temp_dir().join("aegis-dl-test-update-nonexistent");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();
        let result = mgr.update_progress("nope", 100, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DownloadError::NotFound { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_complete_nonexistent_fails() {
        let dir = std::env::temp_dir().join("aegis-dl-test-complete-nonexistent");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();
        let result = mgr.complete_download("nope");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DownloadError::NotFound { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cannot_complete_already_completed() {
        let dir = std::env::temp_dir().join("aegis-dl-test-double-complete");
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = DownloadManager::new(test_config(&dir)).unwrap();

        mgr.register_download("dl-1", "https://a.com/a.pdf", "a.pdf")
            .unwrap();
        mgr.complete_download("dl-1").unwrap();

        let result = mgr.complete_download("dl-1");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DownloadError::InvalidState { .. }
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sanitize_filename_empty_fallback() {
        // Completely empty.
        assert_eq!(sanitize_filename(""), "download");
        // Only dots.
        assert_eq!(sanitize_filename("..."), "download");
        // Only control chars.
        assert_eq!(sanitize_filename("\x01\x02\x03"), "download");
    }

    #[test]
    fn test_validate_extension_empty_filename() {
        let blocked = default_blocked_extensions();
        let result = validate_extension("", &blocked);
        assert!(result.is_err());
        match result.unwrap_err() {
            DownloadError::InvalidFilename { reason } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("expected InvalidFilename, got: {other:?}"),
        }
    }
}
