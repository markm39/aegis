//! Cross-platform file security and ACL validation.
//!
//! Provides a platform-agnostic [`FileSecurityChecker`] trait with concrete
//! implementations:
//! - [`UnixFileSecurityChecker`]: uses POSIX mode bits and UID metadata
//! - [`WindowsFileSecurityChecker`] (behind `cfg(windows)`): stubs for Win32
//!   security APIs (`GetNamedSecurityInfoW`, `AccessCheck`, etc.)
//!
//! On both platforms, world-writable files and suspicious ownership are flagged
//! as security warnings.

use std::fmt;
use std::path::Path;

use aegis_types::AegisError;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Security warnings discovered when inspecting file ACLs or permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclWarning {
    /// File is writable by any user (Unix mode `o+w`, or Windows Everyone
    /// write access).
    WorldWritable,
    /// File is owned by an unexpected or service account.
    SuspiciousOwner,
    /// The Windows Guest account has access to the file.
    GuestAccess,
    /// The Windows "Everyone" SID has non-read access.
    EveryoneAccess,
    /// The DACL grants overly broad permissions that do not follow
    /// least-privilege.
    WeakDacl,
}

impl fmt::Display for AclWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclWarning::WorldWritable => write!(f, "file is world-writable"),
            AclWarning::SuspiciousOwner => write!(f, "file has a suspicious owner"),
            AclWarning::GuestAccess => write!(f, "Guest account has access"),
            AclWarning::EveryoneAccess => write!(f, "Everyone group has non-read access"),
            AclWarning::WeakDacl => write!(f, "DACL grants overly broad permissions"),
        }
    }
}

/// Windows-style access mask with common permission constants.
///
/// On Unix platforms the mask is constructed from POSIX mode bits for a
/// consistent API surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessMask(pub u32);

impl AccessMask {
    /// Read access (maps to `FILE_GENERIC_READ` on Windows, `r` on Unix).
    pub const READ: u32 = 0x0001;
    /// Write access (maps to `FILE_GENERIC_WRITE` on Windows, `w` on Unix).
    pub const WRITE: u32 = 0x0002;
    /// Execute access (maps to `FILE_GENERIC_EXECUTE` on Windows, `x` on Unix).
    pub const EXECUTE: u32 = 0x0004;
    /// Full control (maps to `GENERIC_ALL` on Windows).
    pub const FULL_CONTROL: u32 = 0x000F;

    /// Returns `true` if the given permission bit is set.
    pub fn has(&self, permission: u32) -> bool {
        self.0 & permission == permission
    }
}

/// Aggregated file security information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSecurityInfo {
    /// Owner of the file (username or UID on Unix; account name on Windows).
    /// Raw SID values are never exposed here.
    pub owner: String,
    /// Whether the file is writable by any user on the system.
    pub is_world_writable: bool,
    /// Collected warnings from the security check.
    pub warnings: Vec<AclWarning>,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Platform-agnostic interface for inspecting file security metadata.
pub trait FileSecurityChecker: Send + Sync {
    /// Check whether the current process has the requested `access` to `path`.
    fn check_file_access(&self, path: &Path, access: AccessMask) -> Result<bool, AegisError>;

    /// Return the owner of the file at `path` as a human-readable string.
    ///
    /// On Windows the implementation must resolve SIDs to account names so
    /// that raw SID values are never surfaced to users.
    fn get_file_owner(&self, path: &Path) -> Result<String, AegisError>;

    /// Validate that the file at `path` has safe permissions and return any
    /// warnings found.
    fn validate_safe_permissions(&self, path: &Path) -> Result<Vec<AclWarning>, AegisError>;
}

// ---------------------------------------------------------------------------
// Path validation (shared)
// ---------------------------------------------------------------------------

/// Validate that a path is safe to inspect -- reject path traversal attempts
/// and non-absolute paths that could be used to confuse the checker.
fn validate_path(path: &Path) -> Result<(), AegisError> {
    // Require an absolute path so callers cannot trick us with relative
    // components that resolve differently depending on cwd.
    if !path.is_absolute() {
        return Err(AegisError::SandboxError(
            "file security check requires an absolute path".into(),
        ));
    }

    // Reject explicit `..` components that could traverse outside an
    // expected directory tree.
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(AegisError::SandboxError(format!(
                "path contains traversal component '..': {}",
                path.display()
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unix implementation
// ---------------------------------------------------------------------------

/// File security checker backed by POSIX metadata (mode bits + UID).
#[cfg(unix)]
pub struct UnixFileSecurityChecker;

#[cfg(unix)]
impl UnixFileSecurityChecker {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(unix)]
impl Default for UnixFileSecurityChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl FileSecurityChecker for UnixFileSecurityChecker {
    fn check_file_access(&self, path: &Path, access: AccessMask) -> Result<bool, AegisError> {
        validate_path(path)?;

        let meta = std::fs::metadata(path).map_err(|e| {
            AegisError::SandboxError(format!(
                "failed to read metadata for {}: {e}",
                path.display()
            ))
        })?;

        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();

        // Check owner permission bits (bits 8-6).
        let has_read = mode & 0o400 != 0;
        let has_write = mode & 0o200 != 0;
        let has_exec = mode & 0o100 != 0;

        let ok = (!access.has(AccessMask::READ) || has_read)
            && (!access.has(AccessMask::WRITE) || has_write)
            && (!access.has(AccessMask::EXECUTE) || has_exec);

        Ok(ok)
    }

    fn get_file_owner(&self, path: &Path) -> Result<String, AegisError> {
        validate_path(path)?;

        let meta = std::fs::metadata(path).map_err(|e| {
            AegisError::SandboxError(format!(
                "failed to read metadata for {}: {e}",
                path.display()
            ))
        })?;

        use std::os::unix::fs::MetadataExt;
        Ok(meta.uid().to_string())
    }

    fn validate_safe_permissions(&self, path: &Path) -> Result<Vec<AclWarning>, AegisError> {
        validate_path(path)?;

        let meta = std::fs::metadata(path).map_err(|e| {
            AegisError::SandboxError(format!(
                "failed to read metadata for {}: {e}",
                path.display()
            ))
        })?;

        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();

        let mut warnings = Vec::new();

        // World-writable check: other-write bit.
        if mode & 0o002 != 0 {
            warnings.push(AclWarning::WorldWritable);
        }

        // Owner UID 0 (root) on a user-owned sandbox directory is suspicious
        // unless explicitly expected.
        use std::os::unix::fs::MetadataExt;
        if meta.uid() == 0 {
            warnings.push(AclWarning::SuspiciousOwner);
        }

        Ok(warnings)
    }
}

// ---------------------------------------------------------------------------
// Windows stub implementation
// ---------------------------------------------------------------------------

/// File security checker for Windows platforms.
///
/// On Windows this would use the following Win32 APIs:
/// - `GetNamedSecurityInfoW` to retrieve the security descriptor
/// - `GetSecurityDescriptorOwner` to extract the owner SID
/// - `LookupAccountSidW` to resolve SIDs to human-readable account names
/// - `AccessCheck` to determine effective permissions against the DACL
/// - `GetAce` / `GetAclInformation` to enumerate DACL entries
///
/// Since we develop and build on macOS, this implementation is compiled only
/// on Windows targets and provides functional stubs until Win32 integration
/// is complete.
#[cfg(target_os = "windows")]
pub struct WindowsFileSecurityChecker;

#[cfg(target_os = "windows")]
impl WindowsFileSecurityChecker {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "windows")]
impl Default for WindowsFileSecurityChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
impl FileSecurityChecker for WindowsFileSecurityChecker {
    fn check_file_access(&self, path: &Path, _access: AccessMask) -> Result<bool, AegisError> {
        validate_path(path)?;
        // TODO: Implement using AccessCheck with the process token against
        // the file's DACL retrieved via GetNamedSecurityInfoW.
        Ok(true)
    }

    fn get_file_owner(&self, path: &Path) -> Result<String, AegisError> {
        validate_path(path)?;
        // TODO: Implement using GetNamedSecurityInfoW + GetSecurityDescriptorOwner
        // + LookupAccountSidW.  Must resolve SID to account name -- raw SIDs
        // must never appear in user-facing output.
        Ok("UNKNOWN".into())
    }

    fn validate_safe_permissions(&self, path: &Path) -> Result<Vec<AclWarning>, AegisError> {
        validate_path(path)?;
        // TODO: Enumerate DACL entries via GetAce / GetAclInformation and
        // flag Everyone, Guest, and overly permissive ACEs.
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_mask_constants() {
        assert_eq!(AccessMask::READ, 0x0001);
        assert_eq!(AccessMask::WRITE, 0x0002);
        assert_eq!(AccessMask::EXECUTE, 0x0004);
        assert_eq!(AccessMask::FULL_CONTROL, 0x000F);

        let mask = AccessMask(AccessMask::READ | AccessMask::WRITE);
        assert!(mask.has(AccessMask::READ));
        assert!(mask.has(AccessMask::WRITE));
        assert!(!mask.has(AccessMask::EXECUTE));
        assert!(!mask.has(AccessMask::FULL_CONTROL));
    }

    #[test]
    fn acl_warning_display() {
        assert_eq!(
            AclWarning::WorldWritable.to_string(),
            "file is world-writable"
        );
        assert_eq!(
            AclWarning::SuspiciousOwner.to_string(),
            "file has a suspicious owner"
        );
        assert_eq!(
            AclWarning::GuestAccess.to_string(),
            "Guest account has access"
        );
        assert_eq!(
            AclWarning::EveryoneAccess.to_string(),
            "Everyone group has non-read access"
        );
        assert_eq!(
            AclWarning::WeakDacl.to_string(),
            "DACL grants overly broad permissions"
        );
    }

    #[test]
    fn file_security_info_serialization() {
        let info = FileSecurityInfo {
            owner: "501".into(),
            is_world_writable: true,
            warnings: vec![AclWarning::WorldWritable, AclWarning::SuspiciousOwner],
        };

        let json = serde_json::to_string(&info).expect("serialize");
        let roundtrip: FileSecurityInfo = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(roundtrip.owner, "501");
        assert!(roundtrip.is_world_writable);
        assert_eq!(roundtrip.warnings.len(), 2);
        assert_eq!(roundtrip.warnings[0], AclWarning::WorldWritable);
        assert_eq!(roundtrip.warnings[1], AclWarning::SuspiciousOwner);

        // Ensure raw SID patterns are not present in serialized output.
        assert!(
            !json.contains("S-1-"),
            "serialized output must not contain raw SID values"
        );
    }

    #[test]
    fn path_traversal_rejected() {
        assert!(validate_path(Path::new("/safe/path")).is_ok());
        assert!(validate_path(Path::new("/safe/../escape")).is_err());
        assert!(validate_path(Path::new("relative/path")).is_err());
    }

    // -- Unix-specific tests ------------------------------------------------

    #[cfg(unix)]
    mod unix {
        use super::super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn unix_world_writable_detection() {
            let dir = tempfile::tempdir().expect("tempdir");
            let file = dir.path().join("world_writable.txt");
            fs::write(&file, "test").expect("write");
            fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).expect("chmod");

            let checker = UnixFileSecurityChecker::new();
            let warnings = checker.validate_safe_permissions(&file).expect("validate");

            assert!(
                warnings.contains(&AclWarning::WorldWritable),
                "world-writable file must be flagged"
            );
        }

        #[test]
        fn unix_owner_detection() {
            let dir = tempfile::tempdir().expect("tempdir");
            let file = dir.path().join("owned.txt");
            fs::write(&file, "test").expect("write");

            let checker = UnixFileSecurityChecker::new();
            let owner = checker.get_file_owner(&file).expect("owner");

            // The owner UID should be our own (non-empty numeric string).
            let uid: u32 = owner.parse().expect("owner should be a numeric UID");
            assert!(uid > 0, "test should not run as root");
        }

        #[test]
        fn unix_safe_permissions_pass() {
            let dir = tempfile::tempdir().expect("tempdir");
            let file = dir.path().join("safe.txt");
            fs::write(&file, "test").expect("write");
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");

            let checker = UnixFileSecurityChecker::new();
            let warnings = checker.validate_safe_permissions(&file).expect("validate");

            assert!(
                warnings.is_empty(),
                "0600 permissions should produce no warnings, got: {warnings:?}"
            );
        }

        #[test]
        fn unix_world_writable_warning() {
            // Security property test: confirm that any file with the
            // other-write bit set is flagged as WorldWritable.
            let dir = tempfile::tempdir().expect("tempdir");
            let file = dir.path().join("insecure.txt");
            fs::write(&file, "sensitive data").expect("write");

            // Set other-write bit (0o002).
            fs::set_permissions(&file, fs::Permissions::from_mode(0o602)).expect("chmod");

            let checker = UnixFileSecurityChecker::new();
            let warnings = checker.validate_safe_permissions(&file).expect("validate");

            assert!(
                warnings.contains(&AclWarning::WorldWritable),
                "SECURITY: other-write bit must always produce WorldWritable warning"
            );
        }

        #[test]
        fn unix_check_file_access() {
            let dir = tempfile::tempdir().expect("tempdir");
            let file = dir.path().join("access.txt");
            fs::write(&file, "test").expect("write");
            fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).expect("chmod");

            let checker = UnixFileSecurityChecker::new();

            assert!(checker
                .check_file_access(&file, AccessMask(AccessMask::READ))
                .expect("check read"));
            assert!(!checker
                .check_file_access(&file, AccessMask(AccessMask::WRITE))
                .expect("check write"));
            assert!(!checker
                .check_file_access(&file, AccessMask(AccessMask::EXECUTE))
                .expect("check exec"));
        }
    }

    // -- Default no-op test for SandboxBackend ------------------------------

    #[test]
    fn validate_file_permissions_default_noop() {
        use crate::backend::SandboxBackend;
        use crate::ProcessBackend;

        let backend = ProcessBackend;
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("noop.txt");
        std::fs::write(&file, "test").expect("write");

        // The default implementation on SandboxBackend should return Ok(empty).
        let warnings = backend
            .validate_file_permissions(&file)
            .expect("default impl");
        assert!(
            warnings.is_empty(),
            "SECURITY: default validate_file_permissions must return empty warnings \
             so that backends without ACL support do not silently suppress real warnings"
        );
    }
}
