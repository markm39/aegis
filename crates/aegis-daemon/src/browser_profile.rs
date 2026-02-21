//! Per-agent browser profile management with isolation, permissions, and lifecycle cleanup.
//!
//! Each agent gets an isolated browser profile directory under `{data_root}/{agent_id}/`.
//! Profiles are created with restrictive filesystem permissions (0700) and validated
//! to prevent cross-agent access, path traversal attacks, and symlink following.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Information about a managed browser profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
    /// Agent that owns this profile.
    pub agent_id: String,
    /// Filesystem path to the profile directory.
    pub profile_dir: PathBuf,
    /// When the profile was created.
    pub created_at: DateTime<Utc>,
    /// Chrome Preferences JSON written to the profile.
    pub preferences: serde_json::Value,
}

/// Manages per-agent browser profiles with isolation enforcement.
///
/// Each agent is assigned an isolated profile directory. The manager enforces
/// ownership, validates agent IDs against traversal attacks, refuses to follow
/// symlinks, and cleans up profiles when agents are removed.
pub struct BrowserProfileManager {
    /// Root directory under which all agent profile directories are created.
    data_root: PathBuf,
    /// Ownership tracking: agent_id -> ProfileInfo.
    profiles: HashMap<String, ProfileInfo>,
}

/// Regex-like validation for agent IDs: alphanumeric, dash, underscore only.
fn is_valid_agent_id(agent_id: &str) -> bool {
    if agent_id.is_empty() {
        return false;
    }
    agent_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Check whether a path contains any traversal components (..).
fn contains_traversal(path: &Path) -> bool {
    path.components().any(|c| matches!(c, std::path::Component::ParentDir))
}

/// Build the Chrome Preferences JSON for a profile.
fn build_preferences(downloads_dir: &Path) -> serde_json::Value {
    serde_json::json!({
        "browser": {
            "enabled_labs_experiments": []
        },
        "sync": {
            "has_setup_completed": false
        },
        "background_mode": {
            "enabled": false
        },
        "download": {
            "default_directory": downloads_dir.to_string_lossy(),
            "prompt_for_download": false
        }
    })
}

/// Set directory permissions to 0700 (owner-only) on Unix platforms.
#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, perms)
        .map_err(|e| format!("failed to set permissions on {}: {e}", path.display()))
}

/// On non-Unix platforms, permissions are a no-op (best-effort).
#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

impl BrowserProfileManager {
    /// Create a new profile manager rooted at `data_root`.
    ///
    /// The `data_root` directory is created if it does not exist, with 0700 permissions.
    pub fn new(data_root: PathBuf) -> Self {
        Self {
            data_root,
            profiles: HashMap::new(),
        }
    }

    /// Create an isolated browser profile for the given agent.
    ///
    /// - Validates agent_id (alphanumeric + dash/underscore, no traversal).
    /// - Creates `{data_root}/{agent_id}/` with 0700 permissions.
    /// - Creates `{data_root}/{agent_id}/downloads/` for downloads.
    /// - Writes Chrome Preferences JSON to `{data_root}/{agent_id}/Default/Preferences`.
    /// - Rejects creation if the target path is a symlink.
    /// - Returns error if a profile already exists for this agent.
    pub fn create_profile(&mut self, agent_id: &str) -> Result<ProfileInfo, String> {
        // Validate agent ID format.
        if !is_valid_agent_id(agent_id) {
            return Err(format!(
                "invalid agent_id '{}': must be non-empty and contain only alphanumeric, dash, or underscore characters",
                agent_id
            ));
        }

        // Reject if already tracked.
        if self.profiles.contains_key(agent_id) {
            return Err(format!(
                "profile already exists for agent '{}'",
                agent_id
            ));
        }

        let profile_dir = self.data_root.join(agent_id);

        // Reject if path contains traversal.
        if contains_traversal(&profile_dir) {
            return Err(format!(
                "profile path contains traversal components: {}",
                profile_dir.display()
            ));
        }

        // Reject if the target already exists as a symlink (do not follow).
        if profile_dir.symlink_metadata().is_ok() {
            let meta = profile_dir
                .symlink_metadata()
                .map_err(|e| format!("failed to read metadata for {}: {e}", profile_dir.display()))?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "profile path is a symlink (refusing to follow): {}",
                    profile_dir.display()
                ));
            }
        }

        // Ensure data_root exists with proper permissions.
        if !self.data_root.exists() {
            fs::create_dir_all(&self.data_root)
                .map_err(|e| format!("failed to create data_root {}: {e}", self.data_root.display()))?;
            set_owner_only_permissions(&self.data_root)?;
        }

        // Create profile directory.
        fs::create_dir_all(&profile_dir)
            .map_err(|e| format!("failed to create profile dir {}: {e}", profile_dir.display()))?;
        set_owner_only_permissions(&profile_dir)?;

        // Verify canonical path matches expected path to detect symlink races.
        let canonical = profile_dir
            .canonicalize()
            .map_err(|e| format!("failed to canonicalize {}: {e}", profile_dir.display()))?;
        let expected_canonical = self
            .data_root
            .canonicalize()
            .map_err(|e| format!("failed to canonicalize data_root: {e}"))?
            .join(agent_id);
        if canonical != expected_canonical {
            // Clean up the directory we just created if there is a mismatch.
            let _ = fs::remove_dir_all(&profile_dir);
            return Err(format!(
                "canonical path mismatch (possible symlink attack): expected {}, got {}",
                expected_canonical.display(),
                canonical.display()
            ));
        }

        // Create downloads directory.
        let downloads_dir = profile_dir.join("downloads");
        fs::create_dir_all(&downloads_dir)
            .map_err(|e| format!("failed to create downloads dir: {e}"))?;
        set_owner_only_permissions(&downloads_dir)?;

        // Write Chrome Preferences.
        let default_dir = profile_dir.join("Default");
        fs::create_dir_all(&default_dir)
            .map_err(|e| format!("failed to create Default dir: {e}"))?;
        set_owner_only_permissions(&default_dir)?;

        let preferences = build_preferences(&downloads_dir);
        let prefs_path = default_dir.join("Preferences");
        let prefs_json = serde_json::to_string_pretty(&preferences)
            .map_err(|e| format!("failed to serialize preferences: {e}"))?;
        fs::write(&prefs_path, prefs_json)
            .map_err(|e| format!("failed to write preferences to {}: {e}", prefs_path.display()))?;

        // Set permissions on the preferences file itself.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&prefs_path, perms)
                .map_err(|e| format!("failed to set permissions on preferences file: {e}"))?;
        }

        let info = ProfileInfo {
            agent_id: agent_id.to_string(),
            profile_dir,
            created_at: Utc::now(),
            preferences,
        };

        self.profiles.insert(agent_id.to_string(), info.clone());
        Ok(info)
    }

    /// Delete an agent's browser profile, removing all data.
    ///
    /// Recursively removes the profile directory and drops ownership tracking.
    /// Returns error if the profile does not exist or removal fails.
    pub fn delete_profile(&mut self, agent_id: &str) -> Result<(), String> {
        if !is_valid_agent_id(agent_id) {
            return Err(format!(
                "invalid agent_id '{}': must be non-empty and contain only alphanumeric, dash, or underscore characters",
                agent_id
            ));
        }

        let info = self.profiles.remove(agent_id).ok_or_else(|| {
            format!("no profile found for agent '{}'", agent_id)
        })?;

        // Verify the directory is still at the expected canonical path before removing.
        if info.profile_dir.exists() {
            if let Ok(canonical) = info.profile_dir.canonicalize() {
                if let Ok(root_canonical) = self.data_root.canonicalize() {
                    let expected = root_canonical.join(agent_id);
                    if canonical != expected {
                        return Err(format!(
                            "refusing to delete: canonical path mismatch (expected {}, got {})",
                            expected.display(),
                            canonical.display()
                        ));
                    }
                }
            }

            fs::remove_dir_all(&info.profile_dir)
                .map_err(|e| format!("failed to remove profile dir {}: {e}", info.profile_dir.display()))?;
        }

        Ok(())
    }

    /// Get profile info for an agent, if it exists.
    pub fn get_profile(&self, agent_id: &str) -> Option<&ProfileInfo> {
        self.profiles.get(agent_id)
    }

    /// List all tracked profiles.
    pub fn list_profiles(&self) -> Vec<&ProfileInfo> {
        self.profiles.values().collect()
    }

    /// Return the expected profile directory path for an agent.
    ///
    /// This does not check whether the directory or profile actually exists.
    pub fn profile_dir(&self, agent_id: &str) -> PathBuf {
        self.data_root.join(agent_id)
    }

    /// Check whether a profile directory is owned by the given agent.
    ///
    /// Uses canonical path comparison to prevent symlink-based spoofing.
    pub fn is_owned_by(&self, profile_dir: &Path, agent_id: &str) -> bool {
        match self.profiles.get(agent_id) {
            Some(info) => {
                // Compare canonical paths to defeat symlink tricks.
                let profile_canonical = match info.profile_dir.canonicalize() {
                    Ok(p) => p,
                    Err(_) => return false,
                };
                let query_canonical = match profile_dir.canonicalize() {
                    Ok(p) => p,
                    Err(_) => return false,
                };
                profile_canonical == query_canonical
            }
            None => false,
        }
    }

    /// Validate that an agent is allowed to access the given profile directory.
    ///
    /// Rejects:
    /// - Path traversal components (`..`)
    /// - Profile directories not matching the expected pattern for the agent
    /// - Symlink targets that resolve outside the expected path
    pub fn validate_profile_access(
        &self,
        agent_id: &str,
        profile_dir: &Path,
    ) -> Result<(), String> {
        // Validate agent ID.
        if !is_valid_agent_id(agent_id) {
            return Err(format!(
                "invalid agent_id '{}': must contain only alphanumeric, dash, or underscore characters",
                agent_id
            ));
        }

        // Reject traversal components.
        if contains_traversal(profile_dir) {
            return Err(format!(
                "profile path contains traversal components: {}",
                profile_dir.display()
            ));
        }

        // Check that the path matches the expected profile directory.
        let expected = self.profile_dir(agent_id);

        // If the directory exists, compare canonical paths (handles symlinks).
        if profile_dir.exists() {
            let canonical = profile_dir
                .canonicalize()
                .map_err(|e| format!("failed to canonicalize profile path: {e}"))?;
            let expected_canonical = if expected.exists() {
                expected
                    .canonicalize()
                    .map_err(|e| format!("failed to canonicalize expected path: {e}"))?
            } else {
                // Expected path doesn't exist yet, so the queried path can't be valid.
                return Err(format!(
                    "profile directory does not exist for agent '{}'",
                    agent_id
                ));
            };

            if canonical != expected_canonical {
                return Err(format!(
                    "access denied: profile path {} does not belong to agent '{}'",
                    profile_dir.display(),
                    agent_id
                ));
            }
        } else {
            // Directory doesn't exist; do a lexical check.
            if profile_dir != expected {
                return Err(format!(
                    "access denied: profile path {} does not match expected {} for agent '{}'",
                    profile_dir.display(),
                    expected.display(),
                    agent_id
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_profile_creation_sets_permissions() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let data_root = tmp.path().join("profiles");
        let mut mgr = BrowserProfileManager::new(data_root.clone());

        let info = mgr.create_profile("agent-1").expect("create_profile failed");
        assert_eq!(info.agent_id, "agent-1");
        assert!(info.profile_dir.exists());

        // Verify 0700 permissions on the profile directory.
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&info.profile_dir).expect("metadata failed");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "profile dir should have 0700 permissions, got {mode:o}");

        // Verify downloads dir exists with correct permissions.
        let downloads = info.profile_dir.join("downloads");
        assert!(downloads.exists());
        let dl_mode = fs::metadata(&downloads).expect("downloads metadata").permissions().mode() & 0o777;
        assert_eq!(dl_mode, 0o700);

        // Verify Default dir exists with correct permissions.
        let default_dir = info.profile_dir.join("Default");
        assert!(default_dir.exists());
        let def_mode = fs::metadata(&default_dir).expect("Default metadata").permissions().mode() & 0o777;
        assert_eq!(def_mode, 0o700);

        // Verify preferences file has 0600 permissions.
        let prefs_path = default_dir.join("Preferences");
        assert!(prefs_path.exists());
        let prefs_mode = fs::metadata(&prefs_path).expect("prefs metadata").permissions().mode() & 0o777;
        assert_eq!(prefs_mode, 0o600);
    }

    #[test]
    fn test_profile_isolation_between_agents() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let data_root = tmp.path().join("profiles");
        let mut mgr = BrowserProfileManager::new(data_root.clone());

        let info_a = mgr.create_profile("agent-a").expect("create agent-a");
        let info_b = mgr.create_profile("agent-b").expect("create agent-b");

        // agent-a can access its own profile.
        assert!(mgr.is_owned_by(&info_a.profile_dir, "agent-a"));
        // agent-a cannot access agent-b's profile.
        assert!(!mgr.is_owned_by(&info_b.profile_dir, "agent-a"));
        // agent-b can access its own profile.
        assert!(mgr.is_owned_by(&info_b.profile_dir, "agent-b"));
        // agent-b cannot access agent-a's profile.
        assert!(!mgr.is_owned_by(&info_a.profile_dir, "agent-b"));

        // validate_profile_access should reject cross-agent access.
        assert!(mgr.validate_profile_access("agent-a", &info_a.profile_dir).is_ok());
        assert!(mgr.validate_profile_access("agent-a", &info_b.profile_dir).is_err());
        assert!(mgr.validate_profile_access("agent-b", &info_b.profile_dir).is_ok());
        assert!(mgr.validate_profile_access("agent-b", &info_a.profile_dir).is_err());
    }

    #[test]
    fn test_profile_cleanup_on_remove() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let data_root = tmp.path().join("profiles");
        let mut mgr = BrowserProfileManager::new(data_root);

        let info = mgr.create_profile("cleanup-agent").expect("create");
        let dir = info.profile_dir.clone();
        assert!(dir.exists());

        mgr.delete_profile("cleanup-agent").expect("delete");
        assert!(!dir.exists(), "profile directory should be removed after delete");
        assert!(mgr.get_profile("cleanup-agent").is_none());
    }

    #[test]
    fn test_preferences_written_correctly() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let data_root = tmp.path().join("profiles");
        let mut mgr = BrowserProfileManager::new(data_root);

        let info = mgr.create_profile("prefs-agent").expect("create");
        let prefs_path = info.profile_dir.join("Default").join("Preferences");
        let content = fs::read_to_string(&prefs_path).expect("read preferences");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse JSON");

        // Verify sync is disabled.
        assert_eq!(parsed["sync"]["has_setup_completed"], false);
        // Verify background mode is disabled.
        assert_eq!(parsed["background_mode"]["enabled"], false);
        // Verify download directory is set.
        let expected_downloads = info.profile_dir.join("downloads");
        assert_eq!(
            parsed["download"]["default_directory"].as_str().unwrap(),
            expected_downloads.to_string_lossy().as_ref()
        );
        // Verify prompt_for_download is false.
        assert_eq!(parsed["download"]["prompt_for_download"], false);
        // Verify labs experiments is empty.
        assert_eq!(parsed["browser"]["enabled_labs_experiments"], serde_json::json!([]));
    }

    #[test]
    fn test_profile_reuse_rejected() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let data_root = tmp.path().join("profiles");
        let mut mgr = BrowserProfileManager::new(data_root);

        // agent-x creates a profile.
        mgr.create_profile("agent-x").expect("create agent-x");

        // Attempting to use agent-x's profile as agent-y is rejected.
        let agent_x_dir = mgr.profile_dir("agent-x");
        let result = mgr.validate_profile_access("agent-y", &agent_x_dir);
        assert!(result.is_err(), "agent-y should not be able to access agent-x's profile");

        // Creating a duplicate profile for agent-x is rejected.
        let result = mgr.create_profile("agent-x");
        assert!(result.is_err(), "duplicate profile creation should fail");
        assert!(
            result.unwrap_err().contains("already exists"),
            "error should mention profile already exists"
        );
    }

    #[test]
    fn security_test_agent_id_traversal_rejected() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let data_root = tmp.path().join("profiles");
        let mut mgr = BrowserProfileManager::new(data_root);

        // Path traversal in agent_id.
        let result = mgr.create_profile("../etc/passwd");
        assert!(result.is_err(), "traversal agent_id should be rejected");
        assert!(
            result.unwrap_err().contains("invalid agent_id"),
            "error should mention invalid agent_id"
        );

        // Slash in agent_id.
        let result = mgr.create_profile("agent/evil");
        assert!(result.is_err());

        // Dots alone.
        let result = mgr.create_profile("..");
        assert!(result.is_err());

        // Empty string.
        let result = mgr.create_profile("");
        assert!(result.is_err());

        // Spaces.
        let result = mgr.create_profile("agent name");
        assert!(result.is_err());

        // Valid IDs should succeed.
        assert!(mgr.create_profile("valid-agent_1").is_ok());
        assert!(mgr.create_profile("Agent2").is_ok());
        assert!(mgr.create_profile("a").is_ok());

        // Validate traversal in profile_dir path.
        let traversal_path = PathBuf::from("/tmp/../etc/passwd");
        let result = mgr.validate_profile_access("valid-agent_1", &traversal_path);
        assert!(result.is_err(), "traversal path should be rejected");
        assert!(
            result.unwrap_err().contains("traversal"),
            "error should mention traversal"
        );
    }

    #[cfg(unix)]
    #[test]
    fn security_test_symlink_not_followed() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let data_root = tmp.path().join("profiles");
        let mut mgr = BrowserProfileManager::new(data_root.clone());

        // Create a directory that a symlink will point to.
        let evil_target = tmp.path().join("evil-target");
        fs::create_dir_all(&evil_target).expect("create evil target");

        // Create a symlink at the expected profile path before the manager does.
        fs::create_dir_all(&data_root).expect("create data_root");
        let symlink_path = data_root.join("symlink-agent");
        std::os::unix::fs::symlink(&evil_target, &symlink_path)
            .expect("create symlink");

        // Attempting to create a profile where a symlink exists should fail.
        let result = mgr.create_profile("symlink-agent");
        assert!(result.is_err(), "symlink profile creation should be rejected");
        assert!(
            result.unwrap_err().contains("symlink"),
            "error should mention symlink"
        );

        // Ownership check should also fail for the symlinked path.
        assert!(!mgr.is_owned_by(&symlink_path, "symlink-agent"));
    }

    #[test]
    fn test_list_profiles() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let data_root = tmp.path().join("profiles");
        let mut mgr = BrowserProfileManager::new(data_root);

        assert!(mgr.list_profiles().is_empty());

        mgr.create_profile("list-a").expect("create a");
        mgr.create_profile("list-b").expect("create b");

        let profiles = mgr.list_profiles();
        assert_eq!(profiles.len(), 2);

        let ids: Vec<&str> = profiles.iter().map(|p| p.agent_id.as_str()).collect();
        assert!(ids.contains(&"list-a"));
        assert!(ids.contains(&"list-b"));
    }

    #[test]
    fn test_profile_dir_returns_expected_path() {
        let data_root = PathBuf::from("/tmp/aegis-test-profiles");
        let mgr = BrowserProfileManager::new(data_root.clone());
        assert_eq!(mgr.profile_dir("my-agent"), data_root.join("my-agent"));
    }

    #[test]
    fn test_delete_nonexistent_profile_fails() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let data_root = tmp.path().join("profiles");
        let mut mgr = BrowserProfileManager::new(data_root);

        let result = mgr.delete_profile("ghost-agent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no profile found"));
    }
}
