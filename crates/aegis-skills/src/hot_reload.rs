//! Skill hot-reload -- watches skill directories for changes and reloads skills.
//!
//! Provides:
//! - [`SkillWatcher`] -- monitors directories for skill file changes (polling-based)
//! - [`SkillChange`] -- describes what changed (added, modified, removed)
//! - [`HotReloader`] -- applies changes to the skill registry
//! - [`SkillWatcherConfig`] -- configuration for the watcher

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::dispatch::CommandRouter;
use crate::lifecycle::{SkillInstance, SkillState};
use crate::manifest::{parse_manifest_file, validate_manifest};
use crate::registry::SkillRegistry;
use crate::scanner::SkillScanner;

/// Configuration for the skill watcher.
#[derive(Debug, Clone)]
pub struct SkillWatcherConfig {
    /// Whether hot-reload is enabled.
    pub enabled: bool,
    /// Poll interval in seconds.
    pub poll_interval_secs: u64,
    /// Directories to watch for skill changes.
    pub watch_paths: Vec<PathBuf>,
    /// Whether to run the security scanner on reloaded skills.
    pub auto_scan: bool,
}

impl Default for SkillWatcherConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: 5,
            watch_paths: Vec::new(),
            auto_scan: true,
        }
    }
}

/// Describes a change detected in a skill directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillChange {
    /// A new skill directory appeared.
    Added(PathBuf),
    /// An existing skill's manifest or code changed.
    Modified(PathBuf),
    /// A skill directory was deleted.
    Removed(PathBuf),
}

/// Internal state for a watched skill directory.
#[derive(Debug, Clone)]
struct WatchedSkill {
    /// File modification times at last poll.
    file_mtimes: HashMap<PathBuf, SystemTime>,
}

/// Watches skill directories for changes using a polling approach.
///
/// Periodically scans watched directories and reports added, modified, and
/// removed skill directories.
#[derive(Debug)]
pub struct SkillWatcher {
    /// Directories being watched.
    watch_paths: Vec<PathBuf>,
    /// Known skills and their file modification times.
    known_skills: HashMap<PathBuf, WatchedSkill>,
}

impl SkillWatcher {
    /// Create a new watcher with no watched directories.
    pub fn new() -> Self {
        Self {
            watch_paths: Vec::new(),
            known_skills: HashMap::new(),
        }
    }

    /// Create a watcher from a configuration.
    pub fn from_config(config: &SkillWatcherConfig) -> Self {
        let mut watcher = Self::new();
        for path in &config.watch_paths {
            watcher.watch_directory(path.clone());
        }
        watcher
    }

    /// Add a directory to watch for skill changes.
    pub fn watch_directory(&mut self, path: PathBuf) {
        if !self.watch_paths.contains(&path) {
            self.watch_paths.push(path);
        }
    }

    /// Remove a directory from the watch list.
    pub fn unwatch_directory(&mut self, path: &Path) {
        self.watch_paths.retain(|p| p != path);
        // Remove any known skills under this path
        self.known_skills.retain(|k, _| !k.starts_with(path));
    }

    /// Poll all watched directories for changes since the last poll.
    ///
    /// Returns a list of changes detected. The first call establishes the
    /// baseline and returns `Added` for all existing skills.
    pub fn poll_changes(&mut self) -> Vec<SkillChange> {
        let mut changes = Vec::new();

        for watch_path in self.watch_paths.clone() {
            if !watch_path.is_dir() {
                continue;
            }

            // Discover current skill directories
            let current_skills = match scan_skill_dirs(&watch_path) {
                Ok(skills) => skills,
                Err(e) => {
                    warn!("failed to scan {}: {e}", watch_path.display());
                    continue;
                }
            };

            // Check for added and modified skills
            for (skill_path, _skill_name) in &current_skills {
                let file_mtimes = match collect_file_mtimes(skill_path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                match self.known_skills.get(skill_path) {
                    None => {
                        // New skill
                        changes.push(SkillChange::Added(skill_path.clone()));
                        self.known_skills.insert(
                            skill_path.clone(),
                            WatchedSkill { file_mtimes },
                        );
                    }
                    Some(known) => {
                        // Check if any files changed
                        if files_changed(&known.file_mtimes, &file_mtimes) {
                            changes.push(SkillChange::Modified(skill_path.clone()));
                            self.known_skills.insert(
                                skill_path.clone(),
                                WatchedSkill { file_mtimes },
                            );
                        }
                    }
                }
            }

            // Check for removed skills
            let current_paths: std::collections::HashSet<PathBuf> =
                current_skills.iter().map(|(p, _)| p.clone()).collect();

            let removed: Vec<PathBuf> = self
                .known_skills
                .keys()
                .filter(|k| k.starts_with(&watch_path) && !current_paths.contains(*k))
                .cloned()
                .collect();

            for path in removed {
                changes.push(SkillChange::Removed(path.clone()));
                self.known_skills.remove(&path);
            }
        }

        changes
    }

    /// Return the paths currently being watched.
    pub fn watched_paths(&self) -> &[PathBuf] {
        &self.watch_paths
    }

    /// Return the number of known skills across all watched directories.
    pub fn known_skill_count(&self) -> usize {
        self.known_skills.len()
    }
}

impl Default for SkillWatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Applies skill changes to a registry.
///
/// Handles adding, modifying (re-registering), and removing skills when
/// changes are detected by a [`SkillWatcher`].
pub struct HotReloader {
    registry: Arc<Mutex<SkillRegistry>>,
    scanner: Option<SkillScanner>,
    router: Option<Arc<Mutex<CommandRouter>>>,
}

impl HotReloader {
    /// Create a new reloader wrapping a shared registry.
    pub fn new(registry: Arc<Mutex<SkillRegistry>>) -> Self {
        Self {
            registry,
            scanner: None,
            router: None,
        }
    }

    /// Create a reloader with a security scanner for auto-scanning on reload.
    pub fn with_scanner(registry: Arc<Mutex<SkillRegistry>>, scanner: SkillScanner) -> Self {
        Self {
            registry,
            scanner: Some(scanner),
            router: None,
        }
    }

    /// Attach a command router that gets updated when skills are reloaded.
    pub fn set_router(&mut self, router: Arc<Mutex<CommandRouter>>) {
        self.router = Some(router);
    }

    /// Apply a batch of changes to the registry.
    ///
    /// For each change:
    /// - `Added`: discover, validate, optionally scan, register
    /// - `Modified`: unregister old, re-discover, re-validate, re-register
    /// - `Removed`: unregister the skill
    pub fn apply_changes(&mut self, changes: Vec<SkillChange>) -> Result<Vec<String>> {
        let mut messages = Vec::new();

        for change in changes {
            match change {
                SkillChange::Added(path) => {
                    match self.load_skill(&path) {
                        Ok(name) => {
                            info!("hot-reload: added skill '{name}'");
                            messages.push(format!("added skill '{name}'"));
                        }
                        Err(e) => {
                            warn!("hot-reload: failed to add skill at {}: {e}", path.display());
                            messages.push(format!(
                                "failed to add skill at {}: {e}",
                                path.display()
                            ));
                        }
                    }
                }
                SkillChange::Modified(path) => {
                    match self.reload_skill_at_path(&path) {
                        Ok(name) => {
                            info!("hot-reload: reloaded skill '{name}'");
                            messages.push(format!("reloaded skill '{name}'"));
                        }
                        Err(e) => {
                            warn!(
                                "hot-reload: failed to reload skill at {}: {e}",
                                path.display()
                            );
                            messages.push(format!(
                                "failed to reload skill at {}: {e}",
                                path.display()
                            ));
                        }
                    }
                }
                SkillChange::Removed(path) => {
                    match self.remove_skill_at_path(&path) {
                        Ok(name) => {
                            info!("hot-reload: removed skill '{name}'");
                            messages.push(format!("removed skill '{name}'"));
                        }
                        Err(e) => {
                            warn!(
                                "hot-reload: failed to remove skill at {}: {e}",
                                path.display()
                            );
                            messages.push(format!(
                                "failed to remove skill at {}: {e}",
                                path.display()
                            ));
                        }
                    }
                }
            }
        }

        Ok(messages)
    }

    /// Reload a specific skill by name.
    ///
    /// Looks up the skill in the registry, finds its path, and reloads it.
    pub fn reload_skill(&mut self, name: &str) -> Result<()> {
        let path = {
            let registry = self
                .registry
                .lock()
                .map_err(|e| anyhow::anyhow!("registry lock poisoned: {e}"))?;
            let instance = registry
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("skill not found: {name}"))?;
            instance.path.clone()
        };

        self.reload_skill_at_path(&path)?;
        Ok(())
    }

    /// Reload all skills from all paths in the registry.
    pub fn reload_all(&mut self) -> Result<Vec<String>> {
        let paths: Vec<PathBuf> = {
            let registry = self
                .registry
                .lock()
                .map_err(|e| anyhow::anyhow!("registry lock poisoned: {e}"))?;
            registry.list().iter().map(|s| s.path.clone()).collect()
        };

        let mut messages = Vec::new();
        for path in paths {
            match self.reload_skill_at_path(&path) {
                Ok(name) => messages.push(format!("reloaded '{name}'")),
                Err(e) => messages.push(format!("failed to reload {}: {e}", path.display())),
            }
        }

        Ok(messages)
    }

    /// Load a skill from a path and register it.
    fn load_skill(&mut self, path: &Path) -> Result<String> {
        let manifest_path = path.join("manifest.toml");
        let manifest = parse_manifest_file(&manifest_path)
            .with_context(|| format!("failed to parse manifest at {}", manifest_path.display()))?;
        validate_manifest(&manifest)?;

        let name = manifest.name.clone();
        let mut instance = SkillInstance::discover(manifest, path.to_path_buf());
        instance.validate()?;

        // Optionally run security scan
        if let Some(ref mut scanner) = self.scanner {
            let scan_result = instance.load_with_scan(scanner)?;
            if !scan_result.passed {
                anyhow::bail!(
                    "security scan blocked skill '{}': {} error(s)",
                    name,
                    scan_result.errors.len()
                );
            }
        } else {
            instance.load()?;
        }

        instance.activate()?;

        // Register in the registry
        {
            let mut registry = self
                .registry
                .lock()
                .map_err(|e| anyhow::anyhow!("registry lock poisoned: {e}"))?;

            // Update the command router if present
            if let Some(ref router_arc) = self.router {
                if let Ok(mut router) = router_arc.lock() {
                    router.register_from_manifest(&instance.manifest);
                }
            }

            registry.register(instance)?;
        }

        Ok(name)
    }

    /// Reload a skill at a specific path (remove old, add new).
    fn reload_skill_at_path(&mut self, path: &Path) -> Result<String> {
        // First, try to remove the existing skill at this path
        let _ = self.remove_skill_at_path(path);

        // Then load the updated version
        self.load_skill(path)
    }

    /// Remove a skill at a specific path from the registry.
    fn remove_skill_at_path(&mut self, path: &Path) -> Result<String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|e| anyhow::anyhow!("registry lock poisoned: {e}"))?;

        // Find the skill by path
        let name = registry
            .list()
            .iter()
            .find(|s| s.path == path)
            .map(|s| s.manifest.name.clone())
            .ok_or_else(|| anyhow::anyhow!("no skill found at path: {}", path.display()))?;

        // Disable before removing
        if let Some(instance) = registry.get_mut(&name) {
            if instance.state == SkillState::Active {
                instance.disable()?;
            }
        }

        registry.remove(&name)?;

        debug!("removed skill '{name}' from registry");
        Ok(name)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Scan a directory for skill subdirectories (directories containing manifest.toml).
///
/// Returns pairs of (path, skill_name).
fn scan_skill_dirs(dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut results = Vec::new();

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory: {}", dir.display()))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let entry_path = entry.path();
        if !entry_path.is_dir() {
            continue;
        }

        let manifest_path = entry_path.join("manifest.toml");
        if !manifest_path.exists() {
            continue;
        }

        // Try to parse the manifest to get the skill name
        match parse_manifest_file(&manifest_path) {
            Ok(manifest) => {
                results.push((entry_path, manifest.name));
            }
            Err(_) => continue,
        }
    }

    Ok(results)
}

/// Collect modification times for all files in a directory (non-recursive for speed).
fn collect_file_mtimes(dir: &Path) -> Result<HashMap<PathBuf, SystemTime>> {
    let mut mtimes = HashMap::new();

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory: {}", dir.display()))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if path.is_file() {
            if let Ok(metadata) = std::fs::metadata(&path) {
                if let Ok(mtime) = metadata.modified() {
                    mtimes.insert(path, mtime);
                }
            }
        }
    }

    Ok(mtimes)
}

/// Check if any files changed between two mtime snapshots.
fn files_changed(
    old: &HashMap<PathBuf, SystemTime>,
    new: &HashMap<PathBuf, SystemTime>,
) -> bool {
    // Different number of files means something changed
    if old.len() != new.len() {
        return true;
    }

    // Check for modified or new files
    for (path, new_mtime) in new {
        match old.get(path) {
            Some(old_mtime) if old_mtime == new_mtime => {}
            _ => return true,
        }
    }

    // Check for deleted files (path in old but not in new)
    for path in old.keys() {
        if !new.contains_key(path) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_skill(dir: &Path, name: &str) {
        let skill_dir = dir.join(name);
        std::fs::create_dir_all(&skill_dir).unwrap();
        let manifest = format!(
            r#"
name = "{name}"
version = "1.0.0"
description = "Skill {name}"
entry_point = "run.sh"
"#
        );
        std::fs::write(skill_dir.join("manifest.toml"), manifest).unwrap();
        std::fs::write(skill_dir.join("run.sh"), "#!/bin/bash\necho ok").unwrap();
    }

    #[test]
    fn watcher_config_defaults() {
        let config = SkillWatcherConfig::default();
        assert!(config.enabled);
        assert_eq!(config.poll_interval_secs, 5);
        assert!(config.watch_paths.is_empty());
        assert!(config.auto_scan);
    }

    #[test]
    fn watcher_watch_directory() {
        let mut watcher = SkillWatcher::new();
        watcher.watch_directory(PathBuf::from("/tmp/skills"));
        assert_eq!(watcher.watched_paths().len(), 1);

        // Duplicate watch should not add again
        watcher.watch_directory(PathBuf::from("/tmp/skills"));
        assert_eq!(watcher.watched_paths().len(), 1);
    }

    #[test]
    fn watcher_unwatch_directory() {
        let mut watcher = SkillWatcher::new();
        watcher.watch_directory(PathBuf::from("/tmp/skills-a"));
        watcher.watch_directory(PathBuf::from("/tmp/skills-b"));
        assert_eq!(watcher.watched_paths().len(), 2);

        watcher.unwatch_directory(Path::new("/tmp/skills-a"));
        assert_eq!(watcher.watched_paths().len(), 1);
        assert_eq!(watcher.watched_paths()[0], PathBuf::from("/tmp/skills-b"));
    }

    #[test]
    fn watcher_from_config() {
        let config = SkillWatcherConfig {
            enabled: true,
            poll_interval_secs: 10,
            watch_paths: vec![PathBuf::from("/a"), PathBuf::from("/b")],
            auto_scan: false,
        };
        let watcher = SkillWatcher::from_config(&config);
        assert_eq!(watcher.watched_paths().len(), 2);
    }

    #[test]
    fn watcher_detects_added_skills() {
        let tmp = TempDir::new().unwrap();
        write_skill(tmp.path(), "skill-a");

        let mut watcher = SkillWatcher::new();
        watcher.watch_directory(tmp.path().to_path_buf());

        // First poll: everything is new
        let changes = watcher.poll_changes();
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], SkillChange::Added(p) if p.ends_with("skill-a")));

        // Second poll: nothing changed
        let changes = watcher.poll_changes();
        assert!(changes.is_empty());
    }

    #[test]
    fn watcher_detects_removed_skills() {
        let tmp = TempDir::new().unwrap();
        write_skill(tmp.path(), "skill-a");
        write_skill(tmp.path(), "skill-b");

        let mut watcher = SkillWatcher::new();
        watcher.watch_directory(tmp.path().to_path_buf());

        // Initial poll
        let changes = watcher.poll_changes();
        assert_eq!(changes.len(), 2);

        // Remove skill-b
        std::fs::remove_dir_all(tmp.path().join("skill-b")).unwrap();

        let changes = watcher.poll_changes();
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], SkillChange::Removed(p) if p.ends_with("skill-b")));
    }

    #[test]
    fn watcher_detects_modified_skills() {
        let tmp = TempDir::new().unwrap();
        write_skill(tmp.path(), "skill-a");

        let mut watcher = SkillWatcher::new();
        watcher.watch_directory(tmp.path().to_path_buf());

        // Initial poll
        let _ = watcher.poll_changes();

        // Modify a file
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(
            tmp.path().join("skill-a").join("run.sh"),
            "#!/bin/bash\necho modified",
        )
        .unwrap();

        let changes = watcher.poll_changes();
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], SkillChange::Modified(p) if p.ends_with("skill-a")));
    }

    #[test]
    fn watcher_known_skill_count() {
        let tmp = TempDir::new().unwrap();
        write_skill(tmp.path(), "skill-x");
        write_skill(tmp.path(), "skill-y");

        let mut watcher = SkillWatcher::new();
        watcher.watch_directory(tmp.path().to_path_buf());
        assert_eq!(watcher.known_skill_count(), 0);

        let _ = watcher.poll_changes();
        assert_eq!(watcher.known_skill_count(), 2);
    }

    #[test]
    fn watcher_nonexistent_dir_no_panic() {
        let mut watcher = SkillWatcher::new();
        watcher.watch_directory(PathBuf::from("/nonexistent/path/skills"));

        let changes = watcher.poll_changes();
        assert!(changes.is_empty());
    }

    #[test]
    fn files_changed_same() {
        let mut a = HashMap::new();
        let t = SystemTime::now();
        a.insert(PathBuf::from("a.txt"), t);
        a.insert(PathBuf::from("b.txt"), t);

        let b = a.clone();
        assert!(!files_changed(&a, &b));
    }

    #[test]
    fn files_changed_different_count() {
        let mut a = HashMap::new();
        let t = SystemTime::now();
        a.insert(PathBuf::from("a.txt"), t);

        let mut b = a.clone();
        b.insert(PathBuf::from("c.txt"), t);

        assert!(files_changed(&a, &b));
    }

    #[test]
    fn files_changed_different_mtime() {
        let mut a = HashMap::new();
        let t1 = SystemTime::UNIX_EPOCH;
        let t2 = SystemTime::now();
        a.insert(PathBuf::from("a.txt"), t1);

        let mut b = HashMap::new();
        b.insert(PathBuf::from("a.txt"), t2);

        assert!(files_changed(&a, &b));
    }

    #[test]
    fn scan_skill_dirs_finds_skills() {
        let tmp = TempDir::new().unwrap();
        write_skill(tmp.path(), "alpha");
        write_skill(tmp.path(), "beta");

        let skills = scan_skill_dirs(tmp.path()).unwrap();
        assert_eq!(skills.len(), 2);

        let mut names: Vec<&str> = skills.iter().map(|(_, n)| n.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn hot_reloader_load_and_remove() {
        let tmp = TempDir::new().unwrap();
        write_skill(tmp.path(), "reload-test");

        let registry = Arc::new(Mutex::new(SkillRegistry::new()));
        let mut reloader = HotReloader::new(Arc::clone(&registry));

        // Load the skill
        let name = reloader
            .load_skill(&tmp.path().join("reload-test"))
            .unwrap();
        assert_eq!(name, "reload-test");

        // Verify it's in the registry
        {
            let reg = registry.lock().unwrap();
            assert!(reg.get("reload-test").is_some());
            assert_eq!(reg.get("reload-test").unwrap().state, SkillState::Active);
        }

        // Remove it
        let removed = reloader
            .remove_skill_at_path(&tmp.path().join("reload-test"))
            .unwrap();
        assert_eq!(removed, "reload-test");

        // Verify it's gone
        {
            let reg = registry.lock().unwrap();
            assert!(reg.get("reload-test").is_none());
        }
    }

    #[test]
    fn hot_reloader_apply_changes() {
        let tmp = TempDir::new().unwrap();
        write_skill(tmp.path(), "change-test");

        let registry = Arc::new(Mutex::new(SkillRegistry::new()));
        let mut reloader = HotReloader::new(Arc::clone(&registry));

        // Apply an Added change
        let messages = reloader
            .apply_changes(vec![SkillChange::Added(tmp.path().join("change-test"))])
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("added"));

        // Verify it's registered
        {
            let reg = registry.lock().unwrap();
            assert!(reg.get("change-test").is_some());
        }

        // Apply a Removed change
        let messages = reloader
            .apply_changes(vec![SkillChange::Removed(tmp.path().join("change-test"))])
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("removed"));

        // Verify it's gone
        {
            let reg = registry.lock().unwrap();
            assert!(reg.get("change-test").is_none());
        }
    }

    #[test]
    fn hot_reloader_reload_skill_by_name() {
        let tmp = TempDir::new().unwrap();
        write_skill(tmp.path(), "named-reload");

        let registry = Arc::new(Mutex::new(SkillRegistry::new()));
        let mut reloader = HotReloader::new(Arc::clone(&registry));

        // Load initial
        reloader
            .load_skill(&tmp.path().join("named-reload"))
            .unwrap();

        // Modify the manifest description
        let manifest = r#"
name = "named-reload"
version = "2.0.0"
description = "Updated skill"
entry_point = "run.sh"
"#;
        std::fs::write(
            tmp.path().join("named-reload").join("manifest.toml"),
            manifest,
        )
        .unwrap();

        // Reload by name
        reloader.reload_skill("named-reload").unwrap();

        // Verify the updated version
        {
            let reg = registry.lock().unwrap();
            let inst = reg.get("named-reload").unwrap();
            assert_eq!(inst.manifest.version, "2.0.0");
            assert_eq!(inst.manifest.description, "Updated skill");
        }
    }

    #[test]
    fn hot_reloader_reload_all() {
        let tmp = TempDir::new().unwrap();
        write_skill(tmp.path(), "all-a");
        write_skill(tmp.path(), "all-b");

        let registry = Arc::new(Mutex::new(SkillRegistry::new()));
        let mut reloader = HotReloader::new(Arc::clone(&registry));

        reloader.load_skill(&tmp.path().join("all-a")).unwrap();
        reloader.load_skill(&tmp.path().join("all-b")).unwrap();

        let messages = reloader.reload_all().unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages.iter().all(|m| m.contains("reloaded")));
    }

    #[test]
    fn skill_change_eq() {
        let p1 = PathBuf::from("/a");
        let p2 = PathBuf::from("/b");

        assert_eq!(SkillChange::Added(p1.clone()), SkillChange::Added(p1.clone()));
        assert_ne!(SkillChange::Added(p1.clone()), SkillChange::Added(p2.clone()));
        assert_ne!(SkillChange::Added(p1.clone()), SkillChange::Modified(p1.clone()));
        assert_ne!(SkillChange::Added(p1.clone()), SkillChange::Removed(p1));
    }
}
