//! High-level hook manager that integrates discovery and execution.
//!
//! [`HookManager`] is the primary entry point for daemon integration. It
//! discovers hooks from configured directories, caches the results, and
//! provides an async `fire_event` method that runs all matching hooks and
//! returns the aggregated response.

use std::path::{Path, PathBuf};

use crate::discovery::{self, DiscoveredHook};
use crate::events::{HookEvent, HookResponse};
use crate::runner::{self, HookExecution};

/// Manages discovered hooks and orchestrates their execution.
///
/// Typical usage:
///
/// ```no_run
/// use aegis_hooks::manager::HookManager;
/// use aegis_hooks::events::HookEvent;
///
/// # async fn example() {
/// let mut manager = HookManager::new();
/// manager.add_hooks_dir("/path/to/project/.aegis/hooks");
/// manager.discover().unwrap();
///
/// let event = HookEvent::OnAgentStart {
///     agent_name: "claude-1".to_string(),
/// };
/// let response = manager.fire_event(&event).await;
/// println!("action: {:?}", response.action);
/// # }
/// ```
pub struct HookManager {
    /// Directories to scan for hooks, in priority order (later overrides earlier).
    hooks_dirs: Vec<PathBuf>,

    /// Cached discovered hooks from the last `discover()` call.
    hooks: Vec<DiscoveredHook>,
}

impl HookManager {
    /// Create a new hook manager with no directories configured.
    pub fn new() -> Self {
        Self {
            hooks_dirs: Vec::new(),
            hooks: Vec::new(),
        }
    }

    /// Add a hooks directory to scan during discovery.
    ///
    /// Directories are scanned in order, with later directories having
    /// higher priority (their hooks override earlier ones for the same event).
    pub fn add_hooks_dir(&mut self, dir: impl Into<PathBuf>) {
        self.hooks_dirs.push(dir.into());
    }

    /// Discover hooks from all configured directories.
    ///
    /// Clears any previously cached hooks and re-scans all directories.
    /// Returns the number of hooks discovered.
    pub fn discover(&mut self) -> Result<usize, String> {
        let dirs: Vec<&Path> = self.hooks_dirs.iter().map(|p| p.as_path()).collect();
        self.hooks = discovery::discover_hooks_merged(&dirs)?;

        tracing::info!(
            count = self.hooks.len(),
            dirs = ?self.hooks_dirs,
            "discovered user hooks"
        );

        Ok(self.hooks.len())
    }

    /// Fire an event against all matching hooks and return the aggregated response.
    ///
    /// Hooks are matched by event name (exact match for convention hooks,
    /// glob match for manifest hooks). Disabled hooks are skipped. Each matching
    /// hook is executed sequentially with the event data, and the results are
    /// aggregated:
    ///
    /// - If any hook blocks, the aggregate response blocks.
    /// - If any hook modifies (and none block), the aggregate has the last
    ///   modifier's payload.
    /// - Errors in individual hooks are isolated and logged; they don't prevent
    ///   other hooks from running.
    pub async fn fire_event(&self, event: &HookEvent) -> HookResponse {
        let event_name = event.event_name();
        let matching = discovery::hooks_for_event(&self.hooks, event_name);

        if matching.is_empty() {
            return HookResponse::default();
        }

        tracing::debug!(
            event = event_name,
            hook_count = matching.len(),
            "firing hooks for event"
        );

        let executions = runner::execute_hooks_for_event(&matching, event).await;

        // Log individual results.
        for exec in &executions {
            if let Some(ref err) = exec.error {
                tracing::warn!(
                    script = %exec.script_path.display(),
                    event = %exec.event_name,
                    error = %err,
                    "hook execution failed"
                );
            } else {
                tracing::debug!(
                    script = %exec.script_path.display(),
                    event = %exec.event_name,
                    action = ?exec.response.action,
                    duration_ms = exec.duration.as_millis() as u64,
                    "hook executed"
                );
            }
        }

        runner::aggregate_responses(&executions)
    }

    /// Fire an event and return all individual execution results.
    ///
    /// Unlike [`fire_event`](Self::fire_event), this returns the raw execution
    /// results rather than an aggregated response. Useful for detailed logging
    /// or debugging.
    pub async fn fire_event_detailed(&self, event: &HookEvent) -> Vec<HookExecution> {
        let event_name = event.event_name();
        let matching = discovery::hooks_for_event(&self.hooks, event_name);

        if matching.is_empty() {
            return Vec::new();
        }

        runner::execute_hooks_for_event(&matching, event).await
    }

    /// Get the list of currently discovered hooks.
    pub fn hooks(&self) -> &[DiscoveredHook] {
        &self.hooks
    }

    /// Get the number of discovered hooks.
    pub fn hook_count(&self) -> usize {
        self.hooks.len()
    }

    /// Get the configured hooks directories.
    pub fn hooks_dirs(&self) -> &[PathBuf] {
        &self.hooks_dirs
    }

    /// Check whether any hooks are registered for a given event name.
    pub fn has_hooks_for(&self, event_name: &str) -> bool {
        !discovery::hooks_for_event(&self.hooks, event_name).is_empty()
    }
}

impl Default for HookManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::HookResponseAction;

    #[test]
    fn new_manager_is_empty() {
        let manager = HookManager::new();
        assert_eq!(manager.hook_count(), 0);
        assert!(manager.hooks_dirs().is_empty());
    }

    #[test]
    fn discover_from_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = HookManager::new();
        manager.add_hooks_dir(dir.path());
        let count = manager.discover().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn discover_convention_hooks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pre_tool_use.sh"), "#!/bin/sh\nexit 0").unwrap();
        std::fs::write(dir.path().join("on_message.py"), "pass").unwrap();

        let mut manager = HookManager::new();
        manager.add_hooks_dir(dir.path());
        let count = manager.discover().unwrap();
        assert_eq!(count, 2);
        assert!(manager.has_hooks_for("pre_tool_use"));
        assert!(manager.has_hooks_for("on_message"));
        assert!(!manager.has_hooks_for("on_error"));
    }

    #[tokio::test]
    async fn fire_event_no_hooks() {
        let manager = HookManager::new();
        let event = HookEvent::OnAgentStart {
            agent_name: "test".to_string(),
        };
        let resp = manager.fire_event(&event).await;
        assert_eq!(resp.action, HookResponseAction::Allow);
    }

    #[tokio::test]
    async fn fire_event_with_shell_hook() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("on_agent_start.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho '{\"action\": \"allow\", \"message\": \"started\"}'",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let mut manager = HookManager::new();
        manager.add_hooks_dir(dir.path());
        let count = manager.discover().unwrap();
        assert_eq!(count, 1, "should discover exactly one hook");
        assert!(
            manager.has_hooks_for("on_agent_start"),
            "should have hooks for on_agent_start"
        );

        let event = HookEvent::OnAgentStart {
            agent_name: "claude-1".to_string(),
        };
        let resp = manager.fire_event(&event).await;
        assert_eq!(resp.action, HookResponseAction::Allow);
        assert_eq!(resp.message, "started");
    }

    #[tokio::test]
    async fn fire_event_detailed_returns_executions() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("on_error.sh");
        std::fs::write(&script, "#!/bin/sh\necho '{\"action\": \"allow\"}'").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let mut manager = HookManager::new();
        manager.add_hooks_dir(dir.path());
        manager.discover().unwrap();

        let event = HookEvent::OnError {
            error: "test".to_string(),
            context: "unit test".to_string(),
        };
        let results = manager.fire_event_detailed(&event).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[tokio::test]
    async fn fire_event_with_blocking_hook() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("pre_tool_use.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho '{\"action\": \"block\", \"message\": \"forbidden\"}'\nexit 1",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let mut manager = HookManager::new();
        manager.add_hooks_dir(dir.path());
        manager.discover().unwrap();

        let event = HookEvent::PreToolUse {
            tool_name: "Bash".to_string(),
            arguments: serde_json::json!({"command": "rm -rf /"}),
        };
        let resp = manager.fire_event(&event).await;
        assert_eq!(resp.action, HookResponseAction::Block);
        assert_eq!(resp.message, "forbidden");
    }

    #[test]
    fn default_trait() {
        let manager = HookManager::default();
        assert_eq!(manager.hook_count(), 0);
    }
}
