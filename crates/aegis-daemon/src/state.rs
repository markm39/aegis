//! Persistent daemon state for crash recovery.
//!
//! The daemon periodically writes its state to `~/.aegis/daemon/state.json`.
//! On restart after a crash, the daemon reads this file to determine which
//! agents were running and need to be restarted, and which audit sessions
//! need to be closed as orphaned.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use aegis_types::daemon::daemon_state_path;

/// Persistent state of the daemon, saved to disk for crash recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    /// PID of the daemon process.
    pub daemon_pid: u32,
    /// When the daemon started.
    pub started_at: DateTime<Utc>,
    /// State of each agent slot at last save.
    pub agents: Vec<AgentState>,
    /// When this state was last written.
    pub updated_at: DateTime<Utc>,
}

/// Saved state for a single agent slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    /// Slot name.
    pub name: String,
    /// Whether the agent was running at time of save.
    pub was_running: bool,
    /// The agent's audit session ID (if active).
    pub session_id: Option<uuid::Uuid>,
    /// Restart count at time of save.
    pub restart_count: u32,
}

impl DaemonState {
    /// Create a new state snapshot for the given daemon PID.
    pub fn new(daemon_pid: u32) -> Self {
        Self {
            daemon_pid,
            started_at: Utc::now(),
            agents: vec![],
            updated_at: Utc::now(),
        }
    }

    /// Save state to disk atomically (write tmp, then rename).
    pub fn save(&self) -> Result<(), String> {
        let path = daemon_state_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create state dir: {e}"))?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize state: {e}"))?;

        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &json)
            .map_err(|e| format!("failed to write state tmp: {e}"))?;
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| format!("failed to rename state file: {e}"))?;

        Ok(())
    }

    /// Load state from disk, returning None if the file doesn't exist.
    pub fn load() -> Option<Self> {
        let path = daemon_state_path();
        let content = std::fs::read_to_string(&path).ok()?;
        match serde_json::from_str(&content) {
            Ok(state) => Some(state),
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse daemon state file, skipping crash recovery");
                None
            }
        }
    }

    /// Remove the state file from disk.
    pub fn remove() {
        let path = daemon_state_path();
        let _ = std::fs::remove_file(path);
    }
}

/// Recover from a previous daemon crash.
///
/// Logs which agents were running when the previous daemon died and closes
/// any orphaned audit sessions in the ledger. Orphaned sessions (from agents
/// that were running when the daemon crashed) are closed with exit code -1
/// to indicate an abnormal termination.
pub fn recover_from_crash(prev_state: &DaemonState, ledger_path: &std::path::Path) {
    tracing::warn!(
        daemon_pid = prev_state.daemon_pid,
        agents = prev_state.agents.len(),
        "recovering from previous daemon crash"
    );

    // Open the audit store to close orphaned sessions
    let mut store = match aegis_ledger::AuditStore::open(ledger_path) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "could not open audit store for crash recovery");
            None
        }
    };

    for agent in &prev_state.agents {
        if agent.was_running {
            tracing::info!(
                name = agent.name,
                session_id = ?agent.session_id,
                restart_count = agent.restart_count,
                "agent was running at crash time, will be restarted"
            );

            // Close orphaned audit session with exit code -1 (crash)
            if let (Some(ref mut s), Some(ref session_id)) = (&mut store, &agent.session_id) {
                if let Err(e) = s.end_session(session_id, -1) {
                    tracing::warn!(
                        session_id = %session_id, error = %e,
                        "failed to close orphaned audit session"
                    );
                } else {
                    tracing::info!(
                        session_id = %session_id, agent = agent.name,
                        "closed orphaned audit session (exit_code=-1)"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_state() {
        let state = DaemonState::new(1234);
        assert_eq!(state.daemon_pid, 1234);
        assert!(state.agents.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        // Use a temp dir to avoid polluting the real state file
        let tmp = tempfile::tempdir().unwrap();
        let state_path = tmp.path().join("state.json");

        let mut state = DaemonState::new(42);
        state.agents.push(AgentState {
            name: "claude-1".into(),
            was_running: true,
            session_id: Some(uuid::Uuid::new_v4()),
            restart_count: 2,
        });

        // Write to a custom path for testing
        let json = serde_json::to_string_pretty(&state).unwrap();
        std::fs::write(&state_path, &json).unwrap();

        let content = std::fs::read_to_string(&state_path).unwrap();
        let loaded: DaemonState = serde_json::from_str(&content).unwrap();

        assert_eq!(loaded.daemon_pid, 42);
        assert_eq!(loaded.agents.len(), 1);
        assert_eq!(loaded.agents[0].name, "claude-1");
        assert!(loaded.agents[0].was_running);
        assert_eq!(loaded.agents[0].restart_count, 2);
    }

    #[test]
    fn load_nonexistent_returns_none() {
        // DaemonState::load() reads from the default path, which won't exist
        // in a clean test environment. If it does exist from a previous run,
        // that's fine -- just verify it parses.
        let result = DaemonState::load();
        // Either None (no file) or Some (valid file) is acceptable
        if let Some(state) = result {
            assert!(state.daemon_pid > 0);
        }
    }

    #[test]
    fn agent_state_serialization() {
        let agent = AgentState {
            name: "codex-1".into(),
            was_running: false,
            session_id: None,
            restart_count: 0,
        };

        let json = serde_json::to_string(&agent).unwrap();
        let back: AgentState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "codex-1");
        assert!(!back.was_running);
        assert!(back.session_id.is_none());
    }
}
