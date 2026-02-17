//! Fleet: manages all agent slots, handles spawning, stopping, and health checks.
//!
//! The fleet is the central data structure of the daemon. It owns all agent slots
//! and provides methods for lifecycle management (start, stop, restart) and
//! periodic health checks (tick).

use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;

use tracing::{error, info, warn};

use aegis_types::daemon::{AgentSlotConfig, AgentStatus, DaemonConfig, RestartPolicy};
use aegis_types::AegisConfig;

use crate::lifecycle;
use crate::slot::AgentSlot;

/// Fleet of managed agent slots.
pub struct Fleet {
    /// Slots indexed by agent name.
    slots: HashMap<String, AgentSlot>,
    /// Default Aegis configuration (shared across agents that don't override).
    default_aegis_config: AegisConfig,
}

impl Fleet {
    /// Create a new fleet from daemon configuration.
    pub fn new(config: &DaemonConfig, aegis_config: AegisConfig) -> Self {
        let mut slots = HashMap::new();
        for agent_config in &config.agents {
            let slot = AgentSlot::new(agent_config.clone());
            slots.insert(agent_config.name.clone(), slot);
        }

        Self {
            slots,
            default_aegis_config: aegis_config,
        }
    }

    /// Start all enabled agents.
    pub fn start_all(&mut self) {
        let names: Vec<String> = self
            .slots
            .keys()
            .cloned()
            .collect();

        for name in names {
            if self.slots.get(&name).is_some_and(|s| s.config.enabled) {
                self.start_agent(&name);
            }
        }
    }

    /// Start a specific agent by name.
    pub fn start_agent(&mut self, name: &str) {
        let slot = match self.slots.get_mut(name) {
            Some(s) => s,
            None => {
                warn!(agent = name, "start_agent: unknown agent");
                return;
            }
        };

        if slot.is_thread_alive() {
            info!(agent = name, "agent already running, skipping start");
            return;
        }

        let slot_config = slot.config.clone();
        let aegis_config = self.default_aegis_config.clone();
        let (tx, rx) = mpsc::channel::<String>();

        slot.output_rx = Some(rx);
        slot.started_at = Some(std::time::Instant::now());

        let handle = thread::Builder::new()
            .name(format!("agent-{name}"))
            .spawn(move || {
                lifecycle::run_agent_slot(&slot_config, &aegis_config, tx)
            });

        match handle {
            Ok(h) => {
                // Set status to Running with PID 0 (we don't know the child PID
                // from outside the thread until it reports back -- using the
                // thread ID isn't meaningful, so PID 0 signals "spawning").
                slot.status = AgentStatus::Running { pid: 0 };
                slot.thread_handle = Some(h);
                info!(agent = name, "agent thread spawned");
            }
            Err(e) => {
                error!(agent = name, error = %e, "failed to spawn agent thread");
                slot.status = AgentStatus::Failed {
                    exit_code: -1,
                    restart_count: slot.restart_count,
                };
            }
        }
    }

    /// Stop a specific agent by name.
    ///
    /// Currently waits for the thread to finish. In the future, this could
    /// send SIGTERM to the child process first.
    pub fn stop_agent(&mut self, name: &str) {
        let slot = match self.slots.get_mut(name) {
            Some(s) => s,
            None => {
                warn!(agent = name, "stop_agent: unknown agent");
                return;
            }
        };

        if let Some(handle) = slot.thread_handle.take() {
            info!(agent = name, "stopping agent (waiting for thread)");

            // The thread will eventually exit when the child process does.
            // For now, we just mark it and wait.
            match handle.join() {
                Ok(result) => {
                    info!(
                        agent = name,
                        exit_code = ?result.exit_code,
                        "agent stopped"
                    );
                    slot.status = AgentStatus::Stopped {
                        exit_code: result.exit_code.unwrap_or(-1),
                    };
                }
                Err(_) => {
                    error!(agent = name, "agent thread panicked");
                    slot.status = AgentStatus::Failed {
                        exit_code: -1,
                        restart_count: slot.restart_count,
                    };
                }
            }
        }

        slot.started_at = None;
    }

    /// Send text to an agent's PTY stdin (via the lifecycle thread's channel).
    ///
    /// Note: This requires a dedicated command channel to the supervisor, which
    /// is not yet implemented. For now, this is a placeholder.
    pub fn send_to_agent(&self, name: &str, _text: &str) -> Result<(), String> {
        if !self.slots.contains_key(name) {
            return Err(format!("unknown agent: {name}"));
        }
        // TODO: Implement via SupervisorCommand channel
        warn!(agent = name, "send_to_agent not yet implemented");
        Ok(())
    }

    /// Get recent output lines from an agent.
    pub fn agent_output(&self, name: &str, lines: usize) -> Result<Vec<String>, String> {
        let slot = self
            .slots
            .get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        // Drain any pending output first
        slot.drain_output();
        Ok(slot.get_recent_output(lines))
    }

    /// Periodic tick: check for exited threads, apply restart policies,
    /// and drain output channels.
    pub fn tick(&mut self) {
        let names: Vec<String> = self.slots.keys().cloned().collect();

        for name in names {
            // Drain output for all agents
            if let Some(slot) = self.slots.get(&name) {
                slot.drain_output();
            }

            // Check if the thread has finished
            let needs_join = self
                .slots
                .get(&name)
                .is_some_and(|s| {
                    s.thread_handle.as_ref().is_some_and(|h| h.is_finished())
                });

            if needs_join {
                self.tick_slot(&name);
            }
        }
    }

    /// Handle a finished agent thread: join it and apply restart policy.
    fn tick_slot(&mut self, name: &str) {
        let slot = match self.slots.get_mut(name) {
            Some(s) => s,
            None => return,
        };

        let handle = match slot.thread_handle.take() {
            Some(h) => h,
            None => return,
        };

        let result = match handle.join() {
            Ok(r) => r,
            Err(_) => {
                error!(agent = name, "agent thread panicked");
                slot.status = AgentStatus::Failed {
                    exit_code: -1,
                    restart_count: slot.restart_count,
                };
                slot.started_at = None;
                return;
            }
        };

        let exit_code = result.exit_code.unwrap_or(-1);
        info!(agent = name, exit_code, "agent exited, evaluating restart policy");

        self.handle_agent_exit(name, exit_code);
    }

    /// Apply restart policy after an agent exits.
    fn handle_agent_exit(&mut self, name: &str, exit_code: i32) {
        let slot = match self.slots.get_mut(name) {
            Some(s) => s,
            None => return,
        };

        slot.started_at = None;

        let should_restart = match &slot.config.restart {
            RestartPolicy::Never => false,
            RestartPolicy::OnFailure => exit_code != 0,
            RestartPolicy::Always => true,
        };

        if !should_restart {
            slot.status = AgentStatus::Stopped { exit_code };
            return;
        }

        // Check max restarts
        if slot.config.max_restarts > 0 && slot.restart_count >= slot.config.max_restarts {
            warn!(
                agent = name,
                restart_count = slot.restart_count,
                max = slot.config.max_restarts,
                "max restarts exceeded"
            );
            slot.status = AgentStatus::Failed {
                exit_code,
                restart_count: slot.restart_count,
            };
            return;
        }

        slot.restart_count += 1;
        info!(
            agent = name,
            restart_count = slot.restart_count,
            "restarting agent"
        );

        // Drop the mutable borrow before calling start_agent
        let name_owned = name.to_string();
        self.start_agent(&name_owned);
    }

    /// Get the status of a specific agent.
    pub fn agent_status(&self, name: &str) -> Option<&AgentStatus> {
        self.slots.get(name).map(|s| &s.status)
    }

    /// Get the config of a specific agent.
    pub fn agent_config(&self, name: &str) -> Option<&AgentSlotConfig> {
        self.slots.get(name).map(|s| &s.config)
    }

    /// Get a reference to a slot.
    pub fn slot(&self, name: &str) -> Option<&AgentSlot> {
        self.slots.get(name)
    }

    /// Get all agent names.
    pub fn agent_names(&self) -> Vec<String> {
        self.slots.keys().cloned().collect()
    }

    /// Total number of agent slots.
    pub fn agent_count(&self) -> usize {
        self.slots.len()
    }

    /// Number of currently running agents.
    pub fn running_count(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s.status, AgentStatus::Running { .. }))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::daemon::{
        AgentToolConfig, DaemonControlConfig, PersistenceConfig,
    };
    use std::path::PathBuf;

    fn test_daemon_config(agents: Vec<AgentSlotConfig>) -> DaemonConfig {
        DaemonConfig {
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            alerts: vec![],
            agents,
            channel: None,
        }
    }

    fn test_slot_config(name: &str) -> AgentSlotConfig {
        AgentSlotConfig {
            name: name.to_string(),
            tool: AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: vec![],
            },
            working_dir: PathBuf::from("/tmp"),
            task: None,
            pilot: None,
            restart: RestartPolicy::OnFailure,
            max_restarts: 5,
            enabled: true,
        }
    }

    #[test]
    fn empty_fleet() {
        let config = test_daemon_config(vec![]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        assert_eq!(fleet.agent_count(), 0);
        assert_eq!(fleet.running_count(), 0);
        assert!(fleet.agent_names().is_empty());
    }

    #[test]
    fn fleet_from_config() {
        let config = test_daemon_config(vec![
            test_slot_config("agent-1"),
            test_slot_config("agent-2"),
        ]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        assert_eq!(fleet.agent_count(), 2);
        assert!(fleet.agent_status("agent-1").is_some());
        assert!(fleet.agent_status("agent-2").is_some());
        assert!(fleet.agent_status("nonexistent").is_none());
    }

    #[test]
    fn disabled_agent_status() {
        let mut config_slot = test_slot_config("disabled-1");
        config_slot.enabled = false;

        let config = test_daemon_config(vec![config_slot]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        assert_eq!(fleet.agent_status("disabled-1"), Some(&AgentStatus::Disabled));
    }

    #[test]
    fn agent_output_unknown_agent_returns_error() {
        let config = test_daemon_config(vec![]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        assert!(fleet.agent_output("no-such", 10).is_err());
    }

    #[test]
    fn send_to_unknown_agent_returns_error() {
        let config = test_daemon_config(vec![]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        assert!(fleet.send_to_agent("no-such", "hello").is_err());
    }
}
