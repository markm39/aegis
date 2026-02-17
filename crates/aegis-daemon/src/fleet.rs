//! Fleet: manages all agent slots, handles spawning, stopping, and health checks.
//!
//! The fleet is the central data structure of the daemon. It owns all agent slots
//! and provides methods for lifecycle management (start, stop, restart) and
//! periodic health checks (tick).

use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;

use tracing::{error, info, warn};
use uuid::Uuid;

use aegis_pilot::supervisor::SupervisorCommand;
use aegis_types::daemon::{AgentSlotConfig, AgentStatus, AgentToolConfig, DaemonConfig, RestartPolicy};
use aegis_types::AegisConfig;

use crate::lifecycle;
use crate::slot::{AgentSlot, PendingPromptInfo};

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
        let (output_tx, output_rx) = mpsc::channel::<String>();

        // Create command channel: fleet sends commands, supervisor receives
        let (cmd_tx, cmd_rx) = mpsc::channel();
        // Create update channel: supervisor sends updates, fleet receives
        let (upd_tx, upd_rx) = mpsc::channel();

        slot.output_rx = Some(output_rx);
        slot.command_tx = Some(cmd_tx);
        slot.update_rx = Some(upd_rx);
        slot.pending_prompts.clear();
        slot.attention_needed = false;
        slot.started_at = Some(std::time::Instant::now());

        let handle = thread::Builder::new()
            .name(format!("agent-{name}"))
            .spawn(move || {
                lifecycle::run_agent_slot(&slot_config, &aegis_config, output_tx, Some(upd_tx), Some(cmd_rx))
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

    /// Send text to an agent's PTY stdin via the supervisor command channel.
    pub fn send_to_agent(&self, name: &str, text: &str) -> Result<(), String> {
        let slot = self.slots.get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        let tx = slot.command_tx.as_ref()
            .ok_or_else(|| format!("agent '{name}' has no command channel (not running?)"))?;

        tx.send(SupervisorCommand::SendInput { text: text.to_string() })
            .map_err(|_| format!("command channel closed for '{name}' (agent may have exited)"))
    }

    /// Approve a pending permission request for an agent.
    pub fn approve_request(&self, name: &str, request_id: Uuid) -> Result<(), String> {
        let slot = self.slots.get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        let tx = slot.command_tx.as_ref()
            .ok_or_else(|| format!("agent '{name}' has no command channel (not running?)"))?;

        tx.send(SupervisorCommand::Approve { request_id })
            .map_err(|_| format!("command channel closed for '{name}'"))
    }

    /// Deny a pending permission request for an agent.
    pub fn deny_request(&self, name: &str, request_id: Uuid) -> Result<(), String> {
        let slot = self.slots.get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        let tx = slot.command_tx.as_ref()
            .ok_or_else(|| format!("agent '{name}' has no command channel (not running?)"))?;

        tx.send(SupervisorCommand::Deny { request_id })
            .map_err(|_| format!("command channel closed for '{name}'"))
    }

    /// Nudge a stalled agent with an optional message.
    pub fn nudge_agent(&self, name: &str, message: Option<String>) -> Result<(), String> {
        let slot = self.slots.get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        let tx = slot.command_tx.as_ref()
            .ok_or_else(|| format!("agent '{name}' has no command channel (not running?)"))?;

        tx.send(SupervisorCommand::Nudge { message })
            .map_err(|_| format!("command channel closed for '{name}'"))
    }

    /// List pending permission prompts for an agent.
    pub fn list_pending(&self, name: &str) -> Result<&[PendingPromptInfo], String> {
        let slot = self.slots.get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        Ok(&slot.pending_prompts)
    }

    /// Whether an agent needs human attention (max nudges exceeded).
    pub fn agent_attention_needed(&self, name: &str) -> bool {
        self.slots.get(name)
            .is_some_and(|s| s.attention_needed)
    }

    /// Count of pending prompts for an agent.
    pub fn agent_pending_count(&self, name: &str) -> usize {
        self.slots.get(name)
            .map(|s| s.pending_prompts.len())
            .unwrap_or(0)
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
    /// drain output channels, and process supervisor updates.
    pub fn tick(&mut self) {
        let names: Vec<String> = self.slots.keys().cloned().collect();

        for name in names {
            if let Some(slot) = self.slots.get(&name) {
                // Drain output for all agents
                slot.drain_output();
            }

            // Drain rich updates (pending prompts, stats, attention flags)
            if let Some(slot) = self.slots.get_mut(&name) {
                slot.drain_updates();
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

    /// Get agent names sorted alphabetically (for stable display order).
    pub fn agent_names_sorted(&self) -> Vec<String> {
        let mut names: Vec<String> = self.slots.keys().cloned().collect();
        names.sort();
        names
    }

    /// Add a new agent slot at runtime.
    pub fn add_agent(&mut self, config: AgentSlotConfig) {
        let slot = AgentSlot::new(config.clone());
        self.slots.insert(config.name.clone(), slot);
    }

    /// Restart a specific agent (stop then start).
    pub fn restart_agent(&mut self, name: &str) {
        self.stop_agent(name);
        self.start_agent(name);
    }

    /// Get the tool type name for an agent.
    pub fn agent_tool_name(&self, name: &str) -> Option<String> {
        self.slots.get(name).map(|s| match &s.config.tool {
            AgentToolConfig::ClaudeCode { .. } => "ClaudeCode".to_string(),
            AgentToolConfig::Codex { .. } => "Codex".to_string(),
            AgentToolConfig::OpenClaw { .. } => "OpenClaw".to_string(),
            AgentToolConfig::Cursor { .. } => "Cursor".to_string(),
            AgentToolConfig::Custom { command, .. } => format!("Custom({command})"),
        })
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

    #[test]
    fn send_to_agent_no_channel() {
        // Agent exists but has no command channel (not started)
        let config = test_daemon_config(vec![test_slot_config("idle")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        let err = fleet.send_to_agent("idle", "hello").unwrap_err();
        assert!(err.contains("no command channel"));
    }

    #[test]
    fn send_to_agent_with_channel() {
        let config = test_daemon_config(vec![test_slot_config("active")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        // Manually wire up a command channel
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        fleet.slots.get_mut("active").unwrap().command_tx = Some(cmd_tx);

        fleet.send_to_agent("active", "hello world").unwrap();

        // Verify the command was sent
        let cmd = cmd_rx.try_recv().unwrap();
        match cmd {
            aegis_pilot::supervisor::SupervisorCommand::SendInput { text } => {
                assert_eq!(text, "hello world");
            }
            _ => panic!("expected SendInput"),
        }
    }

    #[test]
    fn approve_request_dispatches_command() {
        let config = test_daemon_config(vec![test_slot_config("agent")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        fleet.slots.get_mut("agent").unwrap().command_tx = Some(cmd_tx);

        let id = uuid::Uuid::new_v4();
        fleet.approve_request("agent", id).unwrap();

        let cmd = cmd_rx.try_recv().unwrap();
        match cmd {
            aegis_pilot::supervisor::SupervisorCommand::Approve { request_id } => {
                assert_eq!(request_id, id);
            }
            _ => panic!("expected Approve"),
        }
    }

    #[test]
    fn deny_request_dispatches_command() {
        let config = test_daemon_config(vec![test_slot_config("agent")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        fleet.slots.get_mut("agent").unwrap().command_tx = Some(cmd_tx);

        let id = uuid::Uuid::new_v4();
        fleet.deny_request("agent", id).unwrap();

        let cmd = cmd_rx.try_recv().unwrap();
        match cmd {
            aegis_pilot::supervisor::SupervisorCommand::Deny { request_id } => {
                assert_eq!(request_id, id);
            }
            _ => panic!("expected Deny"),
        }
    }

    #[test]
    fn nudge_agent_dispatches_command() {
        let config = test_daemon_config(vec![test_slot_config("agent")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        fleet.slots.get_mut("agent").unwrap().command_tx = Some(cmd_tx);

        fleet.nudge_agent("agent", Some("wake up".into())).unwrap();

        let cmd = cmd_rx.try_recv().unwrap();
        match cmd {
            aegis_pilot::supervisor::SupervisorCommand::Nudge { message } => {
                assert_eq!(message, Some("wake up".into()));
            }
            _ => panic!("expected Nudge"),
        }
    }

    #[test]
    fn list_pending_empty() {
        let config = test_daemon_config(vec![test_slot_config("agent")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        let pending = fleet.list_pending("agent").unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn list_pending_unknown_agent() {
        let config = test_daemon_config(vec![]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        assert!(fleet.list_pending("ghost").is_err());
    }

    #[test]
    fn agent_pending_count_and_attention() {
        let config = test_daemon_config(vec![test_slot_config("agent")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        assert_eq!(fleet.agent_pending_count("agent"), 0);
        assert!(!fleet.agent_attention_needed("agent"));
    }

    #[test]
    fn agent_names_sorted_returns_alphabetical() {
        let config = test_daemon_config(vec![
            test_slot_config("charlie"),
            test_slot_config("alpha"),
            test_slot_config("bravo"),
        ]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        let names = fleet.agent_names_sorted();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn add_agent_increases_count() {
        let config = test_daemon_config(vec![test_slot_config("existing")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        assert_eq!(fleet.agent_count(), 1);
        fleet.add_agent(test_slot_config("new-agent"));
        assert_eq!(fleet.agent_count(), 2);
        assert!(fleet.agent_status("new-agent").is_some());
    }

    #[test]
    fn agent_tool_name_variants() {
        let mut agents = vec![test_slot_config("claude")];
        agents[0].tool = AgentToolConfig::ClaudeCode {
            skip_permissions: false,
            one_shot: false,
            extra_args: vec![],
        };
        let config = test_daemon_config(agents);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let fleet = Fleet::new(&config, aegis);

        assert_eq!(fleet.agent_tool_name("claude"), Some("ClaudeCode".to_string()));
        assert_eq!(fleet.agent_tool_name("nonexistent"), None);
    }
}
