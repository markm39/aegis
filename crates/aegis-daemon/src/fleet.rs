//! Fleet: manages all agent slots, handles spawning, stopping, and health checks.
//!
//! The fleet is the central data structure of the daemon. It owns all agent slots
//! and provides methods for lifecycle management (start, stop, restart) and
//! periodic health checks (tick).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{error, info, warn};
use uuid::Uuid;

use aegis_pilot::supervisor::SupervisorCommand;
use aegis_types::daemon::{AgentSlotConfig, AgentStatus, AgentToolConfig, DaemonConfig, RestartPolicy};
use aegis_types::AegisConfig;

use crate::lifecycle;
use crate::slot::{AgentSlot, NotableEvent, PendingPromptInfo};

/// Fleet of managed agent slots.
pub struct Fleet {
    /// Slots indexed by agent name.
    slots: HashMap<String, AgentSlot>,
    /// Default Aegis configuration (shared across agents that don't override).
    default_aegis_config: AegisConfig,
    /// Fleet-wide goal that gets composed into every agent's prompt.
    pub fleet_goal: Option<String>,
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
            fleet_goal: config.goal.clone(),
        }
    }

    /// Stop all running agents. Used during daemon shutdown to prevent
    /// orphaned processes.
    ///
    /// Sends SIGTERM to all agents first (parallel), then waits for each.
    /// This is faster than stopping one-at-a-time since all agents get
    /// the signal simultaneously.
    pub fn stop_all(&mut self) {
        // Phase 1: send SIGTERM to all running agents.
        let running: Vec<String> = self
            .slots
            .iter()
            .filter(|(_, s)| s.is_thread_alive())
            .map(|(name, _)| name.clone())
            .collect();

        for name in &running {
            if let Some(slot) = self.slots.get(name) {
                let pid = slot.child_pid.load(Ordering::Acquire);
                if pid > 0 {
                    info!(agent = name, pid, "stop_all: sending SIGTERM");
                    if let Ok(raw_pid) = i32::try_from(pid) {
                        let _ = signal::kill(Pid::from_raw(raw_pid), Signal::SIGTERM);
                    }
                }
            }
        }

        // Phase 2: wait for each to finish (stop_agent handles escalation).
        for name in running {
            self.stop_agent(&name);
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

        if !slot.config.enabled {
            warn!(agent = name, "start_agent: agent is disabled, use enable first");
            return;
        }

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
        slot.stall_attention = false;
        slot.backoff_until = None;
        slot.child_pid.store(0, Ordering::Release);
        slot.started_at = Some(std::time::Instant::now());

        let fleet_goal = self.fleet_goal.clone();
        let child_pid = slot.child_pid.clone();
        // Clear and share session_id for state persistence
        *slot.session_id.lock().unwrap() = None;
        let shared_session_id = slot.session_id.clone();

        let handle = thread::Builder::new()
            .name(format!("agent-{name}"))
            .spawn(move || {
                lifecycle::run_agent_slot(&slot_config, &aegis_config, fleet_goal.as_deref(), output_tx, Some(upd_tx), Some(cmd_rx), child_pid, shared_session_id)
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
    /// Sends SIGTERM to the child process, waits up to 5 seconds for
    /// graceful exit, then escalates to SIGKILL. This prevents
    /// `handle.join()` from blocking indefinitely on hung processes.
    pub fn stop_agent(&mut self, name: &str) {
        let slot = match self.slots.get_mut(name) {
            Some(s) => s,
            None => {
                warn!(agent = name, "stop_agent: unknown agent");
                return;
            }
        };

        // Send SIGTERM to the child process if we know the PID.
        let pid = slot.child_pid.load(Ordering::Acquire);
        let raw_pid = i32::try_from(pid).ok().filter(|&p| p > 0);
        if let Some(p) = raw_pid {
            info!(agent = name, pid, "sending SIGTERM to child");
            let _ = signal::kill(Pid::from_raw(p), Signal::SIGTERM);
        }

        if let Some(handle) = slot.thread_handle.take() {
            info!(agent = name, "waiting for agent thread (5s timeout)");

            // Poll is_finished() with a 5-second timeout for graceful shutdown.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline && !handle.is_finished() {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            if !handle.is_finished() {
                if let Some(p) = raw_pid {
                    warn!(agent = name, pid, "SIGTERM timeout, sending SIGKILL");
                    let _ = signal::kill(Pid::from_raw(p), Signal::SIGKILL);
                }

                // Give it another 2 seconds after SIGKILL.
                let kill_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                while std::time::Instant::now() < kill_deadline && !handle.is_finished() {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }

            if handle.is_finished() {
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
            } else {
                // Thread is truly stuck (shouldn't happen after SIGKILL).
                // Leak the handle rather than blocking the daemon forever.
                error!(agent = name, "agent thread did not exit after SIGKILL, detaching");
                slot.status = AgentStatus::Failed {
                    exit_code: -1,
                    restart_count: slot.restart_count,
                };
            }
        }

        slot.started_at = None;
    }

    /// Enable an agent slot so it can be started.
    pub fn enable_agent(&mut self, name: &str) -> Result<(), String> {
        let slot = self.slots.get_mut(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        if slot.config.enabled {
            return Err(format!("agent '{name}' is already enabled"));
        }

        slot.config.enabled = true;
        if matches!(slot.status, AgentStatus::Disabled) {
            slot.status = AgentStatus::Pending;
        }
        info!(agent = name, "agent enabled");
        Ok(())
    }

    /// Disable an agent slot. Stops it if running and prevents restart.
    pub fn disable_agent(&mut self, name: &str) -> Result<(), String> {
        let slot = self.slots.get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        if !slot.config.enabled {
            return Err(format!("agent '{name}' is already disabled"));
        }

        let is_alive = slot.is_thread_alive();

        // Mark disabled first (second lookup needed: stop_agent borrows &mut self)
        if let Some(slot) = self.slots.get_mut(name) {
            slot.config.enabled = false;
        }

        // Stop if currently running
        if is_alive {
            self.stop_agent(name);
        }

        if let Some(slot) = self.slots.get_mut(name) {
            slot.status = AgentStatus::Disabled;
            slot.backoff_until = None;
        }
        info!(agent = name, "agent disabled");
        Ok(())
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
    /// drain output channels, process supervisor updates, and restart
    /// agents whose backoff period has expired.
    ///
    /// Returns notable events tagged with agent names. These should be forwarded
    /// to the notification channel (Telegram) if one is configured.
    pub fn tick(&mut self) -> Vec<(String, NotableEvent)> {
        let names: Vec<String> = self.slots.keys().cloned().collect();
        let mut all_events = Vec::new();
        let mut backoff_ready: Vec<String> = Vec::new();

        for name in &names {
            if let Some(slot) = self.slots.get(name) {
                // Drain output for all agents
                slot.drain_output();
            }

            // Drain rich updates (pending prompts, stats, attention flags)
            if let Some(slot) = self.slots.get_mut(name) {
                let events = slot.drain_updates();
                for event in events {
                    all_events.push((name.clone(), event));
                }
            }

            // Check if the thread has finished
            let needs_join = self
                .slots
                .get(name)
                .is_some_and(|s| {
                    s.thread_handle.as_ref().is_some_and(|h| h.is_finished())
                });

            if needs_join {
                self.tick_slot(name);
            }

            // Check if backoff has expired and agent should be restarted
            let ready = self
                .slots
                .get(name)
                .is_some_and(|s| {
                    s.backoff_until.is_some_and(|t| std::time::Instant::now() >= t)
                });

            if ready {
                backoff_ready.push(name.clone());
            }
        }

        // Restart agents whose backoff has expired (outside the borrow loop)
        for name in backoff_ready {
            if let Some(slot) = self.slots.get_mut(&name) {
                slot.backoff_until = None;
                // Don't restart disabled agents
                if !slot.config.enabled {
                    continue;
                }
            }
            info!(agent = %name, "backoff expired, restarting agent");
            self.start_agent(&name);
        }

        all_events
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
    ///
    /// If the agent crashed quickly (ran less than 30 seconds), applies
    /// exponential backoff to prevent tight crash loops. The backoff delay
    /// is 2^restart_count seconds, capped at 60 seconds. The agent enters
    /// `Crashed` status and `tick()` will start it once the backoff expires.
    fn handle_agent_exit(&mut self, name: &str, exit_code: i32) {
        let slot = match self.slots.get_mut(name) {
            Some(s) => s,
            None => return,
        };

        // How long did the agent actually run?
        let run_duration = slot.started_at.map(|t| t.elapsed());
        slot.started_at = None;

        // Never restart a disabled agent.
        if !slot.config.enabled {
            slot.status = AgentStatus::Disabled;
            return;
        }

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

        // If the agent ran for less than 30 seconds, apply exponential backoff
        // to prevent crash loops from spinning hot.
        let ran_briefly = run_duration.is_some_and(|d| d.as_secs() < 30);
        if ran_briefly {
            let delay_secs = 1u64
                .checked_shl(slot.restart_count)
                .map(|d| std::cmp::min(d, 60))
                .unwrap_or(60);
            let backoff_until = std::time::Instant::now()
                + std::time::Duration::from_secs(delay_secs);
            info!(
                agent = name,
                restart_count = slot.restart_count,
                delay_secs,
                "agent crashed quickly, backing off before restart"
            );
            slot.backoff_until = Some(backoff_until);
            slot.status = AgentStatus::Crashed {
                exit_code,
                restart_in_secs: delay_secs,
            };
            return;
        }

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

    /// Get a mutable reference to a slot.
    pub fn slot_mut(&mut self, name: &str) -> Option<&mut AgentSlot> {
        self.slots.get_mut(name)
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

    /// Restore the restart count for an agent from a previous daemon state.
    ///
    /// Called during startup to carry restart counts across daemon restarts,
    /// ensuring `max_restarts` guards are enforced across the lifetime of
    /// the agent configuration (not just a single daemon process).
    pub fn restore_restart_count(&mut self, name: &str, count: u32) {
        if let Some(slot) = self.slots.get_mut(name) {
            slot.restart_count = count;
        }
    }

    /// Add a new agent slot at runtime.
    pub fn add_agent(&mut self, config: AgentSlotConfig) {
        let slot = AgentSlot::new(config.clone());
        self.slots.insert(config.name.clone(), slot);
    }

    /// Remove an agent slot. Stops it first if running.
    pub fn remove_agent(&mut self, name: &str) {
        self.stop_agent(name);
        self.slots.remove(name);
    }

    /// Update the stored config for an existing agent slot (without restarting).
    pub fn update_agent_config(&mut self, config: &AgentSlotConfig) {
        if let Some(slot) = self.slots.get_mut(&config.name) {
            slot.config = config.clone();
        }
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
            goal: None,
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
            role: None,
            agent_goal: None,
            context: None,
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
    fn remove_agent_decreases_count() {
        let config = test_daemon_config(vec![
            test_slot_config("a"),
            test_slot_config("b"),
        ]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        assert_eq!(fleet.agent_count(), 2);
        fleet.remove_agent("a");
        assert_eq!(fleet.agent_count(), 1);
        assert!(fleet.agent_status("a").is_none());
        assert!(fleet.agent_status("b").is_some());
    }

    #[test]
    fn remove_nonexistent_agent_is_safe() {
        let config = test_daemon_config(vec![test_slot_config("a")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        fleet.remove_agent("nonexistent");
        assert_eq!(fleet.agent_count(), 1);
    }

    #[test]
    fn update_agent_config_changes_stored_config() {
        let config = test_daemon_config(vec![test_slot_config("a")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        let mut updated = test_slot_config("a");
        updated.role = Some("specialist".into());
        updated.agent_goal = Some("test things".into());
        fleet.update_agent_config(&updated);

        let slot = fleet.slot("a").unwrap();
        assert_eq!(slot.config.role, Some("specialist".into()));
        assert_eq!(slot.config.agent_goal, Some("test things".into()));
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

    #[test]
    fn stop_all_is_safe_on_idle_fleet() {
        let config = test_daemon_config(vec![
            test_slot_config("a"),
            test_slot_config("b"),
        ]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        // stop_all on a fleet with no running agents should not panic
        fleet.stop_all();
        assert_eq!(fleet.agent_count(), 2);
    }

    #[test]
    fn handle_agent_exit_applies_backoff_for_quick_crash() {
        let mut slot_config = test_slot_config("crasher");
        slot_config.restart = RestartPolicy::Always;
        let config = test_daemon_config(vec![slot_config]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        // Simulate a very brief run (started just now)
        fleet.slots.get_mut("crasher").unwrap().started_at =
            Some(std::time::Instant::now());

        fleet.handle_agent_exit("crasher", 1);

        let slot = fleet.slot("crasher").unwrap();
        // Should be in Crashed state with backoff, not immediately restarted
        assert!(matches!(slot.status, AgentStatus::Crashed { .. }));
        assert!(slot.backoff_until.is_some());
        assert_eq!(slot.restart_count, 1);
    }

    #[test]
    fn handle_agent_exit_no_backoff_for_long_run() {
        let mut slot_config = test_slot_config("stable");
        slot_config.restart = RestartPolicy::Always;
        let config = test_daemon_config(vec![slot_config]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        // Simulate an agent that ran for a long time (started 60 seconds ago)
        fleet.slots.get_mut("stable").unwrap().started_at =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(60));

        fleet.handle_agent_exit("stable", 1);

        let slot = fleet.slot("stable").unwrap();
        // Should restart immediately (Running status from start_agent),
        // no backoff applied
        assert!(slot.backoff_until.is_none());
        assert_eq!(slot.restart_count, 1);
    }

    #[test]
    fn handle_agent_exit_respects_max_restarts() {
        let mut slot_config = test_slot_config("limited");
        slot_config.restart = RestartPolicy::Always;
        slot_config.max_restarts = 2;
        let config = test_daemon_config(vec![slot_config]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        // Set restart count to max
        fleet.slots.get_mut("limited").unwrap().restart_count = 2;
        fleet.slots.get_mut("limited").unwrap().started_at =
            Some(std::time::Instant::now());

        fleet.handle_agent_exit("limited", 1);

        let slot = fleet.slot("limited").unwrap();
        assert!(matches!(slot.status, AgentStatus::Failed { .. }));
    }

    #[test]
    fn enable_agent_transitions_from_disabled() {
        let mut slot_config = test_slot_config("off-agent");
        slot_config.enabled = false;
        let config = test_daemon_config(vec![slot_config]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        assert_eq!(fleet.agent_status("off-agent"), Some(&AgentStatus::Disabled));

        fleet.enable_agent("off-agent").unwrap();

        assert!(fleet.slot("off-agent").unwrap().config.enabled);
        assert_eq!(fleet.agent_status("off-agent"), Some(&AgentStatus::Pending));
    }

    #[test]
    fn enable_already_enabled_is_error() {
        let config = test_daemon_config(vec![test_slot_config("running-agent")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        assert!(fleet.enable_agent("running-agent").is_err());
    }

    #[test]
    fn disable_agent_sets_disabled_status() {
        let config = test_daemon_config(vec![test_slot_config("active")]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        fleet.disable_agent("active").unwrap();

        assert!(!fleet.slot("active").unwrap().config.enabled);
        assert_eq!(fleet.agent_status("active"), Some(&AgentStatus::Disabled));
    }

    #[test]
    fn disable_already_disabled_is_error() {
        let mut slot_config = test_slot_config("off");
        slot_config.enabled = false;
        let config = test_daemon_config(vec![slot_config]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        assert!(fleet.disable_agent("off").is_err());
    }

    #[test]
    fn enable_unknown_agent_is_error() {
        let config = test_daemon_config(vec![]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        assert!(fleet.enable_agent("ghost").is_err());
    }
}
