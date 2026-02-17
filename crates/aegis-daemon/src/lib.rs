//! Aegis daemon: persistent multi-agent lifecycle management.
//!
//! The daemon runs as a single persistent process managing a "fleet" of
//! supervised AI agent processes. Each agent runs in its own thread with
//! its own PTY, policy engine, adapter, and audit session.
//!
//! # Architecture
//!
//! - [`fleet::Fleet`]: owns all agent slots, handles spawning/stopping
//! - [`slot::AgentSlot`]: runtime state for one agent
//! - [`lifecycle`]: per-agent thread body (PTY + supervisor + audit)
//! - [`control`]: Unix socket server for external control
//! - [`persistence`]: launchd integration, PID files, caffeinate
//! - [`state`]: crash recovery via persistent state.json

pub mod control;
pub mod fleet;
pub mod lifecycle;
pub mod persistence;
pub mod slot;
pub mod state;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::info;

use aegis_control::daemon::{
    AgentDetail, AgentSummary, DaemonCommand, DaemonPing, DaemonResponse,
    PendingPromptSummary,
};
use aegis_types::daemon::{AgentSlotConfig, AgentStatus, DaemonConfig};
use aegis_types::AegisConfig;

use crate::control::DaemonCmdRx;
use crate::fleet::Fleet;
use crate::state::DaemonState;

/// The daemon runtime: main loop managing the fleet and control plane.
pub struct DaemonRuntime {
    /// Fleet of managed agents.
    pub fleet: Fleet,
    /// Daemon configuration.
    pub config: DaemonConfig,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// When the daemon started.
    pub started_at: Instant,
}

impl DaemonRuntime {
    /// Create a new daemon runtime from configuration.
    pub fn new(config: DaemonConfig, aegis_config: AegisConfig) -> Self {
        let fleet = Fleet::new(&config, aegis_config);

        Self {
            fleet,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
        }
    }

    /// Run the daemon main loop. Blocks until shutdown is signaled.
    ///
    /// 1. Write PID file
    /// 2. Recover from previous crash (if applicable)
    /// 3. Start control socket server
    /// 4. Start all enabled agents
    /// 5. Enter tick loop (health checks, restart logic, command dispatch)
    /// 6. On shutdown: stop all agents, clean up
    pub fn run(&mut self) -> Result<(), String> {
        // Write PID file
        let _pid_path = persistence::write_pid_file()?;

        // Check for previous state and recover
        if let Some(prev_state) = DaemonState::load() {
            state::recover_from_crash(&prev_state);
        }

        // Optionally start caffeinate
        let _caffeinate_pid = if self.config.persistence.prevent_sleep {
            Some(persistence::start_caffeinate()?)
        } else {
            None
        };

        // Start control socket server
        let mut cmd_rx = control::spawn_control_server(
            self.config.control.socket_path.clone(),
            Arc::clone(&self.shutdown),
        );

        info!(
            agents = self.fleet.agent_count(),
            socket = %self.config.control.socket_path.display(),
            "daemon starting"
        );

        // Start all enabled agents
        self.fleet.start_all();

        // Main loop
        let tick_interval = Duration::from_secs(1);
        let state_save_interval = Duration::from_secs(30);
        let mut last_state_save = Instant::now();

        while !self.shutdown.load(Ordering::Relaxed) {
            // Drain pending control commands (non-blocking)
            self.drain_commands(&mut cmd_rx);

            // Tick the fleet (check for exits, apply restart policies)
            self.fleet.tick();

            // Periodically save state
            if last_state_save.elapsed() >= state_save_interval {
                self.save_state();
                last_state_save = Instant::now();
            }

            // Sleep until next tick
            std::thread::sleep(tick_interval);
        }

        info!("daemon shutting down");

        // Save final state
        self.save_state();

        // Clean up
        persistence::remove_pid_file();
        DaemonState::remove();

        info!("daemon shutdown complete");
        Ok(())
    }

    /// Drain all pending commands from the control socket.
    fn drain_commands(&mut self, cmd_rx: &mut DaemonCmdRx) {
        while let Ok((cmd, reply_tx)) = cmd_rx.try_recv() {
            let response = self.handle_command(cmd);
            let _ = reply_tx.send(response);
        }
    }

    /// Handle a single daemon control command.
    fn handle_command(&mut self, cmd: DaemonCommand) -> DaemonResponse {
        match cmd {
            DaemonCommand::Ping => {
                let ping = DaemonPing {
                    uptime_secs: self.uptime_secs(),
                    agent_count: self.fleet.agent_count(),
                    running_count: self.fleet.running_count(),
                    daemon_pid: std::process::id(),
                };
                match serde_json::to_value(&ping) {
                    Ok(data) => DaemonResponse::ok_with_data("pong", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::ListAgents => {
                let summaries: Vec<AgentSummary> = self
                    .fleet
                    .agent_names_sorted()
                    .iter()
                    .filter_map(|name| {
                        let status = self.fleet.agent_status(name)?.clone();
                        let tool = self.fleet.agent_tool_name(name).unwrap_or_default();
                        let config = self.fleet.agent_config(name)?;
                        Some(AgentSummary {
                            name: name.clone(),
                            status,
                            tool,
                            working_dir: config.working_dir.to_string_lossy().into_owned(),
                            restart_count: self
                                .fleet
                                .slot(name)
                                .map(|s| s.restart_count)
                                .unwrap_or(0),
                            pending_count: self.fleet.agent_pending_count(name),
                            attention_needed: self.fleet.agent_attention_needed(name),
                        })
                    })
                    .collect();
                match serde_json::to_value(&summaries) {
                    Ok(data) => DaemonResponse::ok_with_data("agents listed", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::AgentStatus { ref name } => {
                let Some(slot) = self.fleet.slot(name) else {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                };
                let detail = AgentDetail {
                    name: name.clone(),
                    status: slot.status.clone(),
                    tool: self.fleet.agent_tool_name(name).unwrap_or_default(),
                    working_dir: slot.config.working_dir.to_string_lossy().into_owned(),
                    restart_count: slot.restart_count,
                    pid: match &slot.status {
                        AgentStatus::Running { pid } => Some(*pid),
                        _ => None,
                    },
                    uptime_secs: slot.started_at.map(|t| t.elapsed().as_secs()),
                    session_id: None,
                    task: slot.config.task.clone(),
                    enabled: slot.config.enabled,
                    pending_count: slot.pending_prompts.len(),
                    attention_needed: slot.attention_needed,
                };
                match serde_json::to_value(&detail) {
                    Ok(data) => DaemonResponse::ok_with_data("agent detail", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::AgentOutput { ref name, lines } => {
                let line_count = lines.unwrap_or(50);
                match self.fleet.agent_output(name, line_count) {
                    Ok(output) => match serde_json::to_value(&output) {
                        Ok(data) => DaemonResponse::ok_with_data("output", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::StartAgent { ref name } => {
                if self.fleet.agent_status(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                self.fleet.start_agent(name);
                DaemonResponse::ok(format!("agent '{name}' starting"))
            }

            DaemonCommand::StopAgent { ref name } => {
                if self.fleet.agent_status(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                self.fleet.stop_agent(name);
                DaemonResponse::ok(format!("agent '{name}' stopped"))
            }

            DaemonCommand::RestartAgent { ref name } => {
                if self.fleet.agent_status(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                self.fleet.restart_agent(name);
                DaemonResponse::ok(format!("agent '{name}' restarted"))
            }

            DaemonCommand::SendToAgent { ref name, ref text } => {
                match self.fleet.send_to_agent(name, text) {
                    Ok(()) => DaemonResponse::ok(format!("sent to '{name}'")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::AddAgent { ref config, start } => {
                let name = config.name.clone();
                if self.fleet.agent_status(&name).is_some() {
                    return DaemonResponse::error(format!("agent '{name}' already exists"));
                }
                let slot_config: AgentSlotConfig = *config.clone();
                self.fleet.add_agent(slot_config.clone());
                // Also add to the runtime config so it persists
                self.config.agents.push(slot_config);
                if let Err(e) = self.persist_config() {
                    return DaemonResponse::error(format!("agent added but failed to save config: {e}"));
                }
                if start {
                    self.fleet.start_agent(&name);
                }
                DaemonResponse::ok(format!("agent '{name}' added"))
            }

            DaemonCommand::ApproveRequest { ref name, ref request_id } => {
                let id = match uuid::Uuid::parse_str(request_id) {
                    Ok(id) => id,
                    Err(e) => return DaemonResponse::error(format!("invalid request_id: {e}")),
                };
                match self.fleet.approve_request(name, id) {
                    Ok(()) => DaemonResponse::ok(format!("approved request {request_id} for '{name}'")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::DenyRequest { ref name, ref request_id } => {
                let id = match uuid::Uuid::parse_str(request_id) {
                    Ok(id) => id,
                    Err(e) => return DaemonResponse::error(format!("invalid request_id: {e}")),
                };
                match self.fleet.deny_request(name, id) {
                    Ok(()) => DaemonResponse::ok(format!("denied request {request_id} for '{name}'")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::NudgeAgent { ref name, ref message } => {
                match self.fleet.nudge_agent(name, message.clone()) {
                    Ok(()) => DaemonResponse::ok(format!("nudged '{name}'")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::ListPending { ref name } => {
                match self.fleet.list_pending(name) {
                    Ok(pending) => {
                        let summaries: Vec<PendingPromptSummary> = pending
                            .iter()
                            .map(|p| PendingPromptSummary {
                                request_id: p.request_id.to_string(),
                                raw_prompt: p.raw_prompt.clone(),
                                age_secs: p.received_at.elapsed().as_secs(),
                            })
                            .collect();
                        match serde_json::to_value(&summaries) {
                            Ok(data) => DaemonResponse::ok_with_data("pending prompts", data),
                            Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                        }
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::Shutdown => {
                self.request_shutdown();
                DaemonResponse::ok("shutdown initiated")
            }
        }
    }

    /// Signal the daemon to shut down.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Get the shutdown flag for external signal handlers.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Daemon uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Persist the current daemon config to daemon.toml.
    fn persist_config(&self) -> Result<(), String> {
        let toml_str = self.config.to_toml().map_err(|e| e.to_string())?;
        let config_path = aegis_types::daemon::daemon_config_path();
        std::fs::write(&config_path, toml_str).map_err(|e| e.to_string())
    }

    /// Save current state to disk.
    fn save_state(&self) {
        let mut daemon_state = DaemonState::new(std::process::id());
        daemon_state.started_at = chrono::Utc::now()
            - chrono::Duration::seconds(self.started_at.elapsed().as_secs() as i64);

        for name in self.fleet.agent_names() {
            if let Some(slot) = self.fleet.slot(&name) {
                daemon_state.agents.push(state::AgentState {
                    name: name.clone(),
                    was_running: slot.is_thread_alive(),
                    session_id: None,
                    restart_count: slot.restart_count,
                });
            }
        }

        if let Err(e) = daemon_state.save() {
            tracing::warn!(error = e, "failed to save daemon state");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::daemon::{
        AgentSlotConfig, AgentToolConfig, DaemonControlConfig, PersistenceConfig, RestartPolicy,
    };
    use std::path::PathBuf;

    fn test_runtime(agents: Vec<AgentSlotConfig>) -> DaemonRuntime {
        let config = DaemonConfig {
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            alerts: vec![],
            agents,
            channel: None,
        };
        let aegis_config = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        DaemonRuntime::new(config, aegis_config)
    }

    fn test_agent(name: &str) -> AgentSlotConfig {
        AgentSlotConfig {
            name: name.to_string(),
            tool: AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: vec![],
            },
            working_dir: PathBuf::from("/tmp"),
            task: Some("test task".into()),
            pilot: None,
            restart: RestartPolicy::OnFailure,
            max_restarts: 5,
            enabled: true,
        }
    }

    #[test]
    fn daemon_runtime_creation() {
        let runtime = test_runtime(vec![]);
        assert_eq!(runtime.fleet.agent_count(), 0);
        assert!(!runtime.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn shutdown_flag() {
        let runtime = test_runtime(vec![]);
        let flag = runtime.shutdown_flag();
        assert!(!flag.load(Ordering::Relaxed));
        runtime.request_shutdown();
        assert!(flag.load(Ordering::Relaxed));
    }

    #[test]
    fn handle_command_ping() {
        let mut runtime = test_runtime(vec![test_agent("a1"), test_agent("a2")]);
        let resp = runtime.handle_command(DaemonCommand::Ping);
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let ping: DaemonPing = serde_json::from_value(data).unwrap();
        assert_eq!(ping.agent_count, 2);
        assert_eq!(ping.running_count, 0);
    }

    #[test]
    fn handle_command_list_agents() {
        let mut runtime = test_runtime(vec![test_agent("beta"), test_agent("alpha")]);
        let resp = runtime.handle_command(DaemonCommand::ListAgents);
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let agents: Vec<AgentSummary> = serde_json::from_value(data).unwrap();
        assert_eq!(agents.len(), 2);
        // Should be sorted alphabetically
        assert_eq!(agents[0].name, "alpha");
        assert_eq!(agents[1].name, "beta");
    }

    #[test]
    fn handle_command_agent_status_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::AgentStatus {
            name: "nonexistent".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("unknown"));
    }

    #[test]
    fn handle_command_agent_status_known() {
        let mut runtime = test_runtime(vec![test_agent("claude-1")]);
        let resp = runtime.handle_command(DaemonCommand::AgentStatus {
            name: "claude-1".into(),
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let detail: AgentDetail = serde_json::from_value(data).unwrap();
        assert_eq!(detail.name, "claude-1");
        assert_eq!(detail.tool, "ClaudeCode");
        assert!(detail.enabled);
        assert_eq!(detail.task, Some("test task".into()));
    }

    #[test]
    fn handle_command_start_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::StartAgent {
            name: "nope".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_stop_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::StopAgent {
            name: "nope".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_shutdown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::Shutdown);
        assert!(resp.ok);
        assert!(runtime.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn handle_command_agent_output_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::AgentOutput {
            name: "nope".into(),
            lines: Some(10),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_agent_output_empty() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::AgentOutput {
            name: "a1".into(),
            lines: Some(10),
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let lines: Vec<String> = serde_json::from_value(data).unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn handle_command_approve_unknown_agent() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::ApproveRequest {
            name: "ghost".into(),
            request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_approve_invalid_uuid() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ApproveRequest {
            name: "a1".into(),
            request_id: "not-a-uuid".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("invalid request_id"));
    }

    #[test]
    fn handle_command_deny_unknown_agent() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::DenyRequest {
            name: "ghost".into(),
            request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_nudge_unknown_agent() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::NudgeAgent {
            name: "ghost".into(),
            message: None,
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_list_pending_empty() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ListPending {
            name: "a1".into(),
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let pending: Vec<PendingPromptSummary> = serde_json::from_value(data).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn handle_command_list_pending_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::ListPending {
            name: "ghost".into(),
        });
        assert!(!resp.ok);
    }
}
