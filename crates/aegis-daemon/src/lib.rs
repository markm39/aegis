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
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use aegis_channel::ChannelInput;
use aegis_control::daemon::{
    AgentDetail, AgentSummary, DaemonCommand, DaemonPing, DaemonResponse,
    PendingPromptSummary, ToolUseVerdict,
};
use aegis_types::{Action, ActionKind, Decision};
use aegis_control::event::{EventStats, PilotEventKind, PilotWebhookEvent};
use aegis_types::daemon::{AgentSlotConfig, AgentStatus, DaemonConfig};
use aegis_types::AegisConfig;

use crate::control::DaemonCmdRx;
use crate::fleet::Fleet;
use crate::slot::NotableEvent;
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
    /// Sender for outbound events to the notification channel (Telegram).
    channel_tx: Option<mpsc::Sender<ChannelInput>>,
    /// Receiver for inbound commands from the notification channel.
    channel_cmd_rx: Option<mpsc::Receiver<DaemonCommand>>,
    /// Thread handle for the notification channel (detect panics).
    channel_thread: Option<std::thread::JoinHandle<()>>,
    /// Cedar policy engine for evaluating tool use requests from hooks.
    policy_engine: Option<aegis_policy::PolicyEngine>,
    /// Aegis config (needed for policy reload).
    aegis_config: AegisConfig,
}

impl DaemonRuntime {
    /// Create a new daemon runtime from configuration.
    pub fn new(config: DaemonConfig, aegis_config: AegisConfig) -> Self {
        let fleet = Fleet::new(&config, aegis_config.clone());

        // Load Cedar policy engine for hook-based tool use evaluation.
        // Only loads if a policy directory exists AND contains .cedar files.
        // When no policies are configured, hooks default to allow (matching
        // the --dangerously-skip-permissions baseline).
        let policy_engine = aegis_config
            .policy_paths
            .first()
            .filter(|dir| {
                dir.is_dir()
                    && std::fs::read_dir(dir)
                        .ok()
                        .map(|entries| {
                            entries.filter_map(|e| e.ok()).any(|e| {
                                e.path().extension().is_some_and(|ext| ext == "cedar")
                            })
                        })
                        .unwrap_or(false)
            })
            .and_then(|dir| match aegis_policy::PolicyEngine::new(dir, None) {
                Ok(engine) => {
                    info!(policy_dir = %dir.display(), "loaded Cedar policy engine for hooks");
                    Some(engine)
                }
                Err(e) => {
                    info!(?e, "no Cedar policy engine loaded (hooks will default to allow)");
                    None
                }
            });

        Self {
            fleet,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
            channel_tx: None,
            channel_cmd_rx: None,
            channel_thread: None,
            policy_engine,
            aegis_config,
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

        // Check for previous state and recover (close orphaned audit sessions)
        if let Some(prev_state) = DaemonState::load() {
            state::recover_from_crash(&prev_state, &self.aegis_config.ledger_path);
            // Restore restart counts from previous daemon instance so
            // max_restarts guards carry across daemon restarts.
            for agent_state in &prev_state.agents {
                self.fleet.restore_restart_count(&agent_state.name, agent_state.restart_count);
            }
        }

        // Optionally start caffeinate (keep handle alive until function returns;
        // caffeinate self-terminates via -w when daemon PID exits)
        let _caffeinate_child = if self.config.persistence.prevent_sleep {
            Some(persistence::start_caffeinate()?)
        } else {
            None
        };

        // Start control socket server
        let mut cmd_rx = control::spawn_control_server(
            self.config.control.socket_path.clone(),
            Arc::clone(&self.shutdown),
        )?;

        // Start notification channel (Telegram) if configured
        if let Some(ref channel_config) = self.config.channel {
            let (input_tx, input_rx) = mpsc::channel();
            let (feedback_tx, feedback_rx) = mpsc::channel();
            let config = channel_config.clone();

            match std::thread::Builder::new()
                .name("channel".to_string())
                .spawn(move || {
                    aegis_channel::run_fleet(config, input_rx, Some(feedback_tx));
                })
            {
                Ok(handle) => {
                    self.channel_tx = Some(input_tx);
                    self.channel_cmd_rx = Some(feedback_rx);
                    self.channel_thread = Some(handle);
                    info!("notification channel started");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to spawn notification channel thread");
                }
            }
        }

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

            // Drain inbound commands from the notification channel
            self.drain_channel_commands();

            // Check if the channel thread has exited (panic or unexpected exit)
            if let Some(handle) = &self.channel_thread {
                if handle.is_finished() {
                    let handle = self.channel_thread.take().unwrap();
                    match handle.join() {
                        Ok(()) => tracing::warn!("notification channel thread exited unexpectedly"),
                        Err(_) => tracing::error!("notification channel thread panicked"),
                    }
                    // Clear senders so we don't keep trying to send to a dead thread
                    self.channel_tx = None;
                    self.channel_cmd_rx = None;
                }
            }

            // Tick the fleet (check for exits, apply restart policies)
            let notable_events = self.fleet.tick();

            // Forward notable events to the notification channel
            self.forward_to_channel(notable_events);

            // Periodically save state
            if last_state_save.elapsed() >= state_save_interval {
                self.save_state();
                last_state_save = Instant::now();
            }

            // Sleep until next tick
            std::thread::sleep(tick_interval);
        }

        info!("daemon shutting down");

        // Stop all running agents to prevent orphaned processes
        self.fleet.stop_all();

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

    /// Drain inbound commands from the notification channel (Telegram).
    ///
    /// These commands were parsed from Telegram messages and converted to
    /// `DaemonCommand`s by the channel runner. We process them the same as
    /// control socket commands, and send the response back as a text message.
    fn drain_channel_commands(&mut self) {
        let cmds: Vec<DaemonCommand> = match &self.channel_cmd_rx {
            Some(rx) => rx.try_iter().collect(),
            None => return,
        };

        for cmd in cmds {
            info!(?cmd, "processing command from notification channel");
            let response = self.handle_command(cmd);

            // Send the response back to the user via the notification channel
            if let Some(tx) = &self.channel_tx {
                let text = if response.ok {
                    response.message
                } else {
                    format!("Error: {}", response.message)
                };
                let _ = tx.send(ChannelInput::TextMessage(text));
            }
        }
    }

    /// Forward notable fleet events to the notification channel.
    ///
    /// Converts `NotableEvent`s (from `drain_updates`) into `PilotWebhookEvent`s
    /// and sends them through the channel for Telegram delivery.
    fn forward_to_channel(&self, events: Vec<(String, NotableEvent)>) {
        let tx = match &self.channel_tx {
            Some(tx) => tx,
            None => return,
        };

        for (agent_name, event) in events {
            let kind = match event {
                NotableEvent::PendingPrompt { request_id, raw_prompt } => {
                    PilotEventKind::PendingApproval { request_id, raw_prompt }
                }
                NotableEvent::AttentionNeeded { nudge_count } => {
                    PilotEventKind::AttentionNeeded { nudge_count }
                }
                NotableEvent::StallNudge { nudge_count } => {
                    PilotEventKind::StallDetected { nudge_count, idle_secs: 0 }
                }
                NotableEvent::ChildExited { exit_code } => {
                    PilotEventKind::AgentExited { exit_code }
                }
            };

            // Build stats from the slot if available
            let stats = self
                .fleet
                .slot(&agent_name)
                .and_then(|s| s.pilot_stats.as_ref())
                .map(|ps| EventStats {
                    approved: ps.approved,
                    denied: ps.denied,
                    uncertain: ps.uncertain,
                    nudges: ps.nudges,
                    uptime_secs: self
                        .fleet
                        .slot(&agent_name)
                        .and_then(|s| s.uptime_secs())
                        .unwrap_or(0),
                })
                .unwrap_or_default();

            let webhook_event = PilotWebhookEvent::new(
                kind,
                &agent_name,
                0,    // PID not easily available from slot
                vec![],
                None,
                stats,
            );

            let input = ChannelInput::PilotEvent(webhook_event);
            if tx.send(input).is_err() {
                info!("notification channel closed, stopping event forwarding");
                break;
            }
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
                let now = std::time::Instant::now();
                let summaries: Vec<AgentSummary> = self
                    .fleet
                    .agent_names_sorted()
                    .iter()
                    .filter_map(|name| {
                        let slot = self.fleet.slot(name)?;
                        // Compute live remaining backoff for Crashed status
                        let status = match &slot.status {
                            AgentStatus::Crashed { exit_code, .. } => {
                                let remaining = slot.backoff_until
                                    .map(|t| t.saturating_duration_since(now).as_secs())
                                    .unwrap_or(0);
                                AgentStatus::Crashed {
                                    exit_code: *exit_code,
                                    restart_in_secs: remaining,
                                }
                            }
                            other => other.clone(),
                        };
                        let tool = self.fleet.agent_tool_name(name).unwrap_or_default();
                        let config = self.fleet.agent_config(name)?;
                        Some(AgentSummary {
                            name: name.clone(),
                            status,
                            tool,
                            working_dir: config.working_dir.to_string_lossy().into_owned(),
                            role: config.role.clone(),
                            restart_count: slot.restart_count,
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
                let now = std::time::Instant::now();
                let status = match &slot.status {
                    AgentStatus::Crashed { exit_code, .. } => {
                        let remaining = slot.backoff_until
                            .map(|t| t.saturating_duration_since(now).as_secs())
                            .unwrap_or(0);
                        AgentStatus::Crashed {
                            exit_code: *exit_code,
                            restart_in_secs: remaining,
                        }
                    }
                    other => other.clone(),
                };
                let detail = AgentDetail {
                    name: name.clone(),
                    status,
                    tool: self.fleet.agent_tool_name(name).unwrap_or_default(),
                    working_dir: slot.config.working_dir.to_string_lossy().into_owned(),
                    restart_count: slot.restart_count,
                    pid: match &slot.status {
                        AgentStatus::Running { pid } => Some(*pid),
                        _ => None,
                    },
                    uptime_secs: slot.started_at.map(|t| t.elapsed().as_secs()),
                    session_id: slot.session_id.lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .map(|u| u.to_string()),
                    role: slot.config.role.clone(),
                    agent_goal: slot.config.agent_goal.clone(),
                    context: slot.config.context.clone(),
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
                match self.fleet.agent_status(name) {
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                    Some(&AgentStatus::Disabled) => {
                        return DaemonResponse::error(
                            format!("agent '{name}' is disabled. Use enable first.")
                        );
                    }
                    _ => {}
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
                match self.fleet.restart_agent(name) {
                    Ok(()) => DaemonResponse::ok(format!("agent '{name}' restarted")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::SendToAgent { ref name, ref text } => {
                match self.fleet.send_to_agent(name, text) {
                    Ok(()) => DaemonResponse::ok(format!("sent to '{name}'")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::AddAgent { ref config, start } => {
                let name = config.name.clone();
                // Validate agent name to prevent path traversal and injection.
                if let Err(e) = aegis_types::validate_config_name(&name) {
                    return DaemonResponse::error(format!("invalid agent name: {e}"));
                }
                if self.fleet.agent_status(&name).is_some() {
                    return DaemonResponse::error(format!("agent '{name}' already exists"));
                }
                // Validate working directory at the API boundary for immediate feedback.
                if !config.working_dir.is_dir() {
                    return DaemonResponse::error(format!(
                        "working directory '{}' does not exist or is not a directory",
                        config.working_dir.display()
                    ));
                }
                let slot_config: AgentSlotConfig = *config.clone();

                // Persist first: build candidate config and write to disk
                // before mutating in-memory state.
                let mut candidate = self.config.clone();
                candidate.agents.push(slot_config.clone());
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to save config: {e}"));
                }

                // Disk write succeeded -- now safe to update memory
                self.config = candidate;
                self.fleet.add_agent(slot_config);
                if start {
                    self.fleet.start_agent(&name);
                }
                DaemonResponse::ok(format!("agent '{name}' added"))
            }

            DaemonCommand::RemoveAgent { ref name } => {
                if self.fleet.agent_status(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }

                // Persist first: build candidate config without the agent
                let mut candidate = self.config.clone();
                candidate.agents.retain(|a| a.name != *name);
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to save config: {e}"));
                }

                // Disk write succeeded -- now safe to update memory
                self.config = candidate;
                self.fleet.remove_agent(name); // remove_agent stops the agent internally
                DaemonResponse::ok(format!("agent '{name}' removed"))
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

            DaemonCommand::EvaluateToolUse { ref agent, ref tool_name, ref tool_input } => {
                // Interactive tools (AskUserQuestion, EnterPlanMode) would stall
                // a headless daemon-managed agent. Deny them with a contextual
                // prompt so the model proceeds autonomously.
                if is_interactive_tool(tool_name) {
                    let reason = compose_autonomy_prompt(
                        tool_name,
                        self.config.goal.as_deref(),
                        self.fleet.slot(agent).map(|s| &s.config),
                    );
                    info!(
                        agent = %agent, tool = %tool_name,
                        decision = "deny", reason = "interactive tool blocked",
                        "hook policy evaluation"
                    );
                    let tool_verdict = ToolUseVerdict {
                        decision: "deny".to_string(),
                        reason,
                    };
                    return match serde_json::to_value(&tool_verdict) {
                        Ok(data) => DaemonResponse::ok_with_data("deny", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    };
                }

                let action_kind = map_tool_use_to_action(tool_name, tool_input);
                let action = Action::new(agent.clone(), action_kind);

                let (decision_str, reason) = match &self.policy_engine {
                    Some(engine) => {
                        let verdict = engine.evaluate(&action);
                        let d = match verdict.decision {
                            Decision::Allow => "allow",
                            Decision::Deny => "deny",
                        };
                        (d.to_string(), verdict.reason)
                    }
                    None => {
                        // No policy engine loaded; default to allow
                        ("allow".to_string(), "no policy engine loaded".to_string())
                    }
                };

                info!(
                    agent = %agent, tool = %tool_name,
                    decision = %decision_str, reason = %reason,
                    "hook policy evaluation"
                );

                let tool_verdict = ToolUseVerdict {
                    decision: decision_str.clone(),
                    reason,
                };
                match serde_json::to_value(&tool_verdict) {
                    Ok(data) => DaemonResponse::ok_with_data(&decision_str, data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::FleetGoal { ref goal } => {
                match goal {
                    Some(new_goal) => {
                        let new_goal_val = if new_goal.is_empty() { None } else { Some(new_goal.clone()) };
                        let display = new_goal_val.clone().unwrap_or_else(|| "(cleared)".to_string());

                        // Persist first
                        let mut candidate = self.config.clone();
                        candidate.goal = new_goal_val.clone();
                        if let Err(e) = Self::persist_config_to_disk(&candidate) {
                            return DaemonResponse::error(format!("failed to persist goal: {e}"));
                        }

                        // Disk write succeeded -- update memory
                        self.config = candidate;
                        self.fleet.fleet_goal = new_goal_val;
                        DaemonResponse::ok(format!("fleet goal set: {display}"))
                    }
                    None => {
                        DaemonResponse::ok_with_data(
                            "fleet goal",
                            serde_json::json!({ "goal": self.config.goal }),
                        )
                    }
                }
            }

            DaemonCommand::UpdateAgentContext { ref name, ref role, ref agent_goal, ref context, ref task } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }

                // Build candidate config with updated context fields
                let mut candidate = self.config.clone();
                if let Some(cfg) = candidate.agents.iter_mut().find(|a| a.name == *name) {
                    if let Some(r) = role {
                        cfg.role = if r.is_empty() { None } else { Some(r.clone()) };
                    }
                    if let Some(g) = agent_goal {
                        cfg.agent_goal = if g.is_empty() { None } else { Some(g.clone()) };
                    }
                    if let Some(c) = context {
                        cfg.context = if c.is_empty() { None } else { Some(c.clone()) };
                    }
                    if let Some(t) = task {
                        cfg.task = if t.is_empty() { None } else { Some(t.clone()) };
                    }
                }

                // Persist first
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to persist context: {e}"));
                }

                // Disk write succeeded -- update memory (fleet slot + self.config)
                if let Some(slot) = self.fleet.slot_mut(name) {
                    if let Some(cfg) = candidate.agents.iter().find(|a| a.name == *name) {
                        slot.config.role.clone_from(&cfg.role);
                        slot.config.agent_goal.clone_from(&cfg.agent_goal);
                        slot.config.context.clone_from(&cfg.context);
                        slot.config.task.clone_from(&cfg.task);
                    }
                }
                self.config = candidate;
                DaemonResponse::ok(format!("context updated for '{name}' (takes effect on next restart)"))
            }

            DaemonCommand::GetAgentContext { ref name } => {
                let slot = match self.fleet.slot(name) {
                    Some(s) => s,
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                };
                let data = serde_json::json!({
                    "role": slot.config.role,
                    "agent_goal": slot.config.agent_goal,
                    "context": slot.config.context,
                    "task": slot.config.task,
                });
                DaemonResponse::ok_with_data("agent context", data)
            }

            DaemonCommand::EnableAgent { name } => {
                // Validate first
                match self.fleet.slot(&name) {
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                    Some(s) if s.config.enabled => {
                        return DaemonResponse::error(format!("agent '{name}' is already enabled"));
                    }
                    _ => {}
                }

                // Persist first
                let mut candidate = self.config.clone();
                if let Some(cfg) = candidate.agents.iter_mut().find(|a| a.name == name) {
                    cfg.enabled = true;
                }
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to persist enable: {e}"));
                }

                // Disk write succeeded -- update memory
                self.config = candidate;
                match self.fleet.enable_agent(&name) {
                    Ok(()) => DaemonResponse::ok(format!("agent '{name}' enabled")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::DisableAgent { name } => {
                // Validate first
                match self.fleet.slot(&name) {
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                    Some(s) if !s.config.enabled => {
                        return DaemonResponse::error(format!("agent '{name}' is already disabled"));
                    }
                    _ => {}
                }

                // Persist first
                let mut candidate = self.config.clone();
                if let Some(cfg) = candidate.agents.iter_mut().find(|a| a.name == name) {
                    cfg.enabled = false;
                }
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to persist disable: {e}"));
                }

                // Disk write succeeded -- update memory
                self.config = candidate;
                match self.fleet.disable_agent(&name) {
                    Ok(()) => DaemonResponse::ok(format!("agent '{name}' disabled")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::ReloadConfig => {
                self.reload_config()
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

    /// Reload configuration from daemon.toml.
    ///
    /// Adds new agents, updates config for existing agents, and removes
    /// agents no longer in the config file. Running agents are NOT
    /// automatically restarted -- config changes take effect on next start.
    fn reload_config(&mut self) -> DaemonResponse {
        let config_path = aegis_types::daemon::daemon_config_path();
        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => return DaemonResponse::error(format!("failed to read daemon.toml: {e}")),
        };
        let new_config = match DaemonConfig::from_toml(&content) {
            Ok(c) => c,
            Err(e) => return DaemonResponse::error(format!("failed to parse daemon.toml: {e}")),
        };

        let mut added = 0usize;
        let mut updated = 0usize;
        let mut removed = 0usize;

        // Collect current agent names
        let current_names: std::collections::HashSet<String> =
            self.fleet.agent_names().into_iter().collect();
        let new_names: std::collections::HashSet<String> =
            new_config.agents.iter().map(|a| a.name.clone()).collect();

        // Remove agents no longer in config
        for name in current_names.difference(&new_names) {
            self.fleet.remove_agent(name);
            removed += 1;
        }

        // Add or update agents
        let mut started = 0;
        for agent_config in &new_config.agents {
            if current_names.contains(&agent_config.name) {
                self.fleet.update_agent_config(agent_config);
                updated += 1;
            } else {
                self.fleet.add_agent(agent_config.clone());
                // Auto-start newly added enabled agents
                if agent_config.enabled {
                    self.fleet.start_agent(&agent_config.name);
                    started += 1;
                }
                added += 1;
            }
        }

        // Update fleet goal
        self.fleet.fleet_goal = new_config.goal.clone();

        // Update stored config
        self.config = new_config;

        // Reload policy engine (picks up new/changed .cedar files)
        let mut policy_warning: Option<String> = None;
        let policy_dir = self.aegis_config
            .policy_paths
            .first()
            .filter(|dir| {
                dir.is_dir()
                    && std::fs::read_dir(dir)
                        .ok()
                        .map(|entries| {
                            entries.filter_map(|e| e.ok()).any(|e| {
                                e.path().extension().is_some_and(|ext| ext == "cedar")
                            })
                        })
                        .unwrap_or(false)
            })
            .cloned();
        if let Some(ref dir) = policy_dir {
            match aegis_policy::PolicyEngine::new(dir, None) {
                Ok(engine) => {
                    info!(policy_dir = %dir.display(), "policy engine reloaded");
                    self.policy_engine = Some(engine);
                }
                Err(e) => {
                    warn!(?e, "failed to reload policy engine, keeping previous");
                    policy_warning = Some(format!(" (policy reload failed: {e})"));
                }
            }
        } else if self.policy_engine.is_some() {
            info!("no policy directory found, clearing policy engine");
            self.policy_engine = None;
        }

        let warning = policy_warning.unwrap_or_default();
        let msg = if started > 0 {
            format!("config reloaded: {added} added ({started} started), {updated} updated, {removed} removed{warning}")
        } else {
            format!("config reloaded: {added} added, {updated} updated, {removed} removed{warning}")
        };
        DaemonResponse::ok(msg)
    }

    /// Persist a config to daemon.toml.
    ///
    /// Uses atomic write (write to temp file, then rename) to prevent
    /// corruption if the process is interrupted mid-write.
    ///
    /// Accepts the config to write explicitly so callers can build a
    /// candidate config, persist it, and only then update in-memory state.
    /// This prevents memory/disk divergence if the write fails.
    fn persist_config_to_disk(config: &DaemonConfig) -> Result<(), String> {
        use std::sync::atomic::AtomicU64;
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let toml_str = config.to_toml().map_err(|e| e.to_string())?;
        let config_path = aegis_types::daemon::daemon_config_path();

        // Write to a uniquely-named sibling temp file, fsync, then rename for
        // crash safety. Without fsync, a power loss between write and rename could
        // leave the temp file empty/truncated, and rename would replace the good
        // config with a corrupt one.
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = config_path.with_extension(format!("toml.{n}.tmp"));

        let file = std::fs::File::create(&tmp_path)
            .map_err(|e| format!("failed to create temp config: {e}"))?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);
        writer.write_all(toml_str.as_bytes())
            .map_err(|e| format!("failed to write temp config: {e}"))?;
        writer.flush()
            .map_err(|e| format!("failed to flush temp config: {e}"))?;
        writer.into_inner()
            .map_err(|e| format!("failed to finalize temp config: {e}"))?
            .sync_all()
            .map_err(|e| format!("failed to sync temp config to disk: {e}"))?;

        std::fs::rename(&tmp_path, &config_path)
            .map_err(|e| format!("failed to atomically replace config: {e}"))?;

        Ok(())
    }

    /// Save current state to disk.
    fn save_state(&self) {
        let mut daemon_state = DaemonState::new(std::process::id());
        daemon_state.started_at = chrono::Utc::now()
            - chrono::Duration::seconds(self.started_at.elapsed().as_secs() as i64);

        for name in self.fleet.agent_names() {
            if let Some(slot) = self.fleet.slot(&name) {
                let sid = *slot.session_id.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                daemon_state.agents.push(state::AgentState {
                    name: name.clone(),
                    was_running: slot.is_thread_alive(),
                    session_id: sid,
                    restart_count: slot.restart_count,
                });
            }
        }

        if let Err(e) = daemon_state.save() {
            tracing::warn!(error = %e, "failed to save daemon state, retrying");
            std::thread::sleep(std::time::Duration::from_millis(100));
            if let Err(e2) = daemon_state.save() {
                tracing::error!(error = %e2, "state save failed twice, persistence may be broken");
            }
        }
    }
}

/// Map a Claude Code tool use into an Aegis `ActionKind` for Cedar policy evaluation.
///
/// Claude Code hooks provide `tool_name` (e.g., "Bash", "Read", "Write") and
/// `tool_input` (JSON with tool-specific parameters). We map these to the
/// corresponding `ActionKind` so Cedar policies can make fine-grained decisions
/// about file paths, commands, URLs, etc.
fn map_tool_use_to_action(tool_name: &str, tool_input: &serde_json::Value) -> ActionKind {
    match tool_name {
        "Bash" => {
            let command = tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ActionKind::ProcessSpawn {
                command,
                args: vec![],
            }
        }
        "Read" | "NotebookRead" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileRead { path }
        }
        "Write" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileWrite { path }
        }
        "Edit" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileWrite { path }
        }
        "NotebookEdit" => {
            let path = tool_input
                .get("notebook_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileWrite { path }
        }
        "Glob" | "Grep" | "LS" => {
            let path = tool_input
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or(".")
                .into();
            ActionKind::DirList { path }
        }
        "WebFetch" => {
            let url = tool_input
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ActionKind::NetRequest {
                method: "GET".to_string(),
                url,
            }
        }
        "WebSearch" => {
            let query = tool_input
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ActionKind::NetRequest {
                method: "GET".to_string(),
                url: query,
            }
        }
        _ => ActionKind::ToolCall {
            tool: tool_name.to_string(),
            args: tool_input.clone(),
        },
    }
}

/// Tools that require human interaction and would stall a headless agent.
///
/// Only `AskUserQuestion` is blocked -- it genuinely waits for human input
/// and would stall a headless agent indefinitely.
///
/// Plan mode tools (`EnterPlanMode`, `ExitPlanMode`) are intentionally allowed.
/// Plan mode produces better results by giving CC time to research and design
/// before implementing. With `--dangerously-skip-permissions`, `ExitPlanMode`
/// auto-approves so the agent flows through plan -> implement without stalling.
fn is_interactive_tool(tool_name: &str) -> bool {
    tool_name == "AskUserQuestion"
}

/// Compose a denial reason that guides the model to proceed autonomously.
///
/// Includes the agent's role, goal, context, and task (if configured) so the
/// model has enough information to make decisions without human input. Also
/// includes the fleet-wide goal if set.
fn compose_autonomy_prompt(
    tool_name: &str,
    fleet_goal: Option<&str>,
    agent_config: Option<&AgentSlotConfig>,
) -> String {
    let mut sections = Vec::new();

    sections.push(format!(
        "You are running as an autonomous agent managed by Aegis. \
         {tool_name} is not available in headless mode -- proceed without it."
    ));

    if let Some(goal) = fleet_goal {
        if !goal.is_empty() {
            sections.push(format!("Fleet mission: {goal}"));
        }
    }

    if let Some(config) = agent_config {
        if let Some(ref role) = config.role {
            if !role.is_empty() {
                sections.push(format!("Your role: {role}"));
            }
        }
        if let Some(ref goal) = config.agent_goal {
            if !goal.is_empty() {
                sections.push(format!("Your goal: {goal}"));
            }
        }
        if let Some(ref ctx) = config.context {
            if !ctx.is_empty() {
                sections.push(format!("Context: {ctx}"));
            }
        }
        if let Some(ref task) = config.task {
            if !task.is_empty() {
                sections.push(format!("Your task: {task}"));
            }
        }
    }

    // Only AskUserQuestion is denied, so guidance is always about autonomous decisions.
    sections.push(
        "Make decisions autonomously based on your role and context. \
         Do not ask clarifying questions -- use your best judgment and proceed."
            .to_string(),
    );

    sections.join(" ")
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
            goal: None,
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
            role: None,
            agent_goal: None,
            context: None,
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

    #[test]
    fn handle_command_evaluate_tool_use_no_policy() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::EvaluateToolUse {
            agent: "claude-1".into(),
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({"command": "ls -la"}),
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let verdict: ToolUseVerdict = serde_json::from_value(data).unwrap();
        assert_eq!(verdict.decision, "allow");
        assert!(verdict.reason.contains("no policy engine"));
    }

    #[test]
    fn map_tool_use_bash() {
        let kind = map_tool_use_to_action("Bash", &serde_json::json!({"command": "ls -la"}));
        match kind {
            ActionKind::ProcessSpawn { command, .. } => assert_eq!(command, "ls -la"),
            other => panic!("expected ProcessSpawn, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_read() {
        let kind = map_tool_use_to_action("Read", &serde_json::json!({"file_path": "/tmp/f.txt"}));
        match kind {
            ActionKind::FileRead { path } => assert_eq!(path, PathBuf::from("/tmp/f.txt")),
            other => panic!("expected FileRead, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_write() {
        let kind = map_tool_use_to_action("Write", &serde_json::json!({"file_path": "/tmp/out.txt"}));
        match kind {
            ActionKind::FileWrite { path } => assert_eq!(path, PathBuf::from("/tmp/out.txt")),
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_edit() {
        let kind = map_tool_use_to_action("Edit", &serde_json::json!({"file_path": "/src/main.rs"}));
        match kind {
            ActionKind::FileWrite { path } => assert_eq!(path, PathBuf::from("/src/main.rs")),
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_glob() {
        let kind = map_tool_use_to_action("Glob", &serde_json::json!({"path": "/src"}));
        match kind {
            ActionKind::DirList { path } => assert_eq!(path, PathBuf::from("/src")),
            other => panic!("expected DirList, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_web_fetch() {
        let kind = map_tool_use_to_action(
            "WebFetch",
            &serde_json::json!({"url": "https://example.com"}),
        );
        match kind {
            ActionKind::NetRequest { url, .. } => assert_eq!(url, "https://example.com"),
            other => panic!("expected NetRequest, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_unknown_falls_back_to_tool_call() {
        let input = serde_json::json!({"foo": "bar"});
        let kind = map_tool_use_to_action("CustomTool", &input);
        match kind {
            ActionKind::ToolCall { tool, args } => {
                assert_eq!(tool, "CustomTool");
                assert_eq!(args, input);
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
    }

    // ── Interactive tool interception tests ───────────────────────────

    #[test]
    fn is_interactive_tool_only_blocks_ask_user() {
        assert!(is_interactive_tool("AskUserQuestion"));
        // Plan mode tools are allowed -- plan mode produces better results
        // and auto-approves with --dangerously-skip-permissions.
        assert!(!is_interactive_tool("EnterPlanMode"));
        assert!(!is_interactive_tool("ExitPlanMode"));
        assert!(!is_interactive_tool("Bash"));
        assert!(!is_interactive_tool("Read"));
        assert!(!is_interactive_tool("Write"));
    }

    #[test]
    fn compose_autonomy_prompt_minimal() {
        let prompt = compose_autonomy_prompt("AskUserQuestion", None, None);
        assert!(prompt.contains("autonomous agent"));
        assert!(prompt.contains("AskUserQuestion"));
        assert!(prompt.contains("best judgment"));
    }

    #[test]
    fn compose_autonomy_prompt_with_context() {
        let config = AgentSlotConfig {
            name: "ux-agent".into(),
            tool: AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: vec![],
            },
            working_dir: PathBuf::from("/tmp"),
            role: Some("UX specialist".into()),
            agent_goal: Some("Build the homepage".into()),
            context: Some("React + TypeScript stack".into()),
            task: Some("Create a responsive nav bar".into()),
            pilot: None,
            restart: RestartPolicy::OnFailure,
            max_restarts: 5,
            enabled: true,
        };

        let prompt = compose_autonomy_prompt(
            "AskUserQuestion",
            Some("Build a production chess app"),
            Some(&config),
        );

        assert!(prompt.contains("Fleet mission: Build a production chess app"));
        assert!(prompt.contains("Your role: UX specialist"));
        assert!(prompt.contains("Your goal: Build the homepage"));
        assert!(prompt.contains("Context: React + TypeScript"));
        assert!(prompt.contains("Your task: Create a responsive nav bar"));
        assert!(prompt.contains("best judgment"));
    }

    #[test]
    fn compose_autonomy_prompt_always_includes_judgment_guidance() {
        // All denied tools (only AskUserQuestion) get the same guidance.
        let prompt = compose_autonomy_prompt("AskUserQuestion", None, None);
        assert!(prompt.contains("best judgment"));
        assert!(prompt.contains("autonomous"));
    }

    #[test]
    fn evaluate_tool_use_denies_interactive_tools() {
        let agent = test_agent("agent-1");
        let mut runtime = test_runtime(vec![agent]);
        let resp = runtime.handle_command(DaemonCommand::EvaluateToolUse {
            agent: "agent-1".into(),
            tool_name: "AskUserQuestion".into(),
            tool_input: serde_json::json!({"question": "what approach?"}),
        });
        assert!(resp.ok);
        let verdict: ToolUseVerdict =
            serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(verdict.decision, "deny");
        assert!(verdict.reason.contains("autonomous"));
    }

    #[test]
    fn evaluate_tool_use_allows_normal_tools() {
        let mut runtime = test_runtime(vec![test_agent("agent-1")]);
        let resp = runtime.handle_command(DaemonCommand::EvaluateToolUse {
            agent: "agent-1".into(),
            tool_name: "Read".into(),
            tool_input: serde_json::json!({"file_path": "/tmp/test.txt"}),
        });
        assert!(resp.ok);
        let verdict: ToolUseVerdict =
            serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(verdict.decision, "allow");
    }

    #[test]
    fn handle_command_reload_config_without_file() {
        // ReloadConfig should fail gracefully if daemon.toml doesn't exist
        // at the standard path. We can't easily test a full reload since
        // daemon_config_path() is system-dependent, but we can verify
        // the command doesn't panic.
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ReloadConfig);
        // May succeed or fail depending on whether daemon.toml exists on disk
        // The important thing is it doesn't panic
        let _ = resp;
    }

    #[test]
    fn handle_command_enable_agent() {
        let mut config = test_agent("a1");
        config.enabled = false;
        let mut runtime = test_runtime(vec![config]);
        let resp = runtime.handle_command(DaemonCommand::EnableAgent { name: "a1".into() });
        assert!(resp.ok);
        assert!(resp.message.contains("enabled"));
    }

    #[test]
    fn handle_command_disable_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::DisableAgent { name: "a1".into() });
        assert!(resp.ok);
        assert!(resp.message.contains("disabled"));
    }

    #[test]
    fn handle_command_enable_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::EnableAgent { name: "ghost".into() });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_remove_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1"), test_agent("a2")]);
        assert_eq!(runtime.fleet.agent_count(), 2);
        let resp = runtime.handle_command(DaemonCommand::RemoveAgent { name: "a1".into() });
        assert!(resp.ok);
        assert_eq!(runtime.fleet.agent_count(), 1);
        assert!(runtime.fleet.agent_status("a1").is_none());
        assert!(runtime.fleet.agent_status("a2").is_some());
        // Config should also be updated
        assert_eq!(runtime.config.agents.len(), 1);
        assert_eq!(runtime.config.agents[0].name, "a2");
    }

    #[test]
    fn handle_command_remove_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::RemoveAgent { name: "ghost".into() });
        assert!(!resp.ok);
        assert_eq!(runtime.fleet.agent_count(), 1);
    }

    #[test]
    fn handle_command_update_agent_context() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        let resp = runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "a1".into(),
            role: Some("UX specialist".into()),
            agent_goal: Some("Design the landing page".into()),
            context: Some("Use Tailwind CSS".into()),
            task: None, // leave unchanged
        });
        assert!(resp.ok, "update should succeed: {}", resp.message);

        let slot = runtime.fleet.slot("a1").unwrap();
        assert_eq!(slot.config.role.as_deref(), Some("UX specialist"));
        assert_eq!(slot.config.agent_goal.as_deref(), Some("Design the landing page"));
        assert_eq!(slot.config.context.as_deref(), Some("Use Tailwind CSS"));
        assert_eq!(slot.config.task.as_deref(), Some("test task"), "task should be unchanged");
    }

    #[test]
    fn handle_command_update_context_clear_field() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        // Set a role first
        runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "a1".into(),
            role: Some("Backend dev".into()),
            agent_goal: None,
            context: None,
            task: None,
        });
        assert_eq!(runtime.fleet.slot("a1").unwrap().config.role.as_deref(), Some("Backend dev"));

        // Clear it with empty string
        let resp = runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "a1".into(),
            role: Some("".into()),
            agent_goal: None,
            context: None,
            task: None,
        });
        assert!(resp.ok);
        assert!(runtime.fleet.slot("a1").unwrap().config.role.is_none(), "empty string should clear field");
    }

    #[test]
    fn handle_command_update_context_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "ghost".into(),
            role: Some("whatever".into()),
            agent_goal: None,
            context: None,
            task: None,
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_get_agent_context() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        // Set some context
        runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "a1".into(),
            role: Some("Frontend dev".into()),
            agent_goal: Some("Build the dashboard".into()),
            context: None,
            task: None,
        });

        let resp = runtime.handle_command(DaemonCommand::GetAgentContext { name: "a1".into() });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert_eq!(data["role"].as_str(), Some("Frontend dev"));
        assert_eq!(data["agent_goal"].as_str(), Some("Build the dashboard"));
        assert!(data["context"].is_null());
        assert_eq!(data["task"].as_str(), Some("test task"));
    }

    #[test]
    fn handle_command_get_context_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::GetAgentContext { name: "ghost".into() });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_fleet_goal_set_and_get() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        // Get when no goal set -- returns null, not "(none)"
        let resp = runtime.handle_command(DaemonCommand::FleetGoal { goal: None });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert!(data["goal"].is_null(), "unset goal should be null");

        // Set a goal
        let resp = runtime.handle_command(DaemonCommand::FleetGoal {
            goal: Some("Build a chess app".into()),
        });
        assert!(resp.ok);
        assert!(resp.message.contains("Build a chess app"));

        // Get the goal back
        let resp = runtime.handle_command(DaemonCommand::FleetGoal { goal: None });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert_eq!(data["goal"].as_str(), Some("Build a chess app"));
    }

    #[test]
    fn handle_command_fleet_goal_clear() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        // Set then clear
        runtime.handle_command(DaemonCommand::FleetGoal {
            goal: Some("Build something".into()),
        });
        let resp = runtime.handle_command(DaemonCommand::FleetGoal {
            goal: Some("".into()),
        });
        assert!(resp.ok);
        assert!(resp.message.contains("(cleared)"));

        // Verify it's cleared -- returns null
        let resp = runtime.handle_command(DaemonCommand::FleetGoal { goal: None });
        let data = resp.data.unwrap();
        assert!(data["goal"].is_null(), "cleared goal should be null");
    }

    #[test]
    fn handle_command_send_to_agent_not_running() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::SendToAgent {
            name: "a1".into(),
            text: "hello".into(),
        });
        assert!(!resp.ok, "send to non-running agent should fail");
    }

    #[test]
    fn handle_command_send_to_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::SendToAgent {
            name: "ghost".into(),
            text: "hello".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_add_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        assert_eq!(runtime.fleet.agent_count(), 1);

        let new_agent = test_agent("a2");
        let resp = runtime.handle_command(DaemonCommand::AddAgent {
            config: Box::new(new_agent),
            start: false,
        });
        assert!(resp.ok, "add should succeed: {}", resp.message);
        assert_eq!(runtime.fleet.agent_count(), 2);
        assert!(runtime.fleet.agent_status("a2").is_some());
    }

    #[test]
    fn handle_command_add_duplicate_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let dup = test_agent("a1");
        let resp = runtime.handle_command(DaemonCommand::AddAgent {
            config: Box::new(dup),
            start: false,
        });
        assert!(!resp.ok, "duplicate should fail");
        assert!(resp.message.contains("already exists"));
    }

    #[test]
    fn handle_command_remove_agent_success() {
        let mut runtime = test_runtime(vec![test_agent("a1"), test_agent("a2")]);
        assert_eq!(runtime.fleet.agent_count(), 2);

        let resp = runtime.handle_command(DaemonCommand::RemoveAgent { name: "a1".into() });
        assert!(resp.ok, "remove should succeed: {}", resp.message);
        assert_eq!(runtime.fleet.agent_count(), 1);
        assert!(runtime.fleet.agent_status("a1").is_none());
        assert!(runtime.fleet.agent_status("a2").is_some());
    }

    #[test]
    fn handle_command_restart_agent_not_running() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::RestartAgent { name: "a1".into() });
        // RestartAgent stops + starts; stop on a non-running agent is fine
        assert!(resp.ok);
    }

    #[test]
    fn handle_command_add_agent_invalid_working_dir() {
        let mut runtime = test_runtime(vec![]);
        let mut agent = test_agent("bad-dir");
        agent.working_dir = PathBuf::from("/nonexistent/path/that/does/not/exist");
        let resp = runtime.handle_command(DaemonCommand::AddAgent {
            config: Box::new(agent),
            start: false,
        });
        assert!(!resp.ok, "should reject invalid working_dir");
        assert!(resp.message.contains("not a directory") || resp.message.contains("does not exist"));
    }
}
