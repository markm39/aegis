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

use aegis_ledger::{AuditStore, AuditWriter, PiiRedactor};
use aegis_pilot::supervisor::SupervisorCommand;
use aegis_types::config::RedactionConfig;
use aegis_types::daemon::{
    AgentSlotConfig, AgentStatus, AgentToolConfig, DaemonConfig, RestartPolicy, ToolkitConfig,
};
use aegis_types::AegisConfig;

use crate::execution_lanes::{LaneManager, DEFAULT_LANE};
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
    /// Canonical computer-use toolkit contract source from daemon config.
    toolkit_config: ToolkitConfig,
    /// Handle to the dedicated audit writer thread. Cloned into each agent thread.
    audit_writer: AuditWriter,
    /// JoinHandle for the audit writer thread, kept alive until fleet shutdown.
    audit_writer_thread: Option<thread::JoinHandle<()>>,
    /// Shared tokio runtime handle, injected by the daemon after the runtime is created.
    /// Propagated into each agent lifecycle thread for async subsystems (e.g. usage proxy).
    rt_handle: Option<tokio::runtime::Handle>,
    /// PII redaction config applied to per-agent observer/proxy audit stores.
    redaction: RedactionConfig,
    /// Execution lane manager for concurrency control across agent groups.
    lane_manager: LaneManager,
}

impl Fleet {
    /// Create a new fleet from daemon configuration.
    ///
    /// Opens the audit store and spawns the dedicated writer thread. The writer
    /// thread owns the `AuditStore` exclusively -- no mutex needed on the write
    /// path. Each agent thread clones the `AuditWriter` handle.
    pub fn new(config: &DaemonConfig, aegis_config: AegisConfig) -> Self {
        let mut slots = HashMap::new();
        for agent_config in &config.agents {
            let slot = AgentSlot::new(agent_config.clone());
            slots.insert(agent_config.name.to_string(), slot);
        }

        let mut store = AuditStore::open(&aegis_config.ledger_path).unwrap_or_else(|e| {
            panic!(
                "failed to open audit store at '{}': {e}",
                aegis_config.ledger_path.display()
            )
        });
        if let Ok(redactor) = PiiRedactor::from_config(&config.redaction) {
            store.set_redactor(redactor);
        }
        let (audit_writer, audit_writer_thread) = AuditWriter::spawn(store);

        let lane_manager = match LaneManager::new(config.lanes.clone()) {
            Ok(mgr) => {
                if !config.lanes.is_empty() {
                    info!(
                        lanes = config.lanes.len(),
                        "execution lanes initialized"
                    );
                }
                mgr
            }
            Err(e) => {
                warn!(error = %e, "invalid lane config, using default lane only");
                LaneManager::new(vec![]).expect("default lane manager")
            }
        };

        Self {
            slots,
            default_aegis_config: aegis_config,
            fleet_goal: config.goal.clone(),
            toolkit_config: config.toolkit.clone(),
            audit_writer,
            audit_writer_thread: Some(audit_writer_thread),
            rt_handle: None,
            redaction: config.redaction.clone(),
            lane_manager,
        }
    }

    /// Inject a shared tokio runtime handle into the fleet.
    ///
    /// Must be called before `start_all()` or `start_agent()` for the handle to
    /// be available to agent lifecycle threads. The handle is propagated into
    /// each agent thread so async subsystems (e.g. usage proxy) share the
    /// daemon's single multi-thread runtime instead of creating their own.
    pub fn set_rt_handle(&mut self, handle: tokio::runtime::Handle) {
        self.rt_handle = Some(handle);
    }

    /// Shut down the fleet's audit writer thread cleanly.
    ///
    /// Call after all agent threads have exited (e.g., after `stop_all()`
    /// returns) to ensure all queued audit messages are processed before
    /// the process exits.
    pub fn shutdown_audit_writer(&mut self) {
        self.audit_writer.shutdown();
        if let Some(handle) = self.audit_writer_thread.take() {
            if let Err(e) = handle.join() {
                warn!("audit writer thread panicked on shutdown: {e:?}");
            }
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
        let names: Vec<String> = self.slots.keys().cloned().collect();

        for name in names {
            if self.slots.get(&name).is_some_and(|s| s.config.enabled) {
                self.start_agent(&name);
            }
        }
    }

    /// Build per-agent AegisConfig, applying any overrides from the agent's
    /// slot config (policy_dir, isolation) on top of the fleet default.
    fn build_agent_aegis_config(&self, slot_config: &AgentSlotConfig) -> AegisConfig {
        let mut config = self.default_aegis_config.clone();
        config.name = slot_config.name.to_string();
        if let Some(ref policy_dir) = slot_config.policy_dir {
            config.policy_paths = vec![policy_dir.clone()];
        }
        if let Some(ref isolation) = slot_config.isolation {
            config.isolation = isolation.clone();
        }
        config
    }

    /// Start a specific agent by name.
    pub fn start_agent(&mut self, name: &str) {
        // All read-only checks use immutable borrows so lane_manager can be
        // borrowed mutably before the first mutable slot access.
        let is_orchestrator = self
            .slots
            .get(name)
            .is_some_and(|s| s.config.orchestrator.is_some());
        let orchestrator_name = if !is_orchestrator {
            self.slots
                .values()
                .find(|s| s.config.orchestrator.is_some())
                .map(|s| s.config.name.to_string())
        } else {
            None
        };

        // Early-exit checks with immutable borrows.
        let (lane_name, aegis_config) = match self.slots.get(name) {
            Some(s) => {
                if !s.config.enabled {
                    warn!(agent = name, "start_agent: agent is disabled, use enable first");
                    return;
                }
                if s.is_thread_alive() {
                    info!(agent = name, "agent already running, skipping start");
                    return;
                }
                let lane = s
                    .config
                    .lane
                    .as_deref()
                    .unwrap_or(DEFAULT_LANE)
                    .to_string();
                let cfg = self.build_agent_aegis_config(&s.config);
                (lane, cfg)
            }
            None => {
                warn!(agent = name, "start_agent: unknown agent");
                return;
            }
        };
        let toolkit_config = self.toolkit_config.clone();

        // Check execution lane capacity before spawning.
        match self.lane_manager.acquire(&lane_name, name) {
            Ok(true) => { /* slot acquired, proceed with spawn */ }
            Ok(false) => {
                // Lane is full; agent has been queued inside LaneManager.
                if let Some(s) = self.slots.get_mut(name) {
                    s.status = AgentStatus::Queued {
                        lane: lane_name.clone(),
                    };
                }
                info!(agent = name, lane = %lane_name, "queued for lane capacity");
                return;
            }
            Err(e) => {
                // Lane doesn't exist or invalid name -- log and proceed in default.
                warn!(agent = name, lane = %lane_name, error = %e, "lane acquire failed, using default");
                let _ = self.lane_manager.acquire(DEFAULT_LANE, name);
            }
        }

        // Now safe to borrow slot mutably for spawn setup.
        let slot = match self.slots.get_mut(name) {
            Some(s) => s,
            None => return,
        };

        let slot_config = slot.config.clone();
        // Bounded channel provides backpressure: chatty agents block rather than OOM the daemon.
        let (output_tx, output_rx) = mpsc::sync_channel::<String>(1000);

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
        // Clone the writer handle so this agent thread has its own sender.
        let audit_writer = self.audit_writer.clone();
        // Clone the shared runtime handle (None if not injected, e.g. in tests).
        let rt_handle = self.rt_handle.clone();
        let redaction = self.redaction.clone();

        // Clear session_id before spawning the next run.
        *slot.session_id.lock() = None;
        let shared_session_id = slot.session_id.clone();

        let handle = thread::Builder::new()
            .name(format!("agent-{name}"))
            .spawn(move || {
                lifecycle::run_agent_slot(
                    &slot_config,
                    &aegis_config,
                    &toolkit_config,
                    audit_writer,
                    fleet_goal.as_deref(),
                    orchestrator_name.as_deref(),
                    output_tx,
                    Some(upd_tx),
                    Some(cmd_rx),
                    child_pid,
                    shared_session_id,
                    rt_handle,
                    &redaction,
                )
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
                // Clear channels and started_at so callers don't think this
                // agent is reachable (e.g., send_to_agent, approve_request).
                slot.output_rx = None;
                slot.command_tx = None;
                slot.update_rx = None;
                slot.started_at = None;
            }
        }
    }

    /// Stop a specific agent by name.
    ///
    /// Sends SIGTERM to the child process, waits up to 5 seconds for
    /// graceful exit, then escalates to SIGKILL. This prevents
    /// `handle.join()` from blocking indefinitely on hung processes.
    /// Signal an agent to stop (non-blocking).
    ///
    /// Sends SIGTERM and sets the status to `Stopping`. The `tick()` loop
    /// handles joining the thread after exit, escalating to SIGKILL if needed.
    pub fn stop_agent(&mut self, name: &str) {
        let slot = match self.slots.get_mut(name) {
            Some(s) => s,
            None => {
                warn!(agent = name, "stop_agent: unknown agent");
                return;
            }
        };

        // If already stopping or not running, nothing to do.
        if slot.thread_handle.is_none() {
            return;
        }

        // Send SIGTERM to the child process if we know the PID.
        let pid = slot.child_pid.load(Ordering::Acquire);
        let raw_pid = i32::try_from(pid).ok().filter(|&p| p > 0);
        if let Some(p) = raw_pid {
            info!(agent = name, pid, "sending SIGTERM to child");
            let _ = signal::kill(Pid::from_raw(p), Signal::SIGTERM);
        }

        slot.status = AgentStatus::Stopping;
        slot.stop_signaled_at = Some(std::time::Instant::now());
    }

    /// Enable an agent slot so it can be started.
    pub fn enable_agent(&mut self, name: &str) -> Result<(), String> {
        let slot = self
            .slots
            .get_mut(name)
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
        let slot = self
            .slots
            .get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        if !slot.config.enabled {
            return Err(format!("agent '{name}' is already disabled"));
        }

        let is_alive = slot.is_thread_alive();
        let is_queued = matches!(slot.status, AgentStatus::Queued { .. });
        let lane_name = slot
            .config
            .lane
            .as_deref()
            .unwrap_or(DEFAULT_LANE)
            .to_string();

        // Remove from lane queue if the agent was waiting for a slot.
        if is_queued {
            self.lane_manager.remove_from_queue(&lane_name, name);
        }

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
            // Clear channels and timing so nothing references the dead thread.
            slot.output_rx = None;
            slot.command_tx = None;
            slot.update_rx = None;
            slot.started_at = None;
        }
        info!(agent = name, "agent disabled");
        Ok(())
    }

    /// Send text to an agent's PTY stdin via the supervisor command channel.
    pub fn send_to_agent(&self, name: &str, text: &str) -> Result<(), String> {
        let slot = self
            .slots
            .get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        let tx = slot
            .command_tx
            .as_ref()
            .ok_or_else(|| format!("agent '{name}' has no command channel (not running?)"))?;

        let trimmed = text.trim();
        if !trimmed.is_empty() {
            slot.push_output_line(format!("You: {trimmed}"));
        }

        tx.send(SupervisorCommand::SendInput {
            text: text.to_string(),
        })
        .map_err(|_| format!("command channel closed for '{name}' (agent may have exited)"))
    }

    /// Approve a pending permission request for an agent.
    pub fn approve_request(&self, name: &str, request_id: Uuid) -> Result<(), String> {
        let slot = self
            .slots
            .get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        let tx = slot
            .command_tx
            .as_ref()
            .ok_or_else(|| format!("agent '{name}' has no command channel (not running?)"))?;

        tx.send(SupervisorCommand::Approve { request_id })
            .map_err(|_| format!("command channel closed for '{name}'"))
    }

    /// Deny a pending permission request for an agent.
    pub fn deny_request(&self, name: &str, request_id: Uuid) -> Result<(), String> {
        let slot = self
            .slots
            .get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        let tx = slot
            .command_tx
            .as_ref()
            .ok_or_else(|| format!("agent '{name}' has no command channel (not running?)"))?;

        tx.send(SupervisorCommand::Deny { request_id })
            .map_err(|_| format!("command channel closed for '{name}'"))
    }

    /// Nudge a stalled agent with an optional message.
    pub fn nudge_agent(&self, name: &str, message: Option<String>) -> Result<(), String> {
        let slot = self
            .slots
            .get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        let tx = slot
            .command_tx
            .as_ref()
            .ok_or_else(|| format!("agent '{name}' has no command channel (not running?)"))?;

        tx.send(SupervisorCommand::Nudge { message })
            .map_err(|_| format!("command channel closed for '{name}'"))
    }

    /// List pending permission prompts for an agent.
    pub fn list_pending(&self, name: &str) -> Result<&[PendingPromptInfo], String> {
        let slot = self
            .slots
            .get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        Ok(&slot.pending_prompts)
    }

    /// Whether an agent needs human attention (max nudges exceeded).
    pub fn agent_attention_needed(&self, name: &str) -> bool {
        self.slots.get(name).is_some_and(|s| s.attention_needed)
    }

    /// Count of pending prompts for an agent.
    pub fn agent_pending_count(&self, name: &str) -> usize {
        self.slots
            .get(name)
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

            // Escalate SIGTERM -> SIGKILL after 5 seconds for stopping agents.
            if let Some(slot) = self.slots.get(name) {
                if let Some(signaled_at) = slot.stop_signaled_at {
                    if signaled_at.elapsed() >= std::time::Duration::from_secs(5) {
                        let pid = slot.child_pid.load(Ordering::Acquire);
                        let raw_pid = i32::try_from(pid).ok().filter(|&p| p > 0);
                        if let Some(p) = raw_pid {
                            warn!(agent = name, pid, "SIGTERM timeout, sending SIGKILL");
                            let _ = signal::kill(Pid::from_raw(p), Signal::SIGKILL);
                        }
                        // Don't clear stop_signaled_at here -- handle_agent_exit
                        // needs it to know this was a user-initiated stop.
                        // Re-sending SIGKILL on subsequent ticks is harmless.
                    }
                }
            }

            // Check if the thread has finished
            let needs_join = self
                .slots
                .get(name)
                .is_some_and(|s| s.thread_handle.as_ref().is_some_and(|h| h.is_finished()));

            if needs_join {
                self.tick_slot(name);
            }

            // Check if backoff has expired and agent should be restarted.
            // Also verify the agent is still enabled -- a disabled agent's backoff
            // should just be cleared, not trigger a restart.
            let ready = self.slots.get(name).is_some_and(|s| {
                s.config.enabled
                    && s.backoff_until
                        .is_some_and(|t| std::time::Instant::now() >= t)
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

    /// Handle a finished agent thread: join it, release its lane slot, and
    /// apply restart policy. If a queued agent is waiting for the freed lane
    /// slot, it will be started after restart processing completes.
    fn tick_slot(&mut self, name: &str) {
        let slot = match self.slots.get_mut(name) {
            Some(s) => s,
            None => return,
        };

        let handle = match slot.thread_handle.take() {
            Some(h) => h,
            None => return,
        };

        // Capture lane name before any borrows change.
        let lane_name = slot
            .config
            .lane
            .as_deref()
            .unwrap_or(DEFAULT_LANE)
            .to_string();

        // Release the lane slot BEFORE restart processing so the restarting
        // agent competes fairly for capacity through the normal acquire path.
        let dequeued = self
            .lane_manager
            .release(&lane_name, name)
            .ok()
            .flatten();

        // Re-borrow for the panic branch (slot was invalidated by lane_manager borrow).
        match handle.join() {
            Ok(result) => {
                let exit_code = result.exit_code.unwrap_or(-1);
                info!(
                    agent = name,
                    exit_code, "agent exited, evaluating restart policy"
                );
                self.handle_agent_exit(name, exit_code);
            }
            Err(_) => {
                error!(agent = name, "agent thread panicked");
                if let Some(s) = self.slots.get_mut(name) {
                    s.output_rx = None;
                    s.command_tx = None;
                    s.update_rx = None;
                }
                self.handle_agent_exit(name, -1);
            }
        }

        // Start the dequeued agent (if any) after restart processing.
        if let Some(next) = dequeued {
            info!(agent = %next, lane = %lane_name, "lane slot freed, starting queued agent");
            self.start_agent(&next);
        }
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
        let was_user_stopped = slot.stop_signaled_at.is_some();
        slot.stop_signaled_at = None;

        // Clear dead channels (senders dropped when thread exited).
        slot.output_rx = None;
        slot.command_tx = None;
        slot.update_rx = None;

        // If a restart was explicitly requested (via restart_agent), skip the
        // policy evaluation and start immediately.
        if slot.pending_restart {
            slot.pending_restart = false;
            slot.restart_count = 0;
            slot.stop_signaled_at = None;
            slot.status = AgentStatus::Pending;
            info!(agent = name, "pending restart: starting agent");
            self.start_agent(name);
            return;
        }

        // If the user explicitly stopped this agent, don't apply the restart
        // policy -- honor the explicit stop.
        if was_user_stopped {
            slot.status = AgentStatus::Stopped { exit_code };
            info!(agent = name, exit_code, "agent stopped by user");
            return;
        }

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

        // If the agent ran for >= 30 seconds, reset the crash counter since
        // it was a "successful" run (not a fast crash loop).
        let ran_briefly = run_duration.is_some_and(|d| d.as_secs() < 30);
        if !ran_briefly {
            slot.restart_count = 0;
        }

        slot.restart_count += 1;

        // If the agent ran for less than 30 seconds, apply exponential backoff
        // to prevent crash loops from spinning hot.
        if ran_briefly {
            // Exponential backoff: 2, 4, 8, 16, 32, 60, 60, ...
            // Cap shift at 6 to avoid overflow (2^6 = 64 > 60 cap).
            let shift = std::cmp::min(slot.restart_count, 6);
            let delay_secs = std::cmp::min(1u64 << shift, 60);
            let backoff_until =
                std::time::Instant::now() + std::time::Duration::from_secs(delay_secs);
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

    /// Get the status of all execution lanes.
    pub fn lane_status(&self) -> Vec<crate::execution_lanes::LaneStatus> {
        self.lane_manager.lane_status()
    }

    /// Get the status of a specific execution lane.
    pub fn lane_status_by_name(&self, name: &str) -> Option<crate::execution_lanes::LaneStatus> {
        self.lane_manager
            .lane_status()
            .into_iter()
            .find(|s| s.name == name)
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

    /// Total number of pending prompts across all agents.
    pub fn pending_total(&self) -> usize {
        self.slots.values().map(|s| s.pending_prompts.len()).sum()
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
        self.slots.insert(config.name.to_string(), slot);
    }

    /// Remove an agent slot. Stops it first if running and releases any
    /// lane slot or queue entry.
    pub fn remove_agent(&mut self, name: &str) {
        if let Some(slot) = self.slots.get(name) {
            let lane = slot.config.lane.as_deref().unwrap_or(DEFAULT_LANE);
            if slot.is_thread_alive() {
                // Agent is running and holds a lane slot -- release it.
                let _ = self.lane_manager.release(lane, name);
            } else if matches!(slot.status, AgentStatus::Queued { .. }) {
                // Agent is queued -- remove from queue without releasing a slot.
                self.lane_manager.remove_from_queue(lane, name);
            }
        }
        self.stop_agent(name);
        self.slots.remove(name);
    }

    /// Update the stored config for an existing agent slot (without restarting).
    pub fn update_agent_config(&mut self, config: &AgentSlotConfig) {
        if let Some(slot) = self.slots.get_mut(config.name.as_str()) {
            slot.config = config.clone();
        }
    }

    /// Restart a specific agent (stop then start).
    ///
    /// Returns an error if the agent is unknown or disabled.
    /// Clears any backoff timer so the restart happens immediately.
    pub fn restart_agent(&mut self, name: &str) -> Result<(), String> {
        let slot = self
            .slots
            .get(name)
            .ok_or_else(|| format!("unknown agent: {name}"))?;

        if !slot.config.enabled {
            return Err(format!("agent '{name}' is disabled, enable it first"));
        }

        let is_running = slot.thread_handle.is_some();

        // Set flags before calling stop_agent (which borrows &mut self).
        if let Some(slot) = self.slots.get_mut(name) {
            slot.backoff_until = None;
            if is_running {
                slot.pending_restart = true;
            }
        }

        if is_running {
            // Signal stop; tick loop will auto-restart due to pending_restart.
            self.stop_agent(name);
        } else {
            // Not running -- just start directly.
            self.start_agent(name);
        }

        Ok(())
    }

    /// Get the tool type name for an agent.
    pub fn agent_tool_name(&self, name: &str) -> Option<String> {
        self.slots.get(name).map(|s| match &s.config.tool {
            AgentToolConfig::ClaudeCode { .. } => "ClaudeCode".to_string(),
            AgentToolConfig::Codex { .. } => "Codex".to_string(),
            AgentToolConfig::OpenClaw { .. } => "OpenClaw".to_string(),
            AgentToolConfig::Custom { command, .. } => format!("Custom({command})"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::daemon::{AgentToolConfig, DaemonControlConfig, PersistenceConfig};
    use std::path::PathBuf;

    fn test_daemon_config(agents: Vec<AgentSlotConfig>) -> DaemonConfig {
        DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: Default::default(),
            alerts: vec![],
            agents,
            channel: None,
            channel_routing: None,
            toolkit: Default::default(),
            memory: Default::default(),
            session_files: Default::default(),
            cron: Default::default(),
            plugins: Default::default(),
            aliases: Default::default(),
            lanes: vec![],
            workspace_hooks: Default::default(),
            acp_server: None,
            default_model: None,
            skills: vec![],
            retention: Default::default(),
            redaction: Default::default(),
        }
    }

    fn test_slot_config(name: &str) -> AgentSlotConfig {
        AgentSlotConfig {
            name: name.into(),
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
            orchestrator: None,
            security_preset: None,
            policy_dir: None,
            isolation: None,
            lane: None,
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

        assert_eq!(
            fleet.agent_status("disabled-1"),
            Some(&AgentStatus::Disabled)
        );
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
        let config = test_daemon_config(vec![test_slot_config("a"), test_slot_config("b")]);
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

        assert_eq!(
            fleet.agent_tool_name("claude"),
            Some("ClaudeCode".to_string())
        );
        assert_eq!(fleet.agent_tool_name("nonexistent"), None);
    }

    #[test]
    fn stop_all_is_safe_on_idle_fleet() {
        let config = test_daemon_config(vec![test_slot_config("a"), test_slot_config("b")]);
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
        fleet.slots.get_mut("crasher").unwrap().started_at = Some(std::time::Instant::now());

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
        fleet.slots.get_mut("limited").unwrap().started_at = Some(std::time::Instant::now());

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

        assert_eq!(
            fleet.agent_status("off-agent"),
            Some(&AgentStatus::Disabled)
        );

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

    #[test]
    fn restart_disabled_agent_returns_error() {
        let mut slot_config = test_slot_config("off");
        slot_config.enabled = false;
        let config = test_daemon_config(vec![slot_config]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        let err = fleet.restart_agent("off").unwrap_err();
        assert!(
            err.contains("disabled"),
            "expected disabled error, got: {err}"
        );
    }

    #[test]
    fn restart_unknown_agent_returns_error() {
        let config = test_daemon_config(vec![]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        let err = fleet.restart_agent("ghost").unwrap_err();
        assert!(
            err.contains("unknown"),
            "expected unknown error, got: {err}"
        );
    }

    #[test]
    fn tick_slot_panicked_thread_triggers_restart_policy() {
        let mut slot_config = test_slot_config("panicker");
        slot_config.restart = RestartPolicy::Always;
        let config = test_daemon_config(vec![slot_config]);
        let aegis = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        let mut fleet = Fleet::new(&config, aegis);

        // Spawn a thread that panics immediately
        let handle = std::thread::Builder::new()
            .name("panicker".into())
            .spawn(|| -> lifecycle::SlotResult {
                panic!("deliberate panic for testing");
            })
            .unwrap();

        // Wait for thread to finish panicking
        std::thread::sleep(std::time::Duration::from_millis(50));

        let slot = fleet.slots.get_mut("panicker").unwrap();
        slot.thread_handle = Some(handle);
        slot.started_at = Some(std::time::Instant::now());

        // tick_slot should detect the panic and route through handle_agent_exit
        fleet.tick_slot("panicker");

        let slot = fleet.slot("panicker").unwrap();
        // With restart=Always and a brief run, should be in Crashed (backoff) state
        assert!(
            matches!(slot.status, AgentStatus::Crashed { .. }),
            "expected Crashed after panic, got {:?}",
            slot.status
        );
        assert!(
            slot.backoff_until.is_some(),
            "should have backoff after crash"
        );
        assert_eq!(slot.restart_count, 1);
    }
}
