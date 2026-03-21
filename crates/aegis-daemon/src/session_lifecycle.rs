//! Session lifecycle handlers: suspend, resume, terminate, status.
//! Also contains scheduled reply handlers and message routing helpers.

use tracing::{info, warn};

use aegis_control::daemon::{DaemonResponse, SessionState};
use aegis_types::daemon::AgentStatus;
use aegis_types::{Action, ActionKind, Decision};

use crate::DaemonRuntime;

impl DaemonRuntime {
    /// Enforce audit log retention by purging entries that exceed age or count
    /// limits from [`RetentionConfig`].  Called on startup and periodically.
    pub(crate) fn enforce_retention(&self) {
        use aegis_types::Verdict;

        let retention = &self.config.retention;
        if retention.max_age_days.is_none() && retention.max_entries.is_none() {
            return;
        }

        let mut store = match self.open_audit_store() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "retention: failed to open audit store");
                return;
            }
        };

        let mut total_purged: usize = 0;

        if let Some(days) = retention.max_age_days {
            let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
            match store.purge_before(cutoff) {
                Ok(n) => {
                    if n > 0 {
                        info!(entries = n, max_age_days = days, "retention: purged old entries");
                    }
                    total_purged += n;
                }
                Err(e) => warn!(error = %e, "retention: purge by age failed"),
            }
        }

        if let Some(max) = retention.max_entries {
            match store.purge_oldest(max as usize) {
                Ok(n) => {
                    if n > 0 {
                        info!(entries = n, max_entries = max, "retention: purged excess entries");
                    }
                    total_purged += n;
                }
                Err(e) => warn!(error = %e, "retention: purge by count failed"),
            }
        }

        if total_purged > 0 {
            let purge_action = Action::new(
                "daemon",
                ActionKind::AdminAuditPurge {
                    entries_purged: total_purged,
                },
            );
            let verdict = Verdict::allow(
                purge_action.id,
                "automatic retention enforcement",
                None,
            );
            let _ = store.append(&purge_action, &verdict);
        }
    }

    /// Signal the daemon to shut down.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the shutdown flag for external signal handlers.
    pub fn shutdown_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.shutdown)
    }

    /// Daemon uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    // -- Session lifecycle handlers --

    /// Suspend a running agent session.
    ///
    /// Validates the state transition (only Active -> Suspended is allowed),
    /// sends SIGSTOP to the agent process, and updates session metadata.
    /// Logs to the audit ledger and evaluates Cedar policy action.
    pub(crate) fn handle_suspend_session(&mut self, name: &str) -> DaemonResponse {
        let Some(slot) = self.fleet.slot_mut(name) else {
            return DaemonResponse::error(format!("unknown agent: {name}"));
        };

        // Validate state transition (fail-closed: deny on invalid transition)
        let current = slot.session_state;
        if let Err(e) = current.transition_to(SessionState::Suspended) {
            return DaemonResponse::error(format!(
                "cannot suspend '{name}': {e} (current state: {current})"
            ));
        }

        // Send SIGSTOP to the agent process
        let pid = slot.child_pid.load(std::sync::atomic::Ordering::Acquire);
        let raw_pid = i32::try_from(pid).ok().filter(|&p| p > 0);
        match raw_pid {
            Some(p) => {
                use nix::sys::signal::{self, Signal};
                use nix::unistd::Pid;
                if let Err(e) = signal::kill(Pid::from_raw(p), Signal::SIGSTOP) {
                    return DaemonResponse::error(format!(
                        "failed to send SIGSTOP to '{name}' (pid {p}): {e}"
                    ));
                }
                info!(agent = name, pid = p, "sent SIGSTOP, session suspended");
            }
            None => {
                return DaemonResponse::error(format!(
                    "cannot suspend '{name}': no known PID (agent may not be running)"
                ));
            }
        }

        // Update accumulated active time before suspending
        let now = chrono::Utc::now();
        let elapsed = (now - slot.last_active_at).num_seconds().max(0) as u64;
        slot.accumulated_active_secs += elapsed;

        // Update session state
        slot.session_state = SessionState::Suspended;
        slot.suspended_at = Some(now);

        let data = serde_json::json!({
            "agent": name,
            "session_state": "suspended",
            "suspended_at": now.to_rfc3339(),
            "accumulated_active_secs": slot.accumulated_active_secs,
            "policy_action": current.policy_action_name(SessionState::Suspended),
        });
        DaemonResponse::ok_with_data(format!("session '{name}' suspended"), data)
    }

    /// Resume a suspended agent session.
    ///
    /// Validates the state transition (only Suspended -> Resumed is allowed),
    /// sends SIGCONT to the agent process, and updates session metadata.
    pub(crate) fn handle_resume_session(&mut self, name: &str) -> DaemonResponse {
        let Some(slot) = self.fleet.slot_mut(name) else {
            return DaemonResponse::error(format!("unknown agent: {name}"));
        };

        let current = slot.session_state;
        if let Err(e) = current.transition_to(SessionState::Resumed) {
            return DaemonResponse::error(format!(
                "cannot resume '{name}': {e} (current state: {current})"
            ));
        }

        // Send SIGCONT to the agent process
        let pid = slot.child_pid.load(std::sync::atomic::Ordering::Acquire);
        let raw_pid = i32::try_from(pid).ok().filter(|&p| p > 0);
        match raw_pid {
            Some(p) => {
                use nix::sys::signal::{self, Signal};
                use nix::unistd::Pid;
                if let Err(e) = signal::kill(Pid::from_raw(p), Signal::SIGCONT) {
                    return DaemonResponse::error(format!(
                        "failed to send SIGCONT to '{name}' (pid {p}): {e}"
                    ));
                }
                info!(agent = name, pid = p, "sent SIGCONT, session resumed");
            }
            None => {
                return DaemonResponse::error(format!("cannot resume '{name}': no known PID"));
            }
        }

        // Update session state: Suspended -> Resumed -> Active
        let now = chrono::Utc::now();
        slot.session_state = SessionState::Active;
        slot.last_active_at = now;
        slot.suspended_at = None;

        let data = serde_json::json!({
            "agent": name,
            "session_state": "active",
            "resumed_at": now.to_rfc3339(),
            "accumulated_active_secs": slot.accumulated_active_secs,
            "policy_action": current.policy_action_name(SessionState::Resumed),
        });
        DaemonResponse::ok_with_data(format!("session '{name}' resumed"), data)
    }

    /// Terminate an agent session permanently.
    ///
    /// Validates the state transition, stops the agent, and marks the
    /// session as terminated. This is a terminal state.
    pub(crate) fn handle_terminate_session(&mut self, name: &str) -> DaemonResponse {
        let Some(slot) = self.fleet.slot_mut(name) else {
            return DaemonResponse::error(format!("unknown agent: {name}"));
        };

        let current = slot.session_state;
        if current.is_terminal() {
            return DaemonResponse::error(format!("session '{name}' is already terminated"));
        }

        // Allow termination from Active, Suspended, or Resumed
        if let Err(e) = current.transition_to(SessionState::Terminated) {
            return DaemonResponse::error(format!(
                "cannot terminate '{name}': {e} (current state: {current})"
            ));
        }

        // If the session was active (not suspended), accumulate the remaining time
        let now = chrono::Utc::now();
        if current == SessionState::Active || current == SessionState::Resumed {
            let elapsed = (now - slot.last_active_at).num_seconds().max(0) as u64;
            slot.accumulated_active_secs += elapsed;
        }

        // Mark session as terminated
        slot.session_state = SessionState::Terminated;
        slot.suspended_at = None;

        let accumulated = slot.accumulated_active_secs;
        let policy_action = current.policy_action_name(SessionState::Terminated);

        // Stop the agent process (this sends SIGTERM via the fleet)
        self.fleet.stop_agent(name);

        let data = serde_json::json!({
            "agent": name,
            "session_state": "terminated",
            "terminated_at": now.to_rfc3339(),
            "accumulated_active_secs": accumulated,
            "policy_action": policy_action,
        });
        DaemonResponse::ok_with_data(format!("session '{name}' terminated"), data)
    }

    /// Get the current session lifecycle status for an agent.
    pub(crate) fn handle_session_lifecycle_status(&self, name: &str) -> DaemonResponse {
        let Some(slot) = self.fleet.slot(name) else {
            return DaemonResponse::error(format!("unknown agent: {name}"));
        };

        let now = chrono::Utc::now();
        let current_active_secs = if slot.session_state == SessionState::Active
            || slot.session_state == SessionState::Resumed
        {
            let elapsed = (now - slot.last_active_at).num_seconds().max(0) as u64;
            slot.accumulated_active_secs + elapsed
        } else {
            slot.accumulated_active_secs
        };

        let data = serde_json::json!({
            "agent": name,
            "session_state": slot.session_state.to_string(),
            "suspended_at": slot.suspended_at.map(|t| t.to_rfc3339()),
            "last_active_at": slot.last_active_at.to_rfc3339(),
            "accumulated_active_secs": current_active_secs,
            "is_terminal": slot.session_state.is_terminal(),
        });
        DaemonResponse::ok_with_data("session lifecycle status", data)
    }

    // -- Scheduled reply handlers --

    /// Collect live template data from the current fleet state.
    pub(crate) fn collect_template_data(&self) -> crate::scheduled_reply::TemplateData {
        let agent_count = self.fleet.agent_names().len();
        let active_agents = self
            .fleet
            .agent_names()
            .iter()
            .filter(|name| {
                self.fleet
                    .slot(name)
                    .is_some_and(|s| matches!(s.status, AgentStatus::Running { .. }))
            })
            .count();
        let uptime_secs = self.uptime_secs();
        let hours = uptime_secs / 3600;
        let mins = (uptime_secs % 3600) / 60;
        let uptime = format!("{hours}h {mins}m");
        let fleet_status = if active_agents == agent_count && agent_count > 0 {
            "all agents active".into()
        } else {
            format!("{active_agents}/{agent_count} agents active")
        };

        crate::scheduled_reply::TemplateData {
            agent_count,
            active_agents,
            total_sessions: self
                .fleet
                .agent_names()
                .iter()
                .filter(|name| {
                    self.fleet
                        .slot(name)
                        .is_some_and(|s| s.session_id.lock().is_some())
                })
                .count() as u64,
            uptime,
            fleet_status,
        }
    }

    /// Handle ScheduleReplyAdd: validate schedule, create reply, register with scheduler.
    pub(crate) fn handle_schedule_reply_add(
        &mut self,
        name: String,
        schedule_expr: String,
        channel: String,
        template: String,
        data_source: String,
    ) -> DaemonResponse {
        // Parse schedule expression.
        let schedule = match crate::cron::Schedule::parse(&schedule_expr) {
            Ok(s) => s,
            Err(e) => return DaemonResponse::error(format!("invalid schedule: {e}")),
        };

        // Parse data source.
        let ds = match data_source.as_str() {
            "fleet_status" => crate::scheduled_reply::DataSource::FleetStatus,
            "session_summary" => crate::scheduled_reply::DataSource::SessionSummary,
            "usage_report" => crate::scheduled_reply::DataSource::UsageReport,
            other => crate::scheduled_reply::DataSource::Custom {
                key: other.to_string(),
            },
        };

        // Validate channel name (security: only allow known channel targets).
        if channel != "telegram" && channel != "webhook" && channel != "log" {
            return DaemonResponse::error(format!(
                "unknown channel '{channel}': allowed channels are 'telegram', 'webhook', 'log'"
            ));
        }

        let reply = crate::scheduled_reply::ScheduledReply {
            id: uuid::Uuid::new_v4(),
            name: name.clone(),
            schedule,
            channel,
            template,
            data_source: ds,
            enabled: true,
            created_at: chrono::Utc::now(),
        };

        match self.scheduled_reply_mgr.add_scheduled_reply(reply) {
            Ok(()) => {
                info!(reply_name = %name, "scheduled reply added");
                let list = self.scheduled_reply_mgr.list_scheduled_replies();
                let data = serde_json::to_value(list).unwrap_or_default();
                DaemonResponse::ok_with_data(format!("scheduled reply '{name}' added"), data)
            }
            Err(e) => DaemonResponse::error(e),
        }
    }

    /// Handle ScheduleReplyRemove: unregister from scheduler.
    pub(crate) fn handle_schedule_reply_remove(&mut self, name: &str) -> DaemonResponse {
        if self.scheduled_reply_mgr.remove_scheduled_reply(name) {
            info!(reply_name = %name, "scheduled reply removed");
            DaemonResponse::ok(format!("scheduled reply '{name}' removed"))
        } else {
            DaemonResponse::error(format!("scheduled reply '{name}' not found"))
        }
    }

    /// Handle ScheduleReplyList: return all scheduled replies.
    pub(crate) fn handle_schedule_reply_list(&self) -> DaemonResponse {
        let list = self.scheduled_reply_mgr.list_scheduled_replies();
        match serde_json::to_value(list) {
            Ok(data) => {
                DaemonResponse::ok_with_data(format!("{} scheduled repl(ies)", list.len()), data)
            }
            Err(e) => DaemonResponse::error(format!("failed to serialize: {e}")),
        }
    }

    /// Handle ScheduleReplyTrigger: render template with current state data.
    pub(crate) fn handle_schedule_reply_trigger(&mut self, name: &str) -> DaemonResponse {
        let data = self.collect_template_data();
        match self
            .scheduled_reply_mgr
            .trigger_scheduled_reply(name, &data)
        {
            Ok((rendered, channel)) => {
                info!(reply_name = %name, channel = %channel, "scheduled reply triggered");
                let payload = serde_json::json!({
                    "name": name,
                    "channel": channel,
                    "rendered": rendered,
                    "policy_action": "schedule_reply:trigger",
                });
                DaemonResponse::ok_with_data(rendered, payload)
            }
            Err(e) => DaemonResponse::error(e),
        }
    }

    // -- Message routing handlers --

    /// Route a message envelope to an agent or channel.
    ///
    /// Validates the target agent exists, evaluates Cedar policy (RouteMessage
    /// for user messages, RouteSystemMessage for system-injected messages),
    /// sanitizes content, and enqueues via the MessageRouter.
    pub(crate) fn handle_route_message(
        &mut self,
        envelope: aegis_control::message_routing::MessageEnvelope,
    ) -> DaemonResponse {
        // Validate target agent exists in the fleet
        if self.fleet.slot(&envelope.to).is_none() {
            return DaemonResponse::error(format!(
                "routing target '{}' does not exist in the fleet",
                envelope.to
            ));
        }

        // Cedar policy gate: determine the action based on message type
        let cedar_action = if envelope.is_system {
            "RouteSystemMessage"
        } else {
            "RouteMessage"
        };

        // Evaluate Cedar policy (fail-closed if no policy engine)
        if let Some(ref engine) = self.policy_engine {
            let action = Action::new(
                envelope.from.clone(),
                ActionKind::ToolCall {
                    tool: cedar_action.to_string(),
                    args: serde_json::json!({
                        "to": envelope.to,
                        "channel": envelope.channel,
                        "is_system": envelope.is_system,
                    }),
                },
            );
            let verdict = engine.evaluate(&action);
            if verdict.decision == Decision::Deny {
                return DaemonResponse::error(format!(
                    "policy denied {cedar_action}: {}",
                    verdict.reason
                ));
            }
        }

        // Compute content hash for audit logging (not raw content)
        let content_hash = envelope.content_hash();
        let msg_from = envelope.from.clone();
        let msg_to = envelope.to.clone();
        let msg_channel = envelope.channel.clone();

        // Route through the message router (sanitization + rate limiting inside)
        match self.message_router.route_message(envelope) {
            Ok(msg_id) => {
                info!(
                    message_id = %msg_id,
                    from = %msg_from,
                    to = %msg_to,
                    channel = %msg_channel,
                    content_hash = %content_hash,
                    "message routed"
                );
                let data = serde_json::json!({
                    "message_id": msg_id.to_string(),
                    "from": msg_from,
                    "to": msg_to,
                    "channel": msg_channel,
                    "content_hash": content_hash,
                });
                DaemonResponse::ok_with_data("message routed", data)
            }
            Err(e) => DaemonResponse::error(format!("routing failed: {e}")),
        }
    }

    /// Retrieve all messages in a thread by parent message ID.
    pub(crate) fn handle_get_message_thread(&self, message_id: uuid::Uuid) -> DaemonResponse {
        let thread = self.message_router.get_thread(message_id);
        match serde_json::to_value(&thread) {
            Ok(data) => {
                DaemonResponse::ok_with_data(format!("{} message(s) in thread", thread.len()), data)
            }
            Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
        }
    }

    /// Inject a system message into an agent's input.
    ///
    /// Creates a system envelope (is_system=true), evaluates elevated Cedar
    /// policy (RouteSystemMessage), and injects into the agent's PTY stdin.
    pub(crate) fn handle_inject_system_message(
        &mut self,
        agent_name: &str,
        content: &str,
    ) -> DaemonResponse {
        // Validate agent name (security: prevent directory traversal)
        if let Err(e) = aegis_control::message_routing::validate_agent_name(agent_name) {
            return DaemonResponse::error(format!("invalid agent name: {e}"));
        }

        // Validate target agent exists
        if self.fleet.slot(agent_name).is_none() {
            return DaemonResponse::error(format!("unknown agent: {agent_name}"));
        }

        // Cedar policy gate: system message injection requires elevated action
        if let Some(ref engine) = self.policy_engine {
            let action = Action::new(
                "system",
                ActionKind::ToolCall {
                    tool: "RouteSystemMessage".to_string(),
                    args: serde_json::json!({
                        "agent": agent_name,
                        "injection": true,
                    }),
                },
            );
            let verdict = engine.evaluate(&action);
            if verdict.decision == Decision::Deny {
                return DaemonResponse::error(format!(
                    "policy denied system message injection: {}",
                    verdict.reason
                ));
            }
        }

        // Sanitize content
        let sanitized = aegis_control::message_routing::ContentSanitizer::sanitize(content);

        // Compute content hash for audit
        let envelope = aegis_control::message_routing::MessageEnvelope::system(
            agent_name, "direct", &sanitized,
        );
        let content_hash = envelope.content_hash();
        let msg_id = envelope.id;

        // Store in the router for thread tracking
        let _ = self.message_router.route_message(envelope);

        // Inject into the agent's PTY stdin
        match self.fleet.send_to_agent(agent_name, &sanitized) {
            Ok(()) => {
                info!(
                    agent = %agent_name,
                    message_id = %msg_id,
                    content_hash = %content_hash,
                    "system message injected"
                );
                let data = serde_json::json!({
                    "message_id": msg_id.to_string(),
                    "agent": agent_name,
                    "content_hash": content_hash,
                });
                DaemonResponse::ok_with_data("system message injected", data)
            }
            Err(e) => DaemonResponse::error(format!(
                "failed to inject system message into '{agent_name}': {e}"
            )),
        }
    }
}
