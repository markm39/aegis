//! DaemonRuntime main event loop and background tick methods.
//!
//! Contains `run()`, command draining, heartbeat ticking, cron, scheduled
//! replies, deferred reply delivery, and channel forwarding.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use aegis_channel::ChannelInput;
use aegis_control::daemon::DaemonCommand;
use aegis_control::event::{EventStats, PilotEventKind, PilotWebhookEvent};
use aegis_types::daemon::AgentStatus;
use aegis_types::{Action, ActionKind, Verdict};

use crate::capture::status_label;
use crate::channel_session::{
    build_channel_system_prompt, detect_channel_model, is_heartbeat_content_actionable,
    is_heartbeat_response_empty,
};
use crate::control::DaemonCmdRx;
use crate::slot::NotableEvent;
use crate::state::DaemonState;
use crate::DaemonRuntime;

use super::BROWSER_SESSION_TTL;

impl DaemonRuntime {
    /// Run the daemon main loop. Blocks until shutdown is signaled.
    ///
    /// 1. Write PID file
    /// 2. Recover from previous crash (if applicable)
    /// 3. Start control socket server
    /// 4. Start all enabled agents
    /// 5. Enter tick loop (health checks, restart logic, command dispatch)
    /// 6. On shutdown: stop all agents, clean up
    pub fn run(&mut self) -> Result<(), String> {
        use crate::persistence;
        use crate::state;
        use aegis_ledger::PiiRedactor;

        // Kill any stale daemon before we take over.
        if let Some(old_pid) = persistence::read_pid() {
            if persistence::is_process_alive(old_pid) {
                if let Ok(raw_pid) = i32::try_from(old_pid) {
                    let nix_pid = nix::unistd::Pid::from_raw(raw_pid);
                    let _ = nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGTERM);
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    if persistence::is_process_alive(old_pid) {
                        let _ =
                            nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGKILL);
                    }
                }
            }
        }

        // Write PID file
        let _pid_path = persistence::write_pid_file()?;

        // Check for previous state and recover (close orphaned audit sessions)
        if let Some(prev_state) = DaemonState::load() {
            state::recover_from_crash(&prev_state, &self.aegis_config.ledger_path);
            // Restore restart counts from previous daemon instance so
            // max_restarts guards carry across daemon restarts.
            for agent_state in &prev_state.agents {
                self.fleet
                    .restore_restart_count(&agent_state.name, agent_state.restart_count);
            }
        }

        // Validate redaction config early so bad regex surfaces immediately
        if self.config.redaction.enabled {
            match PiiRedactor::from_config(&self.config.redaction) {
                Ok(_) => info!(
                    custom_patterns = self.config.redaction.custom_patterns.len(),
                    "PII redaction enabled"
                ),
                Err(e) => tracing::error!(
                    error = %e,
                    "redaction config contains invalid patterns; redaction will be disabled"
                ),
            }
        }

        // Enforce audit retention on startup to catch accumulation during downtime
        self.enforce_retention();

        // Optionally start caffeinate (keep handle alive until function returns;
        // caffeinate self-terminates via -w when daemon PID exits)
        let _caffeinate_child = if self.config.persistence.prevent_sleep {
            Some(persistence::start_caffeinate()?)
        } else {
            None
        };

        // Start control socket server
        let (cmd_tx, mut cmd_rx) = crate::control::spawn_control_server(
            self.config.control.socket_path.clone(),
            std::sync::Arc::clone(&self.shutdown),
            self.tokio_rt.handle().clone(),
        )?;

        // Start dashboard server (read-only web UI)
        if self.config.dashboard.enabled && !self.config.dashboard.listen.trim().is_empty() {
            let token = if self.config.dashboard.api_key.trim().is_empty() {
                uuid::Uuid::new_v4().to_string()
            } else {
                self.config.dashboard.api_key.clone()
            };
            let listen = self.config.dashboard.listen.clone();
            if let Err(e) = crate::dashboard::spawn_dashboard_server(
                listen.clone(),
                token.clone(),
                cmd_tx.clone(),
                std::sync::Arc::clone(&self.shutdown),
                self.config.dashboard.rate_limit_burst,
                self.config.dashboard.rate_limit_per_sec,
                self.tokio_rt.handle().clone(),
            ) {
                warn!(error = %e, "failed to start dashboard server");
            } else {
                let url = format!("http://{listen}/?token={token}");
                info!(%url, "dashboard server started");
                self.dashboard_listen = Some(listen);
                self.dashboard_token = Some(token);
            }
        }

        // Start notification channel (Telegram) if configured
        if let Some(ref channel_config) = self.config.channel {
            let (input_tx, input_rx) = std::sync::mpsc::channel();
            let (feedback_tx, feedback_rx) = std::sync::mpsc::channel();
            let config = channel_config.clone();

            // Build channel command router from config (if present)
            let router = self
                .config
                .channel_routing
                .as_ref()
                .and_then(|routing_cfg| {
                    match aegis_channel::channel_routing::router_from_config(routing_cfg) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            warn!(error = %e, "invalid channel routing config; routing disabled");
                            None
                        }
                    }
                });

            // Load initial auto-reply rules from the store for the channel runner
            let initial_auto_reply_rules = self
                .auto_reply_store
                .as_ref()
                .and_then(|store| store.list_rules().ok())
                .unwrap_or_default();
            let rule_count = initial_auto_reply_rules.len();

            match std::thread::Builder::new()
                .name("channel".to_string())
                .spawn(move || {
                    aegis_channel::run_fleet(
                        config,
                        input_rx,
                        Some(feedback_tx),
                        router,
                        initial_auto_reply_rules,
                    );
                }) {
                Ok(handle) => {
                    self.channel_tx = Some(input_tx);
                    self.channel_cmd_rx = Some(feedback_rx);
                    self.channel_thread = Some(handle);
                    info!(auto_reply_rules = rule_count, "notification channel started");
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

        // Register running agents with the heartbeat runner.
        for name in self.fleet.agent_names_sorted() {
            if self
                .fleet
                .slot(&name)
                .is_some_and(|s| matches!(s.status, AgentStatus::Running { .. }))
            {
                self.heartbeat_runner.register_agent(&name);
            }
        }

        // Main loop
        //
        // Uses recv_timeout instead of sleep so the daemon wakes immediately
        // when a command arrives from the fleet TUI or other clients. Heavy
        // work (fleet tick, channel drain, state save) is rate-limited to ~1s.
        let tick_interval = Duration::from_secs(1);
        let state_save_interval = Duration::from_secs(30);
        let retention_interval = Duration::from_secs(3600);
        let mut last_state_save = Instant::now();
        let mut last_tick = Instant::now();

        while !self.shutdown.load(Ordering::Relaxed) {
            // Block until a command arrives OR the remaining tick interval expires.
            // This makes the daemon respond to commands instantly instead of
            // sleeping for up to 1 second.
            let timeout = tick_interval.saturating_sub(last_tick.elapsed());
            match cmd_rx.recv_timeout(timeout) {
                Ok((cmd, reply_tx)) => {
                    let response = self.handle_command(cmd);
                    let _ = reply_tx.send(response);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    warn!("control channel disconnected");
                    break;
                }
            }

            // Drain any additional commands that queued up
            self.drain_commands(&mut cmd_rx);

            // Fleet tick + heavy work only at ~1s intervals
            if last_tick.elapsed() >= tick_interval {
                // Drain inbound commands from the notification channel
                self.drain_channel_commands();

                // Check if the channel thread has exited (panic or unexpected exit)
                if let Some(handle) = &self.channel_thread {
                    if handle.is_finished() {
                        let handle = self.channel_thread.take().unwrap();
                        match handle.join() {
                            Ok(()) => {
                                tracing::warn!("notification channel thread exited unexpectedly")
                            }
                            Err(_) => tracing::error!("notification channel thread panicked"),
                        }
                        // Clear senders so we don't keep trying to send to a dead thread
                        self.channel_tx = None;
                        self.channel_cmd_rx = None;
                    }
                }

                // Tick the fleet (check for exits, apply restart policies)
                let notable_events = self.fleet.tick();

                // Record heartbeat activity for agents with notable events
                // (they're doing something, so reset their idle timer).
                for (agent_name, event) in &notable_events {
                    if matches!(
                        event,
                        NotableEvent::PendingPrompt { .. } | NotableEvent::StallNudge { .. }
                    ) {
                        self.heartbeat_runner.record_activity(agent_name);
                    }
                }

                // Relay completed subagent results back to parent orchestrators.
                self.relay_subagent_results(&notable_events);

                // Forward notable events to the notification channel
                self.forward_to_channel(notable_events);

                // Periodic orchestrator heartbeat (review cycle)
                self.maybe_send_heartbeat();

                // Agent keepalives + heartbeat-gated deferred reply drain
                self.tick_heartbeat();

                // LLM-powered channel heartbeat (HEARTBEAT.md -> LLM -> Telegram)
                self.tick_channel_heartbeat();

                // Drain time-based deferred replies that are now due
                self.drain_deferred_replies();

                // Auto-trigger due cron jobs
                self.tick_cron_jobs();

                // Auto-trigger due scheduled replies
                self.tick_scheduled_replies();

                if let Some(runtime) = self.toolkit_runtime.as_mut() {
                    runtime.prune_idle_sessions(BROWSER_SESSION_TTL);
                }

                // Periodically save state
                if last_state_save.elapsed() >= state_save_interval {
                    self.save_state();
                    last_state_save = Instant::now();
                }

                // Periodically enforce audit retention
                if self.last_retention_check.elapsed() >= retention_interval {
                    self.enforce_retention();
                    self.last_retention_check = Instant::now();
                }

                last_tick = Instant::now();
            }
        }

        info!("daemon shutting down");

        // Give background threads (control socket, dashboard) time to notice
        // the shutdown flag and exit cleanly. Without this pause, the tokio
        // runtime can be dropped while they're still running, causing a panic
        // ("A Tokio 1.x context was found, but it is being shutdown.").
        std::thread::sleep(std::time::Duration::from_millis(1500));

        // Stop all running agents to prevent orphaned processes
        self.fleet.stop_all();
        self.stop_all_capture_streams();
        if let Some(runtime) = self.toolkit_runtime.as_mut() {
            runtime.shutdown();
        }

        // Save final state
        self.save_state();

        // Shut down the alert dispatcher (drop sender to close channel, then join).
        drop(self.alert_tx.take());
        if let Some(handle) = self.alert_thread.take() {
            if let Err(e) = handle.join() {
                warn!("alert dispatcher thread panicked: {e:?}");
            }
        }

        // Clean up
        persistence::remove_pid_file();
        DaemonState::remove();

        info!("daemon shutdown complete");
        Ok(())
    }

    /// Drain all pending commands from the control socket.
    pub(crate) fn drain_commands(&mut self, cmd_rx: &mut DaemonCmdRx) {
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
    pub(crate) fn drain_channel_commands(&mut self) {
        let cmds: Vec<DaemonCommand> = match &self.channel_cmd_rx {
            Some(rx) => rx.try_iter().collect(),
            None => return,
        };

        for cmd in cmds {
            info!(?cmd, "processing command from notification channel");
            let response = self.handle_command(cmd);

            // Send the response back to the user via the notification channel,
            // checking for deferral tokens like [[defer:30s]].
            let text = if response.ok {
                response.message
            } else {
                format!("Error: {}", response.message)
            };
            self.send_to_channel_with_deferral(&text, "channel");
        }
    }

    /// Send text to the notification channel, intercepting deferral tokens.
    ///
    /// Parses `[[defer:30s]]`, `[[sleep:next_heartbeat]]`, and
    /// `[[schedule:TIMESTAMP]]` tokens. If found, the reply is enqueued in the
    /// deferred reply queue instead of being sent immediately.
    pub(crate) fn send_to_channel_with_deferral(&mut self, text: &str, agent_name: &str) {
        use crate::deferred_reply::{parse_deferral, ParseResult};

        match parse_deferral(text) {
            Ok(ParseResult::Immediate(immediate_text)) => {
                if let Some(tx) = &self.channel_tx {
                    let _ = tx.send(ChannelInput::TextMessage(immediate_text));
                }
            }
            Ok(ParseResult::Deferred { text: deferred_text, kind }) => {
                if let Err(e) = self.deferred_reply_queue.enqueue(
                    agent_name,
                    "telegram",
                    &deferred_text,
                    kind,
                ) {
                    warn!("failed to enqueue deferred reply: {e}");
                    // Fall back to immediate delivery
                    if let Some(tx) = &self.channel_tx {
                        let _ = tx.send(ChannelInput::TextMessage(deferred_text));
                    }
                }
            }
            Err(e) => {
                warn!("failed to parse deferral token: {e}");
                // Deliver as-is on parse error
                if let Some(tx) = &self.channel_tx {
                    let _ = tx.send(ChannelInput::TextMessage(text.to_string()));
                }
            }
        }
    }

    /// Reload auto-reply rules in the channel runner after a mutation.
    ///
    /// Loads all rules from the persistent store and sends them to the channel
    /// thread via `ChannelInput::ReloadAutoReplies`. The channel runner replaces
    /// its in-memory engine with the updated rules.
    pub(crate) fn reload_auto_reply_rules(&self) {
        if let Some(ref store) = self.auto_reply_store {
            if let Ok(rules) = store.list_rules() {
                if let Some(tx) = &self.channel_tx {
                    let count = rules.len();
                    let _ = tx.send(ChannelInput::ReloadAutoReplies(rules));
                    info!(rules = count, "auto-reply rules sent to channel for reload");
                }
            }
        }
    }

    pub(crate) fn maybe_send_heartbeat(&mut self) {
        let Some(tx) = &self.channel_tx else {
            return;
        };
        let now = Instant::now();
        for name in self.fleet.agent_names_sorted() {
            let Some(slot) = self.fleet.slot(&name) else {
                continue;
            };
            let Some(orch) = &slot.config.orchestrator else {
                continue;
            };
            if !matches!(slot.status, AgentStatus::Running { .. }) {
                continue;
            }
            let interval = Duration::from_secs(orch.review_interval_secs.max(30));
            let due = self
                .heartbeat_last_sent
                .get(&name)
                .map(|t| t.elapsed() >= interval)
                .unwrap_or(true);
            if !due {
                continue;
            }

            let running = self.fleet.running_count();
            let total = self.fleet.agent_count();
            let pending = self.fleet.pending_total();
            let msg = format!(
                "Heartbeat: review cycle due for {name} (interval {}s). Agents: {running}/{total} running. Pending prompts: {pending}.",
                orch.review_interval_secs
            );
            let _ = tx.send(ChannelInput::TextMessage(msg));
            self.heartbeat_last_sent.insert(name.clone(), now);
        }
    }

    /// Process heartbeat ticks: send keepalive messages to idle agents
    /// and drain heartbeat-gated deferred replies.
    pub(crate) fn tick_heartbeat(&mut self) {
        if !self.heartbeat_runner.is_tick_due() {
            return;
        }

        let messages = self.heartbeat_runner.tick();

        for msg in &messages {
            let text = format!(
                "[heartbeat] idle for {}s (seq {})",
                msg.idle_duration.as_secs(),
                msg.sequence
            );
            if let Err(e) = self.fleet.send_to_agent(&msg.agent_name, &text) {
                tracing::debug!(
                    agent = %msg.agent_name,
                    error = %e,
                    "heartbeat keepalive not delivered"
                );
            }
        }

        // Drain heartbeat-gated deferred replies.
        let heartbeat_replies = self.deferred_reply_queue.drain_heartbeat();
        for reply in heartbeat_replies {
            self.deliver_deferred_reply(reply);
        }
    }

    /// LLM-powered channel heartbeat: read HEARTBEAT.md, send to LLM with
    /// workspace context, and deliver substantive responses to Telegram.
    ///
    /// Suppresses HEARTBEAT_OK no-ops and uses adaptive backoff (up to 4x
    /// interval) when consecutive checks find nothing actionable. Duplicates
    /// are also suppressed.
    pub(crate) fn tick_channel_heartbeat(&mut self) {
        // Preflight: need channel + LLM + feature enabled.
        if self.channel_tx.is_none() || self.llm_client.is_none() {
            return;
        }
        if !self.config.channel_heartbeat.enabled {
            return;
        }

        // Adaptive backoff: effective interval grows with consecutive no-ops (up to 4x).
        let base_secs = self.config.channel_heartbeat.interval_secs;
        let backoff_mult = (1 + self.channel_heartbeat_consecutive_ok).min(4) as u64;
        let effective = std::time::Duration::from_secs(base_secs.saturating_mul(backoff_mult));
        if self.channel_heartbeat_last.elapsed() < effective {
            return;
        }
        self.channel_heartbeat_last = Instant::now();

        // Read HEARTBEAT.md from workspace.
        let path = aegis_types::daemon::workspace_dir().join("HEARTBEAT.md");
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // No file, skip silently.
        };

        // Skip if only template boilerplate (no API call wasted).
        if !is_heartbeat_content_actionable(&content) {
            return;
        }

        // Build heartbeat prompt (same format as TUI's trigger_heartbeat).
        let now = chrono::Local::now();
        let uptime_secs = self.started_at.elapsed().as_secs();
        let uptime_display = if uptime_secs < 60 {
            format!("{uptime_secs}s")
        } else if uptime_secs < 3600 {
            format!("{}m {}s", uptime_secs / 60, uptime_secs % 60)
        } else {
            format!("{}h {}m", uptime_secs / 3600, (uptime_secs % 3600) / 60)
        };

        let prompt = format!(
            "[HEARTBEAT -- autonomous check @ {}]\n\
             Daemon uptime: {}\n\
             Consecutive idle heartbeats: {}\n\n\
             ---\n\n\
             {}",
            now.format("%Y-%m-%d %H:%M %Z"),
            uptime_display,
            self.channel_heartbeat_consecutive_ok,
            content.trim(),
        );

        let model = detect_channel_model();

        // Build/cache system prompt from workspace context files.
        let system_prompt = self
            .channel_system_prompt
            .get_or_insert_with(build_channel_system_prompt)
            .clone();

        // Heartbeat uses its own isolated conversation (not channel_chat_history).
        let messages = vec![aegis_types::llm::LlmMessage::user(&prompt)];
        let request = aegis_types::llm::LlmRequest {
            model: model.clone(),
            messages,
            temperature: Some(0.3),
            max_tokens: Some(1024),
            system_prompt: Some(system_prompt),
            tools: Vec::new(),
            thinking_budget: None,
        };

        // Complete the LLM call and extract needed data before taking &mut self.
        let (response, provider_name) = {
            let client = self.llm_client.as_ref().unwrap();
            match client.complete(&request) {
                Ok(resp) => {
                    let provider = client
                        .registry()
                        .resolve_provider(&model)
                        .unwrap_or("unknown")
                        .to_string();
                    (resp, provider)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "channel heartbeat LLM call failed");
                    return;
                }
            }
        };

        let ack_max = self.config.channel_heartbeat.ack_max_chars;
        if is_heartbeat_response_empty(&response.content, ack_max) {
            self.channel_heartbeat_consecutive_ok += 1;
            tracing::debug!(
                consecutive_ok = self.channel_heartbeat_consecutive_ok,
                "channel heartbeat: no action needed"
            );
            return;
        }

        // Duplicate suppression: don't send the same text twice in a row.
        if self
            .channel_heartbeat_last_text
            .as_deref()
            == Some(response.content.trim())
        {
            tracing::debug!("channel heartbeat: duplicate response suppressed");
            self.channel_heartbeat_consecutive_ok += 1;
            return;
        }

        // Substantive response -- deliver to channel.
        self.channel_heartbeat_consecutive_ok = 0;
        self.channel_heartbeat_last_text = Some(response.content.trim().to_string());
        self.send_to_channel_with_deferral(&response.content, "heartbeat");

        // Audit log.
        let action = Action::new(
            "channel-heartbeat".to_string(),
            ActionKind::LlmComplete {
                provider: provider_name,
                model: response.model.clone(),
                endpoint: String::new(),
                input_tokens: response.usage.input_tokens,
                output_tokens: response.usage.output_tokens,
            },
        );
        let verdict = Verdict::allow(
            action.id,
            format!(
                "channel heartbeat: {} in={} out={}",
                response.model,
                response.usage.input_tokens,
                response.usage.output_tokens
            ),
            None,
        );
        self.append_audit_entry(&action, &verdict);
    }

    /// Drain time-based deferred replies that are ready for delivery.
    pub(crate) fn drain_deferred_replies(&mut self) {
        let ready = self.deferred_reply_queue.drain_ready();
        for reply in ready {
            self.deliver_deferred_reply(reply);
        }
    }

    /// Deliver a single deferred reply through the appropriate channel.
    pub(crate) fn deliver_deferred_reply(&self, reply: crate::deferred_reply::DeferredReply) {
        info!(
            id = %reply.id,
            agent = %reply.agent_name,
            channel = %reply.channel,
            "delivering deferred reply"
        );

        if reply.channel == "telegram" {
            if let Some(tx) = &self.channel_tx {
                let msg = format!("[deferred from {}] {}", reply.agent_name, reply.text);
                let _ = tx.send(ChannelInput::TextMessage(msg));
            }
        } else {
            tracing::warn!(
                channel = %reply.channel,
                "unknown delivery channel for deferred reply"
            );
        }
    }

    /// Auto-trigger due cron jobs by dispatching their commands.
    pub(crate) fn tick_cron_jobs(&mut self) {
        if !self.config.cron.enabled {
            return;
        }

        let due_jobs = self.cron_scheduler.tick_due_jobs();
        for (name, command_json) in due_jobs {
            info!(job = %name, "cron job firing");

            match serde_json::from_value::<DaemonCommand>(command_json.clone()) {
                Ok(cmd) => {
                    let response = self.handle_command(cmd);
                    if !response.ok {
                        warn!(
                            job = %name,
                            error = %response.message,
                            "cron job command failed"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        job = %name,
                        error = %e,
                        "cron job has invalid command JSON, skipping"
                    );
                }
            }
        }
    }

    /// Auto-trigger due scheduled replies, render templates, and send.
    pub(crate) fn tick_scheduled_replies(&mut self) {
        let due_names = self.scheduled_reply_mgr.tick_due_reply_names();
        if due_names.is_empty() {
            return;
        }

        let data = self.collect_template_data();
        for name in due_names {
            match self
                .scheduled_reply_mgr
                .trigger_scheduled_reply(&name, &data)
            {
                Ok((rendered, channel)) => {
                    info!(reply_name = %name, channel = %channel, "auto-triggered scheduled reply");
                    if channel == "telegram" {
                        if let Some(tx) = &self.channel_tx {
                            let _ = tx.send(ChannelInput::TextMessage(rendered));
                        }
                    }
                }
                Err(e) => {
                    warn!(reply_name = %name, error = %e, "scheduled reply auto-trigger failed");
                }
            }
        }
    }

    pub(crate) fn relay_subagent_results(&mut self, events: &[(String, NotableEvent)]) {
        use aegis_types::{Decision, Verdict};

        for (child_name, event) in events {
            let NotableEvent::ChildExited { exit_code } = event else {
                continue;
            };
            let Some(meta) = self.subagents.get(child_name).cloned() else {
                continue;
            };
            let parent = meta.parent.clone();

            let (status, role, task, working_dir, output_tail) = match self.fleet.slot(child_name) {
                Some(slot) => {
                    slot.drain_output();
                    (
                        status_label(&slot.status),
                        slot.config.role.clone(),
                        slot.config.task.clone(),
                        slot.config.working_dir.to_string_lossy().into_owned(),
                        slot.get_recent_output(40),
                    )
                }
                None => ("unknown".to_string(), None, None, String::new(), Vec::new()),
            };

            let summary = serde_json::json!({
                "event": "subagent_result",
                "parent": parent.clone(),
                "child": child_name,
                "depth": meta.depth,
                "exit_code": exit_code,
                "status": status,
                "role": role,
                "task": task,
                "working_dir": working_dir,
                "output_tail": output_tail,
            });
            let message = format!("AEGIS_SUBAGENT_RESULT {}", summary);

            let policy_action = Action::new(
                parent.clone(),
                ActionKind::ToolCall {
                    tool: "SubagentResultReturn".to_string(),
                    args: serde_json::json!({
                        "parent": parent.clone(),
                        "child": child_name,
                        "depth": meta.depth,
                        "exit_code": exit_code,
                    }),
                },
            );
            let (decision, policy_reason) = match &self.policy_engine {
                Some(engine) => {
                    let verdict = engine.evaluate(&policy_action);
                    (verdict.decision, verdict.reason)
                }
                None => (
                    Decision::Deny,
                    "policy engine unavailable; denied by fail-closed subagent result policy"
                        .to_string(),
                ),
            };

            let (delivered, delivery_error) = match decision {
                Decision::Allow => match self.fleet.send_to_agent(&parent, &message) {
                    Ok(()) => (true, None),
                    Err(err) => {
                        warn!(
                            parent = %parent,
                            child = %child_name,
                            error = %err,
                            "failed to relay subagent result to parent"
                        );
                        (false, Some(err))
                    }
                },
                Decision::Deny => (false, None),
            };

            let audit_action = Action {
                kind: ActionKind::ToolCall {
                    tool: "SubagentResultReturn".to_string(),
                    args: serde_json::json!({
                        "parent": parent.clone(),
                        "child": child_name,
                        "depth": meta.depth,
                        "exit_code": exit_code,
                        "decision": decision.to_string(),
                        "policy_reason": policy_reason,
                        "delivered": delivered,
                        "delivery_error": delivery_error,
                    }),
                },
                ..policy_action
            };
            let verdict = match decision {
                Decision::Allow if delivered => {
                    Verdict::allow(audit_action.id, "subagent result delivered to parent", None)
                }
                Decision::Allow => Verdict::allow(
                    audit_action.id,
                    "subagent result approved but parent delivery failed",
                    None,
                ),
                Decision::Deny => Verdict::deny(audit_action.id, policy_reason, None),
            };
            self.append_audit_entry(&audit_action, &verdict);
        }
    }

    /// Forward notable fleet events to the notification channel.
    ///
    /// Converts `NotableEvent`s (from `drain_updates`) into `PilotWebhookEvent`s
    /// and sends them through the channel for Telegram delivery.
    pub(crate) fn forward_to_channel(&self, events: Vec<(String, NotableEvent)>) {
        let tx = match &self.channel_tx {
            Some(tx) => tx,
            None => return,
        };

        for (agent_name, event) in events {
            let kind = match event {
                NotableEvent::PendingPrompt {
                    request_id,
                    raw_prompt,
                } => PilotEventKind::PendingApproval {
                    request_id,
                    raw_prompt,
                },
                NotableEvent::AttentionNeeded { nudge_count } => {
                    PilotEventKind::AttentionNeeded { nudge_count }
                }
                NotableEvent::StallNudge { nudge_count } => PilotEventKind::StallDetected {
                    nudge_count,
                    idle_secs: 0,
                },
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
                0, // PID not easily available from slot
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
}
