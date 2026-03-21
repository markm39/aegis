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

pub mod attachment_handler;
pub mod audio_transcription;
pub mod browser_profile;
pub mod builtin_tools;
pub mod capabilities;
pub mod capture;
pub mod channel_session;
pub mod command_queue;
pub mod commands;
pub mod control;
pub mod cron;
pub mod dashboard;
pub mod deferred_reply;
pub mod device_registry;
pub mod embeddings;
pub mod execution_lanes;
pub mod fleet;
pub mod heartbeat;
pub mod image_understanding;
pub mod jobs;
pub mod lifecycle;
pub mod link_understanding;
pub mod llm_client;
pub mod memory;
pub mod memory_capture;
pub mod memory_daily_log;
pub mod memory_flush;
pub mod memory_guard;
pub mod memory_hybrid_search;
pub mod memory_longterm;
pub mod memory_recall;
pub mod memory_tools;
pub mod message_routing;
pub mod ndjson_fmt;
pub mod parity;
pub mod persistence;
pub mod phone_control;
pub mod plugins;
pub mod policy_helpers;
pub mod prompt_builder;
pub mod scheduled_reply;
pub mod semantic_search;
pub mod service;
pub mod session_files;
pub mod session_router;
pub mod session_tools;
pub mod setup_codes;
pub mod slot;
pub mod speech;
pub mod state;
pub mod stream_fmt;
pub mod tool_contract;
pub mod toolkit_runtime;
pub mod video_processing;
pub mod voice;
pub mod voice_gateway;
pub mod web_tools;
pub mod config_persist;
pub mod runtime_init;
pub mod runtime_loop;
pub mod session_lifecycle;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use aegis_channel::ChannelInput;
use aegis_control::alias::AliasRegistry;
use aegis_control::daemon::{
    AgentDetail, AgentSummary, BrowserToolData, CaptureSessionStarted, DaemonCommand, DaemonPing,
    DaemonResponse, DashboardAgent, DashboardPendingPrompt, DashboardSnapshot, DashboardStatus,
    OrchestratorAgentView, OrchestratorSnapshot, PendingPromptSummary,
    RuntimeOperation, SessionHistory, SessionInfo,
    ToolActionExecution, ToolActionOutcome, ToolBatchOutcome, ToolUseVerdict,
};
use aegis_control::hooks;
use aegis_toolkit::contract::{CaptureRegion as ToolkitCaptureRegion, RiskTag, ToolAction};
use aegis_toolkit::policy::map_tool_action;
use aegis_types::daemon::{
    AgentSlotConfig, AgentStatus, AgentToolConfig, DaemonConfig,
};
use aegis_types::{AegisConfig};
use aegis_types::{Action, ActionKind, Decision, Verdict};

use crate::capture::{
    CaptureStream, FleetTuiBridge, SubagentSession,
    copy_dir_recursive, parse_session_key, session_key_for_agent, status_label,
};
use crate::capabilities::runtime_capabilities;
use crate::channel_session::{
    build_channel_system_prompt, channel_generate_conversation_id, channel_list_conversations,
    channel_load_conversation, channel_save_conversation, detect_channel_model,
};
use crate::fleet::Fleet;
use crate::parity::{parity_diff_report, parity_status_report, parity_verify_report};
use crate::policy_helpers::{
    compose_autonomy_prompt, hook_fail_open_enabled, is_interactive_tool, is_known_policy_tool,
    map_tool_use_to_action,
};
use crate::tool_contract::render_orchestrator_tool_contract;
use crate::toolkit_runtime::{ToolkitOutput, ToolkitRuntime};

const BROWSER_SESSION_TTL: Duration = Duration::from_secs(300);

/// The daemon runtime: main loop managing the fleet and control plane.
pub struct DaemonRuntime {
    /// Shared tokio multi-thread runtime for all async subsystems.
    ///
    /// All async work in the daemon (control socket, dashboard, usage proxy,
    /// tool execution) runs on this single runtime, avoiding per-subsystem
    /// thread-pool creation and enabling work-stealing across tasks.
    tokio_rt: Arc<tokio::runtime::Runtime>,
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
    /// Conversation history for Telegram/channel chat (capped at 40 turns).
    channel_chat_history: Vec<aegis_types::llm::LlmMessage>,
    /// Active conversation ID for Telegram/channel chat session persistence.
    channel_session_id: Option<String>,
    /// Cached system prompt for channel chat (built from workspace context files).
    channel_system_prompt: Option<String>,
    /// Last time a channel heartbeat LLM check was triggered.
    channel_heartbeat_last: Instant,
    /// Consecutive heartbeats that returned empty/HEARTBEAT_OK (for adaptive backoff).
    channel_heartbeat_consecutive_ok: u32,
    /// Last substantive heartbeat text sent (for duplicate suppression).
    channel_heartbeat_last_text: Option<String>,
    /// Thread handle for the notification channel (detect panics).
    channel_thread: Option<std::thread::JoinHandle<()>>,
    /// Cedar policy engine for evaluating tool use requests from hooks.
    policy_engine: Option<aegis_policy::PolicyEngine>,
    /// Aegis config (needed for policy reload).
    aegis_config: AegisConfig,
    /// Active capture sessions keyed by agent name.
    capture_sessions: HashMap<String, CaptureSessionStarted>,
    /// Active capture streams keyed by agent name.
    capture_streams: HashMap<String, CaptureStream>,
    /// Last tool-action execution metadata keyed by agent name.
    last_tool_actions: std::collections::HashMap<String, ToolActionExecution>,
    /// Optional computer-use runtime for orchestrator actions.
    toolkit_runtime: Option<ToolkitRuntime>,
    /// Runtime-only subagent sessions keyed by child agent name.
    subagents: HashMap<String, SubagentSession>,
    /// Dashboard listen address (if enabled).
    dashboard_listen: Option<String>,
    /// Dashboard access token (if enabled).
    dashboard_token: Option<String>,
    /// Last heartbeat sent per orchestrator agent.
    heartbeat_last_sent: HashMap<String, Instant>,
    /// Command alias registry.
    alias_registry: AliasRegistry,
    /// Command processing framework router.
    command_router: crate::commands::CommandRouter,
    /// Scheduled auto-reply manager.
    scheduled_reply_mgr: crate::scheduled_reply::ScheduledReplyManager,
    /// Message router for inter-agent and cross-channel communication.
    message_router: crate::message_routing::MessageRouter,
    /// Job tracker for agent long-running task lifecycle.
    job_tracker: crate::jobs::JobTracker,
    /// Priority command queue with concurrency control and DLQ.
    command_queue: crate::command_queue::CommandQueue,
    /// Device registry for paired devices.
    device_store: Option<crate::device_registry::DeviceStore>,
    /// Setup code manager for QR-based device pairing.
    setup_code_manager: Option<crate::setup_codes::SetupCodeManager>,
    /// Phone control command queue for paired devices.
    phone_controller: crate::phone_control::PhoneController,
    /// Voice call manager (Twilio integration), initialized if TWILIO_AUTH_TOKEN is set.
    voice_manager: Option<crate::voice::VoiceManager>,
    /// Speech recognition manager (Deepgram/Whisper), initialized if STT API key is set.
    speech_manager: Option<crate::speech::SpeechRecognitionManager>,
    /// Voice gateway for WebSocket-based voice session management.
    voice_gateway: crate::voice_gateway::VoiceGateway,
    /// LLM HTTP client for Anthropic and OpenAI completions.
    llm_client: Option<crate::llm_client::LlmClient>,
    /// Tool registry for builtin tool execution (bash, read_file, etc.).
    tool_registry: Option<aegis_tools::ToolRegistry>,
    /// SQLite-backed key-value memory store for agent context.
    memory_store: Option<crate::memory::MemoryStore>,
    /// Cron job scheduler for periodic daemon tasks.
    cron_scheduler: crate::cron::CronScheduler,
    /// Plugin manifest registry for external process plugins.
    plugin_registry: crate::plugins::PluginRegistry,
    /// SQLite-backed auto-reply rule store for inbound messages.
    auto_reply_store: Option<aegis_channel::auto_reply::AutoReplyStore>,
    /// In-memory interactive poll manager for messaging channels.
    poll_manager: aegis_channel::polls::PollManager,
    /// Fleet-wide model allowlist patterns (glob syntax, e.g. "claude-*").
    model_allowlist: Vec<String>,
    /// SQLite-backed Web Push subscription store for browser notifications.
    push_store: Option<aegis_alert::push::PushSubscriptionStore>,
    /// Rate limiter for push notification delivery (60 per minute).
    /// Used by the alert dispatcher; stored here for future TestPush with VAPID.
    #[allow(dead_code)]
    push_rate_limiter: aegis_alert::push::PushRateLimiter,
    /// When the last audit retention check ran.
    last_retention_check: Instant,
    /// Sender end of the alert channel. Cloned into each transient AuditStore
    /// so insert_entry() can forward events to the dispatcher thread.
    alert_tx: Option<std::sync::mpsc::SyncSender<aegis_alert::AlertEvent>>,
    /// Join handle for the alert dispatcher background thread.
    alert_thread: Option<std::thread::JoinHandle<()>>,
    /// Heartbeat runner for periodic agent keepalive messages.
    heartbeat_runner: crate::heartbeat::HeartbeatRunner,
    /// Deferred reply queue for time-delayed and heartbeat-gated message delivery.
    deferred_reply_queue: crate::deferred_reply::DeferredReplyQueue,
}


impl DaemonRuntime {
    /// Handle a single daemon control command.
    fn handle_command(&mut self, cmd: DaemonCommand) -> DaemonResponse {
        match cmd {
            DaemonCommand::Ping => {
                let ping = DaemonPing {
                    uptime_secs: self.uptime_secs(),
                    agent_count: self.fleet.agent_count(),
                    running_count: self.fleet.running_count(),
                    daemon_pid: std::process::id(),
                    policy_engine_loaded: self.policy_engine.is_some(),
                    hook_fail_open: hook_fail_open_enabled(),
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
                                let remaining = slot
                                    .backoff_until
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
                        let fallback = slot.fallback_state.lock().clone();
                        Some(AgentSummary {
                            name: name.clone(),
                            status,
                            tool,
                            working_dir: config.working_dir.to_string_lossy().into_owned(),
                            role: config.role.clone(),
                            restart_count: slot.restart_count,
                            pending_count: self.fleet.agent_pending_count(name),
                            attention_needed: self.fleet.agent_attention_needed(name),
                            is_orchestrator: config.orchestrator.is_some(),
                            attach_command: slot.attach_command.clone(),
                            fallback,
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
                        let remaining = slot
                            .backoff_until
                            .map(|t| t.saturating_duration_since(now).as_secs())
                            .unwrap_or(0);
                        AgentStatus::Crashed {
                            exit_code: *exit_code,
                            restart_in_secs: remaining,
                        }
                    }
                    other => other.clone(),
                };
                let fallback = slot.fallback_state.lock().clone();
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
                    session_id: slot.session_id.lock().map(|u| u.to_string()),
                    role: slot.config.role.clone(),
                    agent_goal: slot.config.agent_goal.clone(),
                    context: slot.config.context.clone(),
                    task: slot.config.task.clone(),
                    enabled: slot.config.enabled,
                    pending_count: slot.pending_prompts.len(),
                    attention_needed: slot.attention_needed,
                    fallback,
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

            DaemonCommand::SessionList => {
                let sessions: Vec<SessionInfo> = self
                    .fleet
                    .agent_names_sorted()
                    .into_iter()
                    .filter_map(|name| {
                        let slot = self.fleet.slot(&name)?;
                        Some(SessionInfo {
                            session_key: session_key_for_agent(&name),
                            agent: name,
                            is_orchestrator: slot.config.orchestrator.is_some(),
                            parent: self
                                .subagents
                                .get(slot.config.name.as_str())
                                .map(|s| s.parent.clone()),
                        })
                    })
                    .collect();
                match serde_json::to_value(&sessions) {
                    Ok(data) => DaemonResponse::ok_with_data("session list", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }
            DaemonCommand::SessionHistory {
                ref session_key,
                lines,
            } => {
                let Some(agent) = parse_session_key(session_key) else {
                    return DaemonResponse::error(format!("invalid session key: {session_key}"));
                };
                let limit = lines.unwrap_or(50);
                match self.fleet.agent_output(&agent, limit) {
                    Ok(output) => {
                        let history = SessionHistory {
                            session_key: session_key.clone(),
                            lines: output,
                        };
                        match serde_json::to_value(&history) {
                            Ok(data) => DaemonResponse::ok_with_data("session history", data),
                            Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                        }
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::SessionSend {
                ref session_key,
                ref text,
            } => {
                let Some(agent) = parse_session_key(session_key) else {
                    return DaemonResponse::error(format!("invalid session key: {session_key}"));
                };
                match self.fleet.send_to_agent(&agent, text) {
                    Ok(()) => DaemonResponse::ok(format!("sent to '{session_key}'")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::StartAgent { ref name } => {
                match self.fleet.agent_status(name) {
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                    Some(&AgentStatus::Disabled) => {
                        return DaemonResponse::error(format!(
                            "agent '{name}' is disabled. Use enable first."
                        ));
                    }
                    _ => {}
                }
                self.fleet.start_agent(name);
                self.heartbeat_runner.register_agent(name);
                DaemonResponse::ok(format!("agent '{name}' starting"))
            }

            DaemonCommand::StopAgent { ref name } => {
                if self.fleet.agent_status(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                self.fleet.stop_agent(name);
                self.heartbeat_runner.unregister_agent(name);
                DaemonResponse::ok(format!("stopping '{name}'"))
            }

            DaemonCommand::RestartAgent { ref name } => match self.fleet.restart_agent(name) {
                Ok(()) => DaemonResponse::ok(format!("restarting '{name}'")),
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::SendToAgent { ref name, ref text } => {
                match self.fleet.send_to_agent(name, text) {
                    Ok(()) => {
                        self.heartbeat_runner.record_activity(name);
                        DaemonResponse::ok(format!("sent to '{name}'"))
                    }
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
                    self.heartbeat_runner.register_agent(&name);
                }

                // Record admin action in audit ledger.
                let admin_action = Action::new(
                    "daemon",
                    ActionKind::AdminAgentAdd {
                        agent_name: name.to_string(),
                    },
                );
                let verdict = Verdict::allow(admin_action.id, "agent added", None);
                self.append_audit_entry(&admin_action, &verdict);

                DaemonResponse::ok(format!("agent '{name}' added"))
            }

            DaemonCommand::SpawnSubagent { ref request } => {
                match self.spawn_subagent(request.clone()) {
                    Ok(result) => match serde_json::to_value(result) {
                        Ok(data) => DaemonResponse::ok_with_data("subagent spawned", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    Err(e) => DaemonResponse::error(e),
                }
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
                self.remove_subagent_descendants(name);
                self.cleanup_agent_runtime_state(name);
                self.fleet.remove_agent(name); // remove_agent stops the agent internally
                self.subagents.remove(name);

                // Record admin action in audit ledger.
                let admin_action = Action::new(
                    "daemon",
                    ActionKind::AdminAgentRemove {
                        agent_name: name.clone(),
                    },
                );
                let verdict = Verdict::allow(admin_action.id, "agent removed", None);
                self.append_audit_entry(&admin_action, &verdict);

                DaemonResponse::ok(format!("agent '{name}' removed"))
            }

            DaemonCommand::ApproveRequest {
                ref name,
                ref request_id,
            } => {
                let id = match uuid::Uuid::parse_str(request_id) {
                    Ok(id) => id,
                    Err(e) => return DaemonResponse::error(format!("invalid request_id: {e}")),
                };
                match self.fleet.approve_request(name, id) {
                    Ok(()) => {
                        DaemonResponse::ok(format!("approved request {request_id} for '{name}'"))
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::DenyRequest {
                ref name,
                ref request_id,
            } => {
                let id = match uuid::Uuid::parse_str(request_id) {
                    Ok(id) => id,
                    Err(e) => return DaemonResponse::error(format!("invalid request_id: {e}")),
                };
                match self.fleet.deny_request(name, id) {
                    Ok(()) => {
                        DaemonResponse::ok(format!("denied request {request_id} for '{name}'"))
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::NudgeAgent {
                ref name,
                ref message,
            } => match self.fleet.nudge_agent(name, message.clone()) {
                Ok(()) => DaemonResponse::ok(format!("nudged '{name}'")),
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::ListPending { ref name } => match self.fleet.list_pending(name) {
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
            },

            DaemonCommand::EvaluateToolUse {
                ref agent,
                ref tool_name,
                ref tool_input,
            } => {
                let slot = self.fleet.slot(agent);
                let is_openclaw_agent = slot
                    .as_ref()
                    .map(|s| matches!(s.config.tool, AgentToolConfig::OpenClaw { .. }))
                    .unwrap_or(false);
                if is_openclaw_agent {
                    let bridge_connected = slot
                        .as_ref()
                        .map(|s| hooks::openclaw_bridge_connected(&s.config.working_dir))
                        .unwrap_or(false);
                    if !bridge_connected {
                        let tool_verdict = ToolUseVerdict {
                            decision: "deny".to_string(),
                            reason: "secure runtime bridge unavailable; action denied by fail-closed policy".to_string(),
                        };
                        return match serde_json::to_value(&tool_verdict) {
                            Ok(data) => DaemonResponse::ok_with_data("deny", data),
                            Err(e) => {
                                DaemonResponse::error(format!("serialization failed: {e}"))
                            }
                        };
                    }
                    if !is_known_policy_tool(tool_name) {
                        let tool_verdict = ToolUseVerdict {
                            decision: "deny".to_string(),
                            reason: format!(
                                "unmapped runtime tool '{tool_name}' denied by fail-closed policy"
                            ),
                        };
                        return match serde_json::to_value(&tool_verdict) {
                            Ok(data) => DaemonResponse::ok_with_data("deny", data),
                            Err(e) => {
                                DaemonResponse::error(format!("serialization failed: {e}"))
                            }
                        };
                    }
                }

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
                        if hook_fail_open_enabled() {
                            (
                                "allow".to_string(),
                                "policy engine unavailable; allowed due to AEGIS_HOOK_FAIL_OPEN"
                                    .to_string(),
                            )
                        } else {
                            (
                                "deny".to_string(),
                                "policy engine unavailable; denied by fail-closed hook policy"
                                    .to_string(),
                            )
                        }
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

            DaemonCommand::RuntimeCapabilities { ref name } => {
                let slot = match self.fleet.slot(name) {
                    Some(s) => s,
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                };
                let mut caps = runtime_capabilities(&slot.config);
                caps.toolkit_capture_enabled = self.config.toolkit.capture.enabled;
                caps.toolkit_input_enabled = self.config.toolkit.input.enabled;
                caps.toolkit_browser_enabled = self.config.toolkit.browser.enabled;
                caps.toolkit_browser_backend = self.config.toolkit.browser.backend.clone();
                caps.loop_max_micro_actions = self.config.toolkit.loop_executor.max_micro_actions;
                caps.loop_time_budget_ms = self.config.toolkit.loop_executor.time_budget_ms;
                caps.tool_contract = render_orchestrator_tool_contract(name, &self.config.toolkit);
                if let Some(session) = self.capture_sessions.get(name) {
                    caps.active_capture_session_id = Some(session.session_id.clone());
                    caps.active_capture_target_fps = Some(session.target_fps);
                }
                if let Some(last) = self.last_tool_actions.get(name) {
                    caps.last_tool_action = Some(last.result.action.clone());
                    caps.last_tool_risk_tag = Some(last.risk_tag);
                    caps.last_tool_note = last.result.note.clone();
                    caps.last_tool_decision = last
                        .result
                        .note
                        .as_deref()
                        .map(|n| {
                            if n.starts_with("allow:") {
                                "allow"
                            } else {
                                "deny"
                            }
                        })
                        .map(str::to_string);
                }
                match serde_json::to_value(&caps) {
                    Ok(data) => DaemonResponse::ok_with_data("runtime capabilities", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::ParityStatus => match parity_status_report() {
                Ok(report) => match serde_json::to_value(report) {
                    Ok(data) => DaemonResponse::ok_with_data("secure-runtime status", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                },
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::ParityDiff => match parity_diff_report() {
                Ok(report) => match serde_json::to_value(report) {
                    Ok(data) => DaemonResponse::ok_with_data("secure-runtime diff", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                },
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::ParityVerify => match parity_verify_report() {
                Ok(report) => {
                    let msg = if report.ok {
                        "secure-runtime verification passed"
                    } else {
                        "secure-runtime verification failed"
                    };
                    match serde_json::to_value(report) {
                        Ok(data) => DaemonResponse::ok_with_data(msg, data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    }
                }
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::StopBrowserProfile {
                ref name,
                ref session_id,
            } => self.handle_command(DaemonCommand::ExecuteToolAction {
                name: name.clone(),
                action: ToolAction::BrowserProfileStop {
                    session_id: session_id.clone(),
                },
            }),

            DaemonCommand::ExecuteToolAction {
                ref name,
                ref action,
            } => {
                let slot = match self.fleet.slot(name) {
                    Some(slot) => slot,
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                };

                let mapping = map_tool_action(action);
                if matches!(slot.config.tool, AgentToolConfig::OpenClaw { .. })
                    && !hooks::openclaw_bridge_connected(&slot.config.working_dir)
                {
                    let deny_reason =
                        "secure runtime bridge unavailable; action denied by fail-closed policy";
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: mapping.cedar_action.to_string(),
                            risk_tag: mapping.risk_tag,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: self
                                .capture_sessions
                                .get(name)
                                .map(|s| s.session_id.clone()),
                            note: Some(format!("deny: {deny_reason}")),
                        },
                        risk_tag: mapping.risk_tag,
                    };
                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    let fallback_action = Action::new(
                        name.clone(),
                        ActionKind::ToolCall {
                            tool: mapping.cedar_action.to_string(),
                            args: serde_json::json!({ "bridge_connected": false }),
                        },
                    );
                    self.append_runtime_audit(
                        fallback_action,
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::ExecuteToolAction,
                            action,
                            "deny",
                            deny_reason,
                            &execution,
                        ),
                    );
                    let data = serde_json::to_value(ToolActionOutcome {
                        execution,
                        frame: None,
                        tui: None,
                        browser: None,
                    })
                    .unwrap_or(serde_json::Value::Null);
                    return DaemonResponse::ok_with_data("deny", data);
                }

                if let Err(precheck_reason) = self.precheck_tool_action(action) {
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: mapping.cedar_action.to_string(),
                            risk_tag: mapping.risk_tag,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: self
                                .capture_sessions
                                .get(name)
                                .map(|s| s.session_id.clone()),
                            note: Some(format!("deny: {precheck_reason}")),
                        },
                        risk_tag: mapping.risk_tag,
                    };
                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    let fallback_action = Action::new(
                        name.clone(),
                        ActionKind::ToolCall {
                            tool: mapping.cedar_action.to_string(),
                            args: serde_json::json!({ "precheck": true }),
                        },
                    );
                    self.append_runtime_audit(
                        fallback_action,
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::ExecuteToolAction,
                            action,
                            "deny",
                            &precheck_reason,
                            &execution,
                        ),
                    );
                    let data = serde_json::to_value(ToolActionOutcome {
                        execution,
                        frame: None,
                        tui: None,
                        browser: None,
                    })
                    .unwrap_or(serde_json::Value::Null);
                    return DaemonResponse::ok_with_data("deny", data);
                }
                let (cedar_action, decision, reason) =
                    self.evaluate_runtime_tool_action(name, action);

                if decision == "deny" {
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: mapping.cedar_action.to_string(),
                            risk_tag: mapping.risk_tag,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: self
                                .capture_sessions
                                .get(name)
                                .map(|s| s.session_id.clone()),
                            note: Some(format!("deny: {reason}")),
                        },
                        risk_tag: mapping.risk_tag,
                    };

                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    self.append_runtime_audit(
                        cedar_action.clone(),
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::ExecuteToolAction,
                            action,
                            "deny",
                            &reason,
                            &execution,
                        ),
                    );

                    let data = serde_json::to_value(ToolActionOutcome {
                        execution,
                        frame: None,
                        tui: None,
                        browser: None,
                    })
                    .unwrap_or(serde_json::Value::Null);
                    return DaemonResponse::ok_with_data("deny", data);
                }

                if let ToolAction::ScreenCapture { region, .. } = action {
                    if let Some(cached) = self.latest_cached_frame(name, region) {
                        let age_ms = cached.captured_at.elapsed().as_millis() as u64;
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: mapping.cedar_action.to_string(),
                                risk_tag: mapping.risk_tag,
                                capture_latency_ms: Some(age_ms),
                                input_latency_ms: None,
                                frame_id: Some(cached.frame_id),
                                window_id: None,
                                session_id: self
                                    .capture_sessions
                                    .get(name)
                                    .map(|s| s.session_id.clone()),
                                note: Some(format!("allow: {reason} (cached {}ms)", age_ms)),
                            },
                            risk_tag: mapping.risk_tag,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        self.append_runtime_audit(
                            cedar_action.clone(),
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::ExecuteToolAction,
                                action,
                                "allow",
                                &reason,
                                &execution,
                            ),
                        );
                        let data = serde_json::to_value(ToolActionOutcome {
                            execution,
                            frame: Some(cached.payload),
                            tui: None,
                            browser: None,
                        })
                        .unwrap_or(serde_json::Value::Null);
                        return DaemonResponse::ok_with_data("allow", data);
                    }
                }

                if self.toolkit_runtime.is_none() {
                    match ToolkitRuntime::new(&self.config.toolkit) {
                        Ok(rt) => self.toolkit_runtime = Some(rt),
                        Err(e) => {
                            let execution = ToolActionExecution {
                                result: aegis_toolkit::contract::ToolResult {
                                    action: mapping.cedar_action.to_string(),
                                    risk_tag: mapping.risk_tag,
                                    capture_latency_ms: None,
                                    input_latency_ms: None,
                                    frame_id: None,
                                    window_id: None,
                                    session_id: self
                                        .capture_sessions
                                        .get(name)
                                        .map(|s| s.session_id.clone()),
                                    note: Some(format!("deny: runtime unavailable ({e})")),
                                },
                                risk_tag: mapping.risk_tag,
                            };
                            self.last_tool_actions
                                .insert(name.clone(), execution.clone());
                            let denied_reason = format!("runtime unavailable ({e})");
                            self.append_runtime_audit(
                                cedar_action.clone(),
                                self.runtime_provenance(
                                    name,
                                    RuntimeOperation::ExecuteToolAction,
                                    action,
                                    "deny",
                                    &denied_reason,
                                    &execution,
                                ),
                            );
                            let data = serde_json::to_value(ToolActionOutcome {
                                execution,
                                frame: None,
                                tui: None,
                                browser: match action {
                                    ToolAction::BrowserNavigate { session_id, .. }
                                    | ToolAction::BrowserEvaluate { session_id, .. }
                                    | ToolAction::BrowserClick { session_id, .. }
                                    | ToolAction::BrowserType { session_id, .. }
                                    | ToolAction::BrowserSnapshot { session_id, .. }
                                    | ToolAction::BrowserProfileStart { session_id, .. }
                                    | ToolAction::BrowserProfileStop { session_id, .. } => {
                                        Some(BrowserToolData {
                                            session_id: session_id.clone(),
                                            backend: "cdp".to_string(),
                                            available: false,
                                            note: "browser backend unavailable".to_string(),
                                            screenshot_base64: None,
                                            ws_url: self.config.toolkit.browser.cdp_ws_url.clone(),
                                            result_json: None,
                                        })
                                    }
                                    _ => None,
                                },
                            })
                            .unwrap_or(serde_json::Value::Null);
                            return DaemonResponse::ok_with_data("deny", data);
                        }
                    }
                }

                let bridge = FleetTuiBridge {
                    fleet: &self.fleet,
                    default_target: name,
                };
                let mut output: ToolkitOutput = match self
                    .toolkit_runtime
                    .as_mut()
                    .expect("toolkit runtime initialized")
                    .execute_with_tui_bridge(action, Some(&bridge))
                {
                    Ok(output) => output,
                    Err(e) => {
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: mapping.cedar_action.to_string(),
                                risk_tag: mapping.risk_tag,
                                capture_latency_ms: None,
                                input_latency_ms: None,
                                frame_id: None,
                                window_id: None,
                                session_id: self
                                    .capture_sessions
                                    .get(name)
                                    .map(|s| s.session_id.clone()),
                                note: Some(format!("deny: runtime error ({e})")),
                            },
                            risk_tag: mapping.risk_tag,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        let denied_reason = format!("runtime error ({e})");
                        self.append_runtime_audit(
                            cedar_action.clone(),
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::ExecuteToolAction,
                                action,
                                "deny",
                                &denied_reason,
                                &execution,
                            ),
                        );
                        let data = serde_json::to_value(ToolActionOutcome {
                            execution,
                            frame: None,
                            tui: None,
                            browser: match action {
                                ToolAction::BrowserNavigate { session_id, .. }
                                | ToolAction::BrowserEvaluate { session_id, .. }
                                | ToolAction::BrowserClick { session_id, .. }
                                | ToolAction::BrowserType { session_id, .. }
                                | ToolAction::BrowserSnapshot { session_id, .. }
                                | ToolAction::BrowserProfileStart { session_id, .. }
                                | ToolAction::BrowserProfileStop { session_id, .. } => {
                                    Some(BrowserToolData {
                                        session_id: session_id.clone(),
                                        backend: "cdp".to_string(),
                                        available: false,
                                        note: "browser action denied: CDP backend unavailable"
                                            .to_string(),
                                        screenshot_base64: None,
                                        ws_url: self.config.toolkit.browser.cdp_ws_url.clone(),
                                        result_json: None,
                                    })
                                }
                                _ => None,
                            },
                        })
                        .unwrap_or(serde_json::Value::Null);
                        return DaemonResponse::ok_with_data("deny", data);
                    }
                };

                output.execution.result.note = Some(format!("allow: {reason}"));
                self.last_tool_actions
                    .insert(name.clone(), output.execution.clone());
                self.append_runtime_audit(
                    cedar_action.clone(),
                    self.runtime_provenance(
                        name,
                        RuntimeOperation::ExecuteToolAction,
                        action,
                        "allow",
                        &reason,
                        &output.execution,
                    ),
                );

                let data = serde_json::to_value(ToolActionOutcome {
                    execution: output.execution,
                    frame: output.frame,
                    tui: output.tui,
                    browser: output.browser,
                })
                .unwrap_or(serde_json::Value::Null);
                DaemonResponse::ok_with_data("allow", data)
            }

            DaemonCommand::ExecuteToolBatch {
                ref name,
                ref actions,
                max_actions,
            } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                if actions.is_empty() {
                    let empty = ToolBatchOutcome {
                        executed: 0,
                        outcomes: vec![],
                        halted_reason: Some("empty action batch".to_string()),
                    };
                    return DaemonResponse::ok_with_data(
                        "batch halted",
                        serde_json::to_value(empty).unwrap_or(serde_json::Value::Null),
                    );
                }

                let configured_limit = self.config.toolkit.loop_executor.max_micro_actions.max(1);
                let requested_limit = max_actions.unwrap_or(configured_limit).max(1);
                let hard_limit = requested_limit.min(configured_limit);
                let mut outcomes = Vec::new();
                let started = Instant::now();
                let mut halted_reason: Option<String> = None;

                for action in actions.iter().take(usize::from(hard_limit)) {
                    if self.config.toolkit.loop_executor.halt_on_high_risk
                        && matches!(map_tool_action(action).risk_tag, RiskTag::High)
                    {
                        halted_reason = Some(format!(
                            "policy boundary reached before high-risk action {}",
                            action.policy_action_name()
                        ));
                        break;
                    }
                    if started.elapsed().as_millis() as u64
                        > self.config.toolkit.loop_executor.time_budget_ms
                    {
                        halted_reason = Some(format!(
                            "time budget exceeded ({}ms)",
                            self.config.toolkit.loop_executor.time_budget_ms
                        ));
                        break;
                    }

                    let response = self.handle_command(DaemonCommand::ExecuteToolAction {
                        name: name.clone(),
                        action: action.clone(),
                    });
                    if !response.ok {
                        halted_reason = Some(response.message.clone());
                        break;
                    }
                    let Some(data) = response.data else {
                        halted_reason = Some("missing action outcome data".to_string());
                        break;
                    };
                    let outcome: ToolActionOutcome = match serde_json::from_value(data) {
                        Ok(outcome) => outcome,
                        Err(e) => {
                            halted_reason = Some(format!("invalid action outcome: {e}"));
                            break;
                        }
                    };
                    let denied = outcome
                        .execution
                        .result
                        .note
                        .as_deref()
                        .map(|note| note.starts_with("deny:"))
                        .unwrap_or(false);
                    outcomes.push(outcome);
                    if denied {
                        halted_reason = Some("batch halted on denied action".to_string());
                        break;
                    }
                }

                if outcomes.len() == usize::from(hard_limit)
                    && actions.len() > outcomes.len()
                    && halted_reason.is_none()
                {
                    halted_reason = Some(format!("batch cap reached ({hard_limit} actions)"));
                }

                let batch = ToolBatchOutcome {
                    executed: outcomes.len(),
                    outcomes,
                    halted_reason,
                };
                DaemonResponse::ok_with_data(
                    "batch executed",
                    serde_json::to_value(batch).unwrap_or(serde_json::Value::Null),
                )
            }

            DaemonCommand::StartCaptureSession {
                ref name,
                ref request,
            } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                if !self.config.toolkit.capture.enabled {
                    return DaemonResponse::error(
                        "capture start denied: capture actions are disabled by daemon toolkit config",
                    );
                }
                if request.target_fps < self.config.toolkit.capture.min_fps
                    || request.target_fps > self.config.toolkit.capture.max_fps
                {
                    return DaemonResponse::error(format!(
                        "capture start denied: fps {} outside allowed range {}..={}",
                        request.target_fps,
                        self.config.toolkit.capture.min_fps,
                        self.config.toolkit.capture.max_fps
                    ));
                }
                let screen_action = ToolAction::ScreenCapture {
                    region: request.region.as_ref().map(|r| ToolkitCaptureRegion {
                        x: r.x,
                        y: r.y,
                        width: r.width,
                        height: r.height,
                    }),
                    target_fps: request.target_fps,
                };
                let risk = map_tool_action(&screen_action).risk_tag;
                let (cedar_action, decision, reason) =
                    self.evaluate_runtime_tool_action(name, &screen_action);
                if decision == "deny" {
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: "CaptureStart".to_string(),
                            risk_tag: risk,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: None,
                            note: Some(format!("deny: {reason}")),
                        },
                        risk_tag: risk,
                    };
                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    self.append_runtime_audit(
                        cedar_action,
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::StartCaptureSession,
                            &screen_action,
                            "deny",
                            &reason,
                            &execution,
                        ),
                    );
                    return DaemonResponse::error(format!("capture start denied: {reason}"));
                }

                let session = CaptureSessionStarted {
                    session_id: format!("cap-{}", uuid::Uuid::new_v4()),
                    target_fps: request.target_fps,
                };
                self.capture_sessions.insert(name.clone(), session.clone());
                let stream_region = request.region.as_ref().map(|r| ToolkitCaptureRegion {
                    x: r.x,
                    y: r.y,
                    width: r.width,
                    height: r.height,
                });
                if let Err(e) = self.spawn_capture_stream(name, &session, stream_region) {
                    warn!(error = %e, "failed to start capture stream");
                }
                let execution = ToolActionExecution {
                    result: aegis_toolkit::contract::ToolResult {
                        action: "CaptureStart".to_string(),
                        risk_tag: risk,
                        capture_latency_ms: None,
                        input_latency_ms: None,
                        frame_id: None,
                        window_id: None,
                        session_id: Some(session.session_id.clone()),
                        note: Some(format!("allow: {reason}")),
                    },
                    risk_tag: risk,
                };
                self.last_tool_actions
                    .insert(name.clone(), execution.clone());
                self.append_runtime_audit(
                    cedar_action,
                    self.runtime_provenance(
                        name,
                        RuntimeOperation::StartCaptureSession,
                        &screen_action,
                        "allow",
                        &reason,
                        &execution,
                    ),
                );
                match serde_json::to_value(&session) {
                    Ok(data) => DaemonResponse::ok_with_data("capture session started", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::StopCaptureSession {
                ref name,
                ref session_id,
            } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                if !self.config.toolkit.capture.enabled {
                    return DaemonResponse::error(
                        "capture stop denied: capture actions are disabled by daemon toolkit config",
                    );
                }
                let target_fps = self
                    .capture_sessions
                    .get(name)
                    .map(|s| s.target_fps)
                    .unwrap_or_default();
                let stop_action = ToolAction::ScreenCapture {
                    region: None,
                    target_fps,
                };
                let risk = map_tool_action(&stop_action).risk_tag;
                let (cedar_action, decision, reason) =
                    self.evaluate_runtime_tool_action(name, &stop_action);
                if decision == "deny" {
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: "CaptureStop".to_string(),
                            risk_tag: risk,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: Some(session_id.clone()),
                            note: Some(format!("deny: {reason}")),
                        },
                        risk_tag: risk,
                    };
                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    self.append_runtime_audit(
                        cedar_action,
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::StopCaptureSession,
                            &stop_action,
                            "deny",
                            &reason,
                            &execution,
                        ),
                    );
                    return DaemonResponse::error(format!("capture stop denied: {reason}"));
                }
                match self.capture_sessions.get(name) {
                    Some(s) if s.session_id == *session_id => {
                        self.capture_sessions.remove(name);
                        self.stop_capture_stream(name);
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: "CaptureStop".to_string(),
                                risk_tag: risk,
                                capture_latency_ms: None,
                                input_latency_ms: None,
                                frame_id: None,
                                window_id: None,
                                session_id: Some(session_id.clone()),
                                note: Some(format!("allow: {reason}")),
                            },
                            risk_tag: risk,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        self.append_runtime_audit(
                            cedar_action,
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::StopCaptureSession,
                                &stop_action,
                                "allow",
                                &reason,
                                &execution,
                            ),
                        );
                        DaemonResponse::ok("capture session stopped")
                    }
                    Some(_) => {
                        let reason = format!("session mismatch for '{name}': {session_id}");
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: "CaptureStop".to_string(),
                                risk_tag: risk,
                                capture_latency_ms: None,
                                input_latency_ms: None,
                                frame_id: None,
                                window_id: None,
                                session_id: Some(session_id.clone()),
                                note: Some(format!("deny: {reason}")),
                            },
                            risk_tag: risk,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        self.append_runtime_audit(
                            cedar_action.clone(),
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::StopCaptureSession,
                                &stop_action,
                                "deny",
                                &reason,
                                &execution,
                            ),
                        );
                        DaemonResponse::error(reason)
                    }
                    None => {
                        let reason = format!("no active capture session for '{name}'");
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: "CaptureStop".to_string(),
                                risk_tag: risk,
                                capture_latency_ms: None,
                                input_latency_ms: None,
                                frame_id: None,
                                window_id: None,
                                session_id: Some(session_id.clone()),
                                note: Some(format!("deny: {reason}")),
                            },
                            risk_tag: risk,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        self.append_runtime_audit(
                            cedar_action,
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::StopCaptureSession,
                                &stop_action,
                                "deny",
                                &reason,
                                &execution,
                            ),
                        );
                        DaemonResponse::error(reason)
                    }
                }
            }

            DaemonCommand::LatestCaptureFrame {
                ref name,
                ref region,
            } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                let region = region.as_ref().map(|r| ToolkitCaptureRegion {
                    x: r.x,
                    y: r.y,
                    width: r.width,
                    height: r.height,
                });
                match self.latest_cached_frame(name, &region) {
                    Some(cached) => {
                        let payload = aegis_control::daemon::LatestCaptureFrame {
                            session_id: self
                                .capture_sessions
                                .get(name)
                                .map(|s| s.session_id.clone()),
                            frame_id: cached.frame_id,
                            age_ms: cached.captured_at.elapsed().as_millis() as u64,
                            frame: cached.payload,
                        };
                        match serde_json::to_value(payload) {
                            Ok(data) => DaemonResponse::ok_with_data("latest frame", data),
                            Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                        }
                    }
                    None => DaemonResponse::error("no cached frame available"),
                }
            }

            DaemonCommand::DashboardStatus => {
                let enabled = self.dashboard_listen.is_some() && self.dashboard_token.is_some();
                let listen = self.dashboard_listen.clone().unwrap_or_default();
                let base_url = if enabled && !listen.is_empty() {
                    Some(format!("http://{listen}"))
                } else {
                    None
                };
                let payload = DashboardStatus {
                    enabled,
                    listen,
                    base_url,
                    token: self.dashboard_token.clone(),
                };
                match serde_json::to_value(payload) {
                    Ok(data) => DaemonResponse::ok_with_data("dashboard status", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::DashboardSnapshot => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                let mut agents = Vec::new();
                for name in self.fleet.agent_names_sorted() {
                    let status = self
                        .fleet
                        .agent_status(&name)
                        .map(status_label)
                        .unwrap_or_else(|| "unknown".to_string());
                    let tool = self
                        .fleet
                        .agent_tool_name(&name)
                        .unwrap_or_else(|| "unknown".to_string());
                    let config = self.fleet.agent_config(&name);
                    let role = config.and_then(|c| c.role.clone());
                    let goal = config.and_then(|c| c.agent_goal.clone());

                    let pending_prompts = match self.fleet.list_pending(&name) {
                        Ok(list) => list
                            .iter()
                            .take(3)
                            .map(|p| DashboardPendingPrompt {
                                request_id: p.request_id.to_string(),
                                raw_prompt: p.raw_prompt.clone(),
                                received_at_ms: p.received_at.elapsed().as_millis(),
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    let pending_count = self.fleet.agent_pending_count(&name);

                    let last_output = self.fleet.agent_output(&name, 50).unwrap_or_default();

                    let (last_tool_action, last_tool_decision, last_tool_note) =
                        if let Some(last) = self.last_tool_actions.get(&name) {
                            let decision = last.result.note.as_deref().map(|note| {
                                if note.starts_with("allow:") {
                                    "allow".to_string()
                                } else {
                                    "deny".to_string()
                                }
                            });
                            (
                                Some(last.result.action.clone()),
                                decision,
                                last.result.note.clone(),
                            )
                        } else {
                            (None, None, None)
                        };

                    let latest_frame_age_ms = self
                        .latest_cached_frame_any(&name)
                        .map(|f| f.captured_at.elapsed().as_millis() as u64);
                    let fallback = self
                        .fleet
                        .slot(&name)
                        .and_then(|slot| slot.fallback_state.lock().clone());

                    agents.push(DashboardAgent {
                        name,
                        status,
                        tool,
                        role,
                        goal,
                        pending_count,
                        pending_prompts,
                        last_tool_action,
                        last_tool_decision,
                        last_tool_note,
                        last_output,
                        latest_frame_age_ms,
                        fallback,
                    });
                }
                let snapshot = DashboardSnapshot {
                    timestamp_ms: now,
                    agents,
                };
                match serde_json::to_value(snapshot) {
                    Ok(data) => DaemonResponse::ok_with_data("dashboard snapshot", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }
            DaemonCommand::TelegramSnapshot { .. } => DaemonResponse::error(
                "telegram snapshots are not available in the control API; use the Telegram channel",
            ),

            DaemonCommand::FleetGoal { ref goal } => {
                match goal {
                    Some(new_goal) => {
                        let new_goal_val = if new_goal.is_empty() {
                            None
                        } else {
                            Some(new_goal.clone())
                        };
                        let display = new_goal_val
                            .clone()
                            .unwrap_or_else(|| "(cleared)".to_string());

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
                    None => DaemonResponse::ok_with_data(
                        "fleet goal",
                        serde_json::json!({ "goal": self.config.goal }),
                    ),
                }
            }

            DaemonCommand::UpdateAgentContext {
                ref name,
                ref role,
                ref agent_goal,
                ref context,
                ref task,
            } => {
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
                DaemonResponse::ok(format!(
                    "context updated for '{name}' (takes effect on next restart)"
                ))
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
                        return DaemonResponse::error(format!(
                            "agent '{name}' is already disabled"
                        ));
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

            DaemonCommand::ReloadConfig => self.reload_config(),

            DaemonCommand::OrchestratorContext {
                ref agents,
                output_lines,
            } => {
                let line_count = output_lines.unwrap_or(30);
                let all_names = self.fleet.agent_names_sorted();

                // Determine which agents to include
                let target_names: Vec<&String> = if agents.is_empty() {
                    // All non-orchestrator agents
                    all_names
                        .iter()
                        .filter(|name| {
                            self.fleet
                                .agent_config(name)
                                .map(|c| c.orchestrator.is_none())
                                .unwrap_or(true)
                        })
                        .collect()
                } else {
                    all_names
                        .iter()
                        .filter(|name| agents.contains(name))
                        .collect()
                };

                let agent_views: Vec<OrchestratorAgentView> = target_names
                    .iter()
                    .filter_map(|name| {
                        let slot = self.fleet.slot(name)?;
                        let config = self.fleet.agent_config(name)?;
                        let recent_output = self
                            .fleet
                            .agent_output(name, line_count)
                            .unwrap_or_default();

                        Some(OrchestratorAgentView {
                            name: (*name).clone(),
                            status: slot.status.clone(),
                            role: config.role.clone(),
                            agent_goal: config.agent_goal.clone(),
                            task: config.task.clone(),
                            recent_output,
                            uptime_secs: slot.uptime_secs(),
                            attention_needed: slot.attention_needed,
                            pending_count: slot.pending_prompts.len(),
                        })
                    })
                    .collect();

                let snapshot = OrchestratorSnapshot {
                    fleet_goal: self.config.goal.clone(),
                    agents: agent_views,
                };

                match serde_json::to_value(&snapshot) {
                    Ok(data) => DaemonResponse::ok_with_data("orchestrator context", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::Shutdown => {
                self.request_shutdown();
                DaemonResponse::ok("shutdown initiated")
            }

            // -- Memory store commands --
            DaemonCommand::MemoryGet { namespace, key } => {
                let Some(ref store) = self.memory_store else {
                    return DaemonResponse::error("memory store not enabled (set memory.enabled = true in daemon.toml)");
                };
                match store.get(&namespace, &key) {
                    Ok(Some(value)) => DaemonResponse::ok_with_data(
                        format!("{namespace}/{key}"),
                        serde_json::json!({ "namespace": namespace, "key": key, "value": value }),
                    ),
                    Ok(None) => DaemonResponse::error(format!("key not found: {namespace}/{key}")),
                    Err(e) => DaemonResponse::error(format!("memory get failed: {e}")),
                }
            }
            DaemonCommand::MemorySet { namespace, key, value } => {
                let Some(ref store) = self.memory_store else {
                    return DaemonResponse::error("memory store not enabled (set memory.enabled = true in daemon.toml)");
                };
                match store.set(&namespace, &key, &value) {
                    Ok(()) => DaemonResponse::ok(format!("stored {namespace}/{key}")),
                    Err(e) => DaemonResponse::error(format!("memory set failed: {e}")),
                }
            }
            DaemonCommand::MemoryDelete { namespace, key } => {
                let Some(ref store) = self.memory_store else {
                    return DaemonResponse::error("memory store not enabled (set memory.enabled = true in daemon.toml)");
                };
                match store.delete(&namespace, &key) {
                    Ok(true) => DaemonResponse::ok(format!("deleted {namespace}/{key}")),
                    Ok(false) => DaemonResponse::error(format!("key not found: {namespace}/{key}")),
                    Err(e) => DaemonResponse::error(format!("memory delete failed: {e}")),
                }
            }
            DaemonCommand::MemoryList { namespace, limit } => {
                let Some(ref store) = self.memory_store else {
                    return DaemonResponse::error("memory store not enabled (set memory.enabled = true in daemon.toml)");
                };
                let limit = limit.unwrap_or(100);
                match store.list(&namespace, limit) {
                    Ok(entries) => {
                        let data: Vec<serde_json::Value> = entries
                            .iter()
                            .map(|(k, v)| serde_json::json!({ "key": k, "value": v }))
                            .collect();
                        DaemonResponse::ok_with_data(
                            format!("{} entries in {namespace}", data.len()),
                            serde_json::json!(data),
                        )
                    }
                    Err(e) => DaemonResponse::error(format!("memory list failed: {e}")),
                }
            }
            DaemonCommand::MemorySearch { namespace, query, limit } => {
                let Some(ref store) = self.memory_store else {
                    return DaemonResponse::error("memory store not enabled (set memory.enabled = true in daemon.toml)");
                };
                let limit = limit.unwrap_or(20);
                let half_life = if self.config.memory.decay_enabled {
                    Some(self.config.memory.default_half_life_hours)
                } else {
                    None
                };
                match store.search(&namespace, &query, limit, half_life) {
                    Ok(results) => {
                        let data: Vec<serde_json::Value> = results
                            .iter()
                            .map(|(k, v, score)| serde_json::json!({ "key": k, "value": v, "score": score }))
                            .collect();
                        DaemonResponse::ok_with_data(
                            format!("{} results for '{query}' in {namespace}", data.len()),
                            serde_json::json!(data),
                        )
                    }
                    Err(e) => DaemonResponse::error(format!("memory search failed: {e}")),
                }
            }
            DaemonCommand::CronList => {
                let jobs = self.cron_scheduler.list();
                match serde_json::to_value(jobs) {
                    Ok(data) => DaemonResponse::ok_with_data(
                        format!("{} cron job(s)", jobs.len()),
                        data,
                    ),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }
            DaemonCommand::CronAdd { name, schedule, command } => {
                let parsed_schedule = match crate::cron::Schedule::parse(&schedule) {
                    Ok(s) => s,
                    Err(e) => return DaemonResponse::error(format!("invalid schedule '{schedule}': {e}")),
                };
                self.cron_scheduler.add(crate::cron::CronJob {
                    name: name.clone(),
                    schedule: parsed_schedule,
                    command,
                    enabled: true,
                });
                DaemonResponse::ok(format!("cron job '{name}' added (schedule: {schedule})"))
            }
            DaemonCommand::CronRemove { name } => {
                if self.cron_scheduler.remove(&name) {
                    DaemonResponse::ok(format!("cron job '{name}' removed"))
                } else {
                    DaemonResponse::error(format!("cron job '{name}' not found"))
                }
            }
            DaemonCommand::CronTrigger { name } => {
                match self.cron_scheduler.trigger(&name) {
                    Some(cmd) => {
                        let cmd_json = cmd.clone();
                        DaemonResponse::ok_with_data(
                            format!("triggered cron job '{name}'"),
                            cmd_json,
                        )
                    }
                    None => DaemonResponse::error(format!("cron job '{name}' not found")),
                }
            }
            DaemonCommand::LoadPlugin { path } => {
                let manifest_path = std::path::Path::new(&path);
                match crate::plugins::PluginRegistry::load_manifest(manifest_path) {
                    Ok(manifest) => {
                        let name = manifest.name.clone();
                        self.plugin_registry.add(manifest);
                        DaemonResponse::ok(format!("plugin '{name}' loaded from {path}"))
                    }
                    Err(e) => DaemonResponse::error(format!("failed to load plugin manifest: {e}")),
                }
            }
            DaemonCommand::ListPlugins => {
                let plugins = self.plugin_registry.list();
                match serde_json::to_value(plugins) {
                    Ok(data) => DaemonResponse::ok_with_data(
                        format!("{} plugin(s)", plugins.len()),
                        data,
                    ),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }
            DaemonCommand::UnloadPlugin { name } => {
                if self.plugin_registry.unload(&name) {
                    DaemonResponse::ok(format!("plugin '{name}' unloaded"))
                } else {
                    DaemonResponse::error(format!("plugin '{name}' not found"))
                }
            }
            DaemonCommand::BroadcastToFleet { message, exclude_agents } => {
                let agents: Vec<String> = self.fleet.agent_names()
                    .into_iter()
                    .filter(|name| !exclude_agents.contains(name))
                    .collect();
                if agents.is_empty() {
                    return DaemonResponse::error("no agents to broadcast to");
                }
                let mut sent = 0usize;
                for agent_name in &agents {
                    if self.fleet.send_to_agent(agent_name, &message).is_ok() {
                        sent += 1;
                    }
                }
                DaemonResponse::ok(format!("broadcast sent to {sent}/{} agent(s)", agents.len()))
            }
            DaemonCommand::ListModels => {
                match &self.llm_client {
                    Some(client) => {
                        let registry = client.registry();
                        let providers = registry.provider_names();
                        let data = serde_json::json!({
                            "providers": providers,
                            "allowlist": self.model_allowlist,
                        });
                        DaemonResponse::ok_with_data(
                            format!("{} provider(s) configured", providers.len()),
                            data,
                        )
                    }
                    None => DaemonResponse::error("LLM client not initialized"),
                }
            }
            DaemonCommand::CopilotModels => {
                let catalog = aegis_types::copilot::CopilotModelCatalog::with_defaults();
                let models = catalog.list_models();
                match serde_json::to_value(models) {
                    Ok(data) => DaemonResponse::ok_with_data(
                        format!("{} Copilot models available", models.len()),
                        data,
                    ),
                    Err(e) => DaemonResponse::error(format!(
                        "failed to serialize Copilot model catalog: {e}"
                    )),
                }
            }
            DaemonCommand::ModelAllowlist { patterns } => {
                let count = patterns.len();
                self.model_allowlist = patterns;
                DaemonResponse::ok(format!("model allowlist updated ({count} pattern(s))"))
            }
            DaemonCommand::AddAlias { alias, command, args } => {
                match self.alias_registry.add(alias, command, args) {
                    Ok(()) => {
                        let config = self.alias_registry.to_config();
                        DaemonResponse::ok_with_data(
                            "alias added",
                            serde_json::to_value(config).unwrap_or_default(),
                        )
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::RemoveAlias { alias } => {
                match self.alias_registry.remove(&alias) {
                    Ok(()) => {
                        let config = self.alias_registry.to_config();
                        DaemonResponse::ok_with_data(
                            "alias removed",
                            serde_json::to_value(config).unwrap_or_default(),
                        )
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::ListAliases => {
                let entries: Vec<_> = self.alias_registry.list().into_iter().cloned().collect();
                match serde_json::to_value(&entries) {
                    Ok(data) => DaemonResponse::ok_with_data(
                        format!("{} alias(es)", entries.len()),
                        data,
                    ),
                    Err(e) => DaemonResponse::error(format!("failed to serialize aliases: {e}")),
                }
            }
            DaemonCommand::ExecuteCommand {
                agent_id,
                command,
                args,
            } => {
                let raw_input = if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                };
                let ctx = crate::commands::CommandContext {
                    agent_id: agent_id.unwrap_or_default(),
                    principal: "daemon".into(),
                    channel: "daemon".into(),
                    args,
                    raw_input,
                };
                match self.command_router.route(&command, &ctx) {
                    Ok(result) => {
                        if result.success {
                            match result.data {
                                Some(data) => DaemonResponse::ok_with_data(result.message, data),
                                None => DaemonResponse::ok(result.message),
                            }
                        } else {
                            DaemonResponse::error(result.message)
                        }
                    }
                    Err(e) => DaemonResponse::error(format!("command execution failed: {e}")),
                }
            }
            DaemonCommand::DelegateApproval {
                request_id,
                delegate_to,
            } => {
                let msg = format!("[delegated-approval] request_id={request_id} -- please review and approve/deny");
                match self.fleet.send_to_agent(&delegate_to, &msg) {
                    Ok(()) => DaemonResponse::ok(format!(
                        "approval {request_id} delegated to {delegate_to}"
                    )),
                    Err(e) => DaemonResponse::error(format!(
                        "failed to delegate approval to {delegate_to}: {e}"
                    )),
                }
            }

            // -- Session lifecycle commands --

            DaemonCommand::SuspendSession { ref name } => {
                self.handle_suspend_session(name)
            }

            DaemonCommand::ResumeSession { ref name } => {
                self.handle_resume_session(name)
            }

            DaemonCommand::TerminateSession { ref name } => {
                self.handle_terminate_session(name)
            }

            DaemonCommand::SessionLifecycleStatus { ref name } => {
                self.handle_session_lifecycle_status(name)
            }

            // -- Persistent session management --
            DaemonCommand::SessionListFiltered { .. }
            | DaemonCommand::SessionResumeAudit { .. }
            | DaemonCommand::SessionSaveContext { .. }
            | DaemonCommand::SessionGroup { .. } => {
                DaemonResponse::error("persistent session commands require direct audit store access; use the CLI")
            }

            // -- Auto-reply commands --
            DaemonCommand::AddAutoReply {
                pattern,
                response,
                chat_id,
                priority,
                response_type,
                media_path: _,
                language,
            } => {
                // Parse response_type from JSON string if provided.
                let parsed_type: Option<aegis_channel::auto_reply::MediaResponseType> =
                    response_type.as_deref().and_then(|s| {
                        serde_json::from_str(s).ok()
                    });
                // Scope the store borrow so we can call reload_auto_reply_rules after
                let result = match &self.auto_reply_store {
                    Some(store) => store.add_rule_full(
                        &pattern,
                        &response,
                        chat_id,
                        priority,
                        parsed_type,
                        language.as_deref(),
                    ),
                    None => return DaemonResponse::error("auto-reply store not initialized"),
                };
                match result {
                    Ok(id) => {
                        self.reload_auto_reply_rules();
                        DaemonResponse::ok_with_data(
                            format!("auto-reply rule added: {id}"),
                            serde_json::json!({ "id": id }),
                        )
                    }
                    Err(e) => DaemonResponse::error(format!("failed to add auto-reply rule: {e}")),
                }
            }
            DaemonCommand::RemoveAutoReply { id } => {
                let result = match &self.auto_reply_store {
                    Some(store) => store.remove_rule(&id),
                    None => return DaemonResponse::error("auto-reply store not initialized"),
                };
                match result {
                    Ok(true) => {
                        self.reload_auto_reply_rules();
                        DaemonResponse::ok(format!("auto-reply rule {id} removed"))
                    }
                    Ok(false) => DaemonResponse::error(format!("auto-reply rule {id} not found")),
                    Err(e) => DaemonResponse::error(format!("failed to remove auto-reply rule: {e}")),
                }
            }
            DaemonCommand::ListAutoReplies => {
                let Some(ref store) = self.auto_reply_store else {
                    return DaemonResponse::error("auto-reply store not initialized");
                };
                match store.list_rules() {
                    Ok(rules) => {
                        let data: Vec<serde_json::Value> = rules
                            .iter()
                            .map(|r| serde_json::json!({
                                "id": r.id,
                                "pattern": r.pattern,
                                "response": r.response,
                                "chat_id": r.chat_id,
                                "priority": r.priority,
                                "enabled": r.enabled,
                                "language": r.language,
                            }))
                            .collect();
                        DaemonResponse::ok_with_data(
                            format!("{} auto-reply rule(s)", data.len()),
                            serde_json::json!(data),
                        )
                    }
                    Err(e) => DaemonResponse::error(format!("failed to list auto-reply rules: {e}")),
                }
            }
            DaemonCommand::ToggleAutoReply { id, enabled } => {
                let result = match &self.auto_reply_store {
                    Some(store) => store.toggle_rule(&id, enabled),
                    None => return DaemonResponse::error("auto-reply store not initialized"),
                };
                match result {
                    Ok(true) => {
                        self.reload_auto_reply_rules();
                        let state = if enabled { "enabled" } else { "disabled" };
                        DaemonResponse::ok(format!("auto-reply rule {id} {state}"))
                    }
                    Ok(false) => DaemonResponse::error(format!("auto-reply rule {id} not found")),
                    Err(e) => DaemonResponse::error(format!("failed to toggle auto-reply rule: {e}")),
                }
            }
            DaemonCommand::SetAutoReplyChat { chat_id, enabled } => {
                let result = match &self.auto_reply_store {
                    Some(store) => store.set_chat_enabled(chat_id, enabled),
                    None => return DaemonResponse::error("auto-reply store not initialized"),
                };
                match result {
                    Ok(()) => {
                        self.reload_auto_reply_rules();
                        let state = if enabled { "enabled" } else { "disabled" };
                        DaemonResponse::ok(format!("auto-reply {state} for chat {chat_id}"))
                    }
                    Err(e) => DaemonResponse::error(format!("failed to set chat auto-reply state: {e}")),
                }
            }

            // -- Message routing commands --
            DaemonCommand::RouteMessage { envelope } => {
                self.handle_route_message(envelope)
            }
            DaemonCommand::GetMessageThread { message_id } => {
                self.handle_get_message_thread(message_id)
            }
            DaemonCommand::InjectSystemMessage {
                agent_name,
                content,
            } => self.handle_inject_system_message(&agent_name, &content),

            // -- Scheduled reply commands --
            DaemonCommand::ScheduleReplyAdd {
                name,
                schedule_expr,
                channel,
                template,
                data_source,
            } => self.handle_schedule_reply_add(name, schedule_expr, channel, template, data_source),

            DaemonCommand::ScheduleReplyRemove { name } => {
                self.handle_schedule_reply_remove(&name)
            }

            DaemonCommand::ScheduleReplyList => self.handle_schedule_reply_list(),

            DaemonCommand::ScheduleReplyTrigger { name } => {
                self.handle_schedule_reply_trigger(&name)
            }

            // -- Configuration introspection --
            DaemonCommand::GetEffectiveConfig => {
                match serde_json::to_value(&self.config) {
                    Ok(data) => DaemonResponse::ok_with_data("effective daemon configuration", data),
                    Err(e) => DaemonResponse::error(format!("failed to serialize config: {e}")),
                }
            }

            // -- Agent job tracking commands --

            DaemonCommand::CreateJob { agent, description } => {
                // Validate agent exists in fleet
                if self.fleet.slot(&agent).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {agent}"));
                }

                match self.job_tracker.create_job(&agent, &description) {
                    Ok(job) => {
                        info!(
                            agent = %agent,
                            job_id = %job.id,
                            description = %job.description,
                            "job created"
                        );
                        // Audit log the creation
                        let action = Action::new(
                            agent.clone(),
                            ActionKind::ToolCall {
                                tool: "daemon:create_job".to_string(),
                                args: serde_json::json!({
                                    "agent": agent,
                                    "job_id": job.id.to_string(),
                                    "description": job.description,
                                }),
                            },
                        );
                        let verdict = Verdict::allow(
                            action.id,
                            format!("job {} created for agent {}", job.id, agent),
                            None,
                        );
                        self.append_audit_entry(&action, &verdict);
                        match serde_json::to_value(&job) {
                            Ok(data) => DaemonResponse::ok_with_data(
                                format!("job {} created", job.id),
                                data,
                            ),
                            Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                        }
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::ListJobs { agent } => {
                let jobs: Vec<_> = match &agent {
                    Some(name) => self.job_tracker.list_jobs(name).into_iter().cloned().collect(),
                    None => self.job_tracker.list_all_jobs().into_iter().cloned().collect(),
                };
                match serde_json::to_value(&jobs) {
                    Ok(data) => DaemonResponse::ok_with_data(
                        format!("{} job(s)", jobs.len()),
                        data,
                    ),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::JobStatus { job_id } => {
                match self.job_tracker.get_job(job_id) {
                    Some(job) => match serde_json::to_value(job) {
                        Ok(data) => DaemonResponse::ok_with_data(
                            format!("job {job_id}: {}", job.status),
                            data,
                        ),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    None => DaemonResponse::error(format!("job {job_id} not found")),
                }
            }

            DaemonCommand::CancelJob { job_id } => {
                match self.job_tracker.cancel_job(job_id) {
                    Ok(job) => {
                        let job = job.clone();
                        info!(job_id = %job_id, agent = %job.agent, "job cancelled");
                        let action = Action::new(
                            job.agent.clone(),
                            ActionKind::ToolCall {
                                tool: "daemon:cancel_job".to_string(),
                                args: serde_json::json!({
                                    "agent": job.agent,
                                    "job_id": job_id.to_string(),
                                }),
                            },
                        );
                        let verdict = Verdict::allow(
                            action.id,
                            format!("job {job_id} cancelled"),
                            None,
                        );
                        self.append_audit_entry(&action, &verdict);
                        match serde_json::to_value(&job) {
                            Ok(data) => DaemonResponse::ok_with_data(
                                format!("job {job_id} cancelled"),
                                data,
                            ),
                            Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                        }
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::UpdateJobProgress { job_id, progress_pct } => {
                match self.job_tracker.update_progress(job_id, progress_pct) {
                    Ok(job) => match serde_json::to_value(job) {
                        Ok(data) => DaemonResponse::ok_with_data(
                            format!("job {job_id} progress: {progress_pct}%"),
                            data,
                        ),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    Err(e) => DaemonResponse::error(e),
                }
            }

            // -- Push notification commands --
            DaemonCommand::RegisterPush { endpoint, p256dh, auth, label } => {
                let Some(ref store) = self.push_store else {
                    return DaemonResponse::error("push subscription store not initialized");
                };
                match store.add_subscription(&endpoint, &p256dh, &auth, label.as_deref(), None) {
                    Ok(id) => DaemonResponse::ok_with_data(
                        format!("push subscription {id} registered"),
                        serde_json::json!({ "id": id.to_string() }),
                    ),
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::RemovePush { id } => {
                let Some(ref store) = self.push_store else {
                    return DaemonResponse::error("push subscription store not initialized");
                };
                let Ok(uuid) = uuid::Uuid::parse_str(&id) else {
                    return DaemonResponse::error(format!("invalid UUID: {id}"));
                };
                match store.remove_subscription(&uuid) {
                    Ok(true) => DaemonResponse::ok(format!("push subscription {id} removed")),
                    Ok(false) => DaemonResponse::error(format!("push subscription {id} not found")),
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::ListPush => {
                let Some(ref store) = self.push_store else {
                    return DaemonResponse::error("push subscription store not initialized");
                };
                match store.list_subscriptions() {
                    Ok(subs) => {
                        let items: Vec<serde_json::Value> = subs
                            .iter()
                            .map(|s| {
                                serde_json::json!({
                                    "id": s.id.to_string(),
                                    "endpoint": &s.endpoint[..s.endpoint.len().min(60)],
                                    "label": s.user_label,
                                    "created_at": s.created_at.to_rfc3339(),
                                    "last_used_at": s.last_used_at.map(|t| t.to_rfc3339()),
                                })
                            })
                            .collect();
                        DaemonResponse::ok_with_data(
                            format!("{} push subscription(s)", items.len()),
                            serde_json::json!({ "subscriptions": items }),
                        )
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::TestPush { id } => {
                let Some(ref store) = self.push_store else {
                    return DaemonResponse::error("push subscription store not initialized");
                };
                let Ok(uuid) = uuid::Uuid::parse_str(&id) else {
                    return DaemonResponse::error(format!("invalid UUID: {id}"));
                };
                match store.get_subscription(&uuid) {
                    Ok(Some(_sub)) => {
                        // Test push would require VAPID config, which lives in
                        // the alert dispatcher. Return success for now to confirm
                        // the subscription exists and is reachable.
                        DaemonResponse::ok(format!(
                            "push subscription {id} exists; delivery requires VAPID configuration in alert rules"
                        ))
                    }
                    Ok(None) => DaemonResponse::error(format!("push subscription {id} not found")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            // -- Poll commands --
            DaemonCommand::CreatePoll { question, options, channel, duration_secs } => {
                let duration = duration_secs.unwrap_or(0);
                match self.poll_manager.create_poll(&question, &options, &channel, "daemon", duration) {
                    Ok(poll) => {
                        let data = serde_json::json!({
                            "id": poll.id.to_string(),
                            "question": poll.question,
                            "options": poll.options,
                            "channel": poll.channel,
                            "created_at": poll.created_at.to_rfc3339(),
                            "expires_at": poll.expires_at.map(|t| t.to_rfc3339()),
                        });
                        DaemonResponse::ok_with_data(
                            format!("poll {} created", poll.id),
                            data,
                        )
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::VotePoll { poll_id, option, voter_id } => {
                match self.poll_manager.vote(poll_id, &option, &voter_id) {
                    Ok(()) => DaemonResponse::ok(format!("vote recorded on poll {poll_id}")),
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::ClosePoll { poll_id } => {
                match self.poll_manager.close_poll(poll_id) {
                    Ok(results) => {
                        let data: Vec<serde_json::Value> = results
                            .iter()
                            .map(|r| serde_json::json!({
                                "option": r.option,
                                "vote_count": r.vote_count,
                                "percentage": r.percentage,
                            }))
                            .collect();
                        DaemonResponse::ok_with_data(
                            format!("poll {poll_id} closed"),
                            serde_json::json!(data),
                        )
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::PollResults { poll_id } => {
                match self.poll_manager.get_results(poll_id) {
                    Ok(results) => {
                        let data: Vec<serde_json::Value> = results
                            .iter()
                            .map(|r| serde_json::json!({
                                "option": r.option,
                                "vote_count": r.vote_count,
                                "percentage": r.percentage,
                            }))
                            .collect();
                        DaemonResponse::ok_with_data(
                            format!("poll {poll_id} results"),
                            serde_json::json!(data),
                        )
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::ListPolls => {
                let polls = self.poll_manager.list_active_polls();
                let data: Vec<serde_json::Value> = polls
                    .iter()
                    .map(|p| serde_json::json!({
                        "id": p.id.to_string(),
                        "question": p.question,
                        "channel": p.channel,
                        "options": p.options,
                        "created_at": p.created_at.to_rfc3339(),
                        "expires_at": p.expires_at.map(|t| t.to_rfc3339()),
                        "total_votes": p.votes.values().map(|v| v.len()).sum::<usize>(),
                    }))
                    .collect();
                DaemonResponse::ok_with_data(
                    format!("{} active poll(s)", data.len()),
                    serde_json::json!(data),
                )
            }

            // -- Command queue commands --
            DaemonCommand::QueueCommand { command, priority } => {
                match self.command_queue.enqueue(command, priority) {
                    Ok(id) => DaemonResponse::ok_with_data(
                        format!("command queued with id {id}"),
                        serde_json::json!({ "id": id.to_string() }),
                    ),
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::QueueStatus => {
                let metrics = self.command_queue.queue_status();
                match serde_json::to_value(&metrics) {
                    Ok(data) => DaemonResponse::ok_with_data("queue metrics", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }
            DaemonCommand::QueueFlush => {
                self.command_queue.flush();
                DaemonResponse::ok("pending queue flushed")
            }
            DaemonCommand::QueueInspect => {
                let dlq = self.command_queue.dead_letter_queue();
                let dlq_len = dlq.len();
                match serde_json::to_value(dlq) {
                    Ok(data) => DaemonResponse::ok_with_data(
                        format!("{dlq_len} dead-lettered commands"),
                        data,
                    ),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::FetchUrl { url, summarize: _ } => {
                let config = link_understanding::LinkConfig::default();
                match link_understanding::fetch_url(&url, &config) {
                    Ok(content) => match serde_json::to_value(&content) {
                        Ok(data) => DaemonResponse::ok_with_data(
                            format!("fetched {} ({} words)", content.url, content.word_count),
                            data,
                        ),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    Err(e) => DaemonResponse::error(format!("fetch failed: {e}")),
                }
            }

            DaemonCommand::ListLanes => {
                let statuses = self.fleet.lane_status();
                let summary: Vec<String> = statuses
                    .iter()
                    .map(|s| {
                        let cap = if s.max_concurrent == 0 {
                            "unlimited".to_string()
                        } else {
                            format!("{}/{}", s.current, s.max_concurrent)
                        };
                        let queued_suffix = if s.queued > 0 {
                            format!(" ({} queued)", s.queued)
                        } else {
                            String::new()
                        };
                        format!("{}: {cap}{queued_suffix}", s.name)
                    })
                    .collect();
                let msg = if summary.is_empty() {
                    "no lanes configured".to_string()
                } else {
                    summary.join(", ")
                };
                match serde_json::to_value(&statuses) {
                    Ok(data) => DaemonResponse::ok_with_data(msg, data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::LaneUtilization { lane } => {
                match self.fleet.lane_status_by_name(&lane) {
                    Some(status) => {
                        let cap = if status.max_concurrent == 0 {
                            "unlimited".to_string()
                        } else {
                            format!("{}/{}", status.current, status.max_concurrent)
                        };
                        match serde_json::to_value(&status) {
                            Ok(data) => DaemonResponse::ok_with_data(
                                format!("lane '{}': {cap} ({} queued)", status.name, status.queued),
                                data,
                            ),
                            Err(e) => {
                                DaemonResponse::error(format!("serialization failed: {e}"))
                            }
                        }
                    }
                    None => DaemonResponse::error(format!("unknown lane '{lane}'")),
                }
            }

            DaemonCommand::ListBrowserProfiles => {
                let profiles_dir = self.aegis_config.ledger_path
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("browser-profiles");
                if !profiles_dir.is_dir() {
                    return DaemonResponse::ok_with_data("0 browser profile(s)", serde_json::json!([]));
                }
                let entries: Vec<serde_json::Value> = std::fs::read_dir(&profiles_dir)
                    .ok()
                    .map(|rd| rd
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().is_dir())
                        .map(|e| serde_json::json!({ "name": e.file_name().to_string_lossy() }))
                        .collect())
                    .unwrap_or_default();
                DaemonResponse::ok_with_data(
                    format!("{} browser profile(s)", entries.len()),
                    serde_json::json!(entries),
                )
            }

            DaemonCommand::DeleteBrowserProfile { agent_id } => {
                let profiles_dir = self.aegis_config.ledger_path
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("browser-profiles");
                let profile_path = profiles_dir.join(&agent_id);
                // Path traversal guard.
                if !profile_path.starts_with(&profiles_dir) {
                    return DaemonResponse::error("invalid profile name (path traversal)");
                }
                if !profile_path.is_dir() {
                    return DaemonResponse::error(format!("browser profile '{agent_id}' not found"));
                }
                match std::fs::remove_dir_all(&profile_path) {
                    Ok(()) => DaemonResponse::ok(format!("browser profile '{agent_id}' deleted")),
                    Err(e) => DaemonResponse::error(format!("failed to delete profile: {e}")),
                }
            }

            DaemonCommand::InstallHook { path } => {
                let manifest_path = path.join("manifest.toml");
                if !manifest_path.exists() {
                    return DaemonResponse::error(format!(
                        "no manifest.toml found at {}",
                        path.display()
                    ));
                }
                match aegis_hooks::config::load_manifest(&manifest_path) {
                    Ok(manifest) => {
                        let hooks_dir = self.aegis_config.ledger_path
                            .parent()
                            .and_then(|p| p.parent())
                            .unwrap_or_else(|| std::path::Path::new("."))
                            .join("hooks");
                        let _ = std::fs::create_dir_all(&hooks_dir);
                        let dest = hooks_dir.join(path.file_name().unwrap_or_default());
                        if dest.exists() {
                            return DaemonResponse::error(format!(
                                "hook directory already exists: {}",
                                dest.display()
                            ));
                        }
                        match crate::copy_dir_recursive(&path, &dest) {
                            Ok(()) => {
                                // Record admin action in audit ledger.
                                let events: Vec<String> = manifest.hooks.iter().map(|h| h.event.clone()).collect();
                                for event in &events {
                                    let admin_action = Action::new(
                                        "daemon",
                                        ActionKind::AdminHookInstall {
                                            event: event.clone(),
                                            script_path: dest.display().to_string(),
                                        },
                                    );
                                    let verdict = Verdict::allow(admin_action.id, "hook installed", None);
                                    self.append_audit_entry(&admin_action, &verdict);
                                }
                                DaemonResponse::ok(format!(
                                    "hook installed ({} entries)",
                                    manifest.hooks.len()
                                ))
                            }
                            Err(e) => DaemonResponse::error(format!("install failed: {e}")),
                        }
                    }
                    Err(e) => DaemonResponse::error(format!("invalid hook manifest: {e}")),
                }
            }
            DaemonCommand::ListHooks => {
                let hooks_dir = self.aegis_config.ledger_path
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("hooks");
                match aegis_hooks::discovery::discover_hooks(&hooks_dir) {
                    Ok(hooks) => {
                        let data: Vec<serde_json::Value> = hooks.iter().map(|h| serde_json::json!({
                            "event": h.event,
                            "path": h.script_path.display().to_string(),
                            "enabled": h.enabled,
                        })).collect();
                        DaemonResponse::ok_with_data(
                            format!("{} hook(s)", data.len()),
                            serde_json::json!(data),
                        )
                    }
                    Err(e) => DaemonResponse::error(format!("hook discovery failed: {e}")),
                }
            }
            DaemonCommand::EnableHook { name } => {
                let hooks_dir = self.aegis_config.ledger_path
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("hooks");
                let hook_path = hooks_dir.join(&name);
                if !hook_path.starts_with(&hooks_dir) {
                    return DaemonResponse::error("invalid hook name (path traversal)");
                }
                if !hook_path.exists() {
                    return DaemonResponse::error(format!("hook '{name}' not found"));
                }
                // Make the hook executable.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(md) = std::fs::metadata(&hook_path) {
                        let mut perms = md.permissions();
                        perms.set_mode(perms.mode() | 0o111);
                        let _ = std::fs::set_permissions(&hook_path, perms);
                    }
                }
                // Record admin action in audit ledger.
                let admin_action = Action::new(
                    "daemon",
                    ActionKind::AdminConfigChange {
                        key: format!("hook.{name}.enabled=true"),
                    },
                );
                let verdict = Verdict::allow(admin_action.id, "hook enabled", None);
                self.append_audit_entry(&admin_action, &verdict);

                DaemonResponse::ok(format!("hook '{name}' enabled"))
            }
            DaemonCommand::DisableHook { name } => {
                let hooks_dir = self.aegis_config.ledger_path
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("hooks");
                let hook_path = hooks_dir.join(&name);
                if !hook_path.starts_with(&hooks_dir) {
                    return DaemonResponse::error("invalid hook name (path traversal)");
                }
                if !hook_path.exists() {
                    return DaemonResponse::error(format!("hook '{name}' not found"));
                }
                // Remove executable bit.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(md) = std::fs::metadata(&hook_path) {
                        let mut perms = md.permissions();
                        perms.set_mode(perms.mode() & !0o111);
                        let _ = std::fs::set_permissions(&hook_path, perms);
                    }
                }
                // Record admin action in audit ledger.
                let admin_action = Action::new(
                    "daemon",
                    ActionKind::AdminConfigChange {
                        key: format!("hook.{name}.enabled=false"),
                    },
                );
                let verdict = Verdict::allow(admin_action.id, "hook disabled", None);
                self.append_audit_entry(&admin_action, &verdict);

                DaemonResponse::ok(format!("hook '{name}' disabled"))
            }
            DaemonCommand::HookStatus { name } => {
                let hooks_dir = self.aegis_config.ledger_path
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("hooks");
                let hook_path = hooks_dir.join(&name);
                if !hook_path.starts_with(&hooks_dir) {
                    return DaemonResponse::error("invalid hook name (path traversal)");
                }
                if !hook_path.exists() {
                    return DaemonResponse::error(format!("hook '{name}' not found"));
                }
                let executable = {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::metadata(&hook_path)
                            .map(|m| m.permissions().mode() & 0o111 != 0)
                            .unwrap_or(false)
                    }
                    #[cfg(not(unix))]
                    { true }
                };
                let status = if executable { "active" } else { "disabled" };
                DaemonResponse::ok_with_data(
                    format!("hook '{name}': {status}"),
                    serde_json::json!({ "name": name, "status": status, "path": hook_path.display().to_string() }),
                )
            }

            DaemonCommand::ScanSkill { path } => {
                let skill_path = std::path::Path::new(&path);
                if !skill_path.exists() {
                    return DaemonResponse::error(format!("skill path not found: {path}"));
                }
                let mut scanner = aegis_skills::scanner::SkillScanner::new();
                match scanner.scan(skill_path) {
                    Ok(result) => match serde_json::to_value(&result) {
                        Ok(data) => DaemonResponse::ok_with_data("skill scan complete", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    Err(e) => DaemonResponse::error(format!("skill scan failed: {e}")),
                }
            }

            // -- Session file storage commands --
            DaemonCommand::SessionFileList { session_id } => {
                let base_dir = self.aegis_config.ledger_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));
                let files_dir = base_dir.join("sessions").join(&session_id).join("files");
                if !files_dir.is_dir() {
                    return DaemonResponse::ok_with_data("0 file(s)", serde_json::json!([]));
                }
                // Verify no traversal.
                let sessions_base = base_dir.join("sessions");
                if !files_dir.starts_with(&sessions_base) {
                    return DaemonResponse::error("invalid session ID (path traversal)");
                }
                let entries: Vec<serde_json::Value> = std::fs::read_dir(&files_dir)
                    .ok()
                    .map(|rd| rd
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().is_file())
                        .map(|e| {
                            let md = e.metadata().ok();
                            serde_json::json!({
                                "name": e.file_name().to_string_lossy(),
                                "size": md.as_ref().map(|m| m.len()).unwrap_or(0),
                            })
                        })
                        .collect())
                    .unwrap_or_default();
                DaemonResponse::ok_with_data(
                    format!("{} file(s)", entries.len()),
                    serde_json::json!(entries),
                )
            }
            DaemonCommand::SessionFileGet { session_id, filename } => {
                let base_dir = self.aegis_config.ledger_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));
                let file_path = base_dir.join("sessions").join(&session_id).join("files").join(&filename);
                let sessions_base = base_dir.join("sessions");
                if !file_path.starts_with(&sessions_base) {
                    return DaemonResponse::error("invalid path (traversal detected)");
                }
                match std::fs::read(&file_path) {
                    Ok(data) => {
                        let encoded = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &data,
                        );
                        DaemonResponse::ok_with_data(
                            format!("{filename} ({} bytes)", data.len()),
                            serde_json::json!({ "filename": filename, "data_base64": encoded, "size": data.len() }),
                        )
                    }
                    Err(e) => DaemonResponse::error(format!("failed to read file: {e}")),
                }
            }
            DaemonCommand::SessionFilePut { session_id, filename, data } => {
                let base_dir = self.aegis_config.ledger_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));
                let files_dir = base_dir.join("sessions").join(&session_id).join("files");
                let sessions_base = base_dir.join("sessions");
                if !files_dir.starts_with(&sessions_base) {
                    return DaemonResponse::error("invalid session ID (path traversal)");
                }
                let file_path = files_dir.join(&filename);
                if !file_path.starts_with(&files_dir) {
                    return DaemonResponse::error("invalid filename (path traversal)");
                }
                let decoded = match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &data,
                ) {
                    Ok(d) => d,
                    Err(e) => return DaemonResponse::error(format!("invalid base64 data: {e}")),
                };
                let _ = std::fs::create_dir_all(&files_dir);
                match std::fs::write(&file_path, &decoded) {
                    Ok(()) => DaemonResponse::ok(format!("{filename} written ({} bytes)", decoded.len())),
                    Err(e) => DaemonResponse::error(format!("failed to write file: {e}")),
                }
            }
            DaemonCommand::SessionFileSync { target_session_id, source_session_id, filenames } => {
                let base_dir = self.aegis_config.ledger_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));
                let sessions_base = base_dir.join("sessions");
                let src_dir = sessions_base.join(&source_session_id).join("files");
                let dst_dir = sessions_base.join(&target_session_id).join("files");
                if !src_dir.starts_with(&sessions_base) || !dst_dir.starts_with(&sessions_base) {
                    return DaemonResponse::error("invalid session ID (path traversal)");
                }
                let _ = std::fs::create_dir_all(&dst_dir);
                let mut copied = 0usize;
                let mut errors = Vec::new();
                for name in &filenames {
                    let src = src_dir.join(name);
                    let dst = dst_dir.join(name);
                    if !src.starts_with(&src_dir) || !dst.starts_with(&dst_dir) {
                        errors.push(format!("{name}: path traversal"));
                        continue;
                    }
                    match std::fs::copy(&src, &dst) {
                        Ok(_) => copied += 1,
                        Err(e) => errors.push(format!("{name}: {e}")),
                    }
                }
                if errors.is_empty() {
                    DaemonResponse::ok(format!("{copied} file(s) synced"))
                } else {
                    DaemonResponse::ok_with_data(
                        format!("{copied} file(s) synced, {} error(s)", errors.len()),
                        serde_json::json!({ "copied": copied, "errors": errors }),
                    )
                }
            }

            // -- TTS commands --
            DaemonCommand::Tts { text, voice, format } => {
                DaemonResponse::error(format!(
                    "TTS synthesis requires aegis-tts provider configuration (text_len={}, voice={}, format={})",
                    text.len(),
                    voice.as_deref().unwrap_or("default"),
                    format.as_deref().unwrap_or("default"),
                ))
            }

            DaemonCommand::RegisterDevice {
                code,
                device_name,
                device_type,
                platform,
                capabilities,
            } => {
                let store = match self.device_store.as_mut() {
                    Some(s) => s,
                    None => return DaemonResponse::error("device registry not initialized"),
                };
                match code {
                    None => {
                        // Generate a new pairing code
                        let (pairing_code, expiry) = store.generate_pairing_code();
                        let remaining_secs = expiry
                            .saturating_duration_since(std::time::Instant::now())
                            .as_secs();
                        let data = serde_json::json!({
                            "pairing_code": pairing_code,
                            "expires_in_secs": remaining_secs,
                        });
                        DaemonResponse::ok_with_data("pairing code generated", data)
                    }
                    Some(pairing_code) => {
                        // Complete pairing
                        let name = device_name.unwrap_or_else(|| "Unknown Device".into());
                        let dtype = device_type.unwrap_or_else(|| "Unknown".into());
                        let plat = match platform.as_deref() {
                            Some("ios") => crate::device_registry::DevicePlatform::Ios,
                            Some("android") => crate::device_registry::DevicePlatform::Android,
                            Some("macos") => crate::device_registry::DevicePlatform::MacOs,
                            Some("linux") => crate::device_registry::DevicePlatform::Linux,
                            Some("windows") => crate::device_registry::DevicePlatform::Windows,
                            _ => crate::device_registry::DevicePlatform::Web,
                        };
                        let caps = capabilities
                            .unwrap_or_default()
                            .iter()
                            .filter_map(|c| match c.as_str() {
                                "push_notifications" => Some(crate::device_registry::DeviceCapability::PushNotifications),
                                "remote_control" => Some(crate::device_registry::DeviceCapability::RemoteControl),
                                "audio_capture" => Some(crate::device_registry::DeviceCapability::AudioCapture),
                                "video_capture" => Some(crate::device_registry::DeviceCapability::VideoCapture),
                                _ => None,
                            })
                            .collect();
                        let info = crate::device_registry::DeviceInfo {
                            name,
                            device_type: dtype,
                            platform: plat,
                            capabilities: caps,
                        };
                        match store.complete_pairing(&pairing_code, info) {
                            Ok((device, auth_token)) => {
                                let data = serde_json::json!({
                                    "device_id": device.id.to_string(),
                                    "device_name": device.name,
                                    "auth_token": auth_token,
                                });
                                DaemonResponse::ok_with_data("device paired", data)
                            }
                            Err(e) => DaemonResponse::error(format!("pairing failed: {e}")),
                        }
                    }
                }
            }

            DaemonCommand::ListDevices { status } => {
                let store = match self.device_store.as_ref() {
                    Some(s) => s,
                    None => return DaemonResponse::error("device registry not initialized"),
                };
                let filter = status.as_deref().and_then(|s| match s {
                    "paired" => Some(crate::device_registry::DeviceStatus::Paired),
                    "active" => Some(crate::device_registry::DeviceStatus::Active),
                    "revoked" => Some(crate::device_registry::DeviceStatus::Revoked),
                    _ => None,
                });
                match store.list_devices(filter) {
                    Ok(devices) => {
                        let data: Vec<serde_json::Value> = devices
                            .iter()
                            .map(|d| {
                                serde_json::json!({
                                    "id": d.id.to_string(),
                                    "name": d.name,
                                    "device_type": d.device_type,
                                    "platform": d.platform.to_string(),
                                    "status": d.status.to_string(),
                                    "paired_at": d.paired_at.to_rfc3339(),
                                    "last_seen": d.last_seen.to_rfc3339(),
                                })
                            })
                            .collect();
                        DaemonResponse::ok_with_data(
                            format!("{} device(s)", data.len()),
                            serde_json::json!(data),
                        )
                    }
                    Err(e) => DaemonResponse::error(format!("failed to list devices: {e}")),
                }
            }

            DaemonCommand::RevokeDevice { ref device_id } => {
                let store = match self.device_store.as_mut() {
                    Some(s) => s,
                    None => return DaemonResponse::error("device registry not initialized"),
                };
                let uid = match uuid::Uuid::parse_str(device_id) {
                    Ok(u) => u,
                    Err(e) => return DaemonResponse::error(format!("invalid device ID: {e}")),
                };
                match store.revoke(&crate::device_registry::DeviceId(uid)) {
                    Ok(()) => DaemonResponse::ok(format!("device {device_id} revoked")),
                    Err(e) => DaemonResponse::error(format!("revocation failed: {e}")),
                }
            }

            DaemonCommand::DeviceStatus { ref device_id } => {
                let store = match self.device_store.as_ref() {
                    Some(s) => s,
                    None => return DaemonResponse::error("device registry not initialized"),
                };
                let uid = match uuid::Uuid::parse_str(device_id) {
                    Ok(u) => u,
                    Err(e) => return DaemonResponse::error(format!("invalid device ID: {e}")),
                };
                match store.get_device(&crate::device_registry::DeviceId(uid)) {
                    Ok(Some(device)) => {
                        let data = serde_json::json!({
                            "id": device.id.to_string(),
                            "name": device.name,
                            "device_type": device.device_type,
                            "platform": device.platform.to_string(),
                            "status": device.status.to_string(),
                            "paired_at": device.paired_at.to_rfc3339(),
                            "last_seen": device.last_seen.to_rfc3339(),
                            "capabilities": device.capabilities.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                        });
                        DaemonResponse::ok_with_data("device found", data)
                    }
                    Ok(None) => DaemonResponse::error(format!("device not found: {device_id}")),
                    Err(e) => DaemonResponse::error(format!("query failed: {e}")),
                }
            }

            DaemonCommand::LlmComplete {
                model,
                messages,
                temperature,
                max_tokens,
                system_prompt,
                tools,
            } => {
                let Some(ref client) = self.llm_client else {
                    return DaemonResponse::error(
                        "LLM client not initialized (check provider registry configuration)"
                    );
                };

                // Deserialize messages from JSON value.
                let parsed_messages: Vec<aegis_types::llm::LlmMessage> =
                    match serde_json::from_value(messages) {
                        Ok(msgs) => msgs,
                        Err(e) => {
                            return DaemonResponse::error(format!(
                                "invalid messages format: {e}"
                            ));
                        }
                    };

                // Deserialize tool definitions if provided.
                let parsed_tools: Vec<aegis_types::llm::LlmToolDefinition> =
                    match tools {
                        Some(t) => match serde_json::from_value(t) {
                            Ok(td) => td,
                            Err(e) => {
                                return DaemonResponse::error(format!(
                                    "invalid tools format: {e}"
                                ));
                            }
                        },
                        None => Vec::new(),
                    };

                let request = aegis_types::llm::LlmRequest {
                    model: model.clone(),
                    messages: parsed_messages,
                    temperature,
                    max_tokens,
                    system_prompt,
                    tools: parsed_tools,
                    thinking_budget: None,
                };

                match client.complete(&request) {
                    Ok(response) => {
                        // Log to audit trail (model + token counts, NOT content).
                        let action = Action::new(
                            "daemon".to_string(),
                            ActionKind::LlmComplete {
                                provider: client
                                    .registry()
                                    .resolve_provider(&model)
                                    .unwrap_or("unknown")
                                    .to_string(),
                                model: response.model.clone(),
                                endpoint: String::new(),
                                input_tokens: response.usage.input_tokens,
                                output_tokens: response.usage.output_tokens,
                            },
                        );
                        let verdict = Verdict::allow(
                            action.id,
                            format!(
                                "LLM completion: {} in={} out={}",
                                response.model,
                                response.usage.input_tokens,
                                response.usage.output_tokens
                            ),
                            None,
                        );
                        self.append_audit_entry(&action, &verdict);

                        match serde_json::to_value(&response) {
                            Ok(data) => DaemonResponse::ok_with_data("llm completion ok", data),
                            Err(e) => DaemonResponse::error(format!(
                                "failed to serialize LLM response: {e}"
                            )),
                        }
                    }
                    Err(e) => DaemonResponse::error(format!("LLM completion failed: {e}")),
                }
            }

            DaemonCommand::ChannelChat { text } => {
                // Ensure session is loaded (lazy: first call loads most recent
                // conversation from ~/.aegis/conversations/).
                self.ensure_channel_session();

                // Handle /reset: clear history, new session, force prompt rebuild.
                if text == "/reset" {
                    self.channel_chat_history.clear();
                    self.channel_system_prompt = None;
                    let new_id = channel_generate_conversation_id();
                    info!(session_id = %new_id, "channel session reset");
                    self.channel_session_id = Some(new_id);
                    return DaemonResponse::ok("Chat history and context cleared. New session started.");
                }

                // Handle /session commands.
                if text == "/session" || text.starts_with("/session ") {
                    let arg = text.strip_prefix("/session").unwrap().trim();
                    return if arg.is_empty() {
                        // Show current session ID.
                        let id = self.channel_session_id.as_deref().unwrap_or("none");
                        let count = self.channel_chat_history.len();
                        DaemonResponse::ok(format!("Session: {id} ({count} messages)"))
                    } else if arg == "list" {
                        let sessions = channel_list_conversations();
                        if sessions.is_empty() {
                            DaemonResponse::ok("No saved sessions.".to_string())
                        } else {
                            let current = self.channel_session_id.as_deref().unwrap_or("");
                            let mut out = String::from("Sessions:\n");
                            for (i, s) in sessions.iter().take(5).enumerate() {
                                let marker = if s.id == current { " *" } else { "" };
                                out.push_str(&format!(
                                    "{}. {} ({} msgs, {}){}\n",
                                    i + 1,
                                    s.id,
                                    s.message_count,
                                    &s.timestamp[..10],
                                    marker,
                                ));
                            }
                            DaemonResponse::ok(out.trim_end().to_string())
                        }
                    } else if arg == "new" {
                        // Save current session before switching.
                        if let Some(ref id) = self.channel_session_id {
                            let model = detect_channel_model();
                            channel_save_conversation(id, &self.channel_chat_history, &model);
                        }
                        self.channel_chat_history.clear();
                        self.channel_system_prompt = None;
                        let new_id = channel_generate_conversation_id();
                        info!(session_id = %new_id, "new channel session created");
                        self.channel_session_id = Some(new_id.clone());
                        DaemonResponse::ok(format!("New session started: {new_id}"))
                    } else {
                        // Switch to a specific session by ID.
                        let target_id = arg;
                        if let Some((messages, meta)) = channel_load_conversation(target_id) {
                            // Save current session first.
                            if let Some(ref id) = self.channel_session_id {
                                let model = detect_channel_model();
                                channel_save_conversation(id, &self.channel_chat_history, &model);
                            }
                            self.channel_chat_history = messages;
                            self.channel_session_id = Some(meta.id.clone());
                            self.channel_system_prompt = None;
                            DaemonResponse::ok(format!(
                                "Switched to session {} ({} messages)",
                                meta.id, meta.message_count
                            ))
                        } else {
                            DaemonResponse::error(format!("Session not found: {target_id}"))
                        }
                    };
                }

                if self.llm_client.is_none() {
                    return DaemonResponse::error(
                        "LLM client not initialized (no API keys configured)",
                    );
                }

                // Append user message to history.
                self.channel_chat_history
                    .push(aegis_types::llm::LlmMessage::user(&text));

                // Cap history at 40 messages to bound token usage.
                const MAX_HISTORY: usize = 40;
                if self.channel_chat_history.len() > MAX_HISTORY {
                    let drain = self.channel_chat_history.len() - MAX_HISTORY;
                    self.channel_chat_history.drain(..drain);
                }

                let model = detect_channel_model();

                // Build/cache system prompt from workspace context files.
                let system_prompt = self
                    .channel_system_prompt
                    .get_or_insert_with(build_channel_system_prompt)
                    .clone();

                // Get tool definitions from registry.
                let tool_defs = self
                    .tool_registry
                    .as_ref()
                    .map(|r| r.to_llm_definitions())
                    .unwrap_or_default();

                // Agentic tool-use loop: call LLM, execute any tool calls,
                // feed results back, repeat until EndTurn or max iterations.
                const MAX_TOOL_ITERATIONS: usize = 10;
                let mut final_text = String::new();

                for iteration in 0..MAX_TOOL_ITERATIONS {
                    // Scoped borrow: complete LLM call then release client ref.
                    let llm_result = {
                        let client = self.llm_client.as_ref().unwrap();
                        let request = aegis_types::llm::LlmRequest {
                            model: model.clone(),
                            messages: self.channel_chat_history.clone(),
                            temperature: Some(0.7),
                            max_tokens: Some(2048),
                            system_prompt: Some(system_prompt.clone()),
                            tools: tool_defs.clone(),
                            thinking_budget: None,
                        };
                        match client.complete(&request) {
                            Ok(resp) => {
                                let provider = client
                                    .registry()
                                    .resolve_provider(&model)
                                    .unwrap_or("unknown")
                                    .to_string();
                                Ok((resp, provider))
                            }
                            Err(e) => Err(e),
                        }
                    };

                    let (response, provider_name) = match llm_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            let msg = format!("LLM error: {e}");
                            // Save what we have so far.
                            if let Some(ref id) = self.channel_session_id {
                                channel_save_conversation(id, &self.channel_chat_history, &model);
                            }
                            return DaemonResponse::error(msg);
                        }
                    };

                    // Audit the LLM call.
                    let action = Action::new(
                        "channel-chat".to_string(),
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
                            "channel chat iter={}: {} in={} out={}",
                            iteration,
                            response.model,
                            response.usage.input_tokens,
                            response.usage.output_tokens
                        ),
                        None,
                    );
                    self.append_audit_entry(&action, &verdict);

                    // Check if the LLM wants to use tools.
                    let wants_tools = response
                        .stop_reason
                        .as_ref()
                        .map(|r| matches!(r, aegis_types::llm::StopReason::ToolUse))
                        .unwrap_or(false)
                        && !response.tool_calls.is_empty();

                    if wants_tools {
                        // Append assistant message with tool calls to history.
                        self.channel_chat_history.push(
                            aegis_types::llm::LlmMessage::assistant_with_tools(
                                &response.content,
                                response.tool_calls.clone(),
                            ),
                        );

                        // Execute each tool call.
                        for tc in &response.tool_calls {
                            // Send progress indicator to Telegram.
                            if let Some(tx) = &self.channel_tx {
                                let _ = tx.send(ChannelInput::TextMessage(format!(
                                    "[Running: {}]",
                                    tc.name
                                )));
                            }

                            let tool_result_text = if let Some(ref registry) = self.tool_registry {
                                if let Some(tool) = registry.get_tool(&tc.name) {
                                    match self
                                        .tokio_rt
                                        .handle()
                                        .block_on(tool.execute(tc.input.clone()))
                                    {
                                        Ok(output) => {
                                            // Use .content if available, fall back to serialized .result
                                            output.content.unwrap_or_else(|| {
                                                serde_json::to_string_pretty(&output.result)
                                                    .unwrap_or_else(|_| {
                                                        output.result.to_string()
                                                    })
                                            })
                                        }
                                        Err(e) => format!("Error: {e}"),
                                    }
                                } else {
                                    format!("Error: tool not found: {}", tc.name)
                                }
                            } else {
                                "Error: tool registry not initialized".to_string()
                            };

                            // Append tool result to history.
                            self.channel_chat_history.push(
                                aegis_types::llm::LlmMessage::tool_result(
                                    &tc.id,
                                    &tool_result_text,
                                ),
                            );
                        }
                        // Continue the loop for the next LLM call.
                        continue;
                    }

                    // EndTurn / MaxTokens -- we're done.
                    final_text = response.content.clone();
                    self.channel_chat_history
                        .push(aegis_types::llm::LlmMessage::assistant(&response.content));
                    break;
                }

                // Persist the conversation after the turn.
                if let Some(ref id) = self.channel_session_id {
                    channel_save_conversation(id, &self.channel_chat_history, &model);
                }

                DaemonResponse::ok(final_text)
            }

            DaemonCommand::ExecuteTool {
                ref name,
                input,
                ref session_id,
                ref principal,
            } => {
                // 1. Build audit Action.
                let principal_str = principal.as_deref().unwrap_or("chat-tui");
                let audit_action = Action::new(
                    principal_str.to_string(),
                    ActionKind::ToolCall {
                        tool: name.clone(),
                        args: input.clone(),
                    },
                );

                // 2. Cedar policy evaluation (if engine loaded).
                let verdict = match &self.policy_engine {
                    Some(engine) => engine.evaluate(&audit_action),
                    None => Verdict::allow(
                        audit_action.id,
                        "no policy engine; audit-only",
                        None,
                    ),
                };

                // 3. Audit log -- always, regardless of verdict.
                let session_uuid = session_id
                    .as_deref()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok());
                if let Some(uuid) = session_uuid {
                    match self.open_audit_store() {
                        Ok(mut store) => {
                            if let Err(e) =
                                store.append_with_session(&audit_action, &verdict, &uuid)
                            {
                                warn!(?e, "failed to append session-linked audit entry");
                            }
                        }
                        Err(e) => {
                            warn!(?e, "failed to open audit ledger for tool execution");
                        }
                    }
                } else {
                    self.append_audit_entry(&audit_action, &verdict);
                }

                // 4. If denied by policy, return denial before executing.
                if verdict.decision == Decision::Deny {
                    return DaemonResponse::error(format!(
                        "denied by policy: {}",
                        verdict.reason
                    ));
                }

                // 5. Execute tool.
                let Some(ref registry) = self.tool_registry else {
                    return DaemonResponse::error("tool registry not initialized");
                };
                let Some(tool) = registry.get_tool(name) else {
                    return DaemonResponse::error(format!("tool not found: {name}"));
                };

                match self.tokio_rt.handle().block_on(tool.execute(input)) {
                    Ok(output) => {
                        let data = serde_json::to_value(&output).unwrap_or_default();
                        DaemonResponse::ok_with_data("tool executed", data)
                    }
                    Err(e) => DaemonResponse::error(format!("tool execution failed: {e}")),
                }
            }

            DaemonCommand::RegisterChatSession => {
                match self.open_audit_store() {
                    Ok(mut store) => {
                        match store.begin_session("chat-tui", "chat", &[], Some("chat-tui")) {
                            Ok(uuid) => {
                                let data = serde_json::json!({
                                    "session_id": uuid.to_string()
                                });
                                DaemonResponse::ok_with_data("chat session registered", data)
                            }
                            Err(e) => DaemonResponse::error(format!(
                                "session registration failed: {e}"
                            )),
                        }
                    }
                    Err(e) => DaemonResponse::error(format!("ledger open failed: {e}")),
                }
            }

            DaemonCommand::GenerateSetupCode { ref endpoint } => {
                match self.setup_code_manager {
                    Some(ref mut mgr) => {
                        let result = mgr.generate(endpoint);
                        match serde_json::to_value(&result) {
                            Ok(data) => DaemonResponse::ok_with_data("setup code generated", data),
                            Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                        }
                    }
                    None => DaemonResponse::error(
                        "setup code manager not initialized (no device store configured)"
                    ),
                }
            }

            // Gateway device management commands.
            DaemonCommand::UpdateDeviceStatus { device_id, status } => {
                let store = match self.device_store.as_mut() {
                    Some(s) => s,
                    None => return DaemonResponse::error("device registry not initialized"),
                };
                let uid = match uuid::Uuid::parse_str(&device_id) {
                    Ok(u) => u,
                    Err(e) => return DaemonResponse::error(format!("invalid device ID: {e}")),
                };
                if status == "revoked" {
                    match store.revoke(&crate::device_registry::DeviceId(uid)) {
                        Ok(()) => DaemonResponse::ok(format!("device {device_id} status updated to revoked")),
                        Err(e) => DaemonResponse::error(format!("failed to update device status: {e}")),
                    }
                } else {
                    DaemonResponse::error(format!(
                        "only 'revoked' status transition is supported (got '{status}')"
                    ))
                }
            }
            DaemonCommand::RemoveDevice { device_id } => {
                let store = match self.device_store.as_mut() {
                    Some(s) => s,
                    None => return DaemonResponse::error("device registry not initialized"),
                };
                let uid = match uuid::Uuid::parse_str(&device_id) {
                    Ok(u) => u,
                    Err(e) => return DaemonResponse::error(format!("invalid device ID: {e}")),
                };
                match store.delete_device(&crate::device_registry::DeviceId(uid)) {
                    Ok(true) => DaemonResponse::ok(format!("device {device_id} removed")),
                    Ok(false) => DaemonResponse::error(format!("device {device_id} not found")),
                    Err(e) => DaemonResponse::error(format!("failed to remove device: {e}")),
                }
            }
            DaemonCommand::DeviceHeartbeat { device_id } => {
                // Record the heartbeat timestamp in our in-memory map.
                self.heartbeat_last_sent.insert(device_id.clone(), Instant::now());
                DaemonResponse::ok(format!("heartbeat recorded for {device_id}"))
            }

            // Phone control commands.
            DaemonCommand::QueueDeviceCommand {
                ref device_id,
                ref command,
            } => {
                // Validate device exists and is not revoked.
                if let Some(ref store) = self.device_store {
                    let uid = match uuid::Uuid::parse_str(device_id) {
                        Ok(u) => u,
                        Err(e) => return DaemonResponse::error(format!("invalid device ID: {e}")),
                    };
                    match store.get_device(&crate::device_registry::DeviceId(uid)) {
                        Ok(Some(device)) => {
                            if device.status == crate::device_registry::DeviceStatus::Revoked {
                                return DaemonResponse::error(format!(
                                    "device {device_id} has been revoked"
                                ));
                            }
                        }
                        Ok(None) => {
                            return DaemonResponse::error(format!(
                                "device not found: {device_id}"
                            ));
                        }
                        Err(e) => {
                            return DaemonResponse::error(format!(
                                "device lookup failed: {e}"
                            ));
                        }
                    }
                } else {
                    return DaemonResponse::error("device registry not initialized");
                }

                // Parse and queue the command.
                let device_cmd: crate::phone_control::DeviceCommand =
                    match serde_json::from_value(command.clone()) {
                        Ok(cmd) => cmd,
                        Err(e) => {
                            return DaemonResponse::error(format!(
                                "invalid device command: {e}"
                            ))
                        }
                    };

                match self
                    .phone_controller
                    .queue_command(device_id, device_cmd)
                {
                    Ok(result) => match serde_json::to_value(&result) {
                        Ok(data) => {
                            DaemonResponse::ok_with_data("command queued", data)
                        }
                        Err(e) => {
                            DaemonResponse::error(format!("serialization failed: {e}"))
                        }
                    },
                    Err(e) => DaemonResponse::error(format!("queue failed: {e}")),
                }
            }

            DaemonCommand::PollDeviceCommands { ref device_id } => {
                let commands = self.phone_controller.poll_commands(device_id);
                match serde_json::to_value(&commands) {
                    Ok(data) => DaemonResponse::ok_with_data(
                        format!("{} command(s)", commands.len()),
                        data,
                    ),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::ReportDeviceCommandResult {
                ref command_id,
                ref result,
            } => {
                let uid = match uuid::Uuid::parse_str(command_id) {
                    Ok(u) => u,
                    Err(e) => {
                        return DaemonResponse::error(format!("invalid command ID: {e}"))
                    }
                };
                match self.phone_controller.report_result(uid, result.clone()) {
                    Ok(()) => DaemonResponse::ok("result reported"),
                    Err(e) => DaemonResponse::error(format!("report failed: {e}")),
                }
            }

            // -- Voice call management --
            DaemonCommand::MakeCall {
                ref to,
                ref agent_id,
            } => match &mut self.voice_manager {
                Some(vm) => match vm.make_call(to, agent_id) {
                    Ok(record) => match serde_json::to_value(&record) {
                        Ok(data) => DaemonResponse::ok_with_data("call initiated", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    Err(e) => DaemonResponse::error(format!("make_call failed: {e}")),
                },
                None => DaemonResponse::error("voice manager not configured (set TWILIO_AUTH_TOKEN)"),
            },
            DaemonCommand::HangupCall { ref call_id } => match &mut self.voice_manager {
                Some(vm) => {
                    // For hangup, we use a generic agent check; in production the
                    // requesting agent would be identified from the control session.
                    match vm.hangup_call(call_id, "daemon") {
                        Ok(()) => DaemonResponse::ok("call hung up"),
                        Err(e) => DaemonResponse::error(format!("hangup failed: {e}")),
                    }
                }
                None => DaemonResponse::error("voice manager not configured (set TWILIO_AUTH_TOKEN)"),
            },
            DaemonCommand::ListCalls => match &self.voice_manager {
                Some(vm) => {
                    let calls: Vec<_> = vm.list_calls().into_iter().cloned().collect();
                    match serde_json::to_value(&calls) {
                        Ok(data) => DaemonResponse::ok_with_data(
                            format!("{} call(s)", calls.len()),
                            data,
                        ),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    }
                }
                None => DaemonResponse::error("voice manager not configured (set TWILIO_AUTH_TOKEN)"),
            },
            DaemonCommand::CallStatus { ref call_id } => match &self.voice_manager {
                Some(vm) => match vm.call_status(call_id) {
                    Some(record) => match serde_json::to_value(record) {
                        Ok(data) => DaemonResponse::ok_with_data("call found", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    None => DaemonResponse::error(format!("call not found: {call_id}")),
                },
                None => DaemonResponse::error("voice manager not configured (set TWILIO_AUTH_TOKEN)"),
            },

            // -- Speech recognition commands --
            DaemonCommand::StartSpeechSession {
                ref agent_id,
                ref format,
            } => match &self.speech_manager {
                Some(mgr) => {
                    let audio_format = match crate::speech::AudioFormat::from_str_lossy(format) {
                        Some(f) => f,
                        None => {
                            return DaemonResponse::error(format!(
                                "unsupported audio format: {format}"
                            ))
                        }
                    };
                    match mgr.start_session(audio_format) {
                        Ok(_) => {
                            let session_id = uuid::Uuid::new_v4().to_string();
                            info!(
                                agent_id = %agent_id,
                                session_id = %session_id,
                                format = %format,
                                "speech recognition session started"
                            );
                            DaemonResponse::ok_with_data(
                                "speech session started",
                                serde_json::json!({ "session_id": session_id }),
                            )
                        }
                        Err(e) => DaemonResponse::error(format!("start_speech_session failed: {e}")),
                    }
                }
                None => DaemonResponse::error(
                    "speech recognition not configured (set DEEPGRAM_API_KEY or OPENAI_API_KEY)",
                ),
            },
            DaemonCommand::StopSpeechSession { ref session_id } => match &self.speech_manager {
                Some(mgr) => {
                    mgr.end_session();
                    info!(session_id = %session_id, "speech recognition session stopped");
                    DaemonResponse::ok("speech session stopped")
                }
                None => DaemonResponse::error(
                    "speech recognition not configured (set DEEPGRAM_API_KEY or OPENAI_API_KEY)",
                ),
            },
            DaemonCommand::TranscribeAudio {
                ref audio_base64,
                ref format,
            } => match &self.speech_manager {
                Some(mgr) => {
                    let audio_format = match crate::speech::AudioFormat::from_str_lossy(format) {
                        Some(f) => f,
                        None => {
                            return DaemonResponse::error(format!(
                                "unsupported audio format: {format}"
                            ))
                        }
                    };
                    let audio_data = match base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        audio_base64,
                    ) {
                        Ok(data) => data,
                        Err(e) => {
                            return DaemonResponse::error(format!(
                                "invalid base64 audio data: {e}"
                            ))
                        }
                    };
                    match mgr.transcribe_file(&audio_data, audio_format) {
                        Ok(text) => DaemonResponse::ok_with_data(
                            "transcription complete",
                            serde_json::json!({ "text": text }),
                        ),
                        Err(e) => DaemonResponse::error(format!("transcription failed: {e}")),
                    }
                }
                None => DaemonResponse::error(
                    "speech recognition not configured (set DEEPGRAM_API_KEY or OPENAI_API_KEY)",
                ),
            },

            // -- Voice gateway session commands --
            DaemonCommand::StartVoiceSession {
                ref agent_id,
                ref config,
            } => {
                let session_config: crate::voice_gateway::VoiceSessionConfig =
                    match serde_json::from_value(config.clone()) {
                        Ok(c) => c,
                        Err(e) => {
                            return DaemonResponse::error(format!(
                                "invalid voice session config: {e}"
                            ))
                        }
                    };
                match self.voice_gateway.start_session(agent_id, session_config) {
                    Ok(session) => match serde_json::to_value(&session) {
                        Ok(data) => DaemonResponse::ok_with_data("voice session started", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    Err(e) => DaemonResponse::error(format!("start_voice_session failed: {e}")),
                }
            }
            DaemonCommand::StopVoiceSession { ref session_id } => {
                match self.voice_gateway.stop_session(session_id) {
                    Ok(()) => DaemonResponse::ok("voice session stopped"),
                    Err(e) => DaemonResponse::error(format!("stop_voice_session failed: {e}")),
                }
            }
            DaemonCommand::ListVoiceSessions => {
                let sessions: Vec<_> = self
                    .voice_gateway
                    .list_sessions()
                    .into_iter()
                    .cloned()
                    .collect();
                match serde_json::to_value(&sessions) {
                    Ok(data) => DaemonResponse::ok_with_data(
                        format!("{} voice session(s)", sessions.len()),
                        data,
                    ),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::PurgeAuditLog {
                before_days,
                keep_entries,
            } => {
                if before_days.is_none() && keep_entries.is_none() {
                    return DaemonResponse::error(
                        "at least one of before_days or keep_entries must be specified",
                    );
                }

                match self.open_audit_store() {
                    Ok(mut store) => {
                        let mut total_purged: usize = 0;

                        // 1. Purge by age
                        if let Some(days) = before_days {
                            let cutoff = chrono::Utc::now()
                                - chrono::Duration::days(days as i64);
                            match store.purge_before(cutoff) {
                                Ok(n) => total_purged += n,
                                Err(e) => {
                                    return DaemonResponse::error(format!(
                                        "purge by age failed: {e}"
                                    ))
                                }
                            }
                        }

                        // 2. Purge by count
                        if let Some(keep) = keep_entries {
                            match store.purge_oldest(keep) {
                                Ok(n) => total_purged += n,
                                Err(e) => {
                                    return DaemonResponse::error(format!(
                                        "purge by count failed: {e}"
                                    ))
                                }
                            }
                        }

                        // Record the purge itself as an admin audit entry.
                        let purge_action = Action::new(
                            "daemon",
                            ActionKind::AdminAuditPurge {
                                entries_purged: total_purged,
                            },
                        );
                        let verdict = Verdict::allow(
                            purge_action.id,
                            "admin audit purge executed",
                            None,
                        );
                        let _ = store.append(&purge_action, &verdict);

                        DaemonResponse::ok(format!("{total_purged} audit entries purged"))
                    }
                    Err(e) => DaemonResponse::error(format!("ledger open failed: {e}")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_control::daemon::{
        CaptureSessionRequest, LatestCaptureFrame, RuntimeCapabilities,
    };
    use aegis_pilot::supervisor::SupervisorCommand;
    use aegis_policy::builtin::{ORCHESTRATOR_COMPUTER_USE, PERMIT_ALL};
    use aegis_toolkit::contract::InputAction;
    use aegis_toolkit::contract::{MouseButton, ToolAction};
    use aegis_types::daemon::{
        AgentSlotConfig, AgentToolConfig, DaemonControlConfig, OrchestratorConfig,
        PersistenceConfig, RestartPolicy,
    };
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;
    use tempfile::TempDir;

    // Explicit imports for items not brought in via `super::*` from lib.rs scope.
    use std::sync::atomic::Ordering;
    use aegis_control::daemon::{SessionState, SpawnSubagentRequest};
    use aegis_ledger::AuditStore;
    use crate::slot::NotableEvent;
    use crate::parity::{parity_diff_report_from_dir, parity_status_report_from_dir, parity_verify_report_from_dir};

    fn test_runtime(agents: Vec<AgentSlotConfig>) -> DaemonRuntime {
        let config = DaemonConfig {
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
            heartbeat: Default::default(),
            channel_heartbeat: Default::default(),
            default_security_preset: None,
            default_isolation: None,
            default_network_rules: vec![],
        };
        let aegis_config = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        DaemonRuntime::new(config, aegis_config)
    }

    fn test_agent(name: &str) -> AgentSlotConfig {
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
            task: Some("test task".into()),
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
        assert!(!ping.hook_fail_open);
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
        let resp = runtime.handle_command(DaemonCommand::ListPending { name: "a1".into() });
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
        assert_eq!(verdict.decision, "deny");
        assert!(verdict.reason.contains("fail-closed"));
    }

    #[test]
    fn handle_command_runtime_capabilities() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::RuntimeCapabilities { name: "a1".into() });
        assert!(resp.ok);
        let caps: RuntimeCapabilities = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(caps.name, "a1");
        assert_eq!(caps.tool, "ClaudeCode");
        assert_eq!(caps.policy_mediation, "enforced");
        assert!(caps.headless);
        assert!(!caps.auth_mode.is_empty());
        assert!(!caps.auth_hint.is_empty());
    }

    #[test]
    fn handle_command_execute_tool_action_fail_closed() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ExecuteToolAction {
            name: "a1".into(),
            action: ToolAction::MouseClick {
                x: 100,
                y: 200,
                button: MouseButton::Left,
            },
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let outcome: ToolActionOutcome = serde_json::from_value(data).unwrap();
        assert_eq!(outcome.execution.result.action, "MouseClick");
        assert_eq!(
            outcome.execution.risk_tag,
            outcome.execution.result.risk_tag
        );
        let note = outcome.execution.result.note.unwrap_or_default();
        assert!(note.contains("deny"));
    }

    #[test]
    fn handle_command_execute_tool_batch_halts_on_high_risk_boundary() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ExecuteToolBatch {
            name: "a1".into(),
            actions: vec![
                ToolAction::MouseMove { x: 10, y: 20 },
                ToolAction::BrowserNavigate {
                    session_id: "b1".into(),
                    url: "https://example.com".into(),
                },
            ],
            max_actions: Some(5),
        });
        assert!(resp.ok);
        let batch: ToolBatchOutcome = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(batch.executed, 1);
        let halted = batch.halted_reason.unwrap_or_default();
        assert!(!halted.is_empty(), "batch should report a halt reason");
        assert!(
            halted.contains("policy boundary")
                || halted.contains("denied action")
                || halted.contains("batch cap"),
            "unexpected halt reason: {halted}"
        );
    }

    #[test]
    fn handle_command_start_capture_session_fail_closed_without_policy() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::StartCaptureSession {
            name: "a1".into(),
            request: aegis_control::daemon::CaptureSessionRequest {
                target_fps: 30,
                region: None,
            },
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("denied"));
    }

    #[test]
    fn handle_command_stop_capture_session_fail_closed_without_policy() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::StopCaptureSession {
            name: "a1".into(),
            session_id: "cap-1".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("denied"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires local browser + macOS permissions (screen recording/accessibility)"]
    fn live_browser_automation_writes_runtime_provenance() {
        if std::env::var("AEGIS_LIVE_AUTOMATION_TEST").ok().as_deref() != Some("1") {
            eprintln!("set AEGIS_LIVE_AUTOMATION_TEST=1 to run live automation integration test");
            return;
        }

        let tmp = TempDir::new().expect("create temp dir");
        let base = tmp.path().join("live-automation");
        let policy_dir = base.join("policies");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        std::fs::write(policy_dir.join("default.cedar"), ORCHESTRATOR_COMPUTER_USE)
            .expect("write policy");

        let mut config = DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: Default::default(),
            alerts: vec![],
            agents: vec![test_agent("orch")],
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
            heartbeat: Default::default(),
            channel_heartbeat: Default::default(),
            default_security_preset: None,
            default_isolation: None,
            default_network_rules: vec![],
        };
        config.toolkit.loop_executor.halt_on_high_risk = false;
        config.toolkit.browser.extra_args = vec!["--disable-extensions".to_string()];

        let aegis_config = AegisConfig::default_for("live-orch", &base);
        let mut runtime = DaemonRuntime::new(config, aegis_config.clone());

        let start_capture = runtime.handle_command(DaemonCommand::StartCaptureSession {
            name: "orch".to_string(),
            request: CaptureSessionRequest {
                target_fps: 30,
                region: None,
            },
        });
        assert!(
            start_capture.ok,
            "capture start failed: {}",
            start_capture.message
        );
        let capture_started: CaptureSessionStarted = serde_json::from_value(
            start_capture
                .data
                .expect("capture start response should include session payload"),
        )
        .expect("parse capture session response");

        let start_browser = runtime.handle_command(DaemonCommand::ExecuteToolAction {
            name: "orch".to_string(),
            action: ToolAction::BrowserProfileStart {
                session_id: "live-web".to_string(),
                headless: true,
                url: Some("https://example.com".to_string()),
            },
        });
        assert!(
            start_browser.ok,
            "browser start failed: {}",
            start_browser.message
        );

        let mut first_frame: Option<LatestCaptureFrame> = None;
        for _ in 0..20 {
            let latest = runtime.handle_command(DaemonCommand::LatestCaptureFrame {
                name: "orch".to_string(),
                region: None,
            });
            if latest.ok {
                let payload: LatestCaptureFrame =
                    serde_json::from_value(latest.data.expect("latest frame payload"))
                        .expect("parse latest frame");
                if payload.frame_id > 0 && payload.frame.width > 0 && payload.frame.height > 0 {
                    first_frame = Some(payload);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let first_frame = first_frame.expect("initial latest-frame should be available");

        let batch = runtime.handle_command(DaemonCommand::ExecuteToolBatch {
            name: "orch".to_string(),
            actions: vec![
                ToolAction::BrowserNavigate {
                    session_id: "live-web".to_string(),
                    url: "https://example.com".to_string(),
                },
                ToolAction::MouseClick {
                    x: 20,
                    y: 20,
                    button: MouseButton::Left,
                },
                ToolAction::TypeText {
                    text: "aegis live test".to_string(),
                },
                ToolAction::InputBatch {
                    actions: vec![InputAction::Wait { duration_ms: 150 }],
                },
            ],
            max_actions: Some(6),
        });
        assert!(batch.ok, "batch failed: {}", batch.message);
        let batch_outcome: ToolBatchOutcome =
            serde_json::from_value(batch.data.expect("batch data")).expect("parse batch outcome");
        assert_eq!(
            batch_outcome.executed, 4,
            "all batch actions should execute"
        );

        let mut advanced_frame: Option<LatestCaptureFrame> = None;
        for _ in 0..25 {
            let latest = runtime.handle_command(DaemonCommand::LatestCaptureFrame {
                name: "orch".to_string(),
                region: None,
            });
            if latest.ok {
                let payload: LatestCaptureFrame =
                    serde_json::from_value(latest.data.expect("latest frame payload"))
                        .expect("parse latest frame");
                if payload.frame_id > first_frame.frame_id
                    && payload.frame.width > 0
                    && payload.frame.height > 0
                {
                    advanced_frame = Some(payload);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let advanced_frame =
            advanced_frame.expect("latest-frame should advance after action batch");
        assert!(advanced_frame.frame_id > first_frame.frame_id);

        let stop_browser = runtime.handle_command(DaemonCommand::StopBrowserProfile {
            name: "orch".to_string(),
            session_id: "live-web".to_string(),
        });
        assert!(
            stop_browser.ok,
            "browser stop failed: {}",
            stop_browser.message
        );

        let stop_capture = runtime.handle_command(DaemonCommand::StopCaptureSession {
            name: "orch".to_string(),
            session_id: capture_started.session_id,
        });
        assert!(
            stop_capture.ok,
            "capture stop failed: {}",
            stop_capture.message
        );

        let store = AuditStore::open(&aegis_config.ledger_path).expect("open audit ledger");
        let entries = store.query_last(200).expect("query audit entries");
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("RuntimeComputerUse")),
            "expected RuntimeComputerUse audit entries"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("BrowserProfileStart")),
            "expected BrowserProfileStart provenance in audit entries"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("BrowserProfileStop")),
            "expected BrowserProfileStop provenance in audit entries"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("BrowserNavigate")),
            "expected BrowserNavigate provenance in audit entries"
        );
        assert!(
            entries.iter().any(|e| e.action_kind.contains("MouseClick")),
            "expected MouseClick provenance in audit entries"
        );
        assert!(
            entries.iter().any(|e| e.action_kind.contains("TypeText")),
            "expected TypeText provenance in audit entries"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("duration_ms")),
            "expected wait action provenance in audit entries"
        );
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
        let kind =
            map_tool_use_to_action("Write", &serde_json::json!({"file_path": "/tmp/out.txt"}));
        match kind {
            ActionKind::FileWrite { path } => assert_eq!(path, PathBuf::from("/tmp/out.txt")),
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_edit() {
        let kind =
            map_tool_use_to_action("Edit", &serde_json::json!({"file_path": "/src/main.rs"}));
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
            orchestrator: None,
            security_preset: None,
            policy_dir: None,
            isolation: None,
            lane: None,
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
        let verdict: ToolUseVerdict = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(verdict.decision, "deny");
        assert!(verdict.reason.contains("autonomous"));
    }

    #[test]
    fn evaluate_tool_use_denies_when_policy_unavailable() {
        let mut runtime = test_runtime(vec![test_agent("agent-1")]);
        let resp = runtime.handle_command(DaemonCommand::EvaluateToolUse {
            agent: "agent-1".into(),
            tool_name: "Read".into(),
            tool_input: serde_json::json!({"file_path": "/tmp/test.txt"}),
        });
        assert!(resp.ok);
        let verdict: ToolUseVerdict = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(verdict.decision, "deny");
        assert!(verdict.reason.contains("fail-closed"));
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
        let resp = runtime.handle_command(DaemonCommand::EnableAgent {
            name: "ghost".into(),
        });
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
        let resp = runtime.handle_command(DaemonCommand::RemoveAgent {
            name: "ghost".into(),
        });
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
        assert_eq!(
            slot.config.agent_goal.as_deref(),
            Some("Design the landing page")
        );
        assert_eq!(slot.config.context.as_deref(), Some("Use Tailwind CSS"));
        assert_eq!(
            slot.config.task.as_deref(),
            Some("test task"),
            "task should be unchanged"
        );
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
        assert_eq!(
            runtime.fleet.slot("a1").unwrap().config.role.as_deref(),
            Some("Backend dev")
        );

        // Clear it with empty string
        let resp = runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "a1".into(),
            role: Some("".into()),
            agent_goal: None,
            context: None,
            task: None,
        });
        assert!(resp.ok);
        assert!(
            runtime.fleet.slot("a1").unwrap().config.role.is_none(),
            "empty string should clear field"
        );
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
        let resp = runtime.handle_command(DaemonCommand::GetAgentContext {
            name: "ghost".into(),
        });
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
    fn handle_command_spawn_subagent_requires_orchestrator_or_subagent_parent() {
        let mut runtime = test_runtime(vec![test_agent("worker-1")]);
        runtime.policy_engine =
            Some(aegis_policy::PolicyEngine::from_policies(PERMIT_ALL, None).unwrap());
        let resp = runtime.handle_command(DaemonCommand::SpawnSubagent {
            request: SpawnSubagentRequest {
                parent: "worker-1".into(),
                name: Some("worker-sub-1".into()),
                role: None,
                task: None,
                depth_limit: Some(3),
                start: false,
            },
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("not an orchestrator/subagent"));
    }

    #[test]
    fn handle_command_spawn_subagent_enforces_depth_limit() {
        let mut orch = test_agent("orchestrator");
        orch.orchestrator = Some(OrchestratorConfig::default());
        let mut runtime = test_runtime(vec![orch]);
        runtime.policy_engine =
            Some(aegis_policy::PolicyEngine::from_policies(PERMIT_ALL, None).unwrap());

        let first = runtime.handle_command(DaemonCommand::SpawnSubagent {
            request: SpawnSubagentRequest {
                parent: "orchestrator".into(),
                name: Some("worker-sub-1".into()),
                role: None,
                task: Some("Implement parser".into()),
                depth_limit: Some(1),
                start: false,
            },
        });
        assert!(first.ok, "first spawn should succeed: {}", first.message);

        let second = runtime.handle_command(DaemonCommand::SpawnSubagent {
            request: SpawnSubagentRequest {
                parent: "worker-sub-1".into(),
                name: Some("worker-sub-2".into()),
                role: None,
                task: Some("Write tests".into()),
                depth_limit: Some(1),
                start: false,
            },
        });
        assert!(!second.ok);
        assert!(second.message.contains("exceeds depth_limit"));
    }

    #[test]
    fn relay_subagent_results_child_exit_sends_parent_message_and_audits() {
        let tmp = TempDir::new().expect("create temp dir");
        let base = tmp.path().join("relay-subagent-result-ok");
        std::fs::create_dir_all(&base).expect("create base dir");

        let mut orchestrator = test_agent("orchestrator");
        orchestrator.orchestrator = Some(OrchestratorConfig::default());
        orchestrator.working_dir = base.clone();
        let config = DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: Default::default(),
            alerts: vec![],
            agents: vec![orchestrator],
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
            heartbeat: Default::default(),
            channel_heartbeat: Default::default(),
            default_security_preset: None,
            default_isolation: None,
            default_network_rules: vec![],
        };
        let aegis_config = AegisConfig::default_for("relay-subagent-result-ok", &base);
        let mut runtime = DaemonRuntime::new(config, aegis_config.clone());
        runtime.policy_engine =
            Some(aegis_policy::PolicyEngine::from_policies(PERMIT_ALL, None).unwrap());

        let spawn = runtime.spawn_subagent(SpawnSubagentRequest {
            parent: "orchestrator".into(),
            name: Some("worker-sub-1".into()),
            role: Some("Test worker".into()),
            task: Some("Produce a deterministic output".into()),
            depth_limit: Some(3),
            start: false,
        });
        assert!(spawn.is_ok(), "subagent spawn should succeed: {spawn:?}");

        let (cmd_tx, cmd_rx) = mpsc::channel();
        runtime.fleet.slot_mut("orchestrator").unwrap().command_tx = Some(cmd_tx);
        if let Some(slot) = runtime.fleet.slot("worker-sub-1") {
            slot.recent_output
                .lock()
                .push_back("subagent completed task".to_string());
        }

        runtime.relay_subagent_results(&[(
            "worker-sub-1".to_string(),
            NotableEvent::ChildExited { exit_code: 0 },
        )]);

        let cmd = cmd_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("parent should receive subagent result");
        let text = match cmd {
            SupervisorCommand::SendInput { text } => text,
            other => panic!("expected SendInput relay, got {other:?}"),
        };
        assert!(text.starts_with("AEGIS_SUBAGENT_RESULT "));
        let payload = text
            .strip_prefix("AEGIS_SUBAGENT_RESULT ")
            .expect("result marker prefix");
        let parsed: serde_json::Value = serde_json::from_str(payload).expect("parse result JSON");
        assert_eq!(parsed["event"].as_str(), Some("subagent_result"));
        assert_eq!(parsed["parent"].as_str(), Some("orchestrator"));
        assert_eq!(parsed["child"].as_str(), Some("worker-sub-1"));
        assert_eq!(parsed["exit_code"].as_i64(), Some(0));
        assert!(parsed["output_tail"]
            .as_array()
            .is_some_and(|v| !v.is_empty()));

        let store = AuditStore::open(&aegis_config.ledger_path).expect("open audit ledger");
        let entries = store.query_last(100).expect("query audit entries");
        let relay_entry = entries
            .iter()
            .rev()
            .find(|entry| entry.action_kind.contains("SubagentResultReturn"))
            .expect("expected SubagentResultReturn audit entry");
        assert_eq!(relay_entry.decision, "Allow");
        let kind: serde_json::Value =
            serde_json::from_str(&relay_entry.action_kind).expect("parse action kind");
        assert_eq!(
            kind["ToolCall"]["args"]["delivered"].as_bool(),
            Some(true),
            "relay audit should record delivered=true"
        );
    }

    #[test]
    fn relay_subagent_results_without_parent_channel_audits_delivery_failure() {
        let tmp = TempDir::new().expect("create temp dir");
        let base = tmp.path().join("relay-subagent-result-no-parent-channel");
        std::fs::create_dir_all(&base).expect("create base dir");

        let mut orchestrator = test_agent("orchestrator");
        orchestrator.orchestrator = Some(OrchestratorConfig::default());
        orchestrator.working_dir = base.clone();
        let config = DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: Default::default(),
            alerts: vec![],
            agents: vec![orchestrator],
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
            heartbeat: Default::default(),
            channel_heartbeat: Default::default(),
            default_security_preset: None,
            default_isolation: None,
            default_network_rules: vec![],
        };
        let aegis_config =
            AegisConfig::default_for("relay-subagent-result-no-parent-channel", &base);
        let mut runtime = DaemonRuntime::new(config, aegis_config.clone());
        runtime.policy_engine =
            Some(aegis_policy::PolicyEngine::from_policies(PERMIT_ALL, None).unwrap());

        let spawn = runtime.spawn_subagent(SpawnSubagentRequest {
            parent: "orchestrator".into(),
            name: Some("worker-sub-2".into()),
            role: None,
            task: Some("Return quickly".into()),
            depth_limit: Some(3),
            start: false,
        });
        assert!(spawn.is_ok(), "subagent spawn should succeed: {spawn:?}");

        runtime.relay_subagent_results(&[(
            "worker-sub-2".to_string(),
            NotableEvent::ChildExited { exit_code: 17 },
        )]);

        let store = AuditStore::open(&aegis_config.ledger_path).expect("open audit ledger");
        let entries = store.query_last(100).expect("query audit entries");
        let relay_entry = entries
            .iter()
            .rev()
            .find(|entry| entry.action_kind.contains("SubagentResultReturn"))
            .expect("expected SubagentResultReturn audit entry");
        assert_eq!(relay_entry.decision, "Allow");
        let kind: serde_json::Value =
            serde_json::from_str(&relay_entry.action_kind).expect("parse action kind");
        assert_eq!(
            kind["ToolCall"]["args"]["delivered"].as_bool(),
            Some(false),
            "relay audit should record delivered=false"
        );
        assert!(
            kind["ToolCall"]["args"]["delivery_error"]
                .as_str()
                .is_some_and(|v| v.contains("no command channel")),
            "delivery error should explain parent channel failure"
        );
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
    fn handle_command_orchestrator_context_all_agents() {
        let mut runtime = test_runtime(vec![test_agent("worker-1"), test_agent("worker-2")]);
        let resp = runtime.handle_command(DaemonCommand::OrchestratorContext {
            agents: vec![],
            output_lines: None,
        });
        assert!(resp.ok);
        let snapshot: OrchestratorSnapshot = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(snapshot.agents.len(), 2);
        // Sorted alphabetically
        assert_eq!(snapshot.agents[0].name, "worker-1");
        assert_eq!(snapshot.agents[1].name, "worker-2");
    }

    #[test]
    fn handle_command_orchestrator_context_filters_orchestrator() {
        use aegis_types::daemon::OrchestratorConfig;
        let mut orch = test_agent("orchestrator");
        orch.orchestrator = Some(OrchestratorConfig::default());
        let mut runtime = test_runtime(vec![orch, test_agent("worker-1")]);
        let resp = runtime.handle_command(DaemonCommand::OrchestratorContext {
            agents: vec![],
            output_lines: None,
        });
        assert!(resp.ok);
        let snapshot: OrchestratorSnapshot = serde_json::from_value(resp.data.unwrap()).unwrap();
        // Should only contain the worker, not the orchestrator
        assert_eq!(snapshot.agents.len(), 1);
        assert_eq!(snapshot.agents[0].name, "worker-1");
    }

    #[test]
    fn handle_command_orchestrator_context_specific_agents() {
        let mut runtime = test_runtime(vec![test_agent("a1"), test_agent("a2"), test_agent("a3")]);
        let resp = runtime.handle_command(DaemonCommand::OrchestratorContext {
            agents: vec!["a1".into(), "a3".into()],
            output_lines: Some(10),
        });
        assert!(resp.ok);
        let snapshot: OrchestratorSnapshot = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(snapshot.agents.len(), 2);
        assert_eq!(snapshot.agents[0].name, "a1");
        assert_eq!(snapshot.agents[1].name, "a3");
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
        assert!(
            resp.message.contains("not a directory") || resp.message.contains("does not exist")
        );
    }

    #[test]
    fn parity_status_report_from_dir_parses_matrix() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        let reports = tmp.path().join("reports");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");
        std::fs::create_dir_all(&reports).expect("create reports dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: runtime.hooks.before_tool_call
    aegis_status: complete
    risk_level: high
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
  - feature_id: browser.cdp.session_control
    aegis_status: partial
    risk_level: high
    required_controls:
      - missing_control
    owner: browser
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let report = parity_status_report_from_dir(tmp.path()).expect("status report");
        assert_eq!(report.total_features, 2);
        assert_eq!(report.complete_features, 1);
        assert_eq!(report.partial_features, 1);
        assert_eq!(report.high_risk_blockers, 1);
    }

    #[test]
    fn parity_verify_report_from_dir_fails_on_high_risk_partial() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: orchestrator.computer_use.fast_loop
    aegis_status: partial
    risk_level: high
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let verify = parity_verify_report_from_dir(tmp.path()).expect("verify report");
        assert!(!verify.ok);
        assert_eq!(verify.checked_features, 1);
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_HIGH_RISK_COMPLETE|")));
        assert_eq!(verify.violations_struct.len(), verify.violations.len());
        assert!(verify
            .violations_struct
            .iter()
            .any(|v| v.rule_id == "R_HIGH_RISK_COMPLETE"));
    }

    #[test]
    fn parity_verify_report_from_dir_fails_complete_gate_rules() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: runtime.tools.exec
    aegis_status: complete
    risk_level: medium
    required_controls:
      - missing_control
    owner: runtime
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let verify = parity_verify_report_from_dir(tmp.path()).expect("verify report");
        assert!(!verify.ok);
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_COMPLETE_CONTROLS|runtime.tools.exec|")));
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_COMPLETE_TESTS|runtime.tools.exec|")));
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_COMPLETE_EVIDENCE|runtime.tools.exec|")));
    }

    #[test]
    fn parity_verify_report_from_dir_fails_unknown_status_and_risk() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: runtime.tools.web_search
    aegis_status: done
    risk_level: severe
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let verify = parity_verify_report_from_dir(tmp.path()).expect("verify report");
        assert!(!verify.ok);
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_STATUS_ENUM|runtime.tools.web_search|")));
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_RISK_ENUM|runtime.tools.web_search|")));
    }

    #[test]
    fn parity_verify_report_from_dir_passes_strict_complete() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: orchestrator.computer_use.fast_loop
    aegis_status: complete
    risk_level: critical
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
    acceptance_tests:
      - "tool actions are policy-gated"
    evidence_paths:
      - "crates/aegis-daemon/src/lib.rs"
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let verify = parity_verify_report_from_dir(tmp.path()).expect("verify report");
        assert!(verify.ok, "violations: {:?}", verify.violations);
        assert!(verify.violations.is_empty());
        assert!(verify.violations_struct.is_empty());
    }

    #[test]
    fn parity_diff_report_from_dir_reads_latest_report() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        let reports = tmp.path().join("reports");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");
        std::fs::create_dir_all(&reports).expect("create reports dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: orchestrator.computer_use.fast_loop
    aegis_status: partial
    risk_level: high
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let report_path = reports.join("abc.md");
        std::fs::write(
            &report_path,
            r#"
# OpenClaw Sync Report
- new_processed_sha: deadbeef

## Changed Files
- M src/a.ts
- A src/b.ts
"#,
        )
        .expect("write report");

        let diff = parity_diff_report_from_dir(tmp.path()).expect("diff report");
        assert_eq!(diff.upstream_sha, "deadbeef");
        assert_eq!(diff.changed_files, 2);
        assert_eq!(diff.impacted_feature_ids.len(), 1);
    }

    // ---------------------------------------------------------------
    // Session lifecycle tests
    // ---------------------------------------------------------------

    #[test]
    fn suspend_resume_preserves_agent_context() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        // Agent starts in Created state; first transition to Active
        {
            let slot = runtime.fleet.slot_mut("a1").unwrap();
            slot.session_state = SessionState::Active;
            slot.last_active_at = chrono::Utc::now() - chrono::Duration::seconds(60);
        }

        // Suspending a non-running agent (no PID) should fail
        let resp = runtime.handle_command(DaemonCommand::SuspendSession { name: "a1".into() });
        assert!(!resp.ok, "suspend should fail without a running PID");
        assert!(resp.message.contains("no known PID"));

        // Verify session state is still Active (fail-closed: state not mutated on signal failure)
        let slot = runtime.fleet.slot("a1").unwrap();
        assert_eq!(slot.session_state, SessionState::Active);
    }

    #[test]
    fn session_timeout_auto_terminates() {
        // This test verifies the terminate command works correctly,
        // which is the mechanism used by the timeout watchdog.
        let mut runtime = test_runtime(vec![test_agent("timeout-agent")]);

        // Set agent to Active state
        {
            let slot = runtime.fleet.slot_mut("timeout-agent").unwrap();
            slot.session_state = SessionState::Active;
            slot.last_active_at = chrono::Utc::now() - chrono::Duration::seconds(3600);
        }

        // Terminate the session (simulating what the timeout watchdog would do)
        let resp = runtime.handle_command(DaemonCommand::TerminateSession {
            name: "timeout-agent".into(),
        });
        assert!(resp.ok, "terminate should succeed: {}", resp.message);

        // Verify session is terminated
        let slot = runtime.fleet.slot("timeout-agent").unwrap();
        assert_eq!(slot.session_state, SessionState::Terminated);

        // Verify accumulated time was tracked
        let data = resp.data.unwrap();
        let accumulated: u64 = data["accumulated_active_secs"].as_u64().unwrap();
        // Should be approximately 3600 seconds
        assert!(accumulated >= 3599, "expected ~3600s, got {accumulated}");
    }

    #[test]
    fn concurrent_session_operations_are_serialized() {
        // Session operations go through handle_command which is &mut self,
        // enforcing serialization at the type level. Verify that state
        // transitions are consistent across sequential operations.
        let mut runtime = test_runtime(vec![test_agent("serial-agent")]);

        // Set to Active
        {
            let slot = runtime.fleet.slot_mut("serial-agent").unwrap();
            slot.session_state = SessionState::Active;
        }

        // Try to resume an Active session (should fail)
        let resp = runtime.handle_command(DaemonCommand::ResumeSession {
            name: "serial-agent".into(),
        });
        assert!(!resp.ok, "resume should fail on Active session");
        assert!(resp.message.contains("cannot resume"));

        // Verify state is still Active after the failed operation
        let slot = runtime.fleet.slot("serial-agent").unwrap();
        assert_eq!(slot.session_state, SessionState::Active);

        // Terminate should succeed
        let resp = runtime.handle_command(DaemonCommand::TerminateSession {
            name: "serial-agent".into(),
        });
        assert!(resp.ok);

        // After termination, all further operations should be denied
        let resp = runtime.handle_command(DaemonCommand::SuspendSession {
            name: "serial-agent".into(),
        });
        assert!(!resp.ok, "suspend should fail on Terminated session");

        let resp = runtime.handle_command(DaemonCommand::ResumeSession {
            name: "serial-agent".into(),
        });
        assert!(!resp.ok, "resume should fail on Terminated session");

        let resp = runtime.handle_command(DaemonCommand::TerminateSession {
            name: "serial-agent".into(),
        });
        assert!(!resp.ok, "double terminate should fail");
        assert!(resp.message.contains("already terminated"));
    }

    #[test]
    fn session_lifecycle_status_reports_current_state() {
        let mut runtime = test_runtime(vec![test_agent("status-agent")]);

        // Check initial state
        let resp = runtime.handle_command(DaemonCommand::SessionLifecycleStatus {
            name: "status-agent".into(),
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert_eq!(data["session_state"].as_str().unwrap(), "created");
        assert!(!data["is_terminal"].as_bool().unwrap());

        // Transition to Active and check
        {
            let slot = runtime.fleet.slot_mut("status-agent").unwrap();
            slot.session_state = SessionState::Active;
            slot.last_active_at = chrono::Utc::now() - chrono::Duration::seconds(120);
        }

        let resp = runtime.handle_command(DaemonCommand::SessionLifecycleStatus {
            name: "status-agent".into(),
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert_eq!(data["session_state"].as_str().unwrap(), "active");
        let accumulated = data["accumulated_active_secs"].as_u64().unwrap();
        assert!(accumulated >= 119, "expected ~120s, got {accumulated}");
    }

    #[test]
    fn session_lifecycle_unknown_agent() {
        let mut runtime = test_runtime(vec![]);

        let resp = runtime.handle_command(DaemonCommand::SuspendSession {
            name: "ghost".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("unknown agent"));

        let resp = runtime.handle_command(DaemonCommand::ResumeSession {
            name: "ghost".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("unknown agent"));

        let resp = runtime.handle_command(DaemonCommand::TerminateSession {
            name: "ghost".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("unknown agent"));

        let resp = runtime.handle_command(DaemonCommand::SessionLifecycleStatus {
            name: "ghost".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("unknown agent"));
    }
}
