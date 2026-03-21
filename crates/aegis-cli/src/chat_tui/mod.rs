//! Chat-centric TUI for Aegis.
//!
//! Provides a conversational interface that calls LLM APIs directly via
//! `DaemonCommand::LlmComplete`, with a minimal command bar for system
//! commands. This is the default interface when `aegis` is invoked.

pub mod agent_loop;
pub mod approval;
pub mod commands;
pub mod compaction;
pub mod custom_terminal;
pub mod diff_preview;
pub mod event;
pub mod heartbeat;
pub mod hooks;
pub mod input;
pub mod insert_history;
pub mod overlay;
pub mod markdown;
pub mod message;
pub mod persistence;
pub mod render;
pub mod streaming;
pub mod system_prompt;
pub mod tools;
mod ui;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Instant;

use anyhow::Result;
use crossterm::event::KeyEvent;

use aegis_control::daemon::{DaemonClient, DaemonCommand};
use aegis_types::llm::{LlmMessage, LlmRole};
use aegis_types::tool_classification::ActionRisk;
// LlmResponse and LlmToolCall are only used in tests via super::*
#[cfg(test)]
use aegis_types::llm::{LlmResponse, LlmToolCall};

use self::event::{AppEvent, EventHandler};
use self::message::{ChatMessage, MessageRole};
use self::system_prompt::PromptMode;

use self::tools::{
    SkillExecResult,
    format_skill_output, format_tool_call_content, get_tool_definitions_json,
    get_tool_descriptions, init_skills, summarize_tool_input,
};

use self::diff_preview::generate_diff_preview;

/// How often to poll crossterm for events (milliseconds).
const TICK_RATE_MS: u64 = 200;

/// How often to re-check daemon connectivity (milliseconds).
const POLL_INTERVAL_MS: u128 = 2000;

/// The current input mode in the chat TUI.
#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    /// Default: cursor in input box, typing sends to LLM.
    Chat,
    /// Escape when input empty: navigate message history.
    Scroll,
    /// `/` when input empty: command bar.
    Command,
}

/// A saved conversation state for the restore picker.
#[derive(Debug, Clone)]
pub struct ConversationSnapshot {
    /// First 60 chars of the user message that triggered this snapshot.
    pub label: String,
    /// Display messages at the time of the snapshot.
    pub messages: Vec<ChatMessage>,
    /// LLM conversation history at the time of the snapshot.
    pub conversation: Vec<LlmMessage>,
}

/// Active overlay in the chat TUI.
///
/// Overlays render on top of the main UI and capture all input until
/// dismissed. They are modal: only one overlay can be active at a time.
pub enum Overlay {
    /// Model picker: filterable list of available models.
    ModelPicker {
        /// All available (model_id, display_label) pairs.
        items: Vec<(String, String)>,
        /// User-typed filter string.
        filter: String,
        /// Index of the selected item in the filtered list.
        selected: usize,
    },
    /// Session picker: list of saved conversations.
    SessionPicker {
        /// Saved conversation metadata, newest first.
        items: Vec<persistence::ConversationMeta>,
        /// Index of the selected item.
        selected: usize,
    },
    /// Settings panel: toggle options.
    Settings {
        /// Index of the selected setting.
        selected: usize,
    },
    /// Login overlay: manage provider credentials.
    Login {
        /// All provider entries for display.
        providers: Vec<LoginProviderEntry>,
        /// Index of the selected provider.
        selected: usize,
        /// If set, showing the key input sub-view for a specific provider.
        key_input: Option<LoginKeyInput>,
    },
    /// Conversation restore picker: choose a past point to roll back to.
    RestorePicker {
        /// Snapshots to display, newest first.
        snapshots: Vec<ConversationSnapshot>,
        /// Index of the currently highlighted snapshot.
        selected: usize,
    },
    /// Feature setup wizard (Telegram, skill auth, etc.)
    Setup {
        /// The active setup wizard.
        wizard: Box<dyn crate::setup_wizard::SetupWizard>,
    },
}

/// Entry for a provider in the login overlay.
#[derive(Debug, Clone)]
pub(crate) struct LoginProviderEntry {
    pub id: &'static str,
    pub display_name: &'static str,
    pub status_label: String,
    pub masked_key: Option<String>,
}

/// State for the API key text input sub-view.
#[derive(Debug, Clone)]
pub(crate) struct LoginKeyInput {
    pub provider_id: &'static str,
    pub display_name: &'static str,
    pub buffer: String,
    pub cursor: usize,
    pub masked: bool,
    pub error: Option<String>,
}

use self::agent_loop::{AgentLoopEvent, AgentLoopParams, run_agent_loop};

use self::approval::{ApprovalProfile, approval_context_for_prompt, parse_approval_mode};
// These are used only in tests via super::*
#[cfg(test)]
use self::approval::{
    approval_profile_label, classify_tool_risk, is_safe_tool, should_auto_approve_tool,
};
#[cfg(test)]
pub use self::input::{local_completions, apply_completion};



/// Seed workspace with bootstrap template files if they don't exist.
///
/// Writes SOUL.md, IDENTITY.md, USER.md, TOOLS.md, and BOOTSTRAP.md to
/// `~/.aegis/workspace/`. Returns `true` if BOOTSTRAP.md was just created
/// (indicates first run -- the bootstrap conversation should be triggered).
fn seed_workspace() -> bool {
    let dir = aegis_types::daemon::workspace_dir();
    let _ = std::fs::create_dir_all(&dir);

    let templates: &[(&str, &str)] = &[
        ("BOOTSTRAP.md", include_str!("templates/BOOTSTRAP.md")),
        ("SOUL.md", include_str!("templates/SOUL.md")),
        ("IDENTITY.md", include_str!("templates/IDENTITY.md")),
        ("USER.md", include_str!("templates/USER.md")),
        ("TOOLS.md", include_str!("templates/TOOLS.md")),
        ("MEMORY.md", include_str!("templates/MEMORY.md")),
        ("HEARTBEAT.md", include_str!("templates/HEARTBEAT.md")),
    ];

    let mut is_first_run = false;
    for (name, content) in templates {
        let path = dir.join(name);
        if !path.exists() {
            let _ = std::fs::write(&path, content);
            if *name == "BOOTSTRAP.md" {
                is_first_run = true;
            }
        }
    }
    is_first_run
}

/// Top-level application state for the chat TUI.
pub struct ChatApp {
    /// Whether the main loop should keep running.
    pub running: bool,
    /// Current input mode.
    pub input_mode: InputMode,
    /// Active overlay (modal popup), if any.
    pub overlay: Option<Overlay>,

    // -- Chat --
    /// Display messages for the chat area.
    pub messages: Vec<ChatMessage>,
    /// Scroll offset into the message history (0 = bottom), in visual lines.
    pub scroll_offset: usize,
    /// Total visual lines in the chat area (updated each frame by the renderer).
    pub total_visual_lines: usize,
    /// Visible height of the chat area (updated each frame by the renderer).
    pub visible_height: usize,
    /// When scrolling last occurred (for auto-hiding scrollbar).
    pub last_scroll_at: Option<std::time::Instant>,

    // -- Session persistence --
    /// Unique identifier for this conversation session.
    pub session_id: String,
    /// Audit ledger session UUID, obtained from daemon on connect.
    /// Used to link tool execution audit entries to this chat session.
    pub audit_session_id: Option<String>,

    // -- LLM conversation --
    /// Full LLM conversation history (sent with each request).
    pub conversation: Vec<LlmMessage>,
    /// Model identifier (from daemon config or environment detection).
    pub model: String,
    /// Whether we're waiting for an LLM response or tool execution.
    pub awaiting_response: bool,
    /// Count of thinking delta chunks received (for thinking spinner display).
    pub thinking_tokens: usize,
    /// When the current LLM request started (for elapsed-time display in header).
    pub response_started_at: Option<Instant>,
    /// Channel for receiving agentic loop events from background thread.
    agent_rx: Option<mpsc::Receiver<AgentLoopEvent>>,
    /// Channel for sending approval decisions to the background thread.
    approval_tx: Option<mpsc::Sender<bool>>,
    /// Whether we're waiting for user approval on a tool.
    pub awaiting_approval: bool,
    /// Description of the tool awaiting approval (for display).
    pub pending_tool_desc: Option<String>,
    /// Whether to auto-approve all remaining tools in this turn.
    pub auto_approve_turn: bool,
    /// Approval profile controlling risk-based auto-approval.
    pub approval_profile: ApprovalProfile,
    /// Extended thinking budget in tokens (Anthropic only). None = disabled.
    pub thinking_budget: Option<u32>,
    /// Whether a bootstrap conversation should be auto-triggered on first connect.
    pub bootstrap_pending: bool,
    /// Abort flag shared with the background agent loop thread.
    /// Setting this to `true` causes the loop to stop at the next check point.
    abort_flag: Arc<AtomicBool>,

    // -- Input --
    /// Text buffer for chat input.
    pub input_buffer: String,
    /// Cursor position in the input buffer.
    pub input_cursor: usize,
    /// History of sent inputs.
    pub input_history: Vec<String>,
    /// Current position in input history (None = composing new).
    pub history_index: Option<usize>,
    /// Saved draft buffer before navigating into input history.
    pub input_draft: String,
    /// Timestamp of the last Escape keypress (for double-Esc detection).
    pub last_esc_at: Option<std::time::Instant>,
    /// Conversation snapshots for the restore picker (taken after each assistant turn).
    pub snapshots: Vec<ConversationSnapshot>,

    // -- Command bar --
    /// Text buffer for the command bar.
    pub command_buffer: String,
    /// Cursor position in the command buffer.
    pub command_cursor: usize,
    /// History of executed commands.
    pub command_history: Vec<String>,
    /// Current position in command history.
    pub command_history_index: Option<usize>,
    /// Current tab completions.
    pub command_completions: Vec<String>,
    /// Selected completion index.
    pub completion_idx: Option<usize>,
    /// Result/error message from last command execution.
    pub command_result: Option<String>,
    /// When the command result was set (for auto-clear).
    pub command_result_at: Option<Instant>,

    // -- Usage tracking --
    /// Cumulative input tokens this session.
    pub total_input_tokens: u64,
    /// Cumulative output tokens this session.
    pub total_output_tokens: u64,
    /// Cumulative estimated cost in USD this session.
    pub total_cost_usd: f64,
    /// Whether to show usage info in the status bar.
    pub show_usage: bool,

    // -- Connection --
    /// Whether the last daemon poll succeeded.
    pub connected: bool,
    /// Last error message from daemon communication.
    pub last_error: Option<String>,

    // -- Internal --
    /// Daemon client for sending commands.
    client: Option<DaemonClient>,
    /// When we last polled the daemon.
    last_poll: Instant,
    /// Pricing table for cost calculation.
    pricing: aegis_proxy::pricing::PricingTable,

    // -- Skills --
    /// Registry of discovered and activated skills.
    skill_registry: aegis_skills::SkillRegistry,
    /// Router mapping slash command names to skills.
    skill_router: aegis_skills::CommandRouter,
    /// Dynamic command names from discovered skills (for tab completion).
    skill_command_names: Vec<String>,
    /// Channel for receiving skill execution results from background thread.
    skill_result_rx: Option<mpsc::Receiver<SkillExecResult>>,

    // -- Heartbeat (autonomous thinking) --
    /// Whether periodic heartbeat thinking is enabled.
    pub heartbeat_enabled: bool,
    /// Interval between heartbeat checks in seconds.
    pub heartbeat_interval_secs: u64,
    /// When the last heartbeat was fired (or app start).
    pub last_heartbeat_at: Instant,
    /// Whether a heartbeat-triggered LLM turn is currently in flight.
    pub heartbeat_in_flight: bool,
    /// Set to true to trigger an immediate heartbeat on next tick.
    pub heartbeat_wake_pending: bool,
    /// Count of consecutive HEARTBEAT_OK responses (for adaptive backoff).
    pub heartbeat_consecutive_ok: u32,
    /// When the user last sent a message (for idle duration context).
    pub last_user_interaction: Instant,
}

/// Commands recognized by the minimal command bar.
const COMMANDS: &[&str] = &[
    "quit",
    "q",
    "clear",
    "new",
    "compact",
    "abort",
    "model",
    "provider",
    "help",
    "usage",
    "think",
    "think off",
    "think low",
    "think medium",
    "think high",
    "auto",
    "auto off",
    "auto edits",
    "auto high",
    "auto full",
    "save",
    "resume",
    "sessions",
    "settings",
    "daemon start",
    "daemon stop",
    "daemon status",
    "daemon restart",
    "daemon reload",
    "daemon init",
    // Setup commands
    "setup",
    "setup telegram",
    "setup slack",
    "setup discord",
    "setup whatsapp",
    "setup signal",
    "setup matrix",
    "setup imessage",
    "setup irc",
    "setup msteams",
    "setup googlechat",
    "setup feishu",
    "setup line",
    "setup nostr",
    "setup mattermost",
    "setup voicecall",
    "setup twitch",
    "setup nextcloud",
    "setup zalo",
    "setup tlon",
    "setup lobster",
    "setup gmail",
    "setup webhook",
    "telegram setup",
    "telegram status",
    "telegram disable",
    "sandbox",
    // Skill commands
    "debug",
    "doc",
    "explain",
    "refactor",
    "test",
    "review",
    "security",
    "perf",
    "panel-review",
    "link-worktree",
    "login",
    "heartbeat",
    "heartbeat now",
    "heartbeat on",
    "heartbeat off",
    "heartbeat interval",
];

impl ChatApp {
    /// Create a new chat TUI application.
    pub fn new(client: Option<DaemonClient>, model: String) -> Self {
        let (skill_registry, skill_router) = init_skills();
        let skill_command_names: Vec<String> = skill_router
            .list_commands()
            .into_iter()
            .map(|ci| ci.name.clone())
            .collect();

        let (saved_input_history, saved_command_history) = persistence::load_history();

        Self {
            running: true,
            input_mode: InputMode::Chat,
            overlay: None,

            messages: Vec::new(),
            scroll_offset: 0,
            last_scroll_at: None,
            total_visual_lines: 0,
            visible_height: 0,

            session_id: persistence::generate_conversation_id(),
            audit_session_id: None,

            conversation: Vec::new(),
            model,
            awaiting_response: false,
            thinking_tokens: 0,
            response_started_at: None,
            agent_rx: None,
            approval_tx: None,
            awaiting_approval: false,
            pending_tool_desc: None,
            auto_approve_turn: false,
            approval_profile: ApprovalProfile::Manual,
            thinking_budget: None,
            bootstrap_pending: false,
            abort_flag: Arc::new(AtomicBool::new(false)),

            input_buffer: String::new(),
            input_cursor: 0,
            input_history: saved_input_history,
            history_index: None,
            input_draft: String::new(),
            last_esc_at: None,
            snapshots: Vec::new(),

            command_buffer: String::new(),
            command_cursor: 0,
            command_history: saved_command_history,
            command_history_index: None,
            command_completions: Vec::new(),
            completion_idx: None,
            command_result: None,
            command_result_at: None,

            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost_usd: 0.0,
            show_usage: true,

            connected: false,
            last_error: None,

            client,
            // Force immediate first poll.
            last_poll: Instant::now() - std::time::Duration::from_secs(10),
            pricing: aegis_proxy::pricing::PricingTable::with_defaults(),

            skill_registry,
            skill_router,
            skill_command_names,
            skill_result_rx: None,

            heartbeat_enabled: true,
            heartbeat_interval_secs: 600, // 10 minutes
            last_heartbeat_at: Instant::now(),
            heartbeat_in_flight: false,
            heartbeat_wake_pending: false,
            heartbeat_consecutive_ok: 0,
            last_user_interaction: Instant::now(),
        }
    }

    /// Maximum valid scroll offset (scrolling past this shows blank space).
    fn max_scroll(&self) -> usize {
        self.total_visual_lines.saturating_sub(self.visible_height)
    }

    /// Scroll to the bottom, but only if the user hasn't scrolled up.
    ///
    /// This prevents new content (streaming deltas, tool results, etc.) from
    /// yanking the scroll position when the user is reading earlier messages.
    fn auto_scroll_to_bottom(&mut self) {
        // scroll_offset == 0 means already at bottom; nonzero means the user
        // has deliberately scrolled up, so we don't yank them back.
    }

    /// Clear stale command result messages after timeout.
    fn clear_stale_result(&mut self) {
        if let Some(at) = self.command_result_at {
            if at.elapsed().as_secs() >= 5 {
                self.command_result = None;
                self.command_result_at = None;
            }
        }
    }

    /// Poll the daemon for connectivity and check for LLM responses.
    pub fn poll_daemon(&mut self) {
        self.clear_stale_result();
        self.poll_llm();
        self.poll_skills();
        self.poll_setup_wizard();

        if self.last_poll.elapsed().as_millis() < POLL_INTERVAL_MS {
            return;
        }
        self.last_poll = Instant::now();

        let client = match &self.client {
            Some(c) => c,
            None => {
                self.connected = false;
                self.last_error = Some("no daemon client configured".into());
                return;
            }
        };

        // Ping with a short timeout (500ms) to avoid freezing the TUI event
        // loop when the daemon is unresponsive. The default 5s timeout would
        // block every 2-second poll cycle, making the entire UI unresponsive.
        match client.send_with_timeout(&DaemonCommand::Ping, 500) {
            Ok(resp) if resp.ok => {
                let was_disconnected = !self.connected;
                self.connected = true;
                self.last_error = None;

                // Register an audit session on first connect (or reconnect).
                if was_disconnected && self.audit_session_id.is_none() {
                    self.register_audit_session();
                }

                // Trigger bootstrap conversation on first connect if this is a fresh workspace.
                if was_disconnected && self.bootstrap_pending {
                    self.bootstrap_pending = false;
                    self.trigger_bootstrap();
                }
            }
            Ok(resp) => {
                self.connected = false;
                self.last_error = Some(resp.message);
            }
            Err(e) => {
                self.connected = false;
                self.last_error = Some(e);
            }
        }
    }

    /// Register an audit session in the daemon's audit ledger.
    ///
    /// Sends `RegisterChatSession` and stores the returned UUID so
    /// subsequent tool executions are linked in the audit trail.
    fn register_audit_session(&mut self) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };
        match client.send(&DaemonCommand::RegisterChatSession) {
            Ok(resp) if resp.ok => {
                if let Some(data) = &resp.data {
                    if let Some(sid) = data.get("session_id").and_then(|v| v.as_str()) {
                        self.audit_session_id = Some(sid.to_string());
                    }
                }
            }
            _ => {
                // Non-fatal: audit linkage is best-effort.
                // Tool execution still works; entries just won't have session linkage.
            }
        }
    }

    /// Check for events from the agentic loop running in a background thread.
    fn poll_llm(&mut self) {
        // Drain all available events from the channel.
        while let Some(rx) = self.agent_rx.as_ref() {
            let event = match rx.try_recv() {
                Ok(event) => event,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Background thread died without sending Done.
                    if self.awaiting_response {
                        self.messages.push(ChatMessage::new(
                            MessageRole::System,
                            "Error: background request terminated unexpectedly."
                                .to_string(),
                        ));
                        self.awaiting_response = false;
                        self.response_started_at = None;
                        self.auto_approve_turn = false;
                        self.pending_tool_desc = None;
                    }
                    self.agent_rx = None;
                    break;
                }
            };

            match event {
                AgentLoopEvent::Response(resp) => {
                    // Track usage.
                    self.total_input_tokens += resp.usage.input_tokens;
                    self.total_output_tokens += resp.usage.output_tokens;
                    if let Some(cost) = self.pricing.calculate_cost(
                        &resp.model,
                        resp.usage.input_tokens,
                        resp.usage.output_tokens,
                        0,
                        0,
                    ) {
                        self.total_cost_usd += cost;
                    }

                    // Build assistant message with tool calls if present.
                    let mut assistant_msg = LlmMessage::assistant(resp.content.clone());
                    assistant_msg.tool_calls = resp.tool_calls.clone();
                    self.conversation.push(assistant_msg);

                    // If we were streaming, the display message already exists.
                    // Only create a new display message if we weren't streaming.
                    if !resp.content.is_empty() {
                        let already_streaming = self
                            .messages
                            .last()
                            .is_some_and(|m| m.role == MessageRole::Assistant);
                        if !already_streaming {
                            self.messages
                                .push(ChatMessage::new(MessageRole::Assistant, resp.content));
                        }
                    }
                    self.auto_scroll_to_bottom();
                }
                AgentLoopEvent::StreamThinking(_text) => {
                    // Model is thinking (e.g., MiniMax extended thinking).
                    // Show a visible "thinking" indicator so the user knows
                    // the request is being processed. We don't display the
                    // actual thinking text -- just update a counter.
                    self.thinking_tokens += 1;
                }
                AgentLoopEvent::StreamDelta(text) => {
                    // Clear thinking indicator once real text arrives.
                    self.thinking_tokens = 0;
                    // Append to the current assistant message, or create one.
                    let is_assistant = self
                        .messages
                        .last()
                        .is_some_and(|m| m.role == MessageRole::Assistant);
                    if is_assistant {
                        if let Some(msg) = self.messages.last_mut() {
                            msg.content.push_str(&text);
                        }
                    } else {
                        self.messages
                            .push(ChatMessage::new(MessageRole::Assistant, text));
                    }
                    self.auto_scroll_to_bottom();
                }
                AgentLoopEvent::ToolCalls(tool_calls) => {
                    for tc in &tool_calls {
                        let summary = summarize_tool_input(&tc.name, &tc.input);
                        self.messages.push(ChatMessage::new(
                            MessageRole::ToolCall {
                                tool_name: tc.name.clone(),
                                summary,
                            },
                            format_tool_call_content(&tc.name, &tc.input),
                        ));
                    }
                    self.auto_scroll_to_bottom();
                }
                AgentLoopEvent::ToolResult {
                    tool_call_id,
                    tool_name,
                    result,
                } => {
                    // Add tool result to conversation.
                    self.conversation
                        .push(LlmMessage::tool_result(tool_call_id, result.clone()));
                    // Show abbreviated result in UI.
                    let display = if result.len() > 500 {
                        format!("{}...[truncated]", &result[..500])
                    } else {
                        result
                    };
                    self.messages.push(ChatMessage::new(
                        MessageRole::System,
                        format!("[{tool_name}] {display}"),
                    ));
                    self.auto_scroll_to_bottom();
                }
                AgentLoopEvent::ToolApprovalNeeded { tool_call, .. } => {
                    let desc = format!(
                        "{}: {}",
                        tool_call.name,
                        summarize_tool_input(&tool_call.name, &tool_call.input)
                    );
                    let diff_preview =
                        generate_diff_preview(&tool_call.name, &tool_call.input);
                    self.messages.push(ChatMessage::new(
                        MessageRole::Permission {
                            prompt: desc.clone(),
                            resolved: None,
                            diff_preview,
                        },
                        format!("Allow {}? [y]es / [n]o / [a]ll", tool_call.name),
                    ));
                    self.pending_tool_desc = Some(desc);
                    self.awaiting_approval = true;
                    self.auto_scroll_to_bottom();
                }
                AgentLoopEvent::Error(msg) => {
                    self.messages.push(ChatMessage::new(
                        MessageRole::System,
                        format!("Error: {msg}"),
                    ));
                    self.awaiting_response = false;
                    self.thinking_tokens = 0;
                    self.response_started_at = None;
                    self.auto_approve_turn = false;
                }
                AgentLoopEvent::Notice(msg) => {
                    self.messages
                        .push(ChatMessage::new(MessageRole::System, msg));
                    self.auto_scroll_to_bottom();
                }
                AgentLoopEvent::Done => {
                    self.awaiting_response = false;
                    self.thinking_tokens = 0;
                    self.response_started_at = None;
                    self.auto_approve_turn = false;
                    if self.heartbeat_in_flight {
                        self.complete_heartbeat();
                    } else {
                        // Save a restore point after each completed assistant turn.
                        self.push_snapshot();
                    }
                }
                AgentLoopEvent::SubagentComplete {
                    task_id,
                    description,
                    result,
                    output_file,
                } => {
                    let summary = if result.len() > 300 {
                        format!("{}...", &result[..300])
                    } else {
                        result
                    };
                    self.messages.push(ChatMessage::new(
                        MessageRole::Result {
                            summary: format!(
                                "Task \"{description}\" (id: {task_id}) completed. \
                                 Full output: {output_file}"
                            ),
                        },
                        summary,
                    ));
                    self.auto_scroll_to_bottom();
                }
            }
        }
    }

    /// Trigger the bootstrap "getting to know you" conversation.
    ///
    /// The full bootstrap instructions are included in the system prompt
    /// (via system_prompt.rs) when BOOTSTRAP.md exists. Here we just inject
    /// a short trigger message to kick off the conversation.
    fn trigger_bootstrap(&mut self) {
        let bootstrap_path = aegis_types::daemon::workspace_dir().join("BOOTSTRAP.md");
        if !bootstrap_path.exists() {
            return;
        }

        // Short trigger -- full instructions are in the system prompt.
        self.conversation.push(LlmMessage::user(
            "[First run -- bootstrap mode active. Follow your bootstrap instructions.]"
                .to_string(),
        ));
        self.messages.push(ChatMessage::new(
            MessageRole::System,
            "Starting bootstrap -- getting to know you...".to_string(),
        ));
        self.auto_scroll_to_bottom();
        self.awaiting_response = true;
        self.send_llm_request();
    }

    // -- Heartbeat (autonomous thinking) ------------------------------------------

    /// Check whether a heartbeat thinking turn should fire now.
    fn is_heartbeat_due(&self) -> bool {
        if !self.heartbeat_enabled {
            return false;
        }
        // Don't stack on top of an active LLM request.
        if self.awaiting_response || self.awaiting_approval {
            return false;
        }
        // Immediate wake bypasses the timer.
        if self.heartbeat_wake_pending {
            return true;
        }
        // Adaptive backoff: effective interval grows with consecutive no-ops (up to 4x).
        let backoff_mult = (1 + self.heartbeat_consecutive_ok).min(4) as u64;
        let effective_secs = self.heartbeat_interval_secs.saturating_mul(backoff_mult);
        self.last_heartbeat_at.elapsed().as_secs() >= effective_secs
    }

    /// Trigger an autonomous heartbeat thinking turn.
    ///
    /// Reads HEARTBEAT.md, injects context (current time, idle duration), and
    /// sends to the LLM. Follows the same pattern as `trigger_bootstrap`.
    fn trigger_heartbeat(&mut self) {
        self.heartbeat_wake_pending = false;
        self.last_heartbeat_at = Instant::now();

        let heartbeat_path = aegis_types::daemon::workspace_dir().join("HEARTBEAT.md");
        let heartbeat_content = match std::fs::read_to_string(&heartbeat_path) {
            Ok(c) => c,
            Err(_) => return, // No HEARTBEAT.md, skip silently.
        };

        if !heartbeat::is_heartbeat_content_actionable(&heartbeat_content) {
            return; // Only template boilerplate, skip the API call.
        }

        let prompt = heartbeat::build_heartbeat_prompt(
            &heartbeat_content,
            self.last_user_interaction,
            self.heartbeat_consecutive_ok,
        );
        let now = chrono::Local::now();

        self.conversation.push(LlmMessage::user(prompt));
        self.messages.push(ChatMessage::new(
            MessageRole::Heartbeat,
            format!("[Heartbeat @ {}]", now.format("%H:%M")),
        ));
        // Don't reset scroll_offset here -- heartbeats are background activity
        // and should not yank the user's scroll position.
        self.awaiting_response = true;
        self.heartbeat_in_flight = true;
        self.send_llm_request();
    }

    /// Check if the most recent assistant response is a no-op heartbeat ack.
    ///
    /// Returns false if tools were used during this heartbeat turn (even if
    /// the final response says HEARTBEAT_OK), because tool use means real
    /// work happened and the conversation entries shouldn't be pruned.
    fn is_heartbeat_response_empty(&self) -> bool {
        heartbeat::is_heartbeat_response_empty(&self.messages, &self.conversation)
    }

    /// Remove the last heartbeat prompt + response from conversation and display.
    fn prune_last_heartbeat_exchange(&mut self) {
        heartbeat::prune_last_heartbeat_exchange(&mut self.messages, &mut self.conversation);
    }

    /// Called when a heartbeat-triggered LLM turn completes.
    fn complete_heartbeat(&mut self) {
        self.heartbeat_in_flight = false;
        if self.is_heartbeat_response_empty() {
            self.prune_last_heartbeat_exchange();
            self.heartbeat_consecutive_ok += 1;
        } else {
            // Real content -- reset backoff and save snapshot.
            self.heartbeat_consecutive_ok = 0;
            self.push_snapshot();
            // Save conversation to disk.
            let _ = persistence::save_conversation(
                &self.session_id,
                &self.conversation,
                &self.model,
            );
        }
    }

    /// Abort a heartbeat in flight so the user's message can proceed immediately.
    fn abort_heartbeat_for_user_input(&mut self) {
        if !self.heartbeat_in_flight {
            return;
        }
        // Signal the background thread to stop.
        self.abort_flag.store(true, Ordering::Relaxed);
        self.approval_tx = None;
        self.awaiting_response = false;
        self.response_started_at = None;
        self.awaiting_approval = false;
        self.pending_tool_desc = None;
        self.agent_rx = None;
        self.abort_flag = Arc::new(AtomicBool::new(false));
        self.heartbeat_in_flight = false;

        // Prune any partial heartbeat messages from conversation/display.
        self.prune_last_heartbeat_exchange();
    }

    // -- End heartbeat --------------------------------------------------------

    /// Send the current conversation to the LLM and run the agentic loop.
    /// Save the current conversation as a restore point.
    ///
    /// Called after each completed assistant turn. Capped at 20 snapshots;
    /// oldest are dropped when the cap is exceeded.
    fn push_snapshot(&mut self) {
        // Label: preview of the last user message that triggered this turn.
        let label = self
            .messages
            .iter()
            .rev()
            .find(|m| m.role == MessageRole::User)
            .map(|m| {
                let s = m.content.as_str();
                if s.chars().count() > 60 {
                    let end = s.char_indices().nth(60).map(|(i, _)| i).unwrap_or(s.len());
                    format!("{}…", &s[..end])
                } else {
                    s.to_string()
                }
            })
            .unwrap_or_else(|| "(empty)".to_string());

        self.snapshots.push(ConversationSnapshot {
            label,
            messages: self.messages.clone(),
            conversation: self.conversation.clone(),
        });

        // Keep at most 20 restore points.
        const MAX_SNAPSHOTS: usize = 20;
        if self.snapshots.len() > MAX_SNAPSHOTS {
            self.snapshots.drain(..self.snapshots.len() - MAX_SNAPSHOTS);
        }
    }

    ///
    /// Abort the currently running LLM request/agent loop.
    fn abort_current_request(&mut self) {
        if !self.awaiting_response && !self.awaiting_approval {
            self.set_result("Nothing to abort.");
            return;
        }
        // Signal the background thread to stop.
        self.abort_flag.store(true, Ordering::Relaxed);
        // Drop the approval channel so a blocking recv() in the agent loop unblocks.
        self.approval_tx = None;
        self.awaiting_response = false;
        self.response_started_at = None;
        self.awaiting_approval = false;
        self.pending_tool_desc = None;
        self.agent_rx = None;
        // Reset the flag for the next request.
        self.abort_flag = Arc::new(AtomicBool::new(false));

        // Inject synthetic tool_result messages for any unpaired tool_use blocks.
        // Without this, the conversation history becomes malformed and the LLM API
        // will reject subsequent requests with "tool call result does not follow
        // tool call".
        let pending_tool_ids: Vec<String> = {
            let last_assistant_idx = self
                .conversation
                .iter()
                .rposition(|m| m.role == LlmRole::Assistant && !m.tool_calls.is_empty());
            match last_assistant_idx {
                Some(idx) => {
                    let expected: Vec<String> = self.conversation[idx]
                        .tool_calls
                        .iter()
                        .map(|tc| tc.id.clone())
                        .collect();
                    // Some tool_results may already have been pushed by the
                    // background thread before the abort took effect.
                    let existing: std::collections::HashSet<&str> = self.conversation
                        [idx + 1..]
                        .iter()
                        .filter_map(|m| m.tool_use_id.as_deref())
                        .collect();
                    expected
                        .into_iter()
                        .filter(|id| !existing.contains(id.as_str()))
                        .collect()
                }
                None => vec![],
            }
        };
        for tool_id in pending_tool_ids {
            self.conversation
                .push(LlmMessage::tool_result(tool_id, "[Aborted by user]"));
        }

        self.messages.push(ChatMessage::new(
            MessageRole::System,
            "[Aborted]".to_string(),
        ));
        self.scroll_offset = 0;
    }

    /// The loop runs in a background thread. It sends the conversation + tool
    /// definitions to the LLM, and if the LLM returns `StopReason::ToolUse`,
    /// it executes each tool and loops. Tool approvals are handled via a
    /// separate mpsc channel that the UI thread sends decisions through.
    fn send_llm_request(&mut self) {
        self.response_started_at = Some(Instant::now());
        // Auto-compact if the conversation exceeds the model's context window.
        if let Some(compacted) = compaction::compact_conversation(&self.conversation, &self.model) {
            let old_len = self.conversation.len();
            let new_len = compacted.len();
            self.conversation = compacted;
            self.messages.push(ChatMessage::new(
                MessageRole::System,
                format!(
                    "[Compacted: {} messages -> {} to fit context window]",
                    old_len, new_len
                ),
            ));
        }

        let conv = self.conversation.clone();
        let model = self.model.clone();
        let auto_approve = self.auto_approve_turn;
        let approval_profile = self.approval_profile.clone();
        let thinking_budget = self.thinking_budget;
        let audit_session_id = self.audit_session_id.clone();

        // Build tool descriptions and runtime context for the system prompt.
        let tool_descs = get_tool_descriptions(&self.skill_registry);
        let approval_ctx = approval_context_for_prompt(&approval_profile);
        let runtime_ctx =
            system_prompt::gather_runtime_context(self.client.as_ref(), &self.model);
        let sys_prompt = system_prompt::build_system_prompt(
            &tool_descs,
            Some(approval_ctx),
            PromptMode::Full,
            Some(&runtime_ctx),
        );

        // Get LLM tool definitions via the daemon.
        let tool_defs = get_tool_definitions_json(&self.skill_registry);

        let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");

        let (event_tx, event_rx) = mpsc::channel();
        let (approval_tx, approval_rx) = mpsc::channel();
        self.agent_rx = Some(event_rx);
        self.approval_tx = Some(approval_tx);

        // Reset abort flag for new request.
        self.abort_flag.store(false, Ordering::Relaxed);
        let abort_flag = self.abort_flag.clone();

        // Snapshot skill manifests + paths for the agent loop thread.
        let skill_manifests: Vec<_> = self
            .skill_registry
            .list()
            .iter()
            .map(|inst| {
                (
                    inst.manifest.name.clone(),
                    inst.manifest.clone(),
                    inst.path.clone(),
                )
            })
            .collect();

        std::thread::spawn(move || {
            // Clone tx for the panic guard -- if the closure panics, we still
            // send Error + Done so the UI thread doesn't hang on "Thinking...".
            let panic_tx = event_tx.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let params = AgentLoopParams {
                socket_path,
                conversation: conv,
                model,
                sys_prompt,
                tool_defs,
                auto_approve,
                approval_profile,
                thinking_budget,
                audit_session_id,
                abort_flag,
                skill_manifests,
            };
            // Orchestrator always uses the provider-backed agentic loop.
            // Coding work is delegated to subagents via the "task" tool.
            run_agent_loop(params, event_tx, approval_rx);
            })); // end catch_unwind closure
            if result.is_err() {
                let _ = panic_tx.send(AgentLoopEvent::Error(
                    "Internal error: agent loop panicked".to_string(),
                ));
                let _ = panic_tx.send(AgentLoopEvent::Done);
            }
        });
    }

    /// Handle an approval keypress (y/n/a) when waiting for tool approval.
    fn handle_approval_key(&mut self, approved: bool, approve_all: bool) {
        if approve_all {
            self.auto_approve_turn = true;
        }

        // Update the last permission message to show resolved state.
        if let Some(msg) = self.messages.last_mut() {
            if let MessageRole::Permission {
                ref prompt,
                ref diff_preview,
                ..
            } = msg.role
            {
                msg.role = MessageRole::Permission {
                    prompt: prompt.clone(),
                    resolved: Some(approved),
                    diff_preview: diff_preview.clone(),
                };
            }
        }

        // Send decision to the background thread.
        if let Some(ref tx) = self.approval_tx {
            let _ = tx.send(approved);
        }

        self.awaiting_approval = false;
        self.pending_tool_desc = None;
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        input::handle_key(self, key);
    }

    fn handle_mouse(&mut self, mouse: crossterm::event::MouseEvent) {
        input::handle_mouse(self, mouse);
    }

    fn rebuild_display_messages(&mut self) {
        input::rebuild_display_messages(self);
    }

    /// Handle key events when an overlay is active.
    fn handle_overlay_key(&mut self, key: KeyEvent) {
        overlay::handle_overlay_key(self, key);
    }


    /// Cycle a setting value (used by the Settings overlay).
    ///
    /// `index`: 0 = show_usage, 1 = thinking, 2 = approval.
    /// `reverse`: cycle backward instead of forward.
    fn cycle_setting(&mut self, index: usize, reverse: bool) {
        match index {
            0 => {
                // Toggle show_usage.
                self.show_usage = !self.show_usage;
            }
            1 => {
                // Cycle thinking: off -> low -> medium -> high -> off
                let levels: &[Option<u32>] = &[None, Some(1024), Some(4096), Some(16384)];
                let current = levels
                    .iter()
                    .position(|l| *l == self.thinking_budget)
                    .unwrap_or(0);
                let next = if reverse {
                    if current == 0 {
                        levels.len() - 1
                    } else {
                        current - 1
                    }
                } else {
                    (current + 1) % levels.len()
                };
                self.thinking_budget = levels[next];
            }
            2 => {
                // Cycle approval: Manual -> AutoEdits -> AutoHigh -> FullAuto
                let profiles = [
                    ApprovalProfile::Manual,
                    ApprovalProfile::AutoApprove(ActionRisk::Medium),
                    ApprovalProfile::AutoApprove(ActionRisk::High),
                    ApprovalProfile::FullAuto,
                ];
                let current = profiles
                    .iter()
                    .position(|p| *p == self.approval_profile)
                    .unwrap_or(0);
                let next = if reverse {
                    if current == 0 {
                        profiles.len() - 1
                    } else {
                        current - 1
                    }
                } else {
                    (current + 1) % profiles.len()
                };
                self.approval_profile = profiles[next].clone();
            }
            _ => {}
        }
    }

    /// Open the model picker overlay.
    fn open_model_picker(&mut self) {
        let mut items: Vec<(String, String)> = Vec::new();
        for provider in aegis_types::providers::ALL_PROVIDERS {
            for model in provider.models {
                items.push((
                    model.id.to_string(),
                    format!("{} ({})", model.display_name, provider.id),
                ));
            }
        }
        // Put the currently selected model at the top so it's visible.
        let current = self.model.clone();
        items.sort_by(|a, b| {
            let a_current = a.0 == current;
            let b_current = b.0 == current;
            b_current.cmp(&a_current)
        });
        self.overlay = Some(Overlay::ModelPicker {
            items,
            filter: String::new(),
            selected: 0,
        });
    }

    /// Open the session picker overlay.
    fn open_session_picker(&mut self) {
        match persistence::list_conversations() {
            Ok(items) if items.is_empty() => {
                self.set_result("No saved sessions.");
            }
            Ok(items) => {
                self.overlay = Some(Overlay::SessionPicker { items, selected: 0 });
            }
            Err(e) => {
                self.set_result(format!("Failed to list sessions: {e}"));
            }
        }
    }

    /// Open the settings overlay.
    fn open_settings(&mut self) {
        self.overlay = Some(Overlay::Settings { selected: 0 });
    }

    /// Open the login overlay for managing provider credentials.
    ///
    /// If `provider_arg` is given, jumps directly to the key input for that
    /// provider. Otherwise shows the provider list.
    fn open_login(&mut self, provider_arg: Option<&str>) {
        use aegis_types::credentials::CredentialStore;
        use aegis_types::providers::scan_providers;

        let store = CredentialStore::load_default().unwrap_or_default();
        let providers: Vec<LoginProviderEntry> = scan_providers()
            .into_iter()
            .map(|d| {
                let masked = store
                    .get(d.info.id)
                    .filter(|c| !c.api_key.is_empty())
                    .map(|c| CredentialStore::mask_key(&c.api_key));
                LoginProviderEntry {
                    id: d.info.id,
                    display_name: d.info.display_name,
                    status_label: d.status_label.clone(),
                    masked_key: masked,
                }
            })
            .collect();

        if let Some(arg) = provider_arg {
            let found = providers.iter().position(|p| p.id == arg);
            if let Some(idx) = found {
                let id = providers[idx].id;
                let display_name = providers[idx].display_name;
                self.overlay = Some(Overlay::Login {
                    providers,
                    selected: idx,
                    key_input: Some(LoginKeyInput {
                        provider_id: id,
                        display_name,
                        buffer: String::new(),
                        cursor: 0,
                        masked: true,
                        error: None,
                    }),
                });
            } else {
                self.set_result(format!(
                    "Unknown provider: {arg}. Use /login to see all."
                ));
            }
        } else {
            self.overlay = Some(Overlay::Login {
                providers,
                selected: 0,
                key_input: None,
            });
        }
    }

    /// Execute a command string.
    fn execute_command(&mut self, input: &str) {
        commands::execute_command(self, input);
    }

    /// Poll for completed dynamic skill executions.
    fn poll_skills(&mut self) {
        let result = self
            .skill_result_rx
            .as_ref()
            .and_then(|rx| rx.try_recv().ok());
        if let Some(skill_result) = result {
            match skill_result.output {
                Ok(output) => {
                    let text = format_skill_output(&skill_result.command_name, &output);
                    self.messages
                        .push(ChatMessage::new(MessageRole::System, text));
                }
                Err(e) => {
                    self.messages.push(ChatMessage::new(
                        MessageRole::System,
                        format!("Skill error: {e}"),
                    ));
                }
            }
            self.skill_result_rx = None;
            self.auto_scroll_to_bottom();
        }
    }

    /// Tick the active setup wizard overlay, if any.
    fn poll_setup_wizard(&mut self) {
        let done = if let Some(Overlay::Setup { ref mut wizard }) = self.overlay {
            wizard.tick();
            wizard.is_done()
        } else {
            false
        };
        if done {
            if let Some(Overlay::Setup { mut wizard }) = self.overlay.take() {
                let result = wizard.take_result();
                self.handle_setup_result(result);
            }
        }
    }

    /// Open a setup wizard overlay for the given target name.
    ///
    /// Tries channel wizards first, then skill wizards (for skills with
    /// `required_env` that need credentials configured).
    fn open_setup_wizard(&mut self, target: &str) {
        // Try channel wizard first.
        if let Some(wizard) = crate::setup_wizard::channel_wizard(target) {
            self.overlay = Some(Overlay::Setup { wizard });
            return;
        }

        // Try skill wizard (look up manifest for required_env).
        if let Some(instance) = self.skill_registry.get(target) {
            if !instance.manifest.required_env.is_empty() {
                if let Some(wizard) = crate::setup_wizard::skill_wizard(
                    target,
                    &instance.manifest.required_env,
                ) {
                    self.overlay = Some(Overlay::Setup { wizard });
                    return;
                }
            } else {
                self.set_result(format!(
                    "Skill '{target}' has no required environment variables to configure."
                ));
                return;
            }
        }

        let names = crate::setup_wizard::WIZARD_CHANNEL_NAMES.join(", ");
        self.set_result(format!(
            "No setup wizard for '{target}'. Available channels: {names}\n\
             For skills: /setup <skill-name>"
        ));
    }

    /// Handle the result of a completed setup wizard.
    fn handle_setup_result(&mut self, result: crate::setup_wizard::SetupResult) {
        match result {
            crate::setup_wizard::SetupResult::Channel(config) => {
                match crate::commands::telegram::write_channel_config_quiet(&config) {
                    Ok(msg) => self.set_result(msg),
                    Err(e) => self.set_result(format!("Setup failed: {e}")),
                }
            }
            crate::setup_wizard::SetupResult::SkillEnv { skill_name, vars } => {
                let count = vars.len();
                self.set_result(format!(
                    "Saved {count} environment variable(s) for '{skill_name}' \
                     to ~/.aegis/skill_env/{skill_name}.env"
                ));
            }
            crate::setup_wizard::SetupResult::Cancelled => {
                self.set_result("Setup cancelled.".to_string());
            }
        }
    }

    /// Show current model and available providers.
    fn show_model_info(&mut self) {
        let providers: Vec<String> = aegis_types::providers::scan_providers()
            .into_iter()
            .filter(|d| d.available)
            .map(|d| format!("{} {}", d.info.id, d.status_label))
            .collect();
        if providers.is_empty() {
            self.set_result(format!(
                "Model: {}  |  No providers configured. Set an API key env var.",
                self.model,
            ));
        } else {
            self.set_result(format!(
                "Model: {}  |  Available: {}",
                self.model,
                providers.join(", "),
            ));
        }
    }

    /// Handle pasted text (bracketed paste).
    pub fn handle_paste(&mut self, text: &str) {
        input::handle_paste(self, text);
    }
    /// Send a command to the daemon and show the response message.
    fn send_and_show_result(&mut self, cmd: DaemonCommand) {
        let Some(client) = &self.client else {
            self.last_error = Some("Not connected to daemon. Use /daemon start".into());
            return;
        };
        match client.send(&cmd) {
            Ok(resp) => {
                if resp.ok {
                    self.set_result(resp.message);
                } else {
                    self.last_error = Some(resp.message);
                }
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
            }
            Err(e) => {
                self.last_error = Some(e);
            }
        }
    }

    /// Set the command result message with a timestamp for auto-clear.
    fn set_result(&mut self, msg: impl Into<String>) {
        self.command_result = Some(msg.into());
        self.command_result_at = Some(Instant::now());
        self.last_error = None;
    }
}

/// Get tool descriptions for the system prompt.
///
/// Returns builtin tool descriptions plus dynamically generated `skill_*`
/// tool definitions for each installed skill's commands. The `skill_` prefix
/// makes routing trivial in the agent loop.
fn filter_model_items<'a>(
    items: &'a [(String, String)],
    filter: &str,
) -> Vec<&'a (String, String)> {
    if filter.is_empty() {
        return items.iter().collect();
    }
    let lower = filter.to_lowercase();
    items
        .iter()
        .filter(|(id, label)| {
            id.to_lowercase().contains(&lower) || label.to_lowercase().contains(&lower)
        })
        .collect()
}


/// Resolve user input to a valid model + provider pair.
///
/// Handles: provider names ("openai" -> default model), known model names,
/// prefix-matched models (e.g., "gpt-custom" -> openai), and unknown
/// strings (passed through).
fn resolve_model_input(input: &str) -> (String, Option<&'static str>) {
    let input = input.trim();

    // Case 1: provider name -> default model
    if let Some(provider) = aegis_types::providers::provider_by_id(input) {
        if !provider.default_model.is_empty() {
            return (provider.default_model.to_string(), Some(provider.id));
        }
    }

    // Case 2: exact model in a provider's catalog
    for provider in aegis_types::providers::ALL_PROVIDERS {
        for model in provider.models {
            if model.id == input {
                return (input.to_string(), Some(provider.id));
            }
        }
    }

    // Case 3: prefix match for custom/unlisted models
    let lower = input.to_lowercase();
    let provider_id = if lower.starts_with("claude-") {
        Some("anthropic")
    } else if lower == "gpt-5.3-codex" || lower.starts_with("gpt-5.3-codex-") {
        Some("openai-codex")
    } else if lower.starts_with("gpt-")
        || lower.starts_with("o1-")
        || lower.starts_with("o3-")
        || lower.starts_with("o4-")
    {
        Some("openai")
    } else if lower.starts_with("gemini-") {
        Some("google")
    } else {
        None
    };

    (input.to_string(), provider_id)
}

/// Detect the default model from daemon config or available providers.
fn detect_model() -> String {
    // 1. Check daemon.toml for default_model.
    let config_path = aegis_types::daemon::daemon_config_path();
    if let Ok(config_str) = std::fs::read_to_string(config_path) {
        if let Ok(config) = aegis_types::daemon::DaemonConfig::from_toml(&config_str) {
            if let Some(model) = config.default_model {
                return model;
            }
        }
    }

    // 2. Check credential store for the user's stored model selection.
    let store = aegis_types::credentials::CredentialStore::load_default().unwrap_or_default();
    for detected in aegis_types::providers::scan_providers() {
        if detected.available {
            if let Some(cred) = store.get(detected.info.id) {
                if let Some(ref model) = cred.model {
                    return model.clone();
                }
            }
        }
    }

    // 3. Scan providers and pick the first available with a default model.
    for detected in aegis_types::providers::scan_providers() {
        if detected.available && !detected.info.default_model.is_empty() {
            return detected.info.default_model.to_string();
        }
    }

    // 4. Fallback.
    "claude-sonnet-4-6".to_string()
}

/// Run the chat TUI, connecting to the daemon at the default socket path.
pub fn run_chat_tui(auto_mode: Option<&str>) -> Result<()> {
    let client = DaemonClient::default_path();
    run_chat_tui_with_options(client, auto_mode)
}

/// Run the chat TUI with a specific client and optional auto-approval mode.
pub fn run_chat_tui_with_options(client: DaemonClient, auto_mode: Option<&str>) -> Result<()> {
    let model = detect_model();

    // Install panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stderr(), crossterm::cursor::Show);
        let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\x1b[r");
        original_hook(info);
    }));

    // Set up terminal (inline viewport -- no alternate screen)
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    std::io::Write::write_all(
        &mut stdout,
        b"\x1b[r\x1b[0m\x1b[H\x1b[2J\x1b[3J\x1b[H",
    )?;
    std::io::Write::flush(&mut stdout)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = custom_terminal::CustomTerminal::with_options(backend)?;
    let size = terminal.size()?;
    terminal.set_viewport_area(ratatui::layout::Rect::new(0, 0, size.width, size.height));

    // Seed workspace with template files; detect first run.
    let is_first_run = seed_workspace();

    // Auto-start daemon if config exists and daemon isn't running.
    // The daemon must be running for LLM requests, Telegram, and agents.
    if !client.is_running() && aegis_types::daemon::daemon_config_path().exists() {
        let _ = crate::commands::daemon::start_quiet();
    }

    let events = EventHandler::new(TICK_RATE_MS);
    let mut app = ChatApp::new(Some(client), model);
    app.bootstrap_pending = is_first_run;
    if aegis_types::providers::scan_providers()
        .into_iter()
        .all(|p| !p.available)
    {
        app.messages.push(ChatMessage::new(
            MessageRole::System,
            "No LLM provider is configured yet. Use /provider to see detected options, then run `aegis auth add <provider> --method oauth` or set that provider API key env var. Local backends such as Ollama are auto-detected when running.".to_string(),
        ));
    }

    // Apply --auto CLI flag if provided.
    if let Some(mode) = auto_mode {
        app.approval_profile = parse_approval_mode(mode);
    }

    // Fire SessionStart hook.
    hooks::fire_hook_event(hooks::ChatHookEvent::SessionStart {
        session_id: app.session_id.clone(),
    });

    let result = run_event_loop(&mut terminal, &events, &mut app);

    // NOTE: Do NOT shut down the daemon here. The daemon must outlive the TUI
    // so Telegram, agents, and background services keep running. Zombie
    // prevention is handled by kill_stale_daemon() on daemon startup.

    // Restore terminal
    crossterm::terminal::disable_raw_mode()?;
    terminal.show_cursor()?;
    terminal.clear()?;
    let vp = terminal.viewport_area;
    let _ = crossterm::execute!(
        terminal.backend_mut(),
        crossterm::cursor::MoveTo(0, vp.bottom()),
    );

    result
}

/// Internal event loop.
fn run_event_loop(
    terminal: &mut custom_terminal::CustomTerminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    events: &EventHandler,
    app: &mut ChatApp,
) -> Result<()> {
    while app.running {
        terminal.draw(|f| ui::draw(f, app))?;

        // Drain all pending events before the next render to prevent
        // scroll lag from queued mouse events.
        let mut had_tick = false;
        events.drain(|evt| {
            match evt {
                AppEvent::Key(key) => app.handle_key(key),
                AppEvent::Paste(text) => app.handle_paste(&text),
                AppEvent::Mouse(mouse) => app.handle_mouse(mouse),
                AppEvent::Tick => had_tick = true,
            }
        })?;
        if had_tick && app.is_heartbeat_due() {
            app.trigger_heartbeat();
        }

        app.poll_daemon();
    }
    Ok(())
}

#[cfg(test)]
mod tests;

