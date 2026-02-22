//! Chat-centric TUI for Aegis.
//!
//! Provides a conversational interface that calls LLM APIs directly via
//! `DaemonCommand::LlmComplete`, with a minimal command bar for system
//! commands. This is the default interface when `aegis` is invoked.

pub mod event;
pub mod markdown;
pub mod message;
pub mod render;
pub mod system_prompt;
mod ui;

use std::sync::mpsc;
use std::time::Instant;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_control::daemon::{DaemonClient, DaemonCommand, DaemonResponse};
use aegis_types::llm::{LlmMessage, LlmResponse, LlmToolCall, StopReason};

use self::event::{AppEvent, EventHandler};
use self::message::{ChatMessage, MessageRole};
use self::system_prompt::ToolDescription;
use crate::tui_utils::delete_word_backward_pos;

/// How often to poll crossterm for events (milliseconds).
const TICK_RATE_MS: u64 = 200;

/// How often to re-check daemon connectivity (milliseconds).
const POLL_INTERVAL_MS: u128 = 2000;

/// Timeout for LLM completion requests (seconds).
/// LLM responses can take a while, so this is much longer than the default
/// 5-second DaemonClient timeout.
const LLM_TIMEOUT_SECS: u64 = 120;

/// The current input mode in the chat TUI.
#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    /// Default: cursor in input box, typing sends to LLM.
    Chat,
    /// Escape when input empty: navigate message history.
    Scroll,
    /// `:` when input empty: command bar.
    Command,
}

/// Incremental events from the agentic loop running in a background thread.
enum AgentLoopEvent {
    /// LLM returned a text response (final -- loop ended).
    Response(LlmResponse),
    /// LLM wants to call tools -- display them to the user.
    ToolCalls(Vec<LlmToolCall>),
    /// A tool finished executing -- display the result.
    ToolResult {
        tool_call_id: String,
        tool_name: String,
        result: String,
    },
    /// LLM needs approval for a tool before executing it.
    ToolApprovalNeeded {
        tool_call: LlmToolCall,
    },
    /// An error occurred in the loop.
    Error(String),
    /// The agentic loop finished (all tool calls done, final response received).
    Done,
}

/// Tools that are auto-approved (read-only, safe operations).
const SAFE_TOOLS: &[&str] = &["read_file", "glob_search", "grep_search"];

/// Check whether a tool should be auto-approved.
fn is_safe_tool(name: &str) -> bool {
    SAFE_TOOLS.contains(&name)
}

/// Top-level application state for the chat TUI.
pub struct ChatApp {
    /// Whether the main loop should keep running.
    pub running: bool,
    /// Current input mode.
    pub input_mode: InputMode,

    // -- Chat --
    /// Display messages for the chat area.
    pub messages: Vec<ChatMessage>,
    /// Scroll offset into the message history (0 = bottom).
    pub scroll_offset: usize,

    // -- LLM conversation --
    /// Full LLM conversation history (sent with each request).
    pub conversation: Vec<LlmMessage>,
    /// Model identifier (from daemon config or environment detection).
    pub model: String,
    /// Whether we're waiting for an LLM response or tool execution.
    pub awaiting_response: bool,
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

    // -- Input --
    /// Text buffer for chat input.
    pub input_buffer: String,
    /// Cursor position in the input buffer.
    pub input_cursor: usize,
    /// History of sent inputs.
    pub input_history: Vec<String>,
    /// Current position in input history (None = composing new).
    pub history_index: Option<usize>,

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
}

/// Commands recognized by the minimal command bar.
const COMMANDS: &[&str] = &[
    "quit", "q", "clear", "model", "help",
    "daemon start", "daemon stop", "daemon status",
    "daemon restart", "daemon reload", "daemon init",
];

impl ChatApp {
    /// Create a new chat TUI application.
    pub fn new(client: Option<DaemonClient>, model: String) -> Self {
        Self {
            running: true,
            input_mode: InputMode::Chat,

            messages: Vec::new(),
            scroll_offset: 0,

            conversation: Vec::new(),
            model,
            awaiting_response: false,
            agent_rx: None,
            approval_tx: None,
            awaiting_approval: false,
            pending_tool_desc: None,
            auto_approve_turn: false,

            input_buffer: String::new(),
            input_cursor: 0,
            input_history: Vec::new(),
            history_index: None,

            command_buffer: String::new(),
            command_cursor: 0,
            command_history: Vec::new(),
            command_history_index: None,
            command_completions: Vec::new(),
            completion_idx: None,
            command_result: None,
            command_result_at: None,

            connected: false,
            last_error: None,

            client,
            // Force immediate first poll.
            last_poll: Instant::now() - std::time::Duration::from_secs(10),
        }
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

        // Ping
        match client.send(&DaemonCommand::Ping) {
            Ok(resp) if resp.ok => {
                self.connected = true;
                self.last_error = None;
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

    /// Check for events from the agentic loop running in a background thread.
    fn poll_llm(&mut self) {
        // Drain all available events from the channel.
        loop {
            let event = self.agent_rx.as_ref().and_then(|rx| rx.try_recv().ok());

            let Some(event) = event else {
                break;
            };

            match event {
                AgentLoopEvent::Response(resp) => {
                    // Build assistant message with tool calls if present.
                    let mut assistant_msg = LlmMessage::assistant(resp.content.clone());
                    assistant_msg.tool_calls = resp.tool_calls.clone();
                    self.conversation.push(assistant_msg);

                    if !resp.content.is_empty() {
                        self.messages.push(ChatMessage::new(
                            MessageRole::Assistant,
                            resp.content,
                        ));
                    }
                    self.scroll_offset = 0;
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
                    self.scroll_offset = 0;
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
                    self.scroll_offset = 0;
                }
                AgentLoopEvent::ToolApprovalNeeded { tool_call, .. } => {
                    let desc = format!(
                        "{}: {}",
                        tool_call.name,
                        summarize_tool_input(&tool_call.name, &tool_call.input)
                    );
                    self.messages.push(ChatMessage::new(
                        MessageRole::Permission {
                            prompt: desc.clone(),
                            resolved: None,
                        },
                        format!("Allow {}? [y]es / [n]o / [a]ll", tool_call.name),
                    ));
                    self.pending_tool_desc = Some(desc);
                    self.awaiting_approval = true;
                    self.scroll_offset = 0;
                }
                AgentLoopEvent::Error(msg) => {
                    self.messages.push(ChatMessage::new(
                        MessageRole::System,
                        format!("Error: {msg}"),
                    ));
                    self.awaiting_response = false;
                    self.auto_approve_turn = false;
                }
                AgentLoopEvent::Done => {
                    self.awaiting_response = false;
                    self.auto_approve_turn = false;
                }
            }
        }
    }

    /// Send the current conversation to the LLM and run the agentic loop.
    ///
    /// The loop runs in a background thread. It sends the conversation + tool
    /// definitions to the LLM, and if the LLM returns `StopReason::ToolUse`,
    /// it executes each tool and loops. Tool approvals are handled via a
    /// separate mpsc channel that the UI thread sends decisions through.
    fn send_llm_request(&mut self) {
        let conv = self.conversation.clone();
        let model = self.model.clone();
        let auto_approve = self.auto_approve_turn;

        // Build tool descriptions for the system prompt.
        let tool_descs = get_tool_descriptions();
        let sys_prompt = system_prompt::build_system_prompt(&tool_descs);

        // Get LLM tool definitions via the daemon.
        let tool_defs = get_tool_definitions_json();

        let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");

        let (event_tx, event_rx) = mpsc::channel();
        let (approval_tx, approval_rx) = mpsc::channel();
        self.agent_rx = Some(event_rx);
        self.approval_tx = Some(approval_tx);

        std::thread::spawn(move || {
            run_agent_loop(
                AgentLoopParams {
                    socket_path,
                    conversation: conv,
                    model,
                    sys_prompt,
                    tool_defs,
                    auto_approve,
                },
                event_tx,
                approval_rx,
            );
        });
    }

    /// Handle an approval keypress (y/n/a) when waiting for tool approval.
    fn handle_approval_key(&mut self, approved: bool, approve_all: bool) {
        if approve_all {
            self.auto_approve_turn = true;
        }

        // Update the last permission message to show resolved state.
        if let Some(msg) = self.messages.last_mut() {
            if let MessageRole::Permission { ref prompt, .. } = msg.role {
                msg.role = MessageRole::Permission {
                    prompt: prompt.clone(),
                    resolved: Some(approved),
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
        // Only handle key press events (not release/repeat).
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Ctrl+C: cancel or quit
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            match self.input_mode {
                InputMode::Command => {
                    self.input_mode = InputMode::Chat;
                    self.command_buffer.clear();
                    self.command_cursor = 0;
                    self.command_completions.clear();
                    self.completion_idx = None;
                }
                InputMode::Chat if !self.input_buffer.is_empty() => {
                    self.input_buffer.clear();
                    self.input_cursor = 0;
                }
                InputMode::Scroll => {
                    self.input_mode = InputMode::Chat;
                }
                _ => {
                    self.running = false;
                }
            }
            return;
        }

        self.clear_stale_result();

        match self.input_mode {
            InputMode::Chat => self.handle_chat_key(key),
            InputMode::Scroll => self.handle_scroll_key(key),
            InputMode::Command => self.handle_command_key(key),
        }
    }

    /// Handle keys in Chat mode (default, input focused).
    fn handle_chat_key(&mut self, key: KeyEvent) {
        // Handle approval keys when waiting for tool approval.
        if self.awaiting_approval {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.handle_approval_key(true, false);
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    self.handle_approval_key(true, true);
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.handle_approval_key(false, false);
                }
                _ => {} // Ignore other keys during approval
            }
            return;
        }

        match key.code {
            KeyCode::Enter => {
                if self.awaiting_response {
                    return; // Don't stack requests
                }
                if !self.input_buffer.is_empty() {
                    let text = self.input_buffer.clone();

                    // Add to conversation and display
                    self.conversation.push(LlmMessage::user(text.clone()));
                    self.messages
                        .push(ChatMessage::new(MessageRole::User, text.clone()));
                    self.scroll_offset = 0;

                    // Send to LLM
                    self.awaiting_response = true;
                    self.send_llm_request();

                    // Update input state
                    self.input_history.push(text);
                    self.history_index = None;
                    self.input_buffer.clear();
                    self.input_cursor = 0;
                }
            }
            KeyCode::Up if self.input_buffer.is_empty() => {
                // Browse input history backward
                if !self.input_history.is_empty() {
                    let idx = match self.history_index {
                        Some(0) => 0,
                        Some(i) => i - 1,
                        None => self.input_history.len() - 1,
                    };
                    self.history_index = Some(idx);
                    self.input_buffer = self.input_history[idx].clone();
                    self.input_cursor = self.input_buffer.len();
                }
            }
            KeyCode::Down if self.input_buffer.is_empty() => {
                // Browse input history forward
                match self.history_index {
                    Some(i) if i + 1 < self.input_history.len() => {
                        self.history_index = Some(i + 1);
                        self.input_buffer = self.input_history[i + 1].clone();
                        self.input_cursor = self.input_buffer.len();
                    }
                    Some(_) => {
                        self.history_index = None;
                        self.input_buffer.clear();
                        self.input_cursor = 0;
                    }
                    None => {}
                }
            }
            KeyCode::Char(':') if self.input_buffer.is_empty() => {
                self.enter_command_mode();
            }
            KeyCode::Esc if self.input_buffer.is_empty() => {
                self.input_mode = InputMode::Scroll;
            }
            // Text editing
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => match c {
                'a' => self.input_cursor = 0,
                'e' => self.input_cursor = self.input_buffer.len(),
                'u' => {
                    self.input_buffer.drain(..self.input_cursor);
                    self.input_cursor = 0;
                }
                'w' => {
                    if self.input_cursor > 0 {
                        let new_pos =
                            delete_word_backward_pos(&self.input_buffer, self.input_cursor);
                        self.input_buffer.drain(new_pos..self.input_cursor);
                        self.input_cursor = new_pos;
                    }
                }
                _ => {}
            },
            KeyCode::Char(c) => {
                self.input_buffer.insert(self.input_cursor, c);
                self.input_cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if self.input_cursor > 0 {
                    let prev = self.input_buffer[..self.input_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.input_buffer.remove(prev);
                    self.input_cursor = prev;
                }
            }
            KeyCode::Left => {
                if self.input_cursor > 0 {
                    self.input_cursor = self.input_buffer[..self.input_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if self.input_cursor < self.input_buffer.len() {
                    self.input_cursor = self.input_buffer[self.input_cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| self.input_cursor + i)
                        .unwrap_or(self.input_buffer.len());
                }
            }
            KeyCode::Delete => {
                if self.input_cursor < self.input_buffer.len() {
                    self.input_buffer.remove(self.input_cursor);
                }
            }
            KeyCode::Home => {
                self.input_cursor = 0;
            }
            KeyCode::End => {
                self.input_cursor = self.input_buffer.len();
            }
            _ => {}
        }
    }

    /// Handle keys in Scroll mode (message history navigation).
    fn handle_scroll_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                let max = self.messages.len().saturating_sub(1);
                self.scroll_offset = (self.scroll_offset + 1).min(max);
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.scroll_offset = self.messages.len().saturating_sub(1);
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.scroll_offset = 0;
            }
            KeyCode::PageUp => {
                let max = self.messages.len().saturating_sub(1);
                self.scroll_offset = (self.scroll_offset + 20).min(max);
            }
            KeyCode::PageDown => {
                self.scroll_offset = self.scroll_offset.saturating_sub(20);
            }
            KeyCode::Esc => {
                self.input_mode = InputMode::Chat;
            }
            KeyCode::Char(':') => {
                self.enter_command_mode();
            }
            KeyCode::Char(c) => {
                // Any printable char goes back to Chat mode and inserts it
                self.input_mode = InputMode::Chat;
                self.input_buffer.insert(self.input_cursor, c);
                self.input_cursor += c.len_utf8();
            }
            _ => {}
        }
    }

    /// Enter command mode.
    fn enter_command_mode(&mut self) {
        self.input_mode = InputMode::Command;
        self.command_buffer.clear();
        self.command_cursor = 0;
        self.command_completions.clear();
        self.completion_idx = None;
        self.command_result = None;
        self.command_result_at = None;
        self.command_history_index = None;
    }

    /// Handle keys in Command mode (: bar).
    fn handle_command_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Chat;
                self.command_buffer.clear();
                self.command_cursor = 0;
                self.command_completions.clear();
                self.completion_idx = None;
            }
            KeyCode::Enter => {
                let buffer = self.command_buffer.clone();
                if !buffer.is_empty() {
                    self.command_history.push(buffer.clone());
                    self.execute_command(&buffer);
                }
                self.input_mode = InputMode::Chat;
                self.command_buffer.clear();
                self.command_cursor = 0;
                self.command_completions.clear();
                self.completion_idx = None;
            }
            KeyCode::Tab => {
                self.cycle_completion();
            }
            KeyCode::BackTab => {
                self.cycle_completion_back();
            }
            KeyCode::Up => {
                self.command_history_prev();
            }
            KeyCode::Down => {
                self.command_history_next();
            }
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => match c {
                'a' => self.command_cursor = 0,
                'e' => self.command_cursor = self.command_buffer.len(),
                'u' => {
                    self.command_buffer.drain(..self.command_cursor);
                    self.command_cursor = 0;
                    self.update_completions();
                }
                'w' => {
                    if self.command_cursor > 0 {
                        let new_pos =
                            delete_word_backward_pos(&self.command_buffer, self.command_cursor);
                        self.command_buffer.drain(new_pos..self.command_cursor);
                        self.command_cursor = new_pos;
                        self.update_completions();
                    }
                }
                _ => {}
            },
            KeyCode::Char(c) => {
                self.command_buffer.insert(self.command_cursor, c);
                self.command_cursor += c.len_utf8();
                self.update_completions();
            }
            KeyCode::Backspace => {
                if self.command_cursor > 0 {
                    let prev = self.command_buffer[..self.command_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.command_buffer.remove(prev);
                    self.command_cursor = prev;
                    self.update_completions();
                }
            }
            KeyCode::Left => {
                if self.command_cursor > 0 {
                    self.command_cursor = self.command_buffer[..self.command_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if self.command_cursor < self.command_buffer.len() {
                    self.command_cursor = self.command_buffer[self.command_cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| self.command_cursor + i)
                        .unwrap_or(self.command_buffer.len());
                }
            }
            KeyCode::Delete => {
                if self.command_cursor < self.command_buffer.len() {
                    self.command_buffer.remove(self.command_cursor);
                    self.update_completions();
                }
            }
            KeyCode::Home => {
                self.command_cursor = 0;
            }
            KeyCode::End => {
                self.command_cursor = self.command_buffer.len();
            }
            _ => {}
        }
    }

    /// Update tab completions based on current buffer.
    fn update_completions(&mut self) {
        self.command_completions = local_completions(&self.command_buffer);
        self.completion_idx = None;
    }

    /// Cycle to the next completion.
    fn cycle_completion(&mut self) {
        if self.command_completions.is_empty() {
            self.update_completions();
            if self.command_completions.is_empty() {
                return;
            }
        }
        let idx = match self.completion_idx {
            Some(i) => (i + 1) % self.command_completions.len(),
            None => 0,
        };
        self.completion_idx = Some(idx);
        let completion = self.command_completions[idx].clone();
        self.command_buffer = apply_completion(&self.command_buffer, &completion);
        self.command_cursor = self.command_buffer.len();
    }

    /// Cycle to the previous completion.
    fn cycle_completion_back(&mut self) {
        if self.command_completions.is_empty() {
            self.update_completions();
            if self.command_completions.is_empty() {
                return;
            }
        }
        let idx = match self.completion_idx {
            Some(0) | None => self.command_completions.len() - 1,
            Some(i) => i - 1,
        };
        self.completion_idx = Some(idx);
        let completion = self.command_completions[idx].clone();
        self.command_buffer = apply_completion(&self.command_buffer, &completion);
        self.command_cursor = self.command_buffer.len();
    }

    /// Navigate to previous command in history.
    fn command_history_prev(&mut self) {
        if self.command_history.is_empty() {
            return;
        }
        let idx = match self.command_history_index {
            Some(0) => 0,
            Some(i) => i - 1,
            None => self.command_history.len() - 1,
        };
        self.command_history_index = Some(idx);
        self.command_buffer = self.command_history[idx].clone();
        self.command_cursor = self.command_buffer.len();
    }

    /// Navigate to next command in history.
    fn command_history_next(&mut self) {
        match self.command_history_index {
            Some(i) if i + 1 < self.command_history.len() => {
                self.command_history_index = Some(i + 1);
                self.command_buffer = self.command_history[i + 1].clone();
                self.command_cursor = self.command_buffer.len();
            }
            Some(_) => {
                self.command_history_index = None;
                self.command_buffer.clear();
                self.command_cursor = 0;
            }
            None => {}
        }
    }

    /// Execute a command string.
    fn execute_command(&mut self, input: &str) {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return;
        }

        match trimmed {
            "quit" | "q" => {
                self.running = false;
            }
            "clear" => {
                self.messages.clear();
                self.conversation.clear();
                self.scroll_offset = 0;
                self.set_result("Conversation cleared");
            }
            "help" | "h" => {
                self.set_result(
                    ":quit  :clear  :model <name>  :daemon start|stop|status|restart|reload|init",
                );
            }
            _ if trimmed.starts_with("model ") => {
                let new_model = trimmed.strip_prefix("model ").unwrap().trim();
                if new_model.is_empty() {
                    self.set_result(format!("Current model: {}", self.model));
                } else {
                    self.model = new_model.to_string();
                    self.set_result(format!("Model set to: {}", self.model));
                }
            }
            "model" => {
                self.set_result(format!("Current model: {}", self.model));
            }
            "daemon start" => match crate::commands::daemon::start_quiet() {
                Ok(msg) => {
                    self.set_result(msg);
                    self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                }
                Err(e) => {
                    self.last_error = Some(format!("Failed to start daemon: {e}"));
                }
            },
            "daemon stop" => {
                if !self.connected {
                    self.set_result("Daemon is not running.");
                } else {
                    match crate::commands::daemon::stop_quiet() {
                        Ok(msg) => {
                            self.set_result(msg);
                            self.last_poll =
                                Instant::now() - std::time::Duration::from_secs(10);
                        }
                        Err(e) => {
                            self.last_error = Some(format!("Failed to stop daemon: {e}"));
                        }
                    }
                }
            }
            "daemon status" => {
                if !self.connected {
                    self.set_result("Daemon is not running (offline mode).");
                } else {
                    self.set_result(format!("Daemon is running. Model: {}", self.model));
                }
            }
            "daemon restart" => {
                if !self.connected {
                    self.set_result("Daemon is not running. Use :daemon start.");
                } else {
                    match crate::commands::daemon::restart_quiet() {
                        Ok(msg) => {
                            self.set_result(msg);
                            self.last_poll =
                                Instant::now() - std::time::Duration::from_secs(10);
                        }
                        Err(e) => {
                            self.last_error = Some(format!("Failed to restart daemon: {e}"));
                        }
                    }
                }
            }
            "daemon reload" => {
                if !self.connected {
                    self.set_result("Daemon is not running.");
                } else {
                    self.send_and_show_result(DaemonCommand::ReloadConfig);
                }
            }
            "daemon init" => match crate::commands::daemon::init_quiet() {
                Ok(msg) => self.set_result(msg),
                Err(e) => {
                    self.last_error = Some(format!("{e}"));
                }
            },
            other => {
                self.set_result(format!("Unknown command: '{other}'. Type :help for commands."));
            }
        }
    }

    /// Handle pasted text (bracketed paste).
    pub fn handle_paste(&mut self, text: &str) {
        match self.input_mode {
            InputMode::Command => {
                let cleaned = text.replace(['\n', '\r'], " ");
                self.command_buffer
                    .insert_str(self.command_cursor, &cleaned);
                self.command_cursor += cleaned.len();
                self.update_completions();
            }
            InputMode::Chat => {
                let cleaned = text.replace(['\n', '\r'], " ");
                self.input_buffer.insert_str(self.input_cursor, &cleaned);
                self.input_cursor += cleaned.len();
            }
            InputMode::Scroll => {
                // Switch to chat mode and paste
                self.input_mode = InputMode::Chat;
                let cleaned = text.replace(['\n', '\r'], " ");
                self.input_buffer.insert_str(self.input_cursor, &cleaned);
                self.input_cursor += cleaned.len();
            }
        }
    }

    /// Send a command to the daemon and show the response message.
    fn send_and_show_result(&mut self, cmd: DaemonCommand) {
        let Some(client) = &self.client else {
            self.last_error = Some("Not connected to daemon. Use :daemon start".into());
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
/// Queries the daemon for registered tools. Falls back to hardcoded
/// descriptions if the daemon is not available.
fn get_tool_descriptions() -> Vec<ToolDescription> {
    vec![
        ToolDescription {
            name: "bash".into(),
            description: "Execute a shell command and return stdout/stderr".into(),
        },
        ToolDescription {
            name: "read_file".into(),
            description: "Read file contents from disk (max 500KB)".into(),
        },
        ToolDescription {
            name: "write_file".into(),
            description: "Write content to a file, creating parent directories if needed".into(),
        },
        ToolDescription {
            name: "edit_file".into(),
            description: "Replace the first occurrence of old_string with new_string in a file"
                .into(),
        },
        ToolDescription {
            name: "glob_search".into(),
            description: "Find files matching a glob pattern".into(),
        },
        ToolDescription {
            name: "grep_search".into(),
            description: "Search file contents for a regex pattern".into(),
        },
    ]
}

/// Get tool definitions as JSON for the LLM request.
///
/// Returns the serialized tool definitions that will be passed to
/// `DaemonCommand::LlmComplete { tools }`.
fn get_tool_definitions_json() -> Option<serde_json::Value> {
    use aegis_types::llm::LlmToolDefinition;

    let defs: Vec<LlmToolDefinition> = get_tool_descriptions()
        .into_iter()
        .map(|td| {
            let schema = match td.name.as_str() {
                "bash" => serde_json::json!({
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The shell command to execute"
                        }
                    },
                    "required": ["command"]
                }),
                "read_file" => serde_json::json!({
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to the file to read"
                        }
                    },
                    "required": ["file_path"]
                }),
                "write_file" => serde_json::json!({
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to the file to write"
                        },
                        "content": {
                            "type": "string",
                            "description": "Content to write to the file"
                        }
                    },
                    "required": ["file_path", "content"]
                }),
                "edit_file" => serde_json::json!({
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to the file to edit"
                        },
                        "old_string": {
                            "type": "string",
                            "description": "The exact string to find and replace"
                        },
                        "new_string": {
                            "type": "string",
                            "description": "The replacement string"
                        }
                    },
                    "required": ["file_path", "old_string", "new_string"]
                }),
                "glob_search" => serde_json::json!({
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Glob pattern to match files (e.g., \"**/*.rs\")"
                        },
                        "path": {
                            "type": "string",
                            "description": "Base directory to search in (defaults to current directory)"
                        }
                    },
                    "required": ["pattern"]
                }),
                "grep_search" => serde_json::json!({
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Regular expression pattern to search for"
                        },
                        "path": {
                            "type": "string",
                            "description": "Directory or file to search in (defaults to current directory)"
                        },
                        "include": {
                            "type": "string",
                            "description": "Glob pattern to filter files (e.g., \"*.rs\")"
                        }
                    },
                    "required": ["pattern"]
                }),
                _ => serde_json::json!({"type": "object", "properties": {}}),
            };
            LlmToolDefinition {
                name: td.name,
                description: td.description,
                input_schema: schema,
            }
        })
        .collect();

    serde_json::to_value(&defs).ok()
}

/// Create a short summary of a tool call's input for display.
fn summarize_tool_input(name: &str, input: &serde_json::Value) -> String {
    match name {
        "bash" => input
            .get("command")
            .and_then(|v| v.as_str())
            .map(|s| {
                if s.len() > 80 {
                    format!("{}...", &s[..80])
                } else {
                    s.to_string()
                }
            })
            .unwrap_or_default(),
        "read_file" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "write_file" => {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let len = input
                .get("content")
                .and_then(|v| v.as_str())
                .map(|s| s.len())
                .unwrap_or(0);
            format!("{path} ({len} bytes)")
        }
        "edit_file" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "glob_search" => input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "grep_search" => input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        _ => serde_json::to_string(input)
            .unwrap_or_default()
            .chars()
            .take(100)
            .collect(),
    }
}

/// Format a tool call's full content for display in the chat.
fn format_tool_call_content(name: &str, input: &serde_json::Value) -> String {
    match name {
        "bash" => input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "read_file" | "edit_file" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => serde_json::to_string_pretty(input).unwrap_or_default(),
    }
}

/// Parameters for `run_agent_loop`, grouped to stay under clippy's argument limit.
struct AgentLoopParams {
    socket_path: std::path::PathBuf,
    conversation: Vec<LlmMessage>,
    model: String,
    sys_prompt: String,
    tool_defs: Option<serde_json::Value>,
    auto_approve: bool,
}

/// Run the agentic loop in a background thread.
///
/// Sends the conversation + tools to the LLM, and if the LLM returns tool
/// calls, executes them and loops. Safe tools are auto-approved; dangerous
/// tools require user approval via the `approval_rx` channel.
fn run_agent_loop(
    params: AgentLoopParams,
    event_tx: mpsc::Sender<AgentLoopEvent>,
    approval_rx: mpsc::Receiver<bool>,
) {
    let client = DaemonClient::new(params.socket_path.clone());
    let auto_approve_all = params.auto_approve;
    let mut conversation = params.conversation;

    // Maximum iterations to prevent infinite loops.
    const MAX_ITERATIONS: usize = 50;

    for _iteration in 0..MAX_ITERATIONS {
        // Serialize conversation.
        let messages = match serde_json::to_value(&conversation) {
            Ok(v) => v,
            Err(e) => {
                let _ = event_tx.send(AgentLoopEvent::Error(format!(
                    "failed to serialize conversation: {e}"
                )));
                let _ = event_tx.send(AgentLoopEvent::Done);
                return;
            }
        };

        let cmd = DaemonCommand::LlmComplete {
            model: params.model.clone(),
            messages,
            temperature: None,
            max_tokens: None,
            system_prompt: Some(params.sys_prompt.clone()),
            tools: params.tool_defs.clone(),
        };

        // Send LLM request with long timeout.
        let result = send_with_timeout(&client, &cmd, LLM_TIMEOUT_SECS);

        let resp = match parse_llm_response(result) {
            Ok(r) => r,
            Err(e) => {
                let _ = event_tx.send(AgentLoopEvent::Error(e));
                let _ = event_tx.send(AgentLoopEvent::Done);
                return;
            }
        };

        // Check if the LLM wants to call tools.
        let wants_tools = resp.stop_reason == Some(StopReason::ToolUse) && !resp.tool_calls.is_empty();

        if !wants_tools {
            // Final response -- send it and finish.
            let _ = event_tx.send(AgentLoopEvent::Response(resp));
            let _ = event_tx.send(AgentLoopEvent::Done);
            return;
        }

        // LLM wants to call tools. Send the response first (may contain text).
        let _ = event_tx.send(AgentLoopEvent::Response(resp.clone()));

        // Display all tool calls.
        let _ = event_tx.send(AgentLoopEvent::ToolCalls(resp.tool_calls.clone()));

        // Execute each tool call.
        for tc in &resp.tool_calls {
            let tool_result = if is_safe_tool(&tc.name) || auto_approve_all {
                // Auto-approved -- execute directly.
                execute_tool_via_daemon(&params.socket_path, &tc.name, &tc.input)
            } else {
                // Need user approval.
                let _ = event_tx.send(AgentLoopEvent::ToolApprovalNeeded {
                    tool_call: tc.clone(),
                });

                // Wait for approval decision (blocks this thread).
                match approval_rx.recv() {
                    Ok(true) => execute_tool_via_daemon(&params.socket_path, &tc.name, &tc.input),
                    Ok(false) => {
                        // Tool denied by user.
                        Ok("Tool execution denied by user.".to_string())
                    }
                    Err(_) => {
                        // Channel closed -- UI exited.
                        let _ = event_tx.send(AgentLoopEvent::Done);
                        return;
                    }
                }
            };

            let result_text = match tool_result {
                Ok(text) => text,
                Err(e) => format!("Error executing {}: {e}", tc.name),
            };

            // Send result event for UI display.
            let _ = event_tx.send(AgentLoopEvent::ToolResult {
                tool_call_id: tc.id.clone(),
                tool_name: tc.name.clone(),
                result: result_text.clone(),
            });

            // Add tool result to conversation for next LLM call.
            conversation.push(LlmMessage::tool_result(&tc.id, result_text));
        }

        // Loop back to send the updated conversation to the LLM.
    }

    // If we reach here, we hit the max iteration limit.
    let _ = event_tx.send(AgentLoopEvent::Error(
        "Agentic loop exceeded maximum iterations (50). Stopping.".into(),
    ));
    let _ = event_tx.send(AgentLoopEvent::Done);
}

/// Parse an LLM response from a daemon response.
fn parse_llm_response(
    result: Result<DaemonResponse, String>,
) -> Result<LlmResponse, String> {
    match result {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                serde_json::from_value::<LlmResponse>(data)
                    .map_err(|e| format!("failed to parse LLM response: {e}"))
            } else {
                Err("daemon returned ok but no response data".into())
            }
        }
        Ok(resp) => Err(resp.message),
        Err(e) => Err(e),
    }
}

/// Execute a tool via the daemon's ExecuteTool command.
fn execute_tool_via_daemon(
    socket_path: &std::path::Path,
    tool_name: &str,
    tool_input: &serde_json::Value,
) -> Result<String, String> {
    let client = DaemonClient::new(socket_path.to_path_buf());

    let cmd = DaemonCommand::ExecuteTool {
        name: tool_name.to_string(),
        input: tool_input.clone(),
    };

    let result = send_with_timeout(&client, &cmd, 60);

    match result {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                // Try to extract the result field from ToolOutput.
                if let Some(result_val) = data.get("result") {
                    Ok(serde_json::to_string_pretty(result_val).unwrap_or_default())
                } else {
                    Ok(serde_json::to_string_pretty(&data).unwrap_or_default())
                }
            } else {
                Ok(resp.message)
            }
        }
        Ok(resp) => Err(resp.message),
        Err(e) => Err(e),
    }
}

/// Send a command to the daemon with a custom read timeout.
///
/// Creates a new Unix socket connection with the specified timeout.
/// This is used for LLM completion requests which can take much longer
/// than the default 5-second timeout.
fn send_with_timeout(
    _client: &DaemonClient,
    command: &DaemonCommand,
    timeout_secs: u64,
) -> Result<aegis_control::daemon::DaemonResponse, String> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixStream;

    let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");

    let stream = UnixStream::connect(&socket_path).map_err(|e| {
        format!(
            "failed to connect to daemon at {}: {e}",
            socket_path.display()
        )
    })?;

    let timeout = Some(std::time::Duration::from_secs(timeout_secs));
    stream
        .set_read_timeout(timeout)
        .map_err(|e| format!("failed to set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| format!("failed to set write timeout: {e}"))?;

    let mut writer = stream
        .try_clone()
        .map_err(|e| format!("failed to clone stream: {e}"))?;

    let mut json = serde_json::to_string(command)
        .map_err(|e| format!("failed to serialize command: {e}"))?;
    json.push('\n');
    writer
        .write_all(json.as_bytes())
        .map_err(|e| format!("failed to send command: {e}"))?;
    writer
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    // Cap at 10 MB
    let mut reader = BufReader::new(stream.take(10 * 1024 * 1024));
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("failed to read response: {e}"))?;

    serde_json::from_str(&line).map_err(|e| format!("failed to parse response: {e}"))
}

/// Get completions for the command buffer.
fn local_completions(input: &str) -> Vec<String> {
    COMMANDS
        .iter()
        .filter(|c| c.starts_with(input))
        .map(|c| c.to_string())
        .collect()
}

/// Apply a completion to the command buffer.
///
/// Replaces the entire buffer with the completion text.
fn apply_completion(_buffer: &str, completion: &str) -> String {
    completion.to_string()
}

/// Detect the default model from daemon config or environment variables.
fn detect_model() -> String {
    // 1. Read daemon.toml for default_model
    let config_path = aegis_types::daemon::daemon_config_path();
    if let Ok(config_str) = std::fs::read_to_string(config_path) {
        if let Ok(config) = aegis_types::daemon::DaemonConfig::from_toml(&config_str) {
            if let Some(model) = config.default_model {
                return model;
            }
        }
    }

    // 2. Detect from environment
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        return "claude-sonnet-4-20250514".to_string();
    }
    if std::env::var("OPENAI_API_KEY").is_ok() {
        return "gpt-4o".to_string();
    }
    if std::env::var("GOOGLE_API_KEY").is_ok() || std::env::var("GEMINI_API_KEY").is_ok() {
        return "gemini-2.0-flash".to_string();
    }
    if std::env::var("OPENROUTER_API_KEY").is_ok() {
        return "anthropic/claude-sonnet-4-20250514".to_string();
    }

    // 3. Default fallback
    "claude-sonnet-4-20250514".to_string()
}

/// Run the chat TUI, connecting to the daemon at the default socket path.
pub fn run_chat_tui() -> Result<()> {
    let client = DaemonClient::default_path();
    run_chat_tui_with_client(client)
}

/// Run the chat TUI with a specific client.
pub fn run_chat_tui_with_client(client: DaemonClient) -> Result<()> {
    let model = detect_model();

    // Install panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stderr(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableBracketedPaste,
            crossterm::cursor::Show,
        );
        original_hook(info);
    }));

    // Set up terminal
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableBracketedPaste,
    )?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let events = EventHandler::new(TICK_RATE_MS);
    let mut app = ChatApp::new(Some(client), model);

    let result = run_event_loop(&mut terminal, &events, &mut app);

    // Restore terminal
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableBracketedPaste,
    )?;
    terminal.show_cursor()?;

    result
}

/// Internal event loop.
fn run_event_loop(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    events: &EventHandler,
    app: &mut ChatApp,
) -> Result<()> {
    while app.running {
        terminal.draw(|f| ui::draw(f, app))?;

        match events.next()? {
            AppEvent::Key(key) => app.handle_key(key),
            AppEvent::Paste(text) => app.handle_paste(&text),
            AppEvent::Tick => {}
        }

        app.poll_daemon();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::empty(),
        }
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(c),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::empty(),
        }
    }

    fn make_app() -> ChatApp {
        ChatApp::new(None, "claude-sonnet-4-20250514".into())
    }

    #[test]
    fn chat_app_defaults() {
        let app = make_app();
        assert!(app.running);
        assert_eq!(app.input_mode, InputMode::Chat);
        assert!(app.messages.is_empty());
        assert_eq!(app.scroll_offset, 0);
        assert!(app.input_buffer.is_empty());
        assert_eq!(app.input_cursor, 0);
        assert!(!app.connected);
        assert_eq!(app.model, "claude-sonnet-4-20250514");
        assert!(app.conversation.is_empty());
        assert!(!app.awaiting_response);
    }

    #[test]
    fn input_mode_transitions_escape_to_scroll() {
        let mut app = make_app();
        assert_eq!(app.input_mode, InputMode::Chat);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.input_mode, InputMode::Scroll);
    }

    #[test]
    fn input_mode_escape_does_not_switch_when_buffer_has_text() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('a')));
        app.handle_key(press(KeyCode::Esc));
        // Should stay in Chat mode because buffer is not empty
        assert_eq!(app.input_mode, InputMode::Chat);
    }

    #[test]
    fn input_mode_colon_enters_command() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char(':')));
        assert_eq!(app.input_mode, InputMode::Command);
    }

    #[test]
    fn input_mode_colon_inserts_when_buffer_not_empty() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('a')));
        app.handle_key(press(KeyCode::Char(':')));
        assert_eq!(app.input_mode, InputMode::Chat);
        assert_eq!(app.input_buffer, "a:");
    }

    #[test]
    fn command_mode_escape_returns_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char(':')));
        assert_eq!(app.input_mode, InputMode::Command);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.input_mode, InputMode::Chat);
        assert!(app.command_buffer.is_empty());
    }

    #[test]
    fn scroll_mode_escape_returns_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Esc)); // -> Scroll
        assert_eq!(app.input_mode, InputMode::Scroll);
        app.handle_key(press(KeyCode::Esc)); // -> Chat
        assert_eq!(app.input_mode, InputMode::Chat);
    }

    #[test]
    fn scroll_mode_printable_char_returns_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Esc)); // -> Scroll
        assert_eq!(app.input_mode, InputMode::Scroll);
        app.handle_key(press(KeyCode::Char('h')));
        assert_eq!(app.input_mode, InputMode::Chat);
        assert_eq!(app.input_buffer, "h");
    }

    #[test]
    fn scroll_mode_colon_enters_command() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Esc)); // -> Scroll
        app.handle_key(press(KeyCode::Char(':')));
        assert_eq!(app.input_mode, InputMode::Command);
    }

    #[test]
    fn ctrl_c_clears_buffer_when_not_empty() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('h')));
        app.handle_key(press(KeyCode::Char('i')));
        assert_eq!(app.input_buffer, "hi");
        app.handle_key(ctrl('c'));
        assert!(app.input_buffer.is_empty());
        assert!(app.running); // should not quit
    }

    #[test]
    fn ctrl_c_quits_when_buffer_empty() {
        let mut app = make_app();
        assert!(app.running);
        app.handle_key(ctrl('c'));
        assert!(!app.running);
    }

    #[test]
    fn text_input_and_cursor() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('h')));
        app.handle_key(press(KeyCode::Char('i')));
        assert_eq!(app.input_buffer, "hi");
        assert_eq!(app.input_cursor, 2);

        app.handle_key(press(KeyCode::Left));
        assert_eq!(app.input_cursor, 1);

        app.handle_key(press(KeyCode::Home));
        assert_eq!(app.input_cursor, 0);

        app.handle_key(press(KeyCode::End));
        assert_eq!(app.input_cursor, 2);

        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.input_buffer, "h");
    }

    #[test]
    fn command_text_input() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char(':')));
        app.handle_key(press(KeyCode::Char('h')));
        app.handle_key(press(KeyCode::Char('e')));
        app.handle_key(press(KeyCode::Char('l')));
        app.handle_key(press(KeyCode::Char('p')));
        assert_eq!(app.command_buffer, "help");
    }

    #[test]
    fn command_enter_executes_and_returns_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char(':')));
        app.handle_key(press(KeyCode::Char('q')));
        app.handle_key(press(KeyCode::Char('u')));
        app.handle_key(press(KeyCode::Char('i')));
        app.handle_key(press(KeyCode::Char('t')));
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.input_mode, InputMode::Chat);
        assert!(!app.running);
    }

    #[test]
    fn release_events_are_ignored() {
        let mut app = make_app();
        let release = KeyEvent {
            code: KeyCode::Char('q'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: crossterm::event::KeyEventState::empty(),
        };
        app.handle_key(release);
        assert!(app.running); // Should not have processed it
    }

    #[test]
    fn enter_adds_to_conversation() {
        let mut app = make_app();
        // Type "hello"
        for c in "hello".chars() {
            app.handle_key(press(KeyCode::Char(c)));
        }
        assert_eq!(app.input_buffer, "hello");

        // Press enter -- no daemon client so LLM request will fail in thread,
        // but conversation and messages should be updated immediately.
        app.handle_key(press(KeyCode::Enter));

        assert!(app.input_buffer.is_empty());
        assert_eq!(app.conversation.len(), 1);
        assert_eq!(app.conversation[0].content, "hello");
        assert_eq!(app.messages.len(), 1);
        assert!(matches!(app.messages[0].role, MessageRole::User));
        assert_eq!(app.messages[0].content, "hello");
        assert!(app.awaiting_response);
    }

    #[test]
    fn enter_ignored_when_awaiting_response() {
        let mut app = make_app();
        app.awaiting_response = true;
        app.input_buffer = "test".into();
        app.input_cursor = 4;
        app.handle_key(press(KeyCode::Enter));
        // Should not have been processed
        assert_eq!(app.input_buffer, "test");
        assert!(app.conversation.is_empty());
    }

    #[test]
    fn clear_command_clears_conversation() {
        let mut app = make_app();
        app.conversation.push(LlmMessage::user("hello"));
        app.messages.push(ChatMessage::new(
            MessageRole::User,
            "hello".to_string(),
        ));
        app.scroll_offset = 5;

        app.execute_command("clear");

        assert!(app.messages.is_empty());
        assert!(app.conversation.is_empty());
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn model_command_shows_current() {
        let mut app = make_app();
        app.execute_command("model");
        assert!(app.command_result.as_ref().unwrap().contains("claude-sonnet-4-20250514"));
    }

    #[test]
    fn model_command_sets_new_model() {
        let mut app = make_app();
        app.execute_command("model gpt-4o");
        assert_eq!(app.model, "gpt-4o");
        assert!(app.command_result.as_ref().unwrap().contains("gpt-4o"));
    }

    #[test]
    fn unknown_command_shows_error() {
        let mut app = make_app();
        app.execute_command("foobar");
        assert!(app.command_result.as_ref().unwrap().contains("Unknown command"));
    }

    #[test]
    fn paste_inserts_in_chat_mode() {
        let mut app = make_app();
        app.handle_paste("hello world");
        assert_eq!(app.input_buffer, "hello world");
    }

    #[test]
    fn paste_inserts_in_command_mode() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char(':')));
        app.handle_paste("status");
        assert_eq!(app.command_buffer, "status");
    }

    #[test]
    fn paste_in_scroll_mode_switches_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Esc)); // -> Scroll
        app.handle_paste("hello");
        assert_eq!(app.input_mode, InputMode::Chat);
        assert_eq!(app.input_buffer, "hello");
    }

    #[test]
    fn input_history_navigation() {
        let mut app = make_app();
        app.input_history = vec!["first".into(), "second".into(), "third".into()];

        // Up goes to latest (buffer must be empty)
        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.input_buffer, "third");
        assert_eq!(app.history_index, Some(2));

        // Clear buffer and go up again to get "second"
        app.input_buffer.clear();
        app.input_cursor = 0;
        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.input_buffer, "second");
        assert_eq!(app.history_index, Some(1));

        // Clear buffer and down goes forward back to "third"
        app.input_buffer.clear();
        app.input_cursor = 0;
        app.handle_key(press(KeyCode::Down));
        assert_eq!(app.input_buffer, "third");
        assert_eq!(app.history_index, Some(2));
    }

    #[test]
    fn poll_llm_handles_response() {
        let mut app = make_app();
        let (tx, rx) = mpsc::channel();
        app.agent_rx = Some(rx);
        app.awaiting_response = true;

        // Simulate a response + done event
        tx.send(AgentLoopEvent::Response(LlmResponse {
            content: "Hello! How can I help?".into(),
            model: "claude-sonnet-4-20250514".into(),
            usage: aegis_types::llm::LlmUsage {
                input_tokens: 10,
                output_tokens: 8,
            },
            tool_calls: vec![],
            stop_reason: None,
        }))
        .unwrap();
        tx.send(AgentLoopEvent::Done).unwrap();

        app.poll_llm();

        assert!(!app.awaiting_response);
        assert_eq!(app.messages.len(), 1);
        assert!(matches!(app.messages[0].role, MessageRole::Assistant));
        assert_eq!(app.messages[0].content, "Hello! How can I help?");
        assert_eq!(app.conversation.len(), 1);
        assert_eq!(app.conversation[0].content, "Hello! How can I help?");
    }

    #[test]
    fn poll_llm_handles_error() {
        let mut app = make_app();
        let (tx, rx) = mpsc::channel();
        app.agent_rx = Some(rx);
        app.awaiting_response = true;

        tx.send(AgentLoopEvent::Error("API key not set".into()))
            .unwrap();

        app.poll_llm();

        assert!(!app.awaiting_response);
        assert_eq!(app.messages.len(), 1);
        assert!(matches!(app.messages[0].role, MessageRole::System));
        assert!(app.messages[0].content.contains("API key not set"));
    }

    #[test]
    fn poll_llm_handles_tool_calls() {
        let mut app = make_app();
        let (tx, rx) = mpsc::channel();
        app.agent_rx = Some(rx);
        app.awaiting_response = true;

        let tool_calls = vec![LlmToolCall {
            id: "call_1".into(),
            name: "read_file".into(),
            input: serde_json::json!({"file_path": "/tmp/test.txt"}),
        }];
        tx.send(AgentLoopEvent::ToolCalls(tool_calls)).unwrap();

        app.poll_llm();

        assert_eq!(app.messages.len(), 1);
        assert!(matches!(
            app.messages[0].role,
            MessageRole::ToolCall { .. }
        ));
    }

    #[test]
    fn poll_llm_handles_tool_result() {
        let mut app = make_app();
        let (tx, rx) = mpsc::channel();
        app.agent_rx = Some(rx);
        app.awaiting_response = true;

        tx.send(AgentLoopEvent::ToolResult {
            tool_call_id: "call_1".into(),
            tool_name: "read_file".into(),
            result: "file contents here".into(),
        })
        .unwrap();

        app.poll_llm();

        assert_eq!(app.messages.len(), 1);
        assert!(matches!(app.messages[0].role, MessageRole::System));
        assert!(app.messages[0].content.contains("file contents here"));
        // Tool result should be added to conversation
        assert_eq!(app.conversation.len(), 1);
        assert_eq!(app.conversation[0].role, aegis_types::llm::LlmRole::Tool);
    }

    #[test]
    fn approval_keys_work() {
        let mut app = make_app();
        let (_, event_rx) = mpsc::channel();
        let (approval_tx, _approval_rx) = mpsc::channel();
        app.agent_rx = Some(event_rx);
        app.approval_tx = Some(approval_tx);
        app.awaiting_approval = true;
        app.pending_tool_desc = Some("bash: ls -la".into());
        app.messages.push(ChatMessage::new(
            MessageRole::Permission {
                prompt: "bash: ls -la".into(),
                resolved: None,
            },
            "Allow bash? [y]es / [n]o / [a]ll".into(),
        ));

        app.handle_key(press(KeyCode::Char('y')));

        assert!(!app.awaiting_approval);
        assert!(app.pending_tool_desc.is_none());
        // Permission message should be resolved
        if let MessageRole::Permission { resolved, .. } = &app.messages[0].role {
            assert_eq!(*resolved, Some(true));
        } else {
            panic!("expected Permission role");
        }
    }

    #[test]
    fn approval_a_sets_auto_approve() {
        let mut app = make_app();
        let (_, event_rx) = mpsc::channel();
        let (approval_tx, _approval_rx) = mpsc::channel();
        app.agent_rx = Some(event_rx);
        app.approval_tx = Some(approval_tx);
        app.awaiting_approval = true;
        app.pending_tool_desc = Some("bash: ls -la".into());
        app.messages.push(ChatMessage::new(
            MessageRole::Permission {
                prompt: "bash: ls -la".into(),
                resolved: None,
            },
            "Allow bash?".into(),
        ));

        app.handle_key(press(KeyCode::Char('a')));

        assert!(!app.awaiting_approval);
        assert!(app.auto_approve_turn);
    }

    #[test]
    fn safe_tools_identified_correctly() {
        assert!(is_safe_tool("read_file"));
        assert!(is_safe_tool("glob_search"));
        assert!(is_safe_tool("grep_search"));
        assert!(!is_safe_tool("bash"));
        assert!(!is_safe_tool("write_file"));
        assert!(!is_safe_tool("edit_file"));
    }

    #[test]
    fn summarize_tool_input_formats_correctly() {
        assert_eq!(
            summarize_tool_input("bash", &serde_json::json!({"command": "ls -la"})),
            "ls -la"
        );
        assert_eq!(
            summarize_tool_input("read_file", &serde_json::json!({"file_path": "/tmp/test.txt"})),
            "/tmp/test.txt"
        );
        assert_eq!(
            summarize_tool_input("glob_search", &serde_json::json!({"pattern": "**/*.rs"})),
            "**/*.rs"
        );
    }

    #[test]
    fn local_completions_filters() {
        let completions = local_completions("da");
        assert!(completions.contains(&"daemon start".to_string()));
        assert!(completions.contains(&"daemon stop".to_string()));
        assert!(completions.contains(&"daemon status".to_string()));
        assert!(!completions.contains(&"quit".to_string()));
    }

    #[test]
    fn local_completions_empty_input() {
        let completions = local_completions("");
        assert_eq!(completions.len(), COMMANDS.len());
    }

    #[test]
    fn y_inserts_char_normally() {
        let mut app = make_app();
        // No pending prompts -- y should just insert the character
        app.handle_key(press(KeyCode::Char('y')));
        assert_eq!(app.input_buffer, "y");
    }

    #[test]
    fn detect_model_returns_fallback() {
        // In a test environment without daemon.toml or API keys, detect_model
        // should return a sensible default. We just verify it returns a
        // non-empty string.
        let model = detect_model();
        assert!(!model.is_empty());
    }
}
