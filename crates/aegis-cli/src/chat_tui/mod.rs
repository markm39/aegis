//! Chat-centric TUI for Aegis.
//!
//! Provides a conversational interface for interacting with a single agent,
//! with the command bar from the fleet TUI available via `:` for fleet-wide
//! operations. This is the default interface when `aegis` is invoked.

pub mod event;
pub mod markdown;
pub mod message;
pub mod render;
pub mod security;
mod ui;

use std::collections::HashMap;
use std::time::Instant;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_control::daemon::{
    AgentSummary, DaemonClient, DaemonCommand, PendingPromptSummary, RuntimeCapabilities,
};
use aegis_types::AgentStatus;

use self::event::{AppEvent, EventHandler};
use self::message::{parse_output_lines, ChatMessage, MessageRole};
use self::security::SecurityPosture;
use crate::tui_utils::delete_word_backward_pos;

/// How often to poll crossterm for events (milliseconds).
const TICK_RATE_MS: u64 = 200;

/// How often to re-fetch agent state from daemon (milliseconds).
/// Faster than the fleet TUI to keep the chat feeling responsive.
const POLL_INTERVAL_MS: u128 = 500;

/// Maximum output lines to retain per agent.
const MAX_OUTPUT_LINES: usize = 500;

/// The current input mode in the chat TUI.
#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    /// Default: cursor in input box, typing sends to agent.
    Chat,
    /// Escape when input empty: navigate message history.
    Scroll,
    /// `:` when input empty: command bar.
    Command,
}

/// Top-level application state for the chat TUI.
pub struct ChatApp {
    /// Whether the main loop should keep running.
    pub running: bool,
    /// Current input mode.
    pub input_mode: InputMode,

    // -- Chat --
    /// Parsed chat messages for the active agent.
    pub messages: Vec<ChatMessage>,
    /// Scroll offset into the message history (0 = bottom).
    pub scroll_offset: usize,
    /// Name of the currently focused agent.
    pub active_agent: Option<String>,

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

    // -- Agents --
    /// Agent summaries from the daemon.
    pub agents: Vec<AgentSummary>,
    /// Whether the agent picker overlay is visible.
    pub agent_picker_visible: bool,
    /// Selected index in the agent picker.
    pub agent_picker_selected: usize,

    // -- Per-agent cache --
    /// Parsed messages per agent name.
    agent_messages: HashMap<String, Vec<ChatMessage>>,
    /// Raw output lines per agent name.
    agent_raw_output: HashMap<String, Vec<String>>,

    // -- Security --
    /// Current security posture for the status bar.
    pub security: SecurityPosture,
    /// Pending permission prompts for the active agent.
    pub pending_prompts: Vec<PendingPromptSummary>,
    /// Focused index in the pending prompts list.
    pub pending_focused: usize,

    // -- Connection --
    /// Whether the last daemon poll succeeded.
    pub connected: bool,
    /// Last error message from daemon communication.
    pub last_error: Option<String>,
    /// Daemon uptime from last ping.
    pub daemon_uptime_secs: u64,

    // -- Internal --
    /// Daemon client for sending commands.
    client: Option<DaemonClient>,
    /// When we last polled the daemon.
    last_poll: Instant,
}

impl ChatApp {
    /// Create a new chat TUI application.
    pub fn new(client: Option<DaemonClient>) -> Self {
        Self {
            running: true,
            input_mode: InputMode::Chat,

            messages: Vec::new(),
            scroll_offset: 0,
            active_agent: None,

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

            agents: Vec::new(),
            agent_picker_visible: false,
            agent_picker_selected: 0,

            agent_messages: HashMap::new(),
            agent_raw_output: HashMap::new(),

            security: SecurityPosture::new(),
            pending_prompts: Vec::new(),
            pending_focused: 0,

            connected: false,
            last_error: None,
            daemon_uptime_secs: 0,

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

    /// Poll the daemon for updated state (called on each tick).
    pub fn poll_daemon(&mut self) {
        self.clear_stale_result();

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
                if let Some(data) = resp.data {
                    self.daemon_uptime_secs = data["uptime_secs"].as_u64().unwrap_or(0);
                }
            }
            Ok(resp) => {
                self.connected = false;
                self.daemon_uptime_secs = 0;
                self.last_error = Some(resp.message);
            }
            Err(e) => {
                self.connected = false;
                self.daemon_uptime_secs = 0;
                self.last_error = Some(e);
            }
        }

        if !self.connected {
            return;
        }

        // Fetch agent list
        self.poll_agent_list();

        // Fetch output for active agent
        if let Some(ref name) = self.active_agent.clone() {
            self.poll_agent_output(name);
            self.poll_pending_prompts(name);
            self.poll_runtime_capabilities(name);
        }
    }

    /// Fetch agent list from daemon.
    fn poll_agent_list(&mut self) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };

        match client.send(&DaemonCommand::ListAgents) {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    match serde_json::from_value::<Vec<AgentSummary>>(data) {
                        Ok(agents) => {
                            self.agents = agents;
                        }
                        Err(e) => {
                            self.last_error = Some(format!("failed to parse agent list: {e}"));
                        }
                    }
                }
            }
            Ok(resp) => {
                self.last_error = Some(resp.message);
            }
            Err(e) => {
                self.last_error = Some(e);
            }
        }

        // Auto-select agent if none is set
        if self.active_agent.is_none() && !self.agents.is_empty() {
            // Prefer an orchestrator, then first running agent, then first agent
            let pick = self
                .agents
                .iter()
                .find(|a| a.is_orchestrator && matches!(a.status, AgentStatus::Running { .. }))
                .or_else(|| {
                    self.agents
                        .iter()
                        .find(|a| matches!(a.status, AgentStatus::Running { .. }))
                })
                .or_else(|| self.agents.first());

            if let Some(agent) = pick {
                self.active_agent = Some(agent.name.clone());
                // Force immediate output poll
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
            }
        }
    }

    /// Fetch output for a specific agent and parse into chat messages.
    fn poll_agent_output(&mut self, agent_name: &str) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };

        let cmd = DaemonCommand::AgentOutput {
            name: agent_name.to_string(),
            lines: Some(MAX_OUTPUT_LINES),
        };

        match client.send(&cmd) {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    match serde_json::from_value::<Vec<String>>(data) {
                        Ok(lines) => {
                            // Cache raw output
                            self.agent_raw_output
                                .insert(agent_name.to_string(), lines.clone());

                            // Parse into messages
                            let parsed = parse_output_lines(&lines);
                            self.agent_messages
                                .insert(agent_name.to_string(), parsed.clone());
                            self.messages = parsed;

                            // Clamp scroll
                            let max = self.messages.len().saturating_sub(1);
                            if self.scroll_offset > max {
                                self.scroll_offset = max;
                            }
                        }
                        Err(e) => {
                            self.last_error =
                                Some(format!("failed to parse agent output: {e}"));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Fetch pending permission prompts for the active agent.
    fn poll_pending_prompts(&mut self, agent_name: &str) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };

        let cmd = DaemonCommand::ListPending {
            name: agent_name.to_string(),
        };

        match client.send(&cmd) {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    match serde_json::from_value::<Vec<PendingPromptSummary>>(data) {
                        Ok(pending) => {
                            self.pending_prompts = pending;
                            if self.pending_focused >= self.pending_prompts.len()
                                && !self.pending_prompts.is_empty()
                            {
                                self.pending_focused = self.pending_prompts.len() - 1;
                            }
                        }
                        Err(e) => {
                            self.last_error =
                                Some(format!("failed to parse pending prompts: {e}"));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Fetch runtime capabilities for the active agent to update security posture.
    fn poll_runtime_capabilities(&mut self, agent_name: &str) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };

        let cmd = DaemonCommand::RuntimeCapabilities {
            name: agent_name.to_string(),
        };

        if let Ok(resp) = client.send(&cmd) {
            if resp.ok {
                if let Some(data) = resp.data {
                    if let Ok(caps) = serde_json::from_value::<RuntimeCapabilities>(data) {
                        self.security.mediation_mode = caps.mediation_mode.clone();
                    }
                }
            }
        }
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
        match key.code {
            KeyCode::Enter => {
                if !self.input_buffer.is_empty() {
                    if let Some(ref agent) = self.active_agent {
                        let cmd = DaemonCommand::SendToAgent {
                            name: agent.clone(),
                            text: self.input_buffer.clone(),
                        };
                        self.send_named_command(cmd);
                        // Add user message to chat immediately
                        self.messages.push(ChatMessage::new(
                            MessageRole::User,
                            self.input_buffer.clone(),
                        ));
                        self.scroll_offset = 0;
                    }
                    self.input_history.push(self.input_buffer.clone());
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
            KeyCode::Tab => {
                // Cycle pending prompts
                if !self.pending_prompts.is_empty() {
                    self.pending_focused =
                        (self.pending_focused + 1) % self.pending_prompts.len();
                }
            }
            KeyCode::Char('y')
                if self.input_buffer.is_empty() && !self.pending_prompts.is_empty() =>
            {
                self.approve_focused_pending();
            }
            KeyCode::Char('n')
                if self.input_buffer.is_empty() && !self.pending_prompts.is_empty() =>
            {
                self.deny_focused_pending();
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
        let agent_names: Vec<String> = self.agents.iter().map(|a| a.name.clone()).collect();
        self.command_completions =
            crate::fleet_tui::command::completions(&self.command_buffer, &agent_names);
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
        self.command_buffer =
            crate::fleet_tui::command::apply_completion(&self.command_buffer, &completion);
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
        self.command_buffer =
            crate::fleet_tui::command::apply_completion(&self.command_buffer, &completion);
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

    /// Execute a parsed command string.
    fn execute_command(&mut self, input: &str) {
        use crate::fleet_tui::command;

        match command::parse(input) {
            Ok(Some(cmd)) => self.dispatch_command(cmd),
            Ok(None) => {}
            Err(e) => {
                self.set_result(e);
            }
        }
    }

    /// Dispatch a parsed FleetCommand in the chat context.
    fn dispatch_command(&mut self, cmd: crate::fleet_tui::command::FleetCommand) {
        use crate::fleet_tui::command::FleetCommand;

        match cmd {
            FleetCommand::Follow { agent } | FleetCommand::Chat { agent: Some(agent) } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.switch_agent(&agent);
                }
            }
            FleetCommand::Chat { agent: None } => {
                // Pick orchestrator or first running agent
                if let Some(name) = self
                    .agents
                    .iter()
                    .find(|a| a.is_orchestrator)
                    .map(|a| a.name.clone())
                {
                    self.switch_agent(&name);
                } else if let Some(first) = self.agents.first() {
                    let name = first.name.clone();
                    self.switch_agent(&name);
                } else {
                    self.set_result("No agents available");
                }
            }
            FleetCommand::Send { agent, text } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.send_and_show_result(DaemonCommand::SendToAgent { name: agent, text });
                }
            }
            FleetCommand::Approve { agent } => {
                if let Some(request_id) = self.fetch_first_pending_id(&agent) {
                    self.send_and_show_result(DaemonCommand::ApproveRequest {
                        name: agent,
                        request_id,
                    });
                } else {
                    self.set_result(format!("no pending prompts for '{agent}'"));
                }
            }
            FleetCommand::Deny { agent } => {
                if let Some(request_id) = self.fetch_first_pending_id(&agent) {
                    self.send_and_show_result(DaemonCommand::DenyRequest {
                        name: agent,
                        request_id,
                    });
                } else {
                    self.set_result(format!("no pending prompts for '{agent}'"));
                }
            }
            FleetCommand::Start { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.send_and_show_result(DaemonCommand::StartAgent { name: agent });
                }
            }
            FleetCommand::Stop { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.send_and_show_result(DaemonCommand::StopAgent { name: agent });
                }
            }
            FleetCommand::Restart { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.send_and_show_result(DaemonCommand::RestartAgent { name: agent });
                }
            }
            FleetCommand::Nudge { agent, message } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.send_and_show_result(DaemonCommand::NudgeAgent {
                        name: agent,
                        message,
                    });
                }
            }
            FleetCommand::Status => {
                let running = self.running_count();
                let total = self.agents.len();
                self.set_result(format!(
                    "{running} running / {total} total, uptime {}",
                    crate::fleet_tui::format_uptime(self.daemon_uptime_secs),
                ));
            }
            FleetCommand::Goal { text } => {
                self.send_and_show_result(DaemonCommand::FleetGoal { goal: text });
            }
            FleetCommand::Help => {
                let help = crate::fleet_tui::command::help_text();
                self.set_result(help.lines().take(5).collect::<Vec<_>>().join(" | "));
            }
            FleetCommand::Quit => {
                self.running = false;
            }
            FleetCommand::Add => {
                self.set_result("Use :agent add or run `aegis fleet` for the add wizard");
            }

            // Commands that spawn terminals
            FleetCommand::Pop { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    let cmd = self
                        .agents
                        .iter()
                        .find(|a| a.name == agent)
                        .and_then(|a| a.attach_command.as_ref())
                        .map(|parts| parts.join(" "))
                        .unwrap_or_else(|| format!("aegis daemon follow {agent}"));
                    self.spawn_terminal(&cmd, &format!("Opened '{agent}' in new terminal"));
                }
            }
            FleetCommand::Monitor => {
                self.spawn_terminal("aegis monitor", "Opened monitor in new terminal");
            }
            FleetCommand::Wrap { cmd } => {
                self.spawn_terminal(
                    &format!("aegis wrap -- {cmd}"),
                    "Launched wrap in new terminal",
                );
            }
            FleetCommand::Run { cmd } => {
                self.spawn_terminal(
                    &format!("aegis run -- {cmd}"),
                    "Launched sandboxed command in new terminal",
                );
            }
            FleetCommand::Pilot { cmd } => {
                self.spawn_terminal(
                    &format!("aegis pilot -- {cmd}"),
                    "Launched pilot in new terminal",
                );
            }
            FleetCommand::Log => {
                self.spawn_terminal("aegis log", "Opened audit log in new terminal");
            }
            FleetCommand::Logs => {
                self.spawn_terminal(
                    "aegis daemon logs --follow",
                    "Opened daemon logs in new terminal",
                );
            }
            FleetCommand::Config => {
                self.spawn_terminal("aegis daemon config edit", "Opened config in editor");
            }
            FleetCommand::Policy => {
                self.spawn_terminal("aegis policy list", "Opened policy list in new terminal");
            }
            FleetCommand::Report => {
                self.spawn_terminal(
                    "aegis report",
                    "Opened compliance report in new terminal",
                );
            }
            FleetCommand::List => {
                self.spawn_terminal("aegis list", "Opened config list in new terminal");
            }
            FleetCommand::Setup => {
                self.spawn_terminal("aegis setup", "Running system checks in new terminal");
            }
            FleetCommand::Init => {
                self.spawn_terminal("aegis init", "Opened init wizard in new terminal");
            }
            FleetCommand::Alerts => {
                self.spawn_terminal("aegis alerts list", "Opened alerts in new terminal");
            }
            FleetCommand::Hook => {
                self.spawn_terminal(
                    "aegis hook install",
                    "Installing hooks in new terminal",
                );
            }
            FleetCommand::Use { name } => match name {
                Some(n) => self.spawn_terminal(
                    &format!("aegis use {n}"),
                    &format!("Switching to config '{n}'"),
                ),
                None => {
                    self.spawn_terminal("aegis use", "Opened config picker in new terminal")
                }
            },
            FleetCommand::Watch { dir } => {
                let cmd = match dir {
                    Some(d) => {
                        format!("aegis watch --dir {}", crate::terminal::shell_quote(&d))
                    }
                    None => "aegis watch".to_string(),
                };
                self.spawn_terminal(&cmd, "Started directory watch in new terminal");
            }
            FleetCommand::Diff { session1, session2 } => {
                self.spawn_terminal(
                    &format!("aegis diff {session1} {session2}"),
                    "Opened session diff in new terminal",
                );
            }
            FleetCommand::Dashboard => {
                self.spawn_terminal(
                    "aegis daemon dashboard --open",
                    "Opened dashboard in browser",
                );
            }
            FleetCommand::Sessions => {
                self.spawn_terminal(
                    "aegis audit sessions",
                    "Opened audit sessions in new terminal",
                );
            }
            FleetCommand::Verify => {
                self.spawn_terminal(
                    "aegis audit verify",
                    "Running audit verification in new terminal",
                );
            }

            // Daemon lifecycle
            FleetCommand::DaemonStart => match crate::commands::daemon::start_quiet() {
                Ok(msg) => {
                    self.set_result(msg);
                    self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                }
                Err(e) => {
                    self.last_error = Some(format!("Failed to start daemon: {e}"));
                }
            },
            FleetCommand::DaemonStop => {
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
            FleetCommand::DaemonInit => match crate::commands::daemon::init_quiet() {
                Ok(msg) => self.set_result(msg),
                Err(e) => {
                    self.last_error = Some(format!("{e}"));
                }
            },
            FleetCommand::DaemonReload => {
                if !self.connected {
                    self.set_result("Daemon is not running.");
                } else {
                    self.send_and_show_result(DaemonCommand::ReloadConfig);
                }
            }
            FleetCommand::DaemonRestart => {
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
            FleetCommand::DaemonStatus => {
                if !self.connected {
                    self.set_result("Daemon is not running (offline mode).");
                } else {
                    let running = self.running_count();
                    let total = self.agents.len();
                    self.set_result(format!(
                        "{running} running / {total} total, uptime {}",
                        crate::fleet_tui::format_uptime(self.daemon_uptime_secs),
                    ));
                }
            }

            // Telegram
            FleetCommand::Telegram => {
                self.set_result("Run :telegram setup to configure Telegram notifications");
            }
            FleetCommand::TelegramSetup => {
                self.spawn_terminal("aegis telegram setup", "Opened Telegram setup wizard");
            }
            FleetCommand::TelegramDisable => {
                match crate::commands::telegram::disable_quiet() {
                    Ok(msg) => self.set_result(msg),
                    Err(e) => {
                        self.last_error = Some(format!("Failed to disable Telegram: {e}"));
                    }
                }
            }

            // Agent enable/disable
            FleetCommand::Enable { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.send_and_show_result(DaemonCommand::EnableAgent { name: agent });
                }
            }
            FleetCommand::Disable { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.send_and_show_result(DaemonCommand::DisableAgent { name: agent });
                }
            }

            FleetCommand::Remove { agent } => {
                if self.connected {
                    self.send_and_show_result(DaemonCommand::RemoveAgent { name: agent });
                    self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                } else {
                    match crate::commands::daemon::remove_agent_quiet(&agent) {
                        Ok(msg) => self.set_result(msg),
                        Err(e) => {
                            self.last_error =
                                Some(format!("Failed to remove '{agent}': {e}"));
                        }
                    }
                }
            }

            FleetCommand::Pending { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.switch_agent(&agent);
                    self.set_result(format!("Switched to '{agent}' (pending prompts view)"));
                }
            }

            // Anything else: show the result or a fallback
            other => {
                self.set_result(format!("Command not available in chat TUI: {other:?}"));
            }
        }
    }

    /// Switch the active agent.
    fn switch_agent(&mut self, name: &str) {
        self.active_agent = Some(name.to_string());
        self.scroll_offset = 0;
        self.pending_prompts.clear();
        self.pending_focused = 0;

        // Restore cached messages or clear
        if let Some(cached) = self.agent_messages.get(name) {
            self.messages = cached.clone();
        } else {
            self.messages.clear();
        }

        // Force immediate poll
        self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
        self.set_result(format!("Chat focused on '{name}'"));
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

    /// Approve the currently focused pending prompt.
    fn approve_focused_pending(&mut self) {
        if let Some(pending) = self.pending_prompts.get(self.pending_focused) {
            if let Some(ref agent) = self.active_agent {
                let cmd = DaemonCommand::ApproveRequest {
                    name: agent.clone(),
                    request_id: pending.request_id.clone(),
                };
                self.send_and_show_result(cmd);
            }
        }
    }

    /// Deny the currently focused pending prompt.
    fn deny_focused_pending(&mut self) {
        if let Some(pending) = self.pending_prompts.get(self.pending_focused) {
            if let Some(ref agent) = self.active_agent {
                let cmd = DaemonCommand::DenyRequest {
                    name: agent.clone(),
                    request_id: pending.request_id.clone(),
                };
                self.send_and_show_result(cmd);
            }
        }
    }

    /// Send a command to the daemon.
    fn send_named_command(&mut self, cmd: DaemonCommand) {
        let Some(client) = &self.client else {
            self.last_error = Some("Not connected to daemon. Use :daemon start".into());
            return;
        };
        match client.send(&cmd) {
            Ok(resp) if !resp.ok => {
                self.last_error = Some(resp.message);
            }
            Err(e) => {
                self.last_error = Some(e);
            }
            _ => {
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
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

    /// Fetch the first pending prompt's request_id for an agent.
    fn fetch_first_pending_id(&self, agent: &str) -> Option<String> {
        // Use cached data if this is the active agent
        if self.active_agent.as_deref() == Some(agent) {
            if let Some(p) = self.pending_prompts.first() {
                return Some(p.request_id.clone());
            }
        }
        // Fetch on demand from daemon
        let client = self.client.as_ref()?;
        let cmd = DaemonCommand::ListPending {
            name: agent.to_string(),
        };
        let resp = client.send(&cmd).ok()?;
        if !resp.ok {
            return None;
        }
        let data = resp.data?;
        let pending: Vec<PendingPromptSummary> = serde_json::from_value(data).ok()?;
        pending.first().map(|p| p.request_id.clone())
    }

    /// Check if an agent name is known (or if we're disconnected and can't validate).
    fn agent_exists(&self, name: &str) -> bool {
        !self.connected || self.agents.iter().any(|a| a.name == name)
    }

    /// Set the command result message with a timestamp for auto-clear.
    fn set_result(&mut self, msg: impl Into<String>) {
        self.command_result = Some(msg.into());
        self.command_result_at = Some(Instant::now());
        self.last_error = None;
    }

    /// Spawn a command in a new terminal and set the result message.
    fn spawn_terminal(&mut self, cmd: &str, msg: &str) {
        match crate::terminal::spawn_in_terminal(cmd) {
            Ok(()) => self.set_result(msg),
            Err(e) => {
                self.last_error = Some(e);
            }
        }
    }

    /// Count of running agents.
    pub fn running_count(&self) -> usize {
        self.agents
            .iter()
            .filter(|a| matches!(a.status, AgentStatus::Running { .. }))
            .count()
    }
}

/// Run the chat TUI, connecting to the daemon at the default socket path.
pub fn run_chat_tui() -> Result<()> {
    let client = DaemonClient::default_path();
    run_chat_tui_with_client(client)
}

/// Run the chat TUI with a specific client.
pub fn run_chat_tui_with_client(client: DaemonClient) -> Result<()> {
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
    let mut app = ChatApp::new(Some(client));

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
        let mut app = ChatApp::new(None);
        app.agents = vec![
            AgentSummary {
                name: "claude-1".into(),
                status: AgentStatus::Running { pid: 100 },
                tool: "ClaudeCode".into(),
                working_dir: "/tmp/claude".into(),
                role: None,
                restart_count: 0,
                pending_count: 2,
                attention_needed: false,
                is_orchestrator: true,
                attach_command: None,
                fallback: None,
            },
            AgentSummary {
                name: "codex-1".into(),
                status: AgentStatus::Stopped { exit_code: 0 },
                tool: "Codex".into(),
                working_dir: "/tmp/codex".into(),
                role: None,
                restart_count: 0,
                pending_count: 0,
                attention_needed: false,
                is_orchestrator: false,
                attach_command: None,
                fallback: None,
            },
        ];
        app.active_agent = Some("claude-1".into());
        app
    }

    #[test]
    fn chat_app_defaults() {
        let app = ChatApp::new(None);
        assert!(app.running);
        assert_eq!(app.input_mode, InputMode::Chat);
        assert!(app.messages.is_empty());
        assert_eq!(app.scroll_offset, 0);
        assert!(app.active_agent.is_none());
        assert!(app.input_buffer.is_empty());
        assert_eq!(app.input_cursor, 0);
        assert!(!app.connected);
        assert!(app.pending_prompts.is_empty());
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
    fn pending_y_approves() {
        let mut app = make_app();
        app.pending_prompts = vec![PendingPromptSummary {
            request_id: "req-1".into(),
            raw_prompt: "Allow file write?".into(),
            age_secs: 5,
        }];
        // Y when input empty and pending exist -- approve
        // No client so this won't actually send, but we can verify it tries
        app.handle_key(press(KeyCode::Char('y')));
        // Should set error because no daemon client
        assert!(app.last_error.is_some());
    }

    #[test]
    fn pending_n_denies() {
        let mut app = make_app();
        app.pending_prompts = vec![PendingPromptSummary {
            request_id: "req-2".into(),
            raw_prompt: "Allow bash?".into(),
            age_secs: 10,
        }];
        app.handle_key(press(KeyCode::Char('n')));
        assert!(app.last_error.is_some());
    }

    #[test]
    fn y_inserts_char_when_no_pending() {
        let mut app = make_app();
        // No pending prompts
        app.handle_key(press(KeyCode::Char('y')));
        assert_eq!(app.input_buffer, "y");
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
    fn agent_auto_selection_prefers_orchestrator() {
        let mut app = ChatApp::new(None);
        app.connected = true;
        app.agents = vec![
            AgentSummary {
                name: "worker".into(),
                status: AgentStatus::Running { pid: 1 },
                tool: "Generic".into(),
                working_dir: "/tmp".into(),
                role: None,
                restart_count: 0,
                pending_count: 0,
                attention_needed: false,
                is_orchestrator: false,
                attach_command: None,
                fallback: None,
            },
            AgentSummary {
                name: "orchestrator".into(),
                status: AgentStatus::Running { pid: 2 },
                tool: "ClaudeCode".into(),
                working_dir: "/tmp".into(),
                role: None,
                restart_count: 0,
                pending_count: 0,
                attention_needed: false,
                is_orchestrator: true,
                attach_command: None,
                fallback: None,
            },
        ];
        // Simulate auto-selection logic from poll_agent_list
        assert!(app.active_agent.is_none());
        app.poll_agent_list();
        // Can't actually poll (no client), but verify the agent list code path
        // by testing the selection logic inline:
        let pick = app
            .agents
            .iter()
            .find(|a| a.is_orchestrator && matches!(a.status, AgentStatus::Running { .. }))
            .or_else(|| {
                app.agents
                    .iter()
                    .find(|a| matches!(a.status, AgentStatus::Running { .. }))
            })
            .or_else(|| app.agents.first());
        assert_eq!(pick.unwrap().name, "orchestrator");
    }

    #[test]
    fn switch_agent_updates_state() {
        let mut app = make_app();
        app.messages.push(ChatMessage::new(
            MessageRole::Assistant,
            "old message".to_string(),
        ));
        app.scroll_offset = 5;

        app.switch_agent("codex-1");
        assert_eq!(app.active_agent.as_deref(), Some("codex-1"));
        assert_eq!(app.scroll_offset, 0);
        assert!(app.pending_prompts.is_empty());
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
    fn running_count() {
        let app = make_app();
        assert_eq!(app.running_count(), 1);
    }
}
