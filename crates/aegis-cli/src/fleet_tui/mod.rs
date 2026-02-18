//! Interactive TUI for the fleet dashboard.
//!
//! Connects to a running daemon via `DaemonClient` and displays a live
//! overview of all agent slots. Supports drilling into individual agents
//! to view their output, and sending start/stop/restart commands.

pub mod command;
pub mod event;
pub mod ui;
pub mod wizard;

use std::collections::VecDeque;
use std::time::Instant;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use aegis_control::daemon::{AgentSummary, DaemonClient, DaemonCommand, PendingPromptSummary};
use aegis_types::AgentStatus;

use self::event::{AppEvent, EventHandler};
use self::wizard::AddAgentWizard;

/// How often to poll the daemon for updates (milliseconds).
const TICK_RATE_MS: u64 = 200;

/// How often to re-fetch agent list from daemon (milliseconds).
const POLL_INTERVAL_MS: u128 = 1000;

/// Maximum output lines to retain per agent in detail view.
const MAX_OUTPUT_LINES: usize = 500;

/// The current view in the fleet TUI.
#[derive(Debug, Clone, PartialEq)]
pub enum FleetView {
    /// Agent table overview.
    Overview,
    /// Viewing a single agent's output.
    AgentDetail,
    /// Add-agent wizard is open.
    AddAgent,
    /// Scrollable help text.
    Help,
}

/// Top-level application state for the fleet TUI.
pub struct FleetApp {
    /// Current view.
    pub view: FleetView,
    /// Whether the main loop should keep running.
    pub running: bool,

    // -- Overview state --
    /// Agent summaries from the daemon.
    pub agents: Vec<AgentSummary>,
    /// Selected index in the agent list.
    pub agent_selected: usize,

    // -- Agent detail state --
    /// Name of the agent being viewed in detail.
    pub detail_name: String,
    /// Recent output lines for the detail agent.
    pub detail_output: VecDeque<String>,
    /// Scroll position in the output pane (0 = bottom/latest).
    pub detail_scroll: usize,

    // -- Connection state --
    /// Whether the last daemon poll succeeded.
    pub connected: bool,
    /// Last error message from daemon communication.
    pub last_error: Option<String>,
    /// Daemon uptime (from last ping).
    pub daemon_uptime_secs: u64,
    /// Daemon PID (from last ping).
    pub daemon_pid: u32,

    // -- Input mode (detail view) --
    /// Whether text input mode is active (typing to agent stdin).
    pub input_mode: bool,
    /// Text buffer for input mode.
    pub input_buffer: String,
    /// Cursor position in the input buffer.
    pub input_cursor: usize,

    // -- Pending prompts (detail view) --
    /// Pending permission prompts for the detail agent.
    pub detail_pending: Vec<PendingPromptSummary>,
    /// Selected index in the pending prompts panel.
    pub pending_selected: usize,
    /// Whether focus is on the pending panel (vs output).
    pub focus_pending: bool,
    /// Whether the detail agent needs attention.
    pub detail_attention: bool,

    // -- Command mode --
    /// Whether command mode is active (: bar).
    pub command_mode: bool,
    /// Text buffer for the command bar.
    pub command_buffer: String,
    /// Cursor position in the command buffer.
    pub command_cursor: usize,
    /// History of executed commands.
    pub command_history: Vec<String>,
    /// Index into command history (-1 means current buffer).
    pub history_index: Option<usize>,
    /// Current tab completions.
    pub command_completions: Vec<String>,
    /// Selected completion index (None = no completion selected).
    pub completion_idx: Option<usize>,
    /// Error/result message from last command execution.
    pub command_result: Option<String>,

    // -- Fleet goal --
    /// Fleet-wide goal (fetched from daemon).
    pub fleet_goal: Option<String>,

    // -- Wizard --
    /// Add-agent wizard (active when view == AddAgent).
    pub wizard: Option<AddAgentWizard>,

    // -- Help view --
    /// Scroll offset for help text.
    pub help_scroll: usize,

    // -- Internal --
    /// Daemon client for sending commands.
    client: Option<DaemonClient>,
    /// When we last polled the daemon.
    last_poll: Instant,
}

impl FleetApp {
    /// Create a new fleet TUI application.
    pub fn new(client: Option<DaemonClient>) -> Self {
        Self {
            view: FleetView::Overview,
            running: true,
            agents: Vec::new(),
            agent_selected: 0,
            detail_name: String::new(),
            detail_output: VecDeque::with_capacity(MAX_OUTPUT_LINES),
            detail_scroll: 0,
            connected: false,
            last_error: None,
            daemon_uptime_secs: 0,
            daemon_pid: 0,
            input_mode: false,
            input_buffer: String::new(),
            input_cursor: 0,
            detail_pending: Vec::new(),
            pending_selected: 0,
            focus_pending: false,
            detail_attention: false,
            command_mode: false,
            command_buffer: String::new(),
            command_cursor: 0,
            command_history: Vec::new(),
            history_index: None,
            command_completions: Vec::new(),
            completion_idx: None,
            command_result: None,
            fleet_goal: None,
            wizard: None,
            help_scroll: 0,
            client,
            last_poll: Instant::now() - std::time::Duration::from_secs(10), // force immediate poll
        }
    }

    /// Poll the daemon for updated state (called on each tick).
    pub fn poll_daemon(&mut self) {
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

        // Ping to get daemon metadata
        match client.send(&DaemonCommand::Ping) {
            Ok(resp) if resp.ok => {
                self.connected = true;
                self.last_error = None;
                if let Some(data) = resp.data {
                    self.daemon_uptime_secs = data["uptime_secs"].as_u64().unwrap_or(0);
                    self.daemon_pid = data["daemon_pid"].as_u64().unwrap_or(0) as u32;
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

        if !self.connected {
            return;
        }

        match self.view {
            FleetView::Overview => self.poll_agent_list(),
            FleetView::AgentDetail => {
                // Also refresh agent list so attention_needed stays current
                self.poll_agent_list();
                self.poll_agent_output();
            }
            FleetView::AddAgent | FleetView::Help => {} // No daemon polling needed
        }
    }

    /// Fetch agent list and fleet goal from daemon.
    fn poll_agent_list(&mut self) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };

        match client.send(&DaemonCommand::ListAgents) {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    if let Ok(agents) = serde_json::from_value::<Vec<AgentSummary>>(data) {
                        self.agents = agents;
                        // Clamp selection
                        if self.agent_selected >= self.agents.len() && !self.agents.is_empty() {
                            self.agent_selected = self.agents.len() - 1;
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

        // Fetch fleet goal
        match client.send(&DaemonCommand::FleetGoal { goal: None }) {
            Ok(resp) if resp.ok => {
                self.fleet_goal = resp.data
                    .and_then(|d| d["goal"].as_str().map(|s| s.to_string()))
                    .filter(|s| !s.is_empty());
            }
            _ => {} // Non-critical, don't overwrite errors
        }
    }

    /// Fetch output and pending prompts for the currently viewed agent.
    fn poll_agent_output(&mut self) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };

        // Fetch output
        let cmd = DaemonCommand::AgentOutput {
            name: self.detail_name.clone(),
            lines: Some(MAX_OUTPUT_LINES),
        };

        match client.send(&cmd) {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    if let Ok(lines) = serde_json::from_value::<Vec<String>>(data) {
                        self.detail_output.clear();
                        for line in lines {
                            self.detail_output.push_back(line);
                        }
                    }
                }
            }
            _ => {} // Don't overwrite error; ping handles connection state
        }

        // Fetch pending prompts
        let pending_cmd = DaemonCommand::ListPending {
            name: self.detail_name.clone(),
        };
        match client.send(&pending_cmd) {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    if let Ok(pending) = serde_json::from_value::<Vec<PendingPromptSummary>>(data) {
                        self.detail_pending = pending;
                        // Clamp selection
                        if self.pending_selected >= self.detail_pending.len()
                            && !self.detail_pending.is_empty()
                        {
                            self.pending_selected = self.detail_pending.len() - 1;
                        }
                        // If pending list became empty, unfocus it
                        if self.detail_pending.is_empty() {
                            self.focus_pending = false;
                        }
                    }
                }
            }
            _ => {}
        }

        // Update attention status from agent summary
        if let Some(agent) = self.agents.iter().find(|a| a.name == self.detail_name) {
            self.detail_attention = agent.attention_needed;
        }
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Only handle key press events (not release/repeat)
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Ctrl+C: cancel modal modes, or quit
        if key.code == KeyCode::Char('c')
            && key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
        {
            if self.command_mode {
                self.command_mode = false;
                self.command_buffer.clear();
                self.command_cursor = 0;
                self.command_completions.clear();
                self.completion_idx = None;
            } else if self.input_mode {
                self.input_mode = false;
                self.input_buffer.clear();
                self.input_cursor = 0;
            } else {
                self.running = false;
            }
            return;
        }

        // Command mode intercepts all keys
        if self.command_mode {
            self.handle_command_key(key);
            return;
        }

        // Clear command result on any keypress (so it fades after one action)
        self.command_result = None;

        // Input mode intercepts all keys
        if self.input_mode {
            self.handle_input_key(key);
            return;
        }

        match self.view {
            FleetView::Overview => self.handle_overview_key(key),
            FleetView::AgentDetail => self.handle_detail_key(key),
            FleetView::AddAgent => self.handle_wizard_key(key),
            FleetView::Help => self.handle_help_key(key),
        }
    }

    /// Handle pasted text (bracketed paste).
    pub fn handle_paste(&mut self, text: &str) {
        // Route paste to command bar if active
        if self.command_mode {
            self.command_buffer.insert_str(self.command_cursor, text);
            self.command_cursor += text.len();
            return;
        }
        // Route paste to input mode if active
        if self.input_mode {
            let cleaned = text.replace(['\n', '\r'], " ");
            self.input_buffer.insert_str(self.input_cursor, &cleaned);
            self.input_cursor += cleaned.len();
            return;
        }
        // Route paste to wizard if active
        if let Some(ref mut wiz) = self.wizard {
            wiz.handle_paste(text);
        }
    }

    /// Handle keys in the overview view.
    fn handle_overview_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => {
                self.running = false;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if !self.agents.is_empty() {
                    self.agent_selected = (self.agent_selected + 1).min(self.agents.len() - 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.agent_selected = self.agent_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if let Some(agent) = self.agents.get(self.agent_selected) {
                    self.detail_name = agent.name.clone();
                    self.detail_output.clear();
                    self.detail_scroll = 0;
                    self.detail_pending.clear();
                    self.pending_selected = 0;
                    self.focus_pending = false;
                    self.detail_attention = false;
                    self.view = FleetView::AgentDetail;
                    // Force immediate poll for output
                    self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                }
            }
            KeyCode::Char('s') => {
                self.send_agent_command(|name| DaemonCommand::StartAgent { name });
            }
            KeyCode::Char('x') => {
                self.send_agent_command(|name| DaemonCommand::StopAgent { name });
            }
            KeyCode::Char('r') => {
                self.send_agent_command(|name| DaemonCommand::RestartAgent { name });
            }
            KeyCode::Char('a') => {
                self.wizard = Some(AddAgentWizard::new());
                self.view = FleetView::AddAgent;
            }
            KeyCode::Char(':') => {
                self.enter_command_mode();
            }
            _ => {}
        }
    }

    /// Handle keys when the wizard is active.
    fn handle_wizard_key(&mut self, key: KeyEvent) {
        if let Some(ref mut wiz) = self.wizard {
            wiz.handle_key(key);
            if !wiz.active {
                if wiz.completed {
                    let config = wiz.build_config();
                    self.send_add_agent(config);
                }
                self.wizard = None;
                self.view = FleetView::Overview;
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
            }
        }
    }

    /// Handle keys in the help view (scrollable help text).
    fn handle_help_key(&mut self, key: KeyEvent) {
        let help_lines = command::help_text().lines().count();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.view = FleetView::Overview;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if self.help_scroll + 1 < help_lines {
                    self.help_scroll += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.help_scroll = self.help_scroll.saturating_sub(1);
            }
            KeyCode::Char('G') => {
                self.help_scroll = help_lines.saturating_sub(1);
            }
            KeyCode::Char('g') => {
                self.help_scroll = 0;
            }
            _ => {}
        }
    }

    /// Add an agent: send to daemon if connected, otherwise write to daemon.toml directly.
    fn send_add_agent(&mut self, config: aegis_types::daemon::AgentSlotConfig) {
        if self.connected {
            let cmd = DaemonCommand::AddAgent {
                config: Box::new(config),
                start: true,
            };
            self.send_and_show_result(cmd);
        } else {
            // Offline: write directly to daemon.toml
            match self.add_agent_to_config(config) {
                Ok(name) => {
                    self.command_result = Some(format!(
                        "Added '{name}' to daemon.toml. Start daemon with :daemon start."
                    ));
                }
                Err(e) => {
                    self.command_result = Some(format!("Failed to add agent: {e}"));
                }
            }
        }
    }

    /// Write an agent directly to daemon.toml (for offline mode).
    fn add_agent_to_config(
        &self,
        agent: aegis_types::daemon::AgentSlotConfig,
    ) -> anyhow::Result<String> {
        use aegis_types::daemon::{daemon_config_path, daemon_dir, DaemonConfig};

        let config_path = daemon_config_path();
        let name = agent.name.clone();

        let mut config = if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            DaemonConfig::from_toml(&content)?
        } else {
            std::fs::create_dir_all(daemon_dir())?;
            DaemonConfig {
                goal: None,
                persistence: aegis_types::daemon::PersistenceConfig::default(),
                control: aegis_types::daemon::DaemonControlConfig::default(),
                alerts: vec![],
                agents: vec![],
                channel: None,
            }
        };

        if config.agents.iter().any(|a| a.name == name) {
            anyhow::bail!("agent '{name}' already exists in config");
        }

        config.agents.push(agent);
        let toml_str = config.to_toml()?;
        std::fs::write(&config_path, &toml_str)?;

        Ok(name)
    }

    /// Handle keys in the agent detail view.
    fn handle_detail_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.view = FleetView::Overview;
                // Force immediate poll for agent list
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
            }
            KeyCode::Char('q') => {
                self.running = false;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if self.focus_pending {
                    // Navigate pending list
                    if !self.detail_pending.is_empty() {
                        self.pending_selected =
                            (self.pending_selected + 1).min(self.detail_pending.len() - 1);
                    }
                } else if self.detail_scroll > 0 {
                    self.detail_scroll -= 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.focus_pending {
                    self.pending_selected = self.pending_selected.saturating_sub(1);
                } else {
                    self.detail_scroll += 1;
                }
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.detail_scroll = 0; // bottom
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.detail_scroll = self.detail_output.len().saturating_sub(1);
            }
            KeyCode::Char('i') => {
                // Enter input mode
                self.input_mode = true;
                self.input_buffer.clear();
                self.input_cursor = 0;
            }
            KeyCode::Char('a') => {
                // Approve selected pending prompt
                if let Some(pending) = self.detail_pending.get(self.pending_selected) {
                    let cmd = DaemonCommand::ApproveRequest {
                        name: self.detail_name.clone(),
                        request_id: pending.request_id.clone(),
                    };
                    self.send_named_command(cmd);
                }
            }
            KeyCode::Char('d') => {
                // Deny selected pending prompt
                if let Some(pending) = self.detail_pending.get(self.pending_selected) {
                    let cmd = DaemonCommand::DenyRequest {
                        name: self.detail_name.clone(),
                        request_id: pending.request_id.clone(),
                    };
                    self.send_named_command(cmd);
                }
            }
            KeyCode::Char('n') => {
                // Nudge stalled agent
                let cmd = DaemonCommand::NudgeAgent {
                    name: self.detail_name.clone(),
                    message: None,
                };
                self.send_named_command(cmd);
            }
            KeyCode::Tab => {
                // Toggle focus between output and pending panel
                if !self.detail_pending.is_empty() {
                    self.focus_pending = !self.focus_pending;
                }
            }
            KeyCode::Char('x') => {
                self.send_named_command(DaemonCommand::StopAgent {
                    name: self.detail_name.clone(),
                });
            }
            KeyCode::Char('r') => {
                self.send_named_command(DaemonCommand::RestartAgent {
                    name: self.detail_name.clone(),
                });
            }
            KeyCode::Char('p') => {
                // Pop agent output into new terminal
                let agent = self.detail_name.clone();
                let cmd = format!("aegis daemon follow {agent}");
                match crate::terminal::spawn_in_terminal(&cmd) {
                    Ok(()) => {
                        self.command_result = Some(format!("Opened '{agent}' in new terminal"));
                    }
                    Err(e) => {
                        self.command_result = Some(e);
                    }
                }
            }
            KeyCode::Char(':') => {
                self.enter_command_mode();
            }
            _ => {}
        }
    }

    /// Handle keys in input mode (typing text to send to agent).
    fn handle_input_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = false;
                self.input_buffer.clear();
                self.input_cursor = 0;
            }
            KeyCode::Enter => {
                if !self.input_buffer.is_empty() {
                    let cmd = DaemonCommand::SendToAgent {
                        name: self.detail_name.clone(),
                        text: self.input_buffer.clone(),
                    };
                    self.send_named_command(cmd);
                }
                self.input_mode = false;
                self.input_buffer.clear();
                self.input_cursor = 0;
            }
            KeyCode::Char(c) => {
                self.input_buffer.insert(self.input_cursor, c);
                self.input_cursor += 1;
            }
            KeyCode::Backspace => {
                if self.input_cursor > 0 {
                    self.input_cursor -= 1;
                    self.input_buffer.remove(self.input_cursor);
                }
            }
            KeyCode::Left => {
                self.input_cursor = self.input_cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                if self.input_cursor < self.input_buffer.len() {
                    self.input_cursor += 1;
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

    /// Enter command mode.
    fn enter_command_mode(&mut self) {
        self.command_mode = true;
        self.command_buffer.clear();
        self.command_cursor = 0;
        self.command_completions.clear();
        self.completion_idx = None;
        self.command_result = None;
        self.history_index = None;
    }

    /// Handle keys in command mode (: bar).
    fn handle_command_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.command_mode = false;
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
                self.command_mode = false;
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
                self.history_prev();
            }
            KeyCode::Down => {
                self.history_next();
            }
            KeyCode::Char(c) => {
                self.command_buffer.insert(self.command_cursor, c);
                self.command_cursor += 1;
                self.update_completions();
            }
            KeyCode::Backspace => {
                if self.command_cursor > 0 {
                    self.command_cursor -= 1;
                    self.command_buffer.remove(self.command_cursor);
                    self.update_completions();
                }
            }
            KeyCode::Left => {
                self.command_cursor = self.command_cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                if self.command_cursor < self.command_buffer.len() {
                    self.command_cursor += 1;
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
        self.command_completions = command::completions(&self.command_buffer, &agent_names);
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
        self.command_buffer = command::apply_completion(&self.command_buffer, &completion);
        self.command_cursor = self.command_buffer.len();
    }

    /// Cycle to the previous completion.
    fn cycle_completion_back(&mut self) {
        if self.command_completions.is_empty() {
            return;
        }
        let idx = match self.completion_idx {
            Some(0) | None => self.command_completions.len() - 1,
            Some(i) => i - 1,
        };
        self.completion_idx = Some(idx);
        let completion = self.command_completions[idx].clone();
        self.command_buffer = command::apply_completion(&self.command_buffer, &completion);
        self.command_cursor = self.command_buffer.len();
    }

    /// Navigate to previous command in history.
    fn history_prev(&mut self) {
        if self.command_history.is_empty() {
            return;
        }
        let idx = match self.history_index {
            Some(0) => 0, // already at oldest
            Some(i) => i - 1,
            None => self.command_history.len() - 1,
        };
        self.history_index = Some(idx);
        self.command_buffer = self.command_history[idx].clone();
        self.command_cursor = self.command_buffer.len();
    }

    /// Navigate to next command in history.
    fn history_next(&mut self) {
        match self.history_index {
            Some(i) if i + 1 < self.command_history.len() => {
                self.history_index = Some(i + 1);
                self.command_buffer = self.command_history[i + 1].clone();
                self.command_cursor = self.command_buffer.len();
            }
            Some(_) => {
                // Past the end of history -- clear to empty
                self.history_index = None;
                self.command_buffer.clear();
                self.command_cursor = 0;
            }
            None => {} // already at newest
        }
    }

    /// Execute a parsed command.
    fn execute_command(&mut self, input: &str) {
        match command::parse(input) {
            Ok(Some(cmd)) => self.dispatch_command(cmd),
            Ok(None) => {}
            Err(e) => {
                self.command_result = Some(e);
            }
        }
    }

    /// Dispatch a parsed FleetCommand.
    fn dispatch_command(&mut self, cmd: command::FleetCommand) {
        use command::FleetCommand;
        match cmd {
            FleetCommand::Add => {
                self.wizard = Some(AddAgentWizard::new());
                self.view = FleetView::AddAgent;
            }
            FleetCommand::Start { agent } => {
                self.send_named_command(DaemonCommand::StartAgent { name: agent });
            }
            FleetCommand::Stop { agent } => {
                self.send_named_command(DaemonCommand::StopAgent { name: agent });
            }
            FleetCommand::Restart { agent } => {
                self.send_named_command(DaemonCommand::RestartAgent { name: agent });
            }
            FleetCommand::Send { agent, text } => {
                self.send_named_command(DaemonCommand::SendToAgent { name: agent, text });
            }
            FleetCommand::Approve { agent } => {
                if let Some(request_id) = self.fetch_first_pending_id(&agent) {
                    let cmd = DaemonCommand::ApproveRequest {
                        name: agent,
                        request_id,
                    };
                    self.send_named_command(cmd);
                } else {
                    self.command_result = Some(format!("no pending prompts for '{agent}'"));
                }
            }
            FleetCommand::Deny { agent } => {
                if let Some(request_id) = self.fetch_first_pending_id(&agent) {
                    let cmd = DaemonCommand::DenyRequest {
                        name: agent,
                        request_id,
                    };
                    self.send_named_command(cmd);
                } else {
                    self.command_result = Some(format!("no pending prompts for '{agent}'"));
                }
            }
            FleetCommand::Nudge { agent, message } => {
                self.send_named_command(DaemonCommand::NudgeAgent { name: agent, message });
            }
            FleetCommand::Pop { agent } => {
                let cmd = format!("aegis daemon follow {agent}");
                match crate::terminal::spawn_in_terminal(&cmd) {
                    Ok(()) => {
                        self.command_result = Some(format!("Opened '{agent}' in new terminal"));
                    }
                    Err(e) => {
                        self.command_result = Some(e);
                    }
                }
            }
            FleetCommand::Monitor => {
                match crate::terminal::spawn_in_terminal("aegis monitor") {
                    Ok(()) => {
                        self.command_result = Some("Opened monitor in new terminal".into());
                    }
                    Err(e) => {
                        self.command_result = Some(e);
                    }
                }
            }
            FleetCommand::Follow { agent } => {
                self.detail_name = agent;
                self.detail_output.clear();
                self.detail_scroll = 0;
                self.detail_pending.clear();
                self.pending_selected = 0;
                self.focus_pending = false;
                self.detail_attention = false;
                self.view = FleetView::AgentDetail;
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
            }
            FleetCommand::Remove { agent } => {
                match crate::commands::daemon::remove_agent(&agent) {
                    Ok(()) => {
                        self.command_result = Some(format!("Removed '{agent}' from config and stopped in daemon."));
                        self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                    }
                    Err(e) => {
                        self.command_result = Some(format!("Failed to remove '{agent}': {e}"));
                    }
                }
            }
            FleetCommand::Config => {
                self.spawn_terminal("aegis daemon config edit", "Opened config in editor");
            }
            FleetCommand::Telegram => {
                self.spawn_terminal("aegis telegram status", "Opened Telegram status in new terminal");
            }
            FleetCommand::Status => {
                // Show status as command result
                let running = self.running_count();
                let total = self.agents.len();
                self.command_result = Some(format!(
                    "{running} running / {total} total, daemon PID {}, uptime {}",
                    self.daemon_pid,
                    format_uptime(self.daemon_uptime_secs),
                ));
            }
            FleetCommand::Help => {
                self.help_scroll = 0;
                self.view = FleetView::Help;
            }
            FleetCommand::Quit => {
                self.running = false;
            }
            FleetCommand::Logs => {
                self.spawn_terminal(
                    "aegis daemon logs --follow",
                    "Opened daemon logs in new terminal",
                );
            }
            FleetCommand::Pending { agent } => {
                // Switch to agent's detail view with focus on pending panel
                self.detail_name = agent;
                self.detail_output.clear();
                self.detail_scroll = 0;
                self.detail_pending.clear();
                self.pending_selected = 0;
                self.focus_pending = true;
                self.detail_attention = false;
                self.view = FleetView::AgentDetail;
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
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
            FleetCommand::Policy => {
                self.spawn_terminal("aegis policy list", "Opened policy list in new terminal");
            }
            FleetCommand::Report => {
                self.spawn_terminal("aegis report", "Opened compliance report in new terminal");
            }
            FleetCommand::List => {
                self.spawn_terminal("aegis list", "Opened config list in new terminal");
            }
            FleetCommand::Hook => {
                self.spawn_terminal("aegis hook install", "Installing hooks in new terminal");
            }
            FleetCommand::Use { name } => {
                match name {
                    Some(n) => self.spawn_terminal(
                        &format!("aegis use {n}"),
                        &format!("Switching to config '{n}'"),
                    ),
                    None => self.spawn_terminal(
                        "aegis use",
                        "Opened config picker in new terminal",
                    ),
                }
            }
            FleetCommand::Watch => {
                self.spawn_terminal("aegis watch", "Started directory watch in new terminal");
            }
            FleetCommand::Diff { session1, session2 } => {
                self.spawn_terminal(
                    &format!("aegis diff {session1} {session2}"),
                    "Opened session diff in new terminal",
                );
            }
            FleetCommand::Alerts => {
                self.spawn_terminal("aegis alerts list", "Opened alerts in new terminal");
            }
            FleetCommand::Setup => {
                self.spawn_terminal("aegis setup", "Running system checks in new terminal");
            }
            FleetCommand::Init => {
                self.spawn_terminal("aegis init", "Opened init wizard in new terminal");
            }
            FleetCommand::Goal { text } => {
                self.send_and_show_result(DaemonCommand::FleetGoal { goal: text });
            }
            FleetCommand::Context { agent, field, value } => {
                match (field, value) {
                    (Some(f), Some(v)) => {
                        let (role, agent_goal, context) = match f.as_str() {
                            "role" => (Some(v), None, None),
                            "goal" => (None, Some(v), None),
                            "context" => (None, None, Some(v)),
                            _ => {
                                self.command_result = Some(format!(
                                    "unknown field '{f}'. Use: role, goal, or context"
                                ));
                                return;
                            }
                        };
                        self.send_and_show_result(DaemonCommand::UpdateAgentContext {
                            name: agent,
                            role,
                            agent_goal,
                            context,
                        });
                    }
                    _ => {
                        self.send_context_query(&agent);
                    }
                }
            }
            FleetCommand::DaemonStart => {
                match crate::commands::daemon::start() {
                    Ok(()) => {
                        self.command_result = Some("Daemon starting...".into());
                        self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                    }
                    Err(e) => {
                        self.command_result = Some(format!("Failed to start daemon: {e}"));
                    }
                }
            }
            FleetCommand::DaemonStop => {
                if !self.connected {
                    self.command_result = Some("Daemon is not running.".into());
                } else {
                    match crate::commands::daemon::stop() {
                        Ok(()) => {
                            self.command_result = Some("Daemon shutdown requested.".into());
                            self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                        }
                        Err(e) => {
                            self.command_result = Some(format!("Failed to stop daemon: {e}"));
                        }
                    }
                }
            }
            FleetCommand::DaemonInit => {
                match crate::commands::daemon::init() {
                    Ok(()) => {
                        self.command_result = Some("Created daemon.toml.".into());
                    }
                    Err(e) => {
                        self.command_result = Some(format!("{e}"));
                    }
                }
            }
            FleetCommand::DaemonReload => {
                if !self.connected {
                    self.command_result = Some("Daemon is not running.".into());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::ReloadConfig) {
                        Ok(resp) => {
                            self.command_result = Some(resp.message);
                            self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
            }
            FleetCommand::DaemonRestart => {
                if !self.connected {
                    self.command_result = Some("Daemon is not running. Use :daemon start.".into());
                } else {
                    // Stop first, then start
                    let stop_result = crate::commands::daemon::stop();
                    match stop_result {
                        Ok(()) => {
                            // Brief pause for socket cleanup
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            match crate::commands::daemon::start() {
                                Ok(()) => {
                                    self.command_result = Some("Daemon restarting...".into());
                                    self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                                }
                                Err(e) => {
                                    self.command_result = Some(format!("Stopped, but failed to restart: {e}"));
                                }
                            }
                        }
                        Err(e) => {
                            self.command_result = Some(format!("Failed to stop daemon: {e}"));
                        }
                    }
                }
            }
            FleetCommand::DaemonStatus => {
                if !self.connected {
                    self.command_result = Some("Daemon is not running (offline mode).".into());
                } else {
                    let running = self.running_count();
                    let total = self.agents.len();
                    self.command_result = Some(format!(
                        "{running} running / {total} total, PID {}, uptime {}",
                        self.daemon_pid,
                        format_uptime(self.daemon_uptime_secs),
                    ));
                }
            }
        }
    }

    /// Send a command for the currently selected agent in overview.
    fn send_agent_command(&mut self, make_cmd: impl FnOnce(String) -> DaemonCommand) {
        if let Some(agent) = self.agents.get(self.agent_selected) {
            let name = agent.name.clone();
            let cmd = make_cmd(name);
            self.send_named_command(cmd);
        }
    }

    /// Send a command to the daemon.
    fn send_named_command(&mut self, cmd: DaemonCommand) {
        if let Some(client) = &self.client {
            match client.send(&cmd) {
                Ok(resp) if !resp.ok => {
                    self.last_error = Some(resp.message);
                }
                Err(e) => {
                    self.last_error = Some(e);
                }
                _ => {
                    // Force immediate re-poll after action
                    self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                }
            }
        }
    }

    /// Send a command to the daemon and show the response message as command_result.
    ///
    /// Unlike `send_named_command`, this captures the success message for display.
    fn send_and_show_result(&mut self, cmd: DaemonCommand) {
        if let Some(client) = &self.client {
            match client.send(&cmd) {
                Ok(resp) => {
                    if resp.ok {
                        self.command_result = Some(resp.message);
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
    }

    /// Query and display an agent's context fields.
    fn send_context_query(&mut self, agent: &str) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };
        match client.send(&DaemonCommand::GetAgentContext { name: agent.to_string() }) {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    let role = data["role"].as_str().unwrap_or("(none)");
                    let goal = data["agent_goal"].as_str().unwrap_or("(none)");
                    let context = data["context"].as_str().unwrap_or("(none)");
                    let task = data["task"].as_str().unwrap_or("(none)");
                    self.command_result = Some(format!(
                        "role={role}  goal={goal}  context={context}  task={task}"
                    ));
                }
            }
            Ok(resp) => {
                self.last_error = Some(resp.message);
            }
            Err(e) => {
                self.last_error = Some(e);
            }
        }
    }

    /// Fetch the first pending prompt's request_id for an agent.
    ///
    /// If we're in detail view for this agent, uses the cached `detail_pending`.
    /// Otherwise, makes a synchronous `ListPending` call to the daemon.
    fn fetch_first_pending_id(&self, agent: &str) -> Option<String> {
        // Use cached data if we're viewing this agent's detail
        if self.detail_name == agent {
            if let Some(p) = self.detail_pending.first() {
                return Some(p.request_id.clone());
            }
        }
        // Fetch on demand from daemon
        let client = self.client.as_ref()?;
        let cmd = DaemonCommand::ListPending { name: agent.to_string() };
        let resp = client.send(&cmd).ok()?;
        if !resp.ok {
            return None;
        }
        let data = resp.data?;
        let pending: Vec<PendingPromptSummary> = serde_json::from_value(data).ok()?;
        pending.first().map(|p| p.request_id.clone())
    }

    /// Spawn a command in a new terminal and set the result message.
    fn spawn_terminal(&mut self, cmd: &str, msg: &str) {
        match crate::terminal::spawn_in_terminal(cmd) {
            Ok(()) => self.command_result = Some(msg.into()),
            Err(e) => self.command_result = Some(e),
        }
    }

    /// Get the selected agent's name (if any).
    #[cfg(test)]
    fn selected_agent_name(&self) -> Option<&str> {
        self.agents.get(self.agent_selected).map(|a| a.name.as_str())
    }

    /// Count of running agents.
    pub fn running_count(&self) -> usize {
        self.agents
            .iter()
            .filter(|a| matches!(a.status, AgentStatus::Running { .. }))
            .count()
    }

    /// Visible output lines for the detail view, accounting for scroll.
    pub fn visible_output(&self, height: usize) -> Vec<&str> {
        if self.detail_output.is_empty() || height == 0 {
            return Vec::new();
        }
        let total = self.detail_output.len();
        let scroll = self.detail_scroll.min(total.saturating_sub(height));
        let end = total.saturating_sub(scroll);
        let start = end.saturating_sub(height);
        self.detail_output
            .iter()
            .skip(start)
            .take(end - start)
            .map(|s| s.as_str())
            .collect()
    }
}

/// Format seconds into a human-readable uptime string.
fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Run the fleet TUI, connecting to the daemon at the default socket path.
///
/// Works in both connected and disconnected modes. When the daemon is not
/// running, the TUI starts in offline mode and auto-reconnects when the
/// daemon becomes available (poll_daemon retries every POLL_INTERVAL_MS).
pub fn run_fleet_tui() -> Result<()> {
    let client = DaemonClient::default_path();
    run_fleet_tui_with_client(client)
}

/// Run the fleet TUI with a specific client (for testing).
pub fn run_fleet_tui_with_client(client: DaemonClient) -> Result<()> {
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
    let mut app = FleetApp::new(Some(client));

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

/// Internal event loop -- separated for testability.
fn run_event_loop(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    events: &EventHandler,
    app: &mut FleetApp,
) -> Result<()> {
    while app.running {
        terminal.draw(|f| ui::draw(f, app))?;

        match events.next()? {
            AppEvent::Key(key) => app.handle_key(key),
            AppEvent::Paste(text) => app.handle_paste(&text),
            AppEvent::Tick => {}
        }

        // Poll daemon on every iteration (poll_daemon rate-limits internally)
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

    fn make_app() -> FleetApp {
        let mut app = FleetApp::new(None);
        app.agents = vec![
            AgentSummary {
                name: "alpha".into(),
                status: AgentStatus::Running { pid: 100 },
                tool: "ClaudeCode".into(),
                working_dir: "/tmp/alpha".into(),
                role: None,
                restart_count: 0,
                pending_count: 0,
                attention_needed: false,
            },
            AgentSummary {
                name: "beta".into(),
                status: AgentStatus::Stopped { exit_code: 0 },
                tool: "Codex".into(),
                working_dir: "/tmp/beta".into(),
                role: None,
                restart_count: 1,
                pending_count: 0,
                attention_needed: false,
            },
            AgentSummary {
                name: "gamma".into(),
                status: AgentStatus::Failed { exit_code: 1, restart_count: 5 },
                tool: "ClaudeCode".into(),
                working_dir: "/tmp/gamma".into(),
                role: None,
                restart_count: 5,
                pending_count: 0,
                attention_needed: false,
            },
        ];
        app
    }

    #[test]
    fn initial_state() {
        let app = FleetApp::new(None);
        assert_eq!(app.view, FleetView::Overview);
        assert!(app.running);
        assert!(app.agents.is_empty());
        assert_eq!(app.agent_selected, 0);
        assert!(!app.connected);
    }

    #[test]
    fn overview_navigation() {
        let mut app = make_app();

        assert_eq!(app.agent_selected, 0);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.agent_selected, 1);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.agent_selected, 2);

        // Can't go past end
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.agent_selected, 2);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.agent_selected, 1);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.agent_selected, 0);

        // Can't go before start
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.agent_selected, 0);
    }

    #[test]
    fn arrow_keys_navigate() {
        let mut app = make_app();

        app.handle_key(press(KeyCode::Down));
        assert_eq!(app.agent_selected, 1);

        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.agent_selected, 0);
    }

    #[test]
    fn enter_drills_into_detail() {
        let mut app = make_app();
        app.agent_selected = 1;

        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.view, FleetView::AgentDetail);
        assert_eq!(app.detail_name, "beta");
    }

    #[test]
    fn esc_returns_to_overview() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.detail_name = "alpha".into();

        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.view, FleetView::Overview);
    }

    #[test]
    fn q_quits() {
        let mut app = make_app();
        assert!(app.running);

        app.handle_key(press(KeyCode::Char('q')));
        assert!(!app.running);
    }

    #[test]
    fn q_quits_from_detail() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;

        app.handle_key(press(KeyCode::Char('q')));
        assert!(!app.running);
    }

    #[test]
    fn running_count() {
        let app = make_app();
        assert_eq!(app.running_count(), 1); // only alpha is Running
    }

    #[test]
    fn selected_agent_name() {
        let mut app = make_app();
        assert_eq!(app.selected_agent_name(), Some("alpha"));
        app.agent_selected = 2;
        assert_eq!(app.selected_agent_name(), Some("gamma"));
    }

    #[test]
    fn selected_agent_name_empty() {
        let app = FleetApp::new(None);
        assert_eq!(app.selected_agent_name(), None);
    }

    #[test]
    fn visible_output_empty() {
        let app = FleetApp::new(None);
        assert!(app.visible_output(20).is_empty());
    }

    #[test]
    fn visible_output_basic() {
        let mut app = FleetApp::new(None);
        for i in 0..10 {
            app.detail_output.push_back(format!("line {i}"));
        }

        let lines = app.visible_output(5);
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "line 5");
        assert_eq!(lines[4], "line 9");
    }

    #[test]
    fn visible_output_scrolled() {
        let mut app = FleetApp::new(None);
        for i in 0..20 {
            app.detail_output.push_back(format!("line {i}"));
        }
        app.detail_scroll = 5;

        let lines = app.visible_output(10);
        assert_eq!(lines.len(), 10);
        assert_eq!(lines[0], "line 5");
        assert_eq!(lines[9], "line 14");
    }

    #[test]
    fn detail_scroll_keys() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        for i in 0..50 {
            app.detail_output.push_back(format!("line {i}"));
        }

        // k scrolls up (increases offset)
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.detail_scroll, 1);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.detail_scroll, 2);

        // j scrolls down (decreases offset)
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.detail_scroll, 1);

        // G jumps to bottom
        app.handle_key(press(KeyCode::Char('G')));
        assert_eq!(app.detail_scroll, 0);

        // g jumps to top
        app.handle_key(press(KeyCode::Char('g')));
        assert_eq!(app.detail_scroll, 49);
    }

    #[test]
    fn enter_on_empty_list_does_nothing() {
        let mut app = FleetApp::new(None);
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.view, FleetView::Overview);
    }

    #[test]
    fn j_on_empty_list_does_not_panic() {
        let mut app = FleetApp::new(None);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.agent_selected, 0);
    }

    #[test]
    fn key_release_ignored() {
        let mut app = make_app();
        let release = KeyEvent {
            code: KeyCode::Char('q'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: crossterm::event::KeyEventState::empty(),
        };
        app.handle_key(release);
        assert!(app.running, "release events should be ignored");
    }

    #[test]
    fn input_mode_enter_and_exit() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.detail_name = "alpha".into();

        // 'i' enters input mode
        app.handle_key(press(KeyCode::Char('i')));
        assert!(app.input_mode);
        assert!(app.input_buffer.is_empty());

        // Typing adds characters
        app.handle_key(press(KeyCode::Char('h')));
        app.handle_key(press(KeyCode::Char('i')));
        assert_eq!(app.input_buffer, "hi");
        assert_eq!(app.input_cursor, 2);

        // Esc exits input mode
        app.handle_key(press(KeyCode::Esc));
        assert!(!app.input_mode);
        assert!(app.input_buffer.is_empty());
    }

    #[test]
    fn input_mode_cursor_movement() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.detail_name = "alpha".into();
        app.input_mode = true;

        // Type "hello"
        for c in "hello".chars() {
            app.handle_key(press(KeyCode::Char(c)));
        }
        assert_eq!(app.input_cursor, 5);

        // Left moves cursor back
        app.handle_key(press(KeyCode::Left));
        assert_eq!(app.input_cursor, 4);

        // Home goes to start
        app.handle_key(press(KeyCode::Home));
        assert_eq!(app.input_cursor, 0);

        // End goes to end
        app.handle_key(press(KeyCode::End));
        assert_eq!(app.input_cursor, 5);

        // Right at end doesn't overflow
        app.handle_key(press(KeyCode::Right));
        assert_eq!(app.input_cursor, 5);
    }

    #[test]
    fn input_mode_backspace() {
        let mut app = make_app();
        app.input_mode = true;

        app.handle_key(press(KeyCode::Char('a')));
        app.handle_key(press(KeyCode::Char('b')));
        app.handle_key(press(KeyCode::Char('c')));
        assert_eq!(app.input_buffer, "abc");

        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.input_buffer, "ab");
        assert_eq!(app.input_cursor, 2);

        // Backspace at start does nothing
        app.input_cursor = 0;
        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.input_buffer, "ab");
    }

    #[test]
    fn input_mode_enter_clears() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.detail_name = "alpha".into();
        app.input_mode = true;

        app.handle_key(press(KeyCode::Char('x')));
        app.handle_key(press(KeyCode::Enter));

        // Enter exits input mode and clears buffer
        assert!(!app.input_mode);
        assert!(app.input_buffer.is_empty());
        assert_eq!(app.input_cursor, 0);
    }

    #[test]
    fn input_mode_blocks_quit() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.input_mode = true;

        // 'q' in input mode should type 'q', not quit
        app.handle_key(press(KeyCode::Char('q')));
        assert!(app.running);
        assert_eq!(app.input_buffer, "q");
    }

    #[test]
    fn tab_toggles_focus() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.detail_pending = vec![PendingPromptSummary {
            request_id: "abc".into(),
            raw_prompt: "Allow?".into(),
            age_secs: 5,
        }];

        assert!(!app.focus_pending);
        app.handle_key(press(KeyCode::Tab));
        assert!(app.focus_pending);
        app.handle_key(press(KeyCode::Tab));
        assert!(!app.focus_pending);
    }

    #[test]
    fn tab_no_toggle_when_no_pending() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;

        app.handle_key(press(KeyCode::Tab));
        assert!(!app.focus_pending);
    }

    #[test]
    fn jk_navigates_pending_when_focused() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.focus_pending = true;
        app.detail_pending = vec![
            PendingPromptSummary {
                request_id: "a".into(),
                raw_prompt: "one".into(),
                age_secs: 1,
            },
            PendingPromptSummary {
                request_id: "b".into(),
                raw_prompt: "two".into(),
                age_secs: 2,
            },
        ];

        assert_eq!(app.pending_selected, 0);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.pending_selected, 1);

        // Can't go past end
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.pending_selected, 1);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.pending_selected, 0);
    }

    #[test]
    fn enter_drills_resets_pending_state() {
        let mut app = make_app();
        app.detail_pending = vec![PendingPromptSummary {
            request_id: "old".into(),
            raw_prompt: "stale".into(),
            age_secs: 100,
        }];
        app.focus_pending = true;
        app.detail_attention = true;

        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.view, FleetView::AgentDetail);
        assert!(app.detail_pending.is_empty());
        assert!(!app.focus_pending);
        assert!(!app.detail_attention);
    }

    // -- Command mode tests --

    #[test]
    fn colon_enters_command_mode_from_overview() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char(':')));
        assert!(app.command_mode);
        assert!(app.command_buffer.is_empty());
    }

    #[test]
    fn colon_enters_command_mode_from_detail() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.handle_key(press(KeyCode::Char(':')));
        assert!(app.command_mode);
    }

    #[test]
    fn command_mode_esc_exits() {
        let mut app = make_app();
        app.command_mode = true;
        app.command_buffer = "start".into();

        app.handle_key(press(KeyCode::Esc));
        assert!(!app.command_mode);
        assert!(app.command_buffer.is_empty());
    }

    #[test]
    fn command_mode_typing() {
        let mut app = make_app();
        app.command_mode = true;

        app.handle_key(press(KeyCode::Char('s')));
        app.handle_key(press(KeyCode::Char('t')));
        assert_eq!(app.command_buffer, "st");
        assert_eq!(app.command_cursor, 2);
    }

    #[test]
    fn command_mode_backspace() {
        let mut app = make_app();
        app.command_mode = true;
        app.command_buffer = "abc".into();
        app.command_cursor = 3;

        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.command_buffer, "ab");
    }

    #[test]
    fn command_mode_enter_executes() {
        let mut app = make_app();
        app.command_mode = true;
        app.command_buffer = "quit".into();
        app.command_cursor = 4;

        app.handle_key(press(KeyCode::Enter));
        assert!(!app.command_mode);
        assert!(!app.running);
    }

    #[test]
    fn command_mode_enter_saves_history() {
        let mut app = make_app();
        app.command_mode = true;
        app.command_buffer = "status".into();
        app.command_cursor = 6;

        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.command_history, vec!["status"]);
    }

    #[test]
    fn command_mode_history_navigation() {
        let mut app = make_app();
        app.command_history = vec!["first".into(), "second".into()];
        app.command_mode = true;

        // Up goes to most recent
        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.command_buffer, "second");

        // Up again goes to oldest
        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.command_buffer, "first");

        // Down goes forward
        app.handle_key(press(KeyCode::Down));
        assert_eq!(app.command_buffer, "second");

        // Down past end clears
        app.handle_key(press(KeyCode::Down));
        assert!(app.command_buffer.is_empty());
    }

    #[test]
    fn command_mode_follow_switches_view() {
        let mut app = make_app();
        app.command_mode = true;
        app.command_buffer = "follow alpha".into();
        app.command_cursor = 12;

        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.view, FleetView::AgentDetail);
        assert_eq!(app.detail_name, "alpha");
    }

    #[test]
    fn command_mode_status_shows_result() {
        let mut app = make_app();
        app.daemon_pid = 1234;
        app.command_mode = true;
        app.command_buffer = "status".into();
        app.command_cursor = 6;

        app.handle_key(press(KeyCode::Enter));
        assert!(app.command_result.is_some());
        assert!(app.command_result.as_ref().unwrap().contains("1234"));
    }

    #[test]
    fn command_mode_unknown_shows_error() {
        let mut app = make_app();
        app.command_mode = true;
        app.command_buffer = "bogus".into();
        app.command_cursor = 5;

        app.handle_key(press(KeyCode::Enter));
        assert!(app.command_result.as_ref().unwrap().contains("unknown command"));
    }

    #[test]
    fn command_result_clears_on_next_key() {
        let mut app = make_app();
        app.command_result = Some("old result".into());

        // Any key clears the result
        app.handle_key(press(KeyCode::Char('j')));
        assert!(app.command_result.is_none());
    }

    #[test]
    fn command_mode_blocks_quit() {
        let mut app = make_app();
        app.command_mode = true;

        app.handle_key(press(KeyCode::Char('q')));
        assert!(app.running, "q in command mode should type 'q', not quit");
        assert_eq!(app.command_buffer, "q");
    }

    #[test]
    fn help_command_opens_help_view() {
        let mut app = make_app();
        app.command_mode = true;
        app.command_buffer = "help".into();
        app.command_cursor = 4;

        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.view, FleetView::Help);
        assert_eq!(app.help_scroll, 0);
    }

    #[test]
    fn help_view_scroll_and_exit() {
        let mut app = make_app();
        app.view = FleetView::Help;
        app.help_scroll = 0;

        // Scroll down
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.help_scroll, 1);

        // Scroll up
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.help_scroll, 0);

        // Exit with Esc
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.view, FleetView::Overview);
    }

    #[test]
    fn help_view_q_exits() {
        let mut app = make_app();
        app.view = FleetView::Help;

        app.handle_key(press(KeyCode::Char('q')));
        assert_eq!(app.view, FleetView::Overview);
        assert!(app.running, "q in help view should go back, not quit");
    }

    fn ctrl_c() -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::empty(),
        }
    }

    #[test]
    fn ctrl_c_quits_from_overview() {
        let mut app = make_app();
        app.handle_key(ctrl_c());
        assert!(!app.running);
    }

    #[test]
    fn ctrl_c_exits_command_mode() {
        let mut app = make_app();
        app.command_mode = true;
        app.command_buffer = "some text".into();

        app.handle_key(ctrl_c());
        assert!(!app.command_mode);
        assert!(app.command_buffer.is_empty());
        assert!(app.running, "Ctrl+C in command mode should exit mode, not quit");
    }

    #[test]
    fn ctrl_c_exits_input_mode() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.input_mode = true;
        app.input_buffer = "some text".into();

        app.handle_key(ctrl_c());
        assert!(!app.input_mode);
        assert!(app.input_buffer.is_empty());
        assert!(app.running, "Ctrl+C in input mode should exit mode, not quit");
    }
}
