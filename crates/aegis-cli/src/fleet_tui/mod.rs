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
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_control::daemon::{
    AgentSummary, CaptureSessionRequest, CaptureSessionStarted, DaemonClient, DaemonCommand,
    ParityDiffReport, ParityStatusReport, ParityVerifyReport, PendingPromptSummary,
    RuntimeCapabilities, SessionHistory, SessionInfo, SpawnSubagentRequest, ToolActionOutcome,
    ToolBatchOutcome,
};
use aegis_toolkit::contract::ToolAction;
use aegis_types::AgentStatus;

use self::event::{AppEvent, EventHandler};
use self::wizard::AddAgentWizard;
use crate::tui_utils::delete_word_backward_pos;

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
    /// Runtime capability/mediation profile for the detail agent.
    pub detail_runtime: Option<RuntimeCapabilities>,

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
    /// When the command result was set (for auto-clear after timeout).
    pub command_result_at: Option<Instant>,

    // -- Fleet goal --
    /// Fleet-wide goal (fetched from daemon).
    pub fleet_goal: Option<String>,

    // -- Wizard --
    /// Add-agent wizard (active when view == AddAgent).
    pub wizard: Option<AddAgentWizard>,

    // -- Help view --
    /// Scroll offset for help text.
    pub help_scroll: usize,
    /// Context editor state for multi-line edits.
    pub context_editor: Option<ContextEditor>,
    /// Whether chat-first auto-focus has already run.
    pub chat_bootstrapped: bool,

    // -- Internal --
    /// Daemon client for sending commands.
    client: Option<DaemonClient>,
    /// When we last polled the daemon.
    last_poll: Instant,
}

#[derive(Debug, Clone)]
pub struct ContextEditor {
    pub agent: String,
    pub field: String,
    pub buffer: String,
    pub cursor: usize,
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
            detail_runtime: None,
            command_mode: false,
            command_buffer: String::new(),
            command_cursor: 0,
            command_history: Vec::new(),
            history_index: None,
            command_completions: Vec::new(),
            completion_idx: None,
            command_result: None,
            command_result_at: None,
            fleet_goal: None,
            wizard: None,
            help_scroll: 0,
            context_editor: None,
            chat_bootstrapped: false,
            client,
            last_poll: Instant::now() - std::time::Duration::from_secs(10), // force immediate poll
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
        // Auto-clear stale command results on every tick, not just key events
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

        // Ping to get daemon metadata
        match client.send(&DaemonCommand::Ping) {
            Ok(resp) if resp.ok => {
                self.connected = true;
                self.last_error = None;
                if let Some(data) = resp.data {
                    self.daemon_uptime_secs = data["uptime_secs"].as_u64().unwrap_or(0);
                    self.daemon_pid = data["daemon_pid"]
                        .as_u64()
                        .unwrap_or(0)
                        .try_into()
                        .unwrap_or(0);
                }
            }
            Ok(resp) => {
                self.connected = false;
                self.daemon_pid = 0;
                self.daemon_uptime_secs = 0;
                self.last_error = Some(resp.message);
            }
            Err(e) => {
                self.connected = false;
                self.daemon_pid = 0;
                self.daemon_uptime_secs = 0;
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
        let mut agents_updated = false;

        match client.send(&DaemonCommand::ListAgents) {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    match serde_json::from_value::<Vec<AgentSummary>>(data) {
                        Ok(agents) => {
                            self.agents = agents;
                            // Clamp selection to valid range
                            if self.agents.is_empty() {
                                self.agent_selected = 0;
                            } else if self.agent_selected >= self.agents.len() {
                                self.agent_selected = self.agents.len() - 1;
                            }
                            agents_updated = true;
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

        // Fetch fleet goal
        match client.send(&DaemonCommand::FleetGoal { goal: None }) {
            Ok(resp) if resp.ok => {
                self.fleet_goal = resp
                    .data
                    .and_then(|d| d["goal"].as_str().map(|s| s.to_string()))
                    .filter(|s| !s.is_empty());
            }
            _ => {} // Non-critical, don't overwrite errors
        }

        if agents_updated {
            self.maybe_open_chat_first();
        }
    }

    /// Auto-focus orchestrator detail once to make chat the default workflow.
    fn maybe_open_chat_first(&mut self) {
        if self.chat_bootstrapped || self.view != FleetView::Overview || !self.connected {
            return;
        }
        if let Some(name) = self
            .agents
            .iter()
            .find(|a| a.is_orchestrator)
            .map(|a| a.name.clone())
        {
            self.open_agent_detail(name.clone(), false);
            self.set_result(format!("Chat focused on orchestrator '{name}'"));
            self.chat_bootstrapped = true;
        }
    }

    /// Switch into agent detail view and optionally focus pending panel.
    fn open_agent_detail(&mut self, agent: String, focus_pending: bool) {
        self.detail_name = agent;
        self.detail_output.clear();
        self.detail_scroll = 0;
        self.detail_pending.clear();
        self.pending_selected = 0;
        self.focus_pending = focus_pending;
        self.detail_attention = false;
        self.detail_runtime = None;
        self.input_mode = true;
        self.input_buffer.clear();
        self.input_cursor = 0;
        self.view = FleetView::AgentDetail;
        self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
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
                    match serde_json::from_value::<Vec<String>>(data) {
                        Ok(lines) => {
                            self.detail_output.clear();
                            for line in lines {
                                self.detail_output.push_back(line);
                            }
                            // Clamp scroll if output shrank
                            let max = self.detail_output.len().saturating_sub(1);
                            if self.detail_scroll > max {
                                self.detail_scroll = max;
                            }
                        }
                        Err(e) => {
                            self.last_error = Some(format!("failed to parse agent output: {e}"));
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
                    match serde_json::from_value::<Vec<PendingPromptSummary>>(data) {
                        Ok(pending) => {
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
                        Err(e) => {
                            self.last_error = Some(format!("failed to parse pending prompts: {e}"));
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

        // Fetch runtime capability profile for the detail agent.
        let caps_cmd = DaemonCommand::RuntimeCapabilities {
            name: self.detail_name.clone(),
        };
        match client.send(&caps_cmd) {
            Ok(resp) if resp.ok => {
                self.detail_runtime = resp
                    .data
                    .and_then(|d| serde_json::from_value::<RuntimeCapabilities>(d).ok());
            }
            _ => {
                self.detail_runtime = None;
            }
        }
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Only handle key press events (not release/repeat)
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Ctrl+C: cancel modal modes, or quit
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if self.command_mode {
                self.command_mode = false;
                self.command_buffer.clear();
                self.command_cursor = 0;
                self.command_completions.clear();
                self.completion_idx = None;
            } else if self.context_editor.is_some() {
                self.context_editor = None;
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

        self.clear_stale_result();

        // Input mode intercepts all keys
        if self.input_mode {
            self.handle_input_key(key);
            return;
        }

        if self.context_editor.is_some() {
            self.handle_context_editor_key(key);
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
            let cleaned = text.replace(['\n', '\r'], " ");
            self.command_buffer
                .insert_str(self.command_cursor, &cleaned);
            self.command_cursor += cleaned.len();
            self.update_completions();
            return;
        }
        // Route paste to input mode if active
        if self.input_mode {
            let cleaned = text.replace(['\n', '\r'], " ");
            self.input_buffer.insert_str(self.input_cursor, &cleaned);
            self.input_cursor += cleaned.len();
            return;
        }
        if let Some(ref mut editor) = self.context_editor {
            let cleaned = text.replace('\r', "");
            editor.buffer.insert_str(editor.cursor, &cleaned);
            editor.cursor += cleaned.len();
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
                    self.open_agent_detail(agent.name.clone(), false);
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
            KeyCode::Tab => {
                // Jump to next agent with pending prompts (wrap around)
                self.jump_to_next_attention();
            }
            KeyCode::Char('?') => {
                self.help_scroll = 0;
                self.view = FleetView::Help;
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
            KeyCode::PageDown => {
                self.help_scroll = (self.help_scroll + 20).min(help_lines.saturating_sub(1));
            }
            KeyCode::PageUp => {
                self.help_scroll = self.help_scroll.saturating_sub(20);
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.help_scroll = help_lines.saturating_sub(1);
            }
            KeyCode::Char('g') | KeyCode::Home => {
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
                    self.set_result(format!(
                        "Added '{name}' to daemon.toml. Start daemon with :daemon start."
                    ));
                }
                Err(e) => {
                    self.set_result(format!("Failed to add agent: {e}"));
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
                dashboard: Default::default(),
                alerts: vec![],
                agents: vec![],
                channel: None,
                toolkit: Default::default(),
                memory: Default::default(),
                cron: Default::default(),
                plugins: Default::default(),
                aliases: Default::default(),
            }
        };

        if config.agents.iter().any(|a| a.name == name) {
            anyhow::bail!("agent '{name}' already exists in config");
        }

        if !agent.working_dir.is_dir() {
            anyhow::bail!(
                "working directory does not exist: {}",
                agent.working_dir.display()
            );
        }

        config.agents.push(agent);
        let toml_str = config.to_toml()?;

        // Atomic write: write to temp file, then rename for crash safety
        let tmp_path = config_path.with_extension("toml.tmp");
        std::fs::write(&tmp_path, &toml_str)?;
        std::fs::rename(&tmp_path, &config_path)?;

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
                self.view = FleetView::Overview;
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
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
                    let max = self.detail_output.len().saturating_sub(1);
                    self.detail_scroll = (self.detail_scroll + 1).min(max);
                }
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.detail_scroll = 0; // bottom
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.detail_scroll = self.detail_output.len().saturating_sub(1);
            }
            KeyCode::PageUp => {
                if self.focus_pending {
                    self.pending_selected = 0;
                } else {
                    let max = self.detail_output.len().saturating_sub(1);
                    self.detail_scroll = (self.detail_scroll + 20).min(max);
                }
            }
            KeyCode::PageDown => {
                if self.focus_pending {
                    if !self.detail_pending.is_empty() {
                        self.pending_selected = self.detail_pending.len() - 1;
                    }
                } else {
                    self.detail_scroll = self.detail_scroll.saturating_sub(20);
                }
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
                    self.send_and_show_result(cmd);
                } else {
                    self.set_result("No pending prompts to approve");
                }
            }
            KeyCode::Char('d') => {
                // Deny selected pending prompt
                if let Some(pending) = self.detail_pending.get(self.pending_selected) {
                    let cmd = DaemonCommand::DenyRequest {
                        name: self.detail_name.clone(),
                        request_id: pending.request_id.clone(),
                    };
                    self.send_and_show_result(cmd);
                } else {
                    self.set_result("No pending prompts to deny");
                }
            }
            KeyCode::Char('n') => {
                // Nudge stalled agent
                let cmd = DaemonCommand::NudgeAgent {
                    name: self.detail_name.clone(),
                    message: None,
                };
                self.send_and_show_result(cmd);
            }
            KeyCode::Tab => {
                // Toggle focus between output and pending panel
                if !self.detail_pending.is_empty() {
                    self.focus_pending = !self.focus_pending;
                }
            }
            KeyCode::Char('s') => {
                self.send_and_show_result(DaemonCommand::StartAgent {
                    name: self.detail_name.clone(),
                });
            }
            KeyCode::Char('x') => {
                self.send_and_show_result(DaemonCommand::StopAgent {
                    name: self.detail_name.clone(),
                });
            }
            KeyCode::Char('r') => {
                self.send_and_show_result(DaemonCommand::RestartAgent {
                    name: self.detail_name.clone(),
                });
            }
            KeyCode::Char('p') => {
                // Pop agent into new terminal (tmux attach if available)
                let agent = self.detail_name.clone();
                let cmd = self
                    .agents
                    .iter()
                    .find(|a| a.name == agent)
                    .and_then(|a| a.attach_command.as_ref())
                    .map(|parts| parts.join(" "))
                    .unwrap_or_else(|| format!("aegis daemon follow {agent}"));
                self.spawn_terminal(&cmd, &format!("Opened '{agent}' in new terminal"));
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
            KeyCode::Char(':') if self.input_buffer.is_empty() => {
                self.enter_command_mode();
            }
            KeyCode::Enter => {
                if !self.input_buffer.is_empty() {
                    let cmd = DaemonCommand::SendToAgent {
                        name: self.detail_name.clone(),
                        text: self.input_buffer.clone(),
                    };
                    self.send_named_command(cmd);
                }
                // Enter submits the draft and keeps chat input mode active.
                self.input_buffer.clear();
                self.input_cursor = 0;
            }
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

    fn handle_context_editor_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.context_editor = None;
            }
            KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let (agent, field, buffer) = match self.context_editor.as_ref() {
                    Some(editor) => (
                        editor.agent.clone(),
                        editor.field.clone(),
                        editor.buffer.clone(),
                    ),
                    None => return,
                };
                let (role, agent_goal, context, task) = match field.as_str() {
                    "role" => (Some(buffer), None, None, None),
                    "goal" => (None, Some(buffer), None, None),
                    "context" => (None, None, Some(buffer), None),
                    "task" => (None, None, None, Some(buffer)),
                    _ => (None, None, None, None),
                };
                if role.is_none() && agent_goal.is_none() && context.is_none() && task.is_none() {
                    self.last_error = Some(format!(
                        "unknown field '{}'. Use: role, goal, context, or task",
                        field
                    ));
                } else {
                    self.send_and_show_result(DaemonCommand::UpdateAgentContext {
                        name: agent,
                        role,
                        agent_goal,
                        context,
                        task,
                    });
                }
                self.context_editor = None;
            }
            KeyCode::Enter => {
                if let Some(editor) = self.context_editor.as_mut() {
                    editor.buffer.insert(editor.cursor, '\n');
                    editor.cursor += 1;
                }
            }
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => match c {
                'a' => {
                    if let Some(editor) = self.context_editor.as_mut() {
                        editor.cursor = 0;
                    }
                }
                'e' => {
                    if let Some(editor) = self.context_editor.as_mut() {
                        editor.cursor = editor.buffer.len();
                    }
                }
                'u' => {
                    if let Some(editor) = self.context_editor.as_mut() {
                        editor.buffer.drain(..editor.cursor);
                        editor.cursor = 0;
                    }
                }
                'w' => {
                    if let Some(editor) = self.context_editor.as_mut() {
                        if editor.cursor > 0 {
                            let new_pos = delete_word_backward_pos(&editor.buffer, editor.cursor);
                            editor.buffer.drain(new_pos..editor.cursor);
                            editor.cursor = new_pos;
                        }
                    }
                }
                _ => {}
            },
            KeyCode::Char(c) => {
                if let Some(editor) = self.context_editor.as_mut() {
                    editor.buffer.insert(editor.cursor, c);
                    editor.cursor += c.len_utf8();
                }
            }
            KeyCode::Backspace => {
                if let Some(editor) = self.context_editor.as_mut() {
                    if editor.cursor > 0 {
                        let prev = editor.buffer[..editor.cursor]
                            .char_indices()
                            .next_back()
                            .map(|(i, _)| i)
                            .unwrap_or(0);
                        editor.buffer.remove(prev);
                        editor.cursor = prev;
                    }
                }
            }
            KeyCode::Left => {
                if let Some(editor) = self.context_editor.as_mut() {
                    if editor.cursor > 0 {
                        editor.cursor = editor.buffer[..editor.cursor]
                            .char_indices()
                            .next_back()
                            .map(|(i, _)| i)
                            .unwrap_or(0);
                    }
                }
            }
            KeyCode::Right => {
                if let Some(editor) = self.context_editor.as_mut() {
                    if editor.cursor < editor.buffer.len() {
                        editor.cursor = editor.buffer[editor.cursor..]
                            .char_indices()
                            .nth(1)
                            .map(|(i, _)| editor.cursor + i)
                            .unwrap_or(editor.buffer.len());
                    }
                }
            }
            KeyCode::Delete => {
                if let Some(editor) = self.context_editor.as_mut() {
                    if editor.cursor < editor.buffer.len() {
                        editor.buffer.remove(editor.cursor);
                    }
                }
            }
            KeyCode::Home => {
                if let Some(editor) = self.context_editor.as_mut() {
                    editor.cursor = 0;
                }
            }
            KeyCode::End => {
                if let Some(editor) = self.context_editor.as_mut() {
                    editor.cursor = editor.buffer.len();
                }
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
        self.command_result_at = None;
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
                self.set_result(e);
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
            FleetCommand::Subagent { parent, name } => {
                if !self.agent_exists(&parent) {
                    self.set_result(format!("unknown parent agent: '{parent}'"));
                } else {
                    self.send_and_show_result(DaemonCommand::SpawnSubagent {
                        request: SpawnSubagentRequest {
                            parent,
                            name,
                            role: None,
                            task: None,
                            depth_limit: None,
                            start: true,
                        },
                    });
                    self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
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
            FleetCommand::Send { agent, text } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.send_and_show_result(DaemonCommand::SendToAgent { name: agent, text });
                }
            }
            FleetCommand::SessionList => {
                if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::SessionList) {
                        Ok(resp) if resp.ok => {
                            if let Some(data) = resp.data {
                                match serde_json::from_value::<Vec<SessionInfo>>(data) {
                                    Ok(list) => {
                                        if list.is_empty() {
                                            self.set_result("No sessions available");
                                        } else {
                                            let mut labels: Vec<String> = list
                                                .iter()
                                                .map(|s| s.session_key.clone())
                                                .collect();
                                            labels.sort();
                                            let shown: Vec<String> =
                                                labels.iter().take(3).cloned().collect();
                                            let suffix = if labels.len() > 3 {
                                                format!(" (+{})", labels.len() - 3)
                                            } else {
                                                String::new()
                                            };
                                            self.set_result(format!(
                                                "Sessions: {}{}",
                                                shown.join(", "),
                                                suffix
                                            ));
                                        }
                                    }
                                    Err(e) => self
                                        .set_result(format!("failed to parse session list: {e}")),
                                }
                            }
                        }
                        Ok(resp) => self.set_result(format!("failed: {}", resp.message)),
                        Err(e) => self.set_result(format!("failed to list sessions: {e}")),
                    }
                }
            }
            FleetCommand::SessionHistory { session_key, lines } => {
                if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::SessionHistory {
                        session_key: session_key.clone(),
                        lines,
                    }) {
                        Ok(resp) if resp.ok => {
                            if let Some(data) = resp.data {
                                match serde_json::from_value::<SessionHistory>(data) {
                                    Ok(history) => {
                                        if let Some(agent) =
                                            Self::session_agent_name(&history.session_key)
                                        {
                                            self.open_agent_detail(agent, false);
                                            self.detail_output.clear();
                                            for line in history.lines {
                                                self.detail_output.push_back(line);
                                            }
                                            self.detail_scroll = 0;
                                        }
                                        self.set_result(format!(
                                            "Loaded session history for {}",
                                            history.session_key
                                        ));
                                    }
                                    Err(e) => self.set_result(format!(
                                        "failed to parse session history: {e}"
                                    )),
                                }
                            }
                        }
                        Ok(resp) => self.set_result(format!("failed: {}", resp.message)),
                        Err(e) => self.set_result(format!("failed to fetch history: {e}")),
                    }
                }
            }
            FleetCommand::SessionSend { session_key, text } => {
                if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else {
                    self.send_and_show_result(DaemonCommand::SessionSend { session_key, text });
                }
            }
            FleetCommand::Approve { agent } => {
                if let Some(request_id) = self.fetch_first_pending_id(&agent) {
                    let cmd = DaemonCommand::ApproveRequest {
                        name: agent,
                        request_id,
                    };
                    self.send_and_show_result(cmd);
                } else {
                    self.set_result(format!("no pending prompts for '{agent}'"));
                }
            }
            FleetCommand::Deny { agent } => {
                if let Some(request_id) = self.fetch_first_pending_id(&agent) {
                    let cmd = DaemonCommand::DenyRequest {
                        name: agent,
                        request_id,
                    };
                    self.send_and_show_result(cmd);
                } else {
                    self.set_result(format!("no pending prompts for '{agent}'"));
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
            FleetCommand::Pop { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    // Use the tmux attach command if available, otherwise fall back to follow
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
            FleetCommand::Dashboard => {
                self.spawn_terminal(
                    "aegis daemon dashboard --open",
                    "Opened dashboard in browser",
                );
            }
            FleetCommand::Follow { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.open_agent_detail(agent, false);
                }
            }
            FleetCommand::Chat { agent } => {
                if let Some(agent) = agent {
                    if !self.agent_exists(&agent) {
                        self.set_result(format!("unknown agent: '{agent}'"));
                    } else {
                        self.open_agent_detail(agent, false);
                    }
                } else if let Some(name) = self
                    .agents
                    .iter()
                    .find(|a| a.is_orchestrator)
                    .map(|a| a.name.clone())
                {
                    self.open_agent_detail(name, false);
                } else if let Some(agent) = self.agents.get(self.agent_selected) {
                    self.open_agent_detail(agent.name.clone(), false);
                } else {
                    self.set_result("No agents available to open chat");
                }
            }
            FleetCommand::Remove { agent } => {
                if self.connected {
                    // Atomic removal via daemon: stops agent, removes from fleet, persists config
                    self.send_and_show_result(DaemonCommand::RemoveAgent { name: agent });
                    self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                } else {
                    // Offline: edit daemon.toml directly
                    match crate::commands::daemon::remove_agent_quiet(&agent) {
                        Ok(msg) => {
                            self.set_result(msg);
                        }
                        Err(e) => {
                            self.last_error = Some(format!("Failed to remove '{agent}': {e}"));
                        }
                    }
                }
            }
            FleetCommand::Config => {
                self.spawn_terminal("aegis daemon config edit", "Opened config in editor");
            }
            FleetCommand::Telegram => {
                use aegis_types::daemon::daemon_config_path;
                use aegis_types::daemon::DaemonConfig;
                let config_path = daemon_config_path();
                let status = if !config_path.exists() {
                    "Telegram: not configured. Run :telegram setup to configure.".to_string()
                } else {
                    match std::fs::read_to_string(&config_path)
                        .ok()
                        .and_then(|c| DaemonConfig::from_toml(&c).ok())
                    {
                        Some(cfg) => match cfg.channel {
                            Some(aegis_types::config::ChannelConfig::Telegram(tg)) => {
                                let token_preview =
                                    crate::tui_utils::truncate_str(&tg.bot_token, 13);
                                format!(
                                    "Telegram: configured (token: {token_preview}, chat: {})",
                                    tg.chat_id
                                )
                            }
                            Some(aegis_types::config::ChannelConfig::Slack(slack)) => {
                                format!(
                                    "Telegram: disabled (Slack configured for channel {})",
                                    slack.channel_id
                                )
                            }
                            Some(_) => {
                                "Telegram: disabled (other channel type active)".to_string()
                            }
                            None => "Telegram: not configured. Run :telegram setup to configure."
                                .to_string(),
                        },
                        None => "Telegram: failed to read daemon.toml".to_string(),
                    }
                };
                self.set_result(status);
            }
            FleetCommand::TelegramSetup => {
                self.spawn_terminal("aegis telegram setup", "Opened Telegram setup wizard");
            }
            FleetCommand::TelegramDisable => match crate::commands::telegram::disable_quiet() {
                Ok(msg) => self.set_result(msg),
                Err(e) => {
                    self.last_error = Some(format!("Failed to disable Telegram: {e}"));
                }
            },
            FleetCommand::Status => {
                // Show status as command result
                let running = self.running_count();
                let total = self.agents.len();
                self.set_result(format!(
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
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else {
                    self.open_agent_detail(agent, true);
                }
            }
            FleetCommand::Capabilities { agent } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::RuntimeCapabilities {
                        name: agent.clone(),
                    }) {
                        Ok(resp) if resp.ok => {
                            if let Some(data) = resp.data {
                                match serde_json::from_value::<RuntimeCapabilities>(data) {
                                    Ok(caps) => {
                                        self.set_result(format!(
                                            "{agent}: mediation={} bridge={} compliance={} headless={} auth={} ready={} ({})",
                                            caps.mediation_mode,
                                            caps.hook_bridge,
                                            caps.compliance_mode,
                                            caps.headless,
                                            caps.auth_mode,
                                            caps.auth_ready,
                                            caps.mediation_note
                                        ));
                                    }
                                    Err(e) => self.set_result(format!(
                                        "failed to parse capabilities for '{agent}': {e}"
                                    )),
                                }
                            }
                        }
                        Ok(resp) => self.set_result(format!("failed: {}", resp.message)),
                        Err(e) => self.set_result(format!("failed to query capabilities: {e}")),
                    }
                }
            }
            FleetCommand::ParityStatus => {
                if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::ParityStatus) {
                        Ok(resp) if resp.ok => {
                            if let Some(data) = resp.data {
                                match serde_json::from_value::<ParityStatusReport>(data) {
                                    Ok(report) => self.set_result(format!(
                                        "secure-runtime: total={} complete={} partial={} high-risk-blockers={}",
                                        report.total_features,
                                        report.complete_features,
                                        report.partial_features,
                                        report.high_risk_blockers
                                    )),
                                    Err(e) => self
                                        .set_result(format!("failed to parse compat status: {e}")),
                                }
                            }
                        }
                        Ok(resp) => self.set_result(format!("failed: {}", resp.message)),
                        Err(e) => self.set_result(format!("failed to query compat status: {e}")),
                    }
                }
            }
            FleetCommand::ParityDiff => {
                if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::ParityDiff) {
                        Ok(resp) if resp.ok => {
                            if let Some(data) = resp.data {
                                match serde_json::from_value::<ParityDiffReport>(data) {
                                    Ok(report) => self.set_result(format!(
                                        "secure-runtime diff: {} files, sha={}, impacted={}",
                                        report.changed_files,
                                        report.upstream_sha,
                                        report.impacted_feature_ids.len()
                                    )),
                                    Err(e) => {
                                        self.set_result(format!("failed to parse compat diff: {e}"))
                                    }
                                }
                            }
                        }
                        Ok(resp) => self.set_result(format!("failed: {}", resp.message)),
                        Err(e) => self.set_result(format!("failed to query compat diff: {e}")),
                    }
                }
            }
            FleetCommand::ParityVerify => {
                if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::ParityVerify) {
                        Ok(resp) if resp.ok => {
                            if let Some(data) = resp.data {
                                match serde_json::from_value::<ParityVerifyReport>(data) {
                                    Ok(report) => {
                                        if report.ok {
                                            self.set_result(format!(
                                                "compat verification passed (features={})",
                                                report.checked_features
                                            ));
                                        } else {
                                            let rule_count = if report.violations_struct.is_empty()
                                            {
                                                report
                                                    .violations
                                                    .iter()
                                                    .filter_map(|v| {
                                                        v.split_once('|').map(|(r, _)| r)
                                                    })
                                                    .collect::<std::collections::BTreeSet<_>>()
                                                    .len()
                                            } else {
                                                report
                                                    .violations_struct
                                                    .iter()
                                                    .map(|v| v.rule_id.as_str())
                                                    .collect::<std::collections::BTreeSet<_>>()
                                                    .len()
                                            };
                                            self.set_result(format!(
                                                "compat verify failed ({} violations, {} rules)",
                                                report.violations.len(),
                                                rule_count
                                            ));
                                        }
                                    }
                                    Err(e) => self
                                        .set_result(format!("failed to parse compat verify: {e}")),
                                }
                            }
                        }
                        Ok(resp) => self.set_result(format!("failed: {}", resp.message)),
                        Err(e) => self.set_result(format!("failed to verify compat: {e}")),
                    }
                }
            }
            FleetCommand::Tool { agent, action_json } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else {
                    match serde_json::from_str::<ToolAction>(&action_json) {
                        Ok(action) => {
                            if let Some(client) = &self.client {
                                match client.send(&DaemonCommand::ExecuteToolAction {
                                    name: agent.clone(),
                                    action,
                                }) {
                                    Ok(resp) if resp.ok => {
                                        if let Some(data) = resp.data {
                                            match serde_json::from_value::<ToolActionOutcome>(data)
                                            {
                                                Ok(outcome) => {
                                                    self.set_result(format!(
                                                        "{agent}: {} {:?} ({})",
                                                        outcome.execution.result.action,
                                                        outcome.execution.risk_tag,
                                                        outcome
                                                            .execution
                                                            .result
                                                            .note
                                                            .unwrap_or_default()
                                                    ));
                                                }
                                                Err(e) => self.set_result(format!(
                                                    "failed to parse tool result: {e}"
                                                )),
                                            }
                                        } else {
                                            self.set_result(format!("{agent}: tool action sent"));
                                        }
                                    }
                                    Ok(resp) => {
                                        self.set_result(format!("failed: {}", resp.message))
                                    }
                                    Err(e) => self
                                        .set_result(format!("failed to execute tool action: {e}")),
                                }
                            }
                        }
                        Err(e) => {
                            self.set_result(format!("invalid ToolAction JSON: {e}"));
                        }
                    }
                }
            }
            FleetCommand::ToolBatch {
                agent,
                actions_json,
                max_actions,
            } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else {
                    match serde_json::from_str::<Vec<ToolAction>>(&actions_json) {
                        Ok(actions) => {
                            if let Some(client) = &self.client {
                                match client.send(&DaemonCommand::ExecuteToolBatch {
                                    name: agent.clone(),
                                    actions,
                                    max_actions,
                                }) {
                                    Ok(resp) if resp.ok => {
                                        if let Some(data) = resp.data {
                                            match serde_json::from_value::<ToolBatchOutcome>(data) {
                                                Ok(batch) => {
                                                    let reason = batch
                                                        .halted_reason
                                                        .unwrap_or_else(|| "completed".to_string());
                                                    self.set_result(format!(
                                                        "{agent}: batch executed={} ({reason})",
                                                        batch.executed
                                                    ));
                                                }
                                                Err(e) => self.set_result(format!(
                                                    "failed to parse tool batch result: {e}"
                                                )),
                                            }
                                        } else {
                                            self.set_result(format!("{agent}: tool batch sent"));
                                        }
                                    }
                                    Ok(resp) => {
                                        self.set_result(format!("failed: {}", resp.message))
                                    }
                                    Err(e) => self
                                        .set_result(format!("failed to execute tool batch: {e}")),
                                }
                            }
                        }
                        Err(e) => self.set_result(format!("invalid ToolAction batch JSON: {e}")),
                    }
                }
            }
            FleetCommand::CaptureStart { agent, target_fps } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::StartCaptureSession {
                        name: agent.clone(),
                        request: CaptureSessionRequest {
                            target_fps: target_fps.unwrap_or(30),
                            region: None,
                        },
                    }) {
                        Ok(resp) if resp.ok => {
                            if let Some(data) = resp.data {
                                match serde_json::from_value::<CaptureSessionStarted>(data) {
                                    Ok(started) => self.set_result(format!(
                                        "{agent}: capture started ({}, {}fps)",
                                        started.session_id, started.target_fps
                                    )),
                                    Err(e) => self
                                        .set_result(format!("failed to parse capture start: {e}")),
                                }
                            } else {
                                self.set_result(format!("{agent}: capture started"));
                            }
                        }
                        Ok(resp) => self.set_result(format!("failed: {}", resp.message)),
                        Err(e) => self.set_result(format!("failed to start capture: {e}")),
                    }
                }
            }
            FleetCommand::CaptureStop { agent, session_id } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::StopCaptureSession {
                        name: agent.clone(),
                        session_id: session_id.clone(),
                    }) {
                        Ok(resp) if resp.ok => {
                            self.set_result(format!("{agent}: capture stopped ({session_id})"))
                        }
                        Ok(resp) => self.set_result(format!("failed: {}", resp.message)),
                        Err(e) => self.set_result(format!("failed to stop capture: {e}")),
                    }
                }
            }
            FleetCommand::BrowserProfileStop { agent, session_id } => {
                if !self.agent_exists(&agent) {
                    self.set_result(format!("unknown agent: '{agent}'"));
                } else if !self.connected {
                    self.set_result("daemon not connected".to_string());
                } else if let Some(client) = &self.client {
                    match client.send(&DaemonCommand::StopBrowserProfile {
                        name: agent.clone(),
                        session_id: session_id.clone(),
                    }) {
                        Ok(resp) if resp.ok => self
                            .set_result(format!("{agent}: browser profile stopped ({session_id})")),
                        Ok(resp) => self.set_result(format!("failed: {}", resp.message)),
                        Err(e) => self.set_result(format!("failed to stop browser profile: {e}")),
                    }
                }
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
            FleetCommand::MatrixStatus => {
                self.spawn_terminal(
                    "aegis parity status",
                    "Opened parity matrix status in new terminal",
                );
            }
            FleetCommand::MatrixDiff => {
                self.spawn_terminal(
                    "aegis parity diff",
                    "Opened parity matrix diff in new terminal",
                );
            }
            FleetCommand::MatrixVerify => {
                self.spawn_terminal(
                    "aegis parity verify",
                    "Running parity verification in new terminal",
                );
            }
            FleetCommand::List => {
                self.spawn_terminal("aegis list", "Opened config list in new terminal");
            }
            FleetCommand::Hook => {
                self.spawn_terminal("aegis hook install", "Installing hooks in new terminal");
            }
            FleetCommand::Use { name } => match name {
                Some(n) => self.spawn_terminal(
                    &format!("aegis use {n}"),
                    &format!("Switching to config '{n}'"),
                ),
                None => self.spawn_terminal("aegis use", "Opened config picker in new terminal"),
            },
            FleetCommand::Watch { dir } => {
                let cmd = match dir {
                    Some(d) => format!("aegis watch --dir {}", crate::terminal::shell_quote(&d)),
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
            FleetCommand::Alerts => {
                self.spawn_terminal("aegis alerts list", "Opened alerts in new terminal");
            }
            FleetCommand::Setup => {
                self.spawn_terminal("aegis setup", "Running system checks in new terminal");
            }
            FleetCommand::Init => {
                self.spawn_terminal("aegis init", "Opened init wizard in new terminal");
            }
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
            FleetCommand::Goal { text } => {
                self.send_and_show_result(DaemonCommand::FleetGoal { goal: text });
            }
            FleetCommand::Context {
                agent,
                field,
                value,
            } => match (field, value) {
                (Some(f), Some(v)) => {
                    let (role, agent_goal, context, task) = match f.as_str() {
                        "role" => (Some(v), None, None, None),
                        "goal" => (None, Some(v), None, None),
                        "context" => (None, None, Some(v), None),
                        "task" => (None, None, None, Some(v)),
                        _ => {
                            self.set_result(format!(
                                "unknown field '{f}'. Use: role, goal, context, or task"
                            ));
                            return;
                        }
                    };
                    self.send_and_show_result(DaemonCommand::UpdateAgentContext {
                        name: agent,
                        role,
                        agent_goal,
                        context,
                        task,
                    });
                }
                _ => {
                    self.send_context_query(&agent);
                }
            },
            FleetCommand::ContextEdit { agent, field } => {
                self.open_context_editor(agent, field);
            }
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
                            self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                        }
                        Err(e) => {
                            self.last_error = Some(format!("Failed to stop daemon: {e}"));
                        }
                    }
                }
            }
            FleetCommand::DaemonInit => match crate::commands::daemon::init_quiet() {
                Ok(msg) => {
                    self.set_result(msg);
                }
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
                            self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
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
                        "{running} running / {total} total, PID {}, uptime {}",
                        self.daemon_pid,
                        format_uptime(self.daemon_uptime_secs),
                    ));
                }
            }
            FleetCommand::DaemonInstall => {
                self.spawn_terminal(
                    "aegis daemon install --start",
                    "Installing launchd plist in new terminal",
                );
            }
            FleetCommand::DaemonUninstall => {
                self.spawn_terminal(
                    "aegis daemon uninstall",
                    "Uninstalling launchd plist in new terminal",
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
            FleetCommand::Export { format } => {
                let cmd = match format {
                    Some(f) => format!("aegis audit export --format {f}"),
                    None => "aegis audit export".to_string(),
                };
                self.spawn_terminal(&cmd, "Exporting audit data in new terminal");
            }
            FleetCommand::OrchestratorStatus => {
                self.spawn_terminal(
                    "aegis daemon orchestrator-status",
                    "Opened orchestrator overview in new terminal",
                );
            }
            FleetCommand::AuthList => {
                self.spawn_terminal(
                    "aegis auth list",
                    "Opened auth profile list in new terminal",
                );
            }
            FleetCommand::AuthAdd { provider, method } => {
                let cmd = match method {
                    Some(method) => format!(
                        "aegis auth add {} --method {}",
                        crate::terminal::shell_quote(&provider),
                        crate::terminal::shell_quote(&method)
                    ),
                    None => format!("aegis auth add {}", crate::terminal::shell_quote(&provider)),
                };
                self.spawn_terminal(&cmd, &format!("Adding auth profile for '{provider}'"));
            }
            FleetCommand::AuthLogin { provider, method } => {
                let cmd = match method {
                    Some(method) => format!(
                        "aegis auth login {} --method {}",
                        crate::terminal::shell_quote(&provider),
                        crate::terminal::shell_quote(&method)
                    ),
                    None => {
                        format!(
                            "aegis auth login {}",
                            crate::terminal::shell_quote(&provider)
                        )
                    }
                };
                self.spawn_terminal(&cmd, &format!("Starting auth flow for '{provider}'"));
            }
            FleetCommand::AuthTest { target } => {
                let cmd = match target {
                    Some(target) => {
                        format!("aegis auth test {}", crate::terminal::shell_quote(&target))
                    }
                    None => "aegis auth test".to_string(),
                };
                self.spawn_terminal(&cmd, "Testing auth readiness in new terminal");
            }
        }
    }

    /// Send a command for the currently selected agent in overview.
    fn send_agent_command(&mut self, make_cmd: impl FnOnce(String) -> DaemonCommand) {
        if let Some(agent) = self.agents.get(self.agent_selected) {
            let name = agent.name.clone();
            let cmd = make_cmd(name);
            self.send_and_show_result(cmd);
        } else {
            self.set_result("No agents available");
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
                // Force immediate re-poll after action
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
            }
        }
    }

    /// Check if an agent name is known (present in the cached agent list).
    /// Returns true if we're disconnected (can't validate) or if the agent exists.
    fn agent_exists(&self, name: &str) -> bool {
        !self.connected || self.agents.iter().any(|a| a.name == name)
    }

    fn session_agent_name(session_key: &str) -> Option<String> {
        let parts: Vec<&str> = session_key.trim().split(':').collect();
        if parts.len() == 3 && parts[0] == "agent" && parts[2] == "main" {
            let name = parts[1].trim();
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        } else {
            None
        }
    }

    /// Jump selection to the next agent that needs attention (has pending prompts).
    /// Wraps around if needed. Shows a message if no agents need attention.
    fn jump_to_next_attention(&mut self) {
        if self.agents.is_empty() {
            return;
        }
        let start = (self.agent_selected + 1) % self.agents.len();
        for offset in 0..self.agents.len() {
            let idx = (start + offset) % self.agents.len();
            if self.agents[idx].attention_needed || self.agents[idx].pending_count > 0 {
                self.agent_selected = idx;
                return;
            }
        }
        self.set_result("No agents need attention");
    }

    /// Send a command to the daemon and show the response message as command_result.
    ///
    /// Unlike `send_named_command`, this captures the success message for display.
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

    /// Query and display an agent's context fields.
    fn send_context_query(&mut self, agent: &str) {
        let Some(client) = &self.client else {
            self.last_error = Some("Not connected to daemon. Use :daemon start".into());
            return;
        };
        match client.send(&DaemonCommand::GetAgentContext {
            name: agent.to_string(),
        }) {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    let role = data["role"].as_str().unwrap_or("(none)");
                    let goal = data["agent_goal"].as_str().unwrap_or("(none)");
                    let context = data["context"].as_str().unwrap_or("(none)");
                    let task = data["task"].as_str().unwrap_or("(none)");
                    self.set_result(format!(
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

    fn open_context_editor(&mut self, agent: String, field: String) {
        let field = field.to_lowercase();
        if !matches!(field.as_str(), "role" | "goal" | "context" | "task") {
            self.set_result(format!(
                "unknown field '{field}'. Use: role, goal, context, or task"
            ));
            return;
        }
        let Some(client) = &self.client else {
            self.last_error = Some("Not connected to daemon. Use :daemon start".into());
            return;
        };
        match client.send(&DaemonCommand::GetAgentContext {
            name: agent.clone(),
        }) {
            Ok(resp) if resp.ok => {
                let value = resp
                    .data
                    .and_then(|data| match field.as_str() {
                        "role" => data["role"].as_str().map(|s| s.to_string()),
                        "goal" => data["agent_goal"].as_str().map(|s| s.to_string()),
                        "context" => data["context"].as_str().map(|s| s.to_string()),
                        "task" => data["task"].as_str().map(|s| s.to_string()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let cursor = value.len();
                self.context_editor = Some(ContextEditor {
                    agent,
                    field,
                    buffer: value,
                    cursor,
                });
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

    /// Set the command result message with a timestamp for auto-clear.
    fn set_result(&mut self, msg: impl Into<String>) {
        self.command_result = Some(msg.into());
        self.command_result_at = Some(Instant::now());
        // Clear any stale error -- success replaces error visually
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

    /// Get the selected agent's name (if any).
    #[cfg(test)]
    fn selected_agent_name(&self) -> Option<&str> {
        self.agents
            .get(self.agent_selected)
            .map(|a| a.name.as_str())
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
pub(super) fn format_uptime(secs: u64) -> String {
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
                is_orchestrator: false,
                attach_command: None,
                fallback: None,
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
                is_orchestrator: false,
                attach_command: None,
                fallback: None,
            },
            AgentSummary {
                name: "gamma".into(),
                status: AgentStatus::Failed {
                    exit_code: 1,
                    restart_count: 5,
                },
                tool: "ClaudeCode".into(),
                working_dir: "/tmp/gamma".into(),
                role: None,
                restart_count: 5,
                pending_count: 0,
                attention_needed: false,
                is_orchestrator: false,
                attach_command: None,
                fallback: None,
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
    fn q_goes_back_from_detail() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;

        app.handle_key(press(KeyCode::Char('q')));
        assert!(app.running, "q in detail view should go back, not quit");
        assert_eq!(app.view, FleetView::Overview);
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

        // Enter sends and clears buffer, input mode remains active for chat
        assert!(app.input_mode);
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
        assert!(app
            .command_result
            .as_ref()
            .unwrap()
            .contains("unknown command"));
    }

    #[test]
    fn command_result_persists_across_keypress() {
        let mut app = make_app();
        app.set_result("recent result");

        // Pressing a key should NOT clear a recent result
        app.handle_key(press(KeyCode::Char('j')));
        assert!(app.command_result.is_some());
    }

    #[test]
    fn command_result_clears_after_timeout() {
        let mut app = make_app();
        app.command_result = Some("old result".into());
        // Set the timestamp to 6 seconds ago (past the 5s threshold)
        app.command_result_at = Some(Instant::now() - std::time::Duration::from_secs(6));

        // Keypress should clear the stale result
        app.handle_key(press(KeyCode::Char('j')));
        assert!(app.command_result.is_none());
    }

    #[test]
    fn command_result_clears_on_entering_command_mode() {
        let mut app = make_app();
        app.set_result("some result");

        // Entering command mode clears the result immediately
        app.handle_key(press(KeyCode::Char(':')));
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

    #[test]
    fn question_mark_opens_help() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('?')));
        assert_eq!(app.view, FleetView::Help);
    }

    #[test]
    fn page_up_down_in_detail_view() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        for i in 0..100 {
            app.detail_output.push_back(format!("line {i}"));
        }

        // PageUp scrolls up by 20
        app.handle_key(press(KeyCode::PageUp));
        assert_eq!(app.detail_scroll, 20);

        // PageDown scrolls down by 20
        app.handle_key(press(KeyCode::PageDown));
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn follow_nonexistent_agent_shows_error() {
        let mut app = make_app();
        app.connected = true;
        app.command_mode = true;
        app.command_buffer = "follow nonexistent".into();
        app.command_cursor = 18;

        app.handle_key(press(KeyCode::Enter));
        // Should stay in overview (not switch to detail)
        assert_eq!(app.view, FleetView::Overview);
        assert!(app
            .command_result
            .as_ref()
            .unwrap()
            .contains("unknown agent"));
    }

    #[test]
    fn follow_existing_agent_switches_view() {
        let mut app = make_app();
        app.connected = true;
        app.command_mode = true;
        app.command_buffer = "follow alpha".into();
        app.command_cursor = 12;

        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.view, FleetView::AgentDetail);
        assert_eq!(app.detail_name, "alpha");
    }

    #[test]
    fn chat_command_without_agent_prefers_orchestrator() {
        let mut app = make_app();
        app.connected = true;
        app.agents.insert(
            0,
            AgentSummary {
                name: "orch".into(),
                status: AgentStatus::Running { pid: 42 },
                tool: "ClaudeCode".into(),
                working_dir: "/tmp/orch".into(),
                role: Some("Orchestrator".into()),
                restart_count: 0,
                pending_count: 0,
                attention_needed: false,
                is_orchestrator: true,
                attach_command: None,
                fallback: None,
            },
        );
        app.command_mode = true;
        app.command_buffer = "chat".into();
        app.command_cursor = 4;

        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.view, FleetView::AgentDetail);
        assert_eq!(app.detail_name, "orch");
    }

    #[test]
    fn chat_first_bootstrap_opens_orchestrator_detail() {
        let mut app = make_app();
        app.connected = true;
        app.agents.insert(
            0,
            AgentSummary {
                name: "orch".into(),
                status: AgentStatus::Running { pid: 42 },
                tool: "ClaudeCode".into(),
                working_dir: "/tmp/orch".into(),
                role: Some("Orchestrator".into()),
                restart_count: 0,
                pending_count: 0,
                attention_needed: false,
                is_orchestrator: true,
                attach_command: None,
                fallback: None,
            },
        );

        app.maybe_open_chat_first();
        assert_eq!(app.view, FleetView::AgentDetail);
        assert_eq!(app.detail_name, "orch");
        assert!(app.chat_bootstrapped);
    }

    #[test]
    fn page_up_down_in_help_view() {
        let mut app = make_app();
        app.view = FleetView::Help;

        app.handle_key(press(KeyCode::PageDown));
        assert_eq!(app.help_scroll, 20);

        app.handle_key(press(KeyCode::PageUp));
        assert_eq!(app.help_scroll, 0);
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
        assert!(
            app.running,
            "Ctrl+C in command mode should exit mode, not quit"
        );
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
        assert!(
            app.running,
            "Ctrl+C in input mode should exit mode, not quit"
        );
    }

    #[test]
    fn paste_in_command_mode_updates_completions() {
        let mut app = make_app();
        app.command_mode = true;

        app.handle_paste("st");
        assert_eq!(app.command_buffer, "st");
        assert_eq!(app.command_cursor, 2);
        // Completions should be refreshed after paste
        assert!(!app.command_completions.is_empty());
        assert!(app.command_completions.contains(&"start".to_string()));
        assert!(app.command_completions.contains(&"stop".to_string()));
    }

    #[test]
    fn multibyte_cursor_movement_in_command_mode() {
        let mut app = make_app();
        app.command_mode = true;

        // Type a multi-byte character (e-acute is 2 bytes in UTF-8)
        app.handle_command_key(press(KeyCode::Char('a')));
        app.handle_command_key(press(KeyCode::Char('\u{00e9}'))); // e-acute
        app.handle_command_key(press(KeyCode::Char('b')));
        assert_eq!(app.command_buffer, "a\u{00e9}b");
        assert_eq!(app.command_cursor, 4); // a(1) + e-acute(2) + b(1) = 4 bytes

        // Left arrow should move back by one character, not one byte
        app.handle_command_key(press(KeyCode::Left));
        assert_eq!(app.command_cursor, 3); // before 'b'
        app.handle_command_key(press(KeyCode::Left));
        assert_eq!(app.command_cursor, 1); // before e-acute (skipped 2 bytes)
        app.handle_command_key(press(KeyCode::Left));
        assert_eq!(app.command_cursor, 0); // before 'a'

        // Right arrow should move forward by one character
        app.handle_command_key(press(KeyCode::Right));
        assert_eq!(app.command_cursor, 1); // after 'a'
        app.handle_command_key(press(KeyCode::Right));
        assert_eq!(app.command_cursor, 3); // after e-acute (advanced 2 bytes)

        // Backspace should delete one character
        app.handle_command_key(press(KeyCode::Backspace));
        assert_eq!(app.command_buffer, "ab");
        assert_eq!(app.command_cursor, 1); // cursor now after 'a'
    }

    #[test]
    fn multibyte_cursor_movement_in_input_mode() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.input_mode = true;

        // Insert multi-byte characters
        app.handle_input_key(press(KeyCode::Char('\u{00fc}'))); // u-umlaut (2 bytes)
        app.handle_input_key(press(KeyCode::Char('x')));
        assert_eq!(app.input_buffer, "\u{00fc}x");
        assert_eq!(app.input_cursor, 3); // u-umlaut(2) + x(1)

        // Navigate left past multi-byte char
        app.handle_input_key(press(KeyCode::Left));
        assert_eq!(app.input_cursor, 2); // before 'x'
        app.handle_input_key(press(KeyCode::Left));
        assert_eq!(app.input_cursor, 0); // before u-umlaut

        // Backspace from end deletes single multi-byte char
        app.handle_input_key(press(KeyCode::End));
        app.handle_input_key(press(KeyCode::Backspace));
        assert_eq!(app.input_buffer, "\u{00fc}");
        assert_eq!(app.input_cursor, 2);
    }

    #[test]
    fn input_mode_delete_key() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.input_mode = true;

        for c in "abc".chars() {
            app.handle_key(press(KeyCode::Char(c)));
        }
        assert_eq!(app.input_buffer, "abc");

        // Move cursor to start, delete forward
        app.handle_key(press(KeyCode::Home));
        assert_eq!(app.input_cursor, 0);

        app.handle_key(press(KeyCode::Delete));
        assert_eq!(app.input_buffer, "bc");
        assert_eq!(app.input_cursor, 0);

        app.handle_key(press(KeyCode::Delete));
        assert_eq!(app.input_buffer, "c");

        // Delete at end does nothing
        app.handle_key(press(KeyCode::End));
        app.handle_key(press(KeyCode::Delete));
        assert_eq!(app.input_buffer, "c");
    }

    #[test]
    fn command_mode_delete_key() {
        let mut app = make_app();
        app.command_mode = true;

        for c in "quit".chars() {
            app.handle_key(press(KeyCode::Char(c)));
        }
        assert_eq!(app.command_buffer, "quit");

        // Move to start, delete forward
        app.handle_key(press(KeyCode::Home));
        app.handle_key(press(KeyCode::Delete));
        assert_eq!(app.command_buffer, "uit");
        assert_eq!(app.command_cursor, 0);

        // Delete at end does nothing
        app.handle_key(press(KeyCode::End));
        app.handle_key(press(KeyCode::Delete));
        assert_eq!(app.command_buffer, "uit");
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::empty(),
        }
    }

    #[test]
    fn input_mode_ctrl_a_e() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.input_mode = true;

        for c in "hello".chars() {
            app.handle_key(press(KeyCode::Char(c)));
        }
        assert_eq!(app.input_cursor, 5);

        app.handle_key(ctrl(KeyCode::Char('a')));
        assert_eq!(app.input_cursor, 0);

        app.handle_key(ctrl(KeyCode::Char('e')));
        assert_eq!(app.input_cursor, 5);
    }

    #[test]
    fn input_mode_ctrl_u() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.input_mode = true;

        for c in "hello world".chars() {
            app.handle_key(press(KeyCode::Char(c)));
        }
        // Move cursor to position 6 ("world")
        for _ in 0..5 {
            app.handle_key(press(KeyCode::Left));
        }
        assert_eq!(app.input_cursor, 6);

        app.handle_key(ctrl(KeyCode::Char('u')));
        assert_eq!(app.input_buffer, "world");
        assert_eq!(app.input_cursor, 0);
    }

    #[test]
    fn input_mode_ctrl_w() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.input_mode = true;

        for c in "hello world".chars() {
            app.handle_key(press(KeyCode::Char(c)));
        }
        assert_eq!(app.input_buffer, "hello world");

        app.handle_key(ctrl(KeyCode::Char('w')));
        assert_eq!(app.input_buffer, "hello ");
        assert_eq!(app.input_cursor, 6);

        app.handle_key(ctrl(KeyCode::Char('w')));
        assert_eq!(app.input_buffer, "");
        assert_eq!(app.input_cursor, 0);
    }

    #[test]
    fn command_mode_ctrl_a_e_u_w() {
        let mut app = make_app();
        app.command_mode = true;

        for c in "daemon start".chars() {
            app.handle_key(press(KeyCode::Char(c)));
        }
        assert_eq!(app.command_buffer, "daemon start");

        app.handle_key(ctrl(KeyCode::Char('a')));
        assert_eq!(app.command_cursor, 0);

        app.handle_key(ctrl(KeyCode::Char('e')));
        assert_eq!(app.command_cursor, 12);

        app.handle_key(ctrl(KeyCode::Char('w')));
        assert_eq!(app.command_buffer, "daemon ");
        assert_eq!(app.command_cursor, 7);

        app.handle_key(ctrl(KeyCode::Char('u')));
        assert_eq!(app.command_buffer, "");
        assert_eq!(app.command_cursor, 0);
    }

    #[test]
    fn help_view_home_end() {
        let mut app = make_app();
        app.view = FleetView::Help;

        // Scroll down a few lines
        app.handle_key(press(KeyCode::PageDown));
        assert!(app.help_scroll > 0);

        // Home goes to top
        app.handle_key(press(KeyCode::Home));
        assert_eq!(app.help_scroll, 0);

        // End goes to bottom
        app.handle_key(press(KeyCode::End));
        let help_lines = command::help_text().lines().count();
        assert_eq!(app.help_scroll, help_lines.saturating_sub(1));
    }

    #[test]
    fn send_named_command_shows_error_when_disconnected() {
        let mut app = FleetApp::new(None);
        // client is None since FleetApp::new(None) has no daemon client
        app.send_named_command(DaemonCommand::StopAgent {
            name: "test".into(),
        });
        assert!(app.last_error.is_some());
        assert!(app.last_error.as_ref().unwrap().contains("Not connected"));
    }

    #[test]
    fn send_and_show_result_shows_error_when_disconnected() {
        let mut app = FleetApp::new(None);
        app.send_and_show_result(DaemonCommand::StopAgent {
            name: "test".into(),
        });
        assert!(app.last_error.is_some());
        assert!(app.last_error.as_ref().unwrap().contains("Not connected"));
    }

    #[test]
    fn send_context_query_shows_error_when_disconnected() {
        let mut app = FleetApp::new(None);
        app.send_context_query("test-agent");
        assert!(app.last_error.is_some());
        assert!(app.last_error.as_ref().unwrap().contains("Not connected"));
    }

    #[test]
    fn set_result_clears_last_error() {
        let mut app = FleetApp::new(None);
        app.last_error = Some("old error".into());
        app.set_result("success");
        assert!(app.last_error.is_none());
        assert_eq!(app.command_result.as_deref(), Some("success"));
    }

    #[test]
    fn detail_scroll_clamped_on_k() {
        let mut app = make_app();
        app.view = FleetView::AgentDetail;
        app.detail_name = "alpha".into();
        // Add 5 lines of output
        for i in 0..5 {
            app.detail_output.push_back(format!("line {i}"));
        }
        // Press k many times -- should not exceed output length
        for _ in 0..50 {
            app.handle_key(press(KeyCode::Char('k')));
        }
        assert!(app.detail_scroll <= app.detail_output.len().saturating_sub(1));
    }

    #[test]
    fn cycle_completion_back_auto_populates() {
        let mut app = make_app();
        app.command_mode = true;
        app.command_buffer = "st".into();
        app.command_cursor = 2;
        // BackTab should auto-populate and select last completion
        app.cycle_completion_back();
        assert!(!app.command_completions.is_empty());
        assert!(app.completion_idx.is_some());
    }

    #[test]
    fn jump_to_next_attention_finds_agent() {
        let mut app = make_app();
        // Set beta to have pending prompts
        app.agents[1].pending_count = 2;
        app.agent_selected = 0; // start at alpha

        app.jump_to_next_attention();
        assert_eq!(app.agent_selected, 1); // jumped to beta
    }

    #[test]
    fn jump_to_next_attention_wraps_around() {
        let mut app = make_app();
        app.agents[0].attention_needed = true;
        app.agent_selected = 2; // start at gamma (last)

        app.jump_to_next_attention();
        assert_eq!(app.agent_selected, 0); // wrapped to alpha
    }

    #[test]
    fn jump_to_next_attention_no_agents_needing_attention() {
        let mut app = make_app();
        app.agent_selected = 0;

        app.jump_to_next_attention();
        // Should show a message, not crash
        assert!(app.command_result.is_some());
        assert!(app
            .command_result
            .as_ref()
            .unwrap()
            .contains("No agents need attention"));
    }

    #[test]
    fn tab_key_jumps_to_attention() {
        let mut app = make_app();
        app.agents[2].pending_count = 1;
        app.agent_selected = 0;

        app.handle_key(press(KeyCode::Tab));
        assert_eq!(app.agent_selected, 2); // jumped to gamma
    }
}
