//! Interactive TUI for the fleet dashboard.
//!
//! Connects to a running daemon via `DaemonClient` and displays a live
//! overview of all agent slots. Supports drilling into individual agents
//! to view their output, and sending start/stop/restart commands.

pub mod event;
pub mod ui;
pub mod wizard;

use std::collections::VecDeque;
use std::time::Instant;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use aegis_control::daemon::{AgentSummary, DaemonClient, DaemonCommand};
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

    // -- Wizard --
    /// Add-agent wizard (active when view == AddAgent).
    pub wizard: Option<AddAgentWizard>,

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
            wizard: None,
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
            FleetView::AgentDetail => self.poll_agent_output(),
            FleetView::AddAgent => {} // Wizard doesn't need daemon polling
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
    }

    /// Fetch output for the currently viewed agent.
    fn poll_agent_output(&mut self) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };

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
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Only handle key press events (not release/repeat)
        if key.kind != KeyEventKind::Press {
            return;
        }

        match self.view {
            FleetView::Overview => self.handle_overview_key(key),
            FleetView::AgentDetail => self.handle_detail_key(key),
            FleetView::AddAgent => self.handle_wizard_key(key),
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

    /// Send AddAgent command to the daemon.
    fn send_add_agent(&mut self, config: aegis_types::daemon::AgentSlotConfig) {
        let cmd = DaemonCommand::AddAgent {
            config: Box::new(config),
            start: true,
        };
        self.send_named_command(cmd);
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
                if self.detail_scroll > 0 {
                    self.detail_scroll -= 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.detail_scroll += 1;
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.detail_scroll = 0; // bottom
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.detail_scroll = self.detail_output.len().saturating_sub(1);
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
            _ => {}
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

/// Run the fleet TUI, connecting to the daemon at the default socket path.
pub fn run_fleet_tui() -> Result<()> {
    let client = DaemonClient::default_path();

    // Quick check that daemon is reachable
    if !client.is_running() {
        anyhow::bail!(
            "daemon is not running. Start it with `aegis daemon start` or `aegis daemon run`."
        );
    }

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
                restart_count: 0,
            },
            AgentSummary {
                name: "beta".into(),
                status: AgentStatus::Stopped { exit_code: 0 },
                tool: "Codex".into(),
                working_dir: "/tmp/beta".into(),
                restart_count: 1,
            },
            AgentSummary {
                name: "gamma".into(),
                status: AgentStatus::Failed { exit_code: 1, restart_count: 5 },
                tool: "ClaudeCode".into(),
                working_dir: "/tmp/gamma".into(),
                restart_count: 5,
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
}
