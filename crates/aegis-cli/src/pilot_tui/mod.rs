//! Interactive TUI for the pilot supervisor.
//!
//! Renders a live dashboard showing agent output, pilot decisions, stats,
//! and pending permission requests. Accepts keyboard input for approving,
//! denying, sending text, and nudging the agent.

pub mod event;
pub mod ui;

use std::collections::VecDeque;
use std::sync::mpsc;

use anyhow::Result;
use chrono::{DateTime, Local};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use uuid::Uuid;

use aegis_pilot::supervisor::{PilotStats, PilotUpdate, SupervisorCommand};
use aegis_types::Decision;

use self::event::{AppEvent, EventHandler};

/// Maximum output lines to retain in the TUI buffer.
const MAX_OUTPUT_LINES: usize = 2000;

/// TUI tick rate in milliseconds (how often we drain supervisor updates).
const TICK_RATE_MS: u64 = 50;

/// The active mode of the pilot TUI.
pub enum PilotMode {
    /// Normal operation: viewing output and handling keybindings.
    Normal,
    /// Typing text to send to the agent (i key).
    InputMode,
}

/// A timestamped output line for the TUI display.
pub struct OutputLine {
    /// When the line was received.
    pub timestamp: DateTime<Local>,
    /// The line content (ANSI-stripped).
    pub text: String,
    /// Optional decoration (e.g., "[APPROVED]", "[DENIED]").
    pub annotation: Option<LineAnnotation>,
}

/// Decoration on an output line indicating a pilot decision.
#[derive(Clone)]
pub enum LineAnnotation {
    Approved { action: String, reason: String },
    Denied { action: String, reason: String },
    Nudge,
    Attention,
}

/// A pending permission request visible in the TUI.
pub struct PendingInfo {
    pub request_id: Uuid,
    pub raw_prompt: String,
    pub received_at: DateTime<Local>,
}

/// Top-level application state for the pilot TUI.
pub struct PilotApp {
    /// Scrollable output lines.
    pub output_lines: VecDeque<OutputLine>,
    /// Current pilot stats.
    pub stats: PilotStats,
    /// Pending permission requests awaiting human decision.
    pub pending: Vec<PendingInfo>,
    /// Scroll position in the output pane (0 = bottom/latest).
    pub scroll_offset: usize,
    /// Selected index in the pending requests list.
    pub pending_selected: usize,
    /// Current TUI mode.
    pub mode: PilotMode,
    /// Text being typed in InputMode.
    pub input_buffer: String,
    /// Whether the main loop should keep running.
    pub running: bool,
    /// The session ID for display.
    pub session_id: String,
    /// The config name for display.
    pub config_name: String,
    /// The command being supervised.
    pub command: String,
    /// Whether the child process is still alive.
    pub child_alive: bool,
    /// Whether focus is on the pending panel (vs output panel).
    pub focus_pending: bool,
    /// Channel to send commands back to the supervisor.
    command_tx: mpsc::Sender<SupervisorCommand>,
}

impl PilotApp {
    /// Create a new pilot TUI application.
    pub fn new(
        session_id: String,
        config_name: String,
        command: String,
        command_tx: mpsc::Sender<SupervisorCommand>,
    ) -> Self {
        Self {
            output_lines: VecDeque::with_capacity(MAX_OUTPUT_LINES),
            stats: PilotStats::default(),
            pending: Vec::new(),
            scroll_offset: 0,
            pending_selected: 0,
            mode: PilotMode::Normal,
            input_buffer: String::new(),
            running: true,
            session_id,
            config_name,
            command,
            child_alive: true,
            focus_pending: false,
            command_tx,
        }
    }

    /// Apply a PilotUpdate from the supervisor.
    pub fn apply_update(&mut self, update: PilotUpdate) {
        match update {
            PilotUpdate::OutputLine(text) => {
                self.push_output(text, None);
            }
            PilotUpdate::PromptDecided { action, decision, reason } => {
                let annotation = match decision {
                    Decision::Allow => LineAnnotation::Approved {
                        action: action.clone(),
                        reason: reason.clone(),
                    },
                    Decision::Deny => LineAnnotation::Denied {
                        action: action.clone(),
                        reason: reason.clone(),
                    },
                };
                let text = match &annotation {
                    LineAnnotation::Approved { action, reason } => {
                        format!("[APPROVED] {action} -- {reason}")
                    }
                    LineAnnotation::Denied { action, reason } => {
                        format!("[DENIED] {action} -- {reason}")
                    }
                    _ => unreachable!(),
                };
                self.push_output(text, Some(annotation));
            }
            PilotUpdate::PendingPrompt { request_id, raw_prompt } => {
                self.pending.push(PendingInfo {
                    request_id,
                    raw_prompt: raw_prompt.clone(),
                    received_at: Local::now(),
                });
                self.push_output(
                    format!("[PENDING] {raw_prompt}"),
                    None,
                );
                // Auto-focus pending panel when first request arrives
                if self.pending.len() == 1 {
                    self.focus_pending = true;
                }
            }
            PilotUpdate::PendingResolved { request_id, approved } => {
                self.pending.retain(|p| p.request_id != request_id);
                if self.pending_selected >= self.pending.len() && !self.pending.is_empty() {
                    self.pending_selected = self.pending.len() - 1;
                }
                if self.pending.is_empty() {
                    self.focus_pending = false;
                }
                let tag = if approved { "RESOLVED:APPROVED" } else { "RESOLVED:DENIED" };
                self.push_output(format!("[{tag}] request {request_id}"), None);
            }
            PilotUpdate::StallNudge { nudge_count } => {
                self.push_output(
                    format!("[NUDGE #{nudge_count}] sent stall nudge to agent"),
                    Some(LineAnnotation::Nudge),
                );
            }
            PilotUpdate::AttentionNeeded { nudge_count } => {
                self.push_output(
                    format!("[ATTENTION] max nudges ({nudge_count}) exceeded, agent needs help"),
                    Some(LineAnnotation::Attention),
                );
            }
            PilotUpdate::ChildExited { exit_code } => {
                self.child_alive = false;
                self.push_output(
                    format!("[EXIT] child process exited with code {exit_code}"),
                    None,
                );
            }
            PilotUpdate::Stats(stats) => {
                self.stats = stats;
            }
        }
    }

    /// Handle a key event based on the current mode.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Only handle Press events (not Release or Repeat)
        if key.kind != KeyEventKind::Press {
            return;
        }

        match self.mode {
            PilotMode::Normal => self.handle_normal_key(key),
            PilotMode::InputMode => self.handle_input_key(key),
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => {
                self.running = false;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if self.focus_pending {
                    if self.pending_selected < self.pending.len().saturating_sub(1) {
                        self.pending_selected += 1;
                    }
                } else {
                    self.scroll_down();
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.focus_pending {
                    self.pending_selected = self.pending_selected.saturating_sub(1);
                } else {
                    self.scroll_up();
                }
            }
            KeyCode::Char('G') => {
                // Jump to bottom (latest output)
                self.scroll_offset = 0;
            }
            KeyCode::Char('g') => {
                // Jump to top (oldest output)
                self.scroll_offset = self.output_lines.len().saturating_sub(1);
            }
            KeyCode::Tab => {
                // Toggle focus between output and pending panels
                if !self.pending.is_empty() {
                    self.focus_pending = !self.focus_pending;
                }
            }
            KeyCode::Char('a') => {
                // Approve selected pending request
                if self.focus_pending {
                    if let Some(info) = self.pending.get(self.pending_selected) {
                        let _ = self.command_tx.send(SupervisorCommand::Approve {
                            request_id: info.request_id,
                        });
                    }
                }
            }
            KeyCode::Char('d') => {
                // Deny selected pending request
                if self.focus_pending {
                    if let Some(info) = self.pending.get(self.pending_selected) {
                        let _ = self.command_tx.send(SupervisorCommand::Deny {
                            request_id: info.request_id,
                        });
                    }
                }
            }
            KeyCode::Char('i') => {
                self.mode = PilotMode::InputMode;
                self.input_buffer.clear();
            }
            KeyCode::Char('n') => {
                // Send nudge
                let _ = self.command_tx.send(SupervisorCommand::Nudge { message: None });
            }
            _ => {}
        }
    }

    fn handle_input_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.mode = PilotMode::Normal;
                self.input_buffer.clear();
            }
            KeyCode::Enter => {
                if !self.input_buffer.is_empty() {
                    let text = std::mem::take(&mut self.input_buffer);
                    let _ = self.command_tx.send(SupervisorCommand::SendInput {
                        text: text.clone(),
                    });
                    self.push_output(format!("[INPUT] > {text}"), None);
                }
                self.mode = PilotMode::Normal;
            }
            KeyCode::Backspace => {
                self.input_buffer.pop();
            }
            KeyCode::Char(c) => {
                self.input_buffer.push(c);
            }
            _ => {}
        }
    }

    fn push_output(&mut self, text: String, annotation: Option<LineAnnotation>) {
        if self.output_lines.len() >= MAX_OUTPUT_LINES {
            self.output_lines.pop_front();
        }
        self.output_lines.push_back(OutputLine {
            timestamp: Local::now(),
            text,
            annotation,
        });
        // Auto-scroll to bottom when new output arrives (if already at bottom)
        if self.scroll_offset == 0 {
            // Already at bottom, stay there
        }
    }

    fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    fn scroll_up(&mut self) {
        let max = self.output_lines.len().saturating_sub(1);
        if self.scroll_offset < max {
            self.scroll_offset += 1;
        }
    }

    /// Return the visible output lines for rendering, accounting for scroll offset.
    pub fn visible_output(&self, visible_height: usize) -> Vec<&OutputLine> {
        let total = self.output_lines.len();
        if total == 0 || visible_height == 0 {
            return Vec::new();
        }
        // scroll_offset 0 = show the latest lines (bottom of buffer)
        let end = total.saturating_sub(self.scroll_offset);
        let start = end.saturating_sub(visible_height);
        self.output_lines.range(start..end).collect()
    }
}

/// Run the pilot TUI event loop.
///
/// Blocks until the user presses 'q' or the child process exits and
/// the user dismisses the TUI.
pub fn run_pilot_tui(
    update_rx: mpsc::Receiver<PilotUpdate>,
    command_tx: mpsc::Sender<SupervisorCommand>,
    session_id: String,
    config_name: String,
    command: String,
) -> Result<()> {
    // Set up terminal
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture,
    )?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let events = EventHandler::new(TICK_RATE_MS);
    let mut app = PilotApp::new(session_id, config_name, command, command_tx);

    let result = run_event_loop(&mut terminal, &events, &mut app, &update_rx);

    // Restore terminal
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture,
    )?;
    terminal.show_cursor()?;

    result
}

/// Internal event loop -- separated for testability.
fn run_event_loop(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    events: &EventHandler,
    app: &mut PilotApp,
    update_rx: &mpsc::Receiver<PilotUpdate>,
) -> Result<()> {
    loop {
        // Drain all pending supervisor updates (non-blocking)
        while let Ok(update) = update_rx.try_recv() {
            app.apply_update(update);
        }

        // Render
        terminal.draw(|f| ui::draw(f, app))?;

        // Poll for key events
        match events.next()? {
            AppEvent::Tick => {}
            AppEvent::Key(key) => app.handle_key(key),
        }

        if !app.running {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app() -> PilotApp {
        let (tx, _rx) = mpsc::channel();
        PilotApp::new(
            "test-session".into(),
            "test-config".into(),
            "echo".into(),
            tx,
        )
    }

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: crossterm::event::KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    #[test]
    fn initial_state() {
        let app = make_app();
        assert!(app.running);
        assert!(app.child_alive);
        assert!(matches!(app.mode, PilotMode::Normal));
        assert!(app.output_lines.is_empty());
        assert!(app.pending.is_empty());
        assert_eq!(app.scroll_offset, 0);
        assert!(!app.focus_pending);
    }

    #[test]
    fn q_quits() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('q')));
        assert!(!app.running);
    }

    #[test]
    fn output_line_update() {
        let mut app = make_app();
        app.apply_update(PilotUpdate::OutputLine("hello".into()));
        assert_eq!(app.output_lines.len(), 1);
        assert_eq!(app.output_lines[0].text, "hello");
    }

    #[test]
    fn prompt_decided_update() {
        let mut app = make_app();
        app.apply_update(PilotUpdate::PromptDecided {
            action: "FileRead".into(),
            decision: Decision::Allow,
            reason: "ok".into(),
        });
        assert_eq!(app.output_lines.len(), 1);
        assert!(app.output_lines[0].text.contains("[APPROVED]"));
        assert!(app.output_lines[0].text.contains("FileRead"));
    }

    #[test]
    fn pending_prompt_update() {
        let mut app = make_app();
        let id = Uuid::new_v4();
        app.apply_update(PilotUpdate::PendingPrompt {
            request_id: id,
            raw_prompt: "Allow?".into(),
        });
        assert_eq!(app.pending.len(), 1);
        assert_eq!(app.pending[0].request_id, id);
        assert!(app.focus_pending);
    }

    #[test]
    fn pending_resolved_update() {
        let mut app = make_app();
        let id = Uuid::new_v4();
        app.apply_update(PilotUpdate::PendingPrompt {
            request_id: id,
            raw_prompt: "Allow?".into(),
        });
        assert_eq!(app.pending.len(), 1);

        app.apply_update(PilotUpdate::PendingResolved {
            request_id: id,
            approved: true,
        });
        assert!(app.pending.is_empty());
        assert!(!app.focus_pending);
    }

    #[test]
    fn child_exited_update() {
        let mut app = make_app();
        app.apply_update(PilotUpdate::ChildExited { exit_code: 0 });
        assert!(!app.child_alive);
    }

    #[test]
    fn stats_update() {
        let mut app = make_app();
        let stats = PilotStats {
            approved: 5,
            denied: 2,
            uncertain: 1,
            nudges: 0,
            lines_processed: 100,
        };
        app.apply_update(PilotUpdate::Stats(stats));
        assert_eq!(app.stats.approved, 5);
        assert_eq!(app.stats.denied, 2);
    }

    #[test]
    fn scroll_up_and_down() {
        let mut app = make_app();
        for i in 0..50 {
            app.apply_update(PilotUpdate::OutputLine(format!("line {i}")));
        }
        assert_eq!(app.scroll_offset, 0);

        // Scroll up (k key)
        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.scroll_offset, 1);

        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.scroll_offset, 2);

        // Scroll down (j key)
        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.scroll_offset, 1);

        // Jump to bottom (G)
        app.handle_key(make_key(KeyCode::Char('G')));
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn input_mode_entry_and_exit() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('i')));
        assert!(matches!(app.mode, PilotMode::InputMode));
        assert!(app.input_buffer.is_empty());

        app.handle_key(make_key(KeyCode::Char('h')));
        app.handle_key(make_key(KeyCode::Char('i')));
        assert_eq!(app.input_buffer, "hi");

        app.handle_key(make_key(KeyCode::Backspace));
        assert_eq!(app.input_buffer, "h");

        app.handle_key(make_key(KeyCode::Esc));
        assert!(matches!(app.mode, PilotMode::Normal));
        assert!(app.input_buffer.is_empty());
    }

    #[test]
    fn input_mode_sends_command() {
        let (tx, rx) = mpsc::channel();
        let mut app = PilotApp::new(
            "test".into(),
            "test".into(),
            "echo".into(),
            tx,
        );

        app.handle_key(make_key(KeyCode::Char('i')));
        app.handle_key(make_key(KeyCode::Char('h')));
        app.handle_key(make_key(KeyCode::Char('i')));
        app.handle_key(make_key(KeyCode::Enter));

        assert!(matches!(app.mode, PilotMode::Normal));
        let cmd = rx.try_recv().unwrap();
        assert!(matches!(cmd, SupervisorCommand::SendInput { text } if text == "hi"));
    }

    #[test]
    fn tab_toggles_focus() {
        let mut app = make_app();
        // No pending -- tab should not toggle
        app.handle_key(make_key(KeyCode::Tab));
        assert!(!app.focus_pending);

        // Add pending request
        app.apply_update(PilotUpdate::PendingPrompt {
            request_id: Uuid::new_v4(),
            raw_prompt: "Allow?".into(),
        });
        assert!(app.focus_pending);

        // Tab toggles back to output
        app.handle_key(make_key(KeyCode::Tab));
        assert!(!app.focus_pending);

        // Tab toggles to pending
        app.handle_key(make_key(KeyCode::Tab));
        assert!(app.focus_pending);
    }

    #[test]
    fn approve_sends_command() {
        let (tx, rx) = mpsc::channel();
        let mut app = PilotApp::new("t".into(), "t".into(), "t".into(), tx);
        let id = Uuid::new_v4();
        app.apply_update(PilotUpdate::PendingPrompt {
            request_id: id,
            raw_prompt: "Allow?".into(),
        });

        // Focus is already on pending, press 'a' to approve
        app.handle_key(make_key(KeyCode::Char('a')));
        let cmd = rx.try_recv().unwrap();
        assert!(matches!(cmd, SupervisorCommand::Approve { request_id } if request_id == id));
    }

    #[test]
    fn deny_sends_command() {
        let (tx, rx) = mpsc::channel();
        let mut app = PilotApp::new("t".into(), "t".into(), "t".into(), tx);
        let id = Uuid::new_v4();
        app.apply_update(PilotUpdate::PendingPrompt {
            request_id: id,
            raw_prompt: "Allow?".into(),
        });

        app.handle_key(make_key(KeyCode::Char('d')));
        let cmd = rx.try_recv().unwrap();
        assert!(matches!(cmd, SupervisorCommand::Deny { request_id } if request_id == id));
    }

    #[test]
    fn nudge_sends_command() {
        let (tx, rx) = mpsc::channel();
        let mut app = PilotApp::new("t".into(), "t".into(), "t".into(), tx);

        app.handle_key(make_key(KeyCode::Char('n')));
        let cmd = rx.try_recv().unwrap();
        assert!(matches!(cmd, SupervisorCommand::Nudge { .. }));
    }

    #[test]
    fn visible_output_empty() {
        let app = make_app();
        assert!(app.visible_output(20).is_empty());
    }

    #[test]
    fn visible_output_at_bottom() {
        let mut app = make_app();
        for i in 0..30 {
            app.apply_update(PilotUpdate::OutputLine(format!("line {i}")));
        }

        let visible = app.visible_output(10);
        assert_eq!(visible.len(), 10);
        assert_eq!(visible[9].text, "line 29"); // Latest line
    }

    #[test]
    fn visible_output_scrolled_up() {
        let mut app = make_app();
        for i in 0..30 {
            app.apply_update(PilotUpdate::OutputLine(format!("line {i}")));
        }

        app.scroll_offset = 5;
        let visible = app.visible_output(10);
        assert_eq!(visible.len(), 10);
        assert_eq!(visible[9].text, "line 24");
    }

    #[test]
    fn output_ring_buffer_eviction() {
        let mut app = make_app();
        for i in 0..MAX_OUTPUT_LINES + 100 {
            app.apply_update(PilotUpdate::OutputLine(format!("line {i}")));
        }
        assert_eq!(app.output_lines.len(), MAX_OUTPUT_LINES);
    }

    #[test]
    fn q_does_not_quit_in_input_mode() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('i')));
        app.handle_key(make_key(KeyCode::Char('q')));
        assert!(app.running);
        assert_eq!(app.input_buffer, "q");
    }

    #[test]
    fn pending_navigation() {
        let mut app = make_app();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        app.apply_update(PilotUpdate::PendingPrompt {
            request_id: id1,
            raw_prompt: "First?".into(),
        });
        app.apply_update(PilotUpdate::PendingPrompt {
            request_id: id2,
            raw_prompt: "Second?".into(),
        });

        assert_eq!(app.pending_selected, 0);

        // Navigate down in pending
        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.pending_selected, 1);

        // Should not go past last
        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.pending_selected, 1);

        // Navigate up
        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.pending_selected, 0);

        // Should not go below zero
        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.pending_selected, 0);
    }
}
