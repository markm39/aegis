//! Onboarding wizard state machine.
//!
//! Manages the current step, handles keyboard input, and tracks all user
//! selections for the streamlined 7-step onboarding wizard.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_types::config::{ChannelConfig, TelegramConfig};
use aegis_types::daemon::{
    AgentSlotConfig, AgentToolConfig, DaemonConfig, DaemonControlConfig, DashboardConfig,
    PersistenceConfig, RestartPolicy,
};

use crate::fleet_tui::wizard::ToolChoice;
use crate::tui_utils::delete_word_backward_pos;

// ---------------------------------------------------------------------------
// Step enum (7 steps + 2 terminal)
// ---------------------------------------------------------------------------

/// Steps in the onboarding wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardStep {
    /// Environment scan results.
    Welcome,
    /// Compact multi-field: tool, name, dir, task.
    AgentSetup,
    /// Conditional: only if Custom tool + API keys detected.
    ModelSelection,
    /// Optional Telegram setup with sub-phases.
    ChannelSetup,
    /// Review and confirm.
    Summary,
    /// Write config, start daemon, verify.
    HealthCheck,
    /// Completed successfully.
    Done,
    /// Cancelled by user.
    Cancelled,
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Which field is active in the AgentSetup screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentField {
    Tool,
    Name,
    WorkingDir,
    Task,
}

/// Sub-phase within ChannelSetup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelPhase {
    Offer,
    TokenInput,
    Validating,
}

/// Environment scan results.
#[derive(Debug, Clone)]
pub struct EnvScanResult {
    pub api_keys: Vec<DetectedProvider>,
    pub tools: Vec<DetectedTool>,
    pub ollama_running: bool,
    pub aegis_dir_ok: bool,
    pub aegis_dir_path: String,
}

/// A detected API key provider.
#[derive(Debug, Clone)]
pub struct DetectedProvider {
    pub env_var: &'static str,
    pub label: &'static str,
    pub default_model: &'static str,
    pub present: bool,
}

/// A detected agent tool binary.
#[derive(Debug, Clone)]
pub struct DetectedTool {
    pub name: &'static str,
    pub label: &'static str,
    pub found: bool,
}

/// Health check progress items.
#[derive(Debug, Clone)]
pub struct HealthCheckItem {
    pub label: String,
    pub status: HealthStatus,
}

/// Status of a single health check item.
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Pending,
    Running,
    Passed,
    Failed(String),
}

/// Events from the health check background worker.
pub enum HealthEvent {
    ConfigWritten,
    DaemonStarted,
    DaemonFailed(String),
    AllDone,
}

/// Events received from the Telegram background worker.
pub enum TelegramEvent {
    /// Bot token validated successfully.
    TokenValid { bot_username: String },
    /// Bot token is invalid.
    TokenInvalid(String),
    /// Chat ID discovered from user message.
    ChatDiscovered { chat_id: i64 },
    /// Confirmation message sent.
    ConfirmationSent,
    /// An error occurred.
    Error(String),
}

/// Telegram setup status for the progress display.
#[derive(Debug, Clone, PartialEq)]
pub enum TelegramStatus {
    Idle,
    ValidatingToken,
    WaitingForChat { bot_username: String },
    SendingConfirmation,
    Complete { bot_username: String, chat_id: i64 },
    Failed(String),
}

/// Result returned after the wizard completes.
pub struct OnboardResult {
    pub cancelled: bool,
    // Config is written and daemon started by the health check step.
    // The caller (onboard.rs) just transitions to the fleet TUI.
}

// ---------------------------------------------------------------------------
// Main state
// ---------------------------------------------------------------------------

/// The onboarding wizard state.
pub struct OnboardApp {
    /// Current step.
    pub step: OnboardStep,
    /// Whether the event loop should keep running.
    pub running: bool,

    // -- Step 1: Welcome --
    pub env_scan: EnvScanResult,

    // -- Step 2: AgentSetup (multi-field) --
    pub active_field: AgentField,
    pub tool_selected: usize,
    pub custom_command: String,
    pub custom_cursor: usize,
    pub name: String,
    pub name_cursor: usize,
    pub name_error: Option<String>,
    pub working_dir: String,
    pub working_dir_cursor: usize,
    pub working_dir_error: Option<String>,
    pub task: String,
    pub task_cursor: usize,

    // -- Step 3: ModelSelection (conditional) --
    pub show_model_step: bool,
    pub provider_selected: usize,

    // -- Step 4: ChannelSetup --
    pub channel_phase: ChannelPhase,
    pub channel_offer_selected: usize, // 0=Skip, 1=Yes
    pub telegram_token: String,
    pub telegram_token_cursor: usize,
    pub telegram_status: TelegramStatus,
    pub telegram_evt_rx: Option<mpsc::Receiver<TelegramEvent>>,
    pub telegram_result: Option<(String, i64, String)>, // (token, chat_id, bot_username)
    pub telegram_started_at: Option<Instant>,

    // -- Step 5: Summary --
    pub start_daemon: bool,

    // -- Step 6: HealthCheck --
    pub health_checks: Vec<HealthCheckItem>,
    pub health_evt_rx: Option<mpsc::Receiver<HealthEvent>>,
    pub health_started: bool,

    // -- Paste indicator --
    pub paste_indicator: Option<(String, Instant)>,
}

// ---------------------------------------------------------------------------
// Which text field is being edited
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum TextField {
    CustomCommand,
    Name,
    WorkingDir,
    Task,
    TelegramToken,
}

// ---------------------------------------------------------------------------
// Environment scan
// ---------------------------------------------------------------------------

fn scan_environment() -> EnvScanResult {
    let api_keys = vec![
        DetectedProvider {
            env_var: "ANTHROPIC_API_KEY",
            label: "Anthropic",
            default_model: "claude-sonnet-4-20250514",
            present: std::env::var("ANTHROPIC_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .is_some(),
        },
        DetectedProvider {
            env_var: "OPENAI_API_KEY",
            label: "OpenAI",
            default_model: "gpt-4o",
            present: std::env::var("OPENAI_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .is_some(),
        },
        DetectedProvider {
            env_var: "GOOGLE_API_KEY",
            label: "Google Gemini",
            default_model: "gemini-2.0-flash",
            present: std::env::var("GOOGLE_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .is_some()
                || std::env::var("GEMINI_API_KEY")
                    .ok()
                    .filter(|k| !k.is_empty())
                    .is_some(),
        },
        DetectedProvider {
            env_var: "OPENROUTER_API_KEY",
            label: "OpenRouter",
            default_model: "openrouter/auto",
            present: std::env::var("OPENROUTER_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .is_some(),
        },
    ];

    let tools = vec![
        DetectedTool {
            name: "claude",
            label: "Claude Code",
            found: crate::tui_utils::binary_exists("claude"),
        },
        DetectedTool {
            name: "codex",
            label: "Codex",
            found: crate::tui_utils::binary_exists("codex"),
        },
        DetectedTool {
            name: "openclaw",
            label: "OpenClaw",
            found: crate::tui_utils::binary_exists("openclaw"),
        },
    ];

    let ollama_running = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:11434".parse().unwrap(),
        std::time::Duration::from_millis(200),
    )
    .is_ok();

    let (aegis_dir_ok, aegis_dir_path) = match crate::commands::init::ensure_aegis_dir() {
        Ok(p) => (true, p.display().to_string()),
        Err(_) => (false, "~/.aegis".into()),
    };

    EnvScanResult {
        api_keys,
        tools,
        ollama_running,
        aegis_dir_ok,
        aegis_dir_path,
    }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl OnboardApp {
    /// Create a new wizard with sensible defaults.
    pub fn new() -> Self {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/tmp".into());

        let default_name = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "my-agent".into());

        let env_scan = scan_environment();

        // Pre-select best detected tool
        let tool_selected = env_scan
            .tools
            .iter()
            .position(|t| t.found)
            .unwrap_or(0);

        Self {
            step: OnboardStep::Welcome,
            running: true,
            env_scan,
            active_field: AgentField::Tool,
            tool_selected,
            custom_command: String::new(),
            custom_cursor: 0,
            name_cursor: default_name.len(),
            name: default_name,
            name_error: None,
            working_dir_cursor: cwd.len(),
            working_dir: cwd,
            working_dir_error: None,
            task: String::new(),
            task_cursor: 0,
            show_model_step: false,
            provider_selected: 0,
            channel_phase: ChannelPhase::Offer,
            channel_offer_selected: 0, // Skip by default
            telegram_token: String::new(),
            telegram_token_cursor: 0,
            telegram_status: TelegramStatus::Idle,
            telegram_evt_rx: None,
            telegram_result: None,
            telegram_started_at: None,
            start_daemon: true,
            health_checks: Vec::new(),
            health_evt_rx: None,
            health_started: false,
            paste_indicator: None,
        }
    }

    // -----------------------------------------------------------------------
    // Public accessors
    // -----------------------------------------------------------------------

    /// Progress label for the title bar.
    pub fn progress_text(&self) -> String {
        match self.step {
            OnboardStep::Welcome => "Environment".into(),
            OnboardStep::AgentSetup => "Agent".into(),
            OnboardStep::ModelSelection => "Model".into(),
            OnboardStep::ChannelSetup => "Notifications".into(),
            OnboardStep::Summary => "Review".into(),
            OnboardStep::HealthCheck => "Health Check".into(),
            OnboardStep::Done | OnboardStep::Cancelled => String::new(),
        }
    }

    /// Build the result from current state.
    pub fn result(&self) -> OnboardResult {
        OnboardResult {
            cancelled: self.step == OnboardStep::Cancelled,
        }
    }

    /// Return only providers with `present == true`, for ModelSelection rendering.
    pub fn available_providers(&self) -> Vec<&DetectedProvider> {
        self.env_scan
            .api_keys
            .iter()
            .filter(|p| p.present)
            .collect()
    }

    /// Get the selected tool choice (bounds-checked).
    pub fn tool_choice(&self) -> ToolChoice {
        // 0..2 map to built-in tools, 3 = Custom
        if self.tool_selected >= ToolChoice::ALL.len() {
            return ToolChoice::Custom;
        }
        ToolChoice::ALL
            .get(self.tool_selected)
            .copied()
            .unwrap_or(ToolChoice::ClaudeCode)
    }

    // -----------------------------------------------------------------------
    // Key handling
    // -----------------------------------------------------------------------

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Ctrl+C always cancels the wizard (raw mode captures the signal).
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.step = OnboardStep::Cancelled;
            self.running = false;
            return;
        }

        match self.step {
            OnboardStep::Welcome => self.handle_welcome(key),
            OnboardStep::AgentSetup => self.handle_agent_setup(key),
            OnboardStep::ModelSelection => self.handle_model_selection(key),
            OnboardStep::ChannelSetup => match self.channel_phase {
                ChannelPhase::Offer => self.handle_channel_offer(key),
                ChannelPhase::TokenInput => self.handle_channel_token(key),
                ChannelPhase::Validating => self.handle_channel_validating(key),
            },
            OnboardStep::Summary => self.handle_summary(key),
            OnboardStep::HealthCheck => self.handle_health_check(key),
            OnboardStep::Done | OnboardStep::Cancelled => {}
        }
    }

    /// Handle pasted text (from `Event::Paste` when bracketed paste is enabled).
    ///
    /// Inserts the pasted text at the cursor position of whichever text field
    /// is currently active. For single-line fields (name, dir, token), newlines
    /// are collapsed to spaces. The task field preserves newlines.
    pub fn handle_paste(&mut self, text: &str) {
        let (buf, cursor, is_task) = match self.step {
            OnboardStep::AgentSetup => match self.active_field {
                AgentField::Tool => return,
                AgentField::Name => (&mut self.name, &mut self.name_cursor, false),
                AgentField::WorkingDir => {
                    (&mut self.working_dir, &mut self.working_dir_cursor, false)
                }
                AgentField::Task => (&mut self.task, &mut self.task_cursor, true),
            },
            OnboardStep::ChannelSetup if self.channel_phase == ChannelPhase::TokenInput => {
                (&mut self.telegram_token, &mut self.telegram_token_cursor, false)
            }
            _ => return,
        };

        // Task keeps newlines; other fields collapse them
        let cleaned = if is_task {
            text.replace('\r', "")
        } else {
            text.replace(['\n', '\r'], " ")
        };

        buf.insert_str(*cursor, &cleaned);
        *cursor += cleaned.len();

        // Show paste indicator for large pastes
        if cleaned.len() > 20 {
            self.paste_indicator =
                Some((format!("[pasted {} chars]", cleaned.len()), Instant::now()));
        }
    }

    /// Poll for async Telegram events (called each tick from the event loop).
    pub fn poll_telegram(&mut self) {
        let evt = match &self.telegram_evt_rx {
            Some(rx) => rx.try_recv().ok(),
            None => None,
        };
        if let Some(evt) = evt {
            self.process_telegram_event(evt);
        }
    }

    /// Poll for async health check events (called each tick from the event loop).
    pub fn poll_health(&mut self) {
        let evt = match &self.health_evt_rx {
            Some(rx) => rx.try_recv().ok(),
            None => None,
        };
        if let Some(evt) = evt {
            match evt {
                HealthEvent::ConfigWritten => {
                    if let Some(c) = self.health_checks.first_mut() {
                        c.status = HealthStatus::Passed;
                    }
                    if let Some(c) = self.health_checks.get_mut(1) {
                        c.status = HealthStatus::Running;
                    }
                }
                HealthEvent::DaemonStarted => {
                    if let Some(c) = self.health_checks.get_mut(1) {
                        c.status = HealthStatus::Passed;
                    }
                }
                HealthEvent::DaemonFailed(e) => {
                    // Mark the currently running check as failed
                    for c in &mut self.health_checks {
                        if c.status == HealthStatus::Running {
                            c.status = HealthStatus::Failed(e.clone());
                            break;
                        }
                    }
                }
                HealthEvent::AllDone => {
                    // Mark any remaining pending as passed
                    for c in &mut self.health_checks {
                        if matches!(c.status, HealthStatus::Pending) {
                            c.status = HealthStatus::Passed;
                        }
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step handlers
    // -----------------------------------------------------------------------

    fn handle_welcome(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => self.step = OnboardStep::AgentSetup,
            KeyCode::Esc | KeyCode::Char('q') => {
                self.step = OnboardStep::Cancelled;
                self.running = false;
            }
            _ => {}
        }
    }

    fn handle_agent_setup(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.active_field = if key.code == KeyCode::Tab {
                    match self.active_field {
                        AgentField::Tool => AgentField::Name,
                        AgentField::Name => AgentField::WorkingDir,
                        AgentField::WorkingDir => AgentField::Task,
                        AgentField::Task => AgentField::Tool,
                    }
                } else {
                    match self.active_field {
                        AgentField::Tool => AgentField::Task,
                        AgentField::Name => AgentField::Tool,
                        AgentField::WorkingDir => AgentField::Name,
                        AgentField::Task => AgentField::WorkingDir,
                    }
                };
            }
            KeyCode::Enter => self.validate_and_advance_agent(),
            KeyCode::Esc => {
                self.step = OnboardStep::Welcome;
            }
            _ => self.handle_agent_field_input(key),
        }
    }

    fn handle_agent_field_input(&mut self, key: KeyEvent) {
        match self.active_field {
            AgentField::Tool => {
                if self.tool_choice() == ToolChoice::Custom {
                    // When Custom is selected, j/k still navigate, but other
                    // keys edit the custom command text.
                    match key.code {
                        KeyCode::Char('j') | KeyCode::Down => {
                            // Can't go further than Custom (last item)
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            self.tool_selected = self.tool_selected.saturating_sub(1);
                        }
                        _ => {
                            self.edit_text(key, TextField::CustomCommand);
                        }
                    }
                } else {
                    match key.code {
                        KeyCode::Char('j') | KeyCode::Down => {
                            self.tool_selected = (self.tool_selected + 1).min(3);
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            self.tool_selected = self.tool_selected.saturating_sub(1);
                        }
                        _ => {}
                    }
                }
                self.update_show_model_step();
            }
            AgentField::Name => {
                self.name_error = None;
                self.edit_text(key, TextField::Name);
            }
            AgentField::WorkingDir => {
                self.working_dir_error = None;
                self.edit_text(key, TextField::WorkingDir);
            }
            AgentField::Task => {
                self.edit_text(key, TextField::Task);
            }
        }
    }

    fn validate_and_advance_agent(&mut self) {
        // Validate tool (Custom needs non-empty command)
        if self.tool_choice() == ToolChoice::Custom && self.custom_command.trim().is_empty() {
            self.active_field = AgentField::Tool;
            return;
        }
        // Validate name
        let trimmed_name = self.name.trim().to_string();
        if trimmed_name.is_empty() {
            self.name_error = Some("Name cannot be empty".into());
            self.active_field = AgentField::Name;
            return;
        }
        if let Err(e) = aegis_types::validate_config_name(&trimmed_name) {
            self.name_error = Some(e.to_string());
            self.active_field = AgentField::Name;
            return;
        }
        // Validate working dir
        let trimmed_dir = self.working_dir.trim().to_string();
        if trimmed_dir.is_empty() {
            self.working_dir_error = Some("Directory cannot be empty".into());
            self.active_field = AgentField::WorkingDir;
            return;
        }
        if !std::path::Path::new(&trimmed_dir).is_dir() {
            self.working_dir_error = Some(format!("Not a directory: {trimmed_dir}"));
            self.active_field = AgentField::WorkingDir;
            return;
        }
        // All valid
        self.name_error = None;
        self.working_dir_error = None;
        self.update_show_model_step();
        if self.show_model_step {
            self.step = OnboardStep::ModelSelection;
        } else {
            self.channel_phase = ChannelPhase::Offer;
            self.step = OnboardStep::ChannelSetup;
        }
    }

    fn update_show_model_step(&mut self) {
        let is_custom = self.tool_choice() == ToolChoice::Custom;
        let has_keys = self.env_scan.api_keys.iter().any(|k| k.present);
        self.show_model_step = is_custom && has_keys;
    }

    fn handle_model_selection(&mut self, key: KeyEvent) {
        let count = self.available_providers().len();
        if count == 0 {
            // Nothing to select; skip
            self.channel_phase = ChannelPhase::Offer;
            self.step = OnboardStep::ChannelSetup;
            return;
        }
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.provider_selected = (self.provider_selected + 1).min(count - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.provider_selected = self.provider_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                self.channel_phase = ChannelPhase::Offer;
                self.step = OnboardStep::ChannelSetup;
            }
            KeyCode::Esc => {
                self.step = OnboardStep::AgentSetup;
            }
            _ => {}
        }
    }

    fn handle_channel_offer(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.channel_offer_selected = (self.channel_offer_selected + 1).min(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.channel_offer_selected = self.channel_offer_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.channel_offer_selected == 0 {
                    // Skip
                    self.step = OnboardStep::Summary;
                } else {
                    // Yes, set up Telegram
                    self.telegram_token_cursor = self.telegram_token.len();
                    self.channel_phase = ChannelPhase::TokenInput;
                }
            }
            KeyCode::Esc => {
                self.back_before_channel();
            }
            _ => {}
        }
    }

    fn handle_channel_token(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                if self.telegram_token.trim().is_empty() {
                    return; // Don't advance with empty token
                }
                self.start_telegram_validation();
                self.channel_phase = ChannelPhase::Validating;
            }
            KeyCode::Esc => {
                self.channel_phase = ChannelPhase::Offer;
            }
            _ => self.edit_text(key, TextField::TelegramToken),
        }
    }

    fn handle_channel_validating(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                // Cancel and go back to offer
                self.telegram_status = TelegramStatus::Idle;
                self.telegram_evt_rx = None;
                self.channel_phase = ChannelPhase::Offer;
            }
            KeyCode::Enter => {
                match &self.telegram_status {
                    TelegramStatus::Complete { .. } => {
                        self.step = OnboardStep::Summary;
                    }
                    TelegramStatus::Failed(_) => {
                        // Go back to token input to retry
                        self.telegram_status = TelegramStatus::Idle;
                        self.channel_phase = ChannelPhase::TokenInput;
                    }
                    _ => {} // Waiting -- do nothing
                }
            }
            _ => {}
        }
    }

    fn handle_summary(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') => {
                self.step = OnboardStep::HealthCheck;
                self.start_health_checks();
            }
            KeyCode::Char('d') => {
                self.start_daemon = !self.start_daemon;
            }
            KeyCode::Esc => {
                self.channel_phase = ChannelPhase::Offer;
                self.step = OnboardStep::ChannelSetup;
            }
            KeyCode::Char('q') | KeyCode::Char('n') => {
                self.step = OnboardStep::Cancelled;
                self.running = false;
            }
            _ => {}
        }
    }

    fn handle_health_check(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Enter {
            let all_done = self
                .health_checks
                .iter()
                .all(|c| matches!(c.status, HealthStatus::Passed | HealthStatus::Failed(_)));
            if all_done {
                self.step = OnboardStep::Done;
                self.running = false;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Navigation helpers
    // -----------------------------------------------------------------------

    fn back_before_channel(&mut self) {
        if self.show_model_step {
            self.step = OnboardStep::ModelSelection;
        } else {
            self.step = OnboardStep::AgentSetup;
        }
    }

    // -----------------------------------------------------------------------
    // Text editing
    // -----------------------------------------------------------------------

    /// Apply a key to a text field (character insert, backspace, cursor movement).
    fn edit_text(&mut self, key: KeyEvent, field: TextField) {
        let (text, cursor) = match field {
            TextField::CustomCommand => (&mut self.custom_command, &mut self.custom_cursor),
            TextField::Name => (&mut self.name, &mut self.name_cursor),
            TextField::WorkingDir => (&mut self.working_dir, &mut self.working_dir_cursor),
            TextField::Task => (&mut self.task, &mut self.task_cursor),
            TextField::TelegramToken => (&mut self.telegram_token, &mut self.telegram_token_cursor),
        };

        match key.code {
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => match c {
                'a' => *cursor = 0,
                'e' => *cursor = text.len(),
                'u' => {
                    text.drain(..*cursor);
                    *cursor = 0;
                }
                'w' => {
                    if *cursor > 0 {
                        let new_pos = delete_word_backward_pos(text, *cursor);
                        text.drain(new_pos..*cursor);
                        *cursor = new_pos;
                    }
                }
                _ => {}
            },
            KeyCode::Char(c) => {
                text.insert(*cursor, c);
                *cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if *cursor > 0 {
                    let prev = text[..*cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    text.remove(prev);
                    *cursor = prev;
                }
            }
            KeyCode::Left => {
                if *cursor > 0 {
                    *cursor = text[..*cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if *cursor < text.len() {
                    *cursor = text[*cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| *cursor + i)
                        .unwrap_or(text.len());
                }
            }
            KeyCode::Delete => {
                if *cursor < text.len() {
                    text.remove(*cursor);
                }
            }
            KeyCode::Home => {
                *cursor = 0;
            }
            KeyCode::End => {
                *cursor = text.len();
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Telegram flow
    // -----------------------------------------------------------------------

    /// Process a single Telegram event, updating status and result.
    fn process_telegram_event(&mut self, evt: TelegramEvent) {
        match evt {
            TelegramEvent::TokenValid { bot_username } => {
                self.telegram_status = TelegramStatus::WaitingForChat { bot_username };
            }
            TelegramEvent::TokenInvalid(e) => {
                self.telegram_status = TelegramStatus::Failed(format!("Invalid token: {e}"));
            }
            TelegramEvent::ChatDiscovered { chat_id } => {
                let bot_username = match &self.telegram_status {
                    TelegramStatus::WaitingForChat { bot_username } => bot_username.clone(),
                    _ => "bot".into(),
                };
                self.telegram_status = TelegramStatus::SendingConfirmation;
                self.telegram_result = Some((self.telegram_token.clone(), chat_id, bot_username));
            }
            TelegramEvent::ConfirmationSent => {
                if let Some((_, chat_id, ref bot_username)) = self.telegram_result {
                    self.telegram_status = TelegramStatus::Complete {
                        bot_username: bot_username.clone(),
                        chat_id,
                    };
                }
            }
            TelegramEvent::Error(e) => {
                self.telegram_status = TelegramStatus::Failed(e);
            }
        }
    }

    /// Launch the Telegram background worker.
    fn start_telegram_validation(&mut self) {
        let token = self.telegram_token.trim().to_string();
        self.telegram_status = TelegramStatus::ValidatingToken;
        self.telegram_started_at = Some(Instant::now());

        let (evt_tx, evt_rx) = mpsc::channel::<TelegramEvent>();
        self.telegram_evt_rx = Some(evt_rx);

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = evt_tx.send(TelegramEvent::Error(format!(
                        "Failed to create runtime: {e}"
                    )));
                    return;
                }
            };

            rt.block_on(async move {
                run_telegram_worker(token, evt_tx).await;
            });
        });
    }

    // -----------------------------------------------------------------------
    // Health check flow
    // -----------------------------------------------------------------------

    fn start_health_checks(&mut self) {
        self.health_started = true;
        self.health_checks = vec![HealthCheckItem {
            label: "Write daemon.toml".into(),
            status: HealthStatus::Running,
        }];
        if self.start_daemon {
            self.health_checks.push(HealthCheckItem {
                label: "Start daemon".into(),
                status: HealthStatus::Pending,
            });
        }

        let config = self.build_daemon_config();
        let start_daemon = self.start_daemon;
        let (tx, rx) = mpsc::channel::<HealthEvent>();
        self.health_evt_rx = Some(rx);

        std::thread::spawn(move || {
            let dir = aegis_types::daemon::daemon_dir();
            if let Err(e) = std::fs::create_dir_all(&dir) {
                let _ = tx.send(HealthEvent::DaemonFailed(format!(
                    "Failed to create dir: {e}"
                )));
                return;
            }
            let config_path = aegis_types::daemon::daemon_config_path();
            match config.to_toml() {
                Ok(toml_str) => {
                    if let Err(e) = std::fs::write(&config_path, &toml_str) {
                        let _ = tx.send(HealthEvent::DaemonFailed(format!(
                            "Failed to write config: {e}"
                        )));
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(HealthEvent::DaemonFailed(format!(
                        "Failed to serialize: {e}"
                    )));
                    return;
                }
            }
            let _ = tx.send(HealthEvent::ConfigWritten);

            if start_daemon {
                match crate::commands::daemon::start_quiet() {
                    Ok(_) => {
                        let _ = tx.send(HealthEvent::DaemonStarted);
                    }
                    Err(e) => {
                        let _ = tx.send(HealthEvent::DaemonFailed(format!("{e:#}")));
                        return;
                    }
                }
            }
            let _ = tx.send(HealthEvent::AllDone);
        });
    }

    // -----------------------------------------------------------------------
    // Config building
    // -----------------------------------------------------------------------

    fn build_agent_slot(&self) -> AgentSlotConfig {
        let tool = self.build_tool_config();
        let task = if self.task.trim().is_empty() {
            None
        } else {
            Some(self.task.clone())
        };
        crate::commands::build_agent_slot(
            self.name.trim().to_string(),
            tool,
            PathBuf::from(self.working_dir.trim()),
            task,
            RestartPolicy::OnFailure,
            5,
        )
    }

    fn build_tool_config(&self) -> AgentToolConfig {
        match self.tool_choice() {
            ToolChoice::ClaudeCode => AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: vec![],
            },
            ToolChoice::Codex => AgentToolConfig::Codex {
                approval_mode: "suggest".into(),
                one_shot: false,
                extra_args: vec![],
            },
            ToolChoice::OpenClaw => AgentToolConfig::OpenClaw {
                agent_name: None,
                extra_args: vec![],
            },
            ToolChoice::Custom => {
                // Split "command --flag1 --flag2" into command + args
                let parts: Vec<&str> = self.custom_command.split_whitespace().collect();
                let command = parts.first().map(|s| s.to_string()).unwrap_or_default();
                let args: Vec<String> = parts.iter().skip(1).map(|s| s.to_string()).collect();
                AgentToolConfig::Custom {
                    command,
                    args,
                    adapter: Default::default(),
                    env: vec![],
                }
            }
        }
    }

    fn build_daemon_config(&self) -> DaemonConfig {
        let agent = self.build_agent_slot();
        let channel = self.telegram_result.as_ref().map(|(token, chat_id, _)| {
            ChannelConfig::Telegram(TelegramConfig {
                bot_token: token.clone(),
                chat_id: *chat_id,
                poll_timeout_secs: 30,
                allow_group_commands: false,
                active_hours: None,
                webhook_mode: false,
                webhook_port: None,
                webhook_url: None,
                webhook_secret: None,
                inline_queries_enabled: false,
            })
        });

        DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: DashboardConfig::default(),
            alerts: vec![],
            agents: vec![agent],
            channel,
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
        }
    }
}

// ---------------------------------------------------------------------------
// Telegram background worker
// ---------------------------------------------------------------------------

/// Run the Telegram validation and chat discovery flow.
async fn run_telegram_worker(token: String, tx: mpsc::Sender<TelegramEvent>) {
    use aegis_channel::telegram::api::TelegramApi;

    let api = TelegramApi::new(&token);

    // Validate token
    let user = match api.get_me().await {
        Ok(u) => u,
        Err(e) => {
            let _ = tx.send(TelegramEvent::TokenInvalid(e.to_string()));
            return;
        }
    };

    let bot_username = user.username.unwrap_or_else(|| "bot".into());
    let _ = tx.send(TelegramEvent::TokenValid {
        bot_username: bot_username.clone(),
    });

    // Discover chat ID (use poll_for_chat_id to avoid println in raw mode)
    let chat_id = match crate::commands::telegram::poll_for_chat_id(&api, 60).await {
        Ok(id) => id,
        Err(e) => {
            let _ = tx.send(TelegramEvent::Error(e.to_string()));
            return;
        }
    };

    let _ = tx.send(TelegramEvent::ChatDiscovered { chat_id });

    // Send confirmation
    let msg =
        format!("Aegis connected! This chat will receive agent notifications.\nChat ID: {chat_id}");
    match api.send_message(chat_id, &msg, None, None, false).await {
        Ok(_) => {
            let _ = tx.send(TelegramEvent::ConfirmationSent);
        }
        Err(e) => {
            let _ = tx.send(TelegramEvent::Error(format!(
                "Failed to send confirmation: {e}"
            )));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn ctrl_c() -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn shift_tab() -> KeyEvent {
        KeyEvent {
            code: KeyCode::BackTab,
            modifiers: KeyModifiers::SHIFT,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    /// Create a test app with pre-set valid defaults so tests don't depend
    /// on environment scanning.
    fn test_app() -> OnboardApp {
        let mut app = OnboardApp::new();
        // Ensure valid defaults for advancing through steps
        app.name = "test-agent".into();
        app.name_cursor = app.name.len();
        app.working_dir = "/tmp".into();
        app.working_dir_cursor = app.working_dir.len();
        app
    }

    // -- 1. Initial state --

    #[test]
    fn initial_state() {
        let app = OnboardApp::new();
        assert_eq!(app.step, OnboardStep::Welcome);
        assert!(app.running);
        assert!(app.start_daemon);
        assert_eq!(app.active_field, AgentField::Tool);
        // env_scan should be populated
        assert!(!app.env_scan.api_keys.is_empty());
        assert!(!app.env_scan.tools.is_empty());
    }

    // -- 2. Welcome step --

    #[test]
    fn welcome_enter_goes_to_agent_setup() {
        let mut app = test_app();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::AgentSetup);
    }

    #[test]
    fn welcome_esc_cancels() {
        let mut app = test_app();
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn welcome_q_cancels() {
        let mut app = test_app();
        app.handle_key(press(KeyCode::Char('q')));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    // -- 3. AgentSetup field navigation --

    #[test]
    fn agent_setup_tab_cycles_forward() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        assert_eq!(app.active_field, AgentField::Tool);

        app.handle_key(press(KeyCode::Tab));
        assert_eq!(app.active_field, AgentField::Name);

        app.handle_key(press(KeyCode::Tab));
        assert_eq!(app.active_field, AgentField::WorkingDir);

        app.handle_key(press(KeyCode::Tab));
        assert_eq!(app.active_field, AgentField::Task);

        app.handle_key(press(KeyCode::Tab));
        assert_eq!(app.active_field, AgentField::Tool);
    }

    #[test]
    fn agent_setup_backtab_cycles_backward() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        assert_eq!(app.active_field, AgentField::Tool);

        app.handle_key(shift_tab());
        assert_eq!(app.active_field, AgentField::Task);

        app.handle_key(shift_tab());
        assert_eq!(app.active_field, AgentField::WorkingDir);

        app.handle_key(shift_tab());
        assert_eq!(app.active_field, AgentField::Name);

        app.handle_key(shift_tab());
        assert_eq!(app.active_field, AgentField::Tool);
    }

    // -- 4. AgentSetup tool navigation --

    #[test]
    fn agent_setup_tool_jk_navigation() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Tool;
        app.tool_selected = 0;

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.tool_selected, 1);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.tool_selected, 2);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.tool_selected, 3); // Custom

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.tool_selected, 3); // clamped

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.tool_selected, 2);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.tool_selected, 1);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.tool_selected, 0);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.tool_selected, 0); // clamped at 0
    }

    #[test]
    fn agent_setup_tool_arrow_navigation() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Tool;
        app.tool_selected = 0;

        app.handle_key(press(KeyCode::Down));
        assert_eq!(app.tool_selected, 1);

        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.tool_selected, 0);
    }

    // -- 5. AgentSetup text editing --

    #[test]
    fn agent_setup_typing_in_name_field() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Name;
        app.name.clear();
        app.name_cursor = 0;

        app.handle_key(press(KeyCode::Char('t')));
        app.handle_key(press(KeyCode::Char('e')));
        app.handle_key(press(KeyCode::Char('s')));
        app.handle_key(press(KeyCode::Char('t')));
        assert_eq!(app.name, "test");
        assert_eq!(app.name_cursor, 4);
    }

    #[test]
    fn agent_setup_cursor_movement() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Name;
        app.name = "hello".into();
        app.name_cursor = 5;

        app.handle_key(press(KeyCode::Left));
        assert_eq!(app.name_cursor, 4);

        app.handle_key(press(KeyCode::Home));
        assert_eq!(app.name_cursor, 0);

        app.handle_key(press(KeyCode::End));
        assert_eq!(app.name_cursor, 5);
    }

    #[test]
    fn agent_setup_backspace() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Name;
        app.name = "test".into();
        app.name_cursor = 4;

        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.name, "tes");
        assert_eq!(app.name_cursor, 3);

        app.name_cursor = 0;
        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.name, "tes"); // no change at beginning
    }

    // -- 6. AgentSetup validation --

    #[test]
    fn agent_setup_empty_name_shows_error() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.name = "  ".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::AgentSetup);
        assert!(app.name_error.is_some());
        assert_eq!(app.active_field, AgentField::Name);
    }

    #[test]
    fn agent_setup_invalid_name_shows_error() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.name = "../bad".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::AgentSetup);
        assert!(app.name_error.is_some());
        assert_eq!(app.active_field, AgentField::Name);
    }

    #[test]
    fn agent_setup_invalid_dir_shows_error() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.name = "good-name".into();
        app.working_dir = "/nonexistent/path/unlikely".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::AgentSetup);
        assert!(app.working_dir_error.is_some());
        assert_eq!(app.active_field, AgentField::WorkingDir);
    }

    #[test]
    fn agent_setup_empty_dir_shows_error() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.name = "good-name".into();
        app.working_dir = "  ".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::AgentSetup);
        assert!(app.working_dir_error.is_some());
        assert_eq!(app.active_field, AgentField::WorkingDir);
    }

    #[test]
    fn agent_setup_empty_custom_command_blocked() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        // Select Custom tool (index 3)
        app.tool_selected = 3;
        app.custom_command.clear();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::AgentSetup);
        assert_eq!(app.active_field, AgentField::Tool);
    }

    // -- 7. AgentSetup valid advance --

    #[test]
    fn agent_setup_valid_advances_to_channel() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        // show_model_step defaults to false with non-custom tool
        app.tool_selected = 0; // ClaudeCode
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ChannelSetup);
        assert_eq!(app.channel_phase, ChannelPhase::Offer);
    }

    #[test]
    fn agent_setup_custom_with_keys_advances_to_model() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.tool_selected = 3; // Custom
        app.custom_command = "/usr/bin/my-agent".into();
        // Simulate having API keys present
        app.env_scan.api_keys[0].present = true;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ModelSelection);
    }

    // -- 8. AgentSetup Esc --

    #[test]
    fn agent_setup_esc_goes_to_welcome() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Welcome);
    }

    // -- 9. ModelSelection navigation --

    #[test]
    fn model_selection_jk_navigation() {
        let mut app = test_app();
        app.step = OnboardStep::ModelSelection;
        // Set up multiple available providers
        app.env_scan.api_keys[0].present = true;
        app.env_scan.api_keys[1].present = true;
        app.provider_selected = 0;

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.provider_selected, 1);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.provider_selected, 1); // clamped at 2 providers

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.provider_selected, 0);
    }

    // -- 10. ModelSelection advance --

    #[test]
    fn model_selection_enter_goes_to_channel() {
        let mut app = test_app();
        app.step = OnboardStep::ModelSelection;
        app.env_scan.api_keys[0].present = true;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ChannelSetup);
        assert_eq!(app.channel_phase, ChannelPhase::Offer);
    }

    // -- 11. ModelSelection Esc --

    #[test]
    fn model_selection_esc_goes_to_agent_setup() {
        let mut app = test_app();
        app.step = OnboardStep::ModelSelection;
        app.env_scan.api_keys[0].present = true;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::AgentSetup);
    }

    // -- 12. Channel offer Skip --

    #[test]
    fn channel_offer_skip_goes_to_summary() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::Offer;
        app.channel_offer_selected = 0; // Skip
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Summary);
    }

    // -- 13. Channel offer Yes --

    #[test]
    fn channel_offer_yes_goes_to_token_input() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::Offer;
        app.channel_offer_selected = 1; // Yes
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ChannelSetup);
        assert_eq!(app.channel_phase, ChannelPhase::TokenInput);
    }

    // -- 14. Channel offer Esc --

    #[test]
    fn channel_offer_esc_goes_back_no_model() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::Offer;
        app.show_model_step = false;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::AgentSetup);
    }

    #[test]
    fn channel_offer_esc_goes_back_with_model() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::Offer;
        app.show_model_step = true;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::ModelSelection);
    }

    // -- 15. Channel token Enter empty --

    #[test]
    fn channel_token_enter_empty_stays() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::TokenInput;
        app.telegram_token.clear();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ChannelSetup);
        assert_eq!(app.channel_phase, ChannelPhase::TokenInput);
    }

    // -- 16. Channel token Enter non-empty --

    #[test]
    fn channel_token_enter_nonempty_starts_validation() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::TokenInput;
        app.telegram_token = "123456:ABC-DEF".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.channel_phase, ChannelPhase::Validating);
        assert_eq!(app.telegram_status, TelegramStatus::ValidatingToken);
    }

    // -- 17. Channel token Esc --

    #[test]
    fn channel_token_esc_goes_to_offer() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::TokenInput;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.channel_phase, ChannelPhase::Offer);
    }

    // -- 18. Channel validating complete Enter --

    #[test]
    fn channel_validating_complete_enter_goes_to_summary() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::Validating;
        app.telegram_status = TelegramStatus::Complete {
            bot_username: "testbot".into(),
            chat_id: 12345,
        };
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Summary);
    }

    // -- 19. Channel validating failed Enter --

    #[test]
    fn channel_validating_failed_enter_retries() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::Validating;
        app.telegram_status = TelegramStatus::Failed("bad token".into());
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.channel_phase, ChannelPhase::TokenInput);
        assert_eq!(app.telegram_status, TelegramStatus::Idle);
    }

    // -- 20. Channel validating Esc --

    #[test]
    fn channel_validating_esc_cancels_to_offer() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::Validating;
        app.telegram_status = TelegramStatus::ValidatingToken;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.channel_phase, ChannelPhase::Offer);
        assert_eq!(app.telegram_status, TelegramStatus::Idle);
    }

    // -- 21. Summary Enter --

    #[test]
    fn summary_enter_goes_to_health_check() {
        let mut app = test_app();
        app.step = OnboardStep::Summary;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::HealthCheck);
        assert!(app.health_started);
    }

    // -- 22. Summary d toggles daemon --

    #[test]
    fn summary_d_toggles_daemon() {
        let mut app = test_app();
        app.step = OnboardStep::Summary;
        assert!(app.start_daemon);
        app.handle_key(press(KeyCode::Char('d')));
        assert!(!app.start_daemon);
        app.handle_key(press(KeyCode::Char('d')));
        assert!(app.start_daemon);
    }

    // -- 23. Summary Esc --

    #[test]
    fn summary_esc_goes_to_channel_offer() {
        let mut app = test_app();
        app.step = OnboardStep::Summary;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::ChannelSetup);
        assert_eq!(app.channel_phase, ChannelPhase::Offer);
    }

    // -- 24. Summary q cancels --

    #[test]
    fn summary_q_cancels() {
        let mut app = test_app();
        app.step = OnboardStep::Summary;
        app.handle_key(press(KeyCode::Char('q')));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn summary_n_cancels() {
        let mut app = test_app();
        app.step = OnboardStep::Summary;
        app.handle_key(press(KeyCode::Char('n')));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    // -- 25. HealthCheck Enter when all done --

    #[test]
    fn health_check_enter_when_all_done() {
        let mut app = test_app();
        app.step = OnboardStep::HealthCheck;
        app.health_checks = vec![HealthCheckItem {
            label: "Write daemon.toml".into(),
            status: HealthStatus::Passed,
        }];
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Done);
        assert!(!app.running);
    }

    #[test]
    fn health_check_enter_with_failure_still_completes() {
        let mut app = test_app();
        app.step = OnboardStep::HealthCheck;
        app.health_checks = vec![
            HealthCheckItem {
                label: "Write daemon.toml".into(),
                status: HealthStatus::Passed,
            },
            HealthCheckItem {
                label: "Start daemon".into(),
                status: HealthStatus::Failed("oops".into()),
            },
        ];
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Done);
        assert!(!app.running);
    }

    // -- 26. HealthCheck Enter when not done --

    #[test]
    fn health_check_enter_when_not_done_stays() {
        let mut app = test_app();
        app.step = OnboardStep::HealthCheck;
        app.health_checks = vec![HealthCheckItem {
            label: "Write daemon.toml".into(),
            status: HealthStatus::Running,
        }];
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::HealthCheck);
    }

    #[test]
    fn health_check_enter_when_pending_stays() {
        let mut app = test_app();
        app.step = OnboardStep::HealthCheck;
        app.health_checks = vec![
            HealthCheckItem {
                label: "Write daemon.toml".into(),
                status: HealthStatus::Passed,
            },
            HealthCheckItem {
                label: "Start daemon".into(),
                status: HealthStatus::Pending,
            },
        ];
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::HealthCheck);
    }

    // -- 27. Ctrl+C from every step --

    #[test]
    fn ctrl_c_cancels_from_welcome() {
        let mut app = test_app();
        app.handle_key(ctrl_c());
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn ctrl_c_cancels_from_any_step() {
        for step in [
            OnboardStep::AgentSetup,
            OnboardStep::ModelSelection,
            OnboardStep::ChannelSetup,
            OnboardStep::Summary,
            OnboardStep::HealthCheck,
        ] {
            let mut app = test_app();
            app.step = step;
            if step == OnboardStep::ChannelSetup {
                app.channel_phase = ChannelPhase::Offer;
            }
            app.handle_key(ctrl_c());
            assert_eq!(
                app.step,
                OnboardStep::Cancelled,
                "Ctrl+C should cancel at {:?}",
                step
            );
            assert!(!app.running);
        }
    }

    // -- 28. Full flow (fast path) --

    #[test]
    fn full_fast_path_flow() {
        let mut app = test_app();

        // Welcome -> AgentSetup
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::AgentSetup);

        // AgentSetup (valid defaults) -> ChannelSetup (skipping model selection)
        app.tool_selected = 0; // ClaudeCode (not Custom, so no model step)
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ChannelSetup);
        assert_eq!(app.channel_phase, ChannelPhase::Offer);

        // ChannelSetup(Offer, Skip) -> Summary
        app.channel_offer_selected = 0; // Skip
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Summary);

        // Summary -> HealthCheck (triggers start_health_checks)
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::HealthCheck);
        assert!(app.health_started);

        // Simulate health checks completing
        app.health_checks = vec![
            HealthCheckItem {
                label: "Write daemon.toml".into(),
                status: HealthStatus::Passed,
            },
            HealthCheckItem {
                label: "Start daemon".into(),
                status: HealthStatus::Passed,
            },
        ];

        // HealthCheck(AllDone) -> Done
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Done);
        assert!(!app.running);
    }

    // -- 29. Result cancelled --

    #[test]
    fn result_cancelled_when_step_is_cancelled() {
        let mut app = test_app();
        app.step = OnboardStep::Cancelled;
        let result = app.result();
        assert!(result.cancelled);
    }

    // -- 30. Result not cancelled --

    #[test]
    fn result_not_cancelled_when_step_is_done() {
        let mut app = test_app();
        app.step = OnboardStep::Done;
        let result = app.result();
        assert!(!result.cancelled);
    }

    // -- 31. Paste handling --

    #[test]
    fn paste_into_name_field() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Name;
        app.name.clear();
        app.name_cursor = 0;

        app.handle_paste("pasted-name");
        assert_eq!(app.name, "pasted-name");
        assert_eq!(app.name_cursor, 11);
    }

    #[test]
    fn paste_into_task_preserves_newlines() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Task;
        app.task.clear();
        app.task_cursor = 0;

        app.handle_paste("line1\nline2");
        assert_eq!(app.task, "line1\nline2");
    }

    #[test]
    fn paste_into_name_collapses_newlines() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Name;
        app.name.clear();
        app.name_cursor = 0;

        app.handle_paste("line1\nline2");
        assert_eq!(app.name, "line1 line2");
    }

    #[test]
    fn paste_into_tool_field_does_nothing() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Tool;
        let before_tool = app.tool_selected;

        app.handle_paste("garbage");
        assert_eq!(app.tool_selected, before_tool);
    }

    #[test]
    fn paste_into_telegram_token() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::TokenInput;
        app.telegram_token.clear();
        app.telegram_token_cursor = 0;

        app.handle_paste("123456:ABC-DEF");
        assert_eq!(app.telegram_token, "123456:ABC-DEF");
    }

    #[test]
    fn paste_shows_indicator_for_large_paste() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Task;
        app.task.clear();
        app.task_cursor = 0;

        let long_text = "a".repeat(50);
        app.handle_paste(&long_text);
        assert!(app.paste_indicator.is_some());
    }

    // -- 32. tool_choice --

    #[test]
    fn tool_choice_bounds_checked() {
        let mut app = test_app();
        app.tool_selected = 0;
        assert_eq!(app.tool_choice(), ToolChoice::ClaudeCode);

        app.tool_selected = 1;
        assert_eq!(app.tool_choice(), ToolChoice::Codex);

        app.tool_selected = 2;
        assert_eq!(app.tool_choice(), ToolChoice::OpenClaw);

        app.tool_selected = 3;
        assert_eq!(app.tool_choice(), ToolChoice::Custom);

        // Out of bounds defaults to Custom
        app.tool_selected = 99;
        assert_eq!(app.tool_choice(), ToolChoice::Custom);
    }

    // -- 33. build_tool_config --

    #[test]
    fn build_tool_config_claude_code() {
        let mut app = test_app();
        app.tool_selected = 0;
        let config = app.build_tool_config();
        assert!(matches!(config, AgentToolConfig::ClaudeCode { .. }));
    }

    #[test]
    fn build_tool_config_codex() {
        let mut app = test_app();
        app.tool_selected = 1;
        let config = app.build_tool_config();
        assert!(matches!(config, AgentToolConfig::Codex { .. }));
    }

    #[test]
    fn build_tool_config_openclaw() {
        let mut app = test_app();
        app.tool_selected = 2;
        let config = app.build_tool_config();
        assert!(matches!(config, AgentToolConfig::OpenClaw { .. }));
    }

    #[test]
    fn build_tool_config_custom() {
        let mut app = test_app();
        app.tool_selected = 3;
        app.custom_command = "/usr/bin/my-agent --flag".into();
        let config = app.build_tool_config();
        match config {
            AgentToolConfig::Custom { command, args, .. } => {
                assert_eq!(command, "/usr/bin/my-agent");
                assert_eq!(args, vec!["--flag".to_string()]);
            }
            other => panic!("Expected Custom, got {:?}", other),
        }
    }

    // -- Additional edge case tests --

    #[test]
    fn channel_offer_jk_navigation() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSetup;
        app.channel_phase = ChannelPhase::Offer;
        app.channel_offer_selected = 0;

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.channel_offer_selected, 1);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.channel_offer_selected, 1); // clamped

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.channel_offer_selected, 0);
    }

    #[test]
    fn progress_text_for_each_step() {
        let mut app = test_app();

        app.step = OnboardStep::Welcome;
        assert_eq!(app.progress_text(), "Environment");

        app.step = OnboardStep::AgentSetup;
        assert_eq!(app.progress_text(), "Agent");

        app.step = OnboardStep::ModelSelection;
        assert_eq!(app.progress_text(), "Model");

        app.step = OnboardStep::ChannelSetup;
        assert_eq!(app.progress_text(), "Notifications");

        app.step = OnboardStep::Summary;
        assert_eq!(app.progress_text(), "Review");

        app.step = OnboardStep::HealthCheck;
        assert_eq!(app.progress_text(), "Health Check");

        app.step = OnboardStep::Done;
        assert_eq!(app.progress_text(), "");

        app.step = OnboardStep::Cancelled;
        assert_eq!(app.progress_text(), "");
    }

    #[test]
    fn poll_health_processes_config_written() {
        let mut app = test_app();
        app.health_checks = vec![
            HealthCheckItem {
                label: "Write daemon.toml".into(),
                status: HealthStatus::Running,
            },
            HealthCheckItem {
                label: "Start daemon".into(),
                status: HealthStatus::Pending,
            },
        ];
        let (tx, rx) = mpsc::channel();
        app.health_evt_rx = Some(rx);
        tx.send(HealthEvent::ConfigWritten).unwrap();
        app.poll_health();
        assert_eq!(app.health_checks[0].status, HealthStatus::Passed);
        assert_eq!(app.health_checks[1].status, HealthStatus::Running);
    }

    #[test]
    fn poll_health_processes_daemon_started() {
        let mut app = test_app();
        app.health_checks = vec![
            HealthCheckItem {
                label: "Write daemon.toml".into(),
                status: HealthStatus::Passed,
            },
            HealthCheckItem {
                label: "Start daemon".into(),
                status: HealthStatus::Running,
            },
        ];
        let (tx, rx) = mpsc::channel();
        app.health_evt_rx = Some(rx);
        tx.send(HealthEvent::DaemonStarted).unwrap();
        app.poll_health();
        assert_eq!(app.health_checks[1].status, HealthStatus::Passed);
    }

    #[test]
    fn poll_health_processes_daemon_failed() {
        let mut app = test_app();
        app.health_checks = vec![
            HealthCheckItem {
                label: "Write daemon.toml".into(),
                status: HealthStatus::Running,
            },
        ];
        let (tx, rx) = mpsc::channel();
        app.health_evt_rx = Some(rx);
        tx.send(HealthEvent::DaemonFailed("boom".into())).unwrap();
        app.poll_health();
        assert_eq!(
            app.health_checks[0].status,
            HealthStatus::Failed("boom".into())
        );
    }

    #[test]
    fn summary_y_goes_to_health_check() {
        let mut app = test_app();
        app.step = OnboardStep::Summary;
        app.handle_key(press(KeyCode::Char('y')));
        assert_eq!(app.step, OnboardStep::HealthCheck);
    }

    #[test]
    fn agent_setup_typing_clears_name_error() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::Name;
        app.name_error = Some("some error".into());
        app.handle_key(press(KeyCode::Char('a')));
        assert!(app.name_error.is_none());
    }

    #[test]
    fn agent_setup_typing_clears_dir_error() {
        let mut app = test_app();
        app.step = OnboardStep::AgentSetup;
        app.active_field = AgentField::WorkingDir;
        app.working_dir_error = Some("some error".into());
        app.handle_key(press(KeyCode::Char('a')));
        assert!(app.working_dir_error.is_none());
    }

    #[test]
    fn available_providers_filters_present() {
        let mut app = test_app();
        // By default, providers depend on environment.
        // Set all to not present, then enable one.
        for p in &mut app.env_scan.api_keys {
            p.present = false;
        }
        assert_eq!(app.available_providers().len(), 0);

        app.env_scan.api_keys[0].present = true;
        assert_eq!(app.available_providers().len(), 1);
        assert_eq!(app.available_providers()[0].label, "Anthropic");
    }

    #[test]
    fn build_agent_slot_produces_valid_config() {
        let mut app = test_app();
        app.name = "my-agent".into();
        app.working_dir = "/tmp".into();
        app.task = "do stuff".into();
        app.tool_selected = 0;

        let slot = app.build_agent_slot();
        assert_eq!(slot.name, "my-agent");
        assert_eq!(slot.working_dir, PathBuf::from("/tmp"));
        assert_eq!(slot.task, Some("do stuff".into()));
        assert!(matches!(slot.tool, AgentToolConfig::ClaudeCode { .. }));
        assert_eq!(slot.restart, RestartPolicy::OnFailure);
        assert_eq!(slot.max_restarts, 5);
    }

    #[test]
    fn build_daemon_config_includes_telegram() {
        let mut app = test_app();
        app.telegram_result = Some(("token".into(), 12345, "bot".into()));
        let config = app.build_daemon_config();
        assert!(config.channel.is_some());
        assert_eq!(config.agents.len(), 1);
    }

    #[test]
    fn build_daemon_config_no_telegram() {
        let app = test_app();
        let config = app.build_daemon_config();
        assert!(config.channel.is_none());
        assert_eq!(config.agents.len(), 1);
    }
}
