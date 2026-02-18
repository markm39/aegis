//! Onboarding wizard state machine.
//!
//! Manages the current step, handles keyboard input, and tracks all user
//! selections for the first-run onboarding wizard.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_types::config::ChannelConfig;
use aegis_types::daemon::{AgentSlotConfig, AgentToolConfig};

use crate::fleet_tui::wizard::{RestartChoice, ToolChoice};
use crate::tui_utils::delete_word_backward_pos;

/// Steps in the onboarding wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardStep {
    /// Welcome screen with system check results.
    Welcome,
    /// Select agent tool.
    Tool,
    /// Custom command path (only when tool == Custom).
    CustomCommand,
    /// Agent name.
    Name,
    /// Working directory.
    WorkingDir,
    /// Task / initial prompt.
    Task,
    /// Restart policy selection.
    RestartPolicy,
    /// Ask whether to set up Telegram.
    TelegramOffer,
    /// Telegram bot token input.
    TelegramToken,
    /// Async validation and chat discovery.
    TelegramProgress,
    /// Review and confirm.
    Summary,
    /// Completed.
    Done,
    /// Cancelled.
    Cancelled,
}

impl OnboardStep {
    /// Step number for the progress display (1-based).
    pub fn number(&self) -> usize {
        match self {
            OnboardStep::Welcome => 1,
            OnboardStep::Tool | OnboardStep::CustomCommand => 2,
            OnboardStep::Name => 3,
            OnboardStep::WorkingDir => 4,
            OnboardStep::Task => 5,
            OnboardStep::RestartPolicy => 6,
            OnboardStep::TelegramOffer
            | OnboardStep::TelegramToken
            | OnboardStep::TelegramProgress => 7,
            OnboardStep::Summary => 8,
            OnboardStep::Done | OnboardStep::Cancelled => 8,
        }
    }

    /// Total steps shown in the progress display.
    pub fn total() -> usize {
        8
    }

    /// Label for the progress display.
    pub fn label(&self) -> &'static str {
        match self {
            OnboardStep::Welcome => "Welcome",
            OnboardStep::Tool | OnboardStep::CustomCommand => "Agent Tool",
            OnboardStep::Name => "Agent Name",
            OnboardStep::WorkingDir => "Working Directory",
            OnboardStep::Task => "Task",
            OnboardStep::RestartPolicy => "Restart Policy",
            OnboardStep::TelegramOffer
            | OnboardStep::TelegramToken
            | OnboardStep::TelegramProgress => "Telegram",
            OnboardStep::Summary => "Summary",
            OnboardStep::Done | OnboardStep::Cancelled => "Complete",
        }
    }
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

/// Telegram setup status for the progress step.
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
    pub agent_slot: AgentSlotConfig,
    pub channel: Option<ChannelConfig>,
    pub start_daemon: bool,
}

/// The onboarding wizard state.
pub struct OnboardApp {
    /// Current step.
    pub step: OnboardStep,
    /// Whether the event loop should keep running.
    pub running: bool,

    // -- Welcome --
    pub aegis_dir_ok: bool,
    pub aegis_dir_path: String,

    // -- Tool --
    pub tool_selected: usize,

    // -- Custom command --
    pub custom_command: String,
    pub custom_cursor: usize,

    // -- Name --
    pub name: String,
    pub name_cursor: usize,
    pub name_error: Option<String>,

    // -- Working dir --
    pub working_dir: String,
    pub working_dir_cursor: usize,
    pub working_dir_error: Option<String>,

    // -- Task --
    pub task: String,
    pub task_cursor: usize,

    // -- Restart policy --
    pub restart_selected: usize,

    // -- Telegram offer --
    pub telegram_offer_selected: usize, // 0 = Yes, 1 = No

    // -- Telegram token --
    pub telegram_token: String,
    pub telegram_token_cursor: usize,
    pub telegram_status: TelegramStatus,

    // -- Telegram async --
    pub telegram_evt_rx: Option<mpsc::Receiver<TelegramEvent>>,
    pub telegram_result: Option<(String, i64, String)>, // (token, chat_id, bot_username)

    // -- Summary --
    pub start_daemon: bool,

    // -- Paste indicator --
    /// Temporary paste notification: (message, when).
    pub paste_indicator: Option<(String, Instant)>,
}

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

        let (aegis_dir_ok, aegis_dir_path) = match crate::commands::init::ensure_aegis_dir() {
            Ok(p) => (true, p.display().to_string()),
            Err(_) => (false, "~/.aegis".into()),
        };

        Self {
            step: OnboardStep::Welcome,
            running: true,
            aegis_dir_ok,
            aegis_dir_path,
            tool_selected: 0,
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
            restart_selected: 0,
            telegram_offer_selected: 1, // default to No
            telegram_token: String::new(),
            telegram_token_cursor: 0,
            telegram_status: TelegramStatus::Idle,
            telegram_evt_rx: None,
            telegram_result: None,
            start_daemon: true,
            paste_indicator: None,
        }
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Ctrl+C always cancels the wizard (raw mode captures the signal).
        if key.code == KeyCode::Char('c')
            && key.modifiers.contains(KeyModifiers::CONTROL)
        {
            self.step = OnboardStep::Cancelled;
            self.running = false;
            return;
        }

        match self.step {
            OnboardStep::Welcome => self.handle_welcome(key),
            OnboardStep::Tool => self.handle_tool(key),
            OnboardStep::CustomCommand => self.handle_text(key, TextField::CustomCommand),
            OnboardStep::Name => self.handle_name(key),
            OnboardStep::WorkingDir => self.handle_working_dir(key),
            OnboardStep::Task => self.handle_text(key, TextField::Task),
            OnboardStep::RestartPolicy => self.handle_restart(key),
            OnboardStep::TelegramOffer => self.handle_telegram_offer(key),
            OnboardStep::TelegramToken => self.handle_text(key, TextField::TelegramToken),
            OnboardStep::TelegramProgress => self.handle_telegram_progress(key),
            OnboardStep::Summary => self.handle_summary(key),
            OnboardStep::Done | OnboardStep::Cancelled => {}
        }
    }

    /// Handle pasted text (from `Event::Paste` when bracketed paste is enabled).
    ///
    /// Inserts the pasted text at the cursor position of whichever text field
    /// is currently active. For single-line fields (name, dir, token), newlines
    /// are collapsed to spaces. The task field preserves newlines.
    pub fn handle_paste(&mut self, text: &str) {
        let (buf, cursor) = match self.step {
            OnboardStep::CustomCommand => (&mut self.custom_command, &mut self.custom_cursor),
            OnboardStep::Name => (&mut self.name, &mut self.name_cursor),
            OnboardStep::WorkingDir => (&mut self.working_dir, &mut self.working_dir_cursor),
            OnboardStep::Task => (&mut self.task, &mut self.task_cursor),
            OnboardStep::TelegramToken => {
                (&mut self.telegram_token, &mut self.telegram_token_cursor)
            }
            _ => return, // Not a text input step
        };

        // Task keeps newlines; other fields collapse them
        let cleaned = if self.step == OnboardStep::Task {
            text.replace('\r', "")
        } else {
            text.replace(['\n', '\r'], " ")
        };

        buf.insert_str(*cursor, &cleaned);
        *cursor += cleaned.len();

        // Show paste indicator for large pastes
        if cleaned.len() > 20 {
            self.paste_indicator = Some((
                format!("[pasted {} chars]", cleaned.len()),
                Instant::now(),
            ));
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

    /// Process a single Telegram event, updating status and result.
    fn process_telegram_event(&mut self, evt: TelegramEvent) {
        match evt {
            TelegramEvent::TokenValid { bot_username } => {
                self.telegram_status = TelegramStatus::WaitingForChat {
                    bot_username,
                };
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
                self.telegram_result = Some((
                    self.telegram_token.clone(),
                    chat_id,
                    bot_username,
                ));
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

    /// Build the result from current state.
    pub fn result(&self) -> OnboardResult {
        if self.step == OnboardStep::Cancelled {
            return OnboardResult {
                cancelled: true,
                agent_slot: self.build_agent_slot(),
                channel: None,
                start_daemon: false,
            };
        }

        let channel = self.telegram_result.as_ref().map(|(token, chat_id, _)| {
            ChannelConfig::Telegram(aegis_types::config::TelegramConfig {
                bot_token: token.clone(),
                chat_id: *chat_id,
                poll_timeout_secs: 30,
                allow_group_commands: false,
            })
        });

        OnboardResult {
            cancelled: false,
            agent_slot: self.build_agent_slot(),
            channel,
            start_daemon: self.start_daemon,
        }
    }

    /// Get the selected tool choice (bounds-checked).
    fn tool_choice(&self) -> ToolChoice {
        ToolChoice::ALL.get(self.tool_selected)
            .copied()
            .unwrap_or(ToolChoice::ClaudeCode)
    }

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
            RestartChoice::ALL.get(self.restart_selected)
                .copied()
                .unwrap_or(RestartChoice::OnFailure)
                .to_policy(),
            5,
        )
    }

    fn build_tool_config(&self) -> AgentToolConfig {
        match ToolChoice::ALL.get(self.tool_selected).copied().unwrap_or(ToolChoice::ClaudeCode) {
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
            ToolChoice::Cursor => AgentToolConfig::Cursor {
                assume_running: false,
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

    // -- Step handlers --

    fn handle_welcome(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => self.step = OnboardStep::Tool,
            KeyCode::Esc | KeyCode::Char('q') => {
                self.step = OnboardStep::Cancelled;
                self.running = false;
            }
            _ => {}
        }
    }

    fn handle_tool(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.tool_selected =
                    (self.tool_selected + 1).min(ToolChoice::ALL.len() - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.tool_selected = self.tool_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.tool_choice() == ToolChoice::Custom {
                    self.custom_cursor = self.custom_command.len();
                    self.step = OnboardStep::CustomCommand;
                } else {
                    self.name_cursor = self.name.len();
                    self.step = OnboardStep::Name;
                }
            }
            KeyCode::Esc => self.step = OnboardStep::Welcome,
            _ => {}
        }
    }

    fn handle_name(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                let trimmed = self.name.trim();
                if trimmed.is_empty() {
                    self.name_error = Some("Name cannot be empty".into());
                    return;
                }
                match aegis_types::validate_config_name(trimmed) {
                    Ok(()) => {
                        self.name_error = None;
                        self.working_dir_cursor = self.working_dir.len();
                        self.step = OnboardStep::WorkingDir;
                    }
                    Err(e) => {
                        self.name_error = Some(e.to_string());
                    }
                }
            }
            KeyCode::Esc => {
                self.name_error = None;
                if self.tool_choice() == ToolChoice::Custom {
                    self.step = OnboardStep::CustomCommand;
                } else {
                    self.step = OnboardStep::Tool;
                }
            }
            _ => {
                self.name_error = None;
                self.edit_text(key, TextField::Name);
            }
        }
    }

    fn handle_working_dir(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                let trimmed = self.working_dir.trim();
                if trimmed.is_empty() {
                    self.working_dir_error = Some("Directory cannot be empty".into());
                    return;
                }
                if !Path::new(trimmed).is_dir() {
                    self.working_dir_error =
                        Some(format!("Not a directory: {trimmed}"));
                    return;
                }
                self.working_dir_error = None;
                self.task_cursor = self.task.len();
                self.step = OnboardStep::Task;
            }
            KeyCode::Esc => {
                self.working_dir_error = None;
                self.step = OnboardStep::Name;
            }
            _ => {
                self.working_dir_error = None;
                self.edit_text(key, TextField::WorkingDir);
            }
        }
    }

    fn handle_restart(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.restart_selected =
                    (self.restart_selected + 1).min(RestartChoice::ALL.len() - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.restart_selected = self.restart_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                self.step = OnboardStep::TelegramOffer;
            }
            KeyCode::Esc => self.step = OnboardStep::Task,
            _ => {}
        }
    }

    fn handle_telegram_offer(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.telegram_offer_selected =
                    (self.telegram_offer_selected + 1).min(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.telegram_offer_selected =
                    self.telegram_offer_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.telegram_offer_selected == 0 {
                    // Yes
                    self.telegram_token_cursor = self.telegram_token.len();
                    self.step = OnboardStep::TelegramToken;
                } else {
                    // No
                    self.step = OnboardStep::Summary;
                }
            }
            KeyCode::Esc => self.step = OnboardStep::RestartPolicy,
            _ => {}
        }
    }

    fn handle_telegram_progress(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                // Cancel and go back
                self.telegram_status = TelegramStatus::Idle;
                self.telegram_evt_rx = None;
                self.step = OnboardStep::TelegramOffer;
            }
            KeyCode::Enter => {
                // If complete or failed, advance/retry
                match &self.telegram_status {
                    TelegramStatus::Complete { .. } => {
                        self.step = OnboardStep::Summary;
                    }
                    TelegramStatus::Failed(_) => {
                        // Go back to token input to retry
                        self.telegram_status = TelegramStatus::Idle;
                        self.step = OnboardStep::TelegramToken;
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
                self.step = OnboardStep::Done;
                self.running = false;
            }
            KeyCode::Char('d') => {
                // Toggle start daemon
                self.start_daemon = !self.start_daemon;
            }
            KeyCode::Esc => {
                self.step = OnboardStep::TelegramOffer;
            }
            KeyCode::Char('q') | KeyCode::Char('n') => {
                self.step = OnboardStep::Cancelled;
                self.running = false;
            }
            _ => {}
        }
    }

    /// Generic text input handler for fields that don't need special Enter logic.
    fn handle_text(&mut self, key: KeyEvent, field: TextField) {
        match key.code {
            KeyCode::Enter => {
                match field {
                    TextField::CustomCommand => {
                        if self.custom_command.trim().is_empty() {
                            return; // Don't advance with empty command
                        }
                        self.name_cursor = self.name.len();
                        self.step = OnboardStep::Name;
                    }
                    TextField::Task => {
                        self.step = OnboardStep::RestartPolicy;
                    }
                    TextField::TelegramToken => {
                        if self.telegram_token.trim().is_empty() {
                            return;
                        }
                        self.start_telegram_validation();
                        self.step = OnboardStep::TelegramProgress;
                    }
                    _ => {}
                }
            }
            KeyCode::Esc => {
                match field {
                    TextField::CustomCommand => self.step = OnboardStep::Tool,
                    TextField::Task => self.step = OnboardStep::WorkingDir,
                    TextField::TelegramToken => {
                        self.step = OnboardStep::TelegramOffer;
                    }
                    _ => {}
                }
            }
            _ => self.edit_text(key, field),
        }
    }

    /// Apply a key to a text field (character insert, backspace, cursor movement).
    fn edit_text(&mut self, key: KeyEvent, field: TextField) {
        let (text, cursor) = match field {
            TextField::CustomCommand => (&mut self.custom_command, &mut self.custom_cursor),
            TextField::Name => (&mut self.name, &mut self.name_cursor),
            TextField::WorkingDir => (&mut self.working_dir, &mut self.working_dir_cursor),
            TextField::Task => (&mut self.task, &mut self.task_cursor),
            TextField::TelegramToken => {
                (&mut self.telegram_token, &mut self.telegram_token_cursor)
            }
        };

        match key.code {
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                match c {
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
                }
            }
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

    /// Launch the Telegram background worker.
    fn start_telegram_validation(&mut self) {
        let token = self.telegram_token.trim().to_string();
        self.telegram_status = TelegramStatus::ValidatingToken;

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
}

/// Which text field is being edited.
#[derive(Debug, Clone, Copy)]
enum TextField {
    CustomCommand,
    Name,
    WorkingDir,
    Task,
    TelegramToken,
}

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
    let msg = format!(
        "Aegis connected! This chat will receive agent notifications.\nChat ID: {chat_id}"
    );
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

    #[test]
    fn initial_state() {
        let app = OnboardApp::new();
        assert_eq!(app.step, OnboardStep::Welcome);
        assert!(app.running);
        assert!(app.start_daemon);
    }

    #[test]
    fn step_numbers_sequential() {
        assert_eq!(OnboardStep::Welcome.number(), 1);
        assert_eq!(OnboardStep::Tool.number(), 2);
        assert_eq!(OnboardStep::Name.number(), 3);
        assert_eq!(OnboardStep::WorkingDir.number(), 4);
        assert_eq!(OnboardStep::Task.number(), 5);
        assert_eq!(OnboardStep::RestartPolicy.number(), 6);
        assert_eq!(OnboardStep::TelegramOffer.number(), 7);
        assert_eq!(OnboardStep::Summary.number(), 8);
        assert_eq!(OnboardStep::total(), 8);
    }

    #[test]
    fn welcome_enter_advances() {
        let mut app = OnboardApp::new();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);
    }

    #[test]
    fn welcome_esc_cancels() {
        let mut app = OnboardApp::new();
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn tool_jk_navigation() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Tool;
        assert_eq!(app.tool_selected, 0);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.tool_selected, 1);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.tool_selected, 0);

        // Can't go below 0
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.tool_selected, 0);
    }

    #[test]
    fn tool_enter_advances_to_name() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Tool;
        app.tool_selected = 0; // ClaudeCode
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Name);
    }

    #[test]
    fn tool_enter_custom_goes_to_custom_command() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Tool;
        // Navigate to Custom (last item)
        app.tool_selected = ToolChoice::ALL
            .iter()
            .position(|t| *t == ToolChoice::Custom)
            .unwrap();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::CustomCommand);
    }

    #[test]
    fn tool_esc_goes_to_welcome() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Tool;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Welcome);
    }

    #[test]
    fn custom_command_enter_empty_does_not_advance() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::CustomCommand;
        app.custom_command.clear();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::CustomCommand);
    }

    #[test]
    fn custom_command_enter_advances_to_name() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::CustomCommand;
        app.custom_command = "/usr/bin/my-tool".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Name);
    }

    #[test]
    fn custom_command_esc_goes_to_tool() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::CustomCommand;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Tool);
    }

    #[test]
    fn name_typing() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
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
    fn name_cursor_movement() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
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
    fn name_backspace() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.name = "test".into();
        app.name_cursor = 4;

        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.name, "tes");

        app.name_cursor = 0;
        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.name, "tes"); // No change at position 0
    }

    #[test]
    fn name_empty_does_not_advance() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.name = "  ".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Name);
        assert!(app.name_error.is_some());
    }

    #[test]
    fn name_enter_advances_to_working_dir() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.name = "my-agent".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::WorkingDir);
        assert!(app.name_error.is_none());
    }

    #[test]
    fn name_esc_goes_to_tool() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Tool);
    }

    #[test]
    fn name_esc_goes_to_custom_if_custom_tool() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.tool_selected = ToolChoice::ALL
            .iter()
            .position(|t| *t == ToolChoice::Custom)
            .unwrap();
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::CustomCommand);
    }

    #[test]
    fn working_dir_enter_with_valid_dir() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::WorkingDir;
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Task);
    }

    #[test]
    fn working_dir_enter_with_invalid_dir() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::WorkingDir;
        app.working_dir = "/nonexistent/path/unlikely".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::WorkingDir);
        assert!(app.working_dir_error.is_some());
    }

    #[test]
    fn working_dir_esc_goes_to_name() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::WorkingDir;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Name);
    }

    #[test]
    fn task_enter_advances_to_restart() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Task;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::RestartPolicy);
    }

    #[test]
    fn task_esc_goes_to_working_dir() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Task;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::WorkingDir);
    }

    #[test]
    fn restart_navigation() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::RestartPolicy;
        assert_eq!(app.restart_selected, 0);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.restart_selected, 1);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.restart_selected, 2);

        // Can't go past end
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.restart_selected, 2);
    }

    #[test]
    fn restart_enter_advances_to_telegram() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::RestartPolicy;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::TelegramOffer);
    }

    #[test]
    fn restart_esc_goes_to_task() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::RestartPolicy;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Task);
    }

    #[test]
    fn telegram_offer_no_goes_to_summary() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::TelegramOffer;
        app.telegram_offer_selected = 1; // No
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Summary);
    }

    #[test]
    fn telegram_offer_yes_goes_to_token() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::TelegramOffer;
        app.telegram_offer_selected = 0; // Yes
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::TelegramToken);
    }

    #[test]
    fn telegram_offer_esc_goes_to_restart() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::TelegramOffer;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::RestartPolicy);
    }

    #[test]
    fn summary_enter_completes() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Summary;
        app.name = "test".into();
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Done);
        assert!(!app.running);
    }

    #[test]
    fn summary_esc_goes_to_telegram_offer() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Summary;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::TelegramOffer);
    }

    #[test]
    fn summary_q_cancels() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Summary;
        app.handle_key(press(KeyCode::Char('q')));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn summary_d_toggles_daemon() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Summary;
        assert!(app.start_daemon);
        app.handle_key(press(KeyCode::Char('d')));
        assert!(!app.start_daemon);
        app.handle_key(press(KeyCode::Char('d')));
        assert!(app.start_daemon);
    }

    #[test]
    fn result_cancelled() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Cancelled;
        let result = app.result();
        assert!(result.cancelled);
    }

    #[test]
    fn result_builds_agent_slot() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Done;
        app.tool_selected = 0; // ClaudeCode
        app.name = "my-agent".into();
        app.working_dir = "/tmp/project".into();
        app.task = "Build it".into();
        app.restart_selected = 0; // OnFailure

        let result = app.result();
        assert!(!result.cancelled);
        assert_eq!(result.agent_slot.name, "my-agent");
        assert!(matches!(
            result.agent_slot.tool,
            AgentToolConfig::ClaudeCode { .. }
        ));
        assert_eq!(result.agent_slot.task, Some("Build it".into()));
        assert!(result.start_daemon);
    }

    #[test]
    fn full_flow_skip_telegram() {
        let mut app = OnboardApp::new();

        // Welcome -> Tool
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);

        // Tool -> Name (Claude Code is default)
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Name);

        // Name -> WorkingDir
        app.name = "test-agent".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::WorkingDir);

        // WorkingDir -> Task
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Task);

        // Task -> RestartPolicy (skip task)
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::RestartPolicy);

        // RestartPolicy -> TelegramOffer
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::TelegramOffer);

        // TelegramOffer (No) -> Summary
        app.telegram_offer_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Summary);

        // Summary -> Done
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Done);
        assert!(!app.running);
    }

    fn ctrl_c() -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn ctrl_c_cancels_from_welcome() {
        let mut app = OnboardApp::new();
        app.handle_key(ctrl_c());
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn ctrl_c_cancels_from_any_step() {
        for step in [
            OnboardStep::Tool,
            OnboardStep::Name,
            OnboardStep::WorkingDir,
            OnboardStep::Task,
            OnboardStep::RestartPolicy,
            OnboardStep::TelegramOffer,
            OnboardStep::Summary,
        ] {
            let mut app = OnboardApp::new();
            app.step = step;
            app.handle_key(ctrl_c());
            assert_eq!(app.step, OnboardStep::Cancelled, "Ctrl+C should cancel at {:?}", step);
            assert!(!app.running);
        }
    }
}
