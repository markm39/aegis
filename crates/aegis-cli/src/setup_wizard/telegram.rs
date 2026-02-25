//! Telegram setup wizard state machine.
//!
//! Walks through: enter bot token -> validate -> wait for message ->
//! discover chat ID -> confirm. Reuses the pure polling functions from
//! `commands::telegram` and calls the Telegram API directly to avoid
//! stdout prints that would corrupt the TUI.

use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use aegis_channel::telegram::api::TelegramApi;
use aegis_types::config::{ChannelConfig, TelegramConfig};

use super::{SetupEvent, SetupInputField, SetupResult, SetupStep, SetupWizard};

/// Phases of the Telegram setup flow.
enum Phase {
    /// User is typing the bot token.
    EnterToken,
    /// Token is being validated via getMe() on a background thread.
    ValidatingToken,
    /// Token validated; show bot name, ask user to message the bot.
    WaitingForMessage { bot_username: String },
    /// Polling getUpdates on a background thread.
    PollingChatId { bot_username: String },
    /// Success: show summary, confirm to write config.
    Confirm {
        bot_username: String,
        chat_id: i64,
    },
    /// Error state (user can retry or cancel).
    Error {
        message: String,
        /// Phase to return to on retry (Enter).
        retry_phase: Box<Phase>,
    },
    /// Done.
    Done(Option<Box<SetupResult>>),
}

/// Telegram setup wizard implementing `SetupWizard`.
pub struct TelegramSetupWizard {
    phase: Phase,
    token_buffer: String,
    token_cursor: usize,
    event_rx: Option<mpsc::Receiver<SetupEvent>>,
}

impl TelegramSetupWizard {
    pub fn new() -> Self {
        Self {
            phase: Phase::EnterToken,
            token_buffer: String::new(),
            token_cursor: 0,
            event_rx: None,
        }
    }

    /// Start async token validation on a background thread.
    fn start_validation(&mut self) {
        let (tx, rx) = mpsc::channel();
        let token = self.token_buffer.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let rt = match rt {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(SetupEvent::ValidationErr(format!(
                        "Failed to create runtime: {e}"
                    )));
                    return;
                }
            };
            rt.block_on(async {
                let api = TelegramApi::new(&token);
                match api.get_me().await {
                    Ok(user) => {
                        let name = user
                            .username
                            .unwrap_or_else(|| user.first_name.clone());
                        let _ = tx.send(SetupEvent::ValidationOk(name));
                    }
                    Err(e) => {
                        let _ = tx.send(SetupEvent::ValidationErr(format!("{e}")));
                    }
                }
            });
        });

        self.event_rx = Some(rx);
        self.phase = Phase::ValidatingToken;
    }

    /// Start async chat ID polling on a background thread.
    fn start_polling(&mut self, bot_username: String) {
        let (tx, rx) = mpsc::channel();
        let token = self.token_buffer.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let rt = match rt {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(SetupEvent::ValidationErr(format!(
                        "Failed to create runtime: {e}"
                    )));
                    return;
                }
            };
            rt.block_on(async {
                let api = TelegramApi::new(&token);
                match crate::commands::telegram::poll_for_chat_id(&api, 120).await {
                    Ok(chat_id) => {
                        let _ = tx.send(SetupEvent::ExternalIdDiscovered(chat_id));
                    }
                    Err(e) => {
                        let _ = tx.send(SetupEvent::ValidationErr(format!("{e}")));
                    }
                }
            });
        });

        self.event_rx = Some(rx);
        self.phase = Phase::PollingChatId { bot_username };
    }

    /// Handle text input keys for the token buffer.
    fn handle_text_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => {
                self.token_buffer.insert(self.token_cursor, c);
                self.token_cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if self.token_cursor > 0 {
                    // Find the previous char boundary.
                    let mut new_cursor = self.token_cursor - 1;
                    while new_cursor > 0 && !self.token_buffer.is_char_boundary(new_cursor) {
                        new_cursor -= 1;
                    }
                    self.token_buffer
                        .drain(new_cursor..self.token_cursor);
                    self.token_cursor = new_cursor;
                }
            }
            KeyCode::Delete => {
                if self.token_cursor < self.token_buffer.len() {
                    let mut end = self.token_cursor + 1;
                    while end < self.token_buffer.len()
                        && !self.token_buffer.is_char_boundary(end)
                    {
                        end += 1;
                    }
                    self.token_buffer.drain(self.token_cursor..end);
                }
            }
            KeyCode::Left => {
                if self.token_cursor > 0 {
                    self.token_cursor -= 1;
                    while self.token_cursor > 0
                        && !self.token_buffer.is_char_boundary(self.token_cursor)
                    {
                        self.token_cursor -= 1;
                    }
                }
            }
            KeyCode::Right => {
                if self.token_cursor < self.token_buffer.len() {
                    self.token_cursor += 1;
                    while self.token_cursor < self.token_buffer.len()
                        && !self.token_buffer.is_char_boundary(self.token_cursor)
                    {
                        self.token_cursor += 1;
                    }
                }
            }
            KeyCode::Home => {
                self.token_cursor = 0;
            }
            KeyCode::End => {
                self.token_cursor = self.token_buffer.len();
            }
            _ => {}
        }
    }

    fn build_channel_config(&self, chat_id: i64) -> ChannelConfig {
        ChannelConfig::Telegram(TelegramConfig {
            bot_token: self.token_buffer.clone(),
            chat_id,
            poll_timeout_secs: 30,
            allow_group_commands: false,
            active_hours: None,
            webhook_mode: false,
            webhook_port: None,
            webhook_url: None,
            webhook_secret: None,
            inline_queries_enabled: false,
        })
    }
}

impl SetupWizard for TelegramSetupWizard {
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Ctrl+C always cancels.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.phase = Phase::Done(Some(Box::new(SetupResult::Cancelled)));
            return true;
        }

        match &self.phase {
            Phase::EnterToken => match key.code {
                KeyCode::Enter => {
                    let token = self.token_buffer.trim().to_string();
                    if token.is_empty() {
                        return true;
                    }
                    self.token_buffer = token;
                    self.token_cursor = self.token_buffer.len();
                    self.start_validation();
                    true
                }
                KeyCode::Esc => {
                    self.phase = Phase::Done(Some(Box::new(SetupResult::Cancelled)));
                    false // let host know Esc was pressed
                }
                _ => {
                    self.handle_text_input(key);
                    true
                }
            },
            Phase::ValidatingToken => match key.code {
                KeyCode::Esc => {
                    self.event_rx = None;
                    self.phase = Phase::EnterToken;
                    true
                }
                _ => true,
            },
            Phase::WaitingForMessage { .. } => match key.code {
                KeyCode::Enter => {
                    if let Phase::WaitingForMessage { bot_username } =
                        std::mem::replace(&mut self.phase, Phase::EnterToken)
                    {
                        self.start_polling(bot_username);
                    }
                    true
                }
                KeyCode::Esc => {
                    self.phase = Phase::EnterToken;
                    true
                }
                _ => true,
            },
            Phase::PollingChatId { .. } => match key.code {
                KeyCode::Esc => {
                    self.event_rx = None;
                    self.phase = Phase::EnterToken;
                    true
                }
                _ => true,
            },
            Phase::Confirm { .. } => match key.code {
                KeyCode::Enter => {
                    if let Phase::Confirm {
                        chat_id,
                        ..
                    } = &self.phase
                    {
                        let config = self.build_channel_config(*chat_id);
                        self.phase = Phase::Done(Some(Box::new(SetupResult::Channel(Box::new(config)))));
                    }
                    true
                }
                KeyCode::Esc => {
                    self.phase = Phase::Done(Some(Box::new(SetupResult::Cancelled)));
                    false
                }
                _ => true,
            },
            Phase::Error { .. } => match key.code {
                KeyCode::Enter => {
                    // Retry: go back to the retry phase.
                    if let Phase::Error { retry_phase, .. } =
                        std::mem::replace(&mut self.phase, Phase::EnterToken)
                    {
                        self.phase = *retry_phase;
                    }
                    true
                }
                KeyCode::Esc => {
                    self.phase = Phase::Done(Some(Box::new(SetupResult::Cancelled)));
                    false
                }
                _ => true,
            },
            Phase::Done(_) => false,
        }
    }

    fn tick(&mut self) {
        let rx = match self.event_rx.as_ref() {
            Some(rx) => rx,
            None => return,
        };

        // Non-blocking drain.
        match rx.try_recv() {
            Ok(SetupEvent::ValidationOk(bot_username)) => {
                self.event_rx = None;
                self.phase = Phase::WaitingForMessage { bot_username };
            }
            Ok(SetupEvent::ValidationErr(err)) => {
                self.event_rx = None;
                self.phase = Phase::Error {
                    message: err,
                    retry_phase: Box::new(Phase::EnterToken),
                };
            }
            Ok(SetupEvent::ExternalIdDiscovered(chat_id)) => {
                self.event_rx = None;
                let bot_username = match &self.phase {
                    Phase::PollingChatId { bot_username } => bot_username.clone(),
                    _ => "your_bot".to_string(),
                };
                self.phase = Phase::Confirm {
                    bot_username,
                    chat_id,
                };
            }
            Err(mpsc::TryRecvError::Empty) => {
                // Nothing yet, keep waiting.
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                // Thread finished without sending. Treat as error.
                self.event_rx = None;
                self.phase = Phase::Error {
                    message: "Background operation terminated unexpectedly".to_string(),
                    retry_phase: Box::new(Phase::EnterToken),
                };
            }
        }
    }

    fn current_step(&self) -> SetupStep {
        match &self.phase {
            Phase::EnterToken => SetupStep {
                title: "Telegram Setup".to_string(),
                instructions: vec![
                    "1. Open Telegram and search for @BotFather".to_string(),
                    "2. Send /newbot and follow the prompts".to_string(),
                    "3. Paste the bot token below".to_string(),
                ],
                inputs: vec![SetupInputField {
                    label: "Bot Token:".to_string(),
                    value: self.token_buffer.clone(),
                    cursor: self.token_cursor,
                    masked: true,
                }],
                active_input: 0,
                status: None,
                error: None,
                is_waiting: false,
                help: "Enter to validate | Esc to cancel".to_string(),
            },
            Phase::ValidatingToken => SetupStep {
                title: "Telegram Setup".to_string(),
                instructions: vec![],
                inputs: vec![],
                active_input: 0,
                status: Some("Validating bot token...".to_string()),
                error: None,
                is_waiting: true,
                help: "Esc to cancel".to_string(),
            },
            Phase::WaitingForMessage { bot_username } => SetupStep {
                title: "Telegram Setup".to_string(),
                instructions: vec![
                    format!("Connected to @{bot_username}"),
                    String::new(),
                    format!("Send any message to @{bot_username} on Telegram"),
                    "so we can discover your chat ID.".to_string(),
                ],
                inputs: vec![],
                active_input: 0,
                status: None,
                error: None,
                is_waiting: false,
                help: "Enter to start listening | Esc to go back".to_string(),
            },
            Phase::PollingChatId { bot_username } => SetupStep {
                title: "Telegram Setup".to_string(),
                instructions: vec![format!(
                    "Waiting for a message to @{bot_username}..."
                )],
                inputs: vec![],
                active_input: 0,
                status: Some("Listening for messages (120s timeout)...".to_string()),
                error: None,
                is_waiting: true,
                help: "Esc to cancel".to_string(),
            },
            Phase::Confirm {
                bot_username,
                chat_id,
            } => SetupStep {
                title: "Telegram Setup -- Confirm".to_string(),
                instructions: vec![
                    format!("Bot:     @{bot_username}"),
                    format!("Chat ID: {chat_id}"),
                    String::new(),
                    "Press Enter to save this configuration.".to_string(),
                ],
                inputs: vec![],
                active_input: 0,
                status: Some("Ready to save".to_string()),
                error: None,
                is_waiting: false,
                help: "Enter to confirm | Esc to cancel".to_string(),
            },
            Phase::Error { message, .. } => SetupStep {
                title: "Telegram Setup -- Error".to_string(),
                instructions: vec![],
                inputs: vec![],
                active_input: 0,
                status: None,
                error: Some(message.clone()),
                is_waiting: false,
                help: "Enter to retry | Esc to cancel".to_string(),
            },
            Phase::Done(_) => SetupStep {
                title: "Telegram Setup".to_string(),
                instructions: vec![],
                inputs: vec![],
                active_input: 0,
                status: Some("Done".to_string()),
                error: None,
                is_waiting: false,
                help: String::new(),
            },
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done(_))
    }

    fn take_result(&mut self) -> SetupResult {
        if let Phase::Done(ref mut result) = self.phase {
            result
                .take()
                .map(|b| *b)
                .unwrap_or(SetupResult::Cancelled)
        } else {
            SetupResult::Cancelled
        }
    }
}
