//! Shared setup wizard infrastructure.
//!
//! Provides a trait-based abstraction for multi-step feature setup flows
//! (Telegram, Slack, skill auth, etc.) that can be hosted in both the
//! onboarding wizard and the chat TUI.

pub mod skill_env;
pub mod telegram;
pub mod ui;

use crossterm::event::KeyEvent;

use aegis_types::config::ChannelConfig;

/// Events from background async operations (token validation, polling, etc.).
pub(crate) enum SetupEvent {
    /// Async validation succeeded.
    ValidationOk(String),
    /// Async validation failed.
    ValidationErr(String),
    /// An external ID was discovered (e.g., Telegram chat_id).
    ExternalIdDiscovered(i64),
}

/// What the wizard produced upon completion.
pub enum SetupResult {
    /// Channel configuration ready to write to daemon.toml.
    Channel(Box<ChannelConfig>),
    /// User cancelled the wizard.
    Cancelled,
}

/// An input field displayed by the wizard.
pub struct SetupInputField {
    /// Label shown to the left of the input.
    pub label: String,
    /// Current text in the buffer.
    pub value: String,
    /// Byte offset of the cursor within `value`.
    pub cursor: usize,
    /// Whether to mask the input (show bullets instead of text).
    pub masked: bool,
}

/// Current visual state of the wizard for rendering.
///
/// This is the rendering contract between wizard logic and UI code.
/// The wizard produces a `SetupStep`; the host renders it.
pub struct SetupStep {
    /// Title displayed at the top (e.g., "Telegram Setup").
    pub title: String,
    /// Instruction lines shown above the input.
    pub instructions: Vec<String>,
    /// Active text input field, if any.
    pub input: Option<SetupInputField>,
    /// Status message (success, info).
    pub status: Option<String>,
    /// Error message.
    pub error: Option<String>,
    /// Whether the wizard is waiting on a background operation (show spinner).
    pub is_waiting: bool,
    /// Help text for the bottom of the overlay.
    pub help: String,
}

/// Trait for a feature setup wizard.
///
/// Implementors manage their own internal state machine. The host
/// (onboarding wizard or chat TUI) calls `handle_key()` for input,
/// `tick()` to drain async events, and `current_step()` for rendering.
pub trait SetupWizard {
    /// Handle a key event. Returns `true` if the wizard consumed the key.
    ///
    /// If the wizard returns `false` for Esc, the host should close it.
    fn handle_key(&mut self, key: KeyEvent) -> bool;

    /// Drain background events. Called every tick (~50ms).
    fn tick(&mut self);

    /// Current visual state for rendering.
    fn current_step(&self) -> SetupStep;

    /// Whether the wizard is finished (completed or cancelled).
    fn is_done(&self) -> bool;

    /// Consume the result. Only valid after `is_done()` returns true.
    fn take_result(&mut self) -> SetupResult;
}

/// Create a setup wizard for the given channel name.
pub fn channel_wizard(channel_name: &str) -> Option<Box<dyn SetupWizard>> {
    match channel_name {
        "telegram" => Some(Box::new(telegram::TelegramSetupWizard::new())),
        _ => None,
    }
}
