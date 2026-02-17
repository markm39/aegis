//! Core channel trait and types for bidirectional messaging.
//!
//! A [`Channel`] implementation handles one messaging backend (Telegram,
//! Slack, etc.). Outbound messages are sent via [`Channel::send`], and
//! inbound user actions are received via [`Channel::recv`].

use aegis_control::command::Command;
use async_trait::async_trait;
use thiserror::Error;

/// Errors from channel operations.
#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API returned error: {0}")]
    Api(String),

    #[error("channel shut down")]
    Shutdown,

    #[error("{0}")]
    Other(String),
}

/// An outbound message to send through the channel.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// The formatted message text (MarkdownV2 for Telegram).
    pub text: String,
    /// Optional inline keyboard buttons (label, callback_data pairs).
    pub buttons: Vec<(String, String)>,
    /// Whether to send silently (no notification sound).
    pub silent: bool,
}

impl OutboundMessage {
    /// Create a simple text message.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            buttons: Vec::new(),
            silent: false,
        }
    }

    /// Create a message with inline keyboard buttons.
    pub fn with_buttons(text: impl Into<String>, buttons: Vec<(String, String)>) -> Self {
        Self {
            text: text.into(),
            buttons,
            silent: false,
        }
    }
}

/// An inbound action received from the user through the channel.
#[derive(Debug)]
pub enum InboundAction {
    /// A recognized command to forward to the supervisor.
    Command(Command),
    /// Unrecognized input (the channel should send help text).
    Unknown(String),
}

/// Trait for a bidirectional messaging channel.
///
/// Each backend (Telegram, Slack, etc.) implements this trait. The
/// [`runner`](crate::runner) drives the send/recv loop on a dedicated thread.
#[async_trait]
pub trait Channel: Send + 'static {
    /// Send an outbound message through this channel.
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError>;

    /// Receive the next inbound action, or `None` if no action is pending.
    ///
    /// Implementations should block (with a timeout) on their polling mechanism
    /// and return `None` on timeout or when no new messages arrived.
    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError>;

    /// Human-readable name for this channel backend.
    fn name(&self) -> &str;
}
