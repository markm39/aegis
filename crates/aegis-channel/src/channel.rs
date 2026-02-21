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

/// Media payload that can be attached to an outbound message.
///
/// Carries pre-loaded binary data for images, files, or sticker references.
/// Data must be validated (size, type, path safety) before constructing.
#[derive(Debug, Clone)]
pub enum MediaPayload {
    /// An image (png, jpg, gif, webp, bmp).
    Image {
        /// Raw image bytes (already validated for size).
        data: Vec<u8>,
        /// Filename for the upload (e.g., "screenshot.png").
        filename: String,
    },
    /// A document file (pdf, txt, csv, json, zip, tar.gz).
    File {
        /// Raw file bytes (already validated for size).
        data: Vec<u8>,
        /// Filename for the upload.
        filename: String,
        /// Optional caption text.
        caption: Option<String>,
    },
    /// A Telegram sticker reference.
    Sticker {
        /// Sticker file_id (validated: alphanumeric + dash/underscore, max 256 chars).
        file_id: String,
    },
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
    /// Optional media attachment.
    pub media: Option<MediaPayload>,
}

impl OutboundMessage {
    /// Create a simple text message.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            buttons: Vec::new(),
            silent: false,
            media: None,
        }
    }

    /// Create a message with inline keyboard buttons.
    pub fn with_buttons(text: impl Into<String>, buttons: Vec<(String, String)>) -> Self {
        Self {
            text: text.into(),
            buttons,
            silent: false,
            media: None,
        }
    }

    /// Create a message with a media attachment.
    pub fn with_media(text: impl Into<String>, media: MediaPayload) -> Self {
        Self {
            text: text.into(),
            buttons: Vec::new(),
            silent: false,
            media: Some(media),
        }
    }
}

/// An outbound photo message to send through the channel.
#[derive(Debug, Clone)]
pub struct OutboundPhoto {
    /// Optional caption (MarkdownV2 for Telegram).
    pub caption: Option<String>,
    /// Filename for the uploaded photo.
    pub filename: String,
    /// Raw photo bytes.
    pub bytes: Vec<u8>,
    /// Whether to send silently (no notification sound).
    pub silent: bool,
}

impl OutboundPhoto {
    pub fn new(filename: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            caption: None,
            filename: filename.into(),
            bytes,
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

    /// Send a photo message (optional capability).
    async fn send_photo(&self, _photo: OutboundPhoto) -> Result<(), ChannelError> {
        Err(ChannelError::Other("photo messages not supported".into()))
    }
}
