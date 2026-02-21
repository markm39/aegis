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

    #[error("operation not supported: {0}")]
    NotSupported(String),

    #[error("{0}")]
    Other(String),
}

/// Describes the interaction capabilities supported by a channel backend.
///
/// Each backend reports which features it supports. Callers can check these
/// flags before invoking optional methods to avoid `NotSupported` errors.
#[derive(Debug, Clone, Default)]
pub struct ChannelCapabilities {
    /// Whether the channel supports typing indicators.
    pub typing_indicators: bool,
    /// Whether previously sent messages can be edited.
    pub message_editing: bool,
    /// Whether previously sent messages can be deleted.
    pub message_deletion: bool,
    /// Whether emoji reactions can be added to messages.
    pub reactions: bool,
    /// Whether the channel supports threaded/topic replies.
    pub threads: bool,
    /// Whether the channel reports user presence (online/offline).
    pub presence: bool,
    /// Whether the channel supports rich media (photos, files, stickers).
    pub rich_media: bool,
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
///
/// All interaction methods (`send_typing`, `edit_message`, etc.) have default
/// implementations so existing backends compile without changes. Backends
/// that support a feature override the relevant method and report it via
/// [`Channel::capabilities`].
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

    /// Send a typing indicator to show the agent is processing.
    ///
    /// Typing indicators typically expire after a few seconds, so this may
    /// need to be called repeatedly for long-running operations.
    async fn send_typing(&self) -> Result<(), ChannelError> {
        Ok(()) // no-op default -- silently succeeds for backends that lack typing
    }

    /// Send a message and return its platform-specific ID.
    ///
    /// Like [`Channel::send`], but returns the message ID assigned by the
    /// platform so callers can later edit, delete, or react to it.
    /// Returns `None` when the backend does not track message IDs.
    async fn send_with_id(
        &self,
        message: OutboundMessage,
    ) -> Result<Option<String>, ChannelError> {
        self.send(message).await?;
        Ok(None)
    }

    /// Edit a previously sent message by its platform-specific ID.
    async fn edit_message(&self, message_id: &str, new_text: &str) -> Result<(), ChannelError> {
        let _ = (message_id, new_text);
        Err(ChannelError::NotSupported("edit_message".into()))
    }

    /// Delete a previously sent message by its platform-specific ID.
    async fn delete_message(&self, message_id: &str) -> Result<(), ChannelError> {
        let _ = message_id;
        Err(ChannelError::NotSupported("delete_message".into()))
    }

    /// Send an emoji reaction to a message.
    async fn react(&self, message_id: &str, emoji: &str) -> Result<(), ChannelError> {
        let _ = (message_id, emoji);
        Err(ChannelError::NotSupported("react".into()))
    }

    /// Reply in a specific thread or topic.
    async fn send_to_thread(
        &self,
        thread_id: &str,
        message: OutboundMessage,
    ) -> Result<(), ChannelError> {
        let _ = (thread_id, message);
        Err(ChannelError::NotSupported("send_to_thread".into()))
    }

    /// Report the interaction capabilities supported by this channel.
    fn capabilities(&self) -> ChannelCapabilities {
        ChannelCapabilities::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ChannelCapabilities tests --

    #[test]
    fn capabilities_default_all_false() {
        let caps = ChannelCapabilities::default();
        assert!(!caps.typing_indicators);
        assert!(!caps.message_editing);
        assert!(!caps.message_deletion);
        assert!(!caps.reactions);
        assert!(!caps.threads);
        assert!(!caps.presence);
        assert!(!caps.rich_media);
    }

    #[test]
    fn capabilities_partial_override() {
        let caps = ChannelCapabilities {
            typing_indicators: true,
            message_editing: true,
            ..Default::default()
        };
        assert!(caps.typing_indicators);
        assert!(caps.message_editing);
        assert!(!caps.message_deletion);
        assert!(!caps.reactions);
        assert!(!caps.threads);
        assert!(!caps.presence);
        assert!(!caps.rich_media);
    }

    // -- NotSupported error variant tests --

    #[test]
    fn not_supported_error_display() {
        let err = ChannelError::NotSupported("edit_message".into());
        assert_eq!(err.to_string(), "operation not supported: edit_message");
    }

    #[test]
    fn not_supported_is_distinct_from_other() {
        let ns = ChannelError::NotSupported("test".into());
        let other = ChannelError::Other("test".into());
        // They should produce different Display output
        assert_ne!(ns.to_string(), other.to_string());
    }

    // -- Default trait method behavior tests --

    /// A minimal Channel implementation with only required methods.
    struct MinimalChannel;

    #[async_trait]
    impl Channel for MinimalChannel {
        async fn send(&self, _message: OutboundMessage) -> Result<(), ChannelError> {
            Ok(())
        }
        async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
            Ok(None)
        }
        fn name(&self) -> &str {
            "minimal"
        }
    }

    #[tokio::test]
    async fn default_send_typing_succeeds() {
        let ch = MinimalChannel;
        // Default send_typing is a no-op that succeeds
        assert!(ch.send_typing().await.is_ok());
    }

    #[tokio::test]
    async fn default_edit_message_returns_not_supported() {
        let ch = MinimalChannel;
        let err = ch.edit_message("123", "new text").await.unwrap_err();
        match err {
            ChannelError::NotSupported(op) => assert_eq!(op, "edit_message"),
            other => panic!("expected NotSupported, got {other}"),
        }
    }

    #[tokio::test]
    async fn default_delete_message_returns_not_supported() {
        let ch = MinimalChannel;
        let err = ch.delete_message("123").await.unwrap_err();
        match err {
            ChannelError::NotSupported(op) => assert_eq!(op, "delete_message"),
            other => panic!("expected NotSupported, got {other}"),
        }
    }

    #[tokio::test]
    async fn default_react_returns_not_supported() {
        let ch = MinimalChannel;
        let err = ch.react("123", "thumbs_up").await.unwrap_err();
        match err {
            ChannelError::NotSupported(op) => assert_eq!(op, "react"),
            other => panic!("expected NotSupported, got {other}"),
        }
    }

    #[tokio::test]
    async fn default_send_to_thread_returns_not_supported() {
        let ch = MinimalChannel;
        let msg = OutboundMessage::text("hello");
        let err = ch.send_to_thread("thread-1", msg).await.unwrap_err();
        match err {
            ChannelError::NotSupported(op) => assert_eq!(op, "send_to_thread"),
            other => panic!("expected NotSupported, got {other}"),
        }
    }

    #[tokio::test]
    async fn default_send_with_id_returns_none() {
        let ch = MinimalChannel;
        let msg = OutboundMessage::text("hello");
        let result = ch.send_with_id(msg).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn default_capabilities_all_false() {
        let ch = MinimalChannel;
        let caps = ch.capabilities();
        assert!(!caps.typing_indicators);
        assert!(!caps.message_editing);
        assert!(!caps.reactions);
        assert!(!caps.threads);
    }
}
