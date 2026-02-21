//! Unified channel abstraction layer with capability-based routing.
//!
//! Provides a [`ChannelRouter`] that manages multiple [`Channel`] backends,
//! routes messages based on channel capabilities, and degrades gracefully
//! when a target channel lacks features (e.g., rendering inline buttons
//! as numbered text when the channel does not support them).
//!
//! # Security
//!
//! - All channel names are validated: alphanumeric + dash/underscore, max 64 chars.
//! - Broadcast is rate-limited (max 10 channels by default, configurable).
//! - All routing decisions are logged via `tracing` for audit trail.
//! - Fail closed: sending to an unknown channel returns an error, never silently skips.

use std::collections::HashMap;

use async_trait::async_trait;
use tracing::{info, warn};

use crate::channel::{Channel, ChannelError, OutboundMessage, MediaPayload};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length for a channel name.
const MAX_CHANNEL_NAME_LEN: usize = 64;

/// Maximum length for a channel type identifier in the factory registry.
const MAX_CHANNEL_TYPE_LEN: usize = 32;

/// Default maximum number of channels a single broadcast may target.
const DEFAULT_BROADCAST_LIMIT: usize = 10;

// ---------------------------------------------------------------------------
// ChannelCapabilities (u32 bitflags -- no external crate)
// ---------------------------------------------------------------------------

/// Capability flags describing what a channel backend supports.
///
/// Implemented as a `u32` newtype with manual bitwise operations.
/// Do not add a `bitflags` crate dependency -- this is intentionally minimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelCapabilities(u32);

impl ChannelCapabilities {
    /// Support for threaded replies.
    pub const THREADS: Self = Self(1);
    /// Support for emoji reactions on messages.
    pub const REACTIONS: Self = Self(2);
    /// Support for file attachments.
    pub const FILE_ATTACHMENTS: Self = Self(4);
    /// Support for inline keyboard buttons.
    pub const INLINE_BUTTONS: Self = Self(8);
    /// Support for group management (add/remove members).
    pub const GROUP_MANAGEMENT: Self = Self(16);
    /// Support for rich text formatting (Markdown, HTML).
    pub const RICH_FORMATTING: Self = Self(32);
    /// Support for sending photo messages.
    pub const PHOTO_MESSAGES: Self = Self(64);
    /// Support for interactive message updates.
    pub const INTERACTIVE_MESSAGES: Self = Self(128);
    /// Support for outgoing webhooks.
    pub const WEBHOOKS: Self = Self(256);

    /// The empty capability set.
    pub const NONE: Self = Self(0);

    /// Create a capabilities value from a raw `u32`.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Return the raw `u32` representation.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check whether this set contains *all* bits of `flag`.
    pub const fn has(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Check whether this set contains *all* bits of `flags`.
    pub const fn supports_all(self, flags: Self) -> bool {
        (self.0 & flags.0) == flags.0
    }

    /// Check whether this set contains *any* bit of `flags`.
    pub const fn supports_any(self, flags: Self) -> bool {
        (self.0 & flags.0) != 0
    }

    /// Combine two capability sets (bitwise OR).
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for ChannelCapabilities {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for ChannelCapabilities {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

// ---------------------------------------------------------------------------
// Unified message types
// ---------------------------------------------------------------------------

/// Visual style for an inline button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonStyle {
    Primary,
    Secondary,
    Danger,
}

/// A channel-agnostic inline button.
#[derive(Debug, Clone)]
pub struct UnifiedButton {
    /// Visible label on the button.
    pub label: String,
    /// Identifier sent back when the button is pressed.
    pub action_id: String,
    /// Visual style hint.
    pub style: ButtonStyle,
}

/// A channel-agnostic file attachment.
#[derive(Debug, Clone)]
pub struct UnifiedAttachment {
    /// Filename (for display and upload).
    pub filename: String,
    /// Raw file bytes.
    pub data: Vec<u8>,
    /// MIME type (e.g., `application/pdf`).
    pub mime_type: String,
}

/// Text formatting mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageFormat {
    /// No formatting.
    Plain,
    /// Markdown formatting.
    Markdown,
    /// HTML formatting.
    Html,
}

/// A channel-agnostic outbound message.
///
/// Carries the full richness of the message intent. The router's
/// [`convert_to_outbound`] function degrades it to an [`OutboundMessage`]
/// appropriate for the target channel's capabilities.
#[derive(Debug, Clone)]
pub struct UnifiedMessage {
    /// Message body text.
    pub text: String,
    /// Inline buttons (empty if none).
    pub buttons: Vec<UnifiedButton>,
    /// Thread/reply context (if the channel supports threads).
    pub thread_id: Option<String>,
    /// File attachments.
    pub attachments: Vec<UnifiedAttachment>,
    /// Text formatting mode.
    pub formatting: MessageFormat,
}

impl UnifiedMessage {
    /// Create a plain text message with no extras.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            buttons: Vec::new(),
            thread_id: None,
            attachments: Vec::new(),
            formatting: MessageFormat::Plain,
        }
    }
}

// ---------------------------------------------------------------------------
// Graceful degradation
// ---------------------------------------------------------------------------

/// Strip basic Markdown formatting characters from text.
fn strip_markdown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        // Skip backslash-escaped characters (keep the character, drop the backslash)
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                out.push(next);
                chars.next();
                continue;
            }
        }
        // Drop common Markdown metacharacters
        if matches!(c, '*' | '_' | '`' | '~' | '#') {
            continue;
        }
        out.push(c);
    }
    out
}

/// Strip HTML tags from text, keeping inner content.
fn strip_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;
    for c in text.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Convert a [`UnifiedMessage`] to an [`OutboundMessage`], gracefully
/// degrading features the target channel does not support.
///
/// Degradation rules:
/// - **INLINE_BUTTONS missing**: buttons rendered as a numbered text list.
/// - **RICH_FORMATTING missing**: Markdown/HTML stripped to plain text.
/// - **FILE_ATTACHMENTS missing**: filename appended to text, data dropped.
/// - **PHOTO_MESSAGES missing**: `[photo: filename]` appended to text.
pub fn convert_to_outbound(msg: &UnifiedMessage, caps: ChannelCapabilities) -> OutboundMessage {
    // -- Text formatting degradation --
    let mut text = match msg.formatting {
        MessageFormat::Plain => msg.text.clone(),
        MessageFormat::Markdown => {
            if caps.has(ChannelCapabilities::RICH_FORMATTING) {
                msg.text.clone()
            } else {
                strip_markdown(&msg.text)
            }
        }
        MessageFormat::Html => {
            if caps.has(ChannelCapabilities::RICH_FORMATTING) {
                msg.text.clone()
            } else {
                strip_html(&msg.text)
            }
        }
    };

    // -- Button degradation --
    let buttons = if caps.has(ChannelCapabilities::INLINE_BUTTONS) {
        msg.buttons
            .iter()
            .map(|b| (b.label.clone(), b.action_id.clone()))
            .collect()
    } else if !msg.buttons.is_empty() {
        // Render buttons as a numbered list in the text body
        text.push_str("\n\nActions:");
        for (i, btn) in msg.buttons.iter().enumerate() {
            text.push_str(&format!("\n  {}. {}", i + 1, btn.label));
        }
        Vec::new()
    } else {
        Vec::new()
    };

    // -- Attachment degradation --
    let mut media = None;
    for att in &msg.attachments {
        let is_image = att.mime_type.starts_with("image/");
        if is_image {
            if caps.has(ChannelCapabilities::PHOTO_MESSAGES) {
                media = Some(MediaPayload::Image {
                    data: att.data.clone(),
                    filename: att.filename.clone(),
                });
            } else {
                text.push_str(&format!("\n[photo: {}]", att.filename));
            }
        } else if caps.has(ChannelCapabilities::FILE_ATTACHMENTS) {
            media = Some(MediaPayload::File {
                data: att.data.clone(),
                filename: att.filename.clone(),
                caption: None,
            });
        } else {
            text.push_str(&format!("\n[attachment: {}]", att.filename));
        }
    }

    OutboundMessage {
        text,
        buttons,
        silent: false,
        media,
    }
}

// ---------------------------------------------------------------------------
// Channel info
// ---------------------------------------------------------------------------

/// Metadata about a registered channel.
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    /// Human-readable channel name.
    pub name: String,
    /// Capabilities this channel supports.
    pub capabilities: ChannelCapabilities,
    /// Whether the channel is currently connected.
    pub is_connected: bool,
    /// Number of messages sent through this channel.
    pub message_count: u64,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a channel name: alphanumeric + dash/underscore, max 64 chars.
/// Rejects empty strings, null bytes, control characters, path traversal,
/// and any character outside `[a-zA-Z0-9_-]`.
fn validate_channel_name(name: &str) -> Result<(), ChannelError> {
    if name.is_empty() {
        return Err(ChannelError::Other(
            "channel name cannot be empty".into(),
        ));
    }
    if name.len() > MAX_CHANNEL_NAME_LEN {
        return Err(ChannelError::Other(format!(
            "channel name exceeds maximum length of {MAX_CHANNEL_NAME_LEN} characters"
        )));
    }
    if name.bytes().any(|b| b == 0 || b < 0x20) {
        return Err(ChannelError::Other(
            "channel name contains null bytes or control characters".into(),
        ));
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(ChannelError::Other(
            "channel name contains path traversal sequences".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ChannelError::Other(
            "channel name may only contain ASCII letters, digits, hyphens, and underscores".into(),
        ));
    }
    Ok(())
}

/// Validate a channel type identifier for the factory registry.
fn validate_channel_type(name: &str) -> Result<(), ChannelError> {
    if name.is_empty() {
        return Err(ChannelError::Other(
            "channel type cannot be empty".into(),
        ));
    }
    if name.len() > MAX_CHANNEL_TYPE_LEN {
        return Err(ChannelError::Other(format!(
            "channel type exceeds maximum length of {MAX_CHANNEL_TYPE_LEN} characters"
        )));
    }
    if name.bytes().any(|b| b == 0 || b < 0x20) {
        return Err(ChannelError::Other(
            "channel type contains null bytes or control characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ChannelError::Other(
            "channel type may only contain ASCII letters, digits, hyphens, and underscores".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ChannelRouter
// ---------------------------------------------------------------------------

/// Routes messages to registered [`Channel`] backends by name or capability.
///
/// Maintains a registry of channels with their capability metadata and
/// enforces security constraints (name validation, broadcast rate limiting,
/// audit logging) on every routing decision.
pub struct ChannelRouter {
    channels: HashMap<String, Box<dyn Channel + Send>>,
    channel_info: HashMap<String, ChannelInfo>,
    /// Maximum number of channels a single broadcast may target.
    broadcast_limit: usize,
}

impl ChannelRouter {
    /// Create an empty router with the default broadcast limit.
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            channel_info: HashMap::new(),
            broadcast_limit: DEFAULT_BROADCAST_LIMIT,
        }
    }

    /// Create a router with a custom broadcast limit.
    pub fn with_broadcast_limit(limit: usize) -> Self {
        Self {
            channels: HashMap::new(),
            channel_info: HashMap::new(),
            broadcast_limit: limit,
        }
    }

    /// Register a channel backend under the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is invalid (see [`validate_channel_name`]).
    pub fn register_channel(
        &mut self,
        name: impl Into<String>,
        channel: Box<dyn Channel + Send>,
        capabilities: ChannelCapabilities,
    ) -> Result<(), ChannelError> {
        let name = name.into();
        validate_channel_name(&name)?;

        info!(channel = %name, capabilities = capabilities.bits(), "registering channel");

        self.channel_info.insert(
            name.clone(),
            ChannelInfo {
                name: name.clone(),
                capabilities,
                is_connected: true,
                message_count: 0,
            },
        );
        self.channels.insert(name, channel);
        Ok(())
    }

    /// Remove a channel by name.
    ///
    /// Returns `true` if the channel existed and was removed.
    pub fn unregister_channel(&mut self, name: &str) -> bool {
        let removed = self.channels.remove(name).is_some();
        self.channel_info.remove(name);
        if removed {
            info!(channel = %name, "unregistered channel");
        }
        removed
    }

    /// Send a message to a specific channel by name.
    ///
    /// Fails closed: if the channel is not registered, returns an error.
    pub async fn send_to(&mut self, name: &str, message: OutboundMessage) -> Result<(), ChannelError> {
        let channel = self.channels.get(name).ok_or_else(|| {
            warn!(channel = %name, "send_to: channel not found");
            ChannelError::Other(format!("channel {name:?} not found"))
        })?;

        info!(channel = %name, "routing message to channel");
        channel.send(message).await?;

        if let Some(info) = self.channel_info.get_mut(name) {
            info.message_count += 1;
        }
        Ok(())
    }

    /// Send a message to the first connected channel that has the given capability.
    ///
    /// Fails closed: if no channel has the capability, returns an error.
    pub async fn send_to_capable(
        &mut self,
        capability: ChannelCapabilities,
        message: OutboundMessage,
    ) -> Result<(), ChannelError> {
        // Find the first connected channel with the required capability.
        let target_name = self
            .channel_info
            .values()
            .find(|info| info.is_connected && info.capabilities.has(capability))
            .map(|info| info.name.clone());

        let target_name = target_name.ok_or_else(|| {
            warn!(
                capability = capability.bits(),
                "send_to_capable: no channel with required capability"
            );
            ChannelError::Other(format!(
                "no connected channel with capability 0x{:x}",
                capability.bits()
            ))
        })?;

        info!(
            channel = %target_name,
            capability = capability.bits(),
            "routing message to capable channel"
        );

        let channel = self.channels.get(&target_name).ok_or_else(|| {
            ChannelError::Other(format!("channel {target_name:?} disappeared during routing"))
        })?;

        channel.send(message).await?;

        if let Some(info) = self.channel_info.get_mut(&target_name) {
            info.message_count += 1;
        }
        Ok(())
    }

    /// Broadcast a message to all connected channels.
    ///
    /// Rate-limited: if the number of connected channels exceeds the
    /// broadcast limit, returns an error instead of sending.
    pub async fn broadcast(&mut self, message: OutboundMessage) -> Result<(), ChannelError> {
        let connected: Vec<String> = self
            .channel_info
            .values()
            .filter(|info| info.is_connected)
            .map(|info| info.name.clone())
            .collect();

        if connected.len() > self.broadcast_limit {
            warn!(
                count = connected.len(),
                limit = self.broadcast_limit,
                "broadcast rate limit exceeded"
            );
            return Err(ChannelError::Other(format!(
                "broadcast rate limit exceeded: {} channels exceeds limit of {}",
                connected.len(),
                self.broadcast_limit
            )));
        }

        info!(count = connected.len(), "broadcasting message to all channels");

        let mut last_error: Option<ChannelError> = None;
        for name in &connected {
            if let Some(channel) = self.channels.get(name) {
                match channel.send(message.clone()).await {
                    Ok(()) => {
                        if let Some(info) = self.channel_info.get_mut(name) {
                            info.message_count += 1;
                        }
                    }
                    Err(e) => {
                        warn!(channel = %name, error = %e, "broadcast send failed");
                        last_error = Some(e);
                    }
                }
            }
        }

        if let Some(e) = last_error {
            return Err(e);
        }
        Ok(())
    }

    /// List metadata for all registered channels.
    pub fn list_channels(&self) -> Vec<&ChannelInfo> {
        self.channel_info.values().collect()
    }

    /// Get a reference to a channel by name.
    pub fn get_channel(&self, name: &str) -> Option<&(dyn Channel + Send)> {
        self.channels.get(name).map(|boxed| &**boxed)
    }
}

impl Default for ChannelRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ChannelFactory / ChannelRegistry
// ---------------------------------------------------------------------------

/// Factory trait for creating channel backends from configuration.
///
/// Each channel type (telegram, slack, etc.) provides a factory that
/// knows how to parse its specific configuration and instantiate a
/// [`Channel`] implementation.
#[async_trait]
pub trait ChannelFactory: Send + Sync {
    /// Create a channel from the given JSON configuration.
    async fn create(
        &self,
        config: serde_json::Value,
    ) -> Result<Box<dyn Channel + Send>, ChannelError>;
}

/// Registry of channel factories, keyed by channel type.
///
/// Allows dynamic channel creation from configuration. Channel types
/// are validated (alphanumeric + dash/underscore, max 32 chars).
pub struct ChannelRegistry {
    factories: HashMap<String, Box<dyn ChannelFactory>>,
}

impl ChannelRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a factory for a channel type.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel type is invalid.
    pub fn register_factory(
        &mut self,
        channel_type: impl Into<String>,
        factory: Box<dyn ChannelFactory>,
    ) -> Result<(), ChannelError> {
        let channel_type = channel_type.into();
        validate_channel_type(&channel_type)?;

        info!(channel_type = %channel_type, "registering channel factory");
        self.factories.insert(channel_type, factory);
        Ok(())
    }

    /// Create a channel using the registered factory for the given type.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel type is unknown or factory creation fails.
    pub async fn create_channel(
        &self,
        channel_type: &str,
        config: serde_json::Value,
    ) -> Result<Box<dyn Channel + Send>, ChannelError> {
        validate_channel_type(channel_type)?;

        let factory = self.factories.get(channel_type).ok_or_else(|| {
            warn!(channel_type = %channel_type, "no factory registered for channel type");
            ChannelError::Other(format!(
                "no factory registered for channel type {channel_type:?}"
            ))
        })?;

        info!(channel_type = %channel_type, "creating channel from factory");
        factory.create(config).await
    }

    /// Check whether a factory is registered for the given type.
    pub fn has_factory(&self, channel_type: &str) -> bool {
        self.factories.contains_key(channel_type)
    }
}

impl Default for ChannelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{InboundAction, OutboundMessage};
    use std::sync::{Arc, Mutex};

    /// A mock channel that records sent messages.
    struct MockChannel {
        name: String,
        sent: Arc<Mutex<Vec<OutboundMessage>>>,
    }

    impl MockChannel {
        fn new(name: &str) -> (Self, Arc<Mutex<Vec<OutboundMessage>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            let ch = Self {
                name: name.to_string(),
                sent: Arc::clone(&sent),
            };
            (ch, sent)
        }
    }

    #[async_trait]
    impl Channel for MockChannel {
        async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
            self.sent.lock().unwrap().push(message);
            Ok(())
        }

        async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
            Ok(None)
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    /// A mock factory that creates MockChannels.
    struct MockFactory;

    #[async_trait]
    impl ChannelFactory for MockFactory {
        async fn create(
            &self,
            _config: serde_json::Value,
        ) -> Result<Box<dyn Channel + Send>, ChannelError> {
            let (ch, _sent) = MockChannel::new("factory-created");
            Ok(Box::new(ch))
        }
    }

    // -- Capability bitflag tests --

    #[test]
    fn test_capabilities_bitflags() {
        let caps = ChannelCapabilities::THREADS | ChannelCapabilities::INLINE_BUTTONS;
        assert!(caps.has(ChannelCapabilities::THREADS));
        assert!(caps.has(ChannelCapabilities::INLINE_BUTTONS));
        assert!(!caps.has(ChannelCapabilities::REACTIONS));
        assert!(!caps.has(ChannelCapabilities::FILE_ATTACHMENTS));

        // supports_all: only true if all requested bits are present
        assert!(caps.supports_all(ChannelCapabilities::THREADS));
        assert!(caps.supports_all(
            ChannelCapabilities::THREADS | ChannelCapabilities::INLINE_BUTTONS
        ));
        assert!(!caps.supports_all(
            ChannelCapabilities::THREADS | ChannelCapabilities::REACTIONS
        ));

        // supports_any: true if any requested bit is present
        assert!(caps.supports_any(
            ChannelCapabilities::THREADS | ChannelCapabilities::REACTIONS
        ));
        assert!(!caps.supports_any(ChannelCapabilities::REACTIONS));

        // NONE has nothing
        assert!(!ChannelCapabilities::NONE.has(ChannelCapabilities::THREADS));

        // union combines
        let combined = ChannelCapabilities::REACTIONS.union(ChannelCapabilities::WEBHOOKS);
        assert!(combined.has(ChannelCapabilities::REACTIONS));
        assert!(combined.has(ChannelCapabilities::WEBHOOKS));
        assert!(!combined.has(ChannelCapabilities::THREADS));

        // Verify individual bit values
        assert_eq!(ChannelCapabilities::THREADS.bits(), 1);
        assert_eq!(ChannelCapabilities::REACTIONS.bits(), 2);
        assert_eq!(ChannelCapabilities::FILE_ATTACHMENTS.bits(), 4);
        assert_eq!(ChannelCapabilities::INLINE_BUTTONS.bits(), 8);
        assert_eq!(ChannelCapabilities::GROUP_MANAGEMENT.bits(), 16);
        assert_eq!(ChannelCapabilities::RICH_FORMATTING.bits(), 32);
        assert_eq!(ChannelCapabilities::PHOTO_MESSAGES.bits(), 64);
        assert_eq!(ChannelCapabilities::INTERACTIVE_MESSAGES.bits(), 128);
        assert_eq!(ChannelCapabilities::WEBHOOKS.bits(), 256);
    }

    // -- Router: send to named channel --

    #[tokio::test]
    async fn test_router_sends_to_named_channel() {
        let mut router = ChannelRouter::new();
        let (ch, sent) = MockChannel::new("telegram");

        router
            .register_channel("telegram", Box::new(ch), ChannelCapabilities::INLINE_BUTTONS)
            .unwrap();

        let msg = OutboundMessage::text("hello");
        router.send_to("telegram", msg).await.unwrap();

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "hello");

        // Verify message count
        let info = router.list_channels();
        let tg_info = info.iter().find(|i| i.name == "telegram").unwrap();
        assert_eq!(tg_info.message_count, 1);
    }

    #[tokio::test]
    async fn test_router_send_to_missing_channel_fails() {
        let mut router = ChannelRouter::new();
        let msg = OutboundMessage::text("hello");
        let result = router.send_to("nonexistent", msg).await;
        assert!(result.is_err());
    }

    // -- Router: capability-based routing --

    #[tokio::test]
    async fn test_router_capability_based_routing() {
        let mut router = ChannelRouter::new();

        let (ch_plain, _sent_plain) = MockChannel::new("plain");
        let (ch_buttons, sent_buttons) = MockChannel::new("buttons");

        // plain: no inline buttons
        router
            .register_channel(
                "plain-channel",
                Box::new(ch_plain),
                ChannelCapabilities::RICH_FORMATTING,
            )
            .unwrap();

        // buttons: has inline buttons
        router
            .register_channel(
                "button-channel",
                Box::new(ch_buttons),
                ChannelCapabilities::INLINE_BUTTONS | ChannelCapabilities::RICH_FORMATTING,
            )
            .unwrap();

        let msg = OutboundMessage::text("test");
        router
            .send_to_capable(ChannelCapabilities::INLINE_BUTTONS, msg)
            .await
            .unwrap();

        let messages = sent_buttons.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "test");
    }

    #[tokio::test]
    async fn test_router_capability_routing_no_match() {
        let mut router = ChannelRouter::new();
        let (ch, _sent) = MockChannel::new("plain");
        router
            .register_channel(
                "plain",
                Box::new(ch),
                ChannelCapabilities::RICH_FORMATTING,
            )
            .unwrap();

        let msg = OutboundMessage::text("test");
        let result = router
            .send_to_capable(ChannelCapabilities::INLINE_BUTTONS, msg)
            .await;
        assert!(result.is_err());
    }

    // -- Graceful degradation --

    #[test]
    fn test_graceful_degradation_buttons_to_text() {
        let msg = UnifiedMessage {
            text: "Choose an action".to_string(),
            buttons: vec![
                UnifiedButton {
                    label: "Approve".to_string(),
                    action_id: "approve:123".to_string(),
                    style: ButtonStyle::Primary,
                },
                UnifiedButton {
                    label: "Deny".to_string(),
                    action_id: "deny:123".to_string(),
                    style: ButtonStyle::Danger,
                },
            ],
            thread_id: None,
            attachments: Vec::new(),
            formatting: MessageFormat::Plain,
        };

        // Channel WITHOUT inline buttons -- buttons degrade to text
        let outbound = convert_to_outbound(&msg, ChannelCapabilities::NONE);
        assert!(outbound.buttons.is_empty());
        assert!(outbound.text.contains("Actions:"));
        assert!(outbound.text.contains("1. Approve"));
        assert!(outbound.text.contains("2. Deny"));

        // Channel WITH inline buttons -- buttons preserved
        let outbound = convert_to_outbound(&msg, ChannelCapabilities::INLINE_BUTTONS);
        assert_eq!(outbound.buttons.len(), 2);
        assert_eq!(outbound.buttons[0].0, "Approve");
        assert_eq!(outbound.buttons[0].1, "approve:123");
        assert!(!outbound.text.contains("Actions:"));
    }

    #[test]
    fn test_graceful_degradation_formatting() {
        // Markdown message to a channel without rich formatting
        let msg = UnifiedMessage {
            text: "**bold** and *italic* and `code`".to_string(),
            buttons: Vec::new(),
            thread_id: None,
            attachments: Vec::new(),
            formatting: MessageFormat::Markdown,
        };

        let outbound = convert_to_outbound(&msg, ChannelCapabilities::NONE);
        assert!(!outbound.text.contains('*'));
        assert!(!outbound.text.contains('`'));
        assert!(outbound.text.contains("bold"));
        assert!(outbound.text.contains("italic"));
        assert!(outbound.text.contains("code"));

        // Same message to a channel WITH rich formatting -- preserved
        let outbound = convert_to_outbound(&msg, ChannelCapabilities::RICH_FORMATTING);
        assert_eq!(outbound.text, "**bold** and *italic* and `code`");
    }

    #[test]
    fn test_graceful_degradation_html() {
        let msg = UnifiedMessage {
            text: "<b>bold</b> and <i>italic</i>".to_string(),
            buttons: Vec::new(),
            thread_id: None,
            attachments: Vec::new(),
            formatting: MessageFormat::Html,
        };

        let outbound = convert_to_outbound(&msg, ChannelCapabilities::NONE);
        assert_eq!(outbound.text, "bold and italic");

        let outbound = convert_to_outbound(&msg, ChannelCapabilities::RICH_FORMATTING);
        assert_eq!(outbound.text, "<b>bold</b> and <i>italic</i>");
    }

    #[test]
    fn test_graceful_degradation_file_attachment() {
        let msg = UnifiedMessage {
            text: "Here is the report".to_string(),
            buttons: Vec::new(),
            thread_id: None,
            attachments: vec![UnifiedAttachment {
                filename: "report.pdf".to_string(),
                data: vec![0x25, 0x50, 0x44, 0x46], // %PDF
                mime_type: "application/pdf".to_string(),
            }],
            formatting: MessageFormat::Plain,
        };

        // Without FILE_ATTACHMENTS: filename in text, no media
        let outbound = convert_to_outbound(&msg, ChannelCapabilities::NONE);
        assert!(outbound.media.is_none());
        assert!(outbound.text.contains("[attachment: report.pdf]"));

        // With FILE_ATTACHMENTS: media attached
        let outbound = convert_to_outbound(&msg, ChannelCapabilities::FILE_ATTACHMENTS);
        assert!(outbound.media.is_some());
        assert!(!outbound.text.contains("[attachment:"));
    }

    #[test]
    fn test_graceful_degradation_photo() {
        let msg = UnifiedMessage {
            text: "Screenshot".to_string(),
            buttons: Vec::new(),
            thread_id: None,
            attachments: vec![UnifiedAttachment {
                filename: "screenshot.png".to_string(),
                data: vec![0x89, 0x50, 0x4E, 0x47], // PNG magic
                mime_type: "image/png".to_string(),
            }],
            formatting: MessageFormat::Plain,
        };

        // Without PHOTO_MESSAGES: [photo: filename] in text
        let outbound = convert_to_outbound(&msg, ChannelCapabilities::NONE);
        assert!(outbound.media.is_none());
        assert!(outbound.text.contains("[photo: screenshot.png]"));

        // With PHOTO_MESSAGES: media attached as image
        let outbound = convert_to_outbound(&msg, ChannelCapabilities::PHOTO_MESSAGES);
        assert!(outbound.media.is_some());
        assert!(!outbound.text.contains("[photo:"));
    }

    // -- Unified message conversion --

    #[test]
    fn test_unified_message_conversion() {
        let msg = UnifiedMessage {
            text: "Full message".to_string(),
            buttons: vec![UnifiedButton {
                label: "OK".to_string(),
                action_id: "ok".to_string(),
                style: ButtonStyle::Primary,
            }],
            thread_id: Some("thread-1".to_string()),
            attachments: vec![UnifiedAttachment {
                filename: "data.csv".to_string(),
                data: vec![0x61, 0x62, 0x63],
                mime_type: "text/csv".to_string(),
            }],
            formatting: MessageFormat::Markdown,
        };

        // Full capabilities
        let full_caps = ChannelCapabilities::INLINE_BUTTONS
            | ChannelCapabilities::RICH_FORMATTING
            | ChannelCapabilities::FILE_ATTACHMENTS
            | ChannelCapabilities::THREADS;

        let outbound = convert_to_outbound(&msg, full_caps);
        assert_eq!(outbound.text, "Full message");
        assert_eq!(outbound.buttons.len(), 1);
        assert_eq!(outbound.buttons[0].0, "OK");
        assert!(outbound.media.is_some());

        // No capabilities
        let outbound = convert_to_outbound(&msg, ChannelCapabilities::NONE);
        // Markdown stripped
        assert_eq!(outbound.text.lines().next().unwrap(), "Full message");
        // Buttons as text
        assert!(outbound.buttons.is_empty());
        assert!(outbound.text.contains("1. OK"));
        // Attachment as text reference
        assert!(outbound.text.contains("[attachment: data.csv]"));
        assert!(outbound.media.is_none());
    }

    // -- Channel registry --

    #[tokio::test]
    async fn test_channel_registry_dynamic_add() {
        let mut registry = ChannelRegistry::new();
        registry
            .register_factory("mock", Box::new(MockFactory))
            .unwrap();

        assert!(registry.has_factory("mock"));
        assert!(!registry.has_factory("nonexistent"));

        let channel = registry
            .create_channel("mock", serde_json::json!({}))
            .await
            .unwrap();

        assert_eq!(channel.name(), "factory-created");
    }

    #[tokio::test]
    async fn test_channel_registry_unknown_type() {
        let registry = ChannelRegistry::new();
        let result = registry
            .create_channel("unknown", serde_json::json!({}))
            .await;
        assert!(result.is_err());
    }

    // -- Channel name validation --

    #[test]
    fn test_channel_name_validation() {
        // Valid names
        assert!(validate_channel_name("telegram").is_ok());
        assert!(validate_channel_name("my-channel").is_ok());
        assert!(validate_channel_name("chan_123").is_ok());
        assert!(validate_channel_name("A").is_ok());

        // Invalid: empty
        assert!(validate_channel_name("").is_err());

        // Invalid: too long
        let long = "a".repeat(MAX_CHANNEL_NAME_LEN + 1);
        assert!(validate_channel_name(&long).is_err());

        // Invalid: special characters
        assert!(validate_channel_name("chan.type").is_err());
        assert!(validate_channel_name("chan type").is_err());
        assert!(validate_channel_name("chan@type").is_err());
        assert!(validate_channel_name("chan!").is_err());

        // Invalid: path traversal
        assert!(validate_channel_name("../etc").is_err());
        assert!(validate_channel_name("foo/bar").is_err());
        assert!(validate_channel_name("foo\\bar").is_err());
    }

    // -- Broadcast --

    #[tokio::test]
    async fn test_broadcast_sends_to_all() {
        let mut router = ChannelRouter::new();

        let (ch1, sent1) = MockChannel::new("ch1");
        let (ch2, sent2) = MockChannel::new("ch2");
        let (ch3, sent3) = MockChannel::new("ch3");

        router
            .register_channel("ch1", Box::new(ch1), ChannelCapabilities::NONE)
            .unwrap();
        router
            .register_channel("ch2", Box::new(ch2), ChannelCapabilities::NONE)
            .unwrap();
        router
            .register_channel("ch3", Box::new(ch3), ChannelCapabilities::NONE)
            .unwrap();

        let msg = OutboundMessage::text("broadcast test");
        router.broadcast(msg).await.unwrap();

        assert_eq!(sent1.lock().unwrap().len(), 1);
        assert_eq!(sent2.lock().unwrap().len(), 1);
        assert_eq!(sent3.lock().unwrap().len(), 1);

        // All received the same message
        assert_eq!(sent1.lock().unwrap()[0].text, "broadcast test");
        assert_eq!(sent2.lock().unwrap()[0].text, "broadcast test");
        assert_eq!(sent3.lock().unwrap()[0].text, "broadcast test");
    }

    #[tokio::test]
    async fn test_broadcast_rate_limit() {
        let mut router = ChannelRouter::with_broadcast_limit(2);

        let (ch1, _s1) = MockChannel::new("ch1");
        let (ch2, _s2) = MockChannel::new("ch2");
        let (ch3, _s3) = MockChannel::new("ch3");

        router
            .register_channel("ch1", Box::new(ch1), ChannelCapabilities::NONE)
            .unwrap();
        router
            .register_channel("ch2", Box::new(ch2), ChannelCapabilities::NONE)
            .unwrap();
        router
            .register_channel("ch3", Box::new(ch3), ChannelCapabilities::NONE)
            .unwrap();

        let msg = OutboundMessage::text("too many");
        let result = router.broadcast(msg).await;
        assert!(result.is_err());

        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("rate limit"));
    }

    // -- Security: injection tests --

    #[test]
    fn test_channel_name_injection() {
        // Null bytes
        assert!(validate_channel_name("chan\0nel").is_err());
        assert!(validate_channel_name("\0").is_err());

        // Path traversal
        assert!(validate_channel_name("../../etc/passwd").is_err());
        assert!(validate_channel_name("..").is_err());
        assert!(validate_channel_name("foo/../bar").is_err());

        // Shell metacharacters
        assert!(validate_channel_name("chan;ls").is_err());
        assert!(validate_channel_name("chan|cat").is_err());
        assert!(validate_channel_name("chan&rm").is_err());
        assert!(validate_channel_name("$(whoami)").is_err());
        assert!(validate_channel_name("`id`").is_err());

        // Control characters
        assert!(validate_channel_name("chan\x01nel").is_err());
        assert!(validate_channel_name("chan\nnel").is_err());
        assert!(validate_channel_name("chan\rnel").is_err());
        assert!(validate_channel_name("\t").is_err());

        // Unicode trickery
        assert!(validate_channel_name("chan\u{200B}nel").is_err()); // zero-width space
        assert!(validate_channel_name("chan\u{00A0}nel").is_err()); // non-breaking space

        // Register should also fail
        let mut router = ChannelRouter::new();
        let (ch, _sent) = MockChannel::new("bad");
        let result = router.register_channel(
            "../escape",
            Box::new(ch),
            ChannelCapabilities::NONE,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_type_injection() {
        // Factory registry also validates types
        assert!(validate_channel_type("telegram").is_ok());
        assert!(validate_channel_type("my-type").is_ok());

        assert!(validate_channel_type("").is_err());
        assert!(validate_channel_type("type\0bad").is_err());
        assert!(validate_channel_type("../etc").is_err());
        assert!(validate_channel_type("type;ls").is_err());

        let long = "a".repeat(MAX_CHANNEL_TYPE_LEN + 1);
        assert!(validate_channel_type(&long).is_err());
    }

    // -- Unregister --

    #[test]
    fn test_unregister_channel() {
        let mut router = ChannelRouter::new();
        let (ch, _sent) = MockChannel::new("temp");
        router
            .register_channel("temp", Box::new(ch), ChannelCapabilities::NONE)
            .unwrap();

        assert_eq!(router.list_channels().len(), 1);
        assert!(router.unregister_channel("temp"));
        assert_eq!(router.list_channels().len(), 0);
        assert!(!router.unregister_channel("temp")); // already removed
    }

    // -- get_channel --

    #[test]
    fn test_get_channel() {
        let mut router = ChannelRouter::new();
        let (ch, _sent) = MockChannel::new("test-ch");
        router
            .register_channel("test-ch", Box::new(ch), ChannelCapabilities::NONE)
            .unwrap();

        assert!(router.get_channel("test-ch").is_some());
        assert_eq!(router.get_channel("test-ch").unwrap().name(), "test-ch");
        assert!(router.get_channel("nonexistent").is_none());
    }

    // -- list_channels --

    #[test]
    fn test_list_channels_metadata() {
        let mut router = ChannelRouter::new();
        let (ch1, _s1) = MockChannel::new("ch1");
        let (ch2, _s2) = MockChannel::new("ch2");

        router
            .register_channel(
                "ch1",
                Box::new(ch1),
                ChannelCapabilities::INLINE_BUTTONS | ChannelCapabilities::THREADS,
            )
            .unwrap();
        router
            .register_channel(
                "ch2",
                Box::new(ch2),
                ChannelCapabilities::WEBHOOKS,
            )
            .unwrap();

        let channels = router.list_channels();
        assert_eq!(channels.len(), 2);

        let ch1_info = channels.iter().find(|i| i.name == "ch1").unwrap();
        assert!(ch1_info.capabilities.has(ChannelCapabilities::INLINE_BUTTONS));
        assert!(ch1_info.capabilities.has(ChannelCapabilities::THREADS));
        assert!(ch1_info.is_connected);
        assert_eq!(ch1_info.message_count, 0);

        let ch2_info = channels.iter().find(|i| i.name == "ch2").unwrap();
        assert!(ch2_info.capabilities.has(ChannelCapabilities::WEBHOOKS));
    }

    // -- UnifiedMessage::text convenience --

    #[test]
    fn test_unified_message_text_constructor() {
        let msg = UnifiedMessage::text("hello");
        assert_eq!(msg.text, "hello");
        assert!(msg.buttons.is_empty());
        assert!(msg.thread_id.is_none());
        assert!(msg.attachments.is_empty());
        assert_eq!(msg.formatting, MessageFormat::Plain);
    }

    // -- Default impls --

    #[test]
    fn test_default_impls() {
        let router = ChannelRouter::default();
        assert!(router.list_channels().is_empty());

        let registry = ChannelRegistry::default();
        assert!(!registry.has_factory("anything"));
    }
}
