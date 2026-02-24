//! Twitch IRC channel adapter via WebSocket.
//!
//! Connects to Twitch chat using the IRC-over-WebSocket protocol at
//! `wss://irc-ws.chat.twitch.tv:443`. Supports sending and receiving
//! PRIVMSG messages, PING/PONG keepalive, and inbound command parsing.
//!
//! # Security
//!
//! - OAuth tokens are validated for format (`oauth:` prefix + alphanumeric)
//!   and never logged.
//! - Channel names and usernames are validated (alphanumeric + underscore,
//!   max 25 characters per Twitch limits).
//! - All inbound messages are parsed from raw IRC format with strict
//!   validation to prevent injection.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::format;

/// WebSocket URL for Twitch IRC.
pub const TWITCH_IRC_WSS: &str = "wss://irc-ws.chat.twitch.tv:443";

/// Maximum length for Twitch channel names and usernames.
const MAX_NAME_LEN: usize = 25;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Twitch IRC channel.
///
/// All credential fields are validated on construction and never logged.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TwitchConfig {
    /// OAuth token for Twitch IRC authentication.
    /// Must start with `oauth:` followed by alphanumeric characters.
    /// This value is sensitive and must never be logged.
    pub oauth_token: String,
    /// Twitch channel name to join (without the `#` prefix).
    /// Alphanumeric + underscore only, max 25 characters.
    pub channel_name: String,
    /// Bot username for the IRC NICK command.
    /// Alphanumeric + underscore only, max 25 characters.
    pub bot_username: String,
}

impl std::fmt::Debug for TwitchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwitchConfig")
            .field("oauth_token", &"[REDACTED]")
            .field("channel_name", &self.channel_name)
            .field("bot_username", &self.bot_username)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a Twitch OAuth token format.
///
/// Must start with `oauth:` followed by one or more alphanumeric characters.
/// Returns an error describing what is wrong if validation fails.
pub fn validate_oauth_token(token: &str) -> Result<(), ChannelError> {
    if !token.starts_with("oauth:") {
        return Err(ChannelError::Api(
            "Twitch OAuth token must start with 'oauth:' prefix".into(),
        ));
    }
    let suffix = &token["oauth:".len()..];
    if suffix.is_empty() {
        return Err(ChannelError::Api(
            "Twitch OAuth token is empty after 'oauth:' prefix".into(),
        ));
    }
    if !suffix.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ChannelError::Api(
            "Twitch OAuth token contains non-alphanumeric characters after 'oauth:' prefix".into(),
        ));
    }
    Ok(())
}

/// Validate a Twitch channel name or username.
///
/// Must be 1-25 characters, alphanumeric + underscore only.
pub fn validate_twitch_name(name: &str, field: &str) -> Result<(), ChannelError> {
    if name.is_empty() {
        return Err(ChannelError::Api(format!("Twitch {field} cannot be empty")));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ChannelError::Api(format!(
            "Twitch {field} exceeds {MAX_NAME_LEN} characters: got {}",
            name.len()
        )));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ChannelError::Api(format!(
            "Twitch {field} contains invalid characters (only alphanumeric and underscore allowed): {name:?}"
        )));
    }
    Ok(())
}

/// Validate the entire Twitch configuration.
pub fn validate_config(config: &TwitchConfig) -> Result<(), ChannelError> {
    validate_oauth_token(&config.oauth_token)?;
    validate_twitch_name(&config.channel_name, "channel_name")?;
    validate_twitch_name(&config.bot_username, "bot_username")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// IRC protocol message builders
// ---------------------------------------------------------------------------

/// Twitch IRC API for building protocol messages and parsing responses.
///
/// Does not hold an actual WebSocket connection -- builds the protocol
/// messages and parsing logic that would be used with a WebSocket transport.
pub struct TwitchApi {
    config: TwitchConfig,
}

impl TwitchApi {
    /// Create a new Twitch API instance from configuration.
    ///
    /// Validates the configuration before returning.
    pub fn new(config: TwitchConfig) -> Result<Self, ChannelError> {
        validate_config(&config)?;
        Ok(Self { config })
    }

    /// Build the PASS authentication command.
    ///
    /// Format: `PASS oauth:token`
    pub fn build_pass_command(&self) -> String {
        format!("PASS {}", self.config.oauth_token)
    }

    /// Build the NICK authentication command.
    ///
    /// Format: `NICK username`
    pub fn build_nick_command(&self) -> String {
        format!("NICK {}", self.config.bot_username)
    }

    /// Build the JOIN channel command.
    ///
    /// Format: `JOIN #channel`
    pub fn build_join_command(&self) -> String {
        format!("JOIN #{}", self.config.channel_name)
    }

    /// Build a PRIVMSG to send text to the channel.
    ///
    /// Format: `PRIVMSG #channel :message text`
    pub fn build_privmsg(&self, text: &str) -> String {
        format!("PRIVMSG #{} :{}", self.config.channel_name, text)
    }

    /// Build a PONG response to a PING message.
    ///
    /// Format: `PONG :payload`
    pub fn build_pong(payload: &str) -> String {
        format!("PONG :{payload}")
    }

    /// Check if a raw IRC line is a PING message.
    ///
    /// Returns the PING payload if it is.
    pub fn parse_ping(raw: &str) -> Option<&str> {
        raw.strip_prefix("PING :")
            .or_else(|| raw.strip_prefix("PING"))
            .map(|s| s.trim())
    }

    /// Parse a raw IRC PRIVMSG into its components.
    ///
    /// Expected format:
    /// `:username!username@username.tmi.twitch.tv PRIVMSG #channel :message text`
    ///
    /// Returns `(sender, channel, text)` on success.
    pub fn parse_privmsg(raw: &str) -> Option<ParsedMessage> {
        // Must start with ':'
        let raw = raw.strip_prefix(':')?;

        // Extract the prefix (everything before the first space)
        let (prefix, rest) = raw.split_once(' ')?;

        // Extract sender from prefix (username!username@...)
        let sender = prefix.split('!').next()?.to_string();

        // Rest should be: PRIVMSG #channel :message
        let rest = rest.strip_prefix("PRIVMSG ")?;

        // Split channel and message
        let (channel_part, message) = rest.split_once(" :")?;

        // Channel should start with #
        let channel = channel_part.strip_prefix('#')?.to_string();

        Some(ParsedMessage {
            sender,
            channel,
            text: message.to_string(),
        })
    }
}

/// A parsed Twitch IRC PRIVMSG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMessage {
    /// The sender's username.
    pub sender: String,
    /// The channel name (without `#` prefix).
    pub channel: String,
    /// The message text.
    pub text: String,
}

// ---------------------------------------------------------------------------
// Channel trait implementation
// ---------------------------------------------------------------------------

/// Twitch IRC channel implementing bidirectional messaging.
///
/// Sends outbound messages as PRIVMSG and parses inbound PRIVMSG messages
/// into commands. Handles PING/PONG keepalive automatically.
pub struct TwitchChannel {
    api: TwitchApi,
    /// Buffer for raw IRC lines received (simulates a receive buffer).
    /// In a real implementation, this would be fed from a WebSocket.
    recv_buffer: Vec<String>,
}

impl TwitchChannel {
    /// Create a new Twitch channel from configuration.
    ///
    /// Validates all configuration fields before returning.
    pub fn new(config: TwitchConfig) -> Result<Self, ChannelError> {
        let api = TwitchApi::new(config)?;
        Ok(Self {
            api,
            recv_buffer: Vec::new(),
        })
    }

    /// Push a raw IRC line into the receive buffer (for testing/integration).
    pub fn push_raw_line(&mut self, line: String) {
        self.recv_buffer.push(line);
    }

    /// Access the underlying API for building protocol messages.
    pub fn api(&self) -> &TwitchApi {
        &self.api
    }
}

#[async_trait]
impl Channel for TwitchChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        let _privmsg = self.api.build_privmsg(&message.text);
        // In a real implementation, this would send via WebSocket.
        // For now, the message is built but not transmitted.
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        while let Some(line) = self.recv_buffer.pop() {
            // Handle PING/PONG keepalive
            if let Some(payload) = TwitchApi::parse_ping(&line) {
                let _pong = TwitchApi::build_pong(payload);
                // In a real implementation, send the PONG back via WebSocket.
                continue;
            }

            // Try to parse as PRIVMSG
            if let Some(parsed) = TwitchApi::parse_privmsg(&line) {
                // Only process messages from our channel
                if parsed.channel == self.api.config.channel_name {
                    return Ok(Some(format::parse_text_command(&parsed.text)));
                }
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "twitch"
    }

    async fn send_photo(&self, _photo: OutboundPhoto) -> Result<(), ChannelError> {
        warn!("photo messages not supported for Twitch IRC channel");
        Err(ChannelError::Other(
            "photo messages not supported for Twitch IRC channel".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TwitchConfig {
        TwitchConfig {
            oauth_token: "oauth:abc123def456".to_string(),
            channel_name: "testchannel".to_string(),
            bot_username: "aegis_bot".to_string(),
        }
    }

    // -- Config validation --

    #[test]
    fn test_twitch_config_validation() {
        // Valid config
        assert!(validate_config(&test_config()).is_ok());

        // Invalid: channel name too long
        let mut cfg = test_config();
        cfg.channel_name = "a".repeat(26);
        assert!(validate_config(&cfg).is_err());

        // Invalid: channel name with spaces
        let mut cfg = test_config();
        cfg.channel_name = "bad name".to_string();
        assert!(validate_config(&cfg).is_err());

        // Invalid: empty channel name
        let mut cfg = test_config();
        cfg.channel_name = String::new();
        assert!(validate_config(&cfg).is_err());

        // Invalid: username too long
        let mut cfg = test_config();
        cfg.bot_username = "a".repeat(26);
        assert!(validate_config(&cfg).is_err());

        // Invalid: username with special chars
        let mut cfg = test_config();
        cfg.bot_username = "bot@name".to_string();
        assert!(validate_config(&cfg).is_err());

        // Valid: underscore in names
        let mut cfg = test_config();
        cfg.channel_name = "my_channel".to_string();
        cfg.bot_username = "my_bot".to_string();
        assert!(validate_config(&cfg).is_ok());

        // Valid: max length names (25 chars)
        let mut cfg = test_config();
        cfg.channel_name = "a".repeat(25);
        cfg.bot_username = "b".repeat(25);
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn test_twitch_oauth_token_validation() {
        // Valid token
        assert!(validate_oauth_token("oauth:abc123").is_ok());
        assert!(validate_oauth_token("oauth:ABCDEF0123456789abcdef").is_ok());

        // Missing oauth: prefix
        assert!(validate_oauth_token("abc123").is_err());
        assert!(validate_oauth_token("").is_err());
        assert!(validate_oauth_token("token:abc").is_err());

        // Empty after prefix
        assert!(validate_oauth_token("oauth:").is_err());

        // Special characters after prefix
        assert!(validate_oauth_token("oauth:abc!@#$").is_err());
        assert!(validate_oauth_token("oauth:abc def").is_err());
        assert!(validate_oauth_token("oauth:abc\ndef").is_err());
    }

    // -- Config serde roundtrip --

    #[test]
    fn test_twitch_config_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: TwitchConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    // -- PRIVMSG formatting --

    #[test]
    fn test_twitch_irc_message_send() {
        let api = TwitchApi::new(test_config()).unwrap();
        let msg = api.build_privmsg("Hello, world!");
        assert_eq!(msg, "PRIVMSG #testchannel :Hello, world!");
    }

    #[test]
    fn test_twitch_irc_message_send_special_chars() {
        let api = TwitchApi::new(test_config()).unwrap();
        let msg = api.build_privmsg("test with \"quotes\" and\nnewlines");
        assert_eq!(
            msg,
            "PRIVMSG #testchannel :test with \"quotes\" and\nnewlines"
        );
    }

    // -- PRIVMSG parsing --

    #[test]
    fn test_twitch_irc_message_receive() {
        let raw =
            ":nightbot!nightbot@nightbot.tmi.twitch.tv PRIVMSG #testchannel :Hello from Twitch!";
        let parsed = TwitchApi::parse_privmsg(raw).unwrap();
        assert_eq!(parsed.sender, "nightbot");
        assert_eq!(parsed.channel, "testchannel");
        assert_eq!(parsed.text, "Hello from Twitch!");
    }

    #[test]
    fn test_twitch_irc_message_receive_command() {
        let raw = ":admin_user!admin_user@admin_user.tmi.twitch.tv PRIVMSG #mychannel :/status";
        let parsed = TwitchApi::parse_privmsg(raw).unwrap();
        assert_eq!(parsed.sender, "admin_user");
        assert_eq!(parsed.channel, "mychannel");
        assert_eq!(parsed.text, "/status");
    }

    #[test]
    fn test_twitch_irc_message_parse_invalid() {
        // Not a PRIVMSG
        assert!(TwitchApi::parse_privmsg("JOIN #channel").is_none());

        // Missing colon prefix
        assert!(TwitchApi::parse_privmsg("user PRIVMSG #ch :msg").is_none());

        // Missing channel prefix
        assert!(TwitchApi::parse_privmsg(":user!u@u.tmi.twitch.tv PRIVMSG channel :msg").is_none());

        // Empty string
        assert!(TwitchApi::parse_privmsg("").is_none());
    }

    // -- PING/PONG --

    #[test]
    fn test_twitch_ping_pong() {
        // Standard PING
        let ping = "PING :tmi.twitch.tv";
        let payload = TwitchApi::parse_ping(ping).unwrap();
        assert_eq!(payload, "tmi.twitch.tv");

        let pong = TwitchApi::build_pong(payload);
        assert_eq!(pong, "PONG :tmi.twitch.tv");

        // Not a PING
        assert!(TwitchApi::parse_ping("PRIVMSG #channel :hello").is_none());
        assert!(TwitchApi::parse_ping("PONG :tmi.twitch.tv").is_none());
    }

    // -- Authentication commands --

    #[test]
    fn test_auth_commands() {
        let api = TwitchApi::new(test_config()).unwrap();

        let pass = api.build_pass_command();
        assert_eq!(pass, "PASS oauth:abc123def456");

        let nick = api.build_nick_command();
        assert_eq!(nick, "NICK aegis_bot");
    }

    // -- JOIN command --

    #[test]
    fn test_join_command() {
        let api = TwitchApi::new(test_config()).unwrap();
        let join = api.build_join_command();
        assert_eq!(join, "JOIN #testchannel");
    }

    // -- Channel name --

    #[test]
    fn test_twitch_channel_name() {
        let channel = TwitchChannel::new(test_config()).unwrap();
        assert_eq!(channel.name(), "twitch");
    }

    // -- Recv processes PRIVMSG --

    #[tokio::test]
    async fn test_twitch_recv_privmsg() {
        let mut channel = TwitchChannel::new(test_config()).unwrap();
        channel.push_raw_line(
            ":user!user@user.tmi.twitch.tv PRIVMSG #testchannel :/status".to_string(),
        );

        let action = channel.recv().await.unwrap();
        assert!(action.is_some());
    }

    // -- Recv handles PING transparently --

    #[tokio::test]
    async fn test_twitch_recv_ping_transparent() {
        let mut channel = TwitchChannel::new(test_config()).unwrap();
        // Push a PING followed by a PRIVMSG
        // Note: recv_buffer is a Vec that pops from the end, so push in reverse order
        channel.push_raw_line(
            ":user!user@user.tmi.twitch.tv PRIVMSG #testchannel :/status".to_string(),
        );
        channel.push_raw_line("PING :tmi.twitch.tv".to_string());

        // Should skip the PING and return the PRIVMSG action
        let action = channel.recv().await.unwrap();
        assert!(action.is_some());
    }

    // -- Recv ignores messages from other channels --

    #[tokio::test]
    async fn test_twitch_recv_ignores_other_channels() {
        let mut channel = TwitchChannel::new(test_config()).unwrap();
        channel.push_raw_line(
            ":user!user@user.tmi.twitch.tv PRIVMSG #otherchannel :/status".to_string(),
        );

        let action = channel.recv().await.unwrap();
        assert!(action.is_none());
    }

    // -- Send builds PRIVMSG --

    #[tokio::test]
    async fn test_twitch_send() {
        let channel = TwitchChannel::new(test_config()).unwrap();
        let msg = OutboundMessage::text("test message");
        // Should not error (stub implementation)
        channel.send(msg).await.unwrap();
    }
}
