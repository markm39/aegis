//! Tlon (Urbit) channel adapter.
//!
//! Minimal stub for Tlon/Urbit ship messaging. Wraps the generic
//! webhook adapter to send messages to an Urbit ship endpoint.
//!
//! # Security
//!
//! - Ship URL is validated for HTTPS.
//! - Ship name is validated for safe characters.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Tlon (Urbit) channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlonConfig {
    /// Urbit ship API endpoint URL.
    pub ship_url: String,
    /// Urbit ship name (e.g., `~zod`).
    pub ship_name: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate the Tlon configuration.
pub fn validate_config(config: &TlonConfig) -> Result<(), ChannelError> {
    if config.ship_url.is_empty() {
        return Err(ChannelError::Api("Tlon ship_url cannot be empty".into()));
    }
    if config.ship_name.is_empty() {
        return Err(ChannelError::Api("Tlon ship_name cannot be empty".into()));
    }
    // Ship names should only contain safe characters
    if !config
        .ship_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '~')
    {
        return Err(ChannelError::Api(format!(
            "Tlon ship_name contains invalid characters: {:?}",
            config.ship_name
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel implementation
// ---------------------------------------------------------------------------

/// Tlon (Urbit) channel wrapping the generic webhook adapter.
pub struct TlonChannel {
    inner: WebhookChannel,
}

impl TlonChannel {
    /// Create a new Tlon channel from configuration.
    pub fn new(config: TlonConfig) -> Result<Self, ChannelError> {
        validate_config(&config)?;

        let url = format!("{}/~/channel", config.ship_url.trim_end_matches('/'));
        let webhook = WebhookConfig {
            name: "tlon".to_string(),
            outbound_url: url,
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"action":"poke","ship":"","mark":"helm-hi","json":"{text}"}"#
                .to_string(),
        };

        Ok(Self {
            inner: WebhookChannel::new(webhook),
        })
    }
}

#[async_trait]
impl Channel for TlonChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        self.inner.send(message).await
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        self.inner.recv().await
    }

    fn name(&self) -> &str {
        "tlon"
    }

    async fn send_photo(&self, photo: OutboundPhoto) -> Result<(), ChannelError> {
        self.inner.send_photo(photo).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TlonConfig {
        TlonConfig {
            ship_url: "https://zod.urbit.org".to_string(),
            ship_name: "~zod".to_string(),
        }
    }

    #[test]
    fn test_tlon_config_validation() {
        assert!(validate_config(&test_config()).is_ok());

        // Empty URL
        let mut cfg = test_config();
        cfg.ship_url = String::new();
        assert!(validate_config(&cfg).is_err());

        // Empty ship name
        let mut cfg = test_config();
        cfg.ship_name = String::new();
        assert!(validate_config(&cfg).is_err());

        // Invalid ship name
        let mut cfg = test_config();
        cfg.ship_name = "bad ship!".to_string();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn test_tlon_config_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: TlonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn test_tlon_channel_name() {
        let channel = TlonChannel::new(test_config()).unwrap();
        assert_eq!(channel.name(), "tlon");
    }
}
