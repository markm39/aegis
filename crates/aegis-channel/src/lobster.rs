//! Lobster channel adapter.
//!
//! Minimal stub for a Lobster messaging backend. Wraps the generic
//! webhook adapter to send messages via a REST API.
//!
//! # Security
//!
//! - API key is never logged.
//! - API URL and key are validated for non-emptiness.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Lobster channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LobsterConfig {
    /// Lobster API base URL.
    pub api_url: String,
    /// API key for authentication.
    /// Sensitive: never log this value.
    pub api_key: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate the Lobster configuration.
pub fn validate_config(config: &LobsterConfig) -> Result<(), ChannelError> {
    if config.api_url.is_empty() {
        return Err(ChannelError::Api("Lobster api_url cannot be empty".into()));
    }
    if config.api_key.is_empty() {
        return Err(ChannelError::Api("Lobster api_key cannot be empty".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel implementation
// ---------------------------------------------------------------------------

/// Lobster channel wrapping the generic webhook adapter.
pub struct LobsterChannel {
    inner: WebhookChannel,
}

impl LobsterChannel {
    /// Create a new Lobster channel from configuration.
    pub fn new(config: LobsterConfig) -> Result<Self, ChannelError> {
        validate_config(&config)?;

        let webhook = WebhookConfig {
            name: "lobster".to_string(),
            outbound_url: format!(
                "{}/api/messages",
                config.api_url.trim_end_matches('/')
            ),
            inbound_url: None,
            auth_header: Some(format!("Bearer {}", config.api_key)),
            payload_template: r#"{"text":"{text}"}"#.to_string(),
        };

        Ok(Self {
            inner: WebhookChannel::new(webhook),
        })
    }
}

#[async_trait]
impl Channel for LobsterChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        self.inner.send(message).await
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        self.inner.recv().await
    }

    fn name(&self) -> &str {
        "lobster"
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

    fn test_config() -> LobsterConfig {
        LobsterConfig {
            api_url: "https://lobster.example.com".to_string(),
            api_key: "lob_key_abc123".to_string(),
        }
    }

    #[test]
    fn test_lobster_config_validation() {
        assert!(validate_config(&test_config()).is_ok());

        // Empty URL
        let mut cfg = test_config();
        cfg.api_url = String::new();
        assert!(validate_config(&cfg).is_err());

        // Empty key
        let mut cfg = test_config();
        cfg.api_key = String::new();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn test_lobster_config_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: LobsterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn test_lobster_channel_name() {
        let channel = LobsterChannel::new(test_config()).unwrap();
        assert_eq!(channel.name(), "lobster");
    }
}
