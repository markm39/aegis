//! Signal messenger channel adapter (via signal-cli REST API).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the Signal channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalConfig {
    /// Signal CLI REST API base URL.
    pub api_url: String,
    /// Registered phone number (e.g., `"+1234567890"`).
    pub phone_number: String,
    /// Recipient phone numbers to send messages to.
    #[serde(default)]
    pub recipients: Vec<String>,
}

/// Signal channel wrapping the generic webhook adapter.
pub struct SignalChannel {
    inner: WebhookChannel,
}

impl SignalChannel {
    /// Create a new Signal channel from configuration.
    pub fn new(config: SignalConfig) -> Self {
        let url = format!(
            "{}/v2/send",
            config.api_url.trim_end_matches('/')
        );
        let webhook = WebhookConfig {
            name: "signal".to_string(),
            outbound_url: url,
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"message":"{text}","number":"","recipients":[]}"#.to_string(),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for SignalChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        self.inner.send(message).await
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        self.inner.recv().await
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn send_photo(&self, photo: OutboundPhoto) -> Result<(), ChannelError> {
        self.inner.send_photo(photo).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_config_roundtrip() {
        let config = SignalConfig {
            api_url: "http://localhost:8080".to_string(),
            phone_number: "+1234567890".to_string(),
            recipients: vec!["+0987654321".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: SignalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn signal_channel_name() {
        let channel = SignalChannel::new(SignalConfig {
            api_url: "http://localhost:8080".to_string(),
            phone_number: "+1".to_string(),
            recipients: vec![],
        });
        assert_eq!(channel.name(), "signal");
    }
}
