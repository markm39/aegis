//! Microsoft Teams channel adapter (via Incoming Webhook connector).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the Microsoft Teams channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MsteamsConfig {
    /// Incoming Webhook URL for the Teams channel.
    pub webhook_url: String,
}

/// Microsoft Teams channel wrapping the generic webhook adapter.
pub struct MsteamsChannel {
    inner: WebhookChannel,
}

impl MsteamsChannel {
    /// Create a new MS Teams channel from configuration.
    pub fn new(config: MsteamsConfig) -> Self {
        let webhook = WebhookConfig {
            name: "msteams".to_string(),
            outbound_url: config.webhook_url,
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"text":"{text}"}"#.to_string(),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for MsteamsChannel {
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
    fn msteams_config_roundtrip() {
        let config = MsteamsConfig {
            webhook_url: "https://outlook.office.com/webhook/abc123".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: MsteamsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn msteams_channel_name() {
        let channel = MsteamsChannel::new(MsteamsConfig {
            webhook_url: "https://example.com".to_string(),
        });
        assert_eq!(channel.name(), "msteams");
    }
}
