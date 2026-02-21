//! iMessage channel adapter (via local API bridge).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the iMessage channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImessageConfig {
    /// API bridge URL (e.g., a local BlueBubbles or Beeper server).
    pub api_url: String,
    /// Recipient phone number or email.
    pub recipient: String,
}

/// iMessage channel wrapping the generic webhook adapter.
pub struct ImessageChannel {
    inner: WebhookChannel,
}

impl ImessageChannel {
    /// Create a new iMessage channel from configuration.
    pub fn new(config: ImessageConfig) -> Self {
        let webhook = WebhookConfig {
            name: "imessage".to_string(),
            outbound_url: config.api_url,
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
impl Channel for ImessageChannel {
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
    fn imessage_config_roundtrip() {
        let config = ImessageConfig {
            api_url: "http://localhost:1234/send".to_string(),
            recipient: "+1234567890".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ImessageConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn imessage_channel_name() {
        let channel = ImessageChannel::new(ImessageConfig {
            api_url: "http://localhost:1234/send".to_string(),
            recipient: "user@example.com".to_string(),
        });
        assert_eq!(channel.name(), "imessage");
    }
}
