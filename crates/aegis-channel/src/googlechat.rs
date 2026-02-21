//! Google Chat channel adapter (via webhook).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the Google Chat channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GooglechatConfig {
    /// Google Chat Incoming Webhook URL.
    pub webhook_url: String,
}

/// Google Chat channel wrapping the generic webhook adapter.
pub struct GooglechatChannel {
    inner: WebhookChannel,
}

impl GooglechatChannel {
    /// Create a new Google Chat channel from configuration.
    pub fn new(config: GooglechatConfig) -> Self {
        let webhook = WebhookConfig {
            name: "googlechat".to_string(),
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
impl Channel for GooglechatChannel {
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
    fn googlechat_config_roundtrip() {
        let config = GooglechatConfig {
            webhook_url: "https://chat.googleapis.com/v1/spaces/abc/messages?key=xyz".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: GooglechatConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn googlechat_channel_name() {
        let channel = GooglechatChannel::new(GooglechatConfig {
            webhook_url: "https://example.com".to_string(),
        });
        assert_eq!(channel.name(), "googlechat");
    }
}
