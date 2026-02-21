//! Mattermost channel adapter (via Incoming Webhook).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the Mattermost channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MattermostConfig {
    /// Mattermost Incoming Webhook URL.
    pub webhook_url: String,
    /// Optional channel ID to override the webhook default.
    #[serde(default)]
    pub channel_id: Option<String>,
}

/// Mattermost channel wrapping the generic webhook adapter.
pub struct MattermostChannel {
    inner: WebhookChannel,
}

impl MattermostChannel {
    /// Create a new Mattermost channel from configuration.
    pub fn new(config: MattermostConfig) -> Self {
        let template = match config.channel_id {
            Some(ref cid) => format!(r#"{{"channel_id":"{}","message":"{{text}}"}}"#, cid),
            None => r#"{"text":"{text}"}"#.to_string(),
        };
        let webhook = WebhookConfig {
            name: "mattermost".to_string(),
            outbound_url: config.webhook_url,
            inbound_url: None,
            auth_header: None,
            payload_template: template,
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for MattermostChannel {
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
    fn mattermost_config_roundtrip() {
        let config = MattermostConfig {
            webhook_url: "https://mattermost.example.com/hooks/abc123".to_string(),
            channel_id: Some("town-square".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: MattermostConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn mattermost_channel_name() {
        let channel = MattermostChannel::new(MattermostConfig {
            webhook_url: "https://example.com".to_string(),
            channel_id: None,
        });
        assert_eq!(channel.name(), "mattermost");
    }
}
