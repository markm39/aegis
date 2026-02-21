//! Discord webhook channel adapter.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the Discord channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscordConfig {
    /// Discord webhook URL.
    pub webhook_url: String,
    /// Optional bot token for API access (enables inbound polling).
    #[serde(default)]
    pub bot_token: Option<String>,
    /// Optional channel ID for inbound message polling.
    #[serde(default)]
    pub channel_id: Option<String>,
}

/// Discord channel wrapping the generic webhook adapter.
pub struct DiscordChannel {
    inner: WebhookChannel,
}

impl DiscordChannel {
    /// Create a new Discord channel from configuration.
    pub fn new(config: DiscordConfig) -> Self {
        let webhook = WebhookConfig {
            name: "discord".to_string(),
            outbound_url: config.webhook_url,
            inbound_url: None,
            auth_header: config.bot_token.map(|t| format!("Bot {t}")),
            payload_template: r#"{"content":"{text}"}"#.to_string(),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for DiscordChannel {
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
    fn discord_config_roundtrip() {
        let config = DiscordConfig {
            webhook_url: "https://discord.com/api/webhooks/123/abc".to_string(),
            bot_token: Some("my-token".to_string()),
            channel_id: Some("123456".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: DiscordConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn discord_channel_name() {
        let channel = DiscordChannel::new(DiscordConfig {
            webhook_url: "https://example.com".to_string(),
            bot_token: None,
            channel_id: None,
        });
        assert_eq!(channel.name(), "discord");
    }
}
