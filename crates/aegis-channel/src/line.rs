//! LINE Messaging API channel adapter.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the LINE channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineConfig {
    /// LINE channel access token.
    pub channel_access_token: String,
    /// Recipient user ID.
    pub user_id: String,
}

/// LINE channel wrapping the generic webhook adapter.
pub struct LineChannel {
    inner: WebhookChannel,
}

impl LineChannel {
    /// Create a new LINE channel from configuration.
    pub fn new(config: LineConfig) -> Self {
        let webhook = WebhookConfig {
            name: "line".to_string(),
            outbound_url: "https://api.line.me/v2/bot/message/push".to_string(),
            inbound_url: None,
            auth_header: Some(format!("Bearer {}", config.channel_access_token)),
            payload_template: format!(
                r#"{{"to":"{}","messages":[{{"type":"text","text":"{{text}}"}}]}}"#,
                config.user_id
            ),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for LineChannel {
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
    fn line_config_roundtrip() {
        let config = LineConfig {
            channel_access_token: "abc123xyz".to_string(),
            user_id: "U1234567890".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: LineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn line_channel_name() {
        let channel = LineChannel::new(LineConfig {
            channel_access_token: "token".to_string(),
            user_id: "U123".to_string(),
        });
        assert_eq!(channel.name(), "line");
    }
}
