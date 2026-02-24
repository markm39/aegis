//! Feishu (Lark) channel adapter (via bot webhook).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the Feishu channel.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeishuConfig {
    /// Feishu bot webhook URL.
    pub webhook_url: String,
    /// Optional webhook signing secret.
    #[serde(default)]
    pub secret: Option<String>,
}

impl std::fmt::Debug for FeishuConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeishuConfig")
            .field("webhook_url", &self.webhook_url)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Feishu channel wrapping the generic webhook adapter.
pub struct FeishuChannel {
    inner: WebhookChannel,
}

impl FeishuChannel {
    /// Create a new Feishu channel from configuration.
    pub fn new(config: FeishuConfig) -> Self {
        let webhook = WebhookConfig {
            name: "feishu".to_string(),
            outbound_url: config.webhook_url,
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"msg_type":"text","content":{"text":"{text}"}}"#.to_string(),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for FeishuChannel {
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
    fn feishu_config_roundtrip() {
        let config = FeishuConfig {
            webhook_url: "https://open.feishu.cn/open-apis/bot/v2/hook/abc123".to_string(),
            secret: Some("my-secret".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: FeishuConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn feishu_channel_name() {
        let channel = FeishuChannel::new(FeishuConfig {
            webhook_url: "https://example.com".to_string(),
            secret: None,
        });
        assert_eq!(channel.name(), "feishu");
    }
}
