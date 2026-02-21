//! WhatsApp Cloud API channel adapter.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the WhatsApp channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhatsappConfig {
    /// WhatsApp Cloud API base URL.
    pub api_url: String,
    /// Access token for the WhatsApp Business API.
    pub access_token: String,
    /// Phone number ID for sending messages.
    pub phone_number_id: String,
}

/// WhatsApp channel wrapping the generic webhook adapter.
pub struct WhatsappChannel {
    inner: WebhookChannel,
}

impl WhatsappChannel {
    /// Create a new WhatsApp channel from configuration.
    pub fn new(config: WhatsappConfig) -> Self {
        let url = format!(
            "{}/{}/messages",
            config.api_url.trim_end_matches('/'),
            config.phone_number_id
        );
        let webhook = WebhookConfig {
            name: "whatsapp".to_string(),
            outbound_url: url,
            inbound_url: None,
            auth_header: Some(format!("Bearer {}", config.access_token)),
            payload_template: r#"{"messaging_product":"whatsapp","type":"text","text":{"body":"{text}"}}"#
                .to_string(),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for WhatsappChannel {
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
    fn whatsapp_config_roundtrip() {
        let config = WhatsappConfig {
            api_url: "https://graph.facebook.com/v17.0".to_string(),
            access_token: "EAAx...".to_string(),
            phone_number_id: "123456789".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: WhatsappConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn whatsapp_channel_name() {
        let channel = WhatsappChannel::new(WhatsappConfig {
            api_url: "https://graph.facebook.com/v17.0".to_string(),
            access_token: "token".to_string(),
            phone_number_id: "123".to_string(),
        });
        assert_eq!(channel.name(), "whatsapp");
    }
}
