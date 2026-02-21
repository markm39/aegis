//! Nostr relay channel adapter.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the Nostr channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NostrConfig {
    /// Nostr relay WebSocket URL (e.g., `"wss://relay.damus.io"`).
    pub relay_url: String,
    /// Private key in hex format for signing events.
    pub private_key_hex: String,
}

/// Nostr channel wrapping the generic webhook adapter.
///
/// This is a minimal stub. A full implementation would use the Nostr
/// protocol (NIP-01 events over WebSocket) rather than HTTP webhooks.
pub struct NostrChannel {
    inner: WebhookChannel,
}

impl NostrChannel {
    /// Create a new Nostr channel from configuration.
    pub fn new(config: NostrConfig) -> Self {
        let webhook = WebhookConfig {
            name: "nostr".to_string(),
            outbound_url: config.relay_url,
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"content":"{text}"}"#.to_string(),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for NostrChannel {
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
    fn nostr_config_roundtrip() {
        let config = NostrConfig {
            relay_url: "wss://relay.damus.io".to_string(),
            private_key_hex: "abcdef0123456789".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: NostrConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn nostr_channel_name() {
        let channel = NostrChannel::new(NostrConfig {
            relay_url: "wss://relay.example.com".to_string(),
            private_key_hex: "0000".to_string(),
        });
        assert_eq!(channel.name(), "nostr");
    }
}
