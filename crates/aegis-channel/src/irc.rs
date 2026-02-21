//! IRC channel adapter (via IRC-to-HTTP bridge).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the IRC channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrcConfig {
    /// IRC server hostname (e.g., `"irc.libera.chat"`).
    pub server: String,
    /// IRC channel to join (e.g., `"#aegis"`).
    pub channel: String,
    /// Bot nickname.
    pub nick: String,
}

/// IRC channel wrapping the generic webhook adapter.
pub struct IrcChannel {
    inner: WebhookChannel,
}

impl IrcChannel {
    /// Create a new IRC channel from configuration.
    ///
    /// Uses an HTTP bridge endpoint for outbound messages. A proper IRC
    /// client implementation would connect via TCP/TLS directly.
    pub fn new(config: IrcConfig) -> Self {
        let webhook = WebhookConfig {
            name: "irc".to_string(),
            outbound_url: format!("http://{}/send", config.server),
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"target":"","text":"{text}"}"#.to_string(),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for IrcChannel {
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
    fn irc_config_roundtrip() {
        let config = IrcConfig {
            server: "irc.libera.chat".to_string(),
            channel: "#aegis".to_string(),
            nick: "aegis-bot".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: IrcConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn irc_channel_name() {
        let channel = IrcChannel::new(IrcConfig {
            server: "irc.libera.chat".to_string(),
            channel: "#test".to_string(),
            nick: "bot".to_string(),
        });
        assert_eq!(channel.name(), "irc");
    }
}
