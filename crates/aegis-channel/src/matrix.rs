//! Matrix channel adapter (via Client-Server API).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the Matrix channel.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatrixConfig {
    /// Matrix homeserver URL (e.g., `"https://matrix.org"`).
    pub homeserver_url: String,
    /// Access token for the Matrix bot account.
    pub access_token: String,
    /// Room ID to send messages to (e.g., `"!abc:matrix.org"`).
    pub room_id: String,
}

impl std::fmt::Debug for MatrixConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixConfig")
            .field("homeserver_url", &self.homeserver_url)
            .field("access_token", &"[REDACTED]")
            .field("room_id", &self.room_id)
            .finish()
    }
}

/// Matrix channel wrapping the generic webhook adapter.
pub struct MatrixChannel {
    inner: WebhookChannel,
}

impl MatrixChannel {
    /// Create a new Matrix channel from configuration.
    pub fn new(config: MatrixConfig) -> Self {
        // Matrix Client-Server API: PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}
        // For simplicity we use a POST-style endpoint; real impl would use PUT with txn IDs.
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message",
            config.homeserver_url.trim_end_matches('/'),
            config.room_id
        );
        let webhook = WebhookConfig {
            name: "matrix".to_string(),
            outbound_url: url,
            inbound_url: None,
            auth_header: Some(format!("Bearer {}", config.access_token)),
            payload_template: r#"{"msgtype":"m.text","body":"{text}"}"#.to_string(),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for MatrixChannel {
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
    fn matrix_config_roundtrip() {
        let config = MatrixConfig {
            homeserver_url: "https://matrix.org".to_string(),
            access_token: "syt_abc123".to_string(),
            room_id: "!room:matrix.org".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: MatrixConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn matrix_channel_name() {
        let channel = MatrixChannel::new(MatrixConfig {
            homeserver_url: "https://matrix.org".to_string(),
            access_token: "token".to_string(),
            room_id: "!room:matrix.org".to_string(),
        });
        assert_eq!(channel.name(), "matrix");
    }
}
