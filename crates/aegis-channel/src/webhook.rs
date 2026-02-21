//! Generic webhook-based channel adapter.
//!
//! Provides a reusable [`Channel`] implementation for services that support
//! outbound HTTP POST webhooks. Concrete channel types (Discord, MS Teams,
//! etc.) wrap this adapter with service-specific configuration.

use async_trait::async_trait;
use reqwest::Client;
use tracing::warn;

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};

/// Configuration for a generic webhook channel.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WebhookConfig {
    /// Human-readable channel name.
    pub name: String,
    /// URL to POST outbound messages to.
    pub outbound_url: String,
    /// Optional URL to poll for inbound messages.
    #[serde(default)]
    pub inbound_url: Option<String>,
    /// Optional auth header value (e.g., `"Bot TOKEN"` or `"Bearer TOKEN"`).
    #[serde(default)]
    pub auth_header: Option<String>,
    /// JSON payload template. Use `{text}` as placeholder for message text.
    #[serde(default = "default_payload_template")]
    pub payload_template: String,
}

fn default_payload_template() -> String {
    r#"{"text":"{text}"}"#.to_string()
}

/// Generic webhook channel that implements the [`Channel`] trait.
///
/// Sends outbound messages by POSTing JSON to a configured URL, replacing
/// `{text}` in the payload template with the actual message content.
pub struct WebhookChannel {
    config: WebhookConfig,
    client: Client,
}

impl WebhookChannel {
    /// Create a new webhook channel with the given configuration.
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    /// Replace `{text}` placeholder in the payload template, escaping for JSON.
    fn build_payload(&self, text: &str) -> String {
        // Escape text for JSON string embedding: backslash, quotes, newlines, etc.
        let escaped = text
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        self.config.payload_template.replace("{text}", &escaped)
    }
}

#[async_trait]
impl Channel for WebhookChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        let payload = self.build_payload(&message.text);

        let mut request = self
            .client
            .post(&self.config.outbound_url)
            .header("Content-Type", "application/json")
            .body(payload);

        if let Some(ref auth) = self.config.auth_header {
            request = request.header("Authorization", auth);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(ChannelError::Api(format!(
                "webhook returned {status}: {body}"
            )));
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        // Inbound polling is not implemented for the generic webhook adapter.
        // Concrete channel types can override this if they support inbound messages.
        Ok(None)
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send_photo(&self, _photo: OutboundPhoto) -> Result<(), ChannelError> {
        warn!(
            channel = self.config.name,
            "photo messages not supported for webhook channels"
        );
        Err(ChannelError::Other(
            "photo messages not supported for webhook channels".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_config_roundtrip() {
        let config = WebhookConfig {
            name: "test-hook".to_string(),
            outbound_url: "https://example.com/webhook".to_string(),
            inbound_url: Some("https://example.com/poll".to_string()),
            auth_header: Some("Bearer abc123".to_string()),
            payload_template: r#"{"msg":"{text}"}"#.to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: WebhookConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn default_payload_template_has_text_placeholder() {
        let tpl = default_payload_template();
        assert!(tpl.contains("{text}"));
    }

    #[test]
    fn build_payload_escapes_quotes() {
        let config = WebhookConfig {
            name: "test".to_string(),
            outbound_url: "https://example.com".to_string(),
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"text":"{text}"}"#.to_string(),
        };
        let channel = WebhookChannel::new(config);
        let payload = channel.build_payload(r#"hello "world""#);
        assert_eq!(payload, r#"{"text":"hello \"world\""}"#);
    }

    #[test]
    fn build_payload_escapes_newlines() {
        let config = WebhookConfig {
            name: "test".to_string(),
            outbound_url: "https://example.com".to_string(),
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"text":"{text}"}"#.to_string(),
        };
        let channel = WebhookChannel::new(config);
        let payload = channel.build_payload("line1\nline2");
        assert_eq!(payload, r#"{"text":"line1\nline2"}"#);
    }

    #[test]
    fn build_payload_escapes_backslashes() {
        let config = WebhookConfig {
            name: "test".to_string(),
            outbound_url: "https://example.com".to_string(),
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"text":"{text}"}"#.to_string(),
        };
        let channel = WebhookChannel::new(config);
        let payload = channel.build_payload(r"path\to\file");
        assert_eq!(payload, r#"{"text":"path\\to\\file"}"#);
    }

    #[test]
    fn channel_name_returns_config_name() {
        let config = WebhookConfig {
            name: "my-webhook".to_string(),
            outbound_url: "https://example.com".to_string(),
            inbound_url: None,
            auth_header: None,
            payload_template: default_payload_template(),
        };
        let channel = WebhookChannel::new(config);
        assert_eq!(channel.name(), "my-webhook");
    }
}
