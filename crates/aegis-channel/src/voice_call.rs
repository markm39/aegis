//! Voice call channel adapter (via telephony API bridge).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Configuration for the voice call channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoiceCallConfig {
    /// Telephony API endpoint URL (e.g., Twilio or Vonage).
    pub api_url: String,
    /// Caller phone number.
    pub from_number: String,
    /// Recipient phone number.
    pub to_number: String,
}

/// Voice call channel wrapping the generic webhook adapter.
///
/// Sends text-to-speech messages via a telephony API. This is a minimal
/// stub -- a real implementation would handle call lifecycle, DTMF input,
/// and speech-to-text for inbound.
pub struct VoiceCallChannel {
    inner: WebhookChannel,
}

impl VoiceCallChannel {
    /// Create a new voice call channel from configuration.
    pub fn new(config: VoiceCallConfig) -> Self {
        let webhook = WebhookConfig {
            name: "voice_call".to_string(),
            outbound_url: config.api_url,
            inbound_url: None,
            auth_header: None,
            payload_template: r#"{"to":"","from":"","text":"{text}"}"#.to_string(),
        };
        Self {
            inner: WebhookChannel::new(webhook),
        }
    }
}

#[async_trait]
impl Channel for VoiceCallChannel {
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
    fn voice_call_config_roundtrip() {
        let config = VoiceCallConfig {
            api_url: "https://api.twilio.com/2010-04-01/Accounts/AC123/Calls.json".to_string(),
            from_number: "+1234567890".to_string(),
            to_number: "+0987654321".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: VoiceCallConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn voice_call_channel_name() {
        let channel = VoiceCallChannel::new(VoiceCallConfig {
            api_url: "https://example.com".to_string(),
            from_number: "+1".to_string(),
            to_number: "+2".to_string(),
        });
        assert_eq!(channel.name(), "voice_call");
    }
}
