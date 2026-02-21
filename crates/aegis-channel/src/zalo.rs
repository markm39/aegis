//! Zalo Official Account channel adapter.
//!
//! Integrates with the Zalo OA API for messaging in Vietnam. Supports
//! outbound message sending and webhook signature verification.
//!
//! # Security
//!
//! - Access token is never logged.
//! - Webhook signatures are verified using HMAC-SHA256 with the secret key.
//! - All configuration fields are validated.

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::webhook::{WebhookChannel, WebhookConfig};

/// Zalo OA API base URL.
const ZALO_API_BASE: &str = "https://openapi.zalo.me/v3.0/oa/message/cs";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Zalo OA channel.
///
/// Connects to the Zalo Official Account API. The access_token and
/// secret_key fields are sensitive and must never be logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZaloConfig {
    /// Zalo Official Account ID.
    pub oa_id: String,
    /// Access token for the Zalo OA API.
    /// Sensitive: never log this value.
    pub access_token: String,
    /// Secret key for webhook HMAC-SHA256 signature verification.
    /// Sensitive: never log this value.
    pub secret_key: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate the Zalo configuration.
pub fn validate_config(config: &ZaloConfig) -> Result<(), ChannelError> {
    if config.oa_id.is_empty() {
        return Err(ChannelError::Api("Zalo oa_id cannot be empty".into()));
    }
    if config.access_token.is_empty() {
        return Err(ChannelError::Api(
            "Zalo access_token cannot be empty".into(),
        ));
    }
    if config.secret_key.is_empty() {
        return Err(ChannelError::Api(
            "Zalo secret_key cannot be empty".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

/// Verify a Zalo webhook callback signature using HMAC-SHA256.
///
/// The signature is computed as `HMAC-SHA256(secret_key, body)` and compared
/// in constant time to prevent timing attacks.
///
/// Returns `true` if the signature is valid.
pub fn verify_webhook_signature(secret_key: &str, body: &[u8], signature: &str) -> bool {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret_key.as_bytes()) else {
        warn!("failed to create HMAC instance for Zalo webhook verification");
        return false;
    };

    mac.update(body);
    let expected = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected);

    // Constant-time comparison to prevent timing attacks
    expected_hex.as_bytes().ct_eq(signature.as_bytes()).into()
}

// ---------------------------------------------------------------------------
// Channel implementation
// ---------------------------------------------------------------------------

/// Zalo OA channel wrapping the generic webhook adapter.
///
/// Sends outbound messages via the Zalo OA CS message API with Bearer token
/// authentication. Inbound messages are received via webhooks (stub).
pub struct ZaloChannel {
    inner: WebhookChannel,
    /// Config stored for webhook verification.
    #[allow(dead_code)]
    config: ZaloConfig,
}

impl ZaloChannel {
    /// Create a new Zalo channel from configuration.
    pub fn new(config: ZaloConfig) -> Result<Self, ChannelError> {
        validate_config(&config)?;

        let webhook = WebhookConfig {
            name: "zalo".to_string(),
            outbound_url: ZALO_API_BASE.to_string(),
            inbound_url: None,
            auth_header: Some(format!("Bearer {}", config.access_token)),
            payload_template: r#"{"recipient":{"user_id":""},"message":{"text":"{text}"}}"#
                .to_string(),
        };

        Ok(Self {
            inner: WebhookChannel::new(webhook),
            config,
        })
    }
}

#[async_trait]
impl Channel for ZaloChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        self.inner.send(message).await
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        // Inbound messages arrive via webhook callbacks (not polling).
        // Full webhook server implementation is out of scope for this stub.
        Ok(None)
    }

    fn name(&self) -> &str {
        "zalo"
    }

    async fn send_photo(&self, _photo: OutboundPhoto) -> Result<(), ChannelError> {
        warn!("photo messages not yet supported for Zalo channel");
        Err(ChannelError::Other(
            "photo messages not yet supported for Zalo channel".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ZaloConfig {
        ZaloConfig {
            oa_id: "12345".to_string(),
            access_token: "zalo_token_abc123".to_string(),
            secret_key: "webhook_secret_key".to_string(),
        }
    }

    // -- Config validation --

    #[test]
    fn test_zalo_config_validation() {
        assert!(validate_config(&test_config()).is_ok());

        // Empty oa_id
        let mut cfg = test_config();
        cfg.oa_id = String::new();
        assert!(validate_config(&cfg).is_err());

        // Empty access_token
        let mut cfg = test_config();
        cfg.access_token = String::new();
        assert!(validate_config(&cfg).is_err());

        // Empty secret_key
        let mut cfg = test_config();
        cfg.secret_key = String::new();
        assert!(validate_config(&cfg).is_err());
    }

    // -- Config serde roundtrip --

    #[test]
    fn test_zalo_config_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: ZaloConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    // -- Webhook signature verification --

    #[test]
    fn test_zalo_webhook_signature_valid() {
        let secret = "my_secret_key";
        let body = b"webhook body content";

        // Compute the expected signature
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let expected = hex::encode(mac.finalize().into_bytes());

        assert!(verify_webhook_signature(secret, body, &expected));
    }

    #[test]
    fn test_zalo_webhook_signature_invalid() {
        let secret = "my_secret_key";
        let body = b"webhook body content";

        // Wrong signature
        assert!(!verify_webhook_signature(secret, body, "deadbeef"));

        // Empty signature
        assert!(!verify_webhook_signature(secret, body, ""));

        // Wrong secret
        let mut mac = Hmac::<Sha256>::new_from_slice(b"wrong_secret").unwrap();
        mac.update(body);
        let wrong_sig = hex::encode(mac.finalize().into_bytes());
        assert!(!verify_webhook_signature(secret, body, &wrong_sig));
    }

    // -- Channel name --

    #[test]
    fn test_zalo_channel_name() {
        let channel = ZaloChannel::new(test_config()).unwrap();
        assert_eq!(channel.name(), "zalo");
    }
}
