//! Nextcloud Talk channel adapter (OCS API).
//!
//! Integrates with Nextcloud Talk (Spreed) using the OCS REST API for
//! enterprise messaging. Supports sending messages, polling for new
//! messages, and listing rooms.
//!
//! # Security
//!
//! - Server URL must be HTTPS (enforced at config validation).
//! - Private/reserved IP addresses are blocked to prevent SSRF.
//! - App password is never logged or serialized in debug output.
//! - Username and room token are validated for safe characters.
//! - All API responses are parsed from the OCS wrapper format.

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::format;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Nextcloud Talk channel.
///
/// Connects to a Nextcloud instance via its OCS API. The app_password
/// field is sensitive and must never appear in logs.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NextcloudConfig {
    /// Nextcloud server URL (must be HTTPS).
    pub server_url: String,
    /// Nextcloud username for authentication.
    /// Alphanumeric, dash, underscore, and dot; max 64 characters.
    pub username: String,
    /// Nextcloud app password for Basic auth.
    /// Sensitive: never log this value.
    pub app_password: String,
    /// Room token for the Talk conversation.
    /// Alphanumeric only, max 32 characters.
    pub room_token: String,
}

impl std::fmt::Debug for NextcloudConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NextcloudConfig")
            .field("server_url", &self.server_url)
            .field("username", &self.username)
            .field("app_password", &"[REDACTED]")
            .field("room_token", &self.room_token)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Maximum username length.
const MAX_USERNAME_LEN: usize = 64;

/// Maximum room token length.
const MAX_ROOM_TOKEN_LEN: usize = 32;

/// Validate that a server URL uses HTTPS and does not point to a private IP.
///
/// This is a critical SSRF prevention measure. All private, loopback,
/// link-local, and reserved IP ranges are blocked.
pub fn validate_server_url(url_str: &str) -> Result<Url, ChannelError> {
    let url = Url::parse(url_str)
        .map_err(|e| ChannelError::Api(format!("invalid Nextcloud server URL: {e}")))?;

    // Enforce HTTPS
    if url.scheme() != "https" {
        return Err(ChannelError::Api(format!(
            "Nextcloud server URL must use HTTPS, got scheme: {:?}",
            url.scheme()
        )));
    }

    // Extract host
    let host = url
        .host_str()
        .ok_or_else(|| ChannelError::Api("Nextcloud server URL has no host".into()))?;

    // Block private/reserved IPs (SSRF prevention)
    if is_private_host(host) {
        return Err(ChannelError::Api(format!(
            "Nextcloud server URL points to a private/reserved IP address: {host} -- \
             this is blocked to prevent SSRF attacks"
        )));
    }

    Ok(url)
}

/// Check if a hostname resolves to a private or reserved IP address.
///
/// Blocks:
/// - 127.0.0.0/8 (loopback)
/// - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
/// - 169.254.0.0/16 (link-local)
/// - ::1, fc00::/7, fe80::/10 (IPv6 private/link-local)
/// - 0.0.0.0
/// - localhost
fn is_private_host(host: &str) -> bool {
    let host_lower = host.to_ascii_lowercase();

    // Block localhost variants
    if host_lower == "localhost"
        || host_lower == "localhost.localdomain"
        || host_lower.ends_with(".localhost")
    {
        return true;
    }

    // Try to parse as IP address
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return is_private_ip(ip);
    }

    // For hostnames, check if they look like IP addresses with brackets (IPv6)
    let trimmed = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return is_private_ip(ip);
    }

    false
}

/// Check if an IP address is private, loopback, or reserved.
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()           // 127.0.0.0/8
                || v4.is_private()     // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()  // 169.254/16
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast()   // 255.255.255.255
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGNAT)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()       // ::1
                || v6.is_unspecified() // ::
                || {
                    let segments = v6.segments();
                    // fc00::/7 (unique local)
                    (segments[0] & 0xfe00) == 0xfc00
                    // fe80::/10 (link-local)
                    || (segments[0] & 0xffc0) == 0xfe80
                }
        }
    }
}

/// Validate a Nextcloud username.
///
/// Alphanumeric, dash, underscore, and dot; max 64 characters.
pub fn validate_username(username: &str) -> Result<(), ChannelError> {
    if username.is_empty() {
        return Err(ChannelError::Api(
            "Nextcloud username cannot be empty".into(),
        ));
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(ChannelError::Api(format!(
            "Nextcloud username exceeds {MAX_USERNAME_LEN} characters: got {}",
            username.len()
        )));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ChannelError::Api(format!(
            "Nextcloud username contains invalid characters: {username:?}"
        )));
    }
    Ok(())
}

/// Validate a Nextcloud Talk room token.
///
/// Alphanumeric only, max 32 characters.
pub fn validate_room_token(token: &str) -> Result<(), ChannelError> {
    if token.is_empty() {
        return Err(ChannelError::Api(
            "Nextcloud room token cannot be empty".into(),
        ));
    }
    if token.len() > MAX_ROOM_TOKEN_LEN {
        return Err(ChannelError::Api(format!(
            "Nextcloud room token exceeds {MAX_ROOM_TOKEN_LEN} characters: got {}",
            token.len()
        )));
    }
    if !token.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ChannelError::Api(format!(
            "Nextcloud room token contains non-alphanumeric characters: {token:?}"
        )));
    }
    Ok(())
}

/// Validate the entire Nextcloud configuration.
pub fn validate_config(config: &NextcloudConfig) -> Result<(), ChannelError> {
    validate_server_url(&config.server_url)?;
    validate_username(&config.username)?;
    validate_room_token(&config.room_token)?;
    // App password is validated only for non-emptiness (format varies).
    if config.app_password.is_empty() {
        return Err(ChannelError::Api(
            "Nextcloud app_password cannot be empty".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OCS API response parsing
// ---------------------------------------------------------------------------

/// OCS API wrapper response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsResponse<T> {
    pub ocs: OcsEnvelope<T>,
}

/// OCS envelope containing metadata and data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsEnvelope<T> {
    pub meta: OcsMeta,
    pub data: T,
}

/// OCS response metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsMeta {
    pub status: String,
    #[serde(default)]
    pub statuscode: u32,
    #[serde(default)]
    pub message: Option<String>,
}

/// A chat message from the Nextcloud Talk API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: u64,
    #[serde(default)]
    pub message: String,
    #[serde(rename = "actorId", default)]
    pub actor_id: String,
    #[serde(rename = "actorDisplayName", default)]
    pub actor_display_name: String,
    #[serde(default)]
    pub timestamp: u64,
}

/// Parse an OCS-wrapped chat message list response.
pub fn parse_ocs_messages(json: &str) -> Result<Vec<ChatMessage>, ChannelError> {
    let response: OcsResponse<Vec<ChatMessage>> = serde_json::from_str(json)
        .map_err(|e| ChannelError::Api(format!("failed to parse OCS response: {e}")))?;

    if response.ocs.meta.statuscode != 200 {
        return Err(ChannelError::Api(format!(
            "OCS API error: status={}, message={:?}",
            response.ocs.meta.statuscode, response.ocs.meta.message
        )));
    }

    Ok(response.ocs.data)
}

// ---------------------------------------------------------------------------
// Nextcloud API client
// ---------------------------------------------------------------------------

/// Nextcloud Talk REST API client.
///
/// Handles authenticated requests to the Nextcloud OCS API.
/// The app_password is stored in memory but never logged.
pub struct NextcloudApi {
    client: Client,
    config: NextcloudConfig,
    base_url: String,
}

impl NextcloudApi {
    /// Create a new Nextcloud API client from configuration.
    ///
    /// Validates the configuration before returning.
    pub fn new(config: NextcloudConfig) -> Result<Self, ChannelError> {
        validate_config(&config)?;
        let base_url = config.server_url.trim_end_matches('/').to_string();
        Ok(Self {
            client: Client::new(),
            config,
            base_url,
        })
    }

    /// Build the URL for sending/receiving chat messages.
    ///
    /// `POST /ocs/v2.php/apps/spreed/api/v1/chat/{token}`
    pub fn chat_url(&self, room_token: &str) -> String {
        format!(
            "{}/ocs/v2.php/apps/spreed/api/v1/chat/{}",
            self.base_url, room_token
        )
    }

    /// Build the URL for listing rooms.
    ///
    /// `GET /ocs/v2.php/apps/spreed/api/v1/room`
    pub fn rooms_url(&self) -> String {
        format!("{}/ocs/v2.php/apps/spreed/api/v1/room", self.base_url)
    }

    /// Build the Basic auth header value.
    fn basic_auth(&self) -> String {
        use base64::Engine;
        let credentials = format!("{}:{}", self.config.username, self.config.app_password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        format!("Basic {encoded}")
    }

    /// Send a message to a room.
    pub async fn send_message(&self, room_token: &str, message: &str) -> Result<(), ChannelError> {
        validate_room_token(room_token)?;

        let url = self.chat_url(room_token);
        let body = serde_json::json!({
            "message": message,
        });

        let response = self
            .client
            .post(&url)
            .header("Authorization", self.basic_auth())
            .header("OCS-APIRequest", "true")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "Nextcloud send_message failed ({status}): {text}"
            )));
        }

        Ok(())
    }

    /// Get messages from a room, optionally after a known message ID.
    ///
    /// Uses `lookIntoFuture=1` to poll for new messages.
    pub async fn get_messages(
        &self,
        room_token: &str,
        last_known_id: Option<u64>,
    ) -> Result<Vec<ChatMessage>, ChannelError> {
        validate_room_token(room_token)?;

        let mut url = format!("{}?lookIntoFuture=1&limit=100", self.chat_url(room_token));
        if let Some(id) = last_known_id {
            url = format!("{url}&lastKnownMessageId={id}");
        }

        let response = self
            .client
            .get(&url)
            .header("Authorization", self.basic_auth())
            .header("OCS-APIRequest", "true")
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "Nextcloud get_messages failed ({status}): {text}"
            )));
        }

        let text = response.text().await?;
        parse_ocs_messages(&text)
    }

    /// Get the list of rooms the bot is a participant in.
    pub async fn get_rooms(&self) -> Result<serde_json::Value, ChannelError> {
        let url = self.rooms_url();

        let response = self
            .client
            .get(&url)
            .header("Authorization", self.basic_auth())
            .header("OCS-APIRequest", "true")
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "Nextcloud get_rooms failed ({status}): {text}"
            )));
        }

        response
            .json()
            .await
            .map_err(|e| ChannelError::Api(format!("failed to parse rooms response: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Channel trait implementation
// ---------------------------------------------------------------------------

/// Nextcloud Talk channel implementing bidirectional messaging via OCS API.
pub struct NextcloudChannel {
    api: NextcloudApi,
    /// Last known message ID for polling.
    last_known_id: Option<u64>,
}

impl NextcloudChannel {
    /// Create a new Nextcloud Talk channel from configuration.
    pub fn new(config: NextcloudConfig) -> Result<Self, ChannelError> {
        let api = NextcloudApi::new(config)?;
        Ok(Self {
            api,
            last_known_id: None,
        })
    }
}

#[async_trait]
impl Channel for NextcloudChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        self.api
            .send_message(&self.api.config.room_token, &message.text)
            .await
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        let messages = self
            .api
            .get_messages(&self.api.config.room_token, self.last_known_id)
            .await?;

        for msg in &messages {
            self.last_known_id = Some(msg.id);

            // Skip messages from our own user
            if msg.actor_id == self.api.config.username {
                continue;
            }

            if !msg.message.is_empty() {
                return Ok(Some(format::parse_text_command(&msg.message)));
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "nextcloud-talk"
    }

    async fn send_photo(&self, _photo: OutboundPhoto) -> Result<(), ChannelError> {
        warn!("photo messages not yet supported for Nextcloud Talk channel");
        Err(ChannelError::Other(
            "photo messages not yet supported for Nextcloud Talk channel".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> NextcloudConfig {
        NextcloudConfig {
            server_url: "https://cloud.example.com".to_string(),
            username: "aegis-bot".to_string(),
            app_password: "abcdef123456".to_string(),
            room_token: "abc123room".to_string(),
        }
    }

    // -- Config validation --

    #[test]
    fn test_nextcloud_config_validation() {
        assert!(validate_config(&test_config()).is_ok());
    }

    #[test]
    fn test_nextcloud_server_url_https_required() {
        let mut cfg = test_config();
        cfg.server_url = "http://cloud.example.com".to_string();
        assert!(validate_config(&cfg).is_err());

        // HTTPS is valid
        cfg.server_url = "https://cloud.example.com".to_string();
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn test_nextcloud_ssrf_prevention() {
        // Loopback
        assert!(validate_server_url("https://127.0.0.1").is_err());
        assert!(validate_server_url("https://127.0.0.1:8080").is_err());

        // Private ranges (RFC 1918)
        assert!(validate_server_url("https://10.0.0.1").is_err());
        assert!(validate_server_url("https://172.16.0.1").is_err());
        assert!(validate_server_url("https://172.31.255.255").is_err());
        assert!(validate_server_url("https://192.168.1.1").is_err());

        // Link-local
        assert!(validate_server_url("https://169.254.0.1").is_err());

        // Localhost hostname
        assert!(validate_server_url("https://localhost").is_err());
        assert!(validate_server_url("https://localhost:8443").is_err());
        assert!(validate_server_url("https://sub.localhost").is_err());

        // Unspecified
        assert!(validate_server_url("https://0.0.0.0").is_err());

        // IPv6 loopback
        assert!(validate_server_url("https://[::1]").is_err());

        // Public IP should pass
        assert!(validate_server_url("https://203.0.113.1").is_ok());

        // Real hostnames should pass
        assert!(validate_server_url("https://cloud.example.com").is_ok());
        assert!(validate_server_url("https://nextcloud.mycompany.com").is_ok());
    }

    #[test]
    fn test_nextcloud_username_validation() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("aegis-bot").is_ok());
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("user.name").is_ok());
        assert!(validate_username(&"a".repeat(64)).is_ok());

        // Too long
        assert!(validate_username(&"a".repeat(65)).is_err());

        // Empty
        assert!(validate_username("").is_err());

        // Invalid chars
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user/name").is_err());
    }

    #[test]
    fn test_nextcloud_room_token_validation() {
        assert!(validate_room_token("abc123").is_ok());
        assert!(validate_room_token(&"a".repeat(32)).is_ok());

        // Too long
        assert!(validate_room_token(&"a".repeat(33)).is_err());

        // Empty
        assert!(validate_room_token("").is_err());

        // Non-alphanumeric
        assert!(validate_room_token("room-token").is_err());
        assert!(validate_room_token("room_token").is_err());
        assert!(validate_room_token("room token").is_err());
    }

    // -- Config serde roundtrip --

    #[test]
    fn test_nextcloud_config_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: NextcloudConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    // -- API URL construction --

    #[test]
    fn test_nextcloud_talk_api_call() {
        let api = NextcloudApi::new(test_config()).unwrap();

        // Chat endpoint
        let chat_url = api.chat_url("abc123room");
        assert_eq!(
            chat_url,
            "https://cloud.example.com/ocs/v2.php/apps/spreed/api/v1/chat/abc123room"
        );

        // Rooms endpoint
        let rooms_url = api.rooms_url();
        assert_eq!(
            rooms_url,
            "https://cloud.example.com/ocs/v2.php/apps/spreed/api/v1/room"
        );

        // Basic auth header
        let auth = api.basic_auth();
        assert!(auth.starts_with("Basic "));
        // Decode and verify
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(auth.strip_prefix("Basic ").unwrap())
            .unwrap();
        let creds = String::from_utf8(decoded).unwrap();
        assert_eq!(creds, "aegis-bot:abcdef123456");
    }

    #[test]
    fn test_nextcloud_talk_api_trailing_slash() {
        let mut cfg = test_config();
        cfg.server_url = "https://cloud.example.com/".to_string();
        let api = NextcloudApi::new(cfg).unwrap();

        let chat_url = api.chat_url("abc123room");
        assert_eq!(
            chat_url,
            "https://cloud.example.com/ocs/v2.php/apps/spreed/api/v1/chat/abc123room"
        );
    }

    // -- OCS response parsing --

    #[test]
    fn test_nextcloud_ocs_response_parsing() {
        let json = r#"{
            "ocs": {
                "meta": {
                    "status": "ok",
                    "statuscode": 200,
                    "message": "OK"
                },
                "data": [
                    {
                        "id": 42,
                        "message": "/status",
                        "actorId": "admin",
                        "actorDisplayName": "Admin User",
                        "timestamp": 1700000000
                    },
                    {
                        "id": 43,
                        "message": "hello world",
                        "actorId": "user2",
                        "actorDisplayName": "User Two",
                        "timestamp": 1700000001
                    }
                ]
            }
        }"#;

        let messages = parse_ocs_messages(json).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].id, 42);
        assert_eq!(messages[0].message, "/status");
        assert_eq!(messages[0].actor_id, "admin");
        assert_eq!(messages[1].id, 43);
        assert_eq!(messages[1].message, "hello world");
    }

    #[test]
    fn test_nextcloud_ocs_error_response() {
        let json = r#"{
            "ocs": {
                "meta": {
                    "status": "failure",
                    "statuscode": 403,
                    "message": "Not allowed"
                },
                "data": []
            }
        }"#;

        let result = parse_ocs_messages(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_nextcloud_ocs_invalid_json() {
        assert!(parse_ocs_messages("not json").is_err());
        assert!(parse_ocs_messages("{}").is_err());
    }

    // -- Channel name --

    #[test]
    fn test_nextcloud_channel_name() {
        let channel = NextcloudChannel::new(test_config()).unwrap();
        assert_eq!(channel.name(), "nextcloud-talk");
    }

    // -- Empty app password rejected --

    #[test]
    fn test_nextcloud_empty_app_password_rejected() {
        let mut cfg = test_config();
        cfg.app_password = String::new();
        assert!(validate_config(&cfg).is_err());
    }
}
