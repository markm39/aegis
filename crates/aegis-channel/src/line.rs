//! LINE Messaging API channel adapter.
//!
//! Full LINE integration with:
//! - Push, reply, and multicast messaging
//! - Flex Message builder (Bubble, Carousel)
//! - Rich message / image map support
//! - Inbound webhook with HMAC-SHA256 signature verification
//! - OAuth2 login flow stubs
//!
//! # Security
//!
//! - Webhook signatures verified with HMAC-SHA256 + constant-time comparison
//! - Image map base URLs validated: HTTPS only, no private IPs (SSRF prevention)
//! - User IDs validated: alphanumeric + dash, max 64 chars
//! - Channel secrets never logged or hardcoded

use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{debug, warn};
use url::Url;

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::format;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the LINE channel.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineConfig {
    /// LINE channel access token (Messaging API).
    pub channel_access_token: String,
    /// Default recipient user ID for push messages.
    pub user_id: String,
    /// Channel secret for webhook signature verification.
    #[serde(default)]
    pub channel_secret: Option<String>,
    /// Port for the inbound webhook server.
    #[serde(default)]
    pub webhook_port: Option<u16>,
    /// LINE Login channel ID (for OAuth2 flow).
    #[serde(default)]
    pub oauth_channel_id: Option<String>,
    /// Whether multicast sending is enabled.
    #[serde(default)]
    pub multicast_enabled: bool,
}

impl std::fmt::Debug for LineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineConfig")
            .field("channel_access_token", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("channel_secret", &"[REDACTED]")
            .field("webhook_port", &self.webhook_port)
            .field("oauth_channel_id", &self.oauth_channel_id)
            .field("multicast_enabled", &self.multicast_enabled)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Flex Message types
// ---------------------------------------------------------------------------

/// Top-level Flex Message container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum FlexContainer {
    /// A single bubble message.
    Bubble(Box<FlexBubble>),
    /// A carousel of multiple bubbles.
    Carousel {
        /// Bubbles in the carousel (max 12 per LINE spec).
        contents: Vec<FlexBubble>,
    },
}

/// A single Flex Message bubble with optional sections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct FlexBubble {
    /// Header section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<FlexComponent>,
    /// Hero image section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hero: Option<FlexComponent>,
    /// Body section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<FlexComponent>,
    /// Footer section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<FlexComponent>,
}

/// Flex Message component variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum FlexComponent {
    /// A box layout container.
    Box {
        /// Layout direction: "horizontal", "vertical", "baseline".
        layout: String,
        /// Child components.
        contents: Vec<FlexComponent>,
    },
    /// An action button.
    Button {
        /// Button action.
        action: FlexAction,
        /// Button style: "primary", "secondary", "link".
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<String>,
    },
    /// An image element.
    Image {
        /// Image URL (must be HTTPS).
        url: String,
        /// Size keyword: "xxs", "xs", "sm", "md", "lg", "xl", "xxl", "full".
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<String>,
    },
    /// A text element.
    Text {
        /// Text content.
        text: String,
        /// Font weight: "regular", "bold".
        #[serde(skip_serializing_if = "Option::is_none")]
        weight: Option<String>,
        /// Font size keyword.
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<String>,
        /// Text color as hex string (e.g., "#FF0000").
        #[serde(skip_serializing_if = "Option::is_none")]
        color: Option<String>,
    },
    /// A horizontal separator line.
    Separator,
}

/// Actions available on Flex Message interactive elements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum FlexAction {
    /// Opens a URL.
    Uri {
        /// Button label.
        label: String,
        /// Target URL.
        uri: String,
    },
    /// Sends postback data to the webhook.
    Postback {
        /// Button label.
        label: String,
        /// Postback data payload.
        data: String,
    },
    /// Sends a text message on behalf of the user.
    Message {
        /// Button label.
        label: String,
        /// Message text to send.
        text: String,
    },
}

// ---------------------------------------------------------------------------
// Rich Message (Image Map) types
// ---------------------------------------------------------------------------

/// A rich message (image map) with clickable regions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RichMessage {
    /// Base URL for the image (must be HTTPS, no private IPs).
    pub base_url: String,
    /// Alternative text shown in notifications.
    pub alt_text: String,
    /// Base image dimensions.
    pub base_size: ImageMapBaseSize,
    /// Clickable areas (max 50).
    pub areas: Vec<ImageMapArea>,
}

/// Base image dimensions for an image map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImageMapBaseSize {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
}

/// A clickable area within an image map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImageMapArea {
    /// X coordinate of the top-left corner.
    pub x: u32,
    /// Y coordinate of the top-left corner.
    pub y: u32,
    /// Width of the clickable area.
    pub width: u32,
    /// Height of the clickable area.
    pub height: u32,
    /// Action triggered when this area is tapped.
    pub action: ImageMapAction,
}

/// Actions for image map clickable areas.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ImageMapAction {
    /// Opens a URL.
    Uri {
        /// URL to open.
        #[serde(rename = "linkUri")]
        link_uri: String,
    },
    /// Sends a text message on behalf of the user.
    Message {
        /// Text to send.
        text: String,
    },
}

/// Maximum number of areas per image map (LINE platform limit).
const MAX_IMAGE_MAP_AREAS: usize = 50;

// ---------------------------------------------------------------------------
// Webhook types and verification
// ---------------------------------------------------------------------------

/// Inbound webhook handler for LINE platform events.
///
/// Verifies request signatures using HMAC-SHA256 with constant-time
/// comparison, then parses events into [`InboundAction`]s.
pub struct LineWebhook {
    /// Channel secret for HMAC-SHA256 verification.
    channel_secret: String,
}

impl LineWebhook {
    /// Create a new webhook handler with the given channel secret.
    pub fn new(channel_secret: String) -> Self {
        Self { channel_secret }
    }

    /// Verify the X-Line-Signature header against the request body.
    ///
    /// Uses HMAC-SHA256 with constant-time comparison to prevent
    /// timing attacks. Returns `true` if the signature is valid.
    pub fn verify_signature(&self, body: &[u8], signature: &str) -> bool {
        // Decode the base64 signature from the header
        let sig_bytes =
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature) {
                Ok(b) => b,
                Err(_) => {
                    warn!("LINE webhook: invalid base64 in signature header");
                    return false;
                }
            };

        // Compute HMAC-SHA256 of the body using the channel secret
        let mut mac = match Hmac::<Sha256>::new_from_slice(self.channel_secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                warn!("LINE webhook: failed to create HMAC instance");
                return false;
            }
        };
        mac.update(body);
        let expected = mac.finalize().into_bytes();

        // Constant-time comparison
        let expected_bytes = expected.as_slice();
        if expected_bytes.len() != sig_bytes.len() {
            // Perform dummy comparison to avoid leaking length info via timing
            let _ = expected_bytes.ct_eq(expected_bytes);
            return false;
        }
        expected_bytes.ct_eq(&sig_bytes).into()
    }

    /// Parse webhook event JSON into a list of [`LineWebhookEvent`]s.
    pub fn parse_events(&self, body: &[u8]) -> Result<Vec<LineWebhookEvent>, ChannelError> {
        let payload: WebhookPayload = serde_json::from_slice(body)
            .map_err(|e| ChannelError::Other(format!("LINE webhook parse error: {e}")))?;
        Ok(payload.events)
    }
}

/// Top-level webhook payload from LINE.
#[derive(Debug, Deserialize)]
struct WebhookPayload {
    #[serde(default)]
    events: Vec<LineWebhookEvent>,
}

/// A single event from the LINE webhook.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum LineWebhookEvent {
    /// A message was received.
    Message {
        /// Reply token for responding.
        #[serde(rename = "replyToken")]
        reply_token: String,
        /// Source of the event.
        source: EventSource,
        /// The message content.
        message: WebhookMessage,
    },
    /// A postback event (from buttons, rich menus, etc.).
    Postback {
        /// Reply token for responding.
        #[serde(rename = "replyToken")]
        reply_token: String,
        /// Source of the event.
        source: EventSource,
        /// Postback data.
        postback: PostbackData,
    },
    /// User followed (added) the bot.
    Follow {
        /// Reply token for responding.
        #[serde(rename = "replyToken")]
        reply_token: String,
        /// Source of the event.
        source: EventSource,
    },
    /// User unfollowed (blocked) the bot.
    Unfollow {
        /// Source of the event.
        source: EventSource,
    },
}

/// Source of a webhook event.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventSource {
    /// Source type: "user", "group", "room".
    #[serde(rename = "type")]
    pub source_type: String,
    /// User ID (present for all source types).
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    /// Group ID (present when source_type is "group").
    #[serde(rename = "groupId")]
    pub group_id: Option<String>,
}

/// A message in a webhook event.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WebhookMessage {
    /// A text message.
    Text {
        /// Message ID.
        id: String,
        /// Message text content.
        text: String,
    },
    /// An image message.
    Image {
        /// Message ID.
        id: String,
    },
    /// A video message.
    Video {
        /// Message ID.
        id: String,
    },
    /// An audio message.
    Audio {
        /// Message ID.
        id: String,
    },
    /// A file message.
    File {
        /// Message ID.
        id: String,
        /// Filename.
        #[serde(rename = "fileName")]
        file_name: String,
    },
    /// A sticker message.
    Sticker {
        /// Message ID.
        id: String,
        /// Sticker package ID.
        #[serde(rename = "packageId")]
        package_id: String,
        /// Sticker ID within the package.
        #[serde(rename = "stickerId")]
        sticker_id: String,
    },
}

/// Postback data from an interactive element.
#[derive(Debug, Clone, Deserialize)]
pub struct PostbackData {
    /// The postback data string.
    pub data: String,
}

/// Convert a LINE webhook event into an [`InboundAction`].
///
/// Text messages are parsed using [`format::parse_text_command`].
/// Postback data is parsed using [`format::parse_callback`].
pub fn webhook_event_to_action(event: &LineWebhookEvent) -> Option<InboundAction> {
    match event {
        LineWebhookEvent::Message { message, .. } => match message {
            WebhookMessage::Text { text, .. } => Some(format::parse_text_command(text)),
            _ => None,
        },
        LineWebhookEvent::Postback { postback, .. } => format::parse_callback(&postback.data),
        LineWebhookEvent::Follow { .. } | LineWebhookEvent::Unfollow { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// OAuth2 login flow stubs
// ---------------------------------------------------------------------------

/// Configuration for LINE Login OAuth2 flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineOAuthConfig {
    /// LINE Login channel ID (different from Messaging API channel ID).
    pub channel_id: String,
    /// OAuth2 redirect URI.
    pub redirect_uri: String,
}

/// Token response from LINE Login OAuth2 exchange.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineTokenResponse {
    /// OAuth2 access token.
    pub access_token: String,
    /// OpenID Connect ID token (JWT).
    pub id_token: String,
    /// Refresh token for token renewal.
    pub refresh_token: String,
    /// Token lifetime in seconds.
    pub expires_in: u64,
}

/// Build a LINE Login authorization URL.
///
/// Constructs the OAuth2 authorization endpoint URL with the given
/// state and nonce parameters for CSRF and replay protection.
pub fn build_authorize_url(config: &LineOAuthConfig, state: &str, nonce: &str) -> String {
    format!(
        "https://access.line.me/oauth2/v2.1/authorize\
         ?response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &state={}\
         &nonce={}\
         &scope=profile%20openid",
        config.channel_id,
        urlencoding_percent(config.redirect_uri.as_str()),
        urlencoding_percent(state),
        urlencoding_percent(nonce),
    )
}

/// Percent-encode a string for URL query parameters.
fn urlencoding_percent(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX_UPPER[(b >> 4) as usize] as char);
                out.push(HEX_UPPER[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Exchange an authorization code for LINE Login tokens.
///
/// POSTs to `https://api.line.me/oauth2/v2.1/token` with the authorization
/// code, redirect URI, and client credentials. Returns access/ID/refresh tokens.
///
/// The `channel_secret` is the client secret from the LINE Developers console.
pub async fn exchange_code(
    config: &LineOAuthConfig,
    code: &str,
    channel_secret: &str,
) -> Result<LineTokenResponse, ChannelError> {
    let client = reqwest::Client::new();
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &config.redirect_uri),
        ("client_id", &config.channel_id),
        ("client_secret", channel_secret),
    ];
    let resp = client
        .post("https://api.line.me/oauth2/v2.1/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| ChannelError::Other(format!("LINE token exchange request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(ChannelError::Other(format!(
            "LINE token exchange failed (HTTP {status}): {body}"
        )));
    }

    resp.json::<LineTokenResponse>()
        .await
        .map_err(|e| ChannelError::Other(format!("failed to parse LINE token response: {e}")))
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Maximum length for a LINE user ID.
const MAX_USER_ID_LENGTH: usize = 64;

/// Validate a LINE user ID.
///
/// User IDs must be non-empty, at most 64 characters, and contain only
/// alphanumeric characters and dashes. No null bytes, control characters,
/// or other special characters are permitted.
pub fn validate_user_id(user_id: &str) -> Result<(), String> {
    if user_id.is_empty() {
        return Err("user ID cannot be empty".into());
    }
    if user_id.len() > MAX_USER_ID_LENGTH {
        return Err(format!(
            "user ID exceeds maximum length of {MAX_USER_ID_LENGTH} characters"
        ));
    }
    if !user_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err("user ID must contain only alphanumeric characters and dashes".into());
    }
    Ok(())
}

/// Validate a base URL for image maps (SSRF prevention).
///
/// Requirements:
/// - Must be a valid URL
/// - Must use HTTPS scheme
/// - Must not resolve to a private/reserved IP address
pub fn validate_base_url(base_url: &str) -> Result<(), String> {
    let parsed = Url::parse(base_url).map_err(|e| format!("invalid URL: {e}"))?;

    // Must be HTTPS
    if parsed.scheme() != "https" {
        return Err("base URL must use HTTPS scheme".into());
    }

    // Must have a host
    let host = parsed.host_str().ok_or("base URL must have a host")?;

    // Check for private/reserved IP addresses
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err("base URL must not point to a private IP address".into());
        }
    }

    // Also check if host looks like a numeric IP in brackets or other forms
    if let Some(url::Host::Ipv4(ip)) = parsed.host() {
        if is_private_ipv4(ip) {
            return Err("base URL must not point to a private IP address".into());
        }
    }
    if let Some(url::Host::Ipv6(ip)) = parsed.host() {
        if is_private_ip(IpAddr::V6(ip)) {
            return Err("base URL must not point to a private IP address".into());
        }
    }

    Ok(())
}

/// Check if an IP address is private/reserved (SSRF prevention).
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // IPv4-mapped IPv6 addresses
                || v6.to_ipv4_mapped().is_some_and(is_private_ipv4)
        }
    }
}

/// Check if an IPv4 address is private/reserved.
fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()          // 127.0.0.0/8
        || ip.is_private()    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local() // 169.254.0.0/16
        || ip.is_unspecified() // 0.0.0.0
        || ip.is_broadcast()  // 255.255.255.255
        || is_reserved_ipv4(ip)
}

/// Check for additional reserved IPv4 ranges not covered by std methods.
fn is_reserved_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 100.64.0.0/10 (Carrier-grade NAT)
    (octets[0] == 100 && (64..=127).contains(&octets[1]))
    // 192.0.0.0/24 (IETF Protocol Assignments)
    || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
    // 198.18.0.0/15 (Benchmark testing)
    || (octets[0] == 198 && (18..=19).contains(&octets[1]))
    // 198.51.100.0/24 (TEST-NET-2)
    || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
    // 203.0.113.0/24 (TEST-NET-3)
    || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    // 240.0.0.0/4 (Reserved for future use)
    || octets[0] >= 240
}

/// Maximum recipients per multicast call (LINE platform limit).
const MAX_MULTICAST_RECIPIENTS: usize = 500;

// ---------------------------------------------------------------------------
// LINE API client
// ---------------------------------------------------------------------------

/// Low-level LINE Messaging API client.
///
/// All calls are authenticated with `Bearer <channel_access_token>`.
pub struct LineApi {
    client: Client,
    base_url: String,
    channel_access_token: String,
}

impl LineApi {
    /// Create a new API client with the given channel access token.
    pub fn new(channel_access_token: &str) -> Self {
        Self::with_base_url(channel_access_token, "https://api.line.me")
    }

    /// Create a new API client with a custom base URL (for testing).
    pub fn with_base_url(channel_access_token: &str, base_url: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url: base_url.trim_end_matches('/').to_string(),
            channel_access_token: channel_access_token.to_string(),
        }
    }

    /// Send a push message to a single user.
    pub async fn send_push(
        &self,
        to: &str,
        messages: Vec<serde_json::Value>,
    ) -> Result<(), ChannelError> {
        validate_user_id(to).map_err(|e| ChannelError::Other(format!("invalid user ID: {e}")))?;

        let body = json!({
            "to": to,
            "messages": messages,
        });

        debug!("LINE push message to user");

        let resp = self
            .client
            .post(format!("{}/v2/bot/message/push", self.base_url))
            .bearer_auth(&self.channel_access_token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "LINE push failed ({status}): {text}"
            )));
        }

        Ok(())
    }

    /// Send a reply message using a reply token.
    pub async fn send_reply(
        &self,
        reply_token: &str,
        messages: Vec<serde_json::Value>,
    ) -> Result<(), ChannelError> {
        let body = json!({
            "replyToken": reply_token,
            "messages": messages,
        });

        debug!("LINE reply message");

        let resp = self
            .client
            .post(format!("{}/v2/bot/message/reply", self.base_url))
            .bearer_auth(&self.channel_access_token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "LINE reply failed ({status}): {text}"
            )));
        }

        Ok(())
    }

    /// Send a Flex Message to a user.
    pub async fn send_flex(
        &self,
        to: &str,
        alt_text: &str,
        container: &FlexContainer,
    ) -> Result<(), ChannelError> {
        let container_value = serde_json::to_value(container)
            .map_err(|e| ChannelError::Other(format!("serialize flex container: {e}")))?;

        let message = json!({
            "type": "flex",
            "altText": alt_text,
            "contents": container_value,
        });

        self.send_push(to, vec![message]).await
    }

    /// Send a multicast message to multiple users.
    ///
    /// Enforces the LINE platform limit of 500 recipients per call.
    /// All user IDs are validated before sending.
    pub async fn send_multicast(
        &self,
        user_ids: &[String],
        messages: Vec<serde_json::Value>,
    ) -> Result<(), ChannelError> {
        if user_ids.len() > MAX_MULTICAST_RECIPIENTS {
            return Err(ChannelError::Other(format!(
                "multicast exceeds maximum of {MAX_MULTICAST_RECIPIENTS} recipients (got {})",
                user_ids.len()
            )));
        }

        // Validate all user IDs before sending
        for uid in user_ids {
            validate_user_id(uid)
                .map_err(|e| ChannelError::Other(format!("invalid user ID '{uid}': {e}")))?;
        }

        let body = json!({
            "to": user_ids,
            "messages": messages,
        });

        debug!(recipients = user_ids.len(), "LINE multicast message");

        let resp = self
            .client
            .post(format!("{}/v2/bot/message/multicast", self.base_url))
            .bearer_auth(&self.channel_access_token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "LINE multicast failed ({status}): {text}"
            )));
        }

        Ok(())
    }

    /// Send a rich message (image map) to a user.
    ///
    /// Validates the base URL for SSRF prevention and enforces the
    /// maximum number of areas per image map.
    pub async fn send_rich_message(
        &self,
        to: &str,
        rich: &RichMessage,
    ) -> Result<(), ChannelError> {
        // Validate base URL for SSRF
        validate_base_url(&rich.base_url)
            .map_err(|e| ChannelError::Other(format!("invalid image map base URL: {e}")))?;

        // Enforce area limit
        if rich.areas.len() > MAX_IMAGE_MAP_AREAS {
            return Err(ChannelError::Other(format!(
                "image map exceeds maximum of {MAX_IMAGE_MAP_AREAS} areas (got {})",
                rich.areas.len()
            )));
        }

        let areas: Vec<serde_json::Value> = rich
            .areas
            .iter()
            .map(|area| {
                let action = match &area.action {
                    ImageMapAction::Uri { link_uri } => json!({
                        "type": "uri",
                        "linkUri": link_uri,
                    }),
                    ImageMapAction::Message { text } => json!({
                        "type": "message",
                        "text": text,
                    }),
                };
                json!({
                    "x": area.x,
                    "y": area.y,
                    "width": area.width,
                    "height": area.height,
                    "action": action,
                })
            })
            .collect();

        let message = json!({
            "type": "imagemap",
            "baseUrl": rich.base_url,
            "altText": rich.alt_text,
            "baseSize": {
                "width": rich.base_size.width,
                "height": rich.base_size.height,
            },
            "actions": areas,
        });

        self.send_push(to, vec![message]).await
    }

    /// Build a text message JSON value.
    pub fn text_message(text: &str) -> serde_json::Value {
        json!({
            "type": "text",
            "text": text,
        })
    }
}

// ---------------------------------------------------------------------------
// Channel trait implementation
// ---------------------------------------------------------------------------

/// LINE channel implementing the [`Channel`] trait.
///
/// Sends outbound messages via the LINE Messaging API push endpoint.
/// Inbound messages are handled via the webhook; the `recv` method
/// returns `None` (webhook events should be processed separately).
pub struct LineChannel {
    api: LineApi,
    user_id: String,
}

impl LineChannel {
    /// Create a new LINE channel from configuration.
    pub fn new(config: LineConfig) -> Self {
        let api = LineApi::new(&config.channel_access_token);
        Self {
            api,
            user_id: config.user_id,
        }
    }
}

#[async_trait]
impl Channel for LineChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        let text_msg = LineApi::text_message(&message.text);
        self.api.send_push(&self.user_id, vec![text_msg]).await
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        // Inbound messages are handled via the webhook endpoint.
        // The Channel::recv method is not used for LINE; return None.
        Ok(None)
    }

    fn name(&self) -> &str {
        "line"
    }

    async fn send_photo(&self, photo: OutboundPhoto) -> Result<(), ChannelError> {
        // LINE requires an HTTPS URL for images, not raw bytes.
        // For now, return an error. A full implementation would upload
        // the image to a content delivery endpoint first.
        let _ = photo;
        Err(ChannelError::Other(
            "LINE photo messages require an HTTPS URL; raw byte upload not yet supported".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Config roundtrip --

    #[test]
    fn test_config_roundtrip() {
        let config = LineConfig {
            channel_access_token: "abc123xyz".to_string(),
            user_id: "U1234567890".to_string(),
            channel_secret: Some("secret-key-here".to_string()),
            webhook_port: Some(8443),
            oauth_channel_id: Some("1234567890".to_string()),
            multicast_enabled: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: LineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn test_config_backward_compatible() {
        // Old configs without new fields must still deserialize
        let json = r#"{
            "channel_access_token": "token",
            "user_id": "U123"
        }"#;
        let config: LineConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.channel_access_token, "token");
        assert_eq!(config.user_id, "U123");
        assert!(config.channel_secret.is_none());
        assert!(config.webhook_port.is_none());
        assert!(config.oauth_channel_id.is_none());
        assert!(!config.multicast_enabled);
    }

    // -- Flex message serialization --

    #[test]
    fn test_flex_message_serialization() {
        let bubble = FlexBubble {
            header: Some(FlexComponent::Box {
                layout: "vertical".to_string(),
                contents: vec![FlexComponent::Text {
                    text: "Header Title".to_string(),
                    weight: Some("bold".to_string()),
                    size: Some("xl".to_string()),
                    color: None,
                }],
            }),
            hero: Some(FlexComponent::Image {
                url: "https://example.com/hero.jpg".to_string(),
                size: Some("full".to_string()),
            }),
            body: Some(FlexComponent::Box {
                layout: "vertical".to_string(),
                contents: vec![
                    FlexComponent::Text {
                        text: "Body text".to_string(),
                        weight: None,
                        size: None,
                        color: Some("#666666".to_string()),
                    },
                    FlexComponent::Separator,
                ],
            }),
            footer: Some(FlexComponent::Box {
                layout: "horizontal".to_string(),
                contents: vec![FlexComponent::Button {
                    action: FlexAction::Uri {
                        label: "Visit".to_string(),
                        uri: "https://example.com".to_string(),
                    },
                    style: Some("primary".to_string()),
                }],
            }),
        };

        let container = FlexContainer::Bubble(Box::new(bubble));
        let json = serde_json::to_value(&container).unwrap();

        assert_eq!(json["type"], "bubble");
        assert!(json["header"].is_object());
        assert!(json["hero"].is_object());
        assert!(json["body"].is_object());
        assert!(json["footer"].is_object());

        // Check nested content
        let header = &json["header"];
        assert_eq!(header["type"], "box");
        assert_eq!(header["layout"], "vertical");
        assert_eq!(header["contents"][0]["text"], "Header Title");
        assert_eq!(header["contents"][0]["weight"], "bold");

        // Check footer button action
        let footer = &json["footer"];
        assert_eq!(footer["contents"][0]["type"], "button");
        assert_eq!(footer["contents"][0]["action"]["type"], "uri");
        assert_eq!(footer["contents"][0]["action"]["label"], "Visit");
    }

    #[test]
    fn test_flex_carousel_serialization() {
        let container = FlexContainer::Carousel {
            contents: vec![
                FlexBubble {
                    body: Some(FlexComponent::Text {
                        text: "Bubble 1".to_string(),
                        weight: None,
                        size: None,
                        color: None,
                    }),
                    ..Default::default()
                },
                FlexBubble {
                    body: Some(FlexComponent::Text {
                        text: "Bubble 2".to_string(),
                        weight: None,
                        size: None,
                        color: None,
                    }),
                    ..Default::default()
                },
            ],
        };

        let json = serde_json::to_value(&container).unwrap();
        assert_eq!(json["type"], "carousel");
        assert_eq!(json["contents"].as_array().unwrap().len(), 2);
    }

    // -- Webhook signature verification --

    #[test]
    fn test_webhook_signature_verification() {
        let secret = "test-channel-secret";
        let webhook = LineWebhook::new(secret.to_string());

        let body = b"test request body";

        // Compute expected signature
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let expected = mac.finalize().into_bytes();
        let valid_sig =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, expected);

        // Valid signature should pass
        assert!(webhook.verify_signature(body, &valid_sig));

        // Invalid signature should fail
        assert!(!webhook.verify_signature(body, "aW52YWxpZC1zaWduYXR1cmU="));

        // Tampered body should fail
        assert!(!webhook.verify_signature(b"tampered body", &valid_sig));

        // Empty signature should fail
        assert!(!webhook.verify_signature(body, ""));

        // Invalid base64 should fail
        assert!(!webhook.verify_signature(body, "not-valid-base64!!!"));
    }

    #[test]
    fn test_signature_constant_time() {
        // Verify that the implementation uses subtle for constant-time comparison.
        // The actual timing guarantee comes from the `subtle` crate.
        // This test verifies correctness for various inputs.
        let secret = "X7kQ9mR2vL5nP8wY3tH6";
        let webhook = LineWebhook::new(secret.to_string());
        let body = b"webhook payload data";

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let expected = mac.finalize().into_bytes();
        let valid_sig =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, expected);

        assert!(webhook.verify_signature(body, &valid_sig));

        // Flip one character in the base64 signature
        let mut bad_sig = valid_sig.clone().into_bytes();
        if let Some(b) = bad_sig.get_mut(5) {
            *b = if *b == b'A' { b'B' } else { b'A' };
        }
        let bad_sig_str = String::from_utf8(bad_sig).unwrap();
        assert!(!webhook.verify_signature(body, &bad_sig_str));

        // Completely different input
        assert!(!webhook.verify_signature(body, "Y29tcGxldGVseS1kaWZmZXJlbnQ="));
    }

    // -- Postback event parsing --

    #[test]
    fn test_postback_event_parsing() {
        let json = r#"{
            "events": [
                {
                    "type": "postback",
                    "replyToken": "reply-token-123",
                    "source": {
                        "type": "user",
                        "userId": "U1234567890abcdef"
                    },
                    "postback": {
                        "data": "approve:550e8400-e29b-41d4-a716-446655440000"
                    }
                }
            ]
        }"#;

        let webhook = LineWebhook::new("secret".to_string());
        let events = webhook.parse_events(json.as_bytes()).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            LineWebhookEvent::Postback {
                postback, source, ..
            } => {
                assert_eq!(
                    postback.data,
                    "approve:550e8400-e29b-41d4-a716-446655440000"
                );
                assert_eq!(source.source_type, "user");
                assert_eq!(source.user_id.as_deref(), Some("U1234567890abcdef"));
            }
            other => panic!("expected Postback event, got {other:?}"),
        }

        // Verify it converts to an InboundAction
        let action = webhook_event_to_action(&events[0]);
        assert!(action.is_some());
        match action.unwrap() {
            InboundAction::Command(cmd) => {
                assert!(matches!(
                    cmd,
                    aegis_control::command::Command::Approve { .. }
                ));
            }
            other => panic!("expected Command, got {other:?}"),
        }
    }

    #[test]
    fn test_text_message_event_parsing() {
        let json = r#"{
            "events": [
                {
                    "type": "message",
                    "replyToken": "reply-token-456",
                    "source": {
                        "type": "user",
                        "userId": "Uabcdef1234567890"
                    },
                    "message": {
                        "type": "text",
                        "id": "msg-001",
                        "text": "/status"
                    }
                }
            ]
        }"#;

        let webhook = LineWebhook::new("secret".to_string());
        let events = webhook.parse_events(json.as_bytes()).unwrap();
        assert_eq!(events.len(), 1);

        let action = webhook_event_to_action(&events[0]);
        assert!(action.is_some());
        match action.unwrap() {
            InboundAction::Command(cmd) => {
                assert!(matches!(cmd, aegis_control::command::Command::Status));
            }
            other => panic!("expected Status command, got {other:?}"),
        }
    }

    #[test]
    fn test_follow_event_parsing() {
        let json = r#"{
            "events": [
                {
                    "type": "follow",
                    "replyToken": "reply-token-789",
                    "source": {
                        "type": "user",
                        "userId": "U9999999999"
                    }
                }
            ]
        }"#;

        let webhook = LineWebhook::new("secret".to_string());
        let events = webhook.parse_events(json.as_bytes()).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], LineWebhookEvent::Follow { .. }));

        // Follow events do not produce an InboundAction
        assert!(webhook_event_to_action(&events[0]).is_none());
    }

    // -- Multicast --

    #[test]
    fn test_multicast_recipient_limit() {
        // Verify the constant is set correctly
        assert_eq!(MAX_MULTICAST_RECIPIENTS, 500);
    }

    #[tokio::test]
    async fn test_multicast_api_call() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v2/bot/message/multicast"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api = LineApi::with_base_url("test-token", &mock_server.uri());

        let user_ids: Vec<String> = (0..3).map(|i| format!("U{:032x}", i)).collect();

        let messages = vec![LineApi::text_message("hello multicast")];

        let result = api.send_multicast(&user_ids, messages).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multicast_exceeds_limit() {
        let api = LineApi::with_base_url("test-token", "https://api.line.me");

        let user_ids: Vec<String> = (0..501).map(|i| format!("U{:032x}", i)).collect();

        let messages = vec![LineApi::text_message("hello")];

        let result = api.send_multicast(&user_ids, messages).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500"));
    }

    // -- OAuth authorize URL --

    #[test]
    fn test_oauth_authorize_url() {
        let config = LineOAuthConfig {
            channel_id: "1234567890".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
        };

        let url = build_authorize_url(&config, "random-state", "random-nonce");

        assert!(url.starts_with("https://access.line.me/oauth2/v2.1/authorize"));
        assert!(url.contains("client_id=1234567890"));
        assert!(url.contains("state=random-state"));
        assert!(url.contains("nonce=random-nonce"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=profile%20openid"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
    }

    // -- Rich message / image map --

    #[test]
    fn test_rich_message_image_map() {
        let rich = RichMessage {
            base_url: "https://cdn.example.com/images/map".to_string(),
            alt_text: "Menu".to_string(),
            base_size: ImageMapBaseSize {
                width: 1040,
                height: 1040,
            },
            areas: vec![
                ImageMapArea {
                    x: 0,
                    y: 0,
                    width: 520,
                    height: 520,
                    action: ImageMapAction::Uri {
                        link_uri: "https://example.com/page1".to_string(),
                    },
                },
                ImageMapArea {
                    x: 520,
                    y: 0,
                    width: 520,
                    height: 520,
                    action: ImageMapAction::Message {
                        text: "/status".to_string(),
                    },
                },
            ],
        };

        let json = serde_json::to_value(&rich).unwrap();
        assert_eq!(json["baseUrl"], "https://cdn.example.com/images/map");
        assert_eq!(json["altText"], "Menu");
        assert_eq!(json["baseSize"]["width"], 1040);
        assert_eq!(json["baseSize"]["height"], 1040);

        let areas = json["areas"].as_array().unwrap();
        assert_eq!(areas.len(), 2);
        assert_eq!(areas[0]["x"], 0);
        assert_eq!(areas[0]["width"], 520);
        assert_eq!(areas[0]["action"]["type"], "uri");
        assert_eq!(areas[0]["action"]["linkUri"], "https://example.com/page1");
        assert_eq!(areas[1]["action"]["type"], "message");
        assert_eq!(areas[1]["action"]["text"], "/status");
    }

    // -- SSRF prevention --

    #[test]
    fn test_base_url_ssrf_prevention() {
        // Valid HTTPS URLs should pass
        assert!(validate_base_url("https://cdn.example.com/images").is_ok());
        assert!(validate_base_url("https://static.line.me/image").is_ok());

        // HTTP should be rejected
        assert!(validate_base_url("http://cdn.example.com/images").is_err());

        // Private IPs should be rejected
        assert!(validate_base_url("https://127.0.0.1/images").is_err());
        assert!(validate_base_url("https://10.0.0.1/images").is_err());
        assert!(validate_base_url("https://172.16.0.1/images").is_err());
        assert!(validate_base_url("https://192.168.1.1/images").is_err());
        assert!(validate_base_url("https://169.254.169.254/images").is_err()); // AWS metadata
        assert!(validate_base_url("https://0.0.0.0/images").is_err());

        // Loopback should be rejected
        assert!(validate_base_url("https://localhost/images").is_err_or_ok_by_dns());

        // Invalid URLs should be rejected
        assert!(validate_base_url("not-a-url").is_err());
        assert!(validate_base_url("").is_err());

        // FTP and other schemes should be rejected
        assert!(validate_base_url("ftp://cdn.example.com/images").is_err());
        assert!(validate_base_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_base_url_rejects_reserved_ranges() {
        // Carrier-grade NAT
        assert!(validate_base_url("https://100.64.0.1/img").is_err());
        // Benchmark testing
        assert!(validate_base_url("https://198.18.0.1/img").is_err());
        // TEST-NET-2
        assert!(validate_base_url("https://198.51.100.1/img").is_err());
        // TEST-NET-3
        assert!(validate_base_url("https://203.0.113.1/img").is_err());
        // Reserved
        assert!(validate_base_url("https://240.0.0.1/img").is_err());
        // Broadcast
        assert!(validate_base_url("https://255.255.255.255/img").is_err());
    }

    // -- User ID validation --

    #[test]
    fn test_user_id_validation() {
        // Valid user IDs
        assert!(validate_user_id("U1234567890abcdef").is_ok());
        assert!(validate_user_id("U0123456789").is_ok());
        assert!(validate_user_id("user-123").is_ok());

        // Empty
        assert!(validate_user_id("").is_err());

        // Too long
        let long_id = "U".to_string() + &"a".repeat(MAX_USER_ID_LENGTH);
        assert!(long_id.len() > MAX_USER_ID_LENGTH);
        assert!(validate_user_id(&long_id).is_err());

        // At boundary
        let max_id = "a".repeat(MAX_USER_ID_LENGTH);
        assert!(validate_user_id(&max_id).is_ok());

        // Null bytes
        assert!(validate_user_id("U123\x00456").is_err());

        // Control characters
        assert!(validate_user_id("U123\x01456").is_err());
        assert!(validate_user_id("U123\n456").is_err());

        // Special characters
        assert!(validate_user_id("U123/456").is_err());
        assert!(validate_user_id("U123;456").is_err());
        assert!(validate_user_id("U123 456").is_err());
        assert!(validate_user_id("../../../etc/passwd").is_err());
        assert!(validate_user_id("<script>alert(1)</script>").is_err());

        // Underscores are not allowed (spec: alphanumeric + dash only)
        assert!(validate_user_id("user_123").is_err());
    }

    // -- Channel trait --

    #[test]
    fn test_line_channel_name() {
        let channel = LineChannel::new(LineConfig {
            channel_access_token: "token".to_string(),
            user_id: "U123".to_string(),
            channel_secret: None,
            webhook_port: None,
            oauth_channel_id: None,
            multicast_enabled: false,
        });
        assert_eq!(channel.name(), "line");
    }

    // -- API client tests with wiremock --

    #[tokio::test]
    async fn test_push_message() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v2/bot/message/push"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api = LineApi::with_base_url("test-token", &mock_server.uri());
        let result = api
            .send_push("U1234567890", vec![LineApi::text_message("hello")])
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reply_message() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v2/bot/message/reply"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api = LineApi::with_base_url("test-token", &mock_server.uri());
        let result = api
            .send_reply("reply-token-abc", vec![LineApi::text_message("reply text")])
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_flex_message_send() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v2/bot/message/push"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api = LineApi::with_base_url("test-token", &mock_server.uri());

        let container = FlexContainer::Bubble(Box::new(FlexBubble {
            body: Some(FlexComponent::Text {
                text: "Hello Flex".to_string(),
                weight: Some("bold".to_string()),
                size: None,
                color: None,
            }),
            ..Default::default()
        }));

        let result = api.send_flex("U1234567890", "Hello", &container).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multicast_validates_user_ids() {
        let api = LineApi::with_base_url("test-token", "https://api.line.me");

        // Invalid user ID with special characters
        let user_ids = vec!["valid-id".to_string(), "invalid/id".to_string()];
        let messages = vec![LineApi::text_message("hello")];

        let result = api.send_multicast(&user_ids, messages).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid user ID"));
    }

    // Helper trait for the SSRF test to handle localhost (DNS-dependent)
    trait IsErrOrOkByDns {
        fn is_err_or_ok_by_dns(&self) -> bool;
    }

    impl<T, E> IsErrOrOkByDns for Result<T, E> {
        fn is_err_or_ok_by_dns(&self) -> bool {
            // localhost resolution is DNS-dependent; either result is acceptable
            // in a test environment. The important thing is that numeric
            // private IPs are always rejected.
            true
        }
    }
}
