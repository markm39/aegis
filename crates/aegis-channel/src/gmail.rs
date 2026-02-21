//! Gmail API client with OAuth2 token management.
//!
//! Provides a Gmail API client that authenticates via OAuth2 device flow,
//! stores tokens securely with restrictive file permissions, and offers
//! basic message listing, retrieval, and sending capabilities.
//!
//! # Security
//!
//! - OAuth2 client secret is read from an **environment variable**, never
//!   stored in config files.
//! - Tokens are stored on disk with `0600` permissions (owner read/write only).
//! - All email content is sanitized: HTML is stripped, control characters are
//!   removed before returning to callers.
//! - Tokens are masked in any log/display output (first 4 chars + `***`).
//! - Email addresses are validated before sending.
//!
//! # Usage
//!
//! This module provides the foundation (config, token store, API client).
//! The `Channel` trait implementation will be added in a follow-up task.

use std::fmt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::channel::ChannelError;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default Gmail labels to watch for inbound messages.
fn default_watch_labels() -> Vec<String> {
    vec!["INBOX".to_string()]
}

/// Default path for storing OAuth2 tokens (wrapped in `Option` for serde default).
fn default_token_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    Some(PathBuf::from(home).join(".aegis").join("gmail").join("tokens.json"))
}

/// Unwrapped default token path for internal use.
fn default_token_path_unwrapped() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".aegis").join("gmail").join("tokens.json")
}

/// Configuration for the Gmail messaging channel.
///
/// The `client_secret_env` field names the environment variable that holds
/// the OAuth2 client secret. The secret itself is **never** stored in config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GmailConfig {
    /// OAuth2 client ID from Google Cloud Console.
    pub client_id: String,

    /// Name of the environment variable holding the OAuth2 client secret.
    /// The actual secret is read at runtime via `std::env::var(client_secret_env)`.
    pub client_secret_env: String,

    /// Google Cloud project ID (optional, used for push notifications).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,

    /// Gmail label IDs to watch for inbound messages.
    #[serde(default = "default_watch_labels")]
    pub watch_labels: Vec<String>,

    /// Path to store OAuth2 tokens. Defaults to `~/.aegis/gmail/tokens.json`.
    #[serde(default = "default_token_path", skip_serializing_if = "Option::is_none")]
    pub token_path: Option<PathBuf>,
}

impl GmailConfig {
    /// Resolve the token storage path, falling back to the default.
    pub fn resolved_token_path(&self) -> PathBuf {
        self.token_path
            .clone()
            .unwrap_or_else(default_token_path_unwrapped)
    }

    /// Read the client secret from the configured environment variable.
    ///
    /// Returns an error if the variable is unset or empty.
    pub fn read_client_secret(&self) -> Result<String, ChannelError> {
        let secret = std::env::var(&self.client_secret_env).map_err(|_| {
            ChannelError::Other(format!(
                "environment variable '{}' not set (required for Gmail OAuth2 client secret)",
                self.client_secret_env
            ))
        })?;
        if secret.is_empty() {
            return Err(ChannelError::Other(format!(
                "environment variable '{}' is empty",
                self.client_secret_env
            )));
        }
        Ok(secret)
    }
}

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

/// Google OAuth2 token endpoint.
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// An OAuth2 token pair with expiry tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// The short-lived access token for API calls.
    pub access_token: String,

    /// The long-lived refresh token for obtaining new access tokens.
    pub refresh_token: String,

    /// When the access token expires. `None` means unknown/treat as expired.
    pub expires_at: Option<DateTime<Utc>>,
}

impl OAuthToken {
    /// Check whether the access token has expired (with a 60-second margin).
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() >= exp - chrono::Duration::seconds(60),
            None => true, // unknown expiry -> treat as expired
        }
    }
}

/// Mask a token for safe log output: show first 4 chars, then `***`.
///
/// Tokens shorter than 4 characters are fully masked.
pub fn mask_token(token: &str) -> String {
    if token.len() <= 4 {
        "***".to_string()
    } else {
        format!("{}***", &token[..4])
    }
}

/// Display implementation that masks the access token.
impl fmt::Display for OAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OAuthToken(access={}, refresh={}, expires_at={:?})",
            mask_token(&self.access_token),
            mask_token(&self.refresh_token),
            self.expires_at,
        )
    }
}

/// Persistent token storage backed by a JSON file with `0600` permissions.
///
/// Tokens are stored as a single JSON object. The file is created with
/// owner-only read/write permissions to prevent other users on the system
/// from reading the OAuth2 tokens.
pub struct GmailTokenStore {
    path: PathBuf,
}

impl GmailTokenStore {
    /// Create a new token store at the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load tokens from the store file.
    ///
    /// Returns `Ok(None)` if the file does not exist. Returns an error
    /// if the file exists but cannot be read or parsed.
    pub fn load(&self) -> Result<Option<OAuthToken>, ChannelError> {
        if !self.path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&self.path).map_err(|e| {
            ChannelError::Other(format!(
                "failed to read token file '{}': {e}",
                self.path.display()
            ))
        })?;

        let token: OAuthToken = serde_json::from_str(&content).map_err(|e| {
            ChannelError::Other(format!(
                "failed to parse token file '{}': {e}",
                self.path.display()
            ))
        })?;

        debug!(
            "loaded Gmail token from {} (expires_at={:?})",
            self.path.display(),
            token.expires_at,
        );

        Ok(Some(token))
    }

    /// Save tokens to the store file with `0600` permissions.
    ///
    /// Creates parent directories as needed. On non-Unix platforms, file
    /// permissions are set to the platform default (no `chmod` equivalent).
    pub fn save(&self, token: &OAuthToken) -> Result<(), ChannelError> {
        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ChannelError::Other(format!(
                    "failed to create token directory '{}': {e}",
                    parent.display()
                ))
            })?;
        }

        let content = serde_json::to_string_pretty(token).map_err(|e| {
            ChannelError::Other(format!("failed to serialize token: {e}"))
        })?;

        std::fs::write(&self.path, &content).map_err(|e| {
            ChannelError::Other(format!(
                "failed to write token file '{}': {e}",
                self.path.display()
            ))
        })?;

        // Set file permissions to 0600 (owner read/write only)
        set_file_permissions_0600(&self.path)?;

        debug!("saved Gmail token to {}", self.path.display());
        Ok(())
    }

    /// Delete the stored tokens.
    pub fn delete(&self) -> Result<(), ChannelError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(|e| {
                ChannelError::Other(format!(
                    "failed to delete token file '{}': {e}",
                    self.path.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Return the store file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Set a file's permissions to `0600` on Unix systems.
///
/// On non-Unix platforms this is a no-op (permissions are left at default).
#[cfg(unix)]
fn set_file_permissions_0600(path: &Path) -> Result<(), ChannelError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| {
        ChannelError::Other(format!(
            "failed to set permissions on '{}': {e}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_file_permissions_0600(_path: &Path) -> Result<(), ChannelError> {
    // No-op on non-Unix platforms
    Ok(())
}

// ---------------------------------------------------------------------------
// Token refresh
// ---------------------------------------------------------------------------

/// Refresh an expired access token using the refresh token.
///
/// POSTs to Google's OAuth2 token endpoint with the `refresh_token` grant type.
/// Returns a new `OAuthToken` with the refreshed access token and updated expiry.
/// The refresh token itself may or may not be rotated by Google.
pub async fn refresh_access_token(
    client: &Client,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<OAuthToken, ChannelError> {
    refresh_access_token_at(client, TOKEN_ENDPOINT, client_id, client_secret, refresh_token).await
}

/// Internal: refresh with a configurable endpoint (for testing).
async fn refresh_access_token_at(
    client: &Client,
    endpoint: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<OAuthToken, ChannelError> {
    debug!("refreshing Gmail access token");

    let resp = client
        .post(endpoint)
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;

    if !status.is_success() {
        let error_desc = body
            .get("error_description")
            .and_then(|v| v.as_str())
            .or_else(|| body.get("error").and_then(|v| v.as_str()))
            .unwrap_or("unknown error");
        warn!("Gmail token refresh failed: {error_desc}");
        return Err(ChannelError::Api(format!(
            "token refresh failed: {error_desc}"
        )));
    }

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChannelError::Api("missing access_token in refresh response".into()))?
        .to_string();

    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_i64())
        .unwrap_or(3600);

    let expires_at = Utc::now() + chrono::Duration::seconds(expires_in);

    // Google may return a new refresh token; fall back to the existing one
    let new_refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or(refresh_token)
        .to_string();

    Ok(OAuthToken {
        access_token,
        refresh_token: new_refresh_token,
        expires_at: Some(expires_at),
    })
}

// ---------------------------------------------------------------------------
// Email content sanitization
// ---------------------------------------------------------------------------

/// Strip HTML tags from a string, returning only the text content.
///
/// This is a simple state-machine-based stripper, not a full HTML parser.
/// It handles `<br>`, `<p>`, `<div>` by inserting newlines, and strips
/// all other tags. HTML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`,
/// `&nbsp;`, `&#NNN;`, `&#xHHH;`) are decoded.
pub fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut tag_name = String::new();
    let mut in_entity = false;
    let mut entity_buf = String::new();

    for ch in html.chars() {
        if in_entity {
            if ch == ';' {
                out.push_str(&decode_entity(&entity_buf));
                entity_buf.clear();
                in_entity = false;
            } else if entity_buf.len() < 10 {
                entity_buf.push(ch);
            } else {
                // Entity too long, not a real entity -- emit raw
                out.push('&');
                out.push_str(&entity_buf);
                out.push(ch);
                entity_buf.clear();
                in_entity = false;
            }
            continue;
        }

        if in_tag {
            if ch == '>' {
                let lower = tag_name.to_ascii_lowercase();
                // Insert newlines for block-level elements
                if lower == "br"
                    || lower == "br/"
                    || lower == "p"
                    || lower == "/p"
                    || lower == "div"
                    || lower == "/div"
                    || lower == "li"
                {
                    out.push('\n');
                }
                tag_name.clear();
                in_tag = false;
            } else if tag_name.len() < 50 {
                // Only capture reasonable tag names; skip attributes
                if ch.is_whitespace() && !tag_name.is_empty() {
                    // Stop capturing after the tag name (before attributes)
                } else if !ch.is_whitespace() || tag_name.is_empty() {
                    tag_name.push(ch);
                }
            }
            continue;
        }

        match ch {
            '<' => {
                in_tag = true;
                tag_name.clear();
            }
            '&' => {
                in_entity = true;
                entity_buf.clear();
            }
            _ => out.push(ch),
        }
    }

    // Flush any incomplete entity
    if in_entity {
        out.push('&');
        out.push_str(&entity_buf);
    }

    out
}

/// Decode a single HTML entity (without the leading `&` and trailing `;`).
fn decode_entity(entity: &str) -> String {
    match entity {
        "amp" => "&".to_string(),
        "lt" => "<".to_string(),
        "gt" => ">".to_string(),
        "quot" => "\"".to_string(),
        "apos" => "'".to_string(),
        "nbsp" => " ".to_string(),
        s if s.starts_with('#') => {
            let num_str = &s[1..];
            let codepoint = if let Some(hex) = num_str.strip_prefix('x') {
                u32::from_str_radix(hex, 16).ok()
            } else {
                num_str.parse::<u32>().ok()
            };
            codepoint
                .and_then(char::from_u32)
                .map(|c| c.to_string())
                .unwrap_or_else(|| format!("&{entity};"))
        }
        _ => format!("&{entity};"),
    }
}

/// Remove control characters (except newline, carriage return, tab) from text.
///
/// This prevents terminal injection and other attacks via email content that
/// contains embedded control sequences.
pub fn remove_control_chars(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .collect()
}

/// Sanitize email content: strip HTML and remove control characters.
pub fn sanitize_email_content(raw: &str) -> String {
    let text = strip_html(raw);
    remove_control_chars(&text)
}

// ---------------------------------------------------------------------------
// Email address validation
// ---------------------------------------------------------------------------

/// Validate a basic email address format.
///
/// Checks for:
/// - Non-empty local and domain parts separated by exactly one `@`
/// - Domain contains at least one `.`
/// - No whitespace or control characters
/// - Reasonable length limits (local <= 64 chars, domain <= 255 chars)
///
/// This is intentionally simple -- full RFC 5321/5322 validation is not
/// attempted. The goal is to catch obvious mistakes and prevent injection.
pub fn validate_email_address(email: &str) -> Result<(), String> {
    if email.is_empty() {
        return Err("email address is empty".into());
    }

    // No whitespace or control characters
    if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("email address contains whitespace or control characters".into());
    }

    // Must contain exactly one @
    let at_count = email.chars().filter(|&c| c == '@').count();
    if at_count != 1 {
        return Err(format!(
            "email address must contain exactly one '@' (found {at_count})"
        ));
    }

    let (local, domain) = email.split_once('@').unwrap();

    if local.is_empty() {
        return Err("email local part is empty".into());
    }
    if domain.is_empty() {
        return Err("email domain is empty".into());
    }

    // Length limits per RFC 5321
    if local.len() > 64 {
        return Err(format!(
            "email local part too long ({} chars, max 64)",
            local.len()
        ));
    }
    if domain.len() > 255 {
        return Err(format!(
            "email domain too long ({} chars, max 255)",
            domain.len()
        ));
    }

    // Domain must contain at least one dot
    if !domain.contains('.') {
        return Err("email domain must contain at least one '.'".into());
    }

    // Domain labels must not be empty
    for label in domain.split('.') {
        if label.is_empty() {
            return Err("email domain contains empty label".into());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gmail API response types
// ---------------------------------------------------------------------------

/// A Gmail message with decoded headers and body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmailMessage {
    /// Gmail message ID.
    pub id: String,
    /// Gmail thread ID.
    pub thread_id: String,
    /// Sender (From header).
    pub from: String,
    /// Recipient (To header).
    pub to: String,
    /// Subject line.
    pub subject: String,
    /// Plain-text body (sanitized).
    pub body_text: String,
    /// When the message was received.
    pub received_at: DateTime<Utc>,
}

/// Raw API response wrapper for Gmail list endpoints.
#[derive(Debug, Deserialize)]
struct GmailListResponse {
    messages: Option<Vec<GmailMessageRef>>,
    #[serde(default)]
    #[allow(dead_code)]
    next_page_token: Option<String>,
}

/// A minimal message reference from the list endpoint.
#[derive(Debug, Deserialize)]
struct GmailMessageRef {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    thread_id: Option<String>,
}

/// Raw API response for a single message.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailMessageResponse {
    id: String,
    thread_id: String,
    #[serde(default)]
    internal_date: Option<String>,
    payload: Option<GmailPayload>,
}

/// Message payload section.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailPayload {
    #[serde(default)]
    headers: Vec<GmailHeader>,
    #[serde(default)]
    parts: Vec<GmailPart>,
    body: Option<GmailBody>,
}

/// A single email header.
#[derive(Debug, Deserialize)]
struct GmailHeader {
    name: String,
    value: String,
}

/// A MIME part of the message.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailPart {
    #[serde(default)]
    mime_type: String,
    body: Option<GmailBody>,
    #[serde(default)]
    parts: Vec<GmailPart>,
}

/// Body data from a message or part.
#[derive(Debug, Deserialize)]
struct GmailBody {
    #[serde(default)]
    data: Option<String>,
}

/// Raw API response for sending a message.
#[derive(Debug, Deserialize)]
struct GmailSendResponse {
    id: String,
}

// ---------------------------------------------------------------------------
// Gmail API Client
// ---------------------------------------------------------------------------

/// Gmail API base URL.
const GMAIL_API_BASE: &str = "https://gmail.googleapis.com/gmail/v1/users/me";

/// Gmail API client with OAuth2 authentication.
///
/// Handles listing, reading, and sending messages. Token refresh is
/// performed automatically when the access token expires.
pub struct GmailClient {
    config: GmailConfig,
    token_store: GmailTokenStore,
    client: Client,
    base_url: String,
}

impl GmailClient {
    /// Create a new Gmail client.
    pub fn new(config: GmailConfig, token_store: GmailTokenStore) -> Self {
        Self::with_base_url(config, token_store, GMAIL_API_BASE)
    }

    /// Create a new Gmail client with a custom base URL (for testing).
    pub fn with_base_url(config: GmailConfig, token_store: GmailTokenStore, base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            config,
            token_store,
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Get a valid access token, refreshing if necessary.
    ///
    /// Loads the token from the store, checks expiry, and refreshes via
    /// the OAuth2 token endpoint if expired. The refreshed token is saved
    /// back to the store.
    async fn get_access_token(&self) -> Result<String, ChannelError> {
        let token = self
            .token_store
            .load()?
            .ok_or_else(|| {
                ChannelError::Other(
                    "no Gmail OAuth2 token found -- run the authorization flow first".into(),
                )
            })?;

        if !token.is_expired() {
            return Ok(token.access_token);
        }

        debug!("Gmail access token expired, refreshing");

        let client_secret = self.config.read_client_secret()?;

        let new_token = refresh_access_token(
            &self.client,
            &self.config.client_id,
            &client_secret,
            &token.refresh_token,
        )
        .await?;

        self.token_store.save(&new_token)?;

        Ok(new_token.access_token)
    }

    /// List messages matching a Gmail search query.
    ///
    /// The `query` parameter uses Gmail's search syntax (e.g., `"is:unread"`).
    /// Returns up to `max_results` message summaries.
    pub async fn list_messages(
        &self,
        query: &str,
        max_results: u32,
    ) -> Result<Vec<GmailMessage>, ChannelError> {
        let token = self.get_access_token().await?;

        let url = format!("{}/messages", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .query(&[
                ("q", query),
                ("maxResults", &max_results.to_string()),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "Gmail list_messages failed ({status}): {body}"
            )));
        }

        let list: GmailListResponse = resp.json().await?;
        let refs = list.messages.unwrap_or_default();

        let mut messages = Vec::with_capacity(refs.len());
        for msg_ref in &refs {
            match self.get_message_with_token(&msg_ref.id, &token).await {
                Ok(msg) => messages.push(msg),
                Err(e) => {
                    warn!("failed to fetch message {}: {e}", msg_ref.id);
                }
            }
        }

        Ok(messages)
    }

    /// Retrieve a single message by ID.
    pub async fn get_message(&self, message_id: &str) -> Result<GmailMessage, ChannelError> {
        let token = self.get_access_token().await?;
        self.get_message_with_token(message_id, &token).await
    }

    /// Internal: get a message using a pre-fetched access token.
    async fn get_message_with_token(
        &self,
        message_id: &str,
        token: &str,
    ) -> Result<GmailMessage, ChannelError> {
        // Validate message_id to prevent path traversal
        if message_id.is_empty()
            || message_id.contains('/')
            || message_id.contains('\\')
            || message_id.contains("..")
        {
            return Err(ChannelError::Other(format!(
                "invalid message ID: {message_id:?}"
            )));
        }

        let url = format!("{}/messages/{}", self.base_url, message_id);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(token)
            .query(&[("format", "full")])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "Gmail get_message failed ({status}): {body}"
            )));
        }

        let raw: GmailMessageResponse = resp.json().await?;
        Ok(parse_gmail_message(raw))
    }

    /// Send an email message.
    ///
    /// The recipient email address is validated before sending. The message
    /// is sent as a simple RFC 2822 message encoded in base64url.
    pub async fn send_message(
        &self,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<String, ChannelError> {
        // Validate recipient address
        validate_email_address(to).map_err(|e| {
            ChannelError::Other(format!("invalid recipient address: {e}"))
        })?;

        let token = self.get_access_token().await?;

        // Sanitize subject and body to prevent header injection
        let safe_subject = subject.replace(['\r', '\n'], " ");
        let safe_body = remove_control_chars(body);

        // Build RFC 2822 message
        let raw_message = format!(
            "To: {to}\r\nSubject: {safe_subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{safe_body}"
        );

        // Gmail API expects base64url-encoded RFC 2822 messages
        use base64::Engine;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_message.as_bytes());

        let url = format!("{}/messages/send", self.base_url);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&token)
            .json(&serde_json::json!({ "raw": encoded }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "Gmail send_message failed ({status}): {body}"
            )));
        }

        let send_resp: GmailSendResponse = resp.json().await?;

        debug!("sent Gmail message, id={}", send_resp.id);
        Ok(send_resp.id)
    }
}

// ---------------------------------------------------------------------------
// Message parsing helpers
// ---------------------------------------------------------------------------

/// Parse a raw Gmail API message response into a sanitized `GmailMessage`.
fn parse_gmail_message(raw: GmailMessageResponse) -> GmailMessage {
    let payload = raw.payload.unwrap_or(GmailPayload {
        headers: vec![],
        parts: vec![],
        body: None,
    });

    let from = find_header(&payload.headers, "From").unwrap_or_default();
    let to = find_header(&payload.headers, "To").unwrap_or_default();
    let subject = find_header(&payload.headers, "Subject").unwrap_or_default();

    // Extract plain text body from parts or top-level body
    let body_raw = extract_body_text(&payload.parts, payload.body.as_ref());

    let body_text = sanitize_email_content(&body_raw);

    // Parse internal date (milliseconds since epoch)
    let received_at = raw
        .internal_date
        .as_deref()
        .and_then(|d| d.parse::<i64>().ok())
        .and_then(|ms| DateTime::from_timestamp(ms / 1000, ((ms % 1000) * 1_000_000) as u32))
        .unwrap_or_else(Utc::now);

    GmailMessage {
        id: raw.id,
        thread_id: raw.thread_id,
        from: sanitize_email_content(&from),
        to: sanitize_email_content(&to),
        subject: sanitize_email_content(&subject),
        body_text,
        received_at,
    }
}

/// Find a header value by name (case-insensitive).
fn find_header(headers: &[GmailHeader], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.clone())
}

/// Extract the plain text body from MIME parts, falling back to the top-level body.
fn extract_body_text(parts: &[GmailPart], top_body: Option<&GmailBody>) -> String {
    // Search parts for text/plain
    if let Some(text) = find_text_part(parts) {
        return text;
    }

    // Fall back to top-level body
    if let Some(body) = top_body {
        if let Some(data) = &body.data {
            return decode_base64url(data);
        }
    }

    String::new()
}

/// Recursively search MIME parts for text/plain content.
fn find_text_part(parts: &[GmailPart]) -> Option<String> {
    for part in parts {
        if part.mime_type == "text/plain" {
            if let Some(body) = &part.body {
                if let Some(data) = &body.data {
                    return Some(decode_base64url(data));
                }
            }
        }
        // Recurse into sub-parts
        if let Some(text) = find_text_part(&part.parts) {
            return Some(text);
        }
    }
    None
}

/// Decode a base64url-encoded string (as used by Gmail API).
fn decode_base64url(encoded: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let store = GmailTokenStore::new(path.clone());

        // Initially empty
        assert!(store.load().unwrap().is_none());

        // Save a token
        let token = OAuthToken {
            access_token: "ya29.test-access-token-1234567890".to_string(),
            refresh_token: "1//0test-refresh-token-abcdef".to_string(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };
        store.save(&token).unwrap();

        // Load it back
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.access_token, token.access_token);
        assert_eq!(loaded.refresh_token, token.refresh_token);

        // Verify file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        // Delete
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn test_token_masking() {
        assert_eq!(mask_token("ya29.abcdef123456"), "ya29***");
        assert_eq!(mask_token("abc"), "***");
        assert_eq!(mask_token(""), "***");
        assert_eq!(mask_token("abcd"), "***");
        assert_eq!(mask_token("abcde"), "abcd***");

        // Display impl should mask tokens
        let token = OAuthToken {
            access_token: "ya29.secret-access-token".to_string(),
            refresh_token: "1//0refresh-secret-token".to_string(),
            expires_at: None,
        };
        let display = format!("{token}");
        assert!(display.contains("ya29***"));
        assert!(display.contains("1//0***"));
        assert!(!display.contains("secret-access-token"));
        assert!(!display.contains("refresh-secret-token"));
    }

    #[test]
    fn test_email_sanitization() {
        // HTML stripping
        assert_eq!(
            strip_html("<p>Hello <b>world</b></p>"),
            "\nHello world\n"
        );

        // Entity decoding
        assert_eq!(strip_html("a &amp; b &lt; c"), "a & b < c");
        assert_eq!(strip_html("&#65;&#x42;"), "AB");

        // Control character removal
        assert_eq!(
            remove_control_chars("hello\x00world\x07foo\nbar"),
            "helloworldfoo\nbar"
        );

        // Full sanitization pipeline
        let html = "<div>Hello<br>World &amp; <script>alert('xss')</script>friends\x07!</div>";
        let sanitized = sanitize_email_content(html);
        assert!(sanitized.contains("Hello"));
        assert!(sanitized.contains("World & "));
        assert!(!sanitized.contains("<script>"));
        assert!(!sanitized.contains("\x07"));
        assert!(sanitized.contains("friends!"));
    }

    #[test]
    fn test_email_address_validation() {
        // Valid addresses
        assert!(validate_email_address("user@example.com").is_ok());
        assert!(validate_email_address("user.name@sub.domain.com").is_ok());
        assert!(validate_email_address("user+tag@example.co.uk").is_ok());
        assert!(validate_email_address("a@b.c").is_ok());

        // Invalid addresses
        assert!(validate_email_address("").is_err());
        assert!(validate_email_address("nope").is_err()); // no @
        assert!(validate_email_address("@example.com").is_err()); // empty local
        assert!(validate_email_address("user@").is_err()); // empty domain
        assert!(validate_email_address("user@nodot").is_err()); // no dot in domain
        assert!(validate_email_address("user@.com").is_err()); // empty label
        assert!(validate_email_address("user@com.").is_err()); // trailing dot -> empty label
        assert!(validate_email_address("user name@example.com").is_err()); // whitespace
        assert!(validate_email_address("user@@example.com").is_err()); // double @
        assert!(validate_email_address("user\x00@example.com").is_err()); // control char
    }

    #[test]
    fn test_config_serialization() {
        let config = GmailConfig {
            client_id: "123456789.apps.googleusercontent.com".to_string(),
            client_secret_env: "AEGIS_GMAIL_CLIENT_SECRET".to_string(),
            project_id: Some("my-project".to_string()),
            watch_labels: vec!["INBOX".to_string(), "IMPORTANT".to_string()],
            token_path: Some(PathBuf::from("/tmp/test-tokens.json")),
        };

        // Serialize to TOML
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("client_id"));
        assert!(toml_str.contains("client_secret_env"));
        assert!(!toml_str.contains("AEGIS_GMAIL_CLIENT_SECRET_VALUE")); // no actual secret

        // Deserialize back
        let parsed: GmailConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.client_id, config.client_id);
        assert_eq!(parsed.client_secret_env, config.client_secret_env);
        assert_eq!(parsed.project_id, config.project_id);
        assert_eq!(parsed.watch_labels, config.watch_labels);
        assert_eq!(parsed.token_path, config.token_path);
    }

    #[test]
    fn test_config_defaults() {
        let toml_str = r#"
            client_id = "test-id"
            client_secret_env = "MY_SECRET_ENV"
        "#;
        let config: GmailConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.watch_labels, vec!["INBOX"]);
        assert!(config.project_id.is_none());
        // token_path should have a default from the function
    }

    #[test]
    fn test_expired_token_detection() {
        // Token expiring in the future -> not expired
        let future_token = OAuthToken {
            access_token: "valid".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };
        assert!(!future_token.is_expired());

        // Token expired in the past -> expired
        let past_token = OAuthToken {
            access_token: "expired".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        };
        assert!(past_token.is_expired());

        // Token with no expiry -> treated as expired
        let no_expiry = OAuthToken {
            access_token: "unknown".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: None,
        };
        assert!(no_expiry.is_expired());

        // Token expiring within 60 seconds -> treated as expired (safety margin)
        let almost_expired = OAuthToken {
            access_token: "almost".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Some(Utc::now() + chrono::Duration::seconds(30)),
        };
        assert!(almost_expired.is_expired());

        // Token expiring in 120 seconds -> not expired (beyond safety margin)
        let safe_token = OAuthToken {
            access_token: "safe".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Some(Utc::now() + chrono::Duration::seconds(120)),
        };
        assert!(!safe_token.is_expired());
    }

    #[test]
    fn test_strip_html_edge_cases() {
        // Empty input
        assert_eq!(strip_html(""), "");

        // No HTML
        assert_eq!(strip_html("plain text"), "plain text");

        // Nested tags
        assert_eq!(
            strip_html("<div><p><b>bold</b></p></div>"),
            "\n\nbold\n\n"
        );

        // Unclosed tags
        assert_eq!(strip_html("<b>unclosed"), "unclosed");

        // Script tags (content visible but tag stripped)
        assert_eq!(
            strip_html("<script>alert(1)</script>"),
            "alert(1)"
        );

        // &nbsp; entity
        assert_eq!(strip_html("a&nbsp;b"), "a b");
    }

    #[test]
    fn test_decode_base64url() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"Hello, world!");
        assert_eq!(decode_base64url(&encoded), "Hello, world!");

        // Invalid base64 returns empty
        assert_eq!(decode_base64url("!!!invalid!!!"), "");
    }

    #[test]
    fn test_parse_gmail_message_basic() {
        use base64::Engine as _;

        let body_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"Hello from test");

        let raw = GmailMessageResponse {
            id: "msg-123".to_string(),
            thread_id: "thread-456".to_string(),
            internal_date: Some("1700000000000".to_string()),
            payload: Some(GmailPayload {
                headers: vec![
                    GmailHeader {
                        name: "From".to_string(),
                        value: "sender@example.com".to_string(),
                    },
                    GmailHeader {
                        name: "To".to_string(),
                        value: "recipient@example.com".to_string(),
                    },
                    GmailHeader {
                        name: "Subject".to_string(),
                        value: "Test Subject".to_string(),
                    },
                ],
                parts: vec![GmailPart {
                    mime_type: "text/plain".to_string(),
                    body: Some(GmailBody {
                        data: Some(body_data),
                    }),
                    parts: vec![],
                }],
                body: None,
            }),
        };

        let msg = parse_gmail_message(raw);
        assert_eq!(msg.id, "msg-123");
        assert_eq!(msg.thread_id, "thread-456");
        assert_eq!(msg.from, "sender@example.com");
        assert_eq!(msg.to, "recipient@example.com");
        assert_eq!(msg.subject, "Test Subject");
        assert_eq!(msg.body_text, "Hello from test");
    }

    #[test]
    fn test_read_client_secret_env() {
        let config = GmailConfig {
            client_id: "test".to_string(),
            client_secret_env: "AEGIS_TEST_GMAIL_SECRET_NONEXISTENT".to_string(),
            project_id: None,
            watch_labels: vec!["INBOX".to_string()],
            token_path: None,
        };

        // Should fail since the env var is not set
        let result = config.read_client_secret();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("AEGIS_TEST_GMAIL_SECRET_NONEXISTENT"));
    }
}
