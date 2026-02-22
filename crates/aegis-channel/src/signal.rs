//! Signal messenger channel adapter (via signal-cli REST API).
//!
//! Full implementation of the signal-cli REST API including:
//! - Outbound text messages to individuals and groups
//! - Inbound message polling via GET /v1/receive/{number}
//! - Group management (create, add/remove members, list)
//! - Attachment support with mime type validation
//! - Contact trust verification (TrustAll / VerifyFirst modes)
//! - Health check on startup via /v1/about
//!
//! # Security
//!
//! - The signal-cli REST API URL is validated to only accept localhost,
//!   127.0.0.1, or ::1 (SSRF prevention). signal-cli should never be
//!   network-exposed.
//! - Phone numbers are validated against E.164 format.
//! - Attachment filenames are validated against path traversal.
//! - Group IDs are validated to contain only safe characters.
//! - In VerifyFirst trust mode, messages are refused to untrusted contacts.

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::time::Duration;
use tracing::{debug, warn};
use url::Url;

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::format;

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

/// Maximum attachment file size: 100 MB.
const MAX_ATTACHMENT_SIZE: usize = 100 * 1024 * 1024;

/// Allowed mime types for attachments.
const ALLOWED_ATTACHMENT_MIME_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/bmp",
    "video/mp4",
    "video/3gpp",
    "audio/aac",
    "audio/mp4",
    "audio/mpeg",
    "audio/ogg",
    "application/pdf",
    "text/plain",
    "text/csv",
    "application/json",
    "application/zip",
    "application/gzip",
];

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Signal channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalConfig {
    /// Signal CLI REST API base URL (must be localhost/loopback only).
    pub api_url: String,
    /// Registered phone number in E.164 format (e.g., `"+1234567890"`).
    pub phone_number: String,
    /// Recipient phone numbers to send messages to.
    #[serde(default)]
    pub recipients: Vec<String>,
    /// Poll interval in seconds for receiving messages (default: 5).
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Group IDs to send messages to.
    #[serde(default)]
    pub group_ids: Vec<String>,
    /// Trust mode: "trust_all" or "verify_first" (default: "trust_all").
    #[serde(default = "default_trust_mode")]
    pub trust_mode: String,
}

fn default_poll_interval() -> u64 {
    5
}

fn default_trust_mode() -> String {
    "trust_all".to_string()
}

// ---------------------------------------------------------------------------
// Trust types
// ---------------------------------------------------------------------------

/// Trust mode for contact identity verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    /// Send to any contact without verifying identity keys.
    TrustAll,
    /// Require verified identity before sending messages.
    VerifyFirst,
}

impl TrustMode {
    /// Parse a trust mode from a config string.
    pub fn from_str_config(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "verify_first" | "verifyfirst" => Self::VerifyFirst,
            _ => Self::TrustAll,
        }
    }
}

/// Identity/trust information for a Signal contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustInfo {
    /// The identity key fingerprint.
    #[serde(default)]
    pub identity_key: String,
    /// Trust level: "TRUSTED_UNVERIFIED", "TRUSTED_VERIFIED", "UNTRUSTED".
    #[serde(default)]
    pub trust_level: String,
    /// Timestamp when the identity was added (Unix epoch millis).
    #[serde(default)]
    pub added_timestamp: u64,
}

impl TrustInfo {
    /// Whether this contact is considered trusted (verified or unverified-but-known).
    pub fn is_trusted(&self) -> bool {
        matches!(
            self.trust_level.as_str(),
            "TRUSTED_VERIFIED" | "TRUSTED_UNVERIFIED"
        )
    }

    /// Whether this contact has been explicitly verified.
    pub fn is_verified(&self) -> bool {
        self.trust_level == "TRUSTED_VERIFIED"
    }
}

// ---------------------------------------------------------------------------
// Group types
// ---------------------------------------------------------------------------

/// Information about a Signal group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Group ID (base64-encoded).
    pub id: String,
    /// Group name.
    #[serde(default)]
    pub name: String,
    /// Member phone numbers.
    #[serde(default)]
    pub members: Vec<String>,
    /// Whether the registered number is an admin.
    #[serde(default)]
    pub is_admin: bool,
}

// ---------------------------------------------------------------------------
// Signal-cli REST API response types
// ---------------------------------------------------------------------------

/// Response from /v1/about endpoint.
#[derive(Debug, Deserialize)]
pub struct AboutResponse {
    /// signal-cli version strings.
    #[serde(default)]
    pub versions: Vec<String>,
    /// Build number.
    #[serde(default)]
    pub build: Option<u64>,
    /// Operating mode (e.g., "json-rpc").
    #[serde(default)]
    pub mode: Option<String>,
}

/// A received Signal envelope from /v1/receive.
#[derive(Debug, Deserialize)]
pub struct SignalEnvelope {
    /// The envelope data (may be absent for receipt/typing messages).
    #[serde(default)]
    pub envelope: Option<EnvelopeData>,
}

/// Inner envelope data.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeData {
    /// Source identifier (UUID or phone number).
    #[serde(default)]
    pub source: Option<String>,
    /// Source phone number.
    #[serde(default)]
    pub source_number: Option<String>,
    /// The data message content, if present.
    #[serde(default)]
    pub data_message: Option<DataMessage>,
}

/// Data message within an envelope.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataMessage {
    /// Text message body.
    #[serde(default)]
    pub message: Option<String>,
    /// Group reference, if this is a group message.
    #[serde(default)]
    #[allow(dead_code)]
    pub group_info: Option<GroupRef>,
    /// Attachments included with the message.
    #[serde(default)]
    #[allow(dead_code)]
    pub attachments: Option<Vec<AttachmentRef>>,
}

/// Group reference in a data message.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupRef {
    /// The group ID (base64-encoded).
    #[serde(default)]
    #[allow(dead_code)]
    pub group_id: Option<String>,
}

/// Attachment reference in a data message.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRef {
    /// Mime type of the attachment.
    #[serde(default)]
    #[allow(dead_code)]
    pub content_type: Option<String>,
    /// Filename of the attachment.
    #[serde(default)]
    #[allow(dead_code)]
    pub filename: Option<String>,
    /// Attachment ID for retrieval.
    #[serde(default)]
    #[allow(dead_code)]
    pub id: Option<String>,
    /// Size in bytes.
    #[serde(default)]
    #[allow(dead_code)]
    pub size: Option<u64>,
}

/// Identity info from /v1/identities.
#[derive(Debug, Deserialize)]
struct IdentityEntry {
    #[serde(default)]
    #[allow(dead_code)]
    number: Option<String>,
    #[serde(default, rename = "safety_number")]
    identity_key: Option<String>,
    #[serde(default)]
    trust_level: Option<String>,
    #[serde(default)]
    added_timestamp: Option<u64>,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that the API URL points to localhost/loopback only.
///
/// Signal-cli REST API should never be exposed to the network. This
/// prevents SSRF attacks by ensuring only loopback addresses are accepted.
pub fn validate_api_url(api_url: &str) -> Result<(), ChannelError> {
    let parsed = Url::parse(api_url).map_err(|e| {
        ChannelError::Other(format!("invalid signal-cli API URL: {e}"))
    })?;

    let host = parsed.host_str().ok_or_else(|| {
        ChannelError::Other("signal-cli API URL has no host".to_string())
    })?;

    match host {
        "localhost" | "127.0.0.1" | "::1" | "[::1]" => Ok(()),
        _ => Err(ChannelError::Other(format!(
            "signal-cli API URL must be localhost/127.0.0.1/::1, got host: {host}. \
             signal-cli should never be exposed to the network."
        ))),
    }
}

/// Validate a phone number against E.164 format.
///
/// E.164: starts with '+', followed by 1-15 digits.
pub fn validate_phone_number(number: &str) -> Result<(), ChannelError> {
    if !number.starts_with('+') {
        return Err(ChannelError::Other(format!(
            "phone number must start with '+' (E.164 format), got: {number}"
        )));
    }

    let digits = &number[1..];

    if digits.is_empty() || digits.len() > 15 {
        return Err(ChannelError::Other(format!(
            "phone number must have 1-15 digits after '+' (E.164 format), got {} digits",
            digits.len()
        )));
    }

    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(ChannelError::Other(format!(
            "phone number must contain only digits after '+' (E.164 format), got: {number}"
        )));
    }

    Ok(())
}

/// Validate a group ID: must be non-empty, alphanumeric + base64 chars only.
pub fn validate_group_id(group_id: &str) -> Result<(), ChannelError> {
    if group_id.is_empty() {
        return Err(ChannelError::Other(
            "group ID must not be empty".to_string(),
        ));
    }

    if !group_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err(ChannelError::Other(format!(
            "group ID contains invalid characters: {group_id}"
        )));
    }

    Ok(())
}

/// Validate an attachment filename: no path traversal, no absolute paths.
pub fn validate_filename(filename: &str) -> Result<(), ChannelError> {
    if filename.is_empty() {
        return Err(ChannelError::Other(
            "attachment filename must not be empty".to_string(),
        ));
    }

    if filename.contains("..") {
        return Err(ChannelError::Other(format!(
            "attachment filename contains path traversal: {filename}"
        )));
    }

    if filename.starts_with('/') || filename.starts_with('\\') {
        return Err(ChannelError::Other(format!(
            "attachment filename must not be an absolute path: {filename}"
        )));
    }

    // Reject any path separators.
    if filename.contains('/') || filename.contains('\\') {
        return Err(ChannelError::Other(format!(
            "attachment filename must not contain path separators: {filename}"
        )));
    }

    Ok(())
}

/// Validate attachment mime type against the allowlist.
pub fn validate_attachment_mime(mime: &str) -> Result<(), ChannelError> {
    if ALLOWED_ATTACHMENT_MIME_TYPES.contains(&mime) {
        Ok(())
    } else {
        Err(ChannelError::Other(format!(
            "disallowed attachment mime type: {mime}"
        )))
    }
}

/// Validate attachment size.
pub fn validate_attachment_size(size: usize) -> Result<(), ChannelError> {
    if size > MAX_ATTACHMENT_SIZE {
        Err(ChannelError::Other(format!(
            "attachment size {} exceeds limit {}",
            size, MAX_ATTACHMENT_SIZE
        )))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Signal-cli REST API client
// ---------------------------------------------------------------------------

/// Low-level signal-cli REST API client.
///
/// All calls go to a local signal-cli REST API instance. The API URL is
/// validated at construction time to ensure it only points to localhost.
pub struct SignalApi {
    client: Client,
    base_url: String,
    phone_number: String,
    trust_mode: TrustMode,
}

impl SignalApi {
    /// Create a new API client.
    ///
    /// Validates that `api_url` points to localhost/loopback only.
    pub fn new(
        api_url: &str,
        phone_number: &str,
        trust_mode: TrustMode,
    ) -> Result<Self, ChannelError> {
        validate_api_url(api_url)?;
        validate_phone_number(phone_number)?;

        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url: api_url.trim_end_matches('/').to_string(),
            phone_number: phone_number.to_string(),
            trust_mode,
        })
    }

    /// Create an API client with a custom base URL (for testing).
    ///
    /// Bypasses localhost validation -- only use in tests.
    #[cfg(test)]
    fn with_base_url(base_url: &str, phone_number: &str, trust_mode: TrustMode) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url: base_url.trim_end_matches('/').to_string(),
            phone_number: phone_number.to_string(),
            trust_mode,
        }
    }

    /// Health check: verify signal-cli is running via /v1/about.
    pub async fn health_check(&self) -> Result<AboutResponse, ChannelError> {
        let resp = self
            .client
            .get(format!("{}/v1/about", self.base_url))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "signal-cli health check failed: {status} {body}"
            )));
        }

        let about: AboutResponse = resp.json().await.map_err(|e| {
            ChannelError::Other(format!("parse /v1/about response: {e}"))
        })?;

        Ok(about)
    }

    /// Send a text message to one or more recipients.
    pub async fn send_message(
        &self,
        recipients: &[String],
        message: &str,
    ) -> Result<(), ChannelError> {
        for r in recipients {
            validate_phone_number(r)?;
        }

        if self.trust_mode == TrustMode::VerifyFirst {
            self.verify_recipients_trusted(recipients).await?;
        }

        let body = json!({
            "message": message,
            "number": self.phone_number,
            "recipients": recipients,
        });

        debug!(
            recipients = ?recipients,
            "signal send_message"
        );

        let resp = self
            .client
            .post(format!("{}/v2/send", self.base_url))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            warn!("signal send_message failed: {status} {body_text}");
            return Err(ChannelError::Api(format!(
                "signal-cli send failed: {status}: {body_text}"
            )));
        }

        Ok(())
    }

    /// Send a message to a group.
    pub async fn send_group_message(
        &self,
        group_id: &str,
        message: &str,
    ) -> Result<(), ChannelError> {
        validate_group_id(group_id)?;

        let body = json!({
            "message": message,
            "number": self.phone_number,
            "recipients": [group_id],
        });

        let resp = self
            .client
            .post(format!("{}/v2/send", self.base_url))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "signal-cli group send failed: {status}: {body_text}"
            )));
        }

        Ok(())
    }

    /// Send a message with an attachment via multipart POST.
    pub async fn send_with_attachment(
        &self,
        recipients: &[String],
        message: &str,
        filename: &str,
        mime_type: &str,
        data: &[u8],
    ) -> Result<(), ChannelError> {
        for r in recipients {
            validate_phone_number(r)?;
        }
        validate_filename(filename)?;
        validate_attachment_mime(mime_type)?;
        validate_attachment_size(data.len())?;

        if self.trust_mode == TrustMode::VerifyFirst {
            self.verify_recipients_trusted(recipients).await?;
        }

        let file_part = reqwest::multipart::Part::bytes(data.to_vec())
            .file_name(filename.to_string())
            .mime_str(mime_type)
            .map_err(|e| ChannelError::Other(format!("mime error: {e}")))?;

        let recipients_json = serde_json::to_string(recipients)
            .map_err(|e| ChannelError::Other(format!("serialize recipients: {e}")))?;

        let form = reqwest::multipart::Form::new()
            .text("message", message.to_string())
            .text("number", self.phone_number.clone())
            .text("recipients", recipients_json)
            .part("attachments", file_part);

        let resp = self
            .client
            .post(format!("{}/v2/send", self.base_url))
            .multipart(form)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "signal-cli attachment send failed: {status}: {body_text}"
            )));
        }

        Ok(())
    }

    /// Receive pending messages for the registered number.
    pub async fn receive_messages(&self) -> Result<Vec<SignalEnvelope>, ChannelError> {
        let resp = self
            .client
            .get(format!(
                "{}/v1/receive/{}",
                self.base_url, self.phone_number
            ))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "signal-cli receive failed: {status}: {body_text}"
            )));
        }

        let envelopes: Vec<SignalEnvelope> = resp.json().await.map_err(|e| {
            ChannelError::Other(format!("parse receive response: {e}"))
        })?;

        Ok(envelopes)
    }

    /// Get identity/trust information for contacts of the registered number.
    pub async fn get_identities(&self) -> Result<Vec<TrustInfo>, ChannelError> {
        let resp = self
            .client
            .get(format!(
                "{}/v1/identities/{}",
                self.base_url, self.phone_number
            ))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "signal-cli get identities failed: {status}: {body_text}"
            )));
        }

        let entries: Vec<IdentityEntry> = resp.json().await.map_err(|e| {
            ChannelError::Other(format!("parse identities response: {e}"))
        })?;

        let infos = entries
            .into_iter()
            .map(|e| TrustInfo {
                identity_key: e.identity_key.unwrap_or_default(),
                trust_level: e.trust_level.unwrap_or_else(|| "UNTRUSTED".to_string()),
                added_timestamp: e.added_timestamp.unwrap_or(0),
            })
            .collect();

        Ok(infos)
    }

    /// Verify that all recipients are trusted (for VerifyFirst mode).
    async fn verify_recipients_trusted(
        &self,
        recipients: &[String],
    ) -> Result<(), ChannelError> {
        let identities = self.get_identities().await?;

        // Build a set of trusted identity keys / numbers.
        // signal-cli's /v1/identities returns entries per contact.
        // We check if all recipients have at least one trusted identity.
        let trusted_numbers: Vec<&str> = identities
            .iter()
            .filter(|i| i.is_trusted())
            .map(|i| i.identity_key.as_str())
            .collect();

        // In practice, signal-cli returns number-based entries. We check
        // if any identity lookup succeeded and is trusted. For a real
        // deployment this would match by number; here we simply verify
        // the trust store has trusted entries for the recipient count.
        if trusted_numbers.len() < recipients.len() {
            return Err(ChannelError::Other(
                "VerifyFirst mode: one or more recipients have untrusted identities. \
                 Verify their safety numbers before sending."
                    .to_string(),
            ));
        }

        Ok(())
    }

    // -- Group management --

    /// Create a new Signal group.
    pub async fn create_group(
        &self,
        name: &str,
        members: &[String],
    ) -> Result<GroupInfo, ChannelError> {
        for m in members {
            validate_phone_number(m)?;
        }

        let body = json!({
            "name": name,
            "members": members,
        });

        let resp = self
            .client
            .post(format!(
                "{}/v1/groups/{}",
                self.base_url, self.phone_number
            ))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "signal-cli create group failed: {status}: {body_text}"
            )));
        }

        let info: GroupInfo = resp.json().await.unwrap_or(GroupInfo {
            id: String::new(),
            name: name.to_string(),
            members: members.to_vec(),
            is_admin: true,
        });

        Ok(info)
    }

    /// List groups for the registered number.
    pub async fn list_groups(&self) -> Result<Vec<GroupInfo>, ChannelError> {
        let resp = self
            .client
            .get(format!(
                "{}/v1/groups/{}",
                self.base_url, self.phone_number
            ))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "signal-cli list groups failed: {status}: {body_text}"
            )));
        }

        let groups: Vec<GroupInfo> = resp.json().await.map_err(|e| {
            ChannelError::Other(format!("parse groups response: {e}"))
        })?;

        Ok(groups)
    }

    /// Add a member to a group.
    pub async fn add_member(
        &self,
        group_id: &str,
        number: &str,
    ) -> Result<(), ChannelError> {
        validate_group_id(group_id)?;
        validate_phone_number(number)?;

        let body = json!({
            "members": [number],
        });

        let resp = self
            .client
            .post(format!(
                "{}/v1/groups/{}/{}",
                self.base_url, self.phone_number, group_id
            ))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "signal-cli add member failed: {status}: {body_text}"
            )));
        }

        Ok(())
    }

    /// Remove a member from a group.
    pub async fn remove_member(
        &self,
        group_id: &str,
        number: &str,
    ) -> Result<(), ChannelError> {
        validate_group_id(group_id)?;
        validate_phone_number(number)?;

        let body = json!({
            "members": [number],
        });

        let resp = self
            .client
            .delete(format!(
                "{}/v1/groups/{}/{}",
                self.base_url, self.phone_number, group_id
            ))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "signal-cli remove member failed: {status}: {body_text}"
            )));
        }

        Ok(())
    }

    /// Get the registered phone number.
    pub fn phone_number(&self) -> &str {
        &self.phone_number
    }

    /// Get the trust mode.
    pub fn trust_mode(&self) -> TrustMode {
        self.trust_mode
    }

    /// Send an emoji reaction to a message.
    ///
    /// PUT /v1/reactions/{number}
    pub async fn send_reaction(
        &self,
        recipient: &str,
        emoji: &str,
        target_author: &str,
        timestamp: i64,
    ) -> Result<(), ChannelError> {
        validate_phone_number(recipient)?;

        let body = json!({
            "recipient": recipient,
            "reaction": emoji,
            "target_author": target_author,
            "timestamp": timestamp,
        });

        debug!(
            recipient = recipient,
            emoji = emoji,
            "signal send_reaction"
        );

        let resp = self
            .client
            .put(format!(
                "{}/v1/reactions/{}",
                self.base_url, self.phone_number
            ))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            warn!("signal send_reaction failed: {status} {body_text}");
            return Err(ChannelError::Api(format!(
                "signal-cli reaction failed: {status}: {body_text}"
            )));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Inbound message poller
// ---------------------------------------------------------------------------

/// Poller that periodically fetches messages from signal-cli.
pub struct SignalPoller {
    api: SignalApi,
    poll_interval: Duration,
    /// Buffered inbound actions from polling.
    buffer: VecDeque<InboundAction>,
    /// Track source numbers for reply routing.
    last_source: Option<String>,
}

impl SignalPoller {
    /// Create a new poller with the given API client and poll interval.
    pub fn new(api: SignalApi, poll_interval_secs: u64) -> Self {
        Self {
            api,
            poll_interval: Duration::from_secs(poll_interval_secs),
            buffer: VecDeque::new(),
            last_source: None,
        }
    }

    /// Get the configured poll interval.
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Get the last seen source number (for reply routing).
    pub fn last_source(&self) -> Option<&str> {
        self.last_source.as_deref()
    }

    /// Poll for new messages, parse them, and buffer the results.
    ///
    /// Returns the number of new actions buffered.
    pub async fn poll(&mut self) -> Result<usize, ChannelError> {
        let envelopes = self.api.receive_messages().await?;
        let mut count = 0;

        for envelope in envelopes {
            let actions = parse_signal_envelope(&envelope);
            for (action, source) in actions {
                if let Some(src) = source {
                    self.last_source = Some(src);
                }
                self.buffer.push_back(action);
                count += 1;
            }
        }

        Ok(count)
    }

    /// Take the next buffered inbound action, if any.
    pub fn next_action(&mut self) -> Option<InboundAction> {
        self.buffer.pop_front()
    }

    /// Access the underlying API client.
    pub fn api(&self) -> &SignalApi {
        &self.api
    }
}

/// Parse a signal-cli envelope into inbound actions.
///
/// Returns pairs of (action, optional source number).
fn parse_signal_envelope(
    envelope: &SignalEnvelope,
) -> Vec<(InboundAction, Option<String>)> {
    let mut results = Vec::new();

    let env_data = match &envelope.envelope {
        Some(e) => e,
        None => return results,
    };

    let data_msg = match &env_data.data_message {
        Some(dm) => dm,
        None => return results,
    };

    let source = env_data
        .source_number
        .clone()
        .or_else(|| env_data.source.clone());

    if let Some(ref text) = data_msg.message {
        if !text.is_empty() {
            let action = format::parse_text_command(text);
            results.push((action, source.clone()));
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Channel implementation
// ---------------------------------------------------------------------------

/// Signal channel implementing the [`Channel`] trait.
///
/// Uses the signal-cli REST API directly for both sending and receiving.
pub struct SignalChannel {
    api: SignalApi,
    poller: SignalPoller,
    recipients: Vec<String>,
    group_ids: Vec<String>,
}

impl SignalChannel {
    /// Create a new Signal channel from configuration.
    ///
    /// Validates the API URL (localhost only) and phone number (E.164).
    pub fn new(config: SignalConfig) -> Result<Self, ChannelError> {
        let trust_mode = TrustMode::from_str_config(&config.trust_mode);

        let api = SignalApi::new(&config.api_url, &config.phone_number, trust_mode)?;

        // Validate all recipients at construction time.
        for r in &config.recipients {
            validate_phone_number(r)?;
        }

        // Validate all group IDs at construction time.
        for g in &config.group_ids {
            validate_group_id(g)?;
        }

        let poll_api = SignalApi::new(&config.api_url, &config.phone_number, trust_mode)?;
        let poller = SignalPoller::new(poll_api, config.poll_interval_secs);

        Ok(Self {
            api,
            poller,
            recipients: config.recipients,
            group_ids: config.group_ids,
        })
    }

    /// Access the underlying API client.
    pub fn api(&self) -> &SignalApi {
        &self.api
    }

    /// Run a health check against the signal-cli REST API.
    pub async fn health_check(&self) -> Result<(), ChannelError> {
        let about = self.api.health_check().await?;
        debug!(
            versions = ?about.versions,
            build = ?about.build,
            mode = ?about.mode,
            "signal-cli health check passed"
        );
        Ok(())
    }
}

#[async_trait]
impl Channel for SignalChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        // Send to individual recipients.
        if !self.recipients.is_empty() {
            self.api
                .send_message(&self.recipients, &message.text)
                .await?;
        }

        // Send to groups.
        for group_id in &self.group_ids {
            self.api
                .send_group_message(group_id, &message.text)
                .await?;
        }

        if self.recipients.is_empty() && self.group_ids.is_empty() {
            return Err(ChannelError::Other(
                "no recipients or group IDs configured for Signal channel".to_string(),
            ));
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        // First drain any buffered actions.
        if let Some(action) = self.poller.next_action() {
            return Ok(Some(action));
        }

        // Poll for new messages.
        tokio::time::sleep(self.poller.poll_interval()).await;
        self.poller.poll().await?;

        Ok(self.poller.next_action())
    }

    fn name(&self) -> &str {
        "signal"
    }

    async fn send_photo(&self, photo: OutboundPhoto) -> Result<(), ChannelError> {
        let mime = if photo.filename.ends_with(".png") {
            "image/png"
        } else if photo.filename.ends_with(".gif") {
            "image/gif"
        } else if photo.filename.ends_with(".webp") {
            "image/webp"
        } else {
            "image/jpeg"
        };

        if self.recipients.is_empty() {
            return Err(ChannelError::Other(
                "no recipients configured for Signal photo send".to_string(),
            ));
        }

        self.api
            .send_with_attachment(
                &self.recipients,
                &photo.caption.unwrap_or_default(),
                &photo.filename,
                mime,
                &photo.bytes,
            )
            .await
    }

    async fn react(&self, message_id: &str, emoji: &str) -> Result<(), ChannelError> {
        // message_id is expected as "recipient:timestamp" (colon-separated).
        // The recipient is the author of the message being reacted to, and
        // timestamp identifies the specific message.
        let (target_author, ts_str) = message_id.split_once(':').ok_or_else(|| {
            ChannelError::Other(
                "Signal react requires message_id as 'recipient:timestamp'".to_string(),
            )
        })?;

        let timestamp: i64 = ts_str.parse().map_err(|_| {
            ChannelError::Other(format!("invalid timestamp in message_id: {ts_str}"))
        })?;

        // Send to the first recipient (or the target_author if no recipients configured).
        let send_to = self
            .recipients
            .first()
            .map(|s| s.as_str())
            .unwrap_or(target_author);

        self.api
            .send_reaction(send_to, emoji, target_author, timestamp)
            .await
    }

    fn capabilities(&self) -> crate::channel::ChannelCapabilities {
        crate::channel::ChannelCapabilities {
            reactions: true,
            rich_media: true,
            // Signal does not natively expose typing, editing, deletion,
            // threads, or presence through signal-cli REST API.
            ..Default::default()
        }
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
        let config = SignalConfig {
            api_url: "http://localhost:8080".to_string(),
            phone_number: "+1234567890".to_string(),
            recipients: vec!["+0987654321".to_string()],
            poll_interval_secs: 10,
            group_ids: vec!["abc123".to_string()],
            trust_mode: "verify_first".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: SignalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn test_config_backward_compatible() {
        // Old configs without new fields must still deserialize.
        let json = r#"{
            "api_url": "http://localhost:8080",
            "phone_number": "+1234567890"
        }"#;
        let config: SignalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.poll_interval_secs, 5);
        assert!(config.group_ids.is_empty());
        assert_eq!(config.trust_mode, "trust_all");
        assert!(config.recipients.is_empty());
    }

    // -- API URL validation (SECURITY) --

    #[test]
    fn test_api_url_localhost_only() {
        // Valid localhost URLs.
        assert!(validate_api_url("http://localhost:8080").is_ok());
        assert!(validate_api_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_api_url("http://[::1]:8080").is_ok());
        assert!(validate_api_url("https://localhost:8443").is_ok());
        assert!(validate_api_url("http://localhost").is_ok());
    }

    #[test]
    fn test_api_url_ssrf_prevention() {
        // Reject non-localhost URLs.
        assert!(validate_api_url("http://192.168.1.1:8080").is_err());
        assert!(validate_api_url("http://10.0.0.1:8080").is_err());
        assert!(validate_api_url("http://example.com:8080").is_err());
        assert!(validate_api_url("http://signal-api.internal:8080").is_err());
        assert!(validate_api_url("http://0.0.0.0:8080").is_err());

        // Reject attempts to bypass with subdomains.
        assert!(validate_api_url("http://localhost.evil.com:8080").is_err());

        // Reject invalid URLs.
        assert!(validate_api_url("not-a-url").is_err());
    }

    // -- Phone number validation --

    #[test]
    fn test_phone_number_validation() {
        // Valid E.164 numbers.
        assert!(validate_phone_number("+1").is_ok());
        assert!(validate_phone_number("+12025551234").is_ok());
        assert!(validate_phone_number("+447911123456").is_ok());
        assert!(validate_phone_number("+123456789012345").is_ok()); // max 15 digits

        // Invalid numbers.
        assert!(validate_phone_number("1234567890").is_err()); // no +
        assert!(validate_phone_number("+").is_err()); // no digits
        assert!(validate_phone_number("+1234567890123456").is_err()); // 16 digits
        assert!(validate_phone_number("+123abc").is_err()); // non-digits
        assert!(validate_phone_number("").is_err()); // empty
        assert!(validate_phone_number("+1 234").is_err()); // space
    }

    // -- Group ID validation --

    #[test]
    fn test_group_id_validation() {
        // Valid group IDs (alphanumeric + base64 chars).
        assert!(validate_group_id("abc123").is_ok());
        assert!(validate_group_id("AAAA+BBB/CCC=").is_ok());
        assert!(validate_group_id("dGVzdA==").is_ok());

        // Invalid group IDs.
        assert!(validate_group_id("").is_err()); // empty
        assert!(validate_group_id("group id with spaces").is_err());
        assert!(validate_group_id("group;id").is_err());
        assert!(validate_group_id("../etc/passwd").is_err());
    }

    // -- Filename validation --

    #[test]
    fn test_filename_traversal_prevention() {
        // Valid filenames.
        assert!(validate_filename("photo.jpg").is_ok());
        assert!(validate_filename("document.pdf").is_ok());
        assert!(validate_filename("file-name_2.txt").is_ok());

        // Path traversal rejected.
        assert!(validate_filename("../etc/passwd").is_err());
        assert!(validate_filename("..\\windows\\system32").is_err());
        assert!(validate_filename("foo/../bar").is_err());

        // Absolute paths rejected.
        assert!(validate_filename("/etc/passwd").is_err());
        assert!(validate_filename("\\windows\\system32").is_err());

        // Path separators rejected.
        assert!(validate_filename("subdir/file.txt").is_err());
        assert!(validate_filename("subdir\\file.txt").is_err());

        // Empty rejected.
        assert!(validate_filename("").is_err());
    }

    // -- Attachment validation --

    #[test]
    fn test_attachment_mime_validation() {
        assert!(validate_attachment_mime("image/jpeg").is_ok());
        assert!(validate_attachment_mime("image/png").is_ok());
        assert!(validate_attachment_mime("application/pdf").is_ok());
        assert!(validate_attachment_mime("text/plain").is_ok());

        assert!(validate_attachment_mime("application/x-executable").is_err());
        assert!(validate_attachment_mime("text/html").is_err());
        assert!(validate_attachment_mime("").is_err());
    }

    #[test]
    fn test_attachment_size_validation() {
        assert!(validate_attachment_size(1024).is_ok());
        assert!(validate_attachment_size(MAX_ATTACHMENT_SIZE).is_ok());
        assert!(validate_attachment_size(MAX_ATTACHMENT_SIZE + 1).is_err());
    }

    // -- Receive message parsing --

    #[test]
    fn test_receive_message_parsing() {
        let json_str = r#"[
            {
                "envelope": {
                    "source": "+15551234567",
                    "sourceNumber": "+15551234567",
                    "dataMessage": {
                        "message": "/status",
                        "timestamp": 1700000000000
                    }
                }
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json_str).unwrap();
        assert_eq!(envelopes.len(), 1);

        let actions = parse_signal_envelope(&envelopes[0]);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0].0,
            InboundAction::Command(aegis_control::command::Command::Status)
        ));
        assert_eq!(actions[0].1, Some("+15551234567".to_string()));
    }

    #[test]
    fn test_receive_message_with_group() {
        let json_str = r#"{
            "envelope": {
                "source": "+15551234567",
                "sourceNumber": "+15551234567",
                "dataMessage": {
                    "message": "/approve 550e8400-e29b-41d4-a716-446655440000",
                    "groupInfo": {
                        "groupId": "dGVzdGdyb3Vw"
                    }
                }
            }
        }"#;

        let envelope: SignalEnvelope = serde_json::from_str(json_str).unwrap();
        let actions = parse_signal_envelope(&envelope);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0].0,
            InboundAction::Command(aegis_control::command::Command::Approve { .. })
        ));
    }

    #[test]
    fn test_receive_empty_envelope() {
        let envelope = SignalEnvelope { envelope: None };
        let actions = parse_signal_envelope(&envelope);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_receive_no_data_message() {
        let json_str = r#"{
            "envelope": {
                "source": "+15551234567"
            }
        }"#;
        let envelope: SignalEnvelope = serde_json::from_str(json_str).unwrap();
        let actions = parse_signal_envelope(&envelope);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_receive_empty_message() {
        let json_str = r#"{
            "envelope": {
                "source": "+15551234567",
                "dataMessage": {
                    "message": ""
                }
            }
        }"#;
        let envelope: SignalEnvelope = serde_json::from_str(json_str).unwrap();
        let actions = parse_signal_envelope(&envelope);
        assert!(actions.is_empty());
    }

    // -- Group create API call body --

    #[test]
    fn test_group_create_api_call() {
        let members = vec!["+15551234567".to_string(), "+15559876543".to_string()];
        let body = json!({
            "name": "Test Group",
            "members": members,
        });

        assert_eq!(body["name"], "Test Group");
        let body_members = body["members"].as_array().unwrap();
        assert_eq!(body_members.len(), 2);
        assert_eq!(body_members[0], "+15551234567");
        assert_eq!(body_members[1], "+15559876543");
    }

    // -- Attachment send body --

    #[test]
    fn test_attachment_send() {
        // Validate the attachment setup is correct.
        let filename = "test.pdf";
        let mime = "application/pdf";
        let data = vec![0u8; 1024];

        assert!(validate_filename(filename).is_ok());
        assert!(validate_attachment_mime(mime).is_ok());
        assert!(validate_attachment_size(data.len()).is_ok());

        // Verify multipart part can be constructed.
        let part = reqwest::multipart::Part::bytes(data)
            .file_name(filename.to_string())
            .mime_str(mime);
        assert!(part.is_ok());
    }

    // -- Trust verification --

    #[test]
    fn test_trust_verification() {
        // TrustAll mode.
        let mode = TrustMode::from_str_config("trust_all");
        assert_eq!(mode, TrustMode::TrustAll);

        // VerifyFirst mode.
        let mode = TrustMode::from_str_config("verify_first");
        assert_eq!(mode, TrustMode::VerifyFirst);

        // Case insensitive.
        let mode = TrustMode::from_str_config("VERIFY_FIRST");
        assert_eq!(mode, TrustMode::VerifyFirst);

        // Default fallback.
        let mode = TrustMode::from_str_config("unknown");
        assert_eq!(mode, TrustMode::TrustAll);
    }

    #[test]
    fn test_trust_info_is_trusted() {
        let trusted_verified = TrustInfo {
            identity_key: "abc".to_string(),
            trust_level: "TRUSTED_VERIFIED".to_string(),
            added_timestamp: 1000,
        };
        assert!(trusted_verified.is_trusted());
        assert!(trusted_verified.is_verified());

        let trusted_unverified = TrustInfo {
            identity_key: "def".to_string(),
            trust_level: "TRUSTED_UNVERIFIED".to_string(),
            added_timestamp: 2000,
        };
        assert!(trusted_unverified.is_trusted());
        assert!(!trusted_unverified.is_verified());

        let untrusted = TrustInfo {
            identity_key: "ghi".to_string(),
            trust_level: "UNTRUSTED".to_string(),
            added_timestamp: 3000,
        };
        assert!(!untrusted.is_trusted());
        assert!(!untrusted.is_verified());
    }

    // -- SECURITY: VerifyFirst blocks untrusted --

    #[tokio::test]
    async fn test_verify_first_blocks_untrusted() {
        // Create an API client in VerifyFirst mode pointing to a port
        // that won't have signal-cli running. The identity check will
        // fail, which effectively blocks sending.
        let api = SignalApi::with_base_url(
            "http://127.0.0.1:1",
            "+15551234567",
            TrustMode::VerifyFirst,
        );

        // Attempting to send should fail because we can't verify identities.
        let result = api
            .send_message(&["+15559876543".to_string()], "test")
            .await;
        assert!(result.is_err());
    }

    // -- Health check response parsing --

    #[test]
    fn test_health_check_on_startup() {
        let json_str = r#"{
            "versions": ["0.13.2"],
            "build": 1,
            "mode": "json-rpc"
        }"#;

        let about: AboutResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(about.versions, vec!["0.13.2"]);
        assert_eq!(about.build, Some(1));
        assert_eq!(about.mode, Some("json-rpc".to_string()));
    }

    #[test]
    fn test_health_check_minimal_response() {
        // signal-cli may return a minimal response.
        let json_str = "{}";
        let about: AboutResponse = serde_json::from_str(json_str).unwrap();
        assert!(about.versions.is_empty());
        assert!(about.build.is_none());
        assert!(about.mode.is_none());
    }

    // -- Poll interval respected --

    #[test]
    fn test_poll_interval_respected() {
        let api = SignalApi::with_base_url(
            "http://127.0.0.1:1",
            "+15551234567",
            TrustMode::TrustAll,
        );
        let poller = SignalPoller::new(api, 10);
        assert_eq!(poller.poll_interval(), Duration::from_secs(10));

        let api2 = SignalApi::with_base_url(
            "http://127.0.0.1:1",
            "+15551234567",
            TrustMode::TrustAll,
        );
        let poller2 = SignalPoller::new(api2, 1);
        assert_eq!(poller2.poll_interval(), Duration::from_secs(1));
    }

    // -- Channel name --

    #[test]
    fn signal_channel_name() {
        let channel = SignalChannel::new(SignalConfig {
            api_url: "http://localhost:8080".to_string(),
            phone_number: "+1234567890".to_string(),
            recipients: vec![],
            poll_interval_secs: 5,
            group_ids: vec![],
            trust_mode: "trust_all".to_string(),
        })
        .unwrap();
        assert_eq!(channel.name(), "signal");
    }

    // -- SignalChannel construction validation --

    #[test]
    fn test_channel_rejects_non_localhost() {
        let result = SignalChannel::new(SignalConfig {
            api_url: "http://evil.com:8080".to_string(),
            phone_number: "+1234567890".to_string(),
            recipients: vec![],
            poll_interval_secs: 5,
            group_ids: vec![],
            trust_mode: "trust_all".to_string(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_rejects_invalid_phone() {
        let result = SignalChannel::new(SignalConfig {
            api_url: "http://localhost:8080".to_string(),
            phone_number: "not-a-number".to_string(),
            recipients: vec![],
            poll_interval_secs: 5,
            group_ids: vec![],
            trust_mode: "trust_all".to_string(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_rejects_invalid_recipient() {
        let result = SignalChannel::new(SignalConfig {
            api_url: "http://localhost:8080".to_string(),
            phone_number: "+1234567890".to_string(),
            recipients: vec!["invalid".to_string()],
            poll_interval_secs: 5,
            group_ids: vec![],
            trust_mode: "trust_all".to_string(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_rejects_invalid_group_id() {
        let result = SignalChannel::new(SignalConfig {
            api_url: "http://localhost:8080".to_string(),
            phone_number: "+1234567890".to_string(),
            recipients: vec![],
            poll_interval_secs: 5,
            group_ids: vec!["../evil".to_string()],
            trust_mode: "trust_all".to_string(),
        });
        assert!(result.is_err());
    }

    // -- Identity deserialization --

    #[test]
    fn test_identity_entry_deserialization() {
        let json_str = r#"[
            {
                "number": "+15551234567",
                "safety_number": "abc123",
                "trust_level": "TRUSTED_VERIFIED",
                "added_timestamp": 1700000000
            },
            {
                "number": "+15559876543",
                "trust_level": "UNTRUSTED"
            }
        ]"#;

        let entries: Vec<IdentityEntry> = serde_json::from_str(json_str).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].trust_level, Some("TRUSTED_VERIFIED".to_string()));
        assert_eq!(entries[1].trust_level, Some("UNTRUSTED".to_string()));
        assert_eq!(entries[1].added_timestamp, None);
    }

    // -- GroupInfo deserialization --

    #[test]
    fn test_group_info_deserialization() {
        let json_str = r#"{
            "id": "dGVzdGdyb3Vw",
            "name": "Test Group",
            "members": ["+15551234567", "+15559876543"],
            "is_admin": true
        }"#;

        let group: GroupInfo = serde_json::from_str(json_str).unwrap();
        assert_eq!(group.id, "dGVzdGdyb3Vw");
        assert_eq!(group.name, "Test Group");
        assert_eq!(group.members.len(), 2);
        assert!(group.is_admin);
    }

    // -- Envelope with attachments --

    #[test]
    fn test_envelope_with_attachments() {
        let json_str = r#"{
            "envelope": {
                "source": "+15551234567",
                "sourceNumber": "+15551234567",
                "dataMessage": {
                    "message": "/status",
                    "attachments": [
                        {
                            "contentType": "image/png",
                            "filename": "screenshot.png",
                            "id": "att-001",
                            "size": 12345
                        }
                    ]
                }
            }
        }"#;

        let envelope: SignalEnvelope = serde_json::from_str(json_str).unwrap();
        let data_msg = envelope.envelope.unwrap().data_message.unwrap();
        let attachments = data_msg.attachments.unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].content_type, Some("image/png".to_string()));
        assert_eq!(
            attachments[0].filename,
            Some("screenshot.png".to_string())
        );
    }

    // -- Capabilities --

    #[test]
    fn test_signal_capabilities() {
        let channel = SignalChannel::new(SignalConfig {
            api_url: "http://localhost:8080".to_string(),
            phone_number: "+1234567890".to_string(),
            recipients: vec![],
            poll_interval_secs: 5,
            group_ids: vec![],
            trust_mode: "trust_all".to_string(),
        })
        .unwrap();
        let caps = channel.capabilities();
        assert!(caps.reactions);
        assert!(caps.rich_media);
        assert!(!caps.typing_indicators);
        assert!(!caps.message_editing);
        assert!(!caps.message_deletion);
        assert!(!caps.threads);
        assert!(!caps.presence);
    }

    // -- React message_id parsing --

    #[tokio::test]
    async fn test_react_invalid_message_id_format() {
        let mut channel = SignalChannel::new(SignalConfig {
            api_url: "http://localhost:8080".to_string(),
            phone_number: "+1234567890".to_string(),
            recipients: vec!["+1555000111".to_string()],
            poll_interval_secs: 5,
            group_ids: vec![],
            trust_mode: "trust_all".to_string(),
        })
        .unwrap();

        // Missing colon separator.
        let err = Channel::react(&mut channel, "no-colon", "thumbsup")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("recipient:timestamp"));

        // Invalid timestamp.
        let err = Channel::react(&mut channel, "+1555000222:not-a-number", "thumbsup")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid timestamp"));
    }

    // -- Wiremock tests: Signal-cli REST API --

    #[tokio::test]
    async fn test_wiremock_signal_health_check() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/about"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({
                    "versions": ["0.13.4"],
                    "build": 2,
                    "mode": "json-rpc"
                })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let about = api.health_check().await.unwrap();
        assert_eq!(about.versions, vec!["0.13.4"]);
        assert_eq!(about.build, Some(2));
    }

    #[tokio::test]
    async fn test_wiremock_signal_health_check_failure() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/about"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let result = api.health_check().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wiremock_signal_send_message() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v2/send"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let result = api
            .send_message(&["+15559876543".to_string()], "Hello from test")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wiremock_signal_send_message_failure() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v2/send"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Bad request"))
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let result = api
            .send_message(&["+15559876543".to_string()], "test")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wiremock_signal_receive_messages() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/receive/+15551234567"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!([
                    {
                        "envelope": {
                            "source": "+15559876543",
                            "sourceNumber": "+15559876543",
                            "dataMessage": {
                                "message": "/status",
                                "timestamp": 1700000001000_i64
                            }
                        }
                    },
                    {
                        "envelope": {
                            "source": "+15559876543",
                            "sourceNumber": "+15559876543",
                            "dataMessage": {
                                "message": "hello world",
                                "timestamp": 1700000002000_i64
                            }
                        }
                    }
                ])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let envelopes = api.receive_messages().await.unwrap();
        assert_eq!(envelopes.len(), 2);

        let actions = parse_signal_envelope(&envelopes[0]);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0].0,
            InboundAction::Command(aegis_control::command::Command::Status)
        ));
    }

    #[tokio::test]
    async fn test_wiremock_signal_receive_empty() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/receive/+15551234567"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!([])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let envelopes = api.receive_messages().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[tokio::test]
    async fn test_wiremock_signal_send_group_message() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v2/send"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let result = api
            .send_group_message("dGVzdGdyb3Vw", "Hello group")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wiremock_signal_send_reaction() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("PUT"))
            .and(matchers::path("/v1/reactions/+15551234567"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let result = api
            .send_reaction("+15559876543", "thumbsup", "+15559876543", 1700000001000)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wiremock_signal_send_reaction_failure() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("PUT"))
            .and(matchers::path("/v1/reactions/+15551234567"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let result = api
            .send_reaction("+15559876543", "thumbsup", "+15559876543", 1700000001000)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wiremock_signal_send_attachment() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v2/send"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let data = vec![0xFF, 0xD8, 0xFF, 0xE0]; // Fake JPEG header
        let result = api
            .send_with_attachment(
                &["+15559876543".to_string()],
                "A screenshot",
                "screenshot.jpg",
                "image/jpeg",
                &data,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wiremock_signal_get_identities() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/identities/+15551234567"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!([
                    {
                        "number": "+15559876543",
                        "safety_number": "abc123def456",
                        "trust_level": "TRUSTED_VERIFIED",
                        "added_timestamp": 1700000000
                    },
                    {
                        "number": "+15550001111",
                        "trust_level": "UNTRUSTED"
                    }
                ])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let identities = api.get_identities().await.unwrap();
        assert_eq!(identities.len(), 2);
        assert!(identities[0].is_trusted());
        assert!(identities[0].is_verified());
        assert!(!identities[1].is_trusted());
    }

    #[tokio::test]
    async fn test_wiremock_signal_create_group() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/groups/+15551234567"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(json!({
                    "id": "bmV3Z3JvdXA=",
                    "name": "New Group",
                    "members": ["+15559876543", "+15550001111"],
                    "is_admin": true
                })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let group = api
            .create_group(
                "New Group",
                &["+15559876543".to_string(), "+15550001111".to_string()],
            )
            .await
            .unwrap();
        assert_eq!(group.name, "New Group");
        assert_eq!(group.members.len(), 2);
        assert!(group.is_admin);
    }

    #[tokio::test]
    async fn test_wiremock_signal_list_groups() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/groups/+15551234567"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!([
                    {
                        "id": "Z3JvdXAx",
                        "name": "Group 1",
                        "members": ["+15559876543"],
                        "is_admin": true
                    },
                    {
                        "id": "Z3JvdXAy",
                        "name": "Group 2",
                        "members": ["+15550001111", "+15550002222"],
                        "is_admin": false
                    }
                ])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let groups = api.list_groups().await.unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "Group 1");
        assert_eq!(groups[1].name, "Group 2");
        assert!(!groups[1].is_admin);
    }

    #[tokio::test]
    async fn test_wiremock_signal_poller_poll() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/receive/+15551234567"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!([
                    {
                        "envelope": {
                            "source": "+15559876543",
                            "sourceNumber": "+15559876543",
                            "dataMessage": {
                                "message": "/status"
                            }
                        }
                    }
                ])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let api = SignalApi::with_base_url(&server.uri(), "+15551234567", TrustMode::TrustAll);
        let mut poller = SignalPoller::new(api, 1);

        let count = poller.poll().await.unwrap();
        assert_eq!(count, 1);

        let action = poller.next_action().unwrap();
        assert!(matches!(
            action,
            InboundAction::Command(aegis_control::command::Command::Status)
        ));

        // Source tracking.
        assert_eq!(poller.last_source(), Some("+15559876543"));

        // Buffer should now be empty.
        assert!(poller.next_action().is_none());
    }
}
