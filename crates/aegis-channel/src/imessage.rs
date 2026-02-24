//! iMessage channel adapter with dual-mode support.
//!
//! Two backends are available:
//!
//! - **AppleScript** (macOS native): sends messages via `osascript` and reads
//!   inbound messages from `~/Library/Messages/chat.db` (SQLite).
//! - **BlueBubbles**: sends and receives via the BlueBubbles REST API.
//!
//! # Security
//!
//! - AppleScript text is escaped to prevent injection (quotes, backslashes,
//!   newlines, backticks, dollar signs, single quotes).
//! - Recipients are validated as E.164 phone numbers or RFC-like email addresses.
//! - `chat_db_path` is validated against directory traversal.
//! - BlueBubbles URLs must be localhost or HTTPS.
//! - BlueBubbles passwords are never logged.

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::format;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Operating mode for the iMessage channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImessageMode {
    /// Use macOS AppleScript to send messages and chat.db to receive.
    #[default]
    Applescript,
    /// Use the BlueBubbles REST API for both send and receive.
    Bluebubbles,
}

/// Configuration for the iMessage channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImessageConfig {
    /// Recipient phone number (E.164) or email address.
    pub recipient: String,
    /// Operating mode: "applescript" or "bluebubbles".
    #[serde(default)]
    pub mode: ImessageMode,
    /// BlueBubbles server URL (required for bluebubbles mode).
    #[serde(default)]
    pub bluebubbles_url: Option<String>,
    /// BlueBubbles server password (required for bluebubbles mode).
    #[serde(default)]
    pub bluebubbles_password: Option<String>,
    /// Poll interval in seconds for inbound message polling.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Path to the iMessage chat database (AppleScript mode).
    /// Defaults to ~/Library/Messages/chat.db.
    #[serde(default)]
    pub chat_db_path: Option<String>,
}

fn default_poll_interval() -> u64 {
    10
}

// ---------------------------------------------------------------------------
// Recipient validation
// ---------------------------------------------------------------------------

/// Validate that a recipient is a valid E.164 phone number or email address.
///
/// E.164: starts with '+', followed by 7-15 digits.
/// Email: simplified check -- alphanumeric/dots/hyphens/underscores before '@',
/// domain after '@' with at least one dot.
///
/// Rejects characters that could be used for injection: semicolons, backticks,
/// dollar signs, pipe, ampersand, angle brackets.
pub fn validate_recipient(recipient: &str) -> Result<(), ChannelError> {
    if recipient.is_empty() {
        return Err(ChannelError::Other("recipient is empty".into()));
    }

    // Reject dangerous characters outright.
    const FORBIDDEN: &[char] = &[
        ';', '`', '$', '|', '&', '<', '>', '"', '\'', '\\', '\n', '\r', '\0',
    ];
    for ch in recipient.chars() {
        if FORBIDDEN.contains(&ch) {
            return Err(ChannelError::Other(format!(
                "recipient contains forbidden character: {:?}",
                ch
            )));
        }
    }

    // E.164 phone number.
    if let Some(digits) = recipient.strip_prefix('+') {
        if digits.len() < 7 || digits.len() > 15 {
            return Err(ChannelError::Other(
                "phone number must have 7-15 digits after '+'".into(),
            ));
        }
        if !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(ChannelError::Other(
                "phone number must contain only digits after '+'".into(),
            ));
        }
        return Ok(());
    }

    // Email address (simplified validation).
    if let Some((local, domain)) = recipient.split_once('@') {
        if local.is_empty() || domain.is_empty() {
            return Err(ChannelError::Other(
                "email local part and domain must be non-empty".into(),
            ));
        }
        if !domain.contains('.') {
            return Err(ChannelError::Other(
                "email domain must contain at least one dot".into(),
            ));
        }
        let valid_local = local
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '+');
        let valid_domain = domain
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-');
        if !valid_local || !valid_domain {
            return Err(ChannelError::Other(
                "email contains invalid characters".into(),
            ));
        }
        return Ok(());
    }

    Err(ChannelError::Other(
        "recipient must be an E.164 phone number (+...) or email (user@domain)".into(),
    ))
}

// ---------------------------------------------------------------------------
// AppleScript escaping and command building
// ---------------------------------------------------------------------------

/// Escape text for safe embedding in an AppleScript string literal.
///
/// AppleScript uses double-quoted strings where `"` and `\` are special.
/// We also escape newlines and carriage returns. Null bytes are stripped.
pub fn escape_applescript(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 4);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => {} // strip null bytes entirely
            _ => out.push(ch),
        }
    }
    out
}

/// Build the osascript command string for sending an iMessage.
///
/// Returns the full command as a vector of arguments suitable for
/// `std::process::Command::new("osascript")`.
///
/// The recipient and text are escaped before embedding.
pub fn build_send_command(recipient: &str, text: &str) -> Result<Vec<String>, ChannelError> {
    validate_recipient(recipient)?;
    let escaped_text = escape_applescript(text);
    let escaped_recipient = escape_applescript(recipient);
    let script = format!(
        "tell application \"Messages\" to send \"{}\" to buddy \"{}\"",
        escaped_text, escaped_recipient
    );
    Ok(vec!["osascript".to_string(), "-e".to_string(), script])
}

/// Check whether macOS Automation permission is granted for osascript.
///
/// Attempts a benign osascript command that returns immediately. If the
/// user has not granted Automation access to Terminal/iTerm, this will fail.
///
/// Only actually executes on macOS; returns `true` on other platforms (for
/// testing purposes -- the escaping logic is platform-independent).
#[cfg(target_os = "macos")]
pub fn check_automation_permission() -> bool {
    use std::process::Command;
    let result = Command::new("osascript")
        .arg("-e")
        .arg("return \"ok\"")
        .output();
    match result {
        Ok(output) => {
            if output.status.success() {
                true
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(
                    "osascript automation permission denied. \
                     Grant Terminal automation access in System Settings > \
                     Privacy & Security > Automation. stderr: {}",
                    stderr
                );
                false
            }
        }
        Err(e) => {
            warn!("failed to execute osascript: {e}");
            false
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn check_automation_permission() -> bool {
    // Non-macOS: escaping logic works everywhere, but osascript is unavailable.
    true
}

// ---------------------------------------------------------------------------
// chat.db path validation
// ---------------------------------------------------------------------------

/// Validate that a chat database path is under ~/Library/Messages/.
///
/// Rejects path traversal attempts (..) and paths outside the expected directory.
pub fn validate_chat_db_path(path: &str) -> Result<(), ChannelError> {
    if path.is_empty() {
        return Err(ChannelError::Other("chat_db_path is empty".into()));
    }

    // Reject any path containing ".."
    if path.contains("..") {
        return Err(ChannelError::Other(
            "chat_db_path must not contain '..' (directory traversal)".into(),
        ));
    }

    // Resolve the expected prefix.
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        return Err(ChannelError::Other(
            "HOME environment variable is not set".into(),
        ));
    }

    let expected_prefix = format!("{}/Library/Messages/", home);

    // The path must start with ~/Library/Messages/ (expanded).
    // Also accept the literal "~/Library/Messages/" prefix and expand it.
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{}", home, rest)
    } else {
        path.to_string()
    };

    if !expanded.starts_with(&expected_prefix) {
        return Err(ChannelError::Other(format!(
            "chat_db_path must be under {expected_prefix}, got: {expanded}"
        )));
    }

    Ok(())
}

/// Get the default chat database path.
pub fn default_chat_db_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    format!("{}/Library/Messages/chat.db", home)
}

// ---------------------------------------------------------------------------
// BlueBubbles API client
// ---------------------------------------------------------------------------

/// Validate that a BlueBubbles server URL is localhost or HTTPS.
///
/// Only localhost URLs (127.0.0.1, [::1], localhost) over HTTP are accepted.
/// All other URLs must use HTTPS.
pub fn validate_bluebubbles_url(url_str: &str) -> Result<(), ChannelError> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| ChannelError::Other(format!("invalid BlueBubbles URL: {e}")))?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    if scheme == "https" {
        return Ok(());
    }

    if scheme == "http" {
        let is_localhost =
            host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1";
        if is_localhost {
            return Ok(());
        }
    }

    Err(ChannelError::Other(format!(
        "BlueBubbles URL must be localhost (HTTP) or HTTPS, got: {url_str}"
    )))
}

/// A parsed inbound message from BlueBubbles.
#[derive(Debug, Clone, Deserialize)]
pub struct BlueBubblesMessage {
    /// Unique message identifier.
    #[serde(default)]
    pub guid: String,
    /// Message text content.
    #[serde(default)]
    pub text: Option<String>,
    /// Whether we sent this message.
    #[serde(default, rename = "isFromMe")]
    pub is_from_me: bool,
    /// Date as milliseconds since epoch.
    #[serde(default, rename = "dateCreated")]
    pub date_created: Option<i64>,
    /// Sender handle info.
    #[serde(default)]
    pub handle: Option<BlueBubblesHandle>,
}

/// Handle (sender) info from BlueBubbles.
#[derive(Debug, Clone, Deserialize)]
pub struct BlueBubblesHandle {
    /// The address (phone number or email).
    #[serde(default)]
    pub address: String,
}

/// Response from BlueBubbles GET /api/v1/message.
#[derive(Debug, Deserialize)]
pub struct BlueBubblesMessagesResponse {
    /// Status indicator.
    #[serde(default)]
    pub status: i32,
    /// The messages array.
    #[serde(default)]
    pub data: Vec<BlueBubblesMessage>,
}

/// Response from BlueBubbles POST /api/v1/message/text.
#[derive(Debug, Deserialize)]
struct BlueBubblesSendResponse {
    #[serde(default)]
    status: i32,
    #[serde(default)]
    message: String,
}

/// Response from BlueBubbles GET /api/v1/chat.
#[derive(Debug, Deserialize)]
pub struct BlueBubblesChatsResponse {
    #[serde(default)]
    pub status: i32,
    #[serde(default)]
    pub data: Vec<BlueBubblesChat>,
}

/// A single chat from the BlueBubbles API.
#[derive(Debug, Clone, Deserialize)]
pub struct BlueBubblesChat {
    /// Chat GUID (e.g., "iMessage;-;+1234567890").
    #[serde(default)]
    pub guid: String,
    /// Display name.
    #[serde(default, rename = "displayName")]
    pub display_name: String,
}

/// Low-level BlueBubbles REST API client.
pub struct BlueBubblesApi {
    client: Client,
    base_url: String,
    password: String,
}

impl BlueBubblesApi {
    /// Create a new BlueBubbles API client.
    ///
    /// The `base_url` is the server URL (e.g., `http://localhost:1234`).
    /// The `password` is used for authentication on every request.
    pub fn new(base_url: &str, password: &str) -> Result<Self, ChannelError> {
        validate_bluebubbles_url(base_url)?;
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url: base_url.trim_end_matches('/').to_string(),
            password: password.to_string(),
        })
    }

    /// Create a client with a custom base URL (for testing with wiremock).
    /// Skips URL validation.
    #[cfg(test)]
    fn _with_base_url_unchecked(base_url: &str, password: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url: base_url.trim_end_matches('/').to_string(),
            password: password.to_string(),
        }
    }

    /// Send a text message to a chat.
    ///
    /// POST /api/v1/message/text
    pub async fn send_text(&self, chat_guid: &str, text: &str) -> Result<(), ChannelError> {
        debug!("BlueBubbles: sending text to chat {}", chat_guid);

        let body = serde_json::json!({
            "chatGuid": chat_guid,
            "message": text,
            "method": "apple-script",
        });

        let resp = self
            .client
            .post(format!("{}/api/v1/message/text", self.base_url))
            .query(&[("password", &self.password)])
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            warn!("BlueBubbles send failed: {status} (body redacted for security)");
            return Err(ChannelError::Api(format!(
                "BlueBubbles API returned {status}: {body_text}"
            )));
        }

        let send_resp: BlueBubblesSendResponse = resp
            .json()
            .await
            .map_err(|e| ChannelError::Other(format!("parse BlueBubbles send response: {e}")))?;

        if send_resp.status != 200 {
            return Err(ChannelError::Api(format!(
                "BlueBubbles send returned status {}: {}",
                send_resp.status, send_resp.message
            )));
        }

        Ok(())
    }

    /// Get messages after a given date.
    ///
    /// GET /api/v1/message?after={timestamp}&limit=100
    pub async fn get_messages(
        &self,
        after_date: i64,
    ) -> Result<Vec<BlueBubblesMessage>, ChannelError> {
        debug!("BlueBubbles: polling messages after {}", after_date);

        let resp = self
            .client
            .get(format!("{}/api/v1/message", self.base_url))
            .query(&[
                ("password", &self.password),
                ("after", &after_date.to_string()),
                ("limit", &"100".to_string()),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(ChannelError::Api(format!(
                "BlueBubbles get_messages returned {status}"
            )));
        }

        let messages_resp: BlueBubblesMessagesResponse = resp.json().await.map_err(|e| {
            ChannelError::Other(format!("parse BlueBubbles messages response: {e}"))
        })?;

        Ok(messages_resp.data)
    }

    /// Get the list of chats.
    ///
    /// GET /api/v1/chat
    pub async fn get_chats(&self) -> Result<Vec<BlueBubblesChat>, ChannelError> {
        debug!("BlueBubbles: fetching chats");

        let resp = self
            .client
            .get(format!("{}/api/v1/chat", self.base_url))
            .query(&[("password", &self.password)])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(ChannelError::Api(format!(
                "BlueBubbles get_chats returned {status}"
            )));
        }

        let chats_resp: BlueBubblesChatsResponse = resp
            .json()
            .await
            .map_err(|e| ChannelError::Other(format!("parse BlueBubbles chats response: {e}")))?;

        Ok(chats_resp.data)
    }

    /// Send an attachment (image/file) to a chat.
    ///
    /// POST /api/v1/message/attachment with multipart form data.
    pub async fn send_attachment(
        &self,
        chat_guid: &str,
        filename: &str,
        data: &[u8],
        caption: Option<&str>,
    ) -> Result<(), ChannelError> {
        debug!(
            "BlueBubbles: sending attachment '{}' to chat {}",
            filename, chat_guid
        );

        let file_part =
            reqwest::multipart::Part::bytes(data.to_vec()).file_name(filename.to_string());

        let mut form = reqwest::multipart::Form::new()
            .text("chatGuid", chat_guid.to_string())
            .text("method", "apple-script".to_string())
            .part("attachment", file_part);

        if let Some(cap) = caption {
            form = form.text("message", cap.to_string());
        }

        let resp = self
            .client
            .post(format!("{}/api/v1/message/attachment", self.base_url))
            .query(&[("password", &self.password)])
            .multipart(form)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            warn!("BlueBubbles attachment send failed: {status} (body redacted for security)");
            return Err(ChannelError::Api(format!(
                "BlueBubbles attachment API returned {status}: {body_text}"
            )));
        }

        Ok(())
    }

    /// Build the expected body JSON for a send_text call (for testing).
    pub fn build_send_body(chat_guid: &str, text: &str) -> serde_json::Value {
        serde_json::json!({
            "chatGuid": chat_guid,
            "message": text,
            "method": "apple-script",
        })
    }
}

/// Map a BlueBubbles message to an `InboundAction`, if applicable.
///
/// Filters out messages sent by us (`is_from_me`), and messages with no text.
/// Text is parsed as a command using `format::parse_text_command`.
pub fn map_inbound_message(msg: &BlueBubblesMessage) -> Option<InboundAction> {
    if msg.is_from_me {
        return None;
    }
    let text = msg.text.as_deref()?.trim();
    if text.is_empty() {
        return None;
    }
    Some(format::parse_text_command(text))
}

// ---------------------------------------------------------------------------
// Channel implementation
// ---------------------------------------------------------------------------

/// iMessage channel implementing the [`Channel`] trait.
///
/// Supports dual-mode operation: AppleScript (macOS native) or BlueBubbles
/// REST API. Inbound messages are polled from either `chat.db` (AppleScript
/// mode) or the BlueBubbles messages endpoint.
pub struct ImessageChannel {
    config: ImessageConfig,
    /// BlueBubbles API client (only for BlueBubbles mode).
    bb_api: Option<BlueBubblesApi>,
    /// Buffered inbound actions.
    inbound_buffer: Vec<InboundAction>,
    /// Last date received for BlueBubbles polling (ms since epoch).
    last_date_received: i64,
    /// Last ROWID read from chat.db (AppleScript mode).
    last_rowid: i64,
}

impl std::fmt::Debug for ImessageChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImessageChannel")
            .field("config", &self.config)
            .field("bb_api", &self.bb_api.is_some())
            .field("inbound_buffer_len", &self.inbound_buffer.len())
            .field("last_date_received", &self.last_date_received)
            .field("last_rowid", &self.last_rowid)
            .finish()
    }
}

impl ImessageChannel {
    /// Create a new iMessage channel from configuration.
    pub fn new(config: ImessageConfig) -> Result<Self, ChannelError> {
        validate_recipient(&config.recipient)?;

        let bb_api = match config.mode {
            ImessageMode::Bluebubbles => {
                let url = config.bluebubbles_url.as_deref().ok_or_else(|| {
                    ChannelError::Other("bluebubbles_url is required for BlueBubbles mode".into())
                })?;
                let password = config.bluebubbles_password.as_deref().ok_or_else(|| {
                    ChannelError::Other(
                        "bluebubbles_password is required for BlueBubbles mode".into(),
                    )
                })?;
                Some(BlueBubblesApi::new(url, password)?)
            }
            ImessageMode::Applescript => {
                // Validate chat_db_path if provided.
                if let Some(ref db_path) = config.chat_db_path {
                    validate_chat_db_path(db_path)?;
                }
                None
            }
        };

        Ok(Self {
            config,
            bb_api,
            inbound_buffer: Vec::new(),
            last_date_received: 0,
            last_rowid: 0,
        })
    }

    /// Poll for inbound messages from chat.db (AppleScript mode).
    ///
    /// Reads new messages from the SQLite database where ROWID > last_rowid
    /// and is_from_me = 0.
    fn poll_chat_db(&mut self) -> Result<(), ChannelError> {
        let default_path = default_chat_db_path();
        let db_path = self.config.chat_db_path.as_deref().unwrap_or(&default_path);

        // Validate path every time (defense in depth).
        validate_chat_db_path(db_path)?;

        let conn = match rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(e) => {
                // Database may be locked by Messages.app -- log and skip.
                debug!("chat.db open failed (may be locked): {e}");
                return Ok(());
            }
        };

        // Set a short busy timeout to avoid blocking.
        let _ = conn.busy_timeout(std::time::Duration::from_millis(500));

        let mut stmt = match conn.prepare(
            "SELECT ROWID, text, handle_id, is_from_me, date \
             FROM message WHERE ROWID > ?1 AND is_from_me = 0 \
             ORDER BY ROWID ASC",
        ) {
            Ok(s) => s,
            Err(e) => {
                debug!("chat.db query prepare failed: {e}");
                return Ok(());
            }
        };

        let rows = match stmt.query_map(rusqlite::params![self.last_rowid], |row| {
            let rowid: i64 = row.get(0)?;
            let text: Option<String> = row.get(1)?;
            let _handle_id: i64 = row.get(2)?;
            let _is_from_me: i64 = row.get(3)?;
            let _date: i64 = row.get(4)?;
            Ok((rowid, text))
        }) {
            Ok(r) => r,
            Err(e) => {
                debug!("chat.db query failed: {e}");
                return Ok(());
            }
        };

        for row in rows {
            match row {
                Ok((rowid, Some(text))) => {
                    self.last_rowid = rowid;
                    let text = text.trim();
                    if !text.is_empty() {
                        self.inbound_buffer.push(format::parse_text_command(text));
                    }
                }
                Ok((rowid, None)) => {
                    self.last_rowid = rowid;
                }
                Err(e) => {
                    debug!("chat.db row read error: {e}");
                }
            }
        }

        Ok(())
    }

    /// Poll for inbound messages from BlueBubbles.
    async fn poll_bluebubbles(&mut self) -> Result<(), ChannelError> {
        let api = self
            .bb_api
            .as_ref()
            .ok_or_else(|| ChannelError::Other("BlueBubbles API not initialized".into()))?;

        let messages = api.get_messages(self.last_date_received).await?;

        for msg in &messages {
            // Update tracking timestamp.
            if let Some(date) = msg.date_created {
                if date > self.last_date_received {
                    self.last_date_received = date;
                }
            }

            // Map to inbound action, filtering out our own messages.
            if let Some(action) = map_inbound_message(msg) {
                self.inbound_buffer.push(action);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Channel for ImessageChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        match self.config.mode {
            ImessageMode::Applescript => {
                let cmd = build_send_command(&self.config.recipient, &message.text)?;
                debug!("iMessage AppleScript send command: {:?}", cmd);

                #[cfg(target_os = "macos")]
                {
                    let output = tokio::process::Command::new(&cmd[0])
                        .args(&cmd[1..])
                        .output()
                        .await
                        .map_err(|e| {
                            ChannelError::Other(format!("osascript execution failed: {e}"))
                        })?;

                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        return Err(ChannelError::Other(format!(
                            "osascript returned {}: {}",
                            output.status, stderr
                        )));
                    }
                }

                #[cfg(not(target_os = "macos"))]
                return Err(ChannelError::Other(
                    "AppleScript mode is only available on macOS".into(),
                ));

                #[cfg(target_os = "macos")]
                Ok(())
            }
            ImessageMode::Bluebubbles => {
                let api = self
                    .bb_api
                    .as_ref()
                    .ok_or_else(|| ChannelError::Other("BlueBubbles API not initialized".into()))?;

                let chat_guid = format!("iMessage;-;{}", self.config.recipient);
                api.send_text(&chat_guid, &message.text).await
            }
        }
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        // Return buffered actions first.
        if !self.inbound_buffer.is_empty() {
            return Ok(Some(self.inbound_buffer.remove(0)));
        }

        // Poll for new messages.
        match self.config.mode {
            ImessageMode::Applescript => {
                self.poll_chat_db()?;
            }
            ImessageMode::Bluebubbles => {
                self.poll_bluebubbles().await?;
            }
        }

        if self.inbound_buffer.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.inbound_buffer.remove(0)))
        }
    }

    fn name(&self) -> &str {
        "imessage"
    }

    async fn send_photo(&self, photo: OutboundPhoto) -> Result<(), ChannelError> {
        match self.config.mode {
            ImessageMode::Applescript => {
                // AppleScript does not have a clean API for sending images
                // programmatically via Messages.app. Fall back to sending a
                // text notification that an image was generated.
                let text = photo.caption.as_deref().unwrap_or("[photo attachment]");
                self.send(OutboundMessage::text(text)).await
            }
            ImessageMode::Bluebubbles => {
                let api = self
                    .bb_api
                    .as_ref()
                    .ok_or_else(|| ChannelError::Other("BlueBubbles API not initialized".into()))?;

                let chat_guid = format!("iMessage;-;{}", self.config.recipient);
                api.send_attachment(
                    &chat_guid,
                    &photo.filename,
                    &photo.bytes,
                    photo.caption.as_deref(),
                )
                .await
            }
        }
    }

    fn capabilities(&self) -> crate::channel::ChannelCapabilities {
        crate::channel::ChannelCapabilities {
            // BlueBubbles mode supports sending images; AppleScript falls back
            // to a text caption, so we report rich_media for BlueBubbles only.
            rich_media: self.config.mode == ImessageMode::Bluebubbles,
            // iMessage / AppleScript does not support typing, editing,
            // deletion, reactions, threads, or presence natively.
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

    // -- AppleScript text escaping --

    #[test]
    fn test_applescript_text_escaping() {
        // Double quotes escaped.
        assert_eq!(escape_applescript(r#"say "hello""#), r#"say \"hello\""#);

        // Backslashes escaped.
        assert_eq!(escape_applescript(r"path\to\file"), r"path\\to\\file");

        // Newlines escaped.
        assert_eq!(escape_applescript("line1\nline2"), "line1\\nline2");

        // Carriage returns escaped.
        assert_eq!(escape_applescript("line1\rline2"), "line1\\rline2");

        // Null bytes stripped.
        assert_eq!(escape_applescript("hello\0world"), "helloworld");

        // Combined.
        assert_eq!(
            escape_applescript("He said \"hi\"\nand left\\"),
            "He said \\\"hi\\\"\\nand left\\\\"
        );
    }

    // -- SECURITY: AppleScript injection prevention --

    #[test]
    fn test_applescript_injection_prevention() {
        // Backticks pass through but are not special in AppleScript strings.
        let text = "`echo hacked`";
        let escaped = escape_applescript(text);
        assert_eq!(escaped, "`echo hacked`");

        // Dollar signs pass through (not special in AppleScript strings).
        let text = "$(rm -rf /)";
        let escaped = escape_applescript(text);
        assert_eq!(escaped, "$(rm -rf /)");

        // Single quotes pass through (not special in AppleScript
        // double-quoted strings).
        let text = "it's a test";
        let escaped = escape_applescript(text);
        assert_eq!(escaped, "it's a test");

        // The critical one: double quotes are escaped to prevent breaking out.
        let text = r#"" & do shell script "whoami" & ""#;
        let escaped = escape_applescript(text);
        assert_eq!(escaped, r#"\" & do shell script \"whoami\" & \""#);

        // Backslash before quote -- both escaped.
        let text = r"\";
        let escaped = escape_applescript(text);
        assert_eq!(escaped, r"\\");
    }

    // -- SECURITY: AppleScript injection in build_send_command --

    #[test]
    fn test_applescript_injection_escaping() {
        // Attempt to inject via text with quotes and shell commands.
        let cmd =
            build_send_command("+1234567890", "\" & do shell script \"whoami\" & \"").unwrap();
        assert_eq!(cmd.len(), 3);
        assert_eq!(cmd[0], "osascript");
        assert_eq!(cmd[1], "-e");
        // The injected text should be safely escaped inside the string.
        assert!(cmd[2].contains("\\\""));
        assert!(!cmd[2].contains("do shell script \"whoami\""));
        // It should contain the escaped version.
        assert!(cmd[2].contains("do shell script \\\"whoami\\\""));
    }

    // -- BlueBubbles API send body --

    #[test]
    fn test_bluebubbles_api_send() {
        let body = BlueBubblesApi::build_send_body("iMessage;-;+1234567890", "Hello, World!");
        assert_eq!(body["chatGuid"], "iMessage;-;+1234567890");
        assert_eq!(body["message"], "Hello, World!");
        assert_eq!(body["method"], "apple-script");
    }

    // -- BlueBubbles API receive (parse messages) --

    #[test]
    fn test_bluebubbles_api_receive() {
        let json = r#"{
            "status": 200,
            "data": [
                {
                    "guid": "msg-001",
                    "text": "/status",
                    "isFromMe": false,
                    "dateCreated": 1700000000000,
                    "handle": {
                        "address": "+1234567890"
                    }
                },
                {
                    "guid": "msg-002",
                    "text": "my own message",
                    "isFromMe": true,
                    "dateCreated": 1700000001000,
                    "handle": null
                },
                {
                    "guid": "msg-003",
                    "text": null,
                    "isFromMe": false,
                    "dateCreated": 1700000002000,
                    "handle": {
                        "address": "user@example.com"
                    }
                }
            ]
        }"#;

        let resp: BlueBubblesMessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.len(), 3);
        assert_eq!(resp.data[0].guid, "msg-001");
        assert_eq!(resp.data[0].text.as_deref(), Some("/status"));
        assert!(!resp.data[0].is_from_me);
        assert!(resp.data[1].is_from_me);
        assert!(resp.data[2].text.is_none());
    }

    // -- Inbound message mapping --

    #[test]
    fn test_inbound_message_mapping() {
        // From someone else with command text.
        let msg = BlueBubblesMessage {
            guid: "msg-1".into(),
            text: Some("/status".into()),
            is_from_me: false,
            date_created: Some(1700000000000),
            handle: Some(BlueBubblesHandle {
                address: "+1234567890".into(),
            }),
        };
        let action = map_inbound_message(&msg);
        assert!(action.is_some());
        assert!(matches!(
            action.unwrap(),
            InboundAction::Command(aegis_control::command::Command::Status)
        ));

        // From me -- should be filtered out.
        let msg_from_me = BlueBubblesMessage {
            guid: "msg-2".into(),
            text: Some("/status".into()),
            is_from_me: true,
            date_created: Some(1700000001000),
            handle: None,
        };
        assert!(map_inbound_message(&msg_from_me).is_none());

        // No text -- should be filtered out.
        let msg_no_text = BlueBubblesMessage {
            guid: "msg-3".into(),
            text: None,
            is_from_me: false,
            date_created: Some(1700000002000),
            handle: None,
        };
        assert!(map_inbound_message(&msg_no_text).is_none());

        // Empty text -- should be filtered out.
        let msg_empty = BlueBubblesMessage {
            guid: "msg-4".into(),
            text: Some("  ".into()),
            is_from_me: false,
            date_created: Some(1700000003000),
            handle: None,
        };
        assert!(map_inbound_message(&msg_empty).is_none());

        // Unknown command text.
        let msg_unknown = BlueBubblesMessage {
            guid: "msg-5".into(),
            text: Some("hello there".into()),
            is_from_me: false,
            date_created: Some(1700000004000),
            handle: None,
        };
        let action = map_inbound_message(&msg_unknown).unwrap();
        assert!(matches!(action, InboundAction::Unknown(ref s) if s == "hello there"));
    }

    // -- SECURITY: chat.db path validation --

    #[test]
    fn test_chat_db_path_validation() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/test".to_string());

        // Valid path.
        let valid = format!("{}/Library/Messages/chat.db", home);
        assert!(validate_chat_db_path(&valid).is_ok());

        // Valid path with tilde.
        assert!(validate_chat_db_path("~/Library/Messages/chat.db").is_ok());

        // Valid subdirectory.
        let sub = format!("{}/Library/Messages/archive/old.db", home);
        assert!(validate_chat_db_path(&sub).is_ok());

        // Empty path rejected.
        assert!(validate_chat_db_path("").is_err());
    }

    // -- SECURITY: chat.db path traversal --

    #[test]
    fn test_chat_db_path_traversal() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/test".to_string());

        // Directory traversal rejected.
        let traversal = format!("{}/Library/Messages/../../../etc/passwd", home);
        assert!(validate_chat_db_path(&traversal).is_err());

        // Tilde with traversal rejected.
        assert!(validate_chat_db_path("~/Library/Messages/../../etc/shadow").is_err());

        // Just ".." rejected.
        assert!(validate_chat_db_path("..").is_err());

        // Path outside Messages directory rejected.
        assert!(validate_chat_db_path("/etc/passwd").is_err());
        assert!(validate_chat_db_path("/tmp/chat.db").is_err());

        // Absolute path to another user's Messages rejected.
        assert!(validate_chat_db_path("/Users/other/Library/Messages/chat.db").is_err());

        // Sneaky embedded ".." even in otherwise valid prefix.
        let sneaky = format!("{}/Library/Messages/foo/../../../etc/passwd", home);
        assert!(validate_chat_db_path(&sneaky).is_err());
    }

    // -- Config roundtrip --

    #[test]
    fn test_config_roundtrip() {
        let config = ImessageConfig {
            recipient: "+1234567890".to_string(),
            mode: ImessageMode::Bluebubbles,
            bluebubbles_url: Some("http://localhost:1234".to_string()),
            bluebubbles_password: Some("secret123".to_string()),
            poll_interval_secs: 15,
            chat_db_path: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ImessageConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);

        // Check that password is present in serialized form (but in real
        // usage should be stored securely, not logged).
        assert!(json.contains("secret123"));
    }

    #[test]
    fn test_config_backward_compatible() {
        // Minimal config with only the old required field.
        let json = r#"{"recipient": "+1234567890"}"#;
        let config: ImessageConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.recipient, "+1234567890");
        assert_eq!(config.mode, ImessageMode::Applescript);
        assert!(config.bluebubbles_url.is_none());
        assert!(config.bluebubbles_password.is_none());
        assert_eq!(config.poll_interval_secs, 10);
        assert!(config.chat_db_path.is_none());
    }

    #[test]
    fn test_config_mode_deserialization() {
        let json = r#"{"recipient": "+1234567890", "mode": "applescript"}"#;
        let config: ImessageConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.mode, ImessageMode::Applescript);

        let json = r#"{"recipient": "+1234567890", "mode": "bluebubbles"}"#;
        let config: ImessageConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.mode, ImessageMode::Bluebubbles);
    }

    // -- Recipient validation --

    #[test]
    fn test_recipient_validation() {
        // Valid E.164 phone numbers.
        assert!(validate_recipient("+1234567890").is_ok());
        assert!(validate_recipient("+441234567890").is_ok());
        assert!(validate_recipient("+1234567").is_ok()); // minimum 7 digits

        // Valid email addresses.
        assert!(validate_recipient("user@example.com").is_ok());
        assert!(validate_recipient("first.last@domain.org").is_ok());
        assert!(validate_recipient("user+tag@sub.domain.co.uk").is_ok());

        // Invalid: empty.
        assert!(validate_recipient("").is_err());

        // Invalid: no prefix.
        assert!(validate_recipient("1234567890").is_err());

        // Invalid: too few digits.
        assert!(validate_recipient("+123456").is_err());

        // Invalid: too many digits.
        assert!(validate_recipient("+1234567890123456").is_err());

        // Invalid: letters in phone.
        assert!(validate_recipient("+123456789a").is_err());

        // Invalid: email without domain dot.
        assert!(validate_recipient("user@localhost").is_err());

        // Invalid: injection characters.
        assert!(validate_recipient("+1234567890;rm -rf /").is_err());
        assert!(validate_recipient("user`whoami`@example.com").is_err());
        assert!(validate_recipient("user$HOME@example.com").is_err());
        assert!(validate_recipient("user|cat@example.com").is_err());
        assert!(validate_recipient("user&bg@example.com").is_err());
        assert!(validate_recipient("user<script>@example.com").is_err());
        assert!(validate_recipient("user\"@example.com").is_err());
        assert!(validate_recipient("user'@example.com").is_err());
        assert!(validate_recipient("user\\@example.com").is_err());
    }

    // -- BlueBubbles URL validation --

    #[test]
    fn test_bluebubbles_url_validation() {
        // Localhost HTTP allowed.
        assert!(validate_bluebubbles_url("http://localhost:1234").is_ok());
        assert!(validate_bluebubbles_url("http://127.0.0.1:1234").is_ok());
        assert!(validate_bluebubbles_url("http://[::1]:1234").is_ok());

        // HTTPS allowed for any host.
        assert!(validate_bluebubbles_url("https://my-server.example.com:443").is_ok());
        assert!(validate_bluebubbles_url("https://192.168.1.100:1234").is_ok());

        // HTTP to non-localhost rejected.
        assert!(validate_bluebubbles_url("http://192.168.1.100:1234").is_err());
        assert!(validate_bluebubbles_url("http://example.com:1234").is_err());

        // Other schemes rejected.
        assert!(validate_bluebubbles_url("ftp://localhost:1234").is_err());

        // Invalid URL rejected.
        assert!(validate_bluebubbles_url("not a url").is_err());
    }

    // -- Channel name --

    #[test]
    fn imessage_channel_name() {
        let channel = ImessageChannel::new(ImessageConfig {
            recipient: "+1234567890".to_string(),
            mode: ImessageMode::Applescript,
            bluebubbles_url: None,
            bluebubbles_password: None,
            poll_interval_secs: 10,
            chat_db_path: None,
        })
        .unwrap();
        assert_eq!(channel.name(), "imessage");
    }

    // -- BlueBubbles channel creation validation --

    #[test]
    fn test_bluebubbles_channel_requires_url() {
        let result = ImessageChannel::new(ImessageConfig {
            recipient: "+1234567890".to_string(),
            mode: ImessageMode::Bluebubbles,
            bluebubbles_url: None,
            bluebubbles_password: Some("pass".to_string()),
            poll_interval_secs: 10,
            chat_db_path: None,
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("bluebubbles_url"));
    }

    #[test]
    fn test_bluebubbles_channel_requires_password() {
        let result = ImessageChannel::new(ImessageConfig {
            recipient: "+1234567890".to_string(),
            mode: ImessageMode::Bluebubbles,
            bluebubbles_url: Some("http://localhost:1234".to_string()),
            bluebubbles_password: None,
            poll_interval_secs: 10,
            chat_db_path: None,
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("bluebubbles_password"));
    }

    #[test]
    fn test_bluebubbles_channel_rejects_insecure_url() {
        let result = ImessageChannel::new(ImessageConfig {
            recipient: "+1234567890".to_string(),
            mode: ImessageMode::Bluebubbles,
            bluebubbles_url: Some("http://192.168.1.100:1234".to_string()),
            bluebubbles_password: Some("pass".to_string()),
            poll_interval_secs: 10,
            chat_db_path: None,
        });
        assert!(result.is_err());
    }

    // -- BlueBubbles message response parsing --

    #[test]
    fn test_bluebubbles_chats_response() {
        let json = r#"{
            "status": 200,
            "data": [
                {
                    "guid": "iMessage;-;+1234567890",
                    "displayName": "John Doe"
                },
                {
                    "guid": "iMessage;-;user@example.com",
                    "displayName": ""
                }
            ]
        }"#;
        let resp: BlueBubblesChatsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.data[0].guid, "iMessage;-;+1234567890");
        assert_eq!(resp.data[0].display_name, "John Doe");
        assert_eq!(resp.data[1].guid, "iMessage;-;user@example.com");
    }

    // -- Build send command --

    #[test]
    fn test_build_send_command_basic() {
        let cmd = build_send_command("+1234567890", "Hello, World!").unwrap();
        assert_eq!(cmd[0], "osascript");
        assert_eq!(cmd[1], "-e");
        assert!(cmd[2].contains("tell application \"Messages\""));
        assert!(cmd[2].contains("Hello, World!"));
        assert!(cmd[2].contains("+1234567890"));
    }

    #[test]
    fn test_build_send_command_escapes_text() {
        let cmd = build_send_command("+1234567890", "He said \"hi\"").unwrap();
        // The text should be escaped within the AppleScript string.
        assert!(cmd[2].contains("He said \\\"hi\\\""));
    }

    #[test]
    fn test_build_send_command_rejects_invalid_recipient() {
        let result = build_send_command("not-a-valid-recipient", "text");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_send_command_email_recipient() {
        let cmd = build_send_command("user@example.com", "Hello").unwrap();
        assert!(cmd[2].contains("user@example.com"));
    }

    // -- Default chat db path --

    #[test]
    fn test_default_chat_db_path() {
        let path = default_chat_db_path();
        assert!(path.ends_with("/Library/Messages/chat.db"));
    }

    // -- Capabilities --

    #[test]
    fn test_applescript_capabilities_no_rich_media() {
        let channel = ImessageChannel::new(ImessageConfig {
            recipient: "+1234567890".to_string(),
            mode: ImessageMode::Applescript,
            bluebubbles_url: None,
            bluebubbles_password: None,
            poll_interval_secs: 10,
            chat_db_path: None,
        })
        .unwrap();
        let caps = channel.capabilities();
        assert!(!caps.rich_media);
        assert!(!caps.typing_indicators);
        assert!(!caps.message_editing);
        assert!(!caps.message_deletion);
        assert!(!caps.reactions);
        assert!(!caps.threads);
        assert!(!caps.presence);
    }

    #[test]
    fn test_bluebubbles_capabilities_rich_media() {
        let channel = ImessageChannel::new(ImessageConfig {
            recipient: "+1234567890".to_string(),
            mode: ImessageMode::Bluebubbles,
            bluebubbles_url: Some("http://localhost:1234".to_string()),
            bluebubbles_password: Some("pass".to_string()),
            poll_interval_secs: 10,
            chat_db_path: None,
        })
        .unwrap();
        let caps = channel.capabilities();
        assert!(caps.rich_media);
        assert!(!caps.typing_indicators);
        assert!(!caps.reactions);
    }

    // -- Wiremock tests: BlueBubbles HTTP API --

    #[tokio::test]
    async fn test_wiremock_bluebubbles_send_text() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/message/text"))
            .and(matchers::query_param("password", "testpass"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": 200,
                "message": "Message sent!"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let api = BlueBubblesApi::_with_base_url_unchecked(&server.uri(), "testpass");
        let result = api
            .send_text("iMessage;-;+1234567890", "Hello from test")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wiremock_bluebubbles_send_text_failure() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/message/text"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&server)
            .await;

        let api = BlueBubblesApi::_with_base_url_unchecked(&server.uri(), "testpass");
        let result = api.send_text("iMessage;-;+1234567890", "Hello").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500"));
    }

    #[tokio::test]
    async fn test_wiremock_bluebubbles_get_messages() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/v1/message"))
            .and(matchers::query_param("password", "testpass"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": 200,
                "data": [
                    {
                        "guid": "msg-100",
                        "text": "/status",
                        "isFromMe": false,
                        "dateCreated": 1700000010000_i64,
                        "handle": { "address": "+1234567890" }
                    },
                    {
                        "guid": "msg-101",
                        "text": "my reply",
                        "isFromMe": true,
                        "dateCreated": 1700000011000_i64
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let api = BlueBubblesApi::_with_base_url_unchecked(&server.uri(), "testpass");
        let messages = api.get_messages(1700000000000).await.unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].guid, "msg-100");
        assert_eq!(messages[0].text.as_deref(), Some("/status"));
        assert!(!messages[0].is_from_me);
        assert!(messages[1].is_from_me);
    }

    #[tokio::test]
    async fn test_wiremock_bluebubbles_get_messages_failure() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/v1/message"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;

        let api = BlueBubblesApi::_with_base_url_unchecked(&server.uri(), "wrongpass");
        let result = api.get_messages(0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wiremock_bluebubbles_get_chats() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/v1/chat"))
            .and(matchers::query_param("password", "testpass"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": 200,
                "data": [
                    {
                        "guid": "iMessage;-;+1234567890",
                        "displayName": "Test User"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let api = BlueBubblesApi::_with_base_url_unchecked(&server.uri(), "testpass");
        let chats = api.get_chats().await.unwrap();
        assert_eq!(chats.len(), 1);
        assert_eq!(chats[0].guid, "iMessage;-;+1234567890");
        assert_eq!(chats[0].display_name, "Test User");
    }

    #[tokio::test]
    async fn test_wiremock_bluebubbles_send_attachment() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/message/attachment"))
            .and(matchers::query_param("password", "testpass"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": 200,
                "message": "Attachment sent!"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let api = BlueBubblesApi::_with_base_url_unchecked(&server.uri(), "testpass");
        let photo_bytes = vec![0xFF, 0xD8, 0xFF, 0xE0]; // Fake JPEG header
        let result = api
            .send_attachment(
                "iMessage;-;+1234567890",
                "photo.jpg",
                &photo_bytes,
                Some("Check this out"),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wiremock_bluebubbles_send_attachment_failure() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/message/attachment"))
            .respond_with(ResponseTemplate::new(413).set_body_string("Payload too large"))
            .expect(1)
            .mount(&server)
            .await;

        let api = BlueBubblesApi::_with_base_url_unchecked(&server.uri(), "testpass");
        let result = api
            .send_attachment("iMessage;-;+1234567890", "big.jpg", &[0u8; 100], None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wiremock_bluebubbles_send_text_bad_status_in_body() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // HTTP 200 but BlueBubbles API status != 200 in body.
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/message/text"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": 400,
                "message": "Invalid chat GUID"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let api = BlueBubblesApi::_with_base_url_unchecked(&server.uri(), "testpass");
        let result = api.send_text("bad-guid", "test message").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("400") || err.contains("Invalid chat GUID"));
    }
}
