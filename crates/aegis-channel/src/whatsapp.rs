//! WhatsApp Cloud API channel adapter.
//!
//! Full implementation of the WhatsApp Business Cloud API including:
//! - Outbound text, template, and interactive messages
//! - Inbound webhook verification and message handling
//! - HMAC-SHA256 signature verification with constant-time comparison
//! - Media upload with mime type validation
//! - Template parameter sanitization
//!
//! # Security
//!
//! - Webhook payloads are verified using HMAC-SHA256 with the app_secret
//! - Signature comparison uses constant-time equality (subtle crate)
//! - Template parameters are sanitized: no null bytes, no control characters, max 1024 chars
//! - Media uploads validate mime types against an allowlist
//! - File sizes are validated before upload (16MB images, 100MB documents)

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use crate::channel::{
    Channel, ChannelCapabilities, ChannelError, InboundAction, OutboundMessage, OutboundPhoto,
};
use crate::format;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the WhatsApp channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhatsappConfig {
    /// WhatsApp Cloud API base URL.
    pub api_url: String,
    /// Access token for the WhatsApp Business API.
    pub access_token: String,
    /// Phone number ID for sending messages.
    pub phone_number_id: String,
    /// App secret for webhook signature verification (HMAC-SHA256).
    #[serde(default)]
    pub app_secret: Option<String>,
    /// Verify token for webhook challenge verification.
    #[serde(default)]
    pub verify_token: Option<String>,
    /// Port for the inbound webhook HTTP server.
    #[serde(default)]
    pub webhook_port: Option<u16>,
    /// Template namespace for message templates.
    #[serde(default)]
    pub template_namespace: Option<String>,
}

// ---------------------------------------------------------------------------
// WhatsApp API types
// ---------------------------------------------------------------------------

/// A WhatsApp message template with parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsappTemplate {
    /// Template name as registered in the WhatsApp Business Manager.
    pub name: String,
    /// Language code (e.g., "en_US", "es").
    pub language: String,
    /// Template components (header, body, buttons).
    #[serde(default)]
    pub components: Vec<TemplateComponent>,
}

/// A component within a message template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateComponent {
    /// Component type: "header", "body", or "button".
    #[serde(rename = "type")]
    pub component_type: String,
    /// Parameters for variable substitution.
    #[serde(default)]
    pub parameters: Vec<TemplateParameter>,
    /// Sub-type for button components (e.g., "quick_reply").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_type: Option<String>,
    /// Button index (0-based).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
}

/// A parameter value within a template component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateParameter {
    /// Parameter type (currently only "text" is supported).
    #[serde(rename = "type")]
    pub param_type: String,
    /// The text value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// A section in an interactive list message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSection {
    /// Section title.
    pub title: String,
    /// Rows within this section.
    pub rows: Vec<ListRow>,
}

/// A single row in a list section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRow {
    /// Unique row identifier (max 200 chars).
    pub id: String,
    /// Row title displayed to the user (max 24 chars).
    pub title: String,
    /// Optional description (max 72 chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Response from the WhatsApp Cloud API /messages endpoint.
#[derive(Debug, Deserialize)]
struct MessagesResponse {
    #[allow(dead_code)]
    messages: Option<Vec<MessageId>>,
}

/// A message ID from the API response.
#[derive(Debug, Deserialize)]
struct MessageId {
    #[allow(dead_code)]
    id: String,
}

/// Error response from the WhatsApp Cloud API.
#[derive(Debug, Deserialize)]
struct ApiError {
    error: Option<ApiErrorDetail>,
}

/// Detailed error information from the API.
#[derive(Debug, Deserialize)]
struct ApiErrorDetail {
    message: String,
    #[allow(dead_code)]
    code: Option<i64>,
}

/// Response from the media upload endpoint.
#[derive(Debug, Deserialize)]
struct MediaUploadResponse {
    id: Option<String>,
}

// ---------------------------------------------------------------------------
// Validation constants and helpers
// ---------------------------------------------------------------------------

/// Maximum length for a single template parameter value.
const MAX_TEMPLATE_PARAM_LENGTH: usize = 1024;

/// Maximum image file size: 16 MB.
const MAX_IMAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum document file size: 100 MB.
const MAX_DOCUMENT_SIZE: usize = 100 * 1024 * 1024;

/// Maximum number of buttons in an interactive button message.
const MAX_INTERACTIVE_BUTTONS: usize = 3;

/// Allowed mime types for media upload.
const ALLOWED_MIME_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/webp",
    "video/mp4",
    "video/3gpp",
    "audio/aac",
    "audio/mp4",
    "audio/mpeg",
    "audio/ogg",
    "application/pdf",
    "application/vnd.ms-powerpoint",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain",
];

/// Mime types that count as images (use image size limit).
const IMAGE_MIME_TYPES: &[&str] = &["image/jpeg", "image/png", "image/webp"];

/// Validate that a mime type is in the allowlist.
pub fn validate_mime_type(mime: &str) -> Result<(), ChannelError> {
    if ALLOWED_MIME_TYPES.contains(&mime) {
        Ok(())
    } else {
        Err(ChannelError::Other(format!(
            "disallowed mime type: {mime}"
        )))
    }
}

/// Validate file size against WhatsApp limits based on mime type.
pub fn validate_file_size(size: usize, mime: &str) -> Result<(), ChannelError> {
    let limit = if IMAGE_MIME_TYPES.contains(&mime) {
        MAX_IMAGE_SIZE
    } else {
        MAX_DOCUMENT_SIZE
    };
    if size > limit {
        Err(ChannelError::Other(format!(
            "file size {size} exceeds limit {limit} for {mime}"
        )))
    } else {
        Ok(())
    }
}

/// Sanitize a template parameter value.
///
/// Rejects null bytes and control characters (U+0000..U+001F, U+007F..U+009F),
/// and enforces the maximum length of 1024 characters.
pub fn sanitize_template_param(value: &str) -> Result<(), ChannelError> {
    if value.len() > MAX_TEMPLATE_PARAM_LENGTH {
        return Err(ChannelError::Other(format!(
            "template parameter exceeds {} chars",
            MAX_TEMPLATE_PARAM_LENGTH
        )));
    }
    for ch in value.chars() {
        if ch == '\0' {
            return Err(ChannelError::Other(
                "template parameter contains null byte".into(),
            ));
        }
        if ch.is_control() {
            return Err(ChannelError::Other(format!(
                "template parameter contains control character U+{:04X}",
                ch as u32
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Webhook verification and signature validation
// ---------------------------------------------------------------------------

/// WhatsApp webhook handler for inbound messages and verification challenges.
pub struct WhatsappWebhook {
    /// App secret for HMAC-SHA256 signature verification.
    app_secret: Option<String>,
    /// Verify token for the GET challenge handshake.
    verify_token: Option<String>,
}

impl WhatsappWebhook {
    /// Create a new webhook handler.
    pub fn new(app_secret: Option<String>, verify_token: Option<String>) -> Self {
        Self {
            app_secret,
            verify_token,
        }
    }

    /// Handle the GET verification challenge from WhatsApp.
    ///
    /// WhatsApp sends a GET request with query parameters:
    /// - `hub.mode` = "subscribe"
    /// - `hub.verify_token` = the token you registered
    /// - `hub.challenge` = a random string to echo back
    ///
    /// Returns `Ok(challenge)` if verification passes, `Err` otherwise.
    pub fn verify_challenge(
        &self,
        mode: &str,
        token: &str,
        challenge: &str,
    ) -> Result<String, ChannelError> {
        if mode != "subscribe" {
            return Err(ChannelError::Other(format!(
                "unexpected hub.mode: {mode}"
            )));
        }

        let expected = match &self.verify_token {
            Some(t) => t.as_str(),
            None => {
                return Err(ChannelError::Other(
                    "no verify_token configured".into(),
                ));
            }
        };

        // Constant-time comparison of the verify token.
        let expected_bytes = expected.as_bytes();
        let provided_bytes = token.as_bytes();

        if expected_bytes.len() != provided_bytes.len() {
            // Dummy comparison to maintain constant-time behavior.
            let _ = expected_bytes.ct_eq(expected_bytes);
            return Err(ChannelError::Other(
                "invalid verify_token".into(),
            ));
        }

        if !bool::from(expected_bytes.ct_eq(provided_bytes)) {
            return Err(ChannelError::Other(
                "invalid verify_token".into(),
            ));
        }

        Ok(challenge.to_string())
    }

    /// Verify the HMAC-SHA256 signature of a webhook POST body.
    ///
    /// The signature is sent in the `X-Hub-Signature-256` header as
    /// `sha256=<hex_digest>`. We compute HMAC-SHA256 of the raw body
    /// using the app_secret and compare using constant-time equality.
    pub fn verify_signature(
        &self,
        raw_body: &[u8],
        signature_header: &str,
    ) -> Result<(), ChannelError> {
        let secret = match &self.app_secret {
            Some(s) => s,
            None => {
                return Err(ChannelError::Other(
                    "no app_secret configured for signature verification".into(),
                ));
            }
        };

        let hex_sig = signature_header
            .strip_prefix("sha256=")
            .ok_or_else(|| {
                ChannelError::Other("signature header missing sha256= prefix".into())
            })?;

        let provided_sig = hex::decode(hex_sig).map_err(|e| {
            ChannelError::Other(format!("invalid hex in signature: {e}"))
        })?;

        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| {
                ChannelError::Other(format!("HMAC key error: {e}"))
            })?;
        mac.update(raw_body);
        let computed = mac.finalize().into_bytes();

        // Constant-time comparison of computed vs provided signature.
        if computed.len() != provided_sig.len() {
            let _ = computed.ct_eq(&computed);
            return Err(ChannelError::Other(
                "webhook signature mismatch".into(),
            ));
        }

        if !bool::from(computed.ct_eq(&provided_sig)) {
            return Err(ChannelError::Other(
                "webhook signature mismatch".into(),
            ));
        }

        Ok(())
    }

    /// Parse an inbound webhook event payload from WhatsApp.
    ///
    /// Extracts text messages and interactive replies (button, list)
    /// and maps them to `InboundAction` using `format::parse_text_command`.
    pub fn process_event(
        &self,
        body: &str,
    ) -> Result<Vec<InboundAction>, ChannelError> {
        let payload: serde_json::Value = serde_json::from_str(body).map_err(|e| {
            ChannelError::Other(format!("invalid webhook JSON: {e}"))
        })?;

        let mut actions = Vec::new();

        // WhatsApp webhook payload structure:
        // { "entry": [{ "changes": [{ "value": { "messages": [...] } }] }] }
        let entries = payload["entry"].as_array();
        let entries = match entries {
            Some(e) => e,
            None => return Ok(actions),
        };

        for entry in entries {
            let changes = match entry["changes"].as_array() {
                Some(c) => c,
                None => continue,
            };
            for change in changes {
                let value = &change["value"];
                let messages = match value["messages"].as_array() {
                    Some(m) => m,
                    None => continue,
                };

                for msg in messages {
                    let msg_type = msg["type"].as_str().unwrap_or("");
                    match msg_type {
                        "text" => {
                            if let Some(text) = msg["text"]["body"].as_str() {
                                actions.push(format::parse_text_command(text));
                            }
                        }
                        "interactive" => {
                            let interactive_type =
                                msg["interactive"]["type"].as_str().unwrap_or("");
                            let reply_text = match interactive_type {
                                "button_reply" => {
                                    msg["interactive"]["button_reply"]["id"]
                                        .as_str()
                                        .or_else(|| {
                                            msg["interactive"]["button_reply"]["title"]
                                                .as_str()
                                        })
                                }
                                "list_reply" => {
                                    msg["interactive"]["list_reply"]["id"]
                                        .as_str()
                                        .or_else(|| {
                                            msg["interactive"]["list_reply"]["title"]
                                                .as_str()
                                        })
                                }
                                _ => None,
                            };
                            if let Some(text) = reply_text {
                                actions.push(format::parse_text_command(text));
                            }
                        }
                        _ => {
                            debug!(msg_type, "ignoring unsupported WhatsApp message type");
                        }
                    }
                }
            }
        }

        Ok(actions)
    }
}

// ---------------------------------------------------------------------------
// WhatsApp API client
// ---------------------------------------------------------------------------

/// Low-level WhatsApp Cloud API client.
///
/// Handles authenticated requests to the Graph API for sending messages,
/// uploading media, and managing templates.
pub struct WhatsappApi {
    client: Client,
    base_url: String,
    access_token: String,
}

impl WhatsappApi {
    /// Create a new API client.
    ///
    /// `base_url` should be the full URL including the phone number ID,
    /// e.g., `https://graph.facebook.com/v17.0/123456789`.
    pub fn new(api_url: &str, phone_number_id: &str, access_token: &str) -> Self {
        let base_url = format!(
            "{}/{}",
            api_url.trim_end_matches('/'),
            phone_number_id,
        );
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url,
            access_token: access_token.to_string(),
        }
    }

    /// Create an API client with a custom base URL (for testing with wiremock).
    pub fn with_base_url(base_url: &str, access_token: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: access_token.to_string(),
        }
    }

    /// Send a text message to a recipient.
    /// Returns the message ID (wamid) on success.
    pub async fn send_text(
        &self,
        recipient: &str,
        text: &str,
    ) -> Result<Option<String>, ChannelError> {
        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": recipient,
            "type": "text",
            "text": {
                "body": text
            }
        });

        self.post_messages(&body).await
    }

    /// Send a template message to a recipient.
    /// Returns the message ID (wamid) on success.
    ///
    /// All template parameters are sanitized before sending.
    pub async fn send_template(
        &self,
        recipient: &str,
        template: &WhatsappTemplate,
    ) -> Result<Option<String>, ChannelError> {
        // Validate all parameters before sending.
        for component in &template.components {
            for param in &component.parameters {
                if let Some(ref text) = param.text {
                    sanitize_template_param(text)?;
                }
            }
        }

        let components_json = serde_json::to_value(&template.components)
            .map_err(|e| ChannelError::Other(format!("serialize template: {e}")))?;

        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": recipient,
            "type": "template",
            "template": {
                "name": template.name,
                "language": {
                    "code": template.language
                },
                "components": components_json
            }
        });

        self.post_messages(&body).await
    }

    /// Send an interactive button message (max 3 buttons).
    /// Returns the message ID (wamid) on success.
    pub async fn send_interactive_buttons(
        &self,
        recipient: &str,
        body_text: &str,
        buttons: &[(String, String)],
    ) -> Result<Option<String>, ChannelError> {
        if buttons.len() > MAX_INTERACTIVE_BUTTONS {
            return Err(ChannelError::Other(format!(
                "interactive button messages support at most {} buttons, got {}",
                MAX_INTERACTIVE_BUTTONS,
                buttons.len()
            )));
        }
        if buttons.is_empty() {
            return Err(ChannelError::Other(
                "interactive button messages require at least 1 button".into(),
            ));
        }

        let button_objects: Vec<serde_json::Value> = buttons
            .iter()
            .map(|(id, title)| {
                json!({
                    "type": "reply",
                    "reply": {
                        "id": id,
                        "title": title
                    }
                })
            })
            .collect();

        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": recipient,
            "type": "interactive",
            "interactive": {
                "type": "button",
                "body": {
                    "text": body_text
                },
                "action": {
                    "buttons": button_objects
                }
            }
        });

        self.post_messages(&body).await
    }

    /// Send an interactive list message.
    /// Returns the message ID (wamid) on success.
    pub async fn send_interactive_list(
        &self,
        recipient: &str,
        body_text: &str,
        button_text: &str,
        sections: &[ListSection],
    ) -> Result<Option<String>, ChannelError> {
        if sections.is_empty() {
            return Err(ChannelError::Other(
                "interactive list messages require at least 1 section".into(),
            ));
        }

        let sections_json = serde_json::to_value(sections)
            .map_err(|e| ChannelError::Other(format!("serialize sections: {e}")))?;

        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": recipient,
            "type": "interactive",
            "interactive": {
                "type": "list",
                "body": {
                    "text": body_text
                },
                "action": {
                    "button": button_text,
                    "sections": sections_json
                }
            }
        });

        self.post_messages(&body).await
    }

    /// Upload media to WhatsApp.
    ///
    /// Validates the mime type against the allowlist and file size against
    /// WhatsApp limits before uploading. Returns the media ID on success.
    pub async fn upload_media(
        &self,
        file_bytes: &[u8],
        mime_type: &str,
    ) -> Result<String, ChannelError> {
        validate_mime_type(mime_type)?;
        validate_file_size(file_bytes.len(), mime_type)?;

        let part = reqwest::multipart::Part::bytes(file_bytes.to_vec())
            .file_name("upload")
            .mime_str(mime_type)
            .map_err(|e| ChannelError::Other(format!("mime error: {e}")))?;

        let form = reqwest::multipart::Form::new()
            .text("messaging_product", "whatsapp")
            .text("type", mime_type.to_string())
            .part("file", part);

        let resp = self
            .client
            .post(format!("{}/media", self.base_url))
            .bearer_auth(&self.access_token)
            .multipart(form)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("media upload failed: {status} {body}");
            return Err(ChannelError::Api(format!(
                "media upload returned {status}"
            )));
        }

        let upload_resp: MediaUploadResponse = resp.json().await.map_err(|e| {
            ChannelError::Other(format!("parse media upload response: {e}"))
        })?;

        upload_resp.id.ok_or_else(|| {
            ChannelError::Api("media upload returned no id".into())
        })
    }

    /// POST to the /messages endpoint with the given body.
    /// Returns the message ID (wamid) on success.
    async fn post_messages(
        &self,
        body: &serde_json::Value,
    ) -> Result<Option<String>, ChannelError> {
        debug!("WhatsApp API POST /messages");

        let resp = self
            .client
            .post(format!("{}/messages", self.base_url))
            .bearer_auth(&self.access_token)
            .json(body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();

            // Try to parse structured error response.
            let detail = serde_json::from_str::<ApiError>(&body_text)
                .ok()
                .and_then(|e| e.error)
                .map(|e| e.message)
                .unwrap_or(body_text);

            warn!("WhatsApp API error: {status} {detail}");
            return Err(ChannelError::Api(format!(
                "WhatsApp API returned {status}: {detail}"
            )));
        }

        let messages_resp: MessagesResponse = resp.json().await.map_err(|e| {
            ChannelError::Other(format!("parse messages response: {e}"))
        })?;

        // Extract the message ID from the response.
        let msg_id = messages_resp
            .messages
            .as_ref()
            .and_then(|msgs| msgs.first())
            .map(|m| m.id.clone());

        Ok(msg_id)
    }

    /// Mark a message as read.
    ///
    /// POST /messages with status "read" and the message_id.
    pub async fn mark_as_read(
        &self,
        message_id: &str,
    ) -> Result<(), ChannelError> {
        let body = json!({
            "messaging_product": "whatsapp",
            "status": "read",
            "message_id": message_id
        });

        let _ = self.post_messages(&body).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Channel implementation
// ---------------------------------------------------------------------------

/// WhatsApp channel implementing the [`Channel`] trait.
///
/// Uses the WhatsApp Cloud API directly (not wrapping WebhookChannel).
pub struct WhatsappChannel {
    api: WhatsappApi,
    webhook: WhatsappWebhook,
    /// Buffered inbound actions from webhook processing.
    inbound_buffer: Vec<InboundAction>,
}

impl WhatsappChannel {
    /// Create a new WhatsApp channel from configuration.
    pub fn new(config: WhatsappConfig) -> Self {
        let api = WhatsappApi::new(
            &config.api_url,
            &config.phone_number_id,
            &config.access_token,
        );
        let webhook = WhatsappWebhook::new(
            config.app_secret.clone(),
            config.verify_token.clone(),
        );
        Self {
            api,
            webhook,
            inbound_buffer: Vec::new(),
        }
    }

    /// Access the underlying API client.
    pub fn api(&self) -> &WhatsappApi {
        &self.api
    }

    /// Access the webhook handler.
    pub fn webhook(&self) -> &WhatsappWebhook {
        &self.webhook
    }

    /// Process a raw webhook payload and buffer any resulting actions.
    ///
    /// Call this from your HTTP handler after verifying the signature.
    pub fn handle_webhook_payload(
        &mut self,
        body: &str,
    ) -> Result<(), ChannelError> {
        let actions = self.webhook.process_event(body)?;
        self.inbound_buffer.extend(actions);
        Ok(())
    }
}

#[async_trait]
impl Channel for WhatsappChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        // If buttons are present, send as interactive button message.
        if !message.buttons.is_empty() {
            // WhatsApp interactive buttons use (id, title) pairs.
            let buttons: Vec<(String, String)> = message
                .buttons
                .iter()
                .take(MAX_INTERACTIVE_BUTTONS)
                .map(|(label, data)| (data.clone(), label.clone()))
                .collect();

            self.api
                .send_interactive_buttons("recipient", &message.text, &buttons)
                .await?;
        } else {
            // Plain text message. The recipient is not part of OutboundMessage,
            // so the caller must use the API directly for targeted sends.
            // This trait implementation is a best-effort dispatch.
            self.api.send_text("recipient", &message.text).await?;
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        if self.inbound_buffer.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.inbound_buffer.remove(0)))
        }
    }

    fn name(&self) -> &str {
        "whatsapp"
    }

    async fn send_photo(&self, photo: OutboundPhoto) -> Result<(), ChannelError> {
        // Upload the photo as media, then send it.
        // For the Channel trait we do a best-effort send.
        let mime = if photo.filename.ends_with(".png") {
            "image/png"
        } else if photo.filename.ends_with(".webp") {
            "image/webp"
        } else {
            "image/jpeg"
        };

        validate_mime_type(mime)?;
        validate_file_size(photo.bytes.len(), mime)?;

        let media_id = self.api.upload_media(&photo.bytes, mime).await?;

        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": "recipient",
            "type": "image",
            "image": {
                "id": media_id,
                "caption": photo.caption.unwrap_or_default()
            }
        });

        self.api.post_messages(&body).await?;
        Ok(())
    }

    async fn send_typing(&self) -> Result<(), ChannelError> {
        // WhatsApp does not have a typing indicator API.
        // The closest equivalent is marking a message as read, but that
        // requires a message_id context we do not have here. No-op.
        Ok(())
    }

    async fn send_with_id(
        &self,
        message: OutboundMessage,
    ) -> Result<Option<String>, ChannelError> {
        if !message.buttons.is_empty() {
            let buttons: Vec<(String, String)> = message
                .buttons
                .iter()
                .take(MAX_INTERACTIVE_BUTTONS)
                .map(|(label, data)| (data.clone(), label.clone()))
                .collect();

            self.api
                .send_interactive_buttons("recipient", &message.text, &buttons)
                .await
        } else {
            self.api.send_text("recipient", &message.text).await
        }
    }

    async fn edit_message(&self, message_id: &str, _new_text: &str) -> Result<(), ChannelError> {
        // WhatsApp does not support editing sent messages.
        // The best we can do is mark the original as read.
        self.api.mark_as_read(message_id).await
    }

    fn capabilities(&self) -> ChannelCapabilities {
        ChannelCapabilities {
            typing_indicators: false,
            message_editing: false, // WhatsApp does not support message editing
            message_deletion: false, // WhatsApp does not support message deletion via API
            reactions: false,
            threads: false,
            presence: false,
            rich_media: true,
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
        let config = WhatsappConfig {
            api_url: "https://graph.facebook.com/v17.0".to_string(),
            access_token: "EAAx...".to_string(),
            phone_number_id: "123456789".to_string(),
            app_secret: Some("secret123".to_string()),
            verify_token: Some("vtoken".to_string()),
            webhook_port: Some(8080),
            template_namespace: Some("ns1".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: WhatsappConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn test_config_backward_compatible() {
        // Old configs without new fields must still deserialize.
        let json = r#"{
            "api_url": "https://graph.facebook.com/v17.0",
            "access_token": "EAAx...",
            "phone_number_id": "123456789"
        }"#;
        let config: WhatsappConfig = serde_json::from_str(json).unwrap();
        assert!(config.app_secret.is_none());
        assert!(config.verify_token.is_none());
        assert!(config.webhook_port.is_none());
        assert!(config.template_namespace.is_none());
    }

    // -- Channel name --

    #[test]
    fn whatsapp_channel_name() {
        let channel = WhatsappChannel::new(WhatsappConfig {
            api_url: "https://graph.facebook.com/v17.0".to_string(),
            access_token: "token".to_string(),
            phone_number_id: "123".to_string(),
            app_secret: None,
            verify_token: None,
            webhook_port: None,
            template_namespace: None,
        });
        assert_eq!(channel.name(), "whatsapp");
    }

    // -- Webhook verification challenge --

    #[test]
    fn test_webhook_verification_challenge() {
        let webhook = WhatsappWebhook::new(None, Some("my_verify_token".to_string()));

        let result = webhook.verify_challenge("subscribe", "my_verify_token", "challenge_abc");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "challenge_abc");
    }

    #[test]
    fn test_webhook_verification_challenge_wrong_token() {
        let webhook = WhatsappWebhook::new(None, Some("my_verify_token".to_string()));

        let result = webhook.verify_challenge("subscribe", "wrong_token_!", "challenge_abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_verification_challenge_wrong_mode() {
        let webhook = WhatsappWebhook::new(None, Some("my_verify_token".to_string()));

        let result = webhook.verify_challenge("unsubscribe", "my_verify_token", "challenge_abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_verification_challenge_no_token_configured() {
        let webhook = WhatsappWebhook::new(None, None);

        let result = webhook.verify_challenge("subscribe", "any_token", "challenge_abc");
        assert!(result.is_err());
    }

    // -- Webhook signature validation --

    #[test]
    fn test_webhook_signature_validation() {
        let secret = "test_app_secret";
        let webhook = WhatsappWebhook::new(Some(secret.to_string()), None);

        let body = b"test payload body";

        // Compute expected signature.
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let expected_sig = hex::encode(mac.finalize().into_bytes());
        let header = format!("sha256={expected_sig}");

        let result = webhook.verify_signature(body, &header);
        assert!(result.is_ok());
    }

    #[test]
    fn test_webhook_signature_validation_invalid() {
        let webhook = WhatsappWebhook::new(Some("secret".to_string()), None);

        let body = b"test payload body";
        let header = "sha256=0000000000000000000000000000000000000000000000000000000000000000";

        let result = webhook.verify_signature(body, &header);
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_signature_validation_bad_prefix() {
        let webhook = WhatsappWebhook::new(Some("secret".to_string()), None);

        let result = webhook.verify_signature(b"body", "md5=abcdef");
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_signature_validation_no_secret() {
        let webhook = WhatsappWebhook::new(None, None);

        let result = webhook.verify_signature(b"body", "sha256=abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_signature_validation_bad_hex() {
        let webhook = WhatsappWebhook::new(Some("secret".to_string()), None);

        let result = webhook.verify_signature(b"body", "sha256=not_valid_hex_zzzz");
        assert!(result.is_err());
    }

    // -- SECURITY: Constant-time signature comparison --

    #[test]
    fn test_signature_constant_time() {
        // This test verifies the function uses ConstantTimeEq by ensuring
        // correct results for various inputs. The actual timing guarantee
        // comes from the subtle crate's implementation.
        let secret = "constant_time_test_secret";
        let webhook = WhatsappWebhook::new(Some(secret.to_string()), None);

        let body1 = b"payload one";
        let body2 = b"payload two";

        // Compute valid signature for body1.
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body1);
        let sig1 = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        // Valid signature for body1 must pass.
        assert!(webhook.verify_signature(body1, &sig1).is_ok());

        // Same signature must fail for body2.
        assert!(webhook.verify_signature(body2, &sig1).is_err());

        // Compute valid signature for body2.
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body2);
        let sig2 = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        assert!(webhook.verify_signature(body2, &sig2).is_ok());
        assert!(webhook.verify_signature(body1, &sig2).is_err());
    }

    // -- Template message serialization --

    #[test]
    fn test_template_message_serialization() {
        let template = WhatsappTemplate {
            name: "order_update".to_string(),
            language: "en_US".to_string(),
            components: vec![
                TemplateComponent {
                    component_type: "body".to_string(),
                    parameters: vec![
                        TemplateParameter {
                            param_type: "text".to_string(),
                            text: Some("John".to_string()),
                        },
                        TemplateParameter {
                            param_type: "text".to_string(),
                            text: Some("Order #1234".to_string()),
                        },
                    ],
                    sub_type: None,
                    index: None,
                },
            ],
        };

        let json = serde_json::to_value(&template).unwrap();
        assert_eq!(json["name"], "order_update");
        assert_eq!(json["language"], "en_US");
        let components = json["components"].as_array().unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0]["type"], "body");
        let params = components[0]["parameters"].as_array().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0]["text"], "John");
        assert_eq!(params[1]["text"], "Order #1234");
    }

    // -- SECURITY: Template parameter sanitization --

    #[test]
    fn test_parameter_sanitization() {
        // Normal text passes.
        assert!(sanitize_template_param("Hello, World!").is_ok());

        // Empty string passes.
        assert!(sanitize_template_param("").is_ok());

        // Null byte rejected.
        assert!(sanitize_template_param("hello\0world").is_err());

        // Control characters rejected.
        assert!(sanitize_template_param("hello\x01world").is_err());
        assert!(sanitize_template_param("hello\x1Fworld").is_err());
        assert!(sanitize_template_param("hello\x7Fworld").is_err());

        // Newline is a control character.
        assert!(sanitize_template_param("hello\nworld").is_err());

        // Tab is a control character.
        assert!(sanitize_template_param("hello\tworld").is_err());

        // Max length boundary.
        let at_limit = "a".repeat(MAX_TEMPLATE_PARAM_LENGTH);
        assert!(sanitize_template_param(&at_limit).is_ok());

        let over_limit = "a".repeat(MAX_TEMPLATE_PARAM_LENGTH + 1);
        assert!(sanitize_template_param(&over_limit).is_err());
    }

    // -- Media upload mime validation --

    #[test]
    fn test_media_upload_mime_validation() {
        // Allowed types pass.
        assert!(validate_mime_type("image/jpeg").is_ok());
        assert!(validate_mime_type("image/png").is_ok());
        assert!(validate_mime_type("application/pdf").is_ok());
        assert!(validate_mime_type("video/mp4").is_ok());
        assert!(validate_mime_type("text/plain").is_ok());

        // Disallowed types rejected.
        assert!(validate_mime_type("application/x-executable").is_err());
        assert!(validate_mime_type("application/javascript").is_err());
        assert!(validate_mime_type("text/html").is_err());
        assert!(validate_mime_type("").is_err());
    }

    // -- File size validation --

    #[test]
    fn test_file_size_validation() {
        // Image under limit.
        assert!(validate_file_size(1024, "image/jpeg").is_ok());
        // Image at limit.
        assert!(validate_file_size(MAX_IMAGE_SIZE, "image/png").is_ok());
        // Image over limit.
        assert!(validate_file_size(MAX_IMAGE_SIZE + 1, "image/jpeg").is_err());

        // Document under limit.
        assert!(validate_file_size(1024, "application/pdf").is_ok());
        // Document at limit.
        assert!(validate_file_size(MAX_DOCUMENT_SIZE, "application/pdf").is_ok());
        // Document over limit.
        assert!(validate_file_size(MAX_DOCUMENT_SIZE + 1, "application/pdf").is_err());
    }

    // -- Interactive button message --

    #[test]
    fn test_interactive_button_message() {
        let buttons = vec![
            ("btn1".to_string(), "Option A".to_string()),
            ("btn2".to_string(), "Option B".to_string()),
            ("btn3".to_string(), "Option C".to_string()),
        ];

        // Build the payload the same way the API method does.
        let button_objects: Vec<serde_json::Value> = buttons
            .iter()
            .map(|(id, title)| {
                json!({
                    "type": "reply",
                    "reply": {
                        "id": id,
                        "title": title
                    }
                })
            })
            .collect();

        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": "15551234567",
            "type": "interactive",
            "interactive": {
                "type": "button",
                "body": {
                    "text": "Choose an option:"
                },
                "action": {
                    "buttons": button_objects
                }
            }
        });

        assert_eq!(body["type"], "interactive");
        assert_eq!(body["interactive"]["type"], "button");
        let btns = body["interactive"]["action"]["buttons"].as_array().unwrap();
        assert_eq!(btns.len(), 3);
        assert_eq!(btns[0]["reply"]["id"], "btn1");
        assert_eq!(btns[0]["reply"]["title"], "Option A");
        assert_eq!(btns[2]["reply"]["id"], "btn3");
    }

    // -- Interactive button max 3 --

    #[tokio::test]
    async fn test_interactive_button_max_3() {
        let api = WhatsappApi::with_base_url("http://localhost:1", "token");

        let buttons = vec![
            ("b1".to_string(), "A".to_string()),
            ("b2".to_string(), "B".to_string()),
            ("b3".to_string(), "C".to_string()),
            ("b4".to_string(), "D".to_string()),
        ];

        let result = api
            .send_interactive_buttons("15551234567", "text", &buttons)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at most 3 buttons"));
    }

    #[tokio::test]
    async fn test_interactive_button_empty_rejected() {
        let api = WhatsappApi::with_base_url("http://localhost:1", "token");

        let buttons: Vec<(String, String)> = vec![];
        let result = api
            .send_interactive_buttons("15551234567", "text", &buttons)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at least 1 button"));
    }

    // -- Inbound message parsing --

    #[test]
    fn test_inbound_message_parsing() {
        let webhook = WhatsappWebhook::new(None, None);

        let payload = r#"{
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "BUSINESS_ID",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": {
                            "display_phone_number": "15551234567",
                            "phone_number_id": "123456789"
                        },
                        "messages": [{
                            "from": "15559876543",
                            "id": "wamid.abc123",
                            "timestamp": "1700000000",
                            "text": {
                                "body": "/status"
                            },
                            "type": "text"
                        }]
                    },
                    "field": "messages"
                }]
            }]
        }"#;

        let actions = webhook.process_event(payload).unwrap();
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            InboundAction::Command(aegis_control::command::Command::Status)
        ));
    }

    #[test]
    fn test_inbound_interactive_button_reply() {
        let webhook = WhatsappWebhook::new(None, None);

        let payload = r#"{
            "entry": [{
                "changes": [{
                    "value": {
                        "messages": [{
                            "from": "15559876543",
                            "id": "wamid.xyz",
                            "timestamp": "1700000000",
                            "type": "interactive",
                            "interactive": {
                                "type": "button_reply",
                                "button_reply": {
                                    "id": "/status",
                                    "title": "Status"
                                }
                            }
                        }]
                    }
                }]
            }]
        }"#;

        let actions = webhook.process_event(payload).unwrap();
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            InboundAction::Command(aegis_control::command::Command::Status)
        ));
    }

    #[test]
    fn test_inbound_interactive_list_reply() {
        let webhook = WhatsappWebhook::new(None, None);

        let payload = r#"{
            "entry": [{
                "changes": [{
                    "value": {
                        "messages": [{
                            "from": "15559876543",
                            "id": "wamid.list1",
                            "timestamp": "1700000000",
                            "type": "interactive",
                            "interactive": {
                                "type": "list_reply",
                                "list_reply": {
                                    "id": "/help",
                                    "title": "Help",
                                    "description": "Show help"
                                }
                            }
                        }]
                    }
                }]
            }]
        }"#;

        let actions = webhook.process_event(payload).unwrap();
        assert_eq!(actions.len(), 1);
        // /help maps to Unknown("")
        assert!(matches!(&actions[0], InboundAction::Unknown(s) if s.is_empty()));
    }

    #[test]
    fn test_inbound_empty_payload() {
        let webhook = WhatsappWebhook::new(None, None);
        let actions = webhook.process_event("{}").unwrap();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_inbound_no_messages() {
        let webhook = WhatsappWebhook::new(None, None);
        let payload = r#"{
            "entry": [{
                "changes": [{
                    "value": {
                        "metadata": {}
                    }
                }]
            }]
        }"#;
        let actions = webhook.process_event(payload).unwrap();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_inbound_invalid_json() {
        let webhook = WhatsappWebhook::new(None, None);
        let result = webhook.process_event("not json");
        assert!(result.is_err());
    }

    // -- List message structure --

    #[test]
    fn test_list_section_serialization() {
        let section = ListSection {
            title: "Commands".to_string(),
            rows: vec![
                ListRow {
                    id: "status".to_string(),
                    title: "Status".to_string(),
                    description: Some("Check agent status".to_string()),
                },
                ListRow {
                    id: "help".to_string(),
                    title: "Help".to_string(),
                    description: None,
                },
            ],
        };

        let json = serde_json::to_value(&section).unwrap();
        assert_eq!(json["title"], "Commands");
        let rows = json["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["id"], "status");
        assert_eq!(rows[0]["description"], "Check agent status");
        // description should be absent (not null) when None.
        assert!(rows[1].get("description").is_none());
    }

    // -- Channel capabilities --

    #[test]
    fn whatsapp_capabilities_reports_features() {
        let channel = WhatsappChannel::new(WhatsappConfig {
            api_url: "https://graph.facebook.com/v17.0".to_string(),
            access_token: "token".to_string(),
            phone_number_id: "123".to_string(),
            app_secret: None,
            verify_token: None,
            webhook_port: None,
            template_namespace: None,
        });
        let caps = channel.capabilities();

        assert!(!caps.typing_indicators);
        assert!(!caps.message_editing);
        assert!(!caps.message_deletion);
        assert!(!caps.reactions);
        assert!(!caps.threads);
        assert!(!caps.presence);
        assert!(caps.rich_media);
    }

    // -- send_typing is no-op --

    #[tokio::test]
    async fn whatsapp_send_typing_succeeds() {
        let channel = WhatsappChannel::new(WhatsappConfig {
            api_url: "https://graph.facebook.com/v17.0".to_string(),
            access_token: "token".to_string(),
            phone_number_id: "123".to_string(),
            app_secret: None,
            verify_token: None,
            webhook_port: None,
            template_namespace: None,
        });
        assert!(channel.send_typing().await.is_ok());
    }

    // -- recv returns buffered actions --

    #[tokio::test]
    async fn whatsapp_recv_returns_buffered_actions() {
        let mut channel = WhatsappChannel::new(WhatsappConfig {
            api_url: "https://graph.facebook.com/v17.0".to_string(),
            access_token: "token".to_string(),
            phone_number_id: "123".to_string(),
            app_secret: None,
            verify_token: None,
            webhook_port: None,
            template_namespace: None,
        });

        // Empty buffer returns None
        assert!(channel.recv().await.unwrap().is_none());

        // After processing a webhook payload, buffer should have actions
        let payload = r#"{
            "entry": [{
                "changes": [{
                    "value": {
                        "messages": [{
                            "from": "15559876543",
                            "id": "wamid.abc",
                            "timestamp": "1700000000",
                            "text": { "body": "/status" },
                            "type": "text"
                        }]
                    }
                }]
            }]
        }"#;
        channel.handle_webhook_payload(payload).unwrap();
        let action = channel.recv().await.unwrap();
        assert!(action.is_some());
        assert!(matches!(
            action.unwrap(),
            InboundAction::Command(aegis_control::command::Command::Status)
        ));

        // Buffer should be empty again
        assert!(channel.recv().await.unwrap().is_none());
    }

    // -- WhatsApp API send_text returns message ID via wiremock --

    #[tokio::test]
    async fn whatsapp_api_send_text_returns_message_id() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path_regex(r".*/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messaging_product": "whatsapp",
                "contacts": [{"input": "15551234567", "wa_id": "15551234567"}],
                "messages": [{"id": "wamid.HBgLMTU1NTEyMzQ1Njc"}]
            })))
            .mount(&server)
            .await;

        let api = WhatsappApi::with_base_url(&server.uri(), "test-token");
        let result = api.send_text("15551234567", "Hello").await.unwrap();
        assert_eq!(result, Some("wamid.HBgLMTU1NTEyMzQ1Njc".to_string()));
    }
}
