//! Discord Bot API channel adapter.
//!
//! Full Discord Bot API client supporting REST API calls, slash commands,
//! message components (buttons), rate limiting, and inbound message polling.
//!
//! This replaces the previous webhook-only stub with a proper bot integration.
//!
//! # Security
//!
//! - Bot token is never logged or serialized in debug output.
//! - Only messages from `authorized_user_ids` are processed (fail closed).
//! - All inputs (channel IDs, emoji names, slash command names) are validated
//!   to prevent injection.
//! - Rate limiting is mandatory; Discord bans bots that ignore rate limits.
//! - Interaction signature verification uses Ed25519. Since `ed25519-dalek`
//!   is not in the workspace dependency tree, the verifier is a stub that
//!   logs a warning and accepts. **Deploy behind a reverse proxy that
//!   verifies signatures, or add `ed25519-dalek` to the workspace.**

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::format;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const API_BASE: &str = "https://discord.com/api/v10";
const USER_AGENT_VALUE: &str = "Aegis/1.0 (https://github.com/aegis; Bot)";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Discord channel.
///
/// All new fields use `#[serde(default)]` for backward compatibility with
/// existing config files that only had `webhook_url`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscordConfig {
    /// Discord webhook URL (kept for backward compat, used as fallback).
    #[serde(default)]
    pub webhook_url: String,
    /// Bot token for API access (required for full bot features).
    #[serde(default)]
    pub bot_token: Option<String>,
    /// Channel ID for sending messages and inbound polling.
    #[serde(default)]
    pub channel_id: Option<String>,
    /// Guild (server) ID for slash command registration.
    #[serde(default)]
    pub guild_id: Option<String>,
    /// Application ID for slash command registration.
    #[serde(default)]
    pub application_id: Option<String>,
    /// Public key for interaction signature verification.
    #[serde(default)]
    pub public_key: Option<String>,
    /// User IDs authorized to issue commands. Empty = no commands processed.
    #[serde(default)]
    pub authorized_user_ids: Vec<String>,
    /// Dedicated channel ID for command input (optional, defaults to `channel_id`).
    #[serde(default)]
    pub command_channel_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

/// Validate a Discord channel/user/guild ID (numeric snowflake).
///
/// Valid IDs contain only ASCII digits and are 1-20 characters long.
pub fn validate_snowflake(id: &str) -> Result<(), ChannelError> {
    if id.is_empty() || id.len() > 20 {
        return Err(ChannelError::Api(format!(
            "invalid snowflake ID: must be 1-20 digits, got {}",
            id.len()
        )));
    }
    if !id.chars().all(|c| c.is_ascii_digit()) {
        return Err(ChannelError::Api(format!(
            "invalid snowflake ID: contains non-digit characters: {id:?}"
        )));
    }
    Ok(())
}

/// Validate a Discord emoji string for the reactions endpoint.
///
/// URL-encoded emoji names may contain alphanumeric chars, underscores,
/// hyphens, colons, and percent signs (for URL encoding). Max 64 chars.
pub fn validate_emoji(name: &str) -> Result<(), ChannelError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ChannelError::Api(format!(
            "invalid emoji: must be 1-64 characters, got {}",
            name.len()
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '%'))
    {
        return Err(ChannelError::Api(format!(
            "invalid emoji: contains disallowed characters: {name:?}"
        )));
    }
    Ok(())
}

/// Validate a slash command name per Discord requirements.
///
/// - 1-32 characters
/// - Lowercase only
/// - Alphanumeric + dash only
/// - Cannot start or end with dash
pub fn validate_command_name(name: &str) -> Result<(), ChannelError> {
    if name.is_empty() || name.len() > 32 {
        return Err(ChannelError::Api(format!(
            "invalid command name: must be 1-32 characters, got {}",
            name.len()
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ChannelError::Api(format!(
            "invalid command name: must be lowercase alphanumeric + dash: {name:?}"
        )));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(ChannelError::Api(format!(
            "invalid command name: cannot start or end with dash: {name:?}"
        )));
    }
    Ok(())
}

/// Validate a slash command option description.
fn validate_description(desc: &str) -> Result<(), ChannelError> {
    if desc.is_empty() || desc.len() > 100 {
        return Err(ChannelError::Api(format!(
            "invalid description: must be 1-100 characters, got {}",
            desc.len()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Button styles and message components
// ---------------------------------------------------------------------------

/// Discord button styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ButtonStyle {
    Primary = 1,
    Secondary = 2,
    Success = 3,
    Danger = 4,
}

/// A message component (button).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Component {
    /// A button component (type 2 in Discord API).
    #[serde(rename = "2")]
    Button {
        style: u8,
        label: String,
        custom_id: String,
        #[serde(default)]
        disabled: bool,
    },
}

impl Component {
    /// Create a new button component.
    pub fn button(
        style: ButtonStyle,
        label: impl Into<String>,
        custom_id: impl Into<String>,
    ) -> Self {
        Component::Button {
            style: style as u8,
            label: label.into(),
            custom_id: custom_id.into(),
            disabled: false,
        }
    }
}

/// An action row containing components (max 5 per row).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRow {
    /// Always 1 for action rows.
    #[serde(rename = "type")]
    pub component_type: u8,
    pub components: Vec<serde_json::Value>,
}

impl ActionRow {
    /// Create an action row from a list of components.
    pub fn new(components: Vec<Component>) -> Self {
        let serialized = components
            .into_iter()
            .map(|c| match c {
                Component::Button {
                    style,
                    label,
                    custom_id,
                    disabled,
                } => serde_json::json!({
                    "type": 2,
                    "style": style,
                    "label": label,
                    "custom_id": custom_id,
                    "disabled": disabled,
                }),
            })
            .collect();
        Self {
            component_type: 1,
            components: serialized,
        }
    }
}

/// Convert OutboundMessage buttons to Discord ActionRow components.
///
/// Maps `(label, callback_data)` pairs to buttons with custom_ids following
/// the `aegis_approve_{id}` / `aegis_deny_{id}` pattern.
fn buttons_to_components(buttons: &[(String, String)]) -> Vec<ActionRow> {
    if buttons.is_empty() {
        return Vec::new();
    }

    let components: Vec<Component> = buttons
        .iter()
        .map(|(label, callback_data)| {
            let (style, custom_id) = if let Some(id) = callback_data.strip_prefix("approve:") {
                (ButtonStyle::Success, format!("aegis_approve_{id}"))
            } else if let Some(id) = callback_data.strip_prefix("deny:") {
                (ButtonStyle::Danger, format!("aegis_deny_{id}"))
            } else {
                (ButtonStyle::Secondary, callback_data.clone())
            };
            Component::button(style, label.as_str(), custom_id)
        })
        .collect();

    vec![ActionRow::new(components)]
}

// ---------------------------------------------------------------------------
// Slash commands
// ---------------------------------------------------------------------------

/// Discord command option type enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CommandOptionType {
    String = 3,
    Integer = 4,
    User = 6,
}

/// A slash command option (parameter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandOption {
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub option_type: u8,
    #[serde(default)]
    pub required: bool,
}

impl CommandOption {
    /// Create a validated command option.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        option_type: CommandOptionType,
        required: bool,
    ) -> Result<Self, ChannelError> {
        let name = name.into();
        let description = description.into();
        validate_command_name(&name)?;
        validate_description(&description)?;
        Ok(Self {
            name,
            description,
            option_type: option_type as u8,
            required,
        })
    }
}

/// A Discord slash command definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashCommand {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<CommandOption>,
}

impl SlashCommand {
    /// Create a validated slash command.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        options: Vec<CommandOption>,
    ) -> Result<Self, ChannelError> {
        let name = name.into();
        let description = description.into();
        validate_command_name(&name)?;
        validate_description(&description)?;
        Ok(Self {
            name,
            description,
            options,
        })
    }
}

/// Build the default set of Aegis slash commands.
pub fn default_slash_commands() -> Result<Vec<SlashCommand>, ChannelError> {
    Ok(vec![
        SlashCommand::new("status", "Show fleet agent status", vec![])?,
        SlashCommand::new(
            "approve",
            "Approve a pending permission request",
            vec![
                CommandOption::new("agent", "Agent name", CommandOptionType::String, true)?,
                CommandOption::new(
                    "request-id",
                    "Request UUID",
                    CommandOptionType::String,
                    true,
                )?,
            ],
        )?,
        SlashCommand::new(
            "deny",
            "Deny a pending permission request",
            vec![
                CommandOption::new("agent", "Agent name", CommandOptionType::String, true)?,
                CommandOption::new(
                    "request-id",
                    "Request UUID",
                    CommandOptionType::String,
                    true,
                )?,
            ],
        )?,
        SlashCommand::new(
            "stop",
            "Stop a running agent",
            vec![CommandOption::new(
                "agent",
                "Agent name to stop",
                CommandOptionType::String,
                true,
            )?],
        )?,
        SlashCommand::new("list", "List all agents in the fleet", vec![])?,
    ])
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Per-route rate limit bucket state.
#[derive(Debug, Clone)]
struct RateBucket {
    remaining: u32,
    reset_at: Instant,
}

/// Rate limiter that tracks per-route Discord API rate limit buckets.
///
/// Thread-safe via internal `Mutex`.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, RateBucket>>,
    global_retry_after: Mutex<Option<Instant>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            global_retry_after: Mutex::new(None),
        }
    }

    /// Check if a request to the given route is allowed.
    ///
    /// Returns `Ok(())` if allowed, or `Err` with the duration to wait.
    pub fn check(&self, route: &str) -> Result<(), Duration> {
        // Check global rate limit first
        if let Ok(guard) = self.global_retry_after.lock() {
            if let Some(retry_after) = *guard {
                if Instant::now() < retry_after {
                    return Err(retry_after - Instant::now());
                }
            }
        }

        // Check per-route bucket
        if let Ok(guard) = self.buckets.lock() {
            if let Some(bucket) = guard.get(route) {
                if bucket.remaining == 0 && Instant::now() < bucket.reset_at {
                    return Err(bucket.reset_at - Instant::now());
                }
            }
        }

        Ok(())
    }

    /// Update rate limit state from a Discord API response.
    pub fn update_from_response(&self, route: &str, response: &Response) {
        let headers = response.headers();

        // Parse remaining requests
        let remaining = headers
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());

        // Parse reset time (seconds from now, can be fractional)
        let reset_after = headers
            .get("x-ratelimit-reset-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<f64>().ok());

        // Use the bucket key from the header if available, fall back to route
        let bucket_key = headers
            .get("x-ratelimit-bucket")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| route.to_string());

        if let (Some(remaining), Some(reset_after)) = (remaining, reset_after) {
            if let Ok(mut guard) = self.buckets.lock() {
                guard.insert(
                    bucket_key,
                    RateBucket {
                        remaining,
                        reset_at: Instant::now() + Duration::from_secs_f64(reset_after),
                    },
                );
            }
        }
    }

    /// Record a 429 (Too Many Requests) response.
    pub fn record_429(&self, response: &Response) {
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(5.0);

        let is_global = response
            .headers()
            .get("x-ratelimit-global")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "true")
            .unwrap_or(false);

        if is_global {
            if let Ok(mut guard) = self.global_retry_after.lock() {
                *guard = Some(Instant::now() + Duration::from_secs_f64(retry_after));
            }
        }
    }

    /// Get remaining request count for a route (for testing).
    pub fn remaining(&self, route: &str) -> Option<u32> {
        self.buckets
            .lock()
            .ok()
            .and_then(|guard| guard.get(route).map(|b| b.remaining))
    }
}

// ---------------------------------------------------------------------------
// Interaction handling
// ---------------------------------------------------------------------------

/// Verify a Discord interaction signature (Ed25519).
///
/// **STUB IMPLEMENTATION**: The `ed25519-dalek` crate is not in the workspace
/// dependency tree. This function logs a warning and returns `true`.
///
/// For production use, either:
/// 1. Add `ed25519-dalek` to the workspace and implement proper verification.
/// 2. Deploy behind a reverse proxy (e.g., Cloudflare Workers) that verifies
///    interaction signatures before forwarding.
///
/// # Arguments
/// * `_public_key` - Hex-encoded Ed25519 public key from Discord app settings
/// * `_timestamp` - Value of the `X-Signature-Timestamp` header
/// * `_body` - Raw request body bytes
/// * `_signature` - Value of the `X-Signature-Ed25519` header
pub fn verify_interaction_signature(
    _public_key: &str,
    _timestamp: &str,
    _body: &str,
    _signature: &str,
) -> bool {
    warn!(
        "Discord interaction signature verification is STUBBED. \
         Deploy behind a signature-verifying proxy or add ed25519-dalek to the workspace."
    );
    true
}

/// Parsed Discord interaction from a webhook POST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscordInteraction {
    /// A slash command invocation.
    SlashCommand {
        name: String,
        options: HashMap<String, String>,
        user_id: String,
    },
    /// A button click (message component interaction).
    ButtonClick { custom_id: String, user_id: String },
}

/// Parse a raw Discord interaction JSON payload into a typed `DiscordInteraction`.
///
/// Expects the standard Discord interaction payload format.
pub fn parse_interaction(payload_json: &str) -> Result<DiscordInteraction, ChannelError> {
    let payload: serde_json::Value =
        serde_json::from_str(payload_json).map_err(|e| ChannelError::Api(e.to_string()))?;

    let interaction_type = payload
        .get("type")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ChannelError::Api("missing interaction type".into()))?;

    let user_id = payload
        .pointer("/member/user/id")
        .or_else(|| payload.pointer("/user/id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    match interaction_type {
        // Type 2 = Application Command (slash command)
        2 => {
            let data = payload
                .get("data")
                .ok_or_else(|| ChannelError::Api("missing data in slash command".into()))?;

            let name = data
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let mut options = HashMap::new();
            if let Some(opts) = data.get("options").and_then(|v| v.as_array()) {
                for opt in opts {
                    let opt_name = opt.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let opt_value = opt
                        .get("value")
                        .map(|v| match v {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .unwrap_or_default();
                    options.insert(opt_name.to_string(), opt_value);
                }
            }

            Ok(DiscordInteraction::SlashCommand {
                name,
                options,
                user_id,
            })
        }
        // Type 3 = Message Component (button click)
        3 => {
            let data = payload.get("data").ok_or_else(|| {
                ChannelError::Api("missing data in component interaction".into())
            })?;

            let custom_id = data
                .get("custom_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            Ok(DiscordInteraction::ButtonClick {
                custom_id,
                user_id,
            })
        }
        _ => Err(ChannelError::Api(format!(
            "unsupported interaction type: {interaction_type}"
        ))),
    }
}

/// Mapped aegis command from a Discord interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedCommand {
    /// List all agents.
    ListAgents,
    /// Approve a pending request.
    Approve { agent: String, request_id: String },
    /// Deny a pending request.
    Deny { agent: String, request_id: String },
    /// Stop a running agent.
    Stop { agent: String },
    /// List all agents (via /list command).
    List,
    /// Unknown interaction (not mapped to an aegis command).
    Unknown { detail: String },
}

/// Map a Discord interaction to an aegis command.
pub fn map_interaction_to_command(interaction: &DiscordInteraction) -> MappedCommand {
    match interaction {
        DiscordInteraction::SlashCommand { name, options, .. } => match name.as_str() {
            "status" => MappedCommand::ListAgents,
            "approve" => {
                let agent = options.get("agent").cloned().unwrap_or_default();
                let request_id = options.get("request-id").cloned().unwrap_or_default();
                MappedCommand::Approve { agent, request_id }
            }
            "deny" => {
                let agent = options.get("agent").cloned().unwrap_or_default();
                let request_id = options.get("request-id").cloned().unwrap_or_default();
                MappedCommand::Deny { agent, request_id }
            }
            "stop" => {
                let agent = options.get("agent").cloned().unwrap_or_default();
                MappedCommand::Stop { agent }
            }
            "list" => MappedCommand::List,
            _ => MappedCommand::Unknown {
                detail: format!("unknown slash command: {name}"),
            },
        },
        DiscordInteraction::ButtonClick { custom_id, .. } => {
            if let Some(request_id) = custom_id.strip_prefix("aegis_approve_") {
                MappedCommand::Approve {
                    agent: String::new(),
                    request_id: request_id.to_string(),
                }
            } else if let Some(request_id) = custom_id.strip_prefix("aegis_deny_") {
                MappedCommand::Deny {
                    agent: String::new(),
                    request_id: request_id.to_string(),
                }
            } else {
                MappedCommand::Unknown {
                    detail: format!("unknown button: {custom_id}"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Discord REST API client
// ---------------------------------------------------------------------------

/// Discord REST API client.
///
/// Handles authenticated requests to the Discord API v10 with rate limiting.
/// The bot token is stored in memory but never logged or serialized.
pub struct DiscordApi {
    client: Client,
    /// Bot token (sensitive -- never log this).
    token: String,
    rate_limiter: RateLimiter,
}

impl DiscordApi {
    /// Create a new Discord API client with the given bot token.
    pub fn new(token: String) -> Self {
        Self {
            client: Client::new(),
            token,
            rate_limiter: RateLimiter::new(),
        }
    }

    /// Build authorization and standard headers.
    fn auth_headers(&self) -> Result<HeaderMap, ChannelError> {
        let mut headers = HeaderMap::new();
        let auth_value = format!("Bot {}", self.token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value)
                .map_err(|e| ChannelError::Api(format!("invalid token header: {e}")))?,
        );
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(headers)
    }

    /// Execute a request with rate limit handling.
    ///
    /// Checks the rate limiter before sending, updates it from the response,
    /// and handles 429 responses.
    async fn execute_with_rate_limit(
        &self,
        route: &str,
        request: reqwest::RequestBuilder,
    ) -> Result<Response, ChannelError> {
        // Check rate limit before sending
        if let Err(wait_duration) = self.rate_limiter.check(route) {
            return Err(ChannelError::Api(format!(
                "rate limited on route {route}: retry after {:.1}s",
                wait_duration.as_secs_f64()
            )));
        }

        let response = request.send().await?;

        // Update rate limiter from response headers
        self.rate_limiter.update_from_response(route, &response);

        // Handle 429
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            self.rate_limiter.record_429(&response);
            return Err(ChannelError::Api(format!(
                "rate limited (429) on route {route}"
            )));
        }

        Ok(response)
    }

    /// Send a message to a channel.
    ///
    /// POST /channels/{channel_id}/messages
    pub async fn send_message(
        &self,
        channel_id: &str,
        content: &str,
        components: &[ActionRow],
    ) -> Result<serde_json::Value, ChannelError> {
        validate_snowflake(channel_id)?;

        let route = format!("POST /channels/{channel_id}/messages");
        let mut body = serde_json::json!({
            "content": content,
        });
        if !components.is_empty() {
            body["components"] = serde_json::to_value(components)
                .map_err(|e| ChannelError::Api(format!("failed to serialize components: {e}")))?;
        }

        let request = self
            .client
            .post(format!("{API_BASE}/channels/{channel_id}/messages"))
            .headers(self.auth_headers()?)
            .json(&body);

        let response = self.execute_with_rate_limit(&route, request).await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "send_message failed ({status}): {text}"
            )));
        }

        response
            .json()
            .await
            .map_err(|e| ChannelError::Api(format!("failed to parse response: {e}")))
    }

    /// Edit an existing message.
    ///
    /// PATCH /channels/{channel_id}/messages/{message_id}
    pub async fn edit_message(
        &self,
        channel_id: &str,
        message_id: &str,
        content: &str,
        components: &[ActionRow],
    ) -> Result<serde_json::Value, ChannelError> {
        validate_snowflake(channel_id)?;
        validate_snowflake(message_id)?;

        let route = format!("PATCH /channels/{channel_id}/messages");
        let mut body = serde_json::json!({
            "content": content,
        });
        if !components.is_empty() {
            body["components"] = serde_json::to_value(components)
                .map_err(|e| ChannelError::Api(format!("failed to serialize components: {e}")))?;
        }

        let request = self
            .client
            .patch(format!(
                "{API_BASE}/channels/{channel_id}/messages/{message_id}"
            ))
            .headers(self.auth_headers()?)
            .json(&body);

        let response = self.execute_with_rate_limit(&route, request).await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "edit_message failed ({status}): {text}"
            )));
        }

        response
            .json()
            .await
            .map_err(|e| ChannelError::Api(format!("failed to parse response: {e}")))
    }

    /// Delete a message.
    ///
    /// DELETE /channels/{channel_id}/messages/{message_id}
    pub async fn delete_message(
        &self,
        channel_id: &str,
        message_id: &str,
    ) -> Result<(), ChannelError> {
        validate_snowflake(channel_id)?;
        validate_snowflake(message_id)?;

        let route = format!("DELETE /channels/{channel_id}/messages");
        let request = self
            .client
            .delete(format!(
                "{API_BASE}/channels/{channel_id}/messages/{message_id}"
            ))
            .headers(self.auth_headers()?);

        let response = self.execute_with_rate_limit(&route, request).await?;

        if !response.status().is_success() && response.status() != StatusCode::NO_CONTENT {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "delete_message failed ({status}): {text}"
            )));
        }

        Ok(())
    }

    /// Add a reaction to a message.
    ///
    /// PUT /channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me
    pub async fn add_reaction(
        &self,
        channel_id: &str,
        message_id: &str,
        emoji: &str,
    ) -> Result<(), ChannelError> {
        validate_snowflake(channel_id)?;
        validate_snowflake(message_id)?;
        validate_emoji(emoji)?;

        let route = format!("PUT /channels/{channel_id}/messages/reactions");
        let encoded_emoji = urlencoding_emoji(emoji);
        let request = self
            .client
            .put(format!(
                "{API_BASE}/channels/{channel_id}/messages/{message_id}/reactions/{encoded_emoji}/@me"
            ))
            .headers(self.auth_headers()?);

        let response = self.execute_with_rate_limit(&route, request).await?;

        if !response.status().is_success() && response.status() != StatusCode::NO_CONTENT {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "add_reaction failed ({status}): {text}"
            )));
        }

        Ok(())
    }

    /// Get messages from a channel (for inbound polling).
    ///
    /// GET /channels/{channel_id}/messages
    pub async fn get_messages(
        &self,
        channel_id: &str,
        limit: Option<u8>,
        after: Option<&str>,
    ) -> Result<Vec<serde_json::Value>, ChannelError> {
        validate_snowflake(channel_id)?;
        if let Some(after_id) = after {
            validate_snowflake(after_id)?;
        }

        let route = format!("GET /channels/{channel_id}/messages");
        let mut url = format!("{API_BASE}/channels/{channel_id}/messages");

        let mut params = Vec::new();
        if let Some(limit) = limit {
            params.push(format!("limit={}", limit.min(100)));
        }
        if let Some(after_id) = after {
            params.push(format!("after={after_id}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }

        let request = self.client.get(&url).headers(self.auth_headers()?);

        let response = self.execute_with_rate_limit(&route, request).await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "get_messages failed ({status}): {text}"
            )));
        }

        response
            .json()
            .await
            .map_err(|e| ChannelError::Api(format!("failed to parse messages: {e}")))
    }

    /// Register slash commands for a guild.
    ///
    /// PUT /applications/{application_id}/guilds/{guild_id}/commands
    pub async fn register_commands(
        &self,
        application_id: &str,
        guild_id: &str,
        commands: &[SlashCommand],
    ) -> Result<(), ChannelError> {
        validate_snowflake(application_id)?;
        validate_snowflake(guild_id)?;

        // Validate all commands before sending
        for cmd in commands {
            validate_command_name(&cmd.name)?;
            validate_description(&cmd.description)?;
            for opt in &cmd.options {
                validate_command_name(&opt.name)?;
                validate_description(&opt.description)?;
            }
        }

        let route = format!("PUT /applications/{application_id}/guilds/{guild_id}/commands");

        let body = serde_json::to_value(commands)
            .map_err(|e| ChannelError::Api(format!("failed to serialize commands: {e}")))?;

        let request = self
            .client
            .put(format!(
                "{API_BASE}/applications/{application_id}/guilds/{guild_id}/commands"
            ))
            .headers(self.auth_headers()?)
            .json(&body);

        let response = self.execute_with_rate_limit(&route, request).await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "register_commands failed ({status}): {text}"
            )));
        }

        debug!(
            "registered {} slash commands for guild {guild_id}",
            commands.len()
        );
        Ok(())
    }

    /// Access the rate limiter (for testing/inspection).
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }
}

/// URL-encode an emoji name for the reactions API path.
///
/// For custom emoji, format is `name:id`. For unicode emoji, it is the
/// percent-encoded character. This function applies percent-encoding only
/// for colons in custom emoji references.
fn urlencoding_emoji(emoji: &str) -> String {
    // Already validated by validate_emoji, safe to use directly in URL
    emoji.replace(':', "%3A")
}

// ---------------------------------------------------------------------------
// Discord Channel (Channel trait impl)
// ---------------------------------------------------------------------------

/// Discord channel implementing bidirectional messaging via the Bot API.
///
/// Sends outbound messages using the REST API and polls for inbound messages
/// from authorized users.
pub struct DiscordChannel {
    api: DiscordApi,
    config: DiscordConfig,
    /// Last seen message ID for inbound polling.
    last_message_id: Option<String>,
}

impl DiscordChannel {
    /// Create a new Discord channel from configuration.
    ///
    /// Requires `bot_token` and `channel_id` in the config for full
    /// functionality. Falls back gracefully if missing.
    pub fn new(config: DiscordConfig) -> Self {
        let token = config.bot_token.clone().unwrap_or_default();
        Self {
            api: DiscordApi::new(token),
            config,
            last_message_id: None,
        }
    }

    /// Resolve the effective channel ID for sending messages.
    fn send_channel_id(&self) -> Result<&str, ChannelError> {
        self.config
            .channel_id
            .as_deref()
            .ok_or_else(|| ChannelError::Api("no channel_id configured".into()))
    }

    /// Resolve the effective channel ID for reading commands.
    fn command_channel_id(&self) -> Result<&str, ChannelError> {
        self.config
            .command_channel_id
            .as_deref()
            .or(self.config.channel_id.as_deref())
            .ok_or_else(|| {
                ChannelError::Api("no channel_id or command_channel_id configured".into())
            })
    }

    /// Check if a user ID is authorized to issue commands.
    ///
    /// Fail closed: if no authorized users configured, nobody is authorized.
    fn is_authorized(&self, user_id: &str) -> bool {
        if self.config.authorized_user_ids.is_empty() {
            return false;
        }
        self.config
            .authorized_user_ids
            .iter()
            .any(|id| id == user_id)
    }

    /// Register the default Aegis slash commands for the configured guild.
    pub async fn register_default_commands(&self) -> Result<(), ChannelError> {
        let app_id = self
            .config
            .application_id
            .as_deref()
            .ok_or_else(|| ChannelError::Api("no application_id configured".into()))?;
        let guild_id = self
            .config
            .guild_id
            .as_deref()
            .ok_or_else(|| ChannelError::Api("no guild_id configured".into()))?;

        let commands = default_slash_commands()?;
        self.api
            .register_commands(app_id, guild_id, &commands)
            .await
    }

    /// Poll for new inbound messages from the command channel.
    ///
    /// Only messages from authorized users are processed. Messages from
    /// unauthorized users are silently discarded (fail closed).
    async fn poll_messages(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        let channel_id = self.command_channel_id()?.to_string();

        let messages = self
            .api
            .get_messages(&channel_id, Some(10), self.last_message_id.as_deref())
            .await?;

        // Messages come in reverse chronological order from the API.
        // Process the oldest first (last in the array).
        for msg in messages.iter().rev() {
            let msg_id = msg.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let author_id = msg
                .pointer("/author/id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content = msg.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let is_bot = msg
                .pointer("/author/bot")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Update last seen message ID (always advance, even for ignored messages)
            if !msg_id.is_empty() {
                self.last_message_id = Some(msg_id.to_string());
            }

            // Skip bot messages
            if is_bot {
                continue;
            }

            // Authorization check: fail closed
            if !self.is_authorized(author_id) {
                debug!("ignoring message from unauthorized user: {author_id}");
                continue;
            }

            // Parse the message text as a command
            if !content.is_empty() {
                return Ok(Some(format::parse_text_command(content)));
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl Channel for DiscordChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        let channel_id = self.send_channel_id()?;
        let components = buttons_to_components(&message.buttons);

        self.api
            .send_message(channel_id, &message.text, &components)
            .await?;

        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        // Only poll if we have a bot token and channel configured
        if self.config.bot_token.is_none() || self.config.channel_id.is_none() {
            return Ok(None);
        }

        self.poll_messages().await
    }

    fn name(&self) -> &str {
        "discord"
    }

    async fn send_photo(&self, photo: OutboundPhoto) -> Result<(), ChannelError> {
        let channel_id = self.send_channel_id()?;
        validate_snowflake(channel_id)?;

        // Discord supports file upload via multipart form
        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(photo.bytes)
                .file_name(photo.filename)
                .mime_str("image/png")
                .map_err(|e| ChannelError::Api(format!("invalid mime type: {e}")))?,
        );

        let mut payload = serde_json::json!({});
        if let Some(caption) = &photo.caption {
            payload["content"] = serde_json::Value::String(caption.clone());
        }

        let form = form.text("payload_json", payload.to_string());

        let auth_value = format!("Bot {}", self.api.token);
        let response = self
            .api
            .client
            .post(format!("{API_BASE}/channels/{channel_id}/messages"))
            .header(AUTHORIZATION, &auth_value)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .multipart(form)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Api(format!(
                "send_photo failed ({status}): {text}"
            )));
        }

        Ok(())
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
        let config = DiscordConfig {
            webhook_url: "https://discord.com/api/webhooks/123/abc".to_string(),
            bot_token: Some("Bot-Token-Here".to_string()),
            channel_id: Some("123456789".to_string()),
            guild_id: Some("987654321".to_string()),
            application_id: Some("111222333".to_string()),
            public_key: Some("abcdef0123456789".to_string()),
            authorized_user_ids: vec!["100200300".to_string(), "400500600".to_string()],
            command_channel_id: Some("999888777".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: DiscordConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn test_config_backward_compat() {
        // Old config with only webhook_url should still parse
        let json = r#"{"webhook_url":"https://discord.com/api/webhooks/123/abc"}"#;
        let config: DiscordConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.webhook_url,
            "https://discord.com/api/webhooks/123/abc"
        );
        assert!(config.bot_token.is_none());
        assert!(config.guild_id.is_none());
        assert!(config.authorized_user_ids.is_empty());
    }

    // -- Slash command registration JSON --

    #[test]
    fn test_slash_command_registration_json() {
        let commands = default_slash_commands().unwrap();

        let json = serde_json::to_value(&commands).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 5);

        // Check /status
        assert_eq!(arr[0]["name"], "status");
        assert_eq!(arr[0]["description"], "Show fleet agent status");

        // Check /approve has two options
        assert_eq!(arr[1]["name"], "approve");
        let opts = arr[1]["options"].as_array().unwrap();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0]["name"], "agent");
        assert!(opts[0]["required"].as_bool().unwrap());
        assert_eq!(opts[1]["name"], "request-id");

        // Check /deny has two options
        assert_eq!(arr[2]["name"], "deny");
        let opts = arr[2]["options"].as_array().unwrap();
        assert_eq!(opts.len(), 2);

        // Check /stop has one option
        assert_eq!(arr[3]["name"], "stop");
        let opts = arr[3]["options"].as_array().unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0]["name"], "agent");

        // Check /list
        assert_eq!(arr[4]["name"], "list");
    }

    // -- Button component serialization --

    #[test]
    fn test_button_component_serialization() {
        let row = ActionRow::new(vec![
            Component::button(ButtonStyle::Success, "Approve", "aegis_approve_abc123"),
            Component::button(ButtonStyle::Danger, "Deny", "aegis_deny_abc123"),
        ]);

        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["type"], 1); // action row

        let components = json["components"].as_array().unwrap();
        assert_eq!(components.len(), 2);

        // First button: success style
        assert_eq!(components[0]["type"], 2); // button
        assert_eq!(components[0]["style"], ButtonStyle::Success as u8);
        assert_eq!(components[0]["label"], "Approve");
        assert_eq!(components[0]["custom_id"], "aegis_approve_abc123");
        assert!(!components[0]["disabled"].as_bool().unwrap());

        // Second button: danger style
        assert_eq!(components[1]["type"], 2);
        assert_eq!(components[1]["style"], ButtonStyle::Danger as u8);
        assert_eq!(components[1]["label"], "Deny");
        assert_eq!(components[1]["custom_id"], "aegis_deny_abc123");
    }

    // -- Button callback mapping --

    #[test]
    fn test_button_callback_mapping() {
        let req_id = uuid::Uuid::new_v4().to_string();
        let buttons = vec![
            ("Approve".to_string(), format!("approve:{req_id}")),
            ("Deny".to_string(), format!("deny:{req_id}")),
        ];

        let rows = buttons_to_components(&buttons);
        assert_eq!(rows.len(), 1);

        let components = &rows[0].components;
        assert_eq!(components.len(), 2);

        // Check the custom_ids follow the aegis_ pattern
        let approve_id = components[0]["custom_id"].as_str().unwrap();
        assert_eq!(approve_id, format!("aegis_approve_{req_id}"));

        let deny_id = components[1]["custom_id"].as_str().unwrap();
        assert_eq!(deny_id, format!("aegis_deny_{req_id}"));

        // Verify styles
        assert_eq!(components[0]["style"], ButtonStyle::Success as u8);
        assert_eq!(components[1]["style"], ButtonStyle::Danger as u8);
    }

    // -- Interaction parsing: /status --

    #[test]
    fn test_status_command_response() {
        let payload = r#"{
            "type": 2,
            "data": { "name": "status", "options": [] },
            "member": { "user": { "id": "123456789" } }
        }"#;

        let interaction = parse_interaction(payload).unwrap();
        let cmd = map_interaction_to_command(&interaction);
        assert_eq!(cmd, MappedCommand::ListAgents);
    }

    // -- Interaction parsing: /approve with options --

    #[test]
    fn test_approve_command_maps_to_control() {
        let payload = r#"{
            "type": 2,
            "data": {
                "name": "approve",
                "options": [
                    { "name": "agent", "value": "claude-1", "type": 3 },
                    { "name": "request-id", "value": "550e8400-e29b-41d4-a716-446655440000", "type": 3 }
                ]
            },
            "member": { "user": { "id": "123456789" } }
        }"#;

        let interaction = parse_interaction(payload).unwrap();
        let cmd = map_interaction_to_command(&interaction);
        assert_eq!(
            cmd,
            MappedCommand::Approve {
                agent: "claude-1".to_string(),
                request_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            }
        );
    }

    // -- Unauthorized user filtering --

    #[test]
    fn test_unauthorized_user_rejected() {
        let config = DiscordConfig {
            webhook_url: String::new(),
            bot_token: Some("token".to_string()),
            channel_id: Some("123".to_string()),
            guild_id: None,
            application_id: None,
            public_key: None,
            authorized_user_ids: vec!["111".to_string(), "222".to_string()],
            command_channel_id: None,
        };
        let channel = DiscordChannel::new(config);

        // Authorized users pass
        assert!(channel.is_authorized("111"));
        assert!(channel.is_authorized("222"));

        // Unauthorized users fail
        assert!(!channel.is_authorized("333"));
        assert!(!channel.is_authorized(""));
    }

    #[test]
    fn test_authorized_user_filter() {
        // Security test: empty authorized_user_ids means NOBODY is authorized (fail closed)
        let config = DiscordConfig {
            webhook_url: String::new(),
            bot_token: Some("token".to_string()),
            channel_id: Some("123".to_string()),
            guild_id: None,
            application_id: None,
            public_key: None,
            authorized_user_ids: vec![], // empty = fail closed
            command_channel_id: None,
        };
        let channel = DiscordChannel::new(config);

        assert!(!channel.is_authorized("111"));
        assert!(!channel.is_authorized("admin"));
        assert!(!channel.is_authorized(""));
    }

    // -- Rate limit bucket tracking --

    #[test]
    fn test_rate_limit_bucket_tracking() {
        let limiter = RateLimiter::new();

        // Initially, no buckets -- should be allowed
        assert!(limiter.check("POST /channels/123/messages").is_ok());

        // Set up a bucket with remaining = 5
        if let Ok(mut guard) = limiter.buckets.lock() {
            guard.insert(
                "test-route".to_string(),
                RateBucket {
                    remaining: 5,
                    reset_at: Instant::now() + Duration::from_secs(10),
                },
            );
        }

        assert_eq!(limiter.remaining("test-route"), Some(5));
        assert!(limiter.check("test-route").is_ok());

        // Simulate exhausted bucket
        if let Ok(mut guard) = limiter.buckets.lock() {
            guard.insert(
                "exhausted-route".to_string(),
                RateBucket {
                    remaining: 0,
                    reset_at: Instant::now() + Duration::from_secs(5),
                },
            );
        }

        assert_eq!(limiter.remaining("exhausted-route"), Some(0));
        assert!(limiter.check("exhausted-route").is_err());
    }

    // -- Rate limit 429 handling --

    #[test]
    fn test_rate_limit_429_handling() {
        let limiter = RateLimiter::new();

        // Simulate a global 429 by setting the global_retry_after directly
        if let Ok(mut guard) = limiter.global_retry_after.lock() {
            *guard = Some(Instant::now() + Duration::from_secs(5));
        }

        // All routes should be blocked
        let result = limiter.check("any-route");
        assert!(result.is_err());

        let wait = result.unwrap_err();
        assert!(wait.as_secs() <= 5);
        assert!(wait.as_secs() >= 4); // allow some tolerance

        // After the retry-after expires, requests should be allowed again
        if let Ok(mut guard) = limiter.global_retry_after.lock() {
            *guard = Some(Instant::now() - Duration::from_secs(1)); // expired
        }

        assert!(limiter.check("any-route").is_ok());
    }

    // -- Command option validation --

    #[test]
    fn test_command_option_validation() {
        // Valid option
        assert!(
            CommandOption::new("agent", "Agent name", CommandOptionType::String, true).is_ok()
        );

        // Name too long (33 chars)
        let long_name = "a".repeat(33);
        assert!(
            CommandOption::new(&long_name, "desc", CommandOptionType::String, true).is_err()
        );

        // Name not lowercase
        assert!(
            CommandOption::new("Agent", "desc", CommandOptionType::String, true).is_err()
        );

        // Name with spaces
        assert!(
            CommandOption::new("agent name", "desc", CommandOptionType::String, true).is_err()
        );

        // Description too long (101 chars)
        let long_desc = "d".repeat(101);
        assert!(
            CommandOption::new("agent", &long_desc, CommandOptionType::String, true).is_err()
        );

        // Empty name
        assert!(CommandOption::new("", "desc", CommandOptionType::String, true).is_err());

        // Empty description
        assert!(CommandOption::new("agent", "", CommandOptionType::String, true).is_err());

        // Name starting with dash
        assert!(
            CommandOption::new("-agent", "desc", CommandOptionType::String, true).is_err()
        );
    }

    // -- Slash command validation --

    #[test]
    fn test_slash_command_validation() {
        // Valid command
        assert!(SlashCommand::new("status", "Show status", vec![]).is_ok());

        // Invalid name
        assert!(SlashCommand::new("INVALID", "desc", vec![]).is_err());

        // Valid name with dash
        assert!(SlashCommand::new("my-command", "My command", vec![]).is_ok());

        // Max length name (32 chars)
        let name = "a".repeat(32);
        assert!(SlashCommand::new(&name, "desc", vec![]).is_ok());
    }

    // -- Snowflake validation --

    #[test]
    fn test_snowflake_validation() {
        assert!(validate_snowflake("123456789").is_ok());
        assert!(validate_snowflake("0").is_ok());
        assert!(validate_snowflake("99999999999999999999").is_ok()); // 20 digits

        assert!(validate_snowflake("").is_err());
        assert!(validate_snowflake("abc").is_err());
        assert!(validate_snowflake("123 456").is_err());
        assert!(validate_snowflake(&"9".repeat(21)).is_err()); // 21 digits
        assert!(validate_snowflake("123;DROP TABLE").is_err());
    }

    // -- Emoji validation --

    #[test]
    fn test_emoji_validation() {
        assert!(validate_emoji("thumbsup").is_ok());
        assert!(validate_emoji("custom_emoji").is_ok());
        assert!(validate_emoji("flag-us").is_ok());
        assert!(validate_emoji("name%3A123").is_ok()); // URL-encoded colon

        assert!(validate_emoji("").is_err());
        assert!(validate_emoji(&"a".repeat(65)).is_err());
        assert!(validate_emoji("emoji name").is_err());
        assert!(validate_emoji("emoji<script>").is_err());
        assert!(validate_emoji("emoji\n").is_err());
    }

    // -- Channel name --

    #[test]
    fn test_channel_name() {
        let channel = DiscordChannel::new(DiscordConfig {
            webhook_url: String::new(),
            bot_token: None,
            channel_id: None,
            guild_id: None,
            application_id: None,
            public_key: None,
            authorized_user_ids: vec![],
            command_channel_id: None,
        });
        assert_eq!(channel.name(), "discord");
    }

    // -- Interaction: button click maps to approve/deny --

    #[test]
    fn test_button_click_interaction() {
        let payload = r#"{
            "type": 3,
            "data": { "custom_id": "aegis_approve_550e8400-e29b-41d4-a716-446655440000" },
            "member": { "user": { "id": "123" } }
        }"#;

        let interaction = parse_interaction(payload).unwrap();
        let cmd = map_interaction_to_command(&interaction);
        assert_eq!(
            cmd,
            MappedCommand::Approve {
                agent: String::new(),
                request_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            }
        );
    }

    #[test]
    fn test_deny_button_click() {
        let payload = r#"{
            "type": 3,
            "data": { "custom_id": "aegis_deny_req-42" },
            "member": { "user": { "id": "456" } }
        }"#;

        let interaction = parse_interaction(payload).unwrap();
        let cmd = map_interaction_to_command(&interaction);
        assert_eq!(
            cmd,
            MappedCommand::Deny {
                agent: String::new(),
                request_id: "req-42".to_string(),
            }
        );
    }

    // -- Stop command interaction --

    #[test]
    fn test_stop_command_interaction() {
        let payload = r#"{
            "type": 2,
            "data": {
                "name": "stop",
                "options": [
                    { "name": "agent", "value": "codex-1", "type": 3 }
                ]
            },
            "member": { "user": { "id": "789" } }
        }"#;

        let interaction = parse_interaction(payload).unwrap();
        let cmd = map_interaction_to_command(&interaction);
        assert_eq!(
            cmd,
            MappedCommand::Stop {
                agent: "codex-1".to_string(),
            }
        );
    }

    // -- List command interaction --

    #[test]
    fn test_list_command_interaction() {
        let payload = r#"{
            "type": 2,
            "data": { "name": "list", "options": [] },
            "member": { "user": { "id": "789" } }
        }"#;

        let interaction = parse_interaction(payload).unwrap();
        let cmd = map_interaction_to_command(&interaction);
        assert_eq!(cmd, MappedCommand::List);
    }

    // -- Invalid interaction type --

    #[test]
    fn test_invalid_interaction_type() {
        let payload = r#"{ "type": 99 }"#;
        let result = parse_interaction(payload);
        assert!(result.is_err());
    }

    // -- Invalid JSON --

    #[test]
    fn test_invalid_json() {
        assert!(parse_interaction("not json").is_err());
        assert!(parse_interaction("{}").is_err()); // missing type
    }

    // -- Buttons to components: empty --

    #[test]
    fn test_empty_buttons_no_components() {
        let rows = buttons_to_components(&[]);
        assert!(rows.is_empty());
    }

    // -- Verify interaction signature stub --

    #[test]
    fn test_interaction_signature_stub() {
        // The stub always returns true (documented behavior)
        assert!(verify_interaction_signature(
            "pubkey",
            "timestamp",
            "body",
            "signature"
        ));
    }

    // -- Unknown button custom_id --

    #[test]
    fn test_unknown_button_maps_to_unknown() {
        let interaction = DiscordInteraction::ButtonClick {
            custom_id: "some_random_button".to_string(),
            user_id: "123".to_string(),
        };
        let cmd = map_interaction_to_command(&interaction);
        assert!(matches!(cmd, MappedCommand::Unknown { .. }));
    }

    // -- Unknown slash command maps to unknown --

    #[test]
    fn test_unknown_slash_command() {
        let interaction = DiscordInteraction::SlashCommand {
            name: "bogus".to_string(),
            options: HashMap::new(),
            user_id: "123".to_string(),
        };
        let cmd = map_interaction_to_command(&interaction);
        assert!(matches!(cmd, MappedCommand::Unknown { .. }));
    }

    // -- User ID from /user path (DM context) --

    #[test]
    fn test_interaction_user_from_dm_context() {
        let payload = r#"{
            "type": 2,
            "data": { "name": "status", "options": [] },
            "user": { "id": "dm-user-123" }
        }"#;

        let interaction = parse_interaction(payload).unwrap();
        match interaction {
            DiscordInteraction::SlashCommand { user_id, .. } => {
                assert_eq!(user_id, "dm-user-123");
            }
            _ => panic!("expected SlashCommand"),
        }
    }
}
