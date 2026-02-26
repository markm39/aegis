//! Configuration types for Aegis agent instances.
//!
//! [`AegisConfig`] is the top-level configuration loaded from `aegis.toml`,
//! controlling sandbox paths, policy locations, network rules, isolation
//! backend, and observer settings.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::AegisError;

/// Filename for Aegis configuration files within a config directory.
pub const CONFIG_FILENAME: &str = "aegis.toml";

/// Default filename for Cedar policy files.
pub const DEFAULT_POLICY_FILENAME: &str = "default.cedar";

/// Filename for the SQLite audit ledger database.
pub const LEDGER_FILENAME: &str = "audit.db";

/// Network protocol for access control rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    /// Raw TCP connections.
    Tcp,
    /// UDP datagrams.
    Udp,
    /// Unencrypted HTTP traffic.
    Http,
    /// TLS-encrypted HTTPS traffic.
    Https,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Https => write!(f, "HTTPS"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = AegisError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "TCP" => Ok(Protocol::Tcp),
            "UDP" => Ok(Protocol::Udp),
            "HTTP" => Ok(Protocol::Http),
            "HTTPS" => Ok(Protocol::Https),
            _ => Err(AegisError::ConfigError(format!(
                "unknown protocol: {s:?} (expected TCP, UDP, HTTP, or HTTPS)"
            ))),
        }
    }
}

/// A network access rule specifying which host/port/protocol combinations are allowed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkRule {
    /// Hostname or IP address (e.g., `"api.openai.com"`).
    pub host: String,
    /// Port number; `None` means any port.
    pub port: Option<u16>,
    /// Protocol type.
    pub protocol: Protocol,
}

impl std::fmt::Display for NetworkRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(f, "{} {}:{}", self.protocol, self.host, port),
            None => write!(f, "{} {}", self.protocol, self.host),
        }
    }
}

/// Observer configuration controlling how Aegis monitors filesystem activity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObserverConfig {
    /// No filesystem observation.
    None,
    /// FSEvents-based observation (no privileges required).
    FsEvents {
        /// Whether to perform pre/post snapshot diffing (catches reads, rapid events).
        enable_snapshots: bool,
    },
    /// Endpoint Security logger (requires root + Full Disk Access).
    EndpointSecurity,
}

impl Default for ObserverConfig {
    fn default() -> Self {
        ObserverConfig::FsEvents {
            enable_snapshots: true,
        }
    }
}

impl std::fmt::Display for ObserverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObserverConfig::None => write!(f, "None"),
            ObserverConfig::FsEvents {
                enable_snapshots: true,
            } => {
                write!(f, "FsEvents (snapshots: enabled)")
            }
            ObserverConfig::FsEvents {
                enable_snapshots: false,
            } => {
                write!(f, "FsEvents (snapshots: disabled)")
            }
            ObserverConfig::EndpointSecurity => write!(f, "Endpoint Security"),
        }
    }
}

/// OS-level isolation mechanism for the sandboxed process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IsolationConfig {
    /// macOS Seatbelt (`sandbox-exec`) with an auto-generated SBPL profile.
    Seatbelt {
        /// Optional path to a hand-written SBPL file that overrides the generated profile.
        profile_overrides: Option<PathBuf>,
        /// Paths that the agent is explicitly denied access to at the kernel level.
        ///
        /// These emit `(deny file-* (subpath "..."))` rules in the SBPL profile.
        /// Because SBPL resolves more-specific path predicates first, a deny entry
        /// for a subpath of the workspace correctly overrides the workspace-wide
        /// allow rule — useful for protecting secrets or unrelated project dirs.
        #[serde(default)]
        deny_paths: Vec<PathBuf>,
    },
    /// Docker container isolation with security-hardened defaults.
    Docker(DockerSandboxConfig),
    /// Simple process isolation (no OS-level sandbox). Relies on observer + policy only.
    Process,
    /// No isolation at all. The command runs unsandboxed.
    None,
}

/// Configuration for the Docker sandbox backend.
///
/// Controls the container image, resource limits, network mode, and
/// additional mount points. All security flags (cap-drop, no-new-privileges,
/// read-only rootfs, PID limits) are enforced unconditionally and cannot
/// be disabled through configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
// Eq is implemented manually below because f64 does not derive Eq,
// but bit-exact equality is correct for configuration values.
pub struct DockerSandboxConfig {
    /// Docker image to use (e.g., `"ubuntu:22.04"`).
    #[serde(default = "default_docker_image")]
    pub image: String,
    /// Network mode: `"none"` (default), `"bridge"`, or a custom network name.
    #[serde(default = "default_docker_network")]
    pub network: String,
    /// Memory limit (e.g., `"512m"`).
    #[serde(default = "default_docker_memory")]
    pub memory: String,
    /// CPU limit (e.g., `1.0`).
    #[serde(default = "default_docker_cpus")]
    pub cpus: f64,
    /// PID limit to prevent fork bombs.
    #[serde(default = "default_docker_pids_limit")]
    pub pids_limit: u32,
    /// Size limit for the /tmp tmpfs mount (e.g., `"100m"`).
    #[serde(default = "default_docker_tmpfs_size")]
    pub tmpfs_size: String,
    /// Whether the workspace mount is read-write (default: false = read-only).
    #[serde(default)]
    pub workspace_writable: bool,
    /// Additional read-only bind mounts (`host_path:container_path`).
    #[serde(default)]
    pub extra_mounts: Vec<String>,
    /// Timeout in seconds for container execution. 0 means no timeout.
    #[serde(default = "default_docker_timeout")]
    pub timeout_secs: u64,
}

fn default_docker_image() -> String {
    "ubuntu:22.04".to_string()
}

fn default_docker_network() -> String {
    "none".to_string()
}

fn default_docker_memory() -> String {
    "512m".to_string()
}

fn default_docker_cpus() -> f64 {
    1.0
}

fn default_docker_pids_limit() -> u32 {
    256
}

fn default_docker_tmpfs_size() -> String {
    "100m".to_string()
}

fn default_docker_timeout() -> u64 {
    300
}

impl Default for DockerSandboxConfig {
    fn default() -> Self {
        Self {
            image: default_docker_image(),
            network: default_docker_network(),
            memory: default_docker_memory(),
            cpus: default_docker_cpus(),
            pids_limit: default_docker_pids_limit(),
            tmpfs_size: default_docker_tmpfs_size(),
            workspace_writable: false,
            extra_mounts: Vec::new(),
            timeout_secs: default_docker_timeout(),
        }
    }
}

// f64 does not implement Eq, but for configuration values bit-exact
// equality is the correct semantic. This lets IsolationConfig keep Eq.
impl Eq for DockerSandboxConfig {}

impl std::fmt::Display for IsolationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsolationConfig::Seatbelt {
                profile_overrides: Some(path),
                ..
            } => {
                write!(f, "Seatbelt (overrides: {})", path.display())
            }
            IsolationConfig::Seatbelt {
                profile_overrides: None,
                ..
            } => write!(f, "Seatbelt"),
            IsolationConfig::Docker(cfg) => {
                write!(f, "Docker (image: {}, network: {})", cfg.image, cfg.network)
            }
            IsolationConfig::Process => write!(f, "Process"),
            IsolationConfig::None => write!(f, "None"),
        }
    }
}

/// Default cooldown between repeated alert dispatches for the same rule.
fn default_cooldown() -> u64 {
    60
}

/// A webhook alert rule that fires when audit events match its filters.
///
/// Configured via `[[alerts]]` sections in `aegis.toml`. Each rule specifies
/// a webhook URL and optional filters on decision, action kind, file path,
/// and principal. When an audit event matches all specified filters, a JSON
/// payload is POSTed to the webhook URL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertRule {
    /// Unique name for this alert rule (used in logs and cooldown tracking).
    pub name: String,
    /// HTTP(S) URL to POST the webhook payload to.
    pub webhook_url: String,
    /// Filter: only fire on this decision ("Allow" or "Deny"). `None` matches both.
    pub decision: Option<String>,
    /// Filter: only fire on these action kinds. Empty means all actions.
    #[serde(default)]
    pub action_kinds: Vec<String>,
    /// Filter: glob pattern matched against the event's file path.
    pub path_glob: Option<String>,
    /// Filter: exact match on the agent principal name.
    pub principal: Option<String>,
    /// Minimum seconds between dispatches for this rule (default 60).
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

/// What to do when the pilot adapter cannot determine the action type
/// from an agent's permission prompt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum UncertainAction {
    /// Deny the action (safest default).
    #[default]
    Deny,
    /// Allow the action (permissive mode, useful during initial setup).
    Allow,
    /// Fire a webhook alert and wait for external input.
    Alert,
}

impl std::fmt::Display for UncertainAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UncertainAction::Deny => write!(f, "Deny"),
            UncertainAction::Allow => write!(f, "Allow"),
            UncertainAction::Alert => write!(f, "Alert"),
        }
    }
}

/// A regex-based prompt detection pattern for the generic agent adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptPatternConfig {
    /// Regex pattern to match permission prompt lines.
    /// May contain named capture groups `tool` and `args`.
    pub regex: String,
    /// String to send to the agent to approve the action.
    #[serde(default = "default_approve_response")]
    pub approve: String,
    /// String to send to the agent to deny the action.
    #[serde(default = "default_deny_response")]
    pub deny: String,
}

fn default_approve_response() -> String {
    "y".to_string()
}

fn default_deny_response() -> String {
    "n".to_string()
}

/// Which agent adapter to use for PTY prompt detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdapterConfig {
    /// Built-in Claude Code adapter.
    ClaudeCode,
    /// Built-in Codex adapter.
    Codex,
    /// Regex-based generic adapter with custom patterns.
    Generic {
        /// Custom prompt detection patterns.
        patterns: Vec<PromptPatternConfig>,
    },
    /// Passthrough adapter (no prompt detection; for autonomous tools).
    Passthrough,
    /// Auto-detect based on the command name.
    #[default]
    Auto,
}

impl std::fmt::Display for AdapterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterConfig::ClaudeCode => write!(f, "ClaudeCode"),
            AdapterConfig::Codex => write!(f, "Codex"),
            AdapterConfig::Generic { patterns } => {
                write!(f, "Generic ({} patterns)", patterns.len())
            }
            AdapterConfig::Passthrough => write!(f, "Passthrough"),
            AdapterConfig::Auto => write!(f, "Auto"),
        }
    }
}

/// Default stall detection timeout in seconds.
fn default_stall_timeout_secs() -> u64 {
    120
}

/// Default maximum number of nudges before giving up.
fn default_max_nudges() -> u32 {
    5
}

/// Default nudge message sent to a stalled agent.
fn default_nudge_message() -> String {
    "continue".to_string()
}

/// Stall detection configuration for the pilot supervisor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StallConfig {
    /// Seconds of no output before considering the agent stalled.
    #[serde(default = "default_stall_timeout_secs")]
    pub timeout_secs: u64,
    /// Maximum number of nudges before firing a "max nudges exceeded" alert.
    #[serde(default = "default_max_nudges")]
    pub max_nudges: u32,
    /// Message to send when nudging (written to the agent's stdin).
    #[serde(default = "default_nudge_message")]
    pub nudge_message: String,
}

impl Default for StallConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_stall_timeout_secs(),
            max_nudges: default_max_nudges(),
            nudge_message: default_nudge_message(),
        }
    }
}

/// Default poll interval for the command polling endpoint.
fn default_poll_interval() -> u64 {
    5
}

/// Control plane listener configuration for remote monitoring and commands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ControlConfig {
    /// HTTP listen address (e.g., `"0.0.0.0:8443"`). Empty means disabled.
    #[serde(default)]
    pub http_listen: String,
    /// API key for HTTP authentication. Empty means no auth (not recommended for remote).
    #[serde(default)]
    pub api_key: String,
    /// URL to poll for pending commands (empty means disabled).
    #[serde(default)]
    pub poll_endpoint: String,
    /// Polling interval in seconds.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

/// Default rolling output buffer size in lines.
fn default_output_buffer_lines() -> usize {
    200
}

/// Configuration for the `aegis pilot` PTY supervisor.
///
/// Controls how the pilot detects and responds to agent permission prompts,
/// handles stalls, and accepts remote commands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PilotConfig {
    /// Which agent adapter to use for prompt detection.
    #[serde(default)]
    pub adapter: AdapterConfig,
    /// Stall detection settings.
    #[serde(default)]
    pub stall: StallConfig,
    /// Control plane settings (Unix socket + optional HTTP).
    #[serde(default)]
    pub control: ControlConfig,
    /// Number of recent output lines to keep in the rolling buffer.
    #[serde(default = "default_output_buffer_lines")]
    pub output_buffer_lines: usize,
    /// What to do when a prompt cannot be parsed by the adapter.
    #[serde(default)]
    pub uncertain_action: UncertainAction,
}

impl Default for PilotConfig {
    fn default() -> Self {
        Self {
            adapter: AdapterConfig::default(),
            stall: StallConfig::default(),
            control: ControlConfig::default(),
            output_buffer_lines: default_output_buffer_lines(),
            uncertain_action: UncertainAction::default(),
        }
    }
}

/// Default Telegram Bot API long-poll timeout in seconds.
fn default_poll_timeout_secs() -> u64 {
    30
}

/// Bidirectional messaging channel for remote control and notifications.
///
/// The channel receives pilot events and alert events (outbound) and
/// forwards user commands back to the supervisor (inbound). Supports
/// Telegram, Slack, Discord, and many more backends.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChannelConfig {
    /// Telegram Bot API channel.
    Telegram(TelegramConfig),
    /// Slack Web API channel.
    Slack(SlackConfig),
    /// Generic webhook channel.
    Webhook(WebhookChannelConfig),
    /// Discord webhook channel.
    Discord(DiscordChannelConfig),
    /// WhatsApp Cloud API channel.
    Whatsapp(WhatsappChannelConfig),
    /// Signal messenger channel.
    Signal(SignalChannelConfig),
    /// Matrix protocol channel.
    Matrix(MatrixChannelConfig),
    /// iMessage channel (via API bridge).
    Imessage(ImessageChannelConfig),
    /// IRC channel (via HTTP bridge).
    Irc(IrcChannelConfig),
    /// Microsoft Teams webhook channel.
    Msteams(MsteamsChannelConfig),
    /// Google Chat webhook channel.
    Googlechat(GooglechatChannelConfig),
    /// Feishu (Lark) webhook channel.
    Feishu(FeishuChannelConfig),
    /// LINE Messaging API channel.
    Line(LineChannelConfig),
    /// Nostr relay channel.
    Nostr(NostrChannelConfig),
    /// Mattermost webhook channel.
    Mattermost(MattermostChannelConfig),
    /// Voice call channel (via telephony API).
    VoiceCall(VoiceCallChannelConfig),
    /// Twitch IRC channel.
    Twitch(TwitchChannelConfig),
    /// Nextcloud Talk (Spreed) channel.
    Nextcloud(NextcloudChannelConfig),
    /// Zalo Official Account channel.
    Zalo(ZaloChannelConfig),
    /// Tlon (Urbit) channel.
    Tlon(TlonChannelConfig),
    /// Lobster channel.
    Lobster(LobsterChannelConfig),
    /// Gmail API channel (OAuth2).
    Gmail(GmailChannelConfig),
}

impl ChannelConfig {
    /// Returns the channel type as a lowercase string matching the serde tag.
    pub fn channel_type_name(&self) -> &'static str {
        match self {
            Self::Telegram(_) => "telegram",
            Self::Slack(_) => "slack",
            Self::Webhook(_) => "webhook",
            Self::Discord(_) => "discord",
            Self::Whatsapp(_) => "whatsapp",
            Self::Signal(_) => "signal",
            Self::Matrix(_) => "matrix",
            Self::Imessage(_) => "imessage",
            Self::Irc(_) => "irc",
            Self::Msteams(_) => "msteams",
            Self::Googlechat(_) => "googlechat",
            Self::Feishu(_) => "feishu",
            Self::Line(_) => "line",
            Self::Nostr(_) => "nostr",
            Self::Mattermost(_) => "mattermost",
            Self::VoiceCall(_) => "voicecall",
            Self::Twitch(_) => "twitch",
            Self::Nextcloud(_) => "nextcloud",
            Self::Zalo(_) => "zalo",
            Self::Tlon(_) => "tlon",
            Self::Lobster(_) => "lobster",
            Self::Gmail(_) => "gmail",
        }
    }
}

/// Configuration for the Telegram messaging channel.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelegramConfig {
    /// Bot token from @BotFather (or `$AEGIS_TELEGRAM_BOT_TOKEN` env var).
    pub bot_token: String,
    /// Chat ID to send messages to and accept commands from.
    pub chat_id: i64,
    /// Long-poll timeout for `getUpdates` in seconds.
    #[serde(default = "default_poll_timeout_secs")]
    pub poll_timeout_secs: u64,
    /// Whether to accept commands from group chats (not just the configured chat_id).
    #[serde(default)]
    pub allow_group_commands: bool,
    /// Optional active hours window for outbound notifications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
    /// Use webhook mode instead of long-polling (default: false).
    #[serde(default)]
    pub webhook_mode: bool,
    /// Port to listen on for incoming webhook requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_port: Option<u16>,
    /// Public URL that Telegram will POST updates to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Secret token for webhook request validation (X-Telegram-Bot-Api-Secret-Token header).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
    /// Enable inline query handling (default: false).
    #[serde(default)]
    pub inline_queries_enabled: bool,
}

impl std::fmt::Debug for TelegramConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramConfig")
            .field("bot_token", &"[REDACTED]")
            .field("chat_id", &self.chat_id)
            .field("poll_timeout_secs", &self.poll_timeout_secs)
            .field("allow_group_commands", &self.allow_group_commands)
            .field("active_hours", &self.active_hours)
            .field("webhook_mode", &self.webhook_mode)
            .field("webhook_port", &self.webhook_port)
            .field("webhook_url", &self.webhook_url)
            .field("webhook_secret", &self.webhook_secret)
            .field("inline_queries_enabled", &self.inline_queries_enabled)
            .finish()
    }
}

/// Configuration for the Slack messaging channel.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlackConfig {
    /// Bot token (xoxb-...).
    pub bot_token: String,
    /// Default channel ID to post into.
    pub channel_id: String,
    /// Optional workspace/team ID for streaming API calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_team_id: Option<String>,
    /// Optional user ID for DM streaming API calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_user_id: Option<String>,
    /// Whether to use Slack streaming API for outbound messages.
    #[serde(default)]
    pub streaming: bool,
    /// Optional active hours window for outbound notifications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
    /// Signing secret for verifying interactive message requests (HMAC-SHA256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_secret: Option<String>,
    /// OAuth client ID for the Slack app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_id: Option<String>,
    /// Port for the interactive message endpoint listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interactive_endpoint_port: Option<u16>,
}

impl std::fmt::Debug for SlackConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackConfig")
            .field("bot_token", &"[REDACTED]")
            .field("channel_id", &self.channel_id)
            .field("recipient_team_id", &self.recipient_team_id)
            .field("recipient_user_id", &self.recipient_user_id)
            .field("streaming", &self.streaming)
            .field("active_hours", &self.active_hours)
            .field("signing_secret", &self.signing_secret)
            .field("oauth_client_id", &self.oauth_client_id)
            .field("interactive_endpoint_port", &self.interactive_endpoint_port)
            .finish()
    }
}

/// Configuration for a generic webhook channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookChannelConfig {
    /// Human-readable channel name.
    pub name: String,
    /// URL to POST outbound messages to.
    pub outbound_url: String,
    /// Optional URL to poll for inbound messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_url: Option<String>,
    /// Optional auth header value (e.g., `"Bearer TOKEN"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_header: Option<String>,
    /// JSON payload template. Use `{text}` for message placeholder.
    #[serde(default = "default_webhook_payload_template")]
    pub payload_template: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

fn default_webhook_payload_template() -> String {
    r#"{"text":"{text}"}"#.to_string()
}

/// Configuration for the Discord channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscordChannelConfig {
    /// Discord webhook URL.
    pub webhook_url: String,
    /// Optional bot token for API access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_token: Option<String>,
    /// Optional channel ID for inbound polling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    /// Guild (server) ID for slash command registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
    /// Application ID for slash command registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// Public key for interaction signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// User IDs authorized to issue commands. Empty = no commands processed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_user_ids: Vec<String>,
    /// Dedicated channel ID for command input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_channel_id: Option<String>,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the WhatsApp Cloud API channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhatsappChannelConfig {
    /// WhatsApp Cloud API base URL.
    pub api_url: String,
    /// Access token for the WhatsApp Business API.
    pub access_token: String,
    /// Phone number ID for sending messages.
    pub phone_number_id: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Signal messenger channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalChannelConfig {
    /// Signal CLI REST API base URL.
    pub api_url: String,
    /// Registered phone number.
    pub phone_number: String,
    /// Recipient phone numbers.
    #[serde(default)]
    pub recipients: Vec<String>,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Matrix protocol channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatrixChannelConfig {
    /// Matrix homeserver URL.
    pub homeserver_url: String,
    /// Access token for the bot account.
    pub access_token: String,
    /// Room ID to send messages to.
    pub room_id: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the iMessage channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImessageChannelConfig {
    /// API bridge URL.
    pub api_url: String,
    /// Recipient phone number or email.
    pub recipient: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the IRC channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrcChannelConfig {
    /// IRC server hostname.
    pub server: String,
    /// IRC channel to join.
    pub channel: String,
    /// Bot nickname.
    pub nick: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Microsoft Teams channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MsteamsChannelConfig {
    /// Incoming Webhook URL for the Teams channel.
    pub webhook_url: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Google Chat channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GooglechatChannelConfig {
    /// Google Chat Incoming Webhook URL.
    pub webhook_url: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Feishu (Lark) channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeishuChannelConfig {
    /// Feishu bot webhook URL.
    pub webhook_url: String,
    /// Optional webhook signing secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the LINE Messaging API channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineChannelConfig {
    /// LINE channel access token.
    pub channel_access_token: String,
    /// Recipient user ID.
    pub user_id: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Nostr relay channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NostrChannelConfig {
    /// Nostr relay WebSocket URL.
    pub relay_url: String,
    /// Private key in hex format for signing events.
    pub private_key_hex: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Mattermost channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MattermostChannelConfig {
    /// Mattermost Incoming Webhook URL.
    pub webhook_url: String,
    /// Optional channel ID to override the webhook default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the voice call channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoiceCallChannelConfig {
    /// Telephony API endpoint URL.
    pub api_url: String,
    /// Caller phone number.
    pub from_number: String,
    /// Recipient phone number.
    pub to_number: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Twitch IRC channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TwitchChannelConfig {
    /// OAuth token for Twitch IRC (oauth: prefix + alphanumeric).
    /// Sensitive: never log this value.
    pub oauth_token: String,
    /// Twitch channel name (alphanumeric + underscore, max 25 chars).
    pub channel_name: String,
    /// Bot username (alphanumeric + underscore, max 25 chars).
    pub bot_username: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Nextcloud Talk channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NextcloudChannelConfig {
    /// Nextcloud server URL (must be HTTPS; private IPs blocked for SSRF prevention).
    pub server_url: String,
    /// Nextcloud username (alphanumeric + dash/underscore/dot, max 64 chars).
    pub username: String,
    /// Nextcloud app password for Basic auth.
    /// Sensitive: never log this value.
    pub app_password: String,
    /// Room token for the Talk conversation (alphanumeric, max 32 chars).
    pub room_token: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Zalo Official Account channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZaloChannelConfig {
    /// Zalo Official Account ID.
    pub oa_id: String,
    /// Access token for the Zalo OA API.
    /// Sensitive: never log this value.
    pub access_token: String,
    /// Secret key for webhook HMAC-SHA256 signature verification.
    /// Sensitive: never log this value.
    pub secret_key: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Tlon (Urbit) channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlonChannelConfig {
    /// Urbit ship API endpoint URL.
    pub ship_url: String,
    /// Urbit ship name (e.g., `~zod`).
    pub ship_name: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Lobster channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LobsterChannelConfig {
    /// Lobster API base URL.
    pub api_url: String,
    /// API key for authentication.
    /// Sensitive: never log this value.
    pub api_key: String,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

/// Configuration for the Gmail API channel (stored in ChannelConfig enum).
///
/// The OAuth2 client secret is read from an environment variable at runtime,
/// never stored in the config file. Only the env var name is persisted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GmailChannelConfig {
    /// OAuth2 client ID from Google Cloud Console.
    pub client_id: String,
    /// Name of the environment variable holding the OAuth2 client secret.
    pub client_secret_env: String,
    /// Google Cloud project ID (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Gmail label IDs to watch. Defaults to `["INBOX"]`.
    #[serde(default = "default_gmail_watch_labels")]
    pub watch_labels: Vec<String>,
    /// Path to store OAuth2 tokens. Defaults to `~/.aegis/gmail/tokens.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_path: Option<std::path::PathBuf>,
    /// Optional active hours window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_hours: Option<ActiveHoursConfig>,
}

fn default_gmail_watch_labels() -> Vec<String> {
    vec!["INBOX".to_string()]
}

/// Access control configuration for messaging channels.
///
/// Controls which chat identifiers have which roles, and optional
/// rate limit overrides. Deserialized from the `[access_control]` section
/// of channel configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessControlConfig {
    /// Default role for unknown users. Valid values: "admin", "user", "viewer".
    /// Defaults to "viewer" (fail-closed).
    #[serde(default = "default_access_control_role")]
    pub default_role: String,
    /// Chat identifiers automatically promoted to Admin role.
    #[serde(default)]
    pub admin_ids: Vec<String>,
    /// Chat identifiers assigned the User role.
    #[serde(default)]
    pub user_ids: Vec<String>,
    /// Optional rate limit override (commands per minute) applied to all users.
    /// When `None`, role-specific defaults apply (Admin: 60, User: 30, Viewer: 10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_minute: Option<u32>,
}

fn default_access_control_role() -> String {
    "viewer".to_string()
}

impl Default for AccessControlConfig {
    fn default() -> Self {
        Self {
            default_role: default_access_control_role(),
            admin_ids: Vec::new(),
            user_ids: Vec::new(),
            rate_limit_per_minute: None,
        }
    }
}

/// Active hours window for channel notifications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveHoursConfig {
    /// Start time in HH:MM (24h).
    pub start: String,
    /// End time in HH:MM (24h). 24:00 allowed.
    pub end: String,
    /// Timezone name (IANA), or "local"/"user" for host local time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// Per-channel command routing configuration.
///
/// Controls which commands are available on each messaging channel,
/// with support for allowlists, blocklists, and aliases. Used by
/// the channel routing module at runtime.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelRoutingConfig {
    /// Global default allowlist. `None` means all non-blocked commands are allowed.
    #[serde(default)]
    pub default_allowed: Option<Vec<String>>,
    /// Global default blocklist. These commands are always denied unless
    /// overridden by a per-channel set.
    #[serde(default)]
    pub default_blocked: Vec<String>,
    /// Per-channel command set overrides, keyed by channel type
    /// (e.g., "telegram", "slack", "discord").
    #[serde(default)]
    pub channels: std::collections::HashMap<String, ChannelCommandSetConfig>,
}

/// Per-channel command set configuration (part of [`ChannelRoutingConfig`]).
///
/// All fields are optional to allow partial overrides. Missing fields
/// inherit from the default set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelCommandSetConfig {
    /// Commands allowed on this channel. `None` means all non-blocked.
    #[serde(default)]
    pub allowed: Option<Vec<String>>,
    /// Commands blocked on this channel.
    #[serde(default)]
    pub blocked: Option<Vec<String>>,
    /// Shorthand aliases (e.g., "s" -> "status").
    #[serde(default)]
    pub aliases: Option<std::collections::HashMap<String, String>>,
}

/// Configuration for the API usage tracking proxy.
///
/// When enabled, Aegis starts a local HTTP reverse proxy that intercepts
/// AI tool API traffic, forwards it to the real upstream, and extracts
/// token/model usage data from responses (including streaming SSE).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageProxyConfig {
    /// Whether usage tracking is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Port to bind the proxy to. 0 means OS-assigned random port.
    #[serde(default)]
    pub port: u16,
    /// Whether to enforce per-provider rate limiting (RPM/TPM).
    /// Uses sensible defaults per provider (e.g., Anthropic: 60 RPM, 100K TPM).
    #[serde(default = "default_true")]
    pub rate_limiting: bool,
    /// Maximum budget in USD cents per agent session. 0 = unlimited.
    /// Example: 500 = $5.00.
    #[serde(default)]
    pub budget_cents: u64,
}

fn default_true() -> bool {
    true
}

impl Default for UsageProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 0,
            rate_limiting: true,
            budget_cents: 0,
        }
    }
}

/// Configuration for audit log data retention (GDPR/CCPA compliance).
///
/// When set, the daemon periodically purges audit entries that exceed
/// the retention window or total entry cap.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Automatically purge entries older than this many days.
    /// None = keep forever.
    #[serde(default)]
    pub max_age_days: Option<u64>,
    /// Cap total audit entries at this count, removing oldest first.
    /// None = no cap.
    #[serde(default)]
    pub max_entries: Option<u64>,
}

/// Configuration for PII redaction in audit logs (GDPR compliance).
///
/// When enabled, the ledger applies pattern-based redaction to entry
/// content before persisting it. Built-in patterns cover email addresses,
/// phone numbers, and IP addresses; custom patterns can be added.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionConfig {
    /// Master toggle for redaction. Default: false (disabled).
    #[serde(default)]
    pub enabled: bool,
    /// Additional regex patterns to redact (pattern -> replacement).
    ///
    /// Example: `{"\\b\\d{3}-\\d{2}-\\d{4}\\b": "[SSN]"}`
    #[serde(default)]
    pub custom_patterns: Vec<RedactionPattern>,
}

/// A single custom PII redaction pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionPattern {
    /// Regex pattern to match.
    pub pattern: String,
    /// Replacement text (e.g., "[SSN]").
    pub replacement: String,
}

/// Top-level configuration for an Aegis agent instance.
///
/// Loaded from `aegis.toml` and controls sandbox directory, policies,
/// audit storage, network rules, isolation backend, observer settings,
/// and real-time webhook alert rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AegisConfig {
    /// Human-readable name for this configuration (also the Cedar principal).
    pub name: String,
    /// Directory the sandboxed process operates within.
    pub sandbox_dir: PathBuf,
    /// Directories containing Cedar policy files (`.cedar`).
    pub policy_paths: Vec<PathBuf>,
    /// Optional path to a Cedar schema file for policy validation.
    pub schema_path: Option<PathBuf>,
    /// Path to the SQLite audit ledger database.
    pub ledger_path: PathBuf,
    /// Network access rules the sandbox enforces.
    pub allowed_network: Vec<NetworkRule>,
    /// Which OS-level isolation mechanism to use.
    pub isolation: IsolationConfig,
    /// How Aegis monitors filesystem activity during execution.
    #[serde(default)]
    pub observer: ObserverConfig,
    /// Webhook alert rules evaluated against every audit event.
    #[serde(default)]
    pub alerts: Vec<AlertRule>,
    /// Pilot PTY supervisor configuration (used by `aegis pilot`).
    #[serde(default)]
    pub pilot: Option<PilotConfig>,
    /// Bidirectional messaging channel (Telegram, Slack, etc.).
    #[serde(default)]
    pub channel: Option<ChannelConfig>,
    /// API usage tracking proxy configuration.
    #[serde(default)]
    pub usage_proxy: Option<UsageProxyConfig>,
}

/// Validate that a config name is safe for use as a directory component.
///
/// Rejects empty names, path separators, `..`, and control characters to
/// prevent path traversal when the name is used in `~/.aegis/<name>/`.
#[must_use = "validation result must be checked to prevent path traversal"]
pub fn validate_config_name(name: &str) -> Result<(), AegisError> {
    if name.is_empty() {
        return Err(AegisError::ConfigError("name cannot be empty".into()));
    }
    if name.chars().all(|c| c == '.') {
        return Err(AegisError::ConfigError(format!("name cannot be {name:?}")));
    }
    // Allow alphanumeric, hyphens, underscores, and dots.
    // This keeps names safe for TOML, command bar tab-completion,
    // daemon protocol, and filesystem paths.
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(AegisError::ConfigError(
            "name may only contain letters, digits, hyphens, underscores, and dots".into(),
        ));
    }
    Ok(())
}

impl AegisConfig {
    /// Parse a configuration from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self, AegisError> {
        toml::from_str(content).map_err(|e| AegisError::ConfigError(e.to_string()))
    }

    /// Serialize the configuration to a TOML string.
    pub fn to_toml(&self) -> Result<String, AegisError> {
        toml::to_string_pretty(self).map_err(|e| AegisError::ConfigError(e.to_string()))
    }

    /// Create a default configuration for a named agent under `base_dir`.
    ///
    /// The sandbox directory defaults to `base_dir/sandbox`.
    pub fn default_for(name: &str, base_dir: &std::path::Path) -> Self {
        let sandbox_dir = base_dir.join("sandbox");
        Self::default_for_with_sandbox(name, base_dir, sandbox_dir)
    }

    /// Like [`default_for`](Self::default_for), but with an explicit sandbox directory.
    ///
    /// Used by `aegis init --dir` to point the sandbox at an existing project
    /// directory instead of creating a dedicated one.
    pub fn default_for_with_sandbox(
        name: &str,
        base_dir: &std::path::Path,
        sandbox_dir: PathBuf,
    ) -> Self {
        let policies_dir = base_dir.join("policies");
        let ledger_path = base_dir.join(LEDGER_FILENAME);

        let isolation = if cfg!(target_os = "macos") {
            IsolationConfig::Seatbelt {
                profile_overrides: None,
                deny_paths: vec![],
            }
        } else {
            IsolationConfig::Process
        };

        Self {
            name: name.to_string(),
            sandbox_dir,
            policy_paths: vec![policies_dir],
            schema_path: None,
            ledger_path,
            allowed_network: Vec::new(),
            isolation,
            observer: ObserverConfig::default(),
            alerts: Vec::new(),
            pilot: None,
            channel: None,
            usage_proxy: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_toml_roundtrip() {
        let config = AegisConfig {
            name: "test".into(),
            sandbox_dir: PathBuf::from("/tmp/sandbox"),
            policy_paths: vec![PathBuf::from("/tmp/policies")],
            schema_path: None,
            ledger_path: PathBuf::from("/tmp/audit.db"),
            allowed_network: vec![NetworkRule {
                host: "api.openai.com".into(),
                port: Some(443),
                protocol: Protocol::Https,
            }],
            isolation: IsolationConfig::Seatbelt {
                profile_overrides: None,
                deny_paths: vec![],
            },
            observer: ObserverConfig::default(),
            alerts: vec![AlertRule {
                name: "deny-alert".into(),
                webhook_url: "https://hooks.slack.com/test".into(),
                decision: Some("Deny".into()),
                action_kinds: vec![],
                path_glob: None,
                principal: None,
                cooldown_secs: 30,
            }],
            pilot: None,
            channel: None,
            usage_proxy: None,
        };

        let toml_str = config.to_toml().unwrap();
        let parsed = AegisConfig::from_toml(&toml_str).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.allowed_network.len(), 1);
        assert_eq!(parsed.allowed_network[0].host, "api.openai.com");
        assert_eq!(parsed.alerts.len(), 1);
        assert_eq!(parsed.alerts[0].name, "deny-alert");
        assert_eq!(parsed.alerts[0].cooldown_secs, 30);
    }

    #[test]
    fn config_default_for() {
        let base = PathBuf::from("/home/user/.aegis/myagent");
        let config = AegisConfig::default_for("myagent", &base);
        assert_eq!(config.name, "myagent");
        assert_eq!(config.sandbox_dir, base.join("sandbox"));
        assert_eq!(config.ledger_path, base.join("audit.db"));
    }

    #[test]
    fn config_default_for_with_sandbox() {
        let base = PathBuf::from("/home/user/.aegis/myagent");
        let project = PathBuf::from("/home/user/my-project");
        let config = AegisConfig::default_for_with_sandbox("myagent", &base, project.clone());
        assert_eq!(config.name, "myagent");
        assert_eq!(config.sandbox_dir, project);
        assert_eq!(config.ledger_path, base.join("audit.db"));
    }

    #[test]
    fn isolation_config_variants() {
        let variants = vec![
            IsolationConfig::Seatbelt {
                profile_overrides: None,
                deny_paths: vec![],
            },
            IsolationConfig::Process,
            IsolationConfig::None,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: IsolationConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn observer_config_display() {
        assert_eq!(ObserverConfig::None.to_string(), "None");
        assert_eq!(
            ObserverConfig::FsEvents {
                enable_snapshots: true
            }
            .to_string(),
            "FsEvents (snapshots: enabled)"
        );
        assert_eq!(
            ObserverConfig::FsEvents {
                enable_snapshots: false
            }
            .to_string(),
            "FsEvents (snapshots: disabled)"
        );
        assert_eq!(
            ObserverConfig::EndpointSecurity.to_string(),
            "Endpoint Security"
        );
    }

    #[test]
    fn network_rule_display() {
        let rule_with_port = NetworkRule {
            host: "api.openai.com".into(),
            port: Some(443),
            protocol: Protocol::Https,
        };
        assert_eq!(rule_with_port.to_string(), "HTTPS api.openai.com:443");

        let rule_no_port = NetworkRule {
            host: "example.com".into(),
            port: None,
            protocol: Protocol::Tcp,
        };
        assert_eq!(rule_no_port.to_string(), "TCP example.com");
    }

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Http.to_string(), "HTTP");
        assert_eq!(Protocol::Https.to_string(), "HTTPS");
    }

    #[test]
    fn protocol_from_str() {
        assert_eq!("TCP".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("Tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("UDP".parse::<Protocol>().unwrap(), Protocol::Udp);
        assert_eq!("HTTP".parse::<Protocol>().unwrap(), Protocol::Http);
        assert_eq!("https".parse::<Protocol>().unwrap(), Protocol::Https);
        assert!("FTP".parse::<Protocol>().is_err());
        assert!("".parse::<Protocol>().is_err());
    }

    #[test]
    fn protocol_display_fromstr_roundtrip() {
        for proto in [
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Http,
            Protocol::Https,
        ] {
            let s = proto.to_string();
            let parsed: Protocol = s.parse().unwrap();
            assert_eq!(parsed, proto);
        }
    }

    #[test]
    fn validate_config_name_valid() {
        assert!(validate_config_name("myagent").is_ok());
        assert!(validate_config_name("claude-code").is_ok());
        assert!(validate_config_name("a").is_ok());
        assert!(validate_config_name("agent_123").is_ok());
    }

    #[test]
    fn validate_config_name_rejects_empty() {
        assert!(validate_config_name("").is_err());
    }

    #[test]
    fn validate_config_name_rejects_path_traversal() {
        assert!(validate_config_name("../etc").is_err());
        assert!(validate_config_name("foo/bar").is_err());
        assert!(validate_config_name("..").is_err());
        assert!(validate_config_name(".").is_err());
        assert!(validate_config_name("...").is_err());
        assert!(validate_config_name("foo\\bar").is_err());
    }

    #[test]
    fn validate_config_name_rejects_control_chars() {
        assert!(validate_config_name("foo\nbar").is_err());
        assert!(validate_config_name("foo\0bar").is_err());
    }

    #[test]
    fn validate_config_name_rejects_special_chars() {
        assert!(validate_config_name("bad name").is_err());
        assert!(validate_config_name("bad[name").is_err());
        assert!(validate_config_name("name=value").is_err());
        assert!(validate_config_name("agent.v1").is_ok()); // dots OK
    }

    #[test]
    fn from_toml_invalid_toml_returns_error() {
        let result = AegisConfig::from_toml("{{invalid toml");
        assert!(result.is_err(), "invalid TOML should fail");
    }

    #[test]
    fn from_toml_missing_required_fields_returns_error() {
        let result = AegisConfig::from_toml("name = \"test\"");
        assert!(
            result.is_err(),
            "valid TOML with missing fields should fail"
        );
    }

    #[test]
    fn isolation_config_display() {
        assert_eq!(IsolationConfig::Process.to_string(), "Process");
        assert_eq!(IsolationConfig::None.to_string(), "None");
        assert_eq!(
            IsolationConfig::Seatbelt {
                profile_overrides: None,
                deny_paths: vec![],
            }
            .to_string(),
            "Seatbelt"
        );
        assert_eq!(
            IsolationConfig::Seatbelt {
                profile_overrides: Some(PathBuf::from("/tmp/custom.sb")),
                deny_paths: vec![],
            }
            .to_string(),
            "Seatbelt (overrides: /tmp/custom.sb)"
        );
    }

    #[test]
    fn config_without_alerts_parses_with_empty_vec() {
        // Existing configs that predate the alerts feature must still parse.
        let toml_str = r#"
            name = "legacy-agent"
            sandbox_dir = "/tmp/sandbox"
            policy_paths = ["/tmp/policies"]
            ledger_path = "/tmp/audit.db"
            allowed_network = []
            isolation = "Process"
        "#;
        let config = AegisConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.name, "legacy-agent");
        assert!(
            config.alerts.is_empty(),
            "alerts should default to empty vec"
        );
    }

    #[test]
    fn alert_rule_toml_roundtrip() {
        let rule = AlertRule {
            name: "write-to-secrets".into(),
            webhook_url: "https://events.pagerduty.com/v2/enqueue".into(),
            decision: Some("Deny".into()),
            action_kinds: vec!["FileWrite".into(), "FileDelete".into()],
            path_glob: Some("**/.env*".into()),
            principal: Some("my-agent".into()),
            cooldown_secs: 10,
        };

        let json = serde_json::to_string(&rule).unwrap();
        let back: AlertRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rule);
    }

    #[test]
    fn alert_rule_default_cooldown() {
        // When cooldown_secs is omitted, it defaults to 60.
        let json = r#"{"name":"test","webhook_url":"https://example.com"}"#;
        let rule: AlertRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.cooldown_secs, 60);
        assert!(rule.action_kinds.is_empty());
        assert!(rule.decision.is_none());
        assert!(rule.path_glob.is_none());
        assert!(rule.principal.is_none());
    }

    #[test]
    fn config_with_multiple_alerts_roundtrip() {
        let toml_str = r#"
            name = "test-agent"
            sandbox_dir = "/tmp/sandbox"
            policy_paths = ["/tmp/policies"]
            ledger_path = "/tmp/audit.db"
            allowed_network = []
            isolation = "Process"

            [[alerts]]
            name = "deny-alert"
            webhook_url = "https://hooks.slack.com/services/T/B/xxx"
            decision = "Deny"
            cooldown_secs = 30

            [[alerts]]
            name = "all-network"
            webhook_url = "https://intake.logs.datadoghq.com/api/v2/logs"
            action_kinds = ["NetConnect"]
        "#;
        let config = AegisConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.alerts.len(), 2);

        assert_eq!(config.alerts[0].name, "deny-alert");
        assert_eq!(config.alerts[0].decision, Some("Deny".into()));
        assert_eq!(config.alerts[0].cooldown_secs, 30);
        assert!(config.alerts[0].action_kinds.is_empty());

        assert_eq!(config.alerts[1].name, "all-network");
        assert_eq!(config.alerts[1].action_kinds, vec!["NetConnect"]);
        assert_eq!(config.alerts[1].cooldown_secs, 60); // default
        assert!(config.alerts[1].decision.is_none());
    }
}
