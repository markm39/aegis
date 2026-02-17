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
            ObserverConfig::FsEvents { enable_snapshots: true } => {
                write!(f, "FsEvents (snapshots: enabled)")
            }
            ObserverConfig::FsEvents { enable_snapshots: false } => {
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
    },
    /// Simple process isolation (no OS-level sandbox). Relies on observer + policy only.
    Process,
    /// No isolation at all. The command runs unsandboxed.
    None,
}

impl std::fmt::Display for IsolationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsolationConfig::Seatbelt { profile_overrides: Some(path) } => {
                write!(f, "Seatbelt (overrides: {})", path.display())
            }
            IsolationConfig::Seatbelt { profile_overrides: None } => write!(f, "Seatbelt"),
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
/// forwards user commands back to the supervisor (inbound). Currently
/// supports Telegram; additional backends (Slack, Discord) can be added
/// as new enum variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChannelConfig {
    /// Telegram Bot API channel.
    Telegram(TelegramConfig),
}

/// Configuration for the Telegram messaging channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
}

/// Top-level configuration for an Aegis agent instance.
///
/// Loaded from `aegis.toml` and controls sandbox directory, policies,
/// audit storage, network rules, isolation backend, observer settings,
/// and real-time webhook alert rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
}

/// Validate that a config name is safe for use as a directory component.
///
/// Rejects empty names, path separators, `..`, and control characters to
/// prevent path traversal when the name is used in `~/.aegis/<name>/`.
#[must_use = "validation result must be checked to prevent path traversal"]
pub fn validate_config_name(name: &str) -> Result<(), AegisError> {
    if name.is_empty() {
        return Err(AegisError::ConfigError("config name cannot be empty".into()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(AegisError::ConfigError(format!(
            "config name contains path separator: {name:?}"
        )));
    }
    if name == "." || name == ".." {
        return Err(AegisError::ConfigError(format!(
            "config name cannot be {name:?}"
        )));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(AegisError::ConfigError(format!(
            "config name contains control characters: {name:?}"
        )));
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
            ObserverConfig::FsEvents { enable_snapshots: true }.to_string(),
            "FsEvents (snapshots: enabled)"
        );
        assert_eq!(
            ObserverConfig::FsEvents { enable_snapshots: false }.to_string(),
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
        for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Http, Protocol::Https] {
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
        assert!(validate_config_name("foo\\bar").is_err());
    }

    #[test]
    fn validate_config_name_rejects_control_chars() {
        assert!(validate_config_name("foo\nbar").is_err());
        assert!(validate_config_name("foo\0bar").is_err());
    }

    #[test]
    fn from_toml_invalid_toml_returns_error() {
        let result = AegisConfig::from_toml("{{invalid toml");
        assert!(result.is_err(), "invalid TOML should fail");
    }

    #[test]
    fn from_toml_missing_required_fields_returns_error() {
        let result = AegisConfig::from_toml("name = \"test\"");
        assert!(result.is_err(), "valid TOML with missing fields should fail");
    }

    #[test]
    fn isolation_config_display() {
        assert_eq!(IsolationConfig::Process.to_string(), "Process");
        assert_eq!(IsolationConfig::None.to_string(), "None");
        assert_eq!(
            IsolationConfig::Seatbelt { profile_overrides: None }.to_string(),
            "Seatbelt"
        );
        assert_eq!(
            IsolationConfig::Seatbelt {
                profile_overrides: Some(PathBuf::from("/tmp/custom.sb"))
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
        assert!(config.alerts.is_empty(), "alerts should default to empty vec");
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
