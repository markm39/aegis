//! Configuration types for Aegis testing runs.
//!
//! [`AegisConfig`] is the top-level configuration loaded from `aegis.toml`.
//! It controls sandbox paths, policy locations, network rules, isolation
//! backend, observer settings, and alerting.

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
    /// Hostname or IP address (for example, `"api.openai.com"`).
    pub host: String,
    /// Port number. `None` means any port.
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
    /// FSEvents-based observation.
    FsEvents {
        /// Whether to perform pre/post snapshot diffing.
        enable_snapshots: bool,
    },
    /// Endpoint Security logger.
    EndpointSecurity,
}

impl Default for ObserverConfig {
    fn default() -> Self {
        Self::FsEvents {
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
            } => write!(f, "FsEvents (snapshots: enabled)"),
            ObserverConfig::FsEvents {
                enable_snapshots: false,
            } => write!(f, "FsEvents (snapshots: disabled)"),
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
        #[serde(default)]
        deny_paths: Vec<PathBuf>,
    },
    /// Docker container isolation with security-hardened defaults.
    Docker(DockerSandboxConfig),
    /// Simple process isolation.
    Process,
    /// No isolation at all.
    None,
}

/// Configuration for the Docker sandbox backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DockerSandboxConfig {
    /// Docker image to use.
    #[serde(default = "default_docker_image")]
    pub image: String,
    /// Network mode.
    #[serde(default = "default_docker_network")]
    pub network: String,
    /// Memory limit.
    #[serde(default = "default_docker_memory")]
    pub memory: String,
    /// CPU limit.
    #[serde(default = "default_docker_cpus")]
    pub cpus: f64,
    /// PID limit to prevent fork bombs.
    #[serde(default = "default_docker_pids_limit")]
    pub pids_limit: u32,
    /// Size limit for the `/tmp` tmpfs mount.
    #[serde(default = "default_docker_tmpfs_size")]
    pub tmpfs_size: String,
    /// Whether the workspace mount is read-write.
    #[serde(default)]
    pub workspace_writable: bool,
    /// Additional read-only bind mounts (`host_path:container_path`).
    #[serde(default)]
    pub extra_mounts: Vec<String>,
    /// Timeout in seconds for container execution. `0` means no timeout.
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

impl Eq for DockerSandboxConfig {}

impl std::fmt::Display for IsolationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsolationConfig::Seatbelt {
                profile_overrides: Some(path),
                ..
            } => write!(f, "Seatbelt (overrides: {})", path.display()),
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

fn default_cooldown() -> u64 {
    60
}

/// A webhook alert rule that fires when audit events match its filters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertRule {
    /// Unique name for this alert rule.
    pub name: String,
    /// HTTP(S) URL to POST the webhook payload to.
    pub webhook_url: String,
    /// Filter: only fire on this decision (`"Allow"` or `"Deny"`).
    pub decision: Option<String>,
    /// Filter: only fire on these action kinds. Empty means all actions.
    #[serde(default)]
    pub action_kinds: Vec<String>,
    /// Filter: glob pattern matched against the event's file path.
    pub path_glob: Option<String>,
    /// Filter: exact match on the agent principal name.
    pub principal: Option<String>,
    /// Minimum seconds between dispatches for this rule.
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

/// What to do when the session adapter cannot determine the action type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum UncertainAction {
    /// Deny the action.
    #[default]
    Deny,
    /// Allow the action.
    Allow,
    /// Emit a pending alert and wait for outside input.
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
    /// Passthrough adapter.
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

fn default_stall_timeout_secs() -> u64 {
    120
}

fn default_max_nudges() -> u32 {
    5
}

fn default_nudge_message() -> String {
    "continue".to_string()
}

/// Stall detection configuration for the PTY session supervisor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StallConfig {
    /// Seconds of no output before considering the agent stalled.
    #[serde(default = "default_stall_timeout_secs")]
    pub timeout_secs: u64,
    /// Maximum number of nudges before giving up.
    #[serde(default = "default_max_nudges")]
    pub max_nudges: u32,
    /// Message to send when nudging.
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

fn default_output_buffer_lines() -> usize {
    200
}

/// Configuration for PTY-based session supervision during probe execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConfig {
    /// Which agent adapter to use for prompt detection.
    #[serde(default)]
    pub adapter: AdapterConfig,
    /// Stall detection settings.
    #[serde(default)]
    pub stall: StallConfig,
    /// Number of recent output lines to keep in the rolling buffer.
    #[serde(default = "default_output_buffer_lines")]
    pub output_buffer_lines: usize,
    /// What to do when a prompt cannot be parsed by the adapter.
    #[serde(default)]
    pub uncertain_action: UncertainAction,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            adapter: AdapterConfig::default(),
            stall: StallConfig::default(),
            output_buffer_lines: default_output_buffer_lines(),
            uncertain_action: UncertainAction::default(),
        }
    }
}

#[doc(hidden)]
pub type PilotConfig = SessionConfig;

/// Configuration for PII redaction in audit logs.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionConfig {
    /// Master toggle for redaction.
    #[serde(default)]
    pub enabled: bool,
    /// Additional regex patterns to redact.
    #[serde(default)]
    pub custom_patterns: Vec<RedactionPattern>,
}

/// A single custom PII redaction pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionPattern {
    /// Regex pattern to match.
    pub pattern: String,
    /// Replacement text.
    pub replacement: String,
}

/// Top-level configuration for an Aegis testing environment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AegisConfig {
    /// Human-readable name for this configuration.
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
    /// PTY session supervision configuration for interactive agents.
    #[serde(default, alias = "pilot")]
    pub session: Option<SessionConfig>,
}

/// Validate that a config name is safe for use as a directory component.
#[must_use = "validation result must be checked to prevent path traversal"]
pub fn validate_config_name(name: &str) -> Result<(), AegisError> {
    if name.is_empty() {
        return Err(AegisError::ConfigError("name cannot be empty".into()));
    }
    if name.chars().all(|c| c == '.') {
        return Err(AegisError::ConfigError(format!("name cannot be {name:?}")));
    }
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

    /// Create a default configuration for a named environment under `base_dir`.
    pub fn default_for(name: &str, base_dir: &std::path::Path) -> Self {
        let sandbox_dir = base_dir.join("sandbox");
        Self::default_for_with_sandbox(name, base_dir, sandbox_dir)
    }

    /// Like [`default_for`](Self::default_for), but with an explicit sandbox directory.
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
            session: None,
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
            session: Some(SessionConfig::default()),
        };

        let toml_str = config.to_toml().unwrap();
        let parsed = AegisConfig::from_toml(&toml_str).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.allowed_network.len(), 1);
        assert_eq!(parsed.allowed_network[0].host, "api.openai.com");
        assert_eq!(parsed.alerts.len(), 1);
        assert!(parsed.session.is_some());
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
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let back: IsolationConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
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
        assert!(validate_config_name("agent.v1").is_ok());
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
        assert!(config.alerts.is_empty());
        assert!(config.session.is_none());
    }

    #[test]
    fn legacy_pilot_key_still_parses() {
        let toml_str = r#"
            name = "legacy-agent"
            sandbox_dir = "/tmp/sandbox"
            policy_paths = ["/tmp/policies"]
            ledger_path = "/tmp/audit.db"
            allowed_network = []
            isolation = "Process"

            [pilot]
            output_buffer_lines = 250
        "#;
        let config = AegisConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.session.unwrap().output_buffer_lines, 250);
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
        assert_eq!(config.alerts[1].cooldown_secs, 60);
        assert!(config.alerts[1].decision.is_none());
    }
}
