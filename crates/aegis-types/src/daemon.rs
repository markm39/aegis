//! Configuration and status types for the Aegis daemon.
//!
//! The daemon manages a fleet of AI agent processes, keeping them alive,
//! supervised by the pilot, and within Cedar policy boundaries. These types
//! define the daemon's configuration file (`daemon.toml`) and runtime state.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{AdapterConfig, AlertRule, ChannelConfig, IsolationConfig, PilotConfig};

/// Security preset applied during onboarding.
///
/// Controls which Cedar policy is generated and what isolation level is used
/// for the agent. Stored in `daemon.toml` per-agent so the daemon knows how
/// to construct the agent's `AegisConfig` at startup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityPresetKind {
    /// Log all activity, enforce nothing. Default for first run.
    ObserveOnly,
    /// Allow reads, block writes and network access.
    ReadOnly,
    /// Block everything except process lifecycle.
    FullLockdown,
    /// User-configured per-action permissions.
    Custom,
}

/// Top-level daemon configuration, loaded from `~/.aegis/daemon/daemon.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Optional fleet-wide goal/mission shared by all agents.
    #[serde(default)]
    pub goal: Option<String>,
    /// Persistence and OS integration settings.
    #[serde(default)]
    pub persistence: PersistenceConfig,
    /// Control plane (Unix socket + optional HTTP) settings.
    #[serde(default)]
    pub control: DaemonControlConfig,
    /// Global alert rules applied to all agents.
    #[serde(default)]
    pub alerts: Vec<AlertRule>,
    /// The fleet: one entry per supervised agent slot.
    #[serde(default)]
    pub agents: Vec<AgentSlotConfig>,
    /// Bidirectional messaging channel (Telegram, Slack, etc.).
    #[serde(default)]
    pub channel: Option<ChannelConfig>,
}

/// Configuration for a single agent slot in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSlotConfig {
    /// Unique name for this slot (used in CLI commands and logs).
    pub name: String,
    /// Which AI tool to run and how to configure it.
    pub tool: AgentToolConfig,
    /// Working directory for the agent process.
    pub working_dir: PathBuf,
    /// Short description of this agent's role (e.g., "UX specialist", "Backend engineer").
    #[serde(default)]
    pub role: Option<String>,
    /// Strategic goal for this agent (what it should achieve, distinct from `task`).
    #[serde(default)]
    pub agent_goal: Option<String>,
    /// Additional context, constraints, or knowledge for this agent.
    #[serde(default)]
    pub context: Option<String>,
    /// Initial task/prompt to inject into the agent after spawn.
    #[serde(default)]
    pub task: Option<String>,
    /// Override pilot settings for this agent (stall detection, adapter, etc.).
    #[serde(default)]
    pub pilot: Option<PilotConfig>,
    /// When to restart the agent after it exits.
    #[serde(default)]
    pub restart: RestartPolicy,
    /// Maximum number of restarts before giving up (0 = unlimited).
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
    /// Whether this slot is enabled. Disabled slots are skipped on daemon start.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// If set, this agent acts as a fleet orchestrator that reviews and
    /// directs other agents instead of writing code itself.
    #[serde(default)]
    pub orchestrator: Option<OrchestratorConfig>,
    /// Security preset applied during onboarding. Controls default policy generation.
    #[serde(default)]
    pub security_preset: Option<SecurityPresetKind>,
    /// Path to a Cedar policy directory for this agent. Overrides the daemon default.
    #[serde(default)]
    pub policy_dir: Option<PathBuf>,
    /// OS-level isolation override for this agent. If not set, derived from security_preset.
    #[serde(default)]
    pub isolation: Option<IsolationConfig>,
}

/// Configuration for an agent acting as the fleet orchestrator.
///
/// The orchestrator periodically reviews other agents' work (git log, output,
/// test results), evaluates whether they're doing high-value work, and
/// redirects them when they go off track. It also verifies output visually
/// (launching TUIs, screenshotting web apps).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    /// How often (seconds) the orchestrator reviews agent progress. Default: 300.
    #[serde(default = "default_review_interval")]
    pub review_interval_secs: u64,
    /// Path to a backlog/roadmap file that defines priorities.
    /// The orchestrator reads this to decide what work matters.
    #[serde(default)]
    pub backlog_path: Option<PathBuf>,
    /// Names of agents this orchestrator manages.
    /// If empty, manages all non-orchestrator agents in the fleet.
    #[serde(default)]
    pub managed_agents: Vec<String>,
}

fn default_review_interval() -> u64 {
    300
}

fn default_max_restarts() -> u32 {
    5
}

fn default_enabled() -> bool {
    true
}

/// Which AI tool to run in an agent slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentToolConfig {
    /// Claude Code CLI.
    ClaudeCode {
        /// Skip all permission prompts (uses --dangerously-skip-permissions).
        #[serde(default)]
        skip_permissions: bool,
        /// Run a single prompt and exit (uses -p "prompt").
        #[serde(default)]
        one_shot: bool,
        /// Additional CLI arguments.
        #[serde(default)]
        extra_args: Vec<String>,
    },
    /// OpenAI Codex CLI.
    Codex {
        /// Approval mode: "suggest", "auto-edit", or "full-auto".
        #[serde(default = "default_codex_approval")]
        approval_mode: String,
        /// Run a single query and exit (uses codex exec -q).
        #[serde(default)]
        one_shot: bool,
        /// Additional CLI arguments.
        #[serde(default)]
        extra_args: Vec<String>,
    },
    /// OpenClaw autonomous agent.
    OpenClaw {
        /// Agent name to run (if OpenClaw supports named agents).
        #[serde(default)]
        agent_name: Option<String>,
        /// Additional CLI arguments.
        #[serde(default)]
        extra_args: Vec<String>,
    },
    /// Cursor editor (observe-only; Aegis monitors but does not control).
    Cursor {
        /// Assume Cursor is already running (don't try to spawn).
        #[serde(default)]
        assume_running: bool,
    },
    /// Custom command with user-specified adapter.
    Custom {
        /// Command to execute.
        command: String,
        /// Command arguments.
        #[serde(default)]
        args: Vec<String>,
        /// Which adapter to use for prompt detection.
        #[serde(default)]
        adapter: AdapterConfig,
        /// Environment variables to set.
        #[serde(default)]
        env: Vec<(String, String)>,
    },
}

fn default_codex_approval() -> String {
    "suggest".to_string()
}

/// When to restart an agent after it exits.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// Never restart (one-shot execution).
    Never,
    /// Restart only if the agent exits with a non-zero code.
    #[default]
    OnFailure,
    /// Always restart, regardless of exit code.
    Always,
}

/// macOS persistence and sleep-prevention settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistenceConfig {
    /// Register as a launchd LaunchAgent for auto-start and crash recovery.
    #[serde(default)]
    pub launchd: bool,
    /// Run `caffeinate` to prevent system sleep while agents are active.
    #[serde(default)]
    pub prevent_sleep: bool,
}

/// Control plane settings for the daemon's Unix socket and optional HTTP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonControlConfig {
    /// Path to the Unix domain socket.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
    /// HTTP listen address (empty = disabled).
    #[serde(default)]
    pub http_listen: String,
    /// API key for HTTP authentication (empty = no auth).
    #[serde(default)]
    pub api_key: String,
}

impl Default for DaemonControlConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            http_listen: String::new(),
            api_key: String::new(),
        }
    }
}

fn default_socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".aegis").join("daemon").join("daemon.sock")
}

/// Runtime status of a single agent slot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentStatus {
    /// Waiting to be started.
    Pending,
    /// Currently running.
    Running {
        /// Process ID of the agent.
        pid: u32,
    },
    /// Stopped normally.
    Stopped {
        /// Exit code of the agent process.
        exit_code: i32,
    },
    /// Crashed and waiting to restart.
    Crashed {
        /// Exit code of the crashed process.
        exit_code: i32,
        /// Seconds until the next restart attempt.
        restart_in_secs: u64,
    },
    /// Exceeded max restarts; will not restart automatically.
    Failed {
        /// Exit code of the last crash.
        exit_code: i32,
        /// Total number of restarts attempted.
        restart_count: u32,
    },
    /// Agent is being stopped (SIGTERM sent, waiting for exit).
    Stopping,
    /// Slot is disabled in configuration.
    Disabled,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentStatus::Pending => write!(f, "Pending"),
            AgentStatus::Running { pid } => write!(f, "Running (pid {pid})"),
            AgentStatus::Stopped { exit_code } => write!(f, "Stopped (exit {exit_code})"),
            AgentStatus::Crashed { exit_code, restart_in_secs } => {
                write!(f, "Crashed (exit {exit_code}, restart in {restart_in_secs}s)")
            }
            AgentStatus::Failed { exit_code, restart_count } => {
                write!(f, "Failed (exit {exit_code}, {restart_count} restarts)")
            }
            AgentStatus::Stopping => write!(f, "Stopping"),
            AgentStatus::Disabled => write!(f, "Disabled"),
        }
    }
}

/// Default daemon directory path.
pub fn daemon_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".aegis").join("daemon")
}

/// Default daemon config file path.
pub fn daemon_config_path() -> PathBuf {
    daemon_dir().join("daemon.toml")
}

/// Default daemon PID file path.
pub fn daemon_pid_path() -> PathBuf {
    daemon_dir().join("daemon.pid")
}

/// Default daemon lock file path.
pub fn daemon_lock_path() -> PathBuf {
    daemon_dir().join("daemon.lock")
}

/// Default daemon state file path.
pub fn daemon_state_path() -> PathBuf {
    daemon_dir().join("state.json")
}

impl DaemonConfig {
    /// Parse a daemon configuration from a TOML string.
    ///
    /// Validates agent slot names against `validate_config_name` to prevent
    /// path traversal and special character injection.
    pub fn from_toml(content: &str) -> Result<Self, crate::AegisError> {
        let config: Self = toml::from_str(content)
            .map_err(|e| crate::AegisError::DaemonError(format!("invalid daemon config: {e}")))?;

        for agent in &config.agents {
            crate::validate_config_name(&agent.name).map_err(|e| {
                crate::AegisError::DaemonError(format!("invalid agent name {:?}: {e}", agent.name))
            })?;
        }

        Ok(config)
    }

    /// Serialize the configuration to a TOML string.
    pub fn to_toml(&self) -> Result<String, crate::AegisError> {
        toml::to_string_pretty(self)
            .map_err(|e| crate::AegisError::DaemonError(format!("failed to serialize config: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_config_toml_roundtrip() {
        let config = DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            alerts: vec![],
            channel: None,
            agents: vec![AgentSlotConfig {
                name: "claude-1".into(),
                tool: AgentToolConfig::ClaudeCode {
                    skip_permissions: false,
                    one_shot: false,
                    extra_args: vec![],
                },
                working_dir: PathBuf::from("/home/user/project"),
                role: None,
                agent_goal: None,
                context: None,
                task: Some("implement the login page".into()),
                pilot: None,
                restart: RestartPolicy::OnFailure,
                max_restarts: 5,
                enabled: true,
                orchestrator: None,
                security_preset: None,
                policy_dir: None,
                isolation: None,
            }],
        };

        let toml_str = config.to_toml().unwrap();
        let parsed = DaemonConfig::from_toml(&toml_str).unwrap();
        assert_eq!(parsed.agents.len(), 1);
        assert_eq!(parsed.agents[0].name, "claude-1");
    }

    #[test]
    fn agent_tool_config_variants() {
        let variants = vec![
            AgentToolConfig::ClaudeCode {
                skip_permissions: true,
                one_shot: false,
                extra_args: vec!["--verbose".into()],
            },
            AgentToolConfig::Codex {
                approval_mode: "full-auto".into(),
                one_shot: true,
                extra_args: vec![],
            },
            AgentToolConfig::OpenClaw {
                agent_name: Some("builder".into()),
                extra_args: vec![],
            },
            AgentToolConfig::Cursor {
                assume_running: true,
            },
            AgentToolConfig::Custom {
                command: "my-agent".into(),
                args: vec!["--mode".into(), "auto".into()],
                adapter: AdapterConfig::Auto,
                env: vec![("API_KEY".into(), "secret".into())],
            },
        ];

        for tool in &variants {
            let json = serde_json::to_string(tool).unwrap();
            let back: AgentToolConfig = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&back).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn restart_policy_default() {
        assert_eq!(RestartPolicy::default(), RestartPolicy::OnFailure);
    }

    #[test]
    fn agent_status_display() {
        assert_eq!(AgentStatus::Pending.to_string(), "Pending");
        assert_eq!(
            AgentStatus::Running { pid: 1234 }.to_string(),
            "Running (pid 1234)"
        );
        assert_eq!(
            AgentStatus::Stopped { exit_code: 0 }.to_string(),
            "Stopped (exit 0)"
        );
        assert_eq!(
            AgentStatus::Crashed { exit_code: 1, restart_in_secs: 10 }.to_string(),
            "Crashed (exit 1, restart in 10s)"
        );
        assert_eq!(
            AgentStatus::Failed { exit_code: 1, restart_count: 5 }.to_string(),
            "Failed (exit 1, 5 restarts)"
        );
        assert_eq!(AgentStatus::Disabled.to_string(), "Disabled");
    }

    #[test]
    fn minimal_daemon_toml() {
        let toml_str = r#"
            [[agents]]
            name = "test"
            working_dir = "/tmp"

            [agents.tool]
            type = "claude_code"
        "#;
        let config = DaemonConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.agents.len(), 1);
        assert_eq!(config.agents[0].name, "test");
        assert!(config.agents[0].enabled); // default true
        assert_eq!(config.agents[0].max_restarts, 5); // default
        assert_eq!(config.agents[0].restart, RestartPolicy::OnFailure); // default
    }

    #[test]
    fn empty_daemon_toml() {
        let config = DaemonConfig::from_toml("").unwrap();
        assert!(config.agents.is_empty());
        assert!(config.alerts.is_empty());
    }

    #[test]
    fn daemon_paths() {
        let dir = daemon_dir();
        assert!(dir.ends_with(".aegis/daemon"));
        assert!(daemon_config_path().ends_with("daemon.toml"));
        assert!(daemon_pid_path().ends_with("daemon.pid"));
        assert!(daemon_lock_path().ends_with("daemon.lock"));
        assert!(daemon_state_path().ends_with("state.json"));
    }

    #[test]
    fn from_toml_rejects_invalid_agent_names() {
        let toml_str = r#"
            [[agents]]
            name = "../escape"
            working_dir = "/tmp"

            [agents.tool]
            type = "claude_code"
        "#;
        let result = DaemonConfig::from_toml(toml_str);
        assert!(result.is_err(), "path traversal in agent name should be rejected");

        let toml_str = r#"
            [[agents]]
            name = "bad name"
            working_dir = "/tmp"

            [agents.tool]
            type = "claude_code"
        "#;
        let result = DaemonConfig::from_toml(toml_str);
        assert!(result.is_err(), "spaces in agent name should be rejected");
    }
}
