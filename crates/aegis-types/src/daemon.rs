//! Configuration and status types for the Aegis daemon.
//!
//! The daemon manages a fleet of AI agent processes, keeping them alive,
//! supervised by the pilot, and within Cedar policy boundaries. These types
//! define the daemon's configuration file (`daemon.toml`) and runtime state.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{
    AdapterConfig, AlertRule, ChannelConfig, ChannelRoutingConfig, IsolationConfig, PilotConfig,
};

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
    /// Local read-only dashboard server settings.
    #[serde(default)]
    pub dashboard: DashboardConfig,
    /// Global alert rules applied to all agents.
    #[serde(default)]
    pub alerts: Vec<AlertRule>,
    /// The fleet: one entry per supervised agent slot.
    #[serde(default)]
    pub agents: Vec<AgentSlotConfig>,
    /// Bidirectional messaging channel (Telegram, Slack, etc.).
    #[serde(default)]
    pub channel: Option<ChannelConfig>,
    /// Per-channel command routing (allowlists, blocklists, aliases).
    #[serde(default)]
    pub channel_routing: Option<ChannelRoutingConfig>,
    /// Computer-use runtime configuration (capture/input/browser/loop behavior).
    #[serde(default)]
    pub toolkit: ToolkitConfig,
    /// Agent memory store settings.
    #[serde(default)]
    pub memory: MemoryConfig,
    /// Session-scoped file storage settings.
    #[serde(default)]
    pub session_files: SessionFilesConfig,
    /// Cron job scheduler settings.
    #[serde(default)]
    pub cron: CronConfig,
    /// Plugin system settings.
    #[serde(default)]
    pub plugins: PluginConfig,
    /// Command aliases for the TUI command bar.
    #[serde(default)]
    pub aliases: std::collections::HashMap<String, AliasConfig>,
    /// Named execution lanes with configurable concurrency limits.
    #[serde(default)]
    pub lanes: Vec<LaneConfig>,
    /// Per-workspace hook configuration.
    #[serde(default)]
    pub workspace_hooks: WorkspaceHooksConfig,
    /// ACP (Agent Communication Protocol) server configuration.
    #[serde(default)]
    pub acp_server: Option<AcpServerConfig>,
    /// Default LLM model for the chat TUI (e.g., "claude-sonnet-4-20250514").
    #[serde(default)]
    pub default_model: Option<String>,
    /// Names of skills enabled by the user (from wizard or manual config).
    #[serde(default)]
    pub skills: Vec<String>,
}

/// Configuration for per-workspace hook discovery and merge behavior.
///
/// When enabled, the daemon scans `.aegis/hooks/` inside each agent's
/// `working_dir` in addition to the global `~/.aegis/hooks/` directory.
/// Workspace hooks can override global hooks by name, except for reserved
/// hook names which are protected from workspace-level override.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceHooksConfig {
    /// Whether workspace-scoped hook discovery is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hook names that workspace hooks cannot override.
    /// These are reserved for global/system hooks only.
    #[serde(default)]
    pub reserved_hook_names: Vec<String>,
}

impl Default for WorkspaceHooksConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            reserved_hook_names: Vec::new(),
        }
    }
}

/// Configuration for a named execution lane in daemon.toml.
///
/// Lanes partition concurrent agent execution. Each lane has a name and an
/// optional concurrency cap. Agents assigned to a lane must acquire a slot
/// before running; if the lane is full they are queued in priority order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaneConfig {
    /// Unique lane name (alphanumeric + dash/underscore, max 64 chars).
    pub name: String,
    /// Maximum concurrent agents in this lane (0 = unlimited).
    #[serde(default)]
    pub max_concurrent: usize,
    /// Priority (higher = more important, 0-255).
    #[serde(default)]
    pub priority: u8,
}

/// Serializable alias configuration for persistence in daemon.toml.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AliasConfig {
    /// The target command name.
    pub command: String,
    /// Optional additional arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
}

/// Top-level configuration for orchestrator computer-use runtime behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ToolkitConfig {
    #[serde(default)]
    pub capture: ToolkitCaptureConfig,
    #[serde(default)]
    pub input: ToolkitInputConfig,
    #[serde(default)]
    pub browser: ToolkitBrowserConfig,
    #[serde(default)]
    pub loop_executor: ToolkitLoopExecutorConfig,
}

/// Local dashboard server settings for read-only monitoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DashboardConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dashboard_listen")]
    pub listen: String,
    /// Optional static API token (empty = random per boot).
    #[serde(default)]
    pub api_key: String,
    /// Optional token expiry in seconds. None means tokens never expire.
    #[serde(default)]
    pub token_expires_secs: Option<u64>,
    /// Maximum burst size for per-IP rate limiting (token bucket capacity).
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,
    /// Sustained request rate per second for per-IP rate limiting.
    #[serde(default = "default_rate_limit_per_sec")]
    pub rate_limit_per_sec: f64,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_dashboard_listen(),
            api_key: String::new(),
            token_expires_secs: None,
            rate_limit_burst: default_rate_limit_burst(),
            rate_limit_per_sec: default_rate_limit_per_sec(),
        }
    }
}

fn default_dashboard_listen() -> String {
    "127.0.0.1:9845".to_string()
}

fn default_rate_limit_burst() -> u32 {
    20
}

fn default_rate_limit_per_sec() -> f64 {
    5.0
}

/// Screen capture runtime settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolkitCaptureConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_capture_default_fps")]
    pub default_fps: u16,
    #[serde(default = "default_capture_min_fps")]
    pub min_fps: u16,
    #[serde(default = "default_capture_max_fps")]
    pub max_fps: u16,
}

impl Default for ToolkitCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_fps: default_capture_default_fps(),
            min_fps: default_capture_min_fps(),
            max_fps: default_capture_max_fps(),
        }
    }
}

/// Input runtime settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolkitInputConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_input_max_batch_actions")]
    pub max_batch_actions: u8,
}

impl Default for ToolkitInputConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_batch_actions: default_input_max_batch_actions(),
        }
    }
}

/// Browser automation runtime settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolkitBrowserConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_browser_backend")]
    pub backend: String,
    #[serde(default)]
    pub cdp_ws_url: Option<String>,
    #[serde(default = "default_true")]
    pub allow_screenshot: bool,
    #[serde(default)]
    pub binary_path: Option<String>,
    #[serde(default)]
    pub extra_args: Vec<String>,
    #[serde(default)]
    pub user_data_root: Option<String>,
    /// Maximum number of concurrent CDP browser sessions (0 = unlimited).
    #[serde(default = "default_browser_max_sessions")]
    pub max_concurrent_sessions: u8,
    /// Maximum CDP response size in bytes (0 = unlimited, default 10MB).
    #[serde(default = "default_browser_max_response_bytes")]
    pub max_response_bytes: usize,
}

impl Default for ToolkitBrowserConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: default_browser_backend(),
            cdp_ws_url: None,
            allow_screenshot: true,
            binary_path: None,
            extra_args: Vec::new(),
            user_data_root: None,
            max_concurrent_sessions: default_browser_max_sessions(),
            max_response_bytes: default_browser_max_response_bytes(),
        }
    }
}

/// Fast loop executor controls for orchestrator micro-action batches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolkitLoopExecutorConfig {
    #[serde(default = "default_loop_max_micro_actions")]
    pub max_micro_actions: u8,
    #[serde(default = "default_loop_time_budget_ms")]
    pub time_budget_ms: u64,
    #[serde(default = "default_true")]
    pub halt_on_high_risk: bool,
}

impl Default for ToolkitLoopExecutorConfig {
    fn default() -> Self {
        Self {
            max_micro_actions: default_loop_max_micro_actions(),
            time_budget_ms: default_loop_time_budget_ms(),
            halt_on_high_risk: true,
        }
    }
}

/// Configuration for the agent memory store.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemoryConfig {
    /// Whether the memory store is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Custom path for the memory SQLite database.
    /// Defaults to `~/.aegis/daemon/memory.db`.
    #[serde(default)]
    pub db_path: Option<String>,
    /// Whether temporal decay is applied to search result ranking.
    /// When enabled, recent memories are weighted higher in search results.
    #[serde(default)]
    pub decay_enabled: bool,
    /// Default half-life in hours for temporal decay.
    /// A memory exactly this old will have its relevance score halved.
    /// Defaults to 168.0 (1 week).
    #[serde(default = "default_half_life_hours")]
    pub default_half_life_hours: f64,
    /// Per-category half-life overrides in hours.
    /// For example, `{"instruction": 720.0}` gives instruction memories
    /// a 30-day half-life instead of the default.
    #[serde(default)]
    pub category_half_lives: std::collections::HashMap<String, f64>,
    /// Automatic memory recall settings.
    #[serde(default)]
    pub auto_recall: AutoRecallConfig,
    /// Automatic memory capture settings.
    #[serde(default)]
    pub auto_capture: AutoCaptureConfig,
}

fn default_half_life_hours() -> f64 {
    168.0
}

/// Configuration for automatic memory recall before LLM calls.
///
/// When enabled, relevant memories are retrieved from the memory store
/// and injected into the agent's context before each LLM invocation.
/// Retrieval uses semantic similarity (if embeddings are available) or
/// full-text search as a fallback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutoRecallConfig {
    /// Whether automatic recall is enabled. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum number of tokens (approximate) to inject. Default: 1024.
    /// Content is truncated to stay within this budget.
    #[serde(default = "default_auto_recall_max_tokens")]
    pub max_tokens: usize,
    /// Minimum relevance score for recalled memories. Default: 0.65.
    /// Memories scoring below this threshold are excluded.
    #[serde(default = "default_auto_recall_threshold")]
    pub relevance_threshold: f32,
    /// Override namespace for recall. Default: None (uses agent_id).
    #[serde(default)]
    pub namespace: Option<String>,
}

impl Default for AutoRecallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_tokens: default_auto_recall_max_tokens(),
            relevance_threshold: default_auto_recall_threshold(),
            namespace: None,
        }
    }
}

fn default_auto_recall_max_tokens() -> usize {
    1024
}

fn default_auto_recall_threshold() -> f32 {
    0.65
}

/// Configuration for automatic memory capture from agent conversations.
///
/// When enabled, the daemon extracts structured information (preferences,
/// decisions, facts, entities, instructions) from agent conversation text
/// and stores them in the memory store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutoCaptureConfig {
    /// Whether automatic capture is enabled. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Which extraction categories to capture. Default: all categories.
    /// Valid values: "preference", "decision", "fact", "entity", "instruction".
    #[serde(default = "default_auto_capture_categories")]
    pub categories: Vec<String>,
    /// Minimum confidence score for extracted entries. Default: 0.7.
    /// Entries below this threshold are discarded.
    #[serde(default = "default_auto_capture_confidence_threshold")]
    pub confidence_threshold: f32,
    /// Maximum number of memory writes per turn. Default: 5.
    /// Prevents runaway extraction from flooding the store.
    #[serde(default = "default_auto_capture_max_per_turn")]
    pub max_per_turn: usize,
}

impl Default for AutoCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            categories: default_auto_capture_categories(),
            confidence_threshold: default_auto_capture_confidence_threshold(),
            max_per_turn: default_auto_capture_max_per_turn(),
        }
    }
}

fn default_auto_capture_categories() -> Vec<String> {
    vec![
        "preference".into(),
        "decision".into(),
        "fact".into(),
        "entity".into(),
        "instruction".into(),
    ]
}

fn default_auto_capture_confidence_threshold() -> f32 {
    0.7
}

fn default_auto_capture_max_per_turn() -> usize {
    5
}

/// Configuration for session-scoped file storage.
///
/// When enabled, each agent session gets an isolated directory for storing
/// files with SHA-256 integrity hashes and configurable size limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionFilesConfig {
    /// Whether session file storage is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum size of a single file in bytes (default 10 MB).
    #[serde(default = "default_max_file_size_bytes")]
    pub max_file_size_bytes: u64,
    /// Maximum total size of all files in a session directory (default 100 MB).
    #[serde(default = "default_max_total_size_bytes")]
    pub max_total_size_bytes: u64,
    /// Base directory for session file storage.
    /// Defaults to `~/.aegis/sessions/`.
    #[serde(default)]
    pub base_dir: Option<String>,
}

impl Default for SessionFilesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_file_size_bytes: default_max_file_size_bytes(),
            max_total_size_bytes: default_max_total_size_bytes(),
            base_dir: None,
        }
    }
}

fn default_max_file_size_bytes() -> u64 {
    10_485_760 // 10 MB
}

fn default_max_total_size_bytes() -> u64 {
    104_857_600 // 100 MB
}

/// Configuration for the cron job scheduler.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CronConfig {
    /// Whether the cron scheduler is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Scheduled jobs.
    #[serde(default)]
    pub jobs: Vec<CronJobConfig>,
}

/// Configuration for a single cron job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CronJobConfig {
    /// Unique name for this job.
    pub name: String,
    /// Schedule expression: "every 5m", "every 2h", "daily 09:30".
    pub schedule: String,
    /// Serialized DaemonCommand to execute when the job fires.
    pub command: serde_json::Value,
    /// Whether this job is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Configuration for the plugin system.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginConfig {
    /// Whether plugin discovery and loading is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Directory to scan for plugin manifests.
    /// Defaults to `~/.aegis/plugins/`.
    #[serde(default)]
    pub plugin_dir: Option<String>,
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
    /// Execution lane this agent belongs to. If not set, uses the "default" lane.
    #[serde(default)]
    pub lane: Option<String>,
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

fn default_true() -> bool {
    true
}

fn default_capture_default_fps() -> u16 {
    30
}

fn default_capture_min_fps() -> u16 {
    5
}

fn default_capture_max_fps() -> u16 {
    60
}

fn default_input_max_batch_actions() -> u8 {
    10
}

fn default_browser_backend() -> String {
    "cdp".to_string()
}

fn default_browser_max_sessions() -> u8 {
    4
}

fn default_browser_max_response_bytes() -> usize {
    10 * 1024 * 1024 // 10 MB
}

fn default_loop_max_micro_actions() -> u8 {
    8
}

fn default_loop_time_budget_ms() -> u64 {
    1_200
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
        /// Runtime engine: "native" (vendored runtime wrapper) or "external"
        /// (`codex` binary on PATH).
        #[serde(default = "default_codex_runtime_engine")]
        runtime_engine: String,
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

fn default_codex_runtime_engine() -> String {
    "native".to_string()
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
    PathBuf::from(home)
        .join(".aegis")
        .join("daemon")
        .join("daemon.sock")
}

/// Server-side configuration for the ACP (Agent Communication Protocol) endpoint.
///
/// Controls the listen address, authentication tokens, and rate limiting for
/// incoming ACP connections. Auth tokens are stored as SHA-256 hashes in the
/// config file -- never as plaintext. At runtime, incoming bearer tokens are
/// hashed and compared against the allowlist using constant-time comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpServerConfig {
    /// Listen address for the ACP HTTP endpoint (e.g., "127.0.0.1:9100").
    pub listen: String,
    /// Allowlist of SHA-256 hex-encoded token hashes. Incoming bearer tokens
    /// are hashed and compared against this list using constant-time equality.
    /// Generate a hash with: `echo -n "your-token" | sha256sum`
    #[serde(default)]
    pub token_hashes: Vec<String>,
    /// Maximum messages per minute per connection (default: 100).
    #[serde(default = "default_acp_rate_limit")]
    pub rate_limit_per_minute: u32,
    /// Maximum request body size in bytes (default: 1 MB).
    #[serde(default = "default_acp_max_body_size")]
    pub max_body_size: usize,
}

fn default_acp_rate_limit() -> u32 {
    100
}

fn default_acp_max_body_size() -> usize {
    1_048_576
}

impl Default for AcpServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9100".to_string(),
            token_hashes: Vec::new(),
            rate_limit_per_minute: default_acp_rate_limit(),
            max_body_size: default_acp_max_body_size(),
        }
    }
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
            AgentStatus::Crashed {
                exit_code,
                restart_in_secs,
            } => {
                write!(
                    f,
                    "Crashed (exit {exit_code}, restart in {restart_in_secs}s)"
                )
            }
            AgentStatus::Failed {
                exit_code,
                restart_count,
            } => {
                write!(f, "Failed (exit {exit_code}, {restart_count} restarts)")
            }
            AgentStatus::Stopping => write!(f, "Stopping"),
            AgentStatus::Disabled => write!(f, "Disabled"),
        }
    }
}

/// Maximum number of execution lanes allowed.
pub const MAX_LANES: usize = 100;

/// Maximum length of a lane name.
const MAX_LANE_NAME_LEN: usize = 64;

/// Validate a lane name: alphanumeric + dash/underscore, max 64 chars, no
/// path traversal. Returns an error message string on failure.
pub fn validate_lane_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("lane name cannot be empty".into());
    }
    if name.len() > MAX_LANE_NAME_LEN {
        return Err(format!("lane name exceeds {MAX_LANE_NAME_LEN} characters"));
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err("lane name must not contain path traversal sequences".into());
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err("lane name may only contain letters, digits, hyphens, and underscores".into());
    }
    Ok(())
}

/// Default daemon directory path.
pub fn daemon_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".aegis").join("daemon")
}

/// Default workspace directory for user context files (SOUL.md, IDENTITY.md, etc.).
pub fn workspace_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".aegis").join("workspace")
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
            if let Some(ref lane) = agent.lane {
                validate_lane_name(lane).map_err(|e| {
                    crate::AegisError::DaemonError(format!(
                        "invalid lane name {:?} on agent {:?}: {e}",
                        lane, agent.name
                    ))
                })?;
            }
        }

        if config.lanes.len() > MAX_LANES {
            return Err(crate::AegisError::DaemonError(format!(
                "too many lanes: {} (max {})",
                config.lanes.len(),
                MAX_LANES
            )));
        }
        for lane in &config.lanes {
            validate_lane_name(&lane.name).map_err(|e| {
                crate::AegisError::DaemonError(format!("invalid lane name {:?}: {e}", lane.name))
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
            dashboard: DashboardConfig::default(),
            alerts: vec![],
            channel: None,
            channel_routing: None,
            toolkit: ToolkitConfig::default(),
            memory: MemoryConfig::default(),
            session_files: SessionFilesConfig::default(),
            cron: CronConfig::default(),
            plugins: PluginConfig::default(),
            aliases: Default::default(),
            lanes: vec![],
            workspace_hooks: WorkspaceHooksConfig::default(),
            acp_server: None,
            default_model: None,
            skills: vec![],
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
                lane: None,
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
                runtime_engine: "native".into(),
                approval_mode: "full-auto".into(),
                one_shot: true,
                extra_args: vec![],
            },
            AgentToolConfig::OpenClaw {
                agent_name: Some("builder".into()),
                extra_args: vec![],
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
    fn codex_runtime_engine_defaults_to_native() {
        let json = r#"{"type":"codex","approval_mode":"suggest","one_shot":false,"extra_args":[]}"#;
        let parsed: AgentToolConfig = serde_json::from_str(json).unwrap();
        match parsed {
            AgentToolConfig::Codex { runtime_engine, .. } => {
                assert_eq!(runtime_engine, "native");
            }
            _ => panic!("expected codex tool config"),
        }
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
            AgentStatus::Crashed {
                exit_code: 1,
                restart_in_secs: 10
            }
            .to_string(),
            "Crashed (exit 1, restart in 10s)"
        );
        assert_eq!(
            AgentStatus::Failed {
                exit_code: 1,
                restart_count: 5
            }
            .to_string(),
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
        assert!(
            result.is_err(),
            "path traversal in agent name should be rejected"
        );

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
