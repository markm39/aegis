//! Daemon-level control protocol types.
//!
//! These commands operate on the daemon fleet (listing agents, starting/stopping
//! individual agents, sending input, reading output). They are separate from
//! the per-agent pilot [`Command`](crate::command::Command) types, which handle
//! prompt approval and stall nudges within a single supervisor session.

use serde::{Deserialize, Serialize};

use aegis_toolkit::contract::{RiskTag, ToolAction, ToolResult};
use aegis_types::daemon::AgentSlotConfig;
use aegis_types::AgentStatus;

/// A command sent to the daemon control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonCommand {
    /// Health check. Returns uptime, agent count, and running count.
    Ping,
    /// List all agent slots with their current status.
    ListAgents,
    /// Get detailed status for a specific agent.
    AgentStatus { name: String },
    /// Get recent output lines from an agent.
    AgentOutput { name: String, lines: Option<usize> },
    /// List active sessions (OpenClaw-style session keys).
    SessionList,
    /// Fetch recent output lines for a session key.
    SessionHistory {
        session_key: String,
        /// Number of lines to return (default: 50).
        #[serde(default)]
        lines: Option<usize>,
    },
    /// Send text to a session key (mapped to agent stdin).
    SessionSend { session_key: String, text: String },
    /// Send text to an agent's stdin (task injection or ad-hoc input).
    SendToAgent { name: String, text: String },
    /// Start a specific agent slot.
    StartAgent { name: String },
    /// Stop a specific agent slot (sends SIGTERM).
    StopAgent { name: String },
    /// Restart a specific agent slot (stop + start).
    RestartAgent { name: String },
    /// Add a new agent slot at runtime and optionally start it.
    AddAgent {
        config: Box<AgentSlotConfig>,
        /// Whether to start the agent immediately after adding.
        #[serde(default = "default_true")]
        start: bool,
    },
    /// Spawn a constrained subagent session from an orchestrator/subagent parent.
    SpawnSubagent { request: SpawnSubagentRequest },
    /// Remove an agent slot (stops it if running, removes from config, persists).
    RemoveAgent { name: String },
    /// Approve a pending permission request for an agent.
    ApproveRequest { name: String, request_id: String },
    /// Deny a pending permission request for an agent.
    DenyRequest { name: String, request_id: String },
    /// Nudge a stalled agent with an optional message.
    NudgeAgent {
        name: String,
        message: Option<String>,
    },
    /// List pending permission prompts for an agent.
    ListPending { name: String },
    /// Evaluate a tool use against Cedar policy (used by hooks).
    ///
    /// The hook client sends this when Claude Code fires a `PreToolUse` hook.
    /// The daemon evaluates Cedar policy and returns allow/deny.
    EvaluateToolUse {
        /// Agent name (from AEGIS_AGENT_NAME env var).
        agent: String,
        /// Tool name (e.g., "Bash", "Read", "Write").
        tool_name: String,
        /// Full tool input as JSON.
        tool_input: serde_json::Value,
    },
    /// Get runtime capability and policy-mediation coverage for an agent.
    RuntimeCapabilities { name: String },
    /// Show secure-runtime compatibility status against internal parity matrix.
    ParityStatus,
    /// Show latest upstream delta impact on secure-runtime features.
    ParityDiff,
    /// Verify secure-runtime parity controls and fail-closed gates.
    ParityVerify,
    /// Execute one computer-use action through the orchestrator runtime.
    ///
    /// This path is expected to be policy-gated and fail closed if runtime
    /// mediation is unavailable.
    ExecuteToolAction { name: String, action: ToolAction },
    /// Execute a short sequence of computer-use actions in one tight loop.
    ///
    /// Intended for orchestrator micro-action batches where the model emits
    /// several low-latency actions per reasoning step.
    ExecuteToolBatch {
        name: String,
        actions: Vec<ToolAction>,
        #[serde(default)]
        max_actions: Option<u8>,
    },
    /// Stop a managed browser profile session for an agent.
    StopBrowserProfile { name: String, session_id: String },
    /// Start a streaming capture session for the given runtime/agent.
    StartCaptureSession {
        name: String,
        request: CaptureSessionRequest,
    },
    /// Stop a previously started capture session.
    StopCaptureSession { name: String, session_id: String },
    /// Fetch the latest cached capture frame for an agent.
    LatestCaptureFrame {
        name: String,
        #[serde(default)]
        region: Option<CaptureRegion>,
    },
    /// Return dashboard status (URL/token) for local web UI.
    DashboardStatus,
    /// Snapshot payload for dashboard updates.
    DashboardSnapshot,
    /// Request a Telegram snapshot for an agent (photo payload).
    TelegramSnapshot { name: String },
    /// Get or set the fleet-wide goal.
    FleetGoal {
        /// If Some, sets the fleet goal. If None, returns the current goal.
        goal: Option<String>,
    },
    /// Update an agent's context fields (role, goal, context, task) at runtime.
    UpdateAgentContext {
        name: String,
        /// New role (None = leave unchanged, Some("") = clear).
        role: Option<String>,
        /// New agent goal (None = leave unchanged, Some("") = clear).
        agent_goal: Option<String>,
        /// New context (None = leave unchanged, Some("") = clear).
        context: Option<String>,
        /// New task (None = leave unchanged, Some("") = clear).
        #[serde(default)]
        task: Option<String>,
    },
    /// Get an agent's full context (role, goal, context, task).
    GetAgentContext { name: String },
    /// Enable an agent slot (allows it to be started).
    EnableAgent { name: String },
    /// Disable an agent slot (stops it if running, prevents restart).
    DisableAgent { name: String },
    /// Reload daemon configuration from daemon.toml.
    ///
    /// Re-reads daemon.toml and applies changes: adds new agents, updates
    /// config fields for existing agents, removes agents no longer present.
    /// Running agents are not restarted -- only their stored config updates.
    ReloadConfig,
    /// Request graceful daemon shutdown (stops all agents first).
    Shutdown,
    /// Bulk fleet snapshot for the orchestrator's review cycle.
    ///
    /// Returns an `OrchestratorSnapshot` with status, context, and recent output
    /// for each managed agent in a single call. Filters out orchestrator slots
    /// by default (the orchestrator should not review itself).
    OrchestratorContext {
        /// Agent names to include. Empty = all non-orchestrator agents.
        #[serde(default)]
        agents: Vec<String>,
        /// Number of recent output lines per agent (default: 30).
        #[serde(default)]
        output_lines: Option<usize>,
    },

    // -- Memory store commands --
    /// Get a value from the agent memory store.
    MemoryGet {
        namespace: String,
        key: String,
    },
    /// Set a value in the agent memory store (upsert).
    MemorySet {
        namespace: String,
        key: String,
        value: String,
    },
    /// Delete a key from the agent memory store.
    MemoryDelete {
        namespace: String,
        key: String,
    },
    /// List keys in a namespace.
    MemoryList {
        namespace: String,
        limit: Option<usize>,
    },
    /// Full-text search across memory entries in a namespace.
    MemorySearch {
        namespace: String,
        query: String,
        limit: Option<usize>,
    },

    // -- Cron scheduler commands --
    /// List all scheduled cron jobs.
    CronList,
    /// Add a new cron job.
    CronAdd {
        name: String,
        schedule: String,
        command: serde_json::Value,
    },
    /// Remove a cron job by name.
    CronRemove {
        name: String,
    },
    /// Manually trigger a cron job by name.
    CronTrigger {
        name: String,
    },

    // -- Plugin commands --
    /// Load a plugin from a manifest path.
    LoadPlugin {
        path: String,
    },
    /// List all loaded plugins.
    ListPlugins,
    /// Unload a plugin by name.
    UnloadPlugin {
        name: String,
    },

    // -- ACP protocol commands --
    /// Broadcast a message to all agents in the fleet.
    BroadcastToFleet {
        message: String,
        /// Agent names to exclude from the broadcast.
        #[serde(default)]
        exclude_agents: Vec<String>,
    },
    /// List all models seen by the usage proxy across the fleet.
    ListModels,
}

fn default_true() -> bool {
    true
}

/// Request payload for runtime subagent spawning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnSubagentRequest {
    /// Parent agent name (orchestrator or existing subagent).
    pub parent: String,
    /// Optional explicit child name.
    #[serde(default)]
    pub name: Option<String>,
    /// Optional role override for the child session.
    #[serde(default)]
    pub role: Option<String>,
    /// Optional initial task for the child session.
    #[serde(default)]
    pub task: Option<String>,
    /// Optional maximum depth allowed for this spawn chain.
    #[serde(default)]
    pub depth_limit: Option<u8>,
    /// Whether to start the child immediately after creating the slot.
    #[serde(default = "default_true")]
    pub start: bool,
}

/// Response payload for successful subagent spawn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnSubagentResult {
    pub parent: String,
    pub child: String,
    pub depth: u8,
    pub working_dir: String,
    pub tool: String,
}

/// Structured inter-agent message for the ACP protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMessage {
    /// Sending agent name.
    pub from: String,
    /// Receiving agent name.
    pub to: String,
    /// Message content.
    pub content: String,
    /// Message priority level.
    pub priority: MessagePriority,
    /// Timestamp when the message was created.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Priority level for inter-agent messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MessagePriority {
    Low,
    Normal,
    High,
    Urgent,
}

/// Response to a daemon command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonResponse {
    /// Whether the command succeeded.
    pub ok: bool,
    /// Human-readable message.
    pub message: String,
    /// Optional structured data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl DaemonResponse {
    /// Create a success response.
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            data: None,
        }
    }

    /// Create a success response with data.
    pub fn ok_with_data(message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            ok: true,
            message: message.into(),
            data: Some(data),
        }
    }

    /// Create an error response.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            data: None,
        }
    }
}

/// Summary of a single agent slot, returned by ListAgents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    /// Slot name.
    pub name: String,
    /// Current status.
    pub status: AgentStatus,
    /// Tool type (e.g., "ClaudeCode", "Codex").
    pub tool: String,
    /// Working directory.
    pub working_dir: String,
    /// Agent's role (short description).
    #[serde(default)]
    pub role: Option<String>,
    /// Number of restarts so far.
    pub restart_count: u32,
    /// Number of pending permission prompts.
    #[serde(default)]
    pub pending_count: usize,
    /// Whether this agent needs human attention.
    #[serde(default)]
    pub attention_needed: bool,
    /// Whether this agent is an orchestrator (vs a worker).
    #[serde(default)]
    pub is_orchestrator: bool,
    /// Model fallback lifecycle status (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<ModelFallbackState>,
    /// If the agent's session supports external attach (e.g., tmux),
    /// the command components to attach (e.g., ["tmux", "attach-session", "-t", "aegis-foo"]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attach_command: Option<Vec<String>>,
}

/// OpenClaw-style session summary for gateway/chat tooling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfo {
    pub session_key: String,
    pub agent: String,
    pub is_orchestrator: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// Session history payload for chat tooling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionHistory {
    pub session_key: String,
    pub lines: Vec<String>,
}

/// Detailed status for a single agent, returned by AgentStatus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDetail {
    /// Slot name.
    pub name: String,
    /// Current status.
    pub status: AgentStatus,
    /// Tool type.
    pub tool: String,
    /// Working directory.
    pub working_dir: String,
    /// Number of restarts so far.
    pub restart_count: u32,
    /// Process ID (if running).
    pub pid: Option<u32>,
    /// Seconds since this agent was started.
    pub uptime_secs: Option<u64>,
    /// Audit session ID (if active).
    pub session_id: Option<String>,
    /// Agent's role.
    #[serde(default)]
    pub role: Option<String>,
    /// Agent's strategic goal.
    #[serde(default)]
    pub agent_goal: Option<String>,
    /// Agent's additional context.
    #[serde(default)]
    pub context: Option<String>,
    /// Initial task/prompt configured for this agent.
    pub task: Option<String>,
    /// Whether the slot is enabled.
    pub enabled: bool,
    /// Number of pending permission prompts.
    #[serde(default)]
    pub pending_count: usize,
    /// Whether this agent needs human attention.
    #[serde(default)]
    pub attention_needed: bool,
    /// Model fallback lifecycle status (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<ModelFallbackState>,
}

/// Model fallback lifecycle status for an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelFallbackState {
    pub active: bool,
    pub selected_model: Option<String>,
    pub active_model: Option<String>,
    pub reason: Option<String>,
    pub updated_at_ms: u128,
}

/// Summary of a pending permission prompt, returned by ListPending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPromptSummary {
    /// Unique ID for this pending request.
    pub request_id: String,
    /// The raw prompt text.
    pub raw_prompt: String,
    /// Seconds since this prompt was received.
    pub age_secs: u64,
}

/// Result of a Cedar policy evaluation for a tool use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUseVerdict {
    /// "allow", "deny", or "ask" (fall through to interactive prompt).
    pub decision: String,
    /// Human-readable reason for the decision.
    pub reason: String,
}

/// Capability and mediation profile for one runtime/agent tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    /// Agent slot name.
    pub name: String,
    /// Tool type (e.g., ClaudeCode, OpenClaw).
    pub tool: String,
    /// Whether the runtime supports headless/non-interactive execution.
    pub headless: bool,
    /// One of: "enforced", "partial", "observe_only", "custom".
    pub policy_mediation: String,
    /// One-line explanation of mediation coverage.
    pub mediation_note: String,
    /// Runtime mediation mode ("enforced", "partial", "observe_only", "custom").
    pub mediation_mode: String,
    /// Hook bridge status ("connected", "disconnected", "unavailable", "custom").
    pub hook_bridge: String,
    /// Tool-coverage status ("covered", "restricted", "partial", "custom").
    pub tool_coverage: String,
    /// Compliance gate mode ("blocking", "advisory", "custom").
    pub compliance_mode: String,
    /// Active capture session id (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_capture_session_id: Option<String>,
    /// Target FPS for active capture session (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_capture_target_fps: Option<u16>,
    /// Last tool action name observed for this agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_tool_action: Option<String>,
    /// Last tool action risk tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_tool_risk_tag: Option<RiskTag>,
    /// Last tool action decision (`allow` or `deny`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_tool_decision: Option<String>,
    /// Last tool action note/reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_tool_note: Option<String>,
    /// Whether capture actions are enabled by toolkit config.
    #[serde(default)]
    pub toolkit_capture_enabled: bool,
    /// Whether input actions are enabled by toolkit config.
    #[serde(default)]
    pub toolkit_input_enabled: bool,
    /// Whether browser actions are enabled by toolkit config.
    #[serde(default)]
    pub toolkit_browser_enabled: bool,
    /// Browser backend configured for toolkit runtime.
    #[serde(default)]
    pub toolkit_browser_backend: String,
    /// Max micro-actions for fast executor batches.
    #[serde(default)]
    pub loop_max_micro_actions: u8,
    /// Time budget (ms) for fast executor batches.
    #[serde(default)]
    pub loop_time_budget_ms: u64,
    /// Auth mode for the agent tool runtime (oauth/api-key/setup-token/none).
    #[serde(default)]
    pub auth_mode: String,
    /// Whether required provider auth appears ready for this runtime.
    #[serde(default)]
    pub auth_ready: bool,
    /// Human-readable auth readiness hint for operators/orchestrators.
    #[serde(default)]
    pub auth_hint: String,
    /// Config-derived tool capability contract for orchestrator usage.
    #[serde(default)]
    pub tool_contract: String,
}

/// One feature row returned in secure-runtime parity status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityFeatureStatus {
    pub feature_id: String,
    pub status: String,
    pub risk_level: String,
    pub owner: String,
    pub required_controls: Vec<String>,
    pub missing_controls: Vec<String>,
}

/// Summary payload for `ParityStatus`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityStatusReport {
    pub source_dir: String,
    pub updated_at_utc: String,
    pub total_features: usize,
    pub complete_features: usize,
    pub partial_features: usize,
    pub high_risk_blockers: usize,
    pub features: Vec<ParityFeatureStatus>,
}

/// Latest delta payload for `ParityDiff`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityDiffReport {
    pub report_file: String,
    pub upstream_sha: String,
    pub changed_files: usize,
    pub impacted_feature_ids: Vec<String>,
}

/// Verification payload for `ParityVerify`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityVerifyReport {
    pub ok: bool,
    pub checked_features: usize,
    pub violations: Vec<String>,
    #[serde(default)]
    pub violations_struct: Vec<ParityViolation>,
}

/// Structured violation entry for `ParityVerifyReport`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityViolation {
    pub rule_id: String,
    pub feature_id: String,
    pub message: String,
}

/// Parameters used to start a capture stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureSessionRequest {
    /// Desired frames per second.
    pub target_fps: u16,
    /// Optional capture bounds.
    #[serde(default)]
    pub region: Option<CaptureRegion>,
}

/// Capture region bounds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureRegion {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// Data returned when a capture session is started.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureSessionStarted {
    pub session_id: String,
    pub target_fps: u16,
}

/// Result wrapper for one tool-action execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolActionExecution {
    pub result: ToolResult,
    pub risk_tag: RiskTag,
}

/// One full response payload from `ExecuteToolAction`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolActionOutcome {
    pub execution: ToolActionExecution,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<FramePayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tui: Option<TuiToolData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserToolData>,
}

/// Encoded screen frame payload returned from capture actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FramePayload {
    pub width: u32,
    pub height: u32,
    pub rgba_base64: String,
}

/// Latest cached capture frame payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatestCaptureFrame {
    pub session_id: Option<String>,
    pub frame_id: u64,
    pub age_ms: u64,
    pub frame: FramePayload,
}

/// TUI-specific result payload for TUI actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TuiToolData {
    Snapshot {
        target: String,
        text: String,
        cursor: [u16; 2],
        size: [u16; 2],
    },
    Input {
        target: String,
        sent: bool,
    },
}

/// Browser-specific result payload for browser actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserToolData {
    pub session_id: String,
    pub backend: String,
    pub available: bool,
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_json: Option<serde_json::Value>,
}

/// Dashboard status payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardStatus {
    pub enabled: bool,
    pub listen: String,
    pub base_url: Option<String>,
    pub token: Option<String>,
}

/// Dashboard snapshot payload for live UI updates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DashboardSnapshot {
    pub timestamp_ms: u128,
    pub agents: Vec<DashboardAgent>,
}

/// Per-agent row in the dashboard snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DashboardAgent {
    pub name: String,
    pub status: String,
    pub tool: String,
    pub role: Option<String>,
    pub goal: Option<String>,
    pub pending_count: usize,
    pub pending_prompts: Vec<DashboardPendingPrompt>,
    pub last_tool_action: Option<String>,
    pub last_tool_decision: Option<String>,
    pub last_tool_note: Option<String>,
    pub last_output: Vec<String>,
    pub latest_frame_age_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<ModelFallbackState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardPendingPrompt {
    pub request_id: String,
    pub raw_prompt: String,
    pub received_at_ms: u128,
}

/// Runtime operation category used for typed audit provenance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOperation {
    ExecuteToolAction,
    StartCaptureSession,
    StopCaptureSession,
}

/// Typed provenance payload persisted for runtime computer-use audit entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeAuditProvenance {
    pub agent: String,
    pub operation: RuntimeOperation,
    pub tool_action: ToolAction,
    pub cedar_action: String,
    pub risk_tag: RiskTag,
    pub decision: String,
    pub reason: String,
    pub outcome: ToolActionExecution,
}

/// Response payload for `ExecuteToolBatch`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolBatchOutcome {
    pub executed: usize,
    pub outcomes: Vec<ToolActionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halted_reason: Option<String>,
}

/// Bulk fleet snapshot returned by `OrchestratorContext`.
///
/// Contains everything an orchestrator agent needs for one review cycle:
/// status, context, and recent output for each managed agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorSnapshot {
    /// Fleet-wide goal (if set).
    pub fleet_goal: Option<String>,
    /// Per-agent views.
    pub agents: Vec<OrchestratorAgentView>,
}

/// Per-agent view included in an `OrchestratorSnapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorAgentView {
    /// Slot name.
    pub name: String,
    /// Current status.
    pub status: AgentStatus,
    /// Agent's role.
    pub role: Option<String>,
    /// Agent's strategic goal.
    pub agent_goal: Option<String>,
    /// Current task.
    pub task: Option<String>,
    /// Recent output lines (most recent last).
    pub recent_output: Vec<String>,
    /// Seconds since this agent was started.
    pub uptime_secs: Option<u64>,
    /// Whether this agent needs human attention (stalled, pending prompt).
    pub attention_needed: bool,
    /// Number of pending permission prompts.
    pub pending_count: usize,
}

/// Daemon health/ping response data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonPing {
    /// Daemon uptime in seconds.
    pub uptime_secs: u64,
    /// Total agent slots configured.
    pub agent_count: usize,
    /// Number of agents currently running.
    pub running_count: usize,
    /// Daemon process ID.
    pub daemon_pid: u32,
    /// Whether the daemon currently has a loaded policy engine for hook checks.
    #[serde(default)]
    pub policy_engine_loaded: bool,
    /// Whether hook evaluation is configured fail-open instead of fail-closed.
    #[serde(default)]
    pub hook_fail_open: bool,
}

/// Client for connecting to the daemon control socket.
///
/// Uses newline-delimited JSON over a Unix domain socket.
pub struct DaemonClient {
    socket_path: std::path::PathBuf,
}

impl DaemonClient {
    /// Create a new client targeting the given socket path.
    pub fn new(socket_path: std::path::PathBuf) -> Self {
        Self { socket_path }
    }

    /// Create a client using the default daemon socket path.
    pub fn default_path() -> Self {
        Self::new(aegis_types::daemon::daemon_dir().join("daemon.sock"))
    }

    /// Send a command and receive the response (blocking).
    ///
    /// Uses a 5-second read/write timeout to prevent the caller from blocking
    /// indefinitely if the daemon hangs. This is critical for the fleet TUI,
    /// which polls every second -- a hanging read would freeze the entire UI.
    pub fn send(&self, command: &DaemonCommand) -> Result<DaemonResponse, String> {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::os::unix::net::UnixStream;

        let stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            format!(
                "failed to connect to daemon at {}: {e}",
                self.socket_path.display()
            )
        })?;

        let timeout = Some(std::time::Duration::from_secs(5));
        stream
            .set_read_timeout(timeout)
            .map_err(|e| format!("failed to set read timeout: {e}"))?;
        stream
            .set_write_timeout(timeout)
            .map_err(|e| format!("failed to set write timeout: {e}"))?;

        let mut writer = stream
            .try_clone()
            .map_err(|e| format!("failed to clone stream: {e}"))?;

        let mut json = serde_json::to_string(command)
            .map_err(|e| format!("failed to serialize command: {e}"))?;
        json.push('\n');
        writer
            .write_all(json.as_bytes())
            .map_err(|e| format!("failed to send command: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush: {e}"))?;

        // Cap at 10 MB to prevent unbounded memory growth from a misbehaving daemon
        let mut reader = BufReader::new(stream.take(10 * 1024 * 1024));
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("failed to read response: {e}"))?;

        serde_json::from_str(&line).map_err(|e| format!("failed to parse response: {e}"))
    }

    /// Check if the daemon is running by attempting a Ping.
    pub fn is_running(&self) -> bool {
        self.send(&DaemonCommand::Ping).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_command_json_roundtrip() {
        let commands = vec![
            DaemonCommand::Ping,
            DaemonCommand::ListAgents,
            DaemonCommand::AgentStatus {
                name: "claude-1".into(),
            },
            DaemonCommand::AgentOutput {
                name: "claude-1".into(),
                lines: Some(50),
            },
            DaemonCommand::SendToAgent {
                name: "claude-1".into(),
                text: "hello".into(),
            },
            DaemonCommand::StartAgent {
                name: "claude-1".into(),
            },
            DaemonCommand::StopAgent {
                name: "claude-1".into(),
            },
            DaemonCommand::RestartAgent {
                name: "claude-1".into(),
            },
            DaemonCommand::AddAgent {
                config: Box::new(AgentSlotConfig {
                    name: "new-agent".into(),
                    tool: aegis_types::daemon::AgentToolConfig::ClaudeCode {
                        skip_permissions: false,
                        one_shot: false,
                        extra_args: vec![],
                    },
                    working_dir: std::path::PathBuf::from("/tmp"),
                    role: None,
                    agent_goal: None,
                    context: None,
                    task: None,
                    pilot: None,
                    restart: aegis_types::daemon::RestartPolicy::OnFailure,
                    max_restarts: 5,
                    enabled: true,
                    orchestrator: None,
                    security_preset: None,
                    policy_dir: None,
                    isolation: None,
                }),
                start: true,
            },
            DaemonCommand::SpawnSubagent {
                request: SpawnSubagentRequest {
                    parent: "orchestrator".into(),
                    name: Some("worker-sub-1".into()),
                    role: Some("Focused implementer".into()),
                    task: Some("Implement the parser".into()),
                    depth_limit: Some(3),
                    start: true,
                },
            },
            DaemonCommand::RemoveAgent {
                name: "claude-1".into(),
            },
            DaemonCommand::ApproveRequest {
                name: "claude-1".into(),
                request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            },
            DaemonCommand::DenyRequest {
                name: "claude-1".into(),
                request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            },
            DaemonCommand::NudgeAgent {
                name: "claude-1".into(),
                message: Some("wake up".into()),
            },
            DaemonCommand::ListPending {
                name: "claude-1".into(),
            },
            DaemonCommand::EvaluateToolUse {
                agent: "claude-1".into(),
                tool_name: "Bash".into(),
                tool_input: serde_json::json!({"command": "ls -la"}),
            },
            DaemonCommand::RuntimeCapabilities {
                name: "claude-1".into(),
            },
            DaemonCommand::ParityStatus,
            DaemonCommand::ParityDiff,
            DaemonCommand::ParityVerify,
            DaemonCommand::ExecuteToolAction {
                name: "claude-1".into(),
                action: ToolAction::MouseClick {
                    x: 120,
                    y: 240,
                    button: aegis_toolkit::contract::MouseButton::Left,
                },
            },
            DaemonCommand::ExecuteToolBatch {
                name: "claude-1".into(),
                actions: vec![
                    ToolAction::MouseMove { x: 100, y: 200 },
                    ToolAction::MouseClick {
                        x: 100,
                        y: 200,
                        button: aegis_toolkit::contract::MouseButton::Left,
                    },
                ],
                max_actions: Some(2),
            },
            DaemonCommand::StopBrowserProfile {
                name: "claude-1".into(),
                session_id: "browser-1".into(),
            },
            DaemonCommand::StartCaptureSession {
                name: "claude-1".into(),
                request: CaptureSessionRequest {
                    target_fps: 30,
                    region: Some(CaptureRegion {
                        x: 0,
                        y: 0,
                        width: 1280,
                        height: 720,
                    }),
                },
            },
            DaemonCommand::StopCaptureSession {
                name: "claude-1".into(),
                session_id: "cap-1".into(),
            },
            DaemonCommand::FleetGoal { goal: None },
            DaemonCommand::FleetGoal {
                goal: Some("Build a chess app".into()),
            },
            DaemonCommand::UpdateAgentContext {
                name: "claude-1".into(),
                role: Some("UX specialist".into()),
                agent_goal: None,
                context: Some("Use Tailwind CSS".into()),
                task: Some("Build the login page".into()),
            },
            DaemonCommand::GetAgentContext {
                name: "claude-1".into(),
            },
            DaemonCommand::EnableAgent {
                name: "claude-1".into(),
            },
            DaemonCommand::DisableAgent {
                name: "claude-1".into(),
            },
            DaemonCommand::ReloadConfig,
            DaemonCommand::Shutdown,
            DaemonCommand::OrchestratorContext {
                agents: vec!["frontend".into(), "backend".into()],
                output_lines: Some(30),
            },
            DaemonCommand::OrchestratorContext {
                agents: vec![],
                output_lines: None,
            },
            // Memory commands
            DaemonCommand::MemoryGet {
                namespace: "agent-1".into(),
                key: "last_task".into(),
            },
            DaemonCommand::MemorySet {
                namespace: "agent-1".into(),
                key: "last_task".into(),
                value: "implement login".into(),
            },
            DaemonCommand::MemoryDelete {
                namespace: "agent-1".into(),
                key: "last_task".into(),
            },
            DaemonCommand::MemoryList {
                namespace: "agent-1".into(),
                limit: Some(10),
            },
            DaemonCommand::MemorySearch {
                namespace: "agent-1".into(),
                query: "login".into(),
                limit: Some(5),
            },
            // Cron commands
            DaemonCommand::CronList,
            DaemonCommand::CronAdd {
                name: "health-check".into(),
                schedule: "every 5m".into(),
                command: serde_json::json!({"type": "ping"}),
            },
            DaemonCommand::CronRemove {
                name: "health-check".into(),
            },
            DaemonCommand::CronTrigger {
                name: "health-check".into(),
            },
            // Plugin commands
            DaemonCommand::LoadPlugin {
                path: "/home/user/.aegis/plugins/my-plugin/manifest.toml".into(),
            },
            DaemonCommand::ListPlugins,
            DaemonCommand::UnloadPlugin {
                name: "my-plugin".into(),
            },
            // ACP protocol commands
            DaemonCommand::BroadcastToFleet {
                message: "Deploy phase 2".into(),
                exclude_agents: vec!["orchestrator".into()],
            },
            DaemonCommand::BroadcastToFleet {
                message: "Stop all work".into(),
                exclude_agents: vec![],
            },
            DaemonCommand::ListModels,
        ];

        for cmd in commands {
            let json = serde_json::to_string(&cmd).unwrap();
            let back: DaemonCommand = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&back).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn daemon_response_ok() {
        let resp = DaemonResponse::ok("success");
        assert!(resp.ok);
        assert_eq!(resp.message, "success");
        assert!(resp.data.is_none());
    }

    #[test]
    fn daemon_response_with_data() {
        let resp = DaemonResponse::ok_with_data("found", serde_json::json!({"count": 3}));
        assert!(resp.ok);
        assert!(resp.data.is_some());
    }

    #[test]
    fn daemon_response_error() {
        let resp = DaemonResponse::error("not found");
        assert!(!resp.ok);
    }

    #[test]
    fn agent_summary_serialization() {
        let summary = AgentSummary {
            name: "claude-1".into(),
            status: AgentStatus::Running { pid: 1234 },
            tool: "ClaudeCode".into(),
            working_dir: "/home/user/project".into(),
            role: Some("UX specialist".into()),
            restart_count: 0,
            pending_count: 2,
            attention_needed: true,
            is_orchestrator: false,
            attach_command: None,
            fallback: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: AgentSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "claude-1");
        assert_eq!(back.pending_count, 2);
        assert!(back.attention_needed);
    }

    #[test]
    fn pending_prompt_summary_serialization() {
        let summary = PendingPromptSummary {
            request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            raw_prompt: "Allow Bash(rm -rf)?".into(),
            age_secs: 30,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: PendingPromptSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.request_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(back.age_secs, 30);
    }

    #[test]
    fn orchestrator_snapshot_serialization() {
        let snapshot = OrchestratorSnapshot {
            fleet_goal: Some("Build a chess app".into()),
            agents: vec![
                OrchestratorAgentView {
                    name: "frontend".into(),
                    status: AgentStatus::Running { pid: 1234 },
                    role: Some("UI developer".into()),
                    agent_goal: Some("Build the board".into()),
                    task: Some("Implement drag-and-drop".into()),
                    recent_output: vec!["compiling...".into(), "done".into()],
                    uptime_secs: Some(3600),
                    attention_needed: false,
                    pending_count: 0,
                },
                OrchestratorAgentView {
                    name: "backend".into(),
                    status: AgentStatus::Stopped { exit_code: 0 },
                    role: None,
                    agent_goal: None,
                    task: None,
                    recent_output: vec![],
                    uptime_secs: None,
                    attention_needed: true,
                    pending_count: 1,
                },
            ],
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let back: OrchestratorSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.fleet_goal.as_deref(), Some("Build a chess app"));
        assert_eq!(back.agents.len(), 2);
        assert_eq!(back.agents[0].name, "frontend");
        assert_eq!(back.agents[0].uptime_secs, Some(3600));
        assert!(back.agents[1].attention_needed);
        assert_eq!(back.agents[1].pending_count, 1);
    }

    #[test]
    fn daemon_ping_serialization() {
        let ping = DaemonPing {
            uptime_secs: 3600,
            agent_count: 4,
            running_count: 3,
            daemon_pid: 5678,
            policy_engine_loaded: true,
            hook_fail_open: false,
        };
        let json = serde_json::to_string(&ping).unwrap();
        let back: DaemonPing = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uptime_secs, 3600);
        assert_eq!(back.running_count, 3);
        assert!(back.policy_engine_loaded);
        assert!(!back.hook_fail_open);
    }

    #[test]
    fn runtime_capabilities_serialization() {
        let caps = RuntimeCapabilities {
            name: "worker-1".into(),
            tool: "OpenClaw".into(),
            headless: true,
            policy_mediation: "enforced".into(),
            mediation_note: "secure runtime bridge disconnected; actions are fail-closed".into(),
            mediation_mode: "enforced".into(),
            hook_bridge: "disconnected".into(),
            tool_coverage: "restricted".into(),
            compliance_mode: "blocking".into(),
            active_capture_session_id: Some("cap-1".into()),
            active_capture_target_fps: Some(30),
            last_tool_action: Some("MouseClick".into()),
            last_tool_risk_tag: Some(RiskTag::Medium),
            last_tool_decision: Some("deny".into()),
            last_tool_note: Some("runtime unavailable".into()),
            toolkit_capture_enabled: true,
            toolkit_input_enabled: true,
            toolkit_browser_enabled: false,
            toolkit_browser_backend: "cdp".into(),
            loop_max_micro_actions: 8,
            loop_time_budget_ms: 1200,
            auth_mode: "oauth".into(),
            auth_ready: true,
            auth_hint: "provider auth appears configured".into(),
            tool_contract: "contract text".into(),
        };
        let json = serde_json::to_string(&caps).unwrap();
        let back: RuntimeCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "worker-1");
        assert_eq!(back.tool, "OpenClaw");
        assert!(back.headless);
        assert_eq!(back.policy_mediation, "enforced");
        assert_eq!(back.hook_bridge, "disconnected");
        assert_eq!(back.compliance_mode, "blocking");
        assert_eq!(back.active_capture_target_fps, Some(30));
        assert_eq!(back.last_tool_decision.as_deref(), Some("deny"));
        assert_eq!(back.auth_mode, "oauth");
        assert!(back.auth_ready);
    }

    #[test]
    fn capture_session_request_roundtrip() {
        let req = CaptureSessionRequest {
            target_fps: 60,
            region: Some(CaptureRegion {
                x: 10,
                y: 20,
                width: 400,
                height: 300,
            }),
        };

        let json = serde_json::to_string(&req).unwrap();
        let back: CaptureSessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn tool_action_outcome_roundtrip() {
        let outcome = ToolActionOutcome {
            execution: ToolActionExecution {
                result: ToolResult {
                    action: "ScreenCapture".into(),
                    risk_tag: RiskTag::Low,
                    capture_latency_ms: Some(12),
                    input_latency_ms: None,
                    frame_id: Some(9),
                    window_id: None,
                    session_id: Some("cap-1".into()),
                    note: Some("allow: test".into()),
                },
                risk_tag: RiskTag::Low,
            },
            frame: Some(FramePayload {
                width: 2,
                height: 2,
                rgba_base64: "AQIDBA==".into(),
            }),
            tui: Some(TuiToolData::Input {
                target: "agent-1".into(),
                sent: true,
            }),
            browser: Some(BrowserToolData {
                session_id: "browser-1".into(),
                backend: "cdp".into(),
                available: false,
                note: "backend unavailable".into(),
                screenshot_base64: None,
                ws_url: None,
                result_json: None,
            }),
        };

        let json = serde_json::to_string(&outcome).unwrap();
        let back: ToolActionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, outcome);
    }

    #[test]
    fn runtime_audit_provenance_roundtrip() {
        let provenance = RuntimeAuditProvenance {
            agent: "worker-1".into(),
            operation: RuntimeOperation::ExecuteToolAction,
            tool_action: ToolAction::MouseMove { x: 1, y: 2 },
            cedar_action: "MouseMove".into(),
            risk_tag: RiskTag::Low,
            decision: "allow".into(),
            reason: "policy permit".into(),
            outcome: ToolActionExecution {
                result: ToolResult {
                    action: "MouseMove".into(),
                    risk_tag: RiskTag::Low,
                    capture_latency_ms: None,
                    input_latency_ms: Some(3),
                    frame_id: None,
                    window_id: None,
                    session_id: None,
                    note: Some("allow: policy permit".into()),
                },
                risk_tag: RiskTag::Low,
            },
        };

        let json = serde_json::to_string(&provenance).unwrap();
        let back: RuntimeAuditProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(back, provenance);
    }

    #[test]
    fn tool_batch_outcome_roundtrip() {
        let batch = ToolBatchOutcome {
            executed: 1,
            outcomes: vec![ToolActionOutcome {
                execution: ToolActionExecution {
                    result: ToolResult {
                        action: "MouseMove".into(),
                        risk_tag: RiskTag::Low,
                        capture_latency_ms: None,
                        input_latency_ms: Some(4),
                        frame_id: None,
                        window_id: None,
                        session_id: None,
                        note: Some("allow: ok".into()),
                    },
                    risk_tag: RiskTag::Low,
                },
                frame: None,
                tui: None,
                browser: None,
            }],
            halted_reason: Some("time budget exceeded".into()),
        };

        let json = serde_json::to_string(&batch).unwrap();
        let back: ToolBatchOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, batch);
    }

    #[test]
    fn agent_message_roundtrip() {
        let msg = AgentMessage {
            from: "orchestrator".into(),
            to: "worker-1".into(),
            content: "Please focus on the API module".into(),
            priority: MessagePriority::High,
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let back: AgentMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.from, "orchestrator");
        assert_eq!(back.to, "worker-1");
        assert_eq!(back.priority, MessagePriority::High);
    }

    #[test]
    fn message_priority_ordering() {
        assert!(MessagePriority::Low < MessagePriority::Normal);
        assert!(MessagePriority::Normal < MessagePriority::High);
        assert!(MessagePriority::High < MessagePriority::Urgent);
    }

    #[test]
    fn message_priority_serde() {
        let json = serde_json::to_string(&MessagePriority::Urgent).unwrap();
        assert_eq!(json, "\"urgent\"");
        let back: MessagePriority = serde_json::from_str(&json).unwrap();
        assert_eq!(back, MessagePriority::Urgent);
    }
}
