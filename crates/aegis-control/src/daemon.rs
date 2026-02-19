//! Daemon-level control protocol types.
//!
//! These commands operate on the daemon fleet (listing agents, starting/stopping
//! individual agents, sending input, reading output). They are separate from
//! the per-agent pilot [`Command`](crate::command::Command) types, which handle
//! prompt approval and stall nudges within a single supervisor session.

use serde::{Deserialize, Serialize};

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
}

fn default_true() -> bool {
    true
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
    /// If the agent's session supports external attach (e.g., tmux),
    /// the command components to attach (e.g., ["tmux", "attach-session", "-t", "aegis-foo"]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attach_command: Option<Vec<String>>,
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
            policy_mediation: "partial".into(),
            mediation_note: "OpenClaw hook bridge not yet implemented".into(),
        };
        let json = serde_json::to_string(&caps).unwrap();
        let back: RuntimeCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "worker-1");
        assert_eq!(back.tool, "OpenClaw");
        assert!(back.headless);
        assert_eq!(back.policy_mediation, "partial");
    }
}
