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
    /// Approve a pending permission request for an agent.
    ApproveRequest { name: String, request_id: String },
    /// Deny a pending permission request for an agent.
    DenyRequest { name: String, request_id: String },
    /// Nudge a stalled agent with an optional message.
    NudgeAgent { name: String, message: Option<String> },
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
    /// Get or set the fleet-wide goal.
    FleetGoal {
        /// If Some, sets the fleet goal. If None, returns the current goal.
        goal: Option<String>,
    },
    /// Update an agent's context fields (role, goal, context) at runtime.
    UpdateAgentContext {
        name: String,
        /// New role (None = leave unchanged, Some("") = clear).
        role: Option<String>,
        /// New agent goal (None = leave unchanged, Some("") = clear).
        agent_goal: Option<String>,
        /// New context (None = leave unchanged, Some("") = clear).
        context: Option<String>,
    },
    /// Get an agent's full context (role, goal, context, task).
    GetAgentContext {
        name: String,
    },
    /// Request graceful daemon shutdown (stops all agents first).
    Shutdown,
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
    pub fn send(&self, command: &DaemonCommand) -> Result<DaemonResponse, String> {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::os::unix::net::UnixStream;

        let stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| format!("failed to connect to daemon at {}: {e}", self.socket_path.display()))?;

        let mut writer = stream.try_clone()
            .map_err(|e| format!("failed to clone stream: {e}"))?;

        let mut json = serde_json::to_string(command)
            .map_err(|e| format!("failed to serialize command: {e}"))?;
        json.push('\n');
        writer.write_all(json.as_bytes())
            .map_err(|e| format!("failed to send command: {e}"))?;
        writer.flush()
            .map_err(|e| format!("failed to flush: {e}"))?;

        let reader = BufReader::new(stream);
        let mut line = String::new();
        reader.take(1_000_000).read_line(&mut line)
            .map_err(|e| format!("failed to read response: {e}"))?;

        serde_json::from_str(&line)
            .map_err(|e| format!("failed to parse response: {e}"))
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
            DaemonCommand::AgentStatus { name: "claude-1".into() },
            DaemonCommand::AgentOutput { name: "claude-1".into(), lines: Some(50) },
            DaemonCommand::SendToAgent { name: "claude-1".into(), text: "hello".into() },
            DaemonCommand::StartAgent { name: "claude-1".into() },
            DaemonCommand::StopAgent { name: "claude-1".into() },
            DaemonCommand::RestartAgent { name: "claude-1".into() },
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
                }),
                start: true,
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
            DaemonCommand::ListPending { name: "claude-1".into() },
            DaemonCommand::EvaluateToolUse {
                agent: "claude-1".into(),
                tool_name: "Bash".into(),
                tool_input: serde_json::json!({"command": "ls -la"}),
            },
            DaemonCommand::FleetGoal { goal: None },
            DaemonCommand::FleetGoal { goal: Some("Build a chess app".into()) },
            DaemonCommand::UpdateAgentContext {
                name: "claude-1".into(),
                role: Some("UX specialist".into()),
                agent_goal: None,
                context: Some("Use Tailwind CSS".into()),
            },
            DaemonCommand::GetAgentContext { name: "claude-1".into() },
            DaemonCommand::Shutdown,
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
    fn daemon_ping_serialization() {
        let ping = DaemonPing {
            uptime_secs: 3600,
            agent_count: 4,
            running_count: 3,
            daemon_pid: 5678,
        };
        let json = serde_json::to_string(&ping).unwrap();
        let back: DaemonPing = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uptime_secs, 3600);
        assert_eq!(back.running_count, 3);
    }
}
