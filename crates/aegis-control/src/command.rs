//! Command and response types for the control plane.
//!
//! Commands are sent from clients (CLI, HTTP, webhooks) to the pilot
//! supervisor. Each command produces a [`CommandResponse`].

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A command sent to the pilot supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// Send text input to the agent's stdin.
    SendInput { text: String },
    /// Approve a pending permission request.
    Approve { request_id: Uuid },
    /// Deny a pending permission request.
    Deny {
        request_id: Uuid,
        reason: Option<String>,
    },
    /// Send a nudge to the agent (uses default message if none specified).
    Nudge { message: Option<String> },
    /// Get current pilot status.
    Status,
    /// Get recent agent output lines.
    GetOutput { lines: Option<usize> },
    /// Hot-reload Cedar policies from disk.
    UpdatePolicy,
    /// Request graceful shutdown of the pilot.
    Shutdown { message: Option<String> },
}

/// Response to a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    /// Whether the command succeeded.
    pub ok: bool,
    /// Human-readable message.
    pub message: String,
    /// Optional structured data (depends on the command).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CommandResponse {
    /// Create a success response with a message.
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            data: None,
        }
    }

    /// Create a success response with message and data.
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

/// Pilot status snapshot returned by the Status command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotStatus {
    /// The agent command being supervised.
    pub command: String,
    /// Process ID of the child.
    pub pid: u32,
    /// Whether the child is still running.
    pub alive: bool,
    /// Seconds since the pilot started.
    pub uptime_secs: u64,
    /// Seconds since last agent output.
    pub idle_secs: u64,
    /// Number of pending permission requests.
    pub pending_count: usize,
    /// Number of prompts approved so far.
    pub approved: u64,
    /// Number of prompts denied so far.
    pub denied: u64,
    /// Number of stall nudges sent.
    pub nudges: u64,
    /// Adapter name in use.
    pub adapter: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_json_roundtrip() {
        let commands = vec![
            Command::SendInput { text: "hello".into() },
            Command::Approve { request_id: Uuid::new_v4() },
            Command::Deny { request_id: Uuid::new_v4(), reason: Some("too risky".into()) },
            Command::Nudge { message: None },
            Command::Status,
            Command::GetOutput { lines: Some(50) },
            Command::UpdatePolicy,
            Command::Shutdown { message: None },
        ];

        for cmd in commands {
            let json = serde_json::to_string(&cmd).unwrap();
            let back: Command = serde_json::from_str(&json).unwrap();
            // Verify roundtrip by re-serializing
            let json2 = serde_json::to_string(&back).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn response_ok() {
        let resp = CommandResponse::ok("success");
        assert!(resp.ok);
        assert_eq!(resp.message, "success");
        assert!(resp.data.is_none());
    }

    #[test]
    fn response_ok_with_data() {
        let resp = CommandResponse::ok_with_data("found", serde_json::json!({"count": 5}));
        assert!(resp.ok);
        assert!(resp.data.is_some());
    }

    #[test]
    fn response_error() {
        let resp = CommandResponse::error("not found");
        assert!(!resp.ok);
        assert_eq!(resp.message, "not found");
    }

    #[test]
    fn status_serialization() {
        let status = PilotStatus {
            command: "claude".into(),
            pid: 12345,
            alive: true,
            uptime_secs: 3600,
            idle_secs: 5,
            pending_count: 0,
            approved: 42,
            denied: 3,
            nudges: 1,
            adapter: "ClaudeCode".into(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: PilotStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 12345);
        assert_eq!(back.approved, 42);
    }
}
