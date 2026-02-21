//! Pilot event types for webhook payloads and logging.
//!
//! These events are emitted by the pilot supervisor and can be forwarded
//! to the webhook alert system or logged for auditing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A pilot-specific event for webhook dispatching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotWebhookEvent {
    /// Unique event ID.
    pub event_id: Uuid,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// The kind of pilot event.
    pub kind: PilotEventKind,
    /// The agent command being supervised.
    pub command: String,
    /// Process ID of the supervised agent.
    pub pid: u32,
    /// Recent output lines for context.
    pub recent_output: Vec<String>,
    /// Callback URL for the HTTP control plane (if enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    /// Session statistics.
    pub stats: EventStats,
}

/// The kind of pilot event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PilotEventKind {
    /// A permission prompt was auto-approved.
    PermissionApproved { action: String, reason: String },
    /// A permission prompt was auto-denied.
    PermissionDenied { action: String, reason: String },
    /// Agent stall detected; nudge sent.
    StallDetected { nudge_count: u32, idle_secs: u64 },
    /// Agent needs human attention (max nudges exceeded).
    AttentionNeeded { nudge_count: u32 },
    /// An uncertain prompt requires human decision.
    PendingApproval {
        request_id: Uuid,
        raw_prompt: String,
    },
    /// The supervised agent has exited.
    AgentExited { exit_code: i32 },
}

/// Summary statistics included in webhook events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventStats {
    pub approved: u64,
    pub denied: u64,
    pub uncertain: u64,
    pub nudges: u64,
    pub uptime_secs: u64,
}

impl PilotWebhookEvent {
    /// Create a new pilot webhook event.
    pub fn new(
        kind: PilotEventKind,
        command: &str,
        pid: u32,
        recent_output: Vec<String>,
        callback_url: Option<String>,
        stats: EventStats,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            kind,
            command: command.to_string(),
            pid,
            recent_output,
            callback_url,
            stats,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serialization() {
        let event = PilotWebhookEvent::new(
            PilotEventKind::PermissionDenied {
                action: "FileWrite /etc/passwd".into(),
                reason: "default deny policy".into(),
            },
            "claude",
            12345,
            vec!["recent line 1".into(), "recent line 2".into()],
            Some("http://localhost:8443/v1/command".into()),
            EventStats {
                approved: 10,
                denied: 2,
                ..Default::default()
            },
        );

        let json = serde_json::to_string_pretty(&event).unwrap();
        let back: PilotWebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 12345);
        assert_eq!(back.command, "claude");
    }

    #[test]
    fn event_kind_variants() {
        let kinds = vec![
            PilotEventKind::PermissionApproved {
                action: "FileRead /tmp/a".into(),
                reason: "permit-all".into(),
            },
            PilotEventKind::StallDetected {
                nudge_count: 1,
                idle_secs: 120,
            },
            PilotEventKind::AttentionNeeded { nudge_count: 5 },
            PilotEventKind::PendingApproval {
                request_id: Uuid::new_v4(),
                raw_prompt: "Allow?".into(),
            },
            PilotEventKind::AgentExited { exit_code: 0 },
        ];

        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: PilotEventKind = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&back).unwrap();
            assert_eq!(json, json2);
        }
    }
}
