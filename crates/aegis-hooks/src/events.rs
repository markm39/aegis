//! Hook event types for the user-extensible hook system.
//!
//! Each variant represents a lifecycle event that can trigger user hooks.
//! Events are serialized to JSON and passed to hook scripts via stdin.

use serde::{Deserialize, Serialize};

/// Lifecycle events that can trigger user hook scripts.
///
/// Each event carries context-specific data. The enum is serialized to JSON
/// with `snake_case` variant names, matching the filename convention used
/// for convention-based hook discovery (e.g., `pre_tool_use.sh`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HookEvent {
    /// Fired before an agent tool call is executed.
    ///
    /// PreToolUse hooks can inspect and optionally modify the arguments,
    /// or block the call entirely.
    PreToolUse {
        tool_name: String,
        arguments: serde_json::Value,
    },

    /// Fired after an agent tool call completes.
    ///
    /// PostToolUse hooks can inspect and optionally modify the result.
    PostToolUse {
        tool_name: String,
        result: serde_json::Value,
    },

    /// Fired when a message is sent or received on a channel.
    OnMessage {
        sender: String,
        content: String,
        channel: String,
    },

    /// Fired when a pending approval request is acted on.
    OnApproval { request_id: String, action: String },

    /// Fired when an agent process starts.
    OnAgentStart { agent_name: String },

    /// Fired when an agent process stops.
    OnAgentStop {
        agent_name: String,
        exit_code: Option<i32>,
    },

    /// Fired when an error occurs in the system.
    OnError { error: String, context: String },

    /// User-defined custom event with an arbitrary name and payload.
    Custom {
        name: String,
        payload: serde_json::Value,
    },
}

impl HookEvent {
    /// Return the canonical event name used for matching against hook filenames
    /// and configuration entries.
    ///
    /// For standard events, this is the `snake_case` variant name.
    /// For `Custom` events, the user-provided name is returned.
    pub fn event_name(&self) -> &str {
        match self {
            HookEvent::PreToolUse { .. } => "pre_tool_use",
            HookEvent::PostToolUse { .. } => "post_tool_use",
            HookEvent::OnMessage { .. } => "on_message",
            HookEvent::OnApproval { .. } => "on_approval",
            HookEvent::OnAgentStart { .. } => "on_agent_start",
            HookEvent::OnAgentStop { .. } => "on_agent_stop",
            HookEvent::OnError { .. } => "on_error",
            HookEvent::Custom { name, .. } => name,
        }
    }

    /// Serialize the event to a JSON value suitable for passing to hook scripts.
    pub fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

/// Response returned by a hook script after processing an event.
///
/// Hook scripts write this as JSON to stdout. The `action` field controls
/// whether the triggering operation proceeds, is blocked, or has its
/// payload modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResponse {
    /// What the hook wants to do with the triggering operation.
    pub action: HookResponseAction,

    /// Optional human-readable message explaining the decision.
    #[serde(default)]
    pub message: String,

    /// Modified payload data (only meaningful when `action` is `Modify`).
    ///
    /// For `PreToolUse`, this replaces the tool arguments.
    /// For `PostToolUse`, this replaces the tool result.
    /// For `OnMessage`, this replaces the message content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,

    /// Machine-readable reason for the response, set automatically on error paths.
    ///
    /// Examples: "hook_timeout", "hook_not_found", "parse_failure", "exit_code_2".
    /// Hook scripts do not need to set this -- it is populated by the runner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The action a hook script wants to take on the triggering operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookResponseAction {
    /// Allow the operation to proceed unchanged.
    Allow,
    /// Block the operation from proceeding.
    Block,
    /// Allow the operation but with a modified payload.
    Modify,
}

impl Default for HookResponse {
    /// Default is **Block** (fail-closed).
    ///
    /// This is a deliberate security decision: when a hook fails to produce a
    /// valid response (timeout, crash, parse error), the safe default is to
    /// block the action rather than silently permit it. Callers that want
    /// fail-open behavior should use `HookResponse::allow()` explicitly.
    fn default() -> Self {
        Self {
            action: HookResponseAction::Block,
            message: "hook did not produce a response (fail-closed default)".to_string(),
            payload: None,
            reason: Some("fail_closed_default".to_string()),
        }
    }
}

impl HookResponse {
    /// Construct an explicit allow response.
    pub fn allow() -> Self {
        Self {
            action: HookResponseAction::Allow,
            message: String::new(),
            payload: None,
            reason: None,
        }
    }

    /// Construct an explicit block response with a reason.
    pub fn block(reason: &str, message: impl Into<String>) -> Self {
        Self {
            action: HookResponseAction::Block,
            message: message.into(),
            payload: None,
            reason: Some(reason.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_name_matches_serde_tag() {
        let event = HookEvent::PreToolUse {
            tool_name: "Bash".to_string(),
            arguments: serde_json::json!({"command": "ls"}),
        };
        assert_eq!(event.event_name(), "pre_tool_use");

        let json = event.to_json().unwrap();
        assert_eq!(json["event"], "pre_tool_use");
        assert_eq!(json["tool_name"], "Bash");
    }

    #[test]
    fn custom_event_uses_user_name() {
        let event = HookEvent::Custom {
            name: "my_workflow".to_string(),
            payload: serde_json::json!({"step": 1}),
        };
        assert_eq!(event.event_name(), "my_workflow");
    }

    #[test]
    fn hook_response_deserializes() {
        let json = r#"{"action": "block", "message": "not allowed"}"#;
        let resp: HookResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.action, HookResponseAction::Block);
        assert_eq!(resp.message, "not allowed");
        assert!(resp.payload.is_none());
    }

    #[test]
    fn hook_response_with_payload() {
        let json = r#"{"action": "modify", "message": "redacted", "payload": {"content": "***"}}"#;
        let resp: HookResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.action, HookResponseAction::Modify);
        assert_eq!(resp.payload.unwrap()["content"], "***");
    }

    #[test]
    fn default_response_is_block() {
        let resp = HookResponse::default();
        assert_eq!(resp.action, HookResponseAction::Block);
        assert!(resp.reason.is_some());
    }

    #[test]
    fn explicit_allow_response() {
        let resp = HookResponse::allow();
        assert_eq!(resp.action, HookResponseAction::Allow);
        assert!(resp.reason.is_none());
    }

    #[test]
    fn all_event_names() {
        let events = vec![
            HookEvent::PreToolUse {
                tool_name: "t".into(),
                arguments: serde_json::Value::Null,
            },
            HookEvent::PostToolUse {
                tool_name: "t".into(),
                result: serde_json::Value::Null,
            },
            HookEvent::OnMessage {
                sender: "s".into(),
                content: "c".into(),
                channel: "ch".into(),
            },
            HookEvent::OnApproval {
                request_id: "r".into(),
                action: "approve".into(),
            },
            HookEvent::OnAgentStart {
                agent_name: "a".into(),
            },
            HookEvent::OnAgentStop {
                agent_name: "a".into(),
                exit_code: Some(0),
            },
            HookEvent::OnError {
                error: "e".into(),
                context: "c".into(),
            },
            HookEvent::Custom {
                name: "x".into(),
                payload: serde_json::Value::Null,
            },
        ];

        let names: Vec<&str> = events.iter().map(|e| e.event_name()).collect();
        assert_eq!(
            names,
            vec![
                "pre_tool_use",
                "post_tool_use",
                "on_message",
                "on_approval",
                "on_agent_start",
                "on_agent_stop",
                "on_error",
                "x",
            ]
        );
    }

    #[test]
    fn events_roundtrip_json() {
        let event = HookEvent::OnAgentStop {
            agent_name: "claude-1".to_string(),
            exit_code: Some(137),
        };
        let json = event.to_json().unwrap();
        let deserialized: HookEvent = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.event_name(), "on_agent_stop");
    }
}
