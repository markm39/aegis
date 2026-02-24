//! ACP message translator between ACP wire format and DaemonCommand/DaemonResponse.
//!
//! Provides bidirectional translation with security guarantees:
//! - All message content is sanitized (control characters stripped)
//! - Unknown message types are rejected (fail-closed)
//! - Per-session rate limiting prevents abuse
//! - Required fields are validated before processing
//! - Translations are logged to the audit trail by message type (never content)
//!
//! ## Security properties
//!
//! - **Fail-closed**: Unknown ACP method strings map to `TranslationError::UnknownMethod`.
//!   No default passthrough exists.
//! - **Content sanitization**: All string fields that flow into `DaemonCommand` are
//!   stripped of ASCII control characters (0x00..0x1F except TAB/LF/CR).
//! - **Rate limiting**: Each session has an independent sliding-window counter.
//!   Exceeding the limit returns a structured error before any translation occurs.
//! - **Audit**: Every successful translation emits a `tracing::info!` event with
//!   the method name and session ID, but never the message content.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::json;
use uuid::Uuid;

use crate::acp_client::AcpMessage;
use crate::daemon::{DaemonCommand, DaemonResponse};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default rate limit: 120 messages per minute per session.
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 120;

/// Known ACP method names that map to DaemonCommand variants.
/// Any method not in this set is rejected (fail-closed).
const KNOWN_METHODS: &[&str] = &["send", "status", "approve", "deny", "list", "stop"];

// ---------------------------------------------------------------------------
// TranslationError
// ---------------------------------------------------------------------------

/// Errors that can occur during ACP <-> Daemon translation.
#[derive(Debug, thiserror::Error)]
pub enum TranslationError {
    /// The ACP method is not in the known set (fail-closed).
    #[error("unknown ACP method: {method:?}; known methods: {}", KNOWN_METHODS.join(", "))]
    UnknownMethod { method: String },

    /// A required field is missing from the ACP message payload.
    #[error("missing required field: {field:?} for method {method:?}")]
    MissingField { method: String, field: String },

    /// A field value is invalid (empty, too long, or contains prohibited content).
    #[error("invalid field {field:?}: {reason}")]
    InvalidField { field: String, reason: String },

    /// The ACP message variant is not a Request (only Requests can be translated
    /// to DaemonCommands).
    #[error("expected ACP Request message, got {variant}")]
    WrongMessageVariant { variant: String },

    /// Per-session rate limit exceeded.
    #[error("rate limit exceeded for session {session_id}: max {limit} messages per minute")]
    RateLimitExceeded { session_id: String, limit: u32 },

    /// Internal error (lock poisoning, serialization failure, etc.).
    #[error("internal translation error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Content sanitization
// ---------------------------------------------------------------------------

/// Strip ASCII control characters from a string, preserving TAB (0x09),
/// LF (0x0A), and CR (0x0D).
///
/// This prevents injection of terminal escape sequences, null bytes, and
/// other control characters that could confuse downstream consumers.
fn sanitize_content(input: &str) -> String {
    input
        .chars()
        .filter(|&c| {
            // Keep printable characters and whitespace (tab, newline, carriage return)
            !c.is_control() || c == '\t' || c == '\n' || c == '\r'
        })
        .collect()
}

/// Sanitize a JSON value recursively: strip control characters from all
/// string values within objects and arrays.
fn sanitize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(sanitize_content(s)),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sanitize_json_value).collect())
        }
        serde_json::Value::Object(obj) => {
            let sanitized: serde_json::Map<String, serde_json::Value> = obj
                .iter()
                .map(|(k, v)| (sanitize_content(k), sanitize_json_value(v)))
                .collect();
            serde_json::Value::Object(sanitized)
        }
        other => other.clone(),
    }
}

/// Extract a required string field from a JSON payload.
///
/// Returns `Err(TranslationError::MissingField)` if the field is absent or null.
/// Returns `Err(TranslationError::InvalidField)` if the field is not a string
/// or is empty after sanitization.
fn require_string_field(
    payload: &serde_json::Value,
    field: &str,
    method: &str,
) -> Result<String, TranslationError> {
    let value = payload
        .get(field)
        .ok_or_else(|| TranslationError::MissingField {
            method: method.to_string(),
            field: field.to_string(),
        })?;

    let s = value
        .as_str()
        .ok_or_else(|| TranslationError::InvalidField {
            field: field.to_string(),
            reason: format!("expected string, got {}", value_type_name(value)),
        })?;

    let sanitized = sanitize_content(s);

    if sanitized.is_empty() {
        return Err(TranslationError::InvalidField {
            field: field.to_string(),
            reason: "field must not be empty after sanitization".to_string(),
        });
    }

    if sanitized.len() > 4096 {
        return Err(TranslationError::InvalidField {
            field: field.to_string(),
            reason: format!(
                "field exceeds maximum length of 4096 (got {})",
                sanitized.len()
            ),
        });
    }

    Ok(sanitized)
}

/// Return a human-readable type name for a JSON value (for error messages).
fn value_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// Per-session rate limiter
// ---------------------------------------------------------------------------

/// Per-session sliding-window rate limiter.
///
/// Maintains independent counters for each session, identified by a string
/// session ID. Sessions that exceed the configured rate are rejected before
/// any translation occurs.
#[derive(Debug)]
pub struct SessionRateLimiter {
    max_per_minute: u32,
    sessions: Mutex<HashMap<String, Vec<Instant>>>,
}

impl SessionRateLimiter {
    /// Create a new per-session rate limiter.
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Check and record a message for the given session.
    ///
    /// Returns `Ok(())` if the message is within limits, or
    /// `Err(TranslationError::RateLimitExceeded)` if the session has
    /// exceeded the per-minute limit.
    pub fn check_and_record(&self, session_id: &str) -> Result<(), TranslationError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| TranslationError::Internal("rate limiter lock poisoned".into()))?;

        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        let window = sessions.entry(session_id.to_string()).or_default();

        // Prune old entries
        window.retain(|&t| t > one_minute_ago);

        if window.len() >= self.max_per_minute as usize {
            return Err(TranslationError::RateLimitExceeded {
                session_id: session_id.to_string(),
                limit: self.max_per_minute,
            });
        }

        window.push(now);
        Ok(())
    }

    /// Prune stale entries from all sessions to prevent unbounded memory growth.
    pub fn prune_stale(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let one_minute_ago = Instant::now() - Duration::from_secs(60);
            sessions.retain(|_, window| {
                window.retain(|&t| t > one_minute_ago);
                !window.is_empty()
            });
        }
    }
}

// ---------------------------------------------------------------------------
// AcpTranslator
// ---------------------------------------------------------------------------

/// Bidirectional translator between ACP wire-format messages and
/// DaemonCommand/DaemonResponse.
///
/// ## Security guarantees
///
/// - Unknown method strings are rejected (fail-closed).
/// - All string content is sanitized before translation.
/// - Per-session rate limiting is enforced before translation.
/// - Required fields are validated with structured error reporting.
/// - Translations are logged by method type, never by content.
#[derive(Debug)]
pub struct AcpTranslator {
    rate_limiter: SessionRateLimiter,
}

impl AcpTranslator {
    /// Create a new translator with the default rate limit.
    pub fn new() -> Self {
        Self {
            rate_limiter: SessionRateLimiter::new(DEFAULT_RATE_LIMIT_PER_MINUTE),
        }
    }

    /// Create a new translator with a custom rate limit.
    pub fn with_rate_limit(max_per_minute: u32) -> Self {
        Self {
            rate_limiter: SessionRateLimiter::new(max_per_minute),
        }
    }

    /// Translate an ACP message into a DaemonCommand.
    ///
    /// Only ACP Request messages are accepted. The method field is matched
    /// against the known set and the payload is validated and sanitized.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique identifier for the ACP session (for rate limiting).
    /// * `message` - The ACP message to translate.
    ///
    /// # Returns
    ///
    /// A tuple of `(DaemonCommand, Uuid)` where the UUID is the original
    /// request ID for response correlation.
    ///
    /// # Errors
    ///
    /// Returns `TranslationError` if:
    /// - The session exceeds its rate limit
    /// - The message is not a Request variant
    /// - The method is unknown
    /// - Required fields are missing or invalid
    pub fn acp_to_daemon(
        &self,
        session_id: &str,
        message: &AcpMessage,
    ) -> Result<(DaemonCommand, Uuid), TranslationError> {
        // Rate limit check (before any processing)
        self.rate_limiter.check_and_record(session_id)?;

        // Only Request messages can be translated to commands
        let (id, method, payload) = match message {
            AcpMessage::Request {
                id,
                method,
                payload,
            } => (id, method, payload),
            AcpMessage::Response { .. } => {
                return Err(TranslationError::WrongMessageVariant {
                    variant: "Response".to_string(),
                });
            }
            AcpMessage::Event { .. } => {
                return Err(TranslationError::WrongMessageVariant {
                    variant: "Event".to_string(),
                });
            }
            AcpMessage::Error { .. } => {
                return Err(TranslationError::WrongMessageVariant {
                    variant: "Error".to_string(),
                });
            }
        };

        // Validate method against known set (fail-closed)
        let sanitized_method = sanitize_content(method);
        if !KNOWN_METHODS.contains(&sanitized_method.as_str()) {
            return Err(TranslationError::UnknownMethod {
                method: sanitized_method,
            });
        }

        // Sanitize the payload
        let clean_payload = sanitize_json_value(payload);

        // Translate based on method
        let command = match sanitized_method.as_str() {
            "send" => {
                let name = require_string_field(&clean_payload, "name", "send")?;
                let text = require_string_field(&clean_payload, "text", "send")?;
                DaemonCommand::SendToAgent { name, text }
            }
            "status" => {
                let name = require_string_field(&clean_payload, "name", "status")?;
                DaemonCommand::AgentStatus { name }
            }
            "approve" => {
                let name = require_string_field(&clean_payload, "name", "approve")?;
                let request_id = require_string_field(&clean_payload, "request_id", "approve")?;
                DaemonCommand::ApproveRequest { name, request_id }
            }
            "deny" => {
                let name = require_string_field(&clean_payload, "name", "deny")?;
                let request_id = require_string_field(&clean_payload, "request_id", "deny")?;
                DaemonCommand::DenyRequest { name, request_id }
            }
            "list" => DaemonCommand::ListAgents,
            "stop" => {
                let name = require_string_field(&clean_payload, "name", "stop")?;
                DaemonCommand::StopAgent { name }
            }
            // This branch is unreachable because we already validated against KNOWN_METHODS,
            // but we keep it for defense-in-depth.
            _ => {
                return Err(TranslationError::UnknownMethod {
                    method: sanitized_method,
                });
            }
        };

        // Audit log: method type only, never content
        tracing::info!(
            session_id = %session_id,
            method = %sanitized_method,
            request_id = %id,
            "ACP message translated to DaemonCommand"
        );

        Ok((command, *id))
    }

    /// Translate a DaemonResponse into an ACP Response message.
    ///
    /// The original request ID is used for correlation. The response content
    /// is sanitized before inclusion in the ACP message.
    pub fn daemon_to_acp(&self, request_id: Uuid, response: &DaemonResponse) -> AcpMessage {
        let sanitized_message = sanitize_content(&response.message);
        let sanitized_data = response.data.as_ref().map(sanitize_json_value);

        let payload = match sanitized_data {
            Some(data) => json!({
                "message": sanitized_message,
                "data": data,
            }),
            None => json!({
                "message": sanitized_message,
            }),
        };

        // Audit log: success/failure status only
        tracing::info!(
            request_id = %request_id,
            ok = response.ok,
            "DaemonResponse translated to ACP Response"
        );

        AcpMessage::Response {
            request_id,
            success: response.ok,
            payload,
        }
    }

    /// Translate a DaemonResponse into an ACP Event message for streaming.
    ///
    /// Used when the daemon emits events that should be pushed to ACP clients
    /// (e.g., agent status changes, output streaming, pending prompt notifications).
    pub fn daemon_event_to_acp(&self, event_type: &str, response: &DaemonResponse) -> AcpMessage {
        let sanitized_event_type = sanitize_content(event_type);
        let sanitized_message = sanitize_content(&response.message);
        let sanitized_data = response.data.as_ref().map(sanitize_json_value);

        let payload = match sanitized_data {
            Some(data) => json!({
                "message": sanitized_message,
                "ok": response.ok,
                "data": data,
            }),
            None => json!({
                "message": sanitized_message,
                "ok": response.ok,
            }),
        };

        tracing::info!(
            event_type = %sanitized_event_type,
            ok = response.ok,
            "DaemonResponse translated to ACP Event"
        );

        AcpMessage::Event {
            event_type: sanitized_event_type,
            payload,
        }
    }

    /// Translate a `TranslationError` into a structured ACP Error message.
    ///
    /// This ensures that even error conditions produce well-formed ACP messages
    /// that clients can programmatically handle.
    pub fn error_to_acp(&self, request_id: Option<Uuid>, error: &TranslationError) -> AcpMessage {
        let (code, message) = match error {
            TranslationError::UnknownMethod { .. } => ("UNKNOWN_METHOD", error.to_string()),
            TranslationError::MissingField { .. } => ("MISSING_FIELD", error.to_string()),
            TranslationError::InvalidField { .. } => ("INVALID_FIELD", error.to_string()),
            TranslationError::WrongMessageVariant { .. } => ("WRONG_VARIANT", error.to_string()),
            TranslationError::RateLimitExceeded { .. } => ("RATE_LIMITED", error.to_string()),
            TranslationError::Internal(_) => {
                // Do not leak internal details to clients
                ("INTERNAL_ERROR", "internal translation error".to_string())
            }
        };

        AcpMessage::Error {
            request_id,
            code: code.to_string(),
            message,
        }
    }

    /// Prune stale rate-limiter entries. Call periodically to prevent
    /// unbounded memory growth from many distinct sessions.
    pub fn prune_stale(&self) {
        self.rate_limiter.prune_stale();
    }
}

impl Default for AcpTranslator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: &str, payload: serde_json::Value) -> AcpMessage {
        AcpMessage::Request {
            id: Uuid::new_v4(),
            method: method.to_string(),
            payload,
        }
    }

    // -- ACP to Daemon translation tests --

    #[test]
    fn acp_to_daemon_send_translation() {
        let translator = AcpTranslator::new();
        let msg = make_request("send", json!({"name": "claude-1", "text": "hello agent"}));
        let (cmd, _id) = translator.acp_to_daemon("session-1", &msg).unwrap();
        match cmd {
            DaemonCommand::SendToAgent { name, text } => {
                assert_eq!(name, "claude-1");
                assert_eq!(text, "hello agent");
            }
            other => panic!("expected SendToAgent, got: {other:?}"),
        }
    }

    #[test]
    fn acp_to_daemon_status_translation() {
        let translator = AcpTranslator::new();
        let msg = make_request("status", json!({"name": "agent-2"}));
        let (cmd, _id) = translator.acp_to_daemon("session-1", &msg).unwrap();
        match cmd {
            DaemonCommand::AgentStatus { name } => {
                assert_eq!(name, "agent-2");
            }
            other => panic!("expected AgentStatus, got: {other:?}"),
        }
    }

    #[test]
    fn acp_to_daemon_approve_translation() {
        let translator = AcpTranslator::new();
        let msg = make_request(
            "approve",
            json!({"name": "claude-1", "request_id": "req-abc"}),
        );
        let (cmd, _id) = translator.acp_to_daemon("session-1", &msg).unwrap();
        match cmd {
            DaemonCommand::ApproveRequest { name, request_id } => {
                assert_eq!(name, "claude-1");
                assert_eq!(request_id, "req-abc");
            }
            other => panic!("expected ApproveRequest, got: {other:?}"),
        }
    }

    #[test]
    fn acp_to_daemon_deny_translation() {
        let translator = AcpTranslator::new();
        let msg = make_request("deny", json!({"name": "claude-1", "request_id": "req-xyz"}));
        let (cmd, _id) = translator.acp_to_daemon("session-1", &msg).unwrap();
        match cmd {
            DaemonCommand::DenyRequest { name, request_id } => {
                assert_eq!(name, "claude-1");
                assert_eq!(request_id, "req-xyz");
            }
            other => panic!("expected DenyRequest, got: {other:?}"),
        }
    }

    #[test]
    fn acp_to_daemon_list_translation() {
        let translator = AcpTranslator::new();
        let msg = make_request("list", json!({}));
        let (cmd, _id) = translator.acp_to_daemon("session-1", &msg).unwrap();
        assert!(
            matches!(cmd, DaemonCommand::ListAgents),
            "expected ListAgents, got: {cmd:?}"
        );
    }

    #[test]
    fn acp_to_daemon_stop_translation() {
        let translator = AcpTranslator::new();
        let msg = make_request("stop", json!({"name": "agent-3"}));
        let (cmd, _id) = translator.acp_to_daemon("session-1", &msg).unwrap();
        match cmd {
            DaemonCommand::StopAgent { name } => {
                assert_eq!(name, "agent-3");
            }
            other => panic!("expected StopAgent, got: {other:?}"),
        }
    }

    // -- Daemon to ACP response translation --

    #[test]
    fn daemon_to_acp_response_translation() {
        let translator = AcpTranslator::new();
        let request_id = Uuid::new_v4();

        // Success response without data
        let response = DaemonResponse::ok("agent started");
        let acp_msg = translator.daemon_to_acp(request_id, &response);
        match &acp_msg {
            AcpMessage::Response {
                request_id: rid,
                success,
                payload,
            } => {
                assert_eq!(rid, &request_id);
                assert!(success);
                assert_eq!(payload["message"], "agent started");
            }
            other => panic!("expected Response, got: {other:?}"),
        }

        // Error response with data
        let response = DaemonResponse {
            ok: false,
            message: "agent not found".to_string(),
            data: Some(json!({"details": "no agent named 'ghost'"})),
        };
        let acp_msg = translator.daemon_to_acp(request_id, &response);
        match &acp_msg {
            AcpMessage::Response {
                success, payload, ..
            } => {
                assert!(!success);
                assert_eq!(payload["message"], "agent not found");
                assert_eq!(payload["data"]["details"], "no agent named 'ghost'");
            }
            other => panic!("expected Response, got: {other:?}"),
        }
    }

    // -- Event translation --

    #[test]
    fn daemon_event_to_acp_translation() {
        let translator = AcpTranslator::new();
        let response = DaemonResponse::ok_with_data("status changed", json!({"status": "running"}));
        let acp_msg = translator.daemon_event_to_acp("agent.status_changed", &response);
        match &acp_msg {
            AcpMessage::Event {
                event_type,
                payload,
            } => {
                assert_eq!(event_type, "agent.status_changed");
                assert_eq!(payload["message"], "status changed");
                assert_eq!(payload["ok"], true);
                assert_eq!(payload["data"]["status"], "running");
            }
            other => panic!("expected Event, got: {other:?}"),
        }
    }

    // -- Rate limiting --

    #[test]
    fn rate_limiting_per_session() {
        let translator = AcpTranslator::with_rate_limit(3);

        let msg = make_request("list", json!({}));

        // First 3 should succeed
        assert!(translator.acp_to_daemon("sess-a", &msg).is_ok());
        assert!(translator.acp_to_daemon("sess-a", &msg).is_ok());
        assert!(translator.acp_to_daemon("sess-a", &msg).is_ok());

        // 4th should fail
        let result = translator.acp_to_daemon("sess-a", &msg);
        assert!(
            matches!(&result, Err(TranslationError::RateLimitExceeded { session_id, limit })
                if session_id == "sess-a" && *limit == 3),
            "expected RateLimitExceeded, got: {result:?}"
        );

        // Different session should still work (isolation)
        assert!(translator.acp_to_daemon("sess-b", &msg).is_ok());
    }

    // -- Unknown method rejection (fail-closed) --

    #[test]
    fn invalid_message_type_rejected() {
        let translator = AcpTranslator::new();
        let msg = make_request("execute_arbitrary_code", json!({"cmd": "rm -rf /"}));
        let result = translator.acp_to_daemon("session-1", &msg);
        assert!(
            matches!(&result, Err(TranslationError::UnknownMethod { method })
                if method == "execute_arbitrary_code"),
            "expected UnknownMethod, got: {result:?}"
        );
    }

    #[test]
    fn empty_method_rejected() {
        let translator = AcpTranslator::new();
        let msg = make_request("", json!({}));
        let result = translator.acp_to_daemon("session-1", &msg);
        assert!(
            matches!(result, Err(TranslationError::UnknownMethod { .. })),
            "expected UnknownMethod, got: {result:?}"
        );
    }

    // -- Content sanitization --

    #[test]
    fn content_sanitized_in_translation() {
        let translator = AcpTranslator::new();

        // Control characters in the text field should be stripped
        let msg = make_request(
            "send",
            json!({"name": "agent-1", "text": "hello\x00world\x07beep"}),
        );
        let (cmd, _id) = translator.acp_to_daemon("session-1", &msg).unwrap();
        match cmd {
            DaemonCommand::SendToAgent { text, .. } => {
                assert_eq!(text, "helloworldbeep");
                assert!(!text.contains('\x00'));
                assert!(!text.contains('\x07'));
            }
            other => panic!("expected SendToAgent, got: {other:?}"),
        }
    }

    #[test]
    fn sanitize_preserves_valid_whitespace() {
        assert_eq!(
            sanitize_content("line1\nline2\ttab\rreturn"),
            "line1\nline2\ttab\rreturn"
        );
    }

    #[test]
    fn sanitize_strips_null_bytes() {
        assert_eq!(sanitize_content("hello\x00world"), "helloworld");
    }

    #[test]
    fn sanitize_strips_bell_and_escape() {
        assert_eq!(
            sanitize_content("normal\x07bell\x1bescape"),
            "normalbellescape"
        );
    }

    #[test]
    fn sanitize_json_strips_nested_control_chars() {
        let input = json!({"key\x00": "val\x07ue", "nested": {"deep": "ok\x00"}});
        let output = sanitize_json_value(&input);
        assert_eq!(output["key"]["deep"], json!(null)); // key was sanitized, so original key gone
        assert_eq!(output["nested"]["deep"], "ok");
    }

    // -- Required fields validation --

    #[test]
    fn required_fields_validated() {
        let translator = AcpTranslator::new();

        // Missing "name" field for send
        let msg = make_request("send", json!({"text": "hello"}));
        let result = translator.acp_to_daemon("session-1", &msg);
        assert!(
            matches!(&result, Err(TranslationError::MissingField { field, .. }) if field == "name"),
            "expected MissingField for 'name', got: {result:?}"
        );

        // Missing "text" field for send
        let msg = make_request("send", json!({"name": "agent-1"}));
        let result = translator.acp_to_daemon("session-1", &msg);
        assert!(
            matches!(&result, Err(TranslationError::MissingField { field, .. }) if field == "text"),
            "expected MissingField for 'text', got: {result:?}"
        );

        // Missing "request_id" for approve
        let msg = make_request("approve", json!({"name": "agent-1"}));
        let result = translator.acp_to_daemon("session-1", &msg);
        assert!(
            matches!(&result, Err(TranslationError::MissingField { field, .. }) if field == "request_id"),
            "expected MissingField for 'request_id', got: {result:?}"
        );

        // Non-string field type
        let msg = make_request("status", json!({"name": 42}));
        let result = translator.acp_to_daemon("session-1", &msg);
        assert!(
            matches!(result, Err(TranslationError::InvalidField { .. })),
            "expected InvalidField, got: {result:?}"
        );

        // Empty string field after sanitization (only control chars)
        let msg = make_request("status", json!({"name": "\x00\x01\x02"}));
        let result = translator.acp_to_daemon("session-1", &msg);
        assert!(
            matches!(result, Err(TranslationError::InvalidField { .. })),
            "expected InvalidField for empty-after-sanitize, got: {result:?}"
        );
    }

    // -- Security: MANDATORY security property tests --

    #[test]
    fn security_unknown_methods_fail_closed() {
        // SECURITY PROPERTY: Any method not in the explicit allow-list MUST be rejected.
        // This is the fail-closed guarantee that prevents attackers from invoking
        // arbitrary daemon commands via crafted ACP messages.
        let translator = AcpTranslator::new();

        let dangerous_methods = [
            "shutdown",
            "remove_agent",
            "add_agent",
            "restart",
            "reload",
            "exec",
            "eval",
            "spawn",
            "__proto__",
            "constructor",
            "../../../etc/passwd",
            "send\x00smuggled",
        ];

        for method in &dangerous_methods {
            let msg = make_request(method, json!({}));
            let result = translator.acp_to_daemon("session-1", &msg);
            assert!(
                matches!(result, Err(TranslationError::UnknownMethod { .. })),
                "SECURITY VIOLATION: method {:?} was not rejected (fail-closed violated), got: {:?}",
                method,
                result
            );
        }
    }

    #[test]
    fn security_control_chars_never_pass_through() {
        // SECURITY PROPERTY: Control characters (especially null bytes, escape
        // sequences) must never appear in translated DaemonCommand fields.
        let translator = AcpTranslator::new();

        let evil_name = "agent\x00\x1b[31mred\x1b[0m";
        let evil_text = "payload\x07\x08\x1b]0;pwned\x07";
        let msg = make_request("send", json!({"name": evil_name, "text": evil_text}));
        let (cmd, _) = translator.acp_to_daemon("session-1", &msg).unwrap();

        match cmd {
            DaemonCommand::SendToAgent { name, text } => {
                // Verify no control characters remain
                assert!(
                    !name
                        .chars()
                        .any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r'),
                    "SECURITY VIOLATION: control characters in agent name: {:?}",
                    name
                );
                assert!(
                    !text
                        .chars()
                        .any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r'),
                    "SECURITY VIOLATION: control characters in text: {:?}",
                    text
                );
            }
            other => panic!("expected SendToAgent, got: {other:?}"),
        }
    }

    #[test]
    fn security_response_sanitized() {
        // SECURITY PROPERTY: DaemonResponse content is sanitized before
        // being included in ACP Response messages.
        let translator = AcpTranslator::new();
        let request_id = Uuid::new_v4();
        let response = DaemonResponse {
            ok: true,
            message: "done\x00\x07\x1b[31m".to_string(),
            data: Some(json!({"key": "val\x00ue"})),
        };

        let acp_msg = translator.daemon_to_acp(request_id, &response);
        match &acp_msg {
            AcpMessage::Response { payload, .. } => {
                let msg_str = payload["message"].as_str().unwrap();
                assert!(
                    !msg_str.contains('\x00'),
                    "SECURITY VIOLATION: null byte in response message"
                );
                let data_val = payload["data"]["key"].as_str().unwrap();
                assert!(
                    !data_val.contains('\x00'),
                    "SECURITY VIOLATION: null byte in response data"
                );
            }
            other => panic!("expected Response, got: {other:?}"),
        }
    }

    // -- Wrong message variant --

    #[test]
    fn wrong_message_variant_rejected() {
        let translator = AcpTranslator::new();

        let event = AcpMessage::Event {
            event_type: "test".to_string(),
            payload: json!({}),
        };
        assert!(matches!(
            translator.acp_to_daemon("session-1", &event),
            Err(TranslationError::WrongMessageVariant { .. })
        ));

        let response = AcpMessage::Response {
            request_id: Uuid::new_v4(),
            success: true,
            payload: json!({}),
        };
        assert!(matches!(
            translator.acp_to_daemon("session-1", &response),
            Err(TranslationError::WrongMessageVariant { .. })
        ));

        let error = AcpMessage::Error {
            request_id: None,
            code: "TEST".to_string(),
            message: "test error".to_string(),
        };
        assert!(matches!(
            translator.acp_to_daemon("session-1", &error),
            Err(TranslationError::WrongMessageVariant { .. })
        ));
    }

    // -- Error to ACP conversion --

    #[test]
    fn error_to_acp_produces_structured_error() {
        let translator = AcpTranslator::new();
        let request_id = Uuid::new_v4();

        let error = TranslationError::UnknownMethod {
            method: "evil".to_string(),
        };
        let acp_msg = translator.error_to_acp(Some(request_id), &error);
        match &acp_msg {
            AcpMessage::Error {
                request_id: rid,
                code,
                ..
            } => {
                assert_eq!(rid, &Some(request_id));
                assert_eq!(code, "UNKNOWN_METHOD");
            }
            other => panic!("expected Error, got: {other:?}"),
        }

        // Internal errors should not leak details
        let error = TranslationError::Internal("secret details".to_string());
        let acp_msg = translator.error_to_acp(None, &error);
        match &acp_msg {
            AcpMessage::Error { message, .. } => {
                assert!(!message.contains("secret"));
                assert_eq!(message, "internal translation error");
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    // -- Request ID correlation --

    #[test]
    fn request_id_preserved_through_translation() {
        let translator = AcpTranslator::new();
        let original_id = Uuid::new_v4();

        let msg = AcpMessage::Request {
            id: original_id,
            method: "list".to_string(),
            payload: json!({}),
        };
        let (_cmd, returned_id) = translator.acp_to_daemon("session-1", &msg).unwrap();
        assert_eq!(returned_id, original_id);
    }

    // -- Rate limiter isolation --

    #[test]
    fn rate_limiter_session_isolation() {
        let limiter = SessionRateLimiter::new(2);

        // Fill up session-a
        assert!(limiter.check_and_record("session-a").is_ok());
        assert!(limiter.check_and_record("session-a").is_ok());
        assert!(limiter.check_and_record("session-a").is_err());

        // session-b is independent
        assert!(limiter.check_and_record("session-b").is_ok());
        assert!(limiter.check_and_record("session-b").is_ok());
        assert!(limiter.check_and_record("session-b").is_err());
    }

    // -- Prune stale --

    #[test]
    fn prune_stale_does_not_panic() {
        let translator = AcpTranslator::new();
        let msg = make_request("list", json!({}));
        let _ = translator.acp_to_daemon("session-1", &msg);
        translator.prune_stale();
        // Should still work after pruning
        assert!(translator.acp_to_daemon("session-1", &msg).is_ok());
    }
}
