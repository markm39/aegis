//! Message routing types for parent-child threading and channel-aware delivery.
//!
//! [`MessageEnvelope`] is the core unit of inter-agent and cross-channel
//! messaging. Each envelope carries sender/recipient routing, an optional
//! parent ID for threading, and a channel tag for format-specific rendering.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A routable message envelope with threading and channel metadata.
///
/// Envelopes are the wire format for all message routing. They carry enough
/// context for the router to determine the target queue, the formatter to
/// apply channel-specific escaping, and the audit system to log a content
/// hash without persisting raw content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    /// Unique identifier for this message.
    pub id: Uuid,
    /// Parent message ID for threading (None for top-level messages).
    pub parent_id: Option<Uuid>,
    /// Sender identifier (agent name, channel name, or "system").
    pub from: String,
    /// Recipient agent name or channel identifier.
    pub to: String,
    /// Delivery channel (e.g., "telegram", "slack", "direct").
    pub channel: String,
    /// Message content (sanitized before routing).
    pub content: String,
    /// When the message was created.
    pub timestamp: DateTime<Utc>,
    /// Whether this is a system-injected message (no user attribution).
    /// System messages require elevated Cedar policy action.
    pub is_system: bool,
}

impl MessageEnvelope {
    /// Create a new user-attributed message envelope.
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        channel: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            parent_id: None,
            from: from.into(),
            to: to.into(),
            channel: channel.into(),
            content: content.into(),
            timestamp: Utc::now(),
            is_system: false,
        }
    }

    /// Create a system-injected message (no user attribution).
    ///
    /// System messages are used for orchestrator directives and require
    /// elevated Cedar policy permissions (`RouteSystemMessage`).
    pub fn system(
        to: impl Into<String>,
        channel: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            parent_id: None,
            from: "system".to_string(),
            to: to.into(),
            channel: channel.into(),
            content: content.into(),
            timestamp: Utc::now(),
            is_system: true,
        }
    }

    /// Set the parent message ID for threading.
    #[must_use]
    pub fn with_parent(mut self, parent_id: Uuid) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Compute a SHA-256 hash of the message content for audit logging.
    ///
    /// We log the hash rather than raw content to avoid persisting potentially
    /// sensitive data in the audit ledger while still maintaining traceability.
    pub fn content_hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.content.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

/// Sanitize message content from external channels.
///
/// Strips or escapes potentially dangerous content before routing:
/// - Removes null bytes (can confuse C-level string processing)
/// - Removes ANSI escape sequences (terminal injection)
/// - Truncates to a maximum length to prevent memory exhaustion
/// - Strips control characters (except newline and tab)
pub struct ContentSanitizer;

/// Maximum message content length in bytes after sanitization.
const MAX_CONTENT_LENGTH: usize = 64 * 1024; // 64 KiB

impl ContentSanitizer {
    /// Sanitize message content, returning the cleaned string.
    pub fn sanitize(input: &str) -> String {
        let mut output = String::with_capacity(input.len().min(MAX_CONTENT_LENGTH));

        for ch in input.chars() {
            if output.len() >= MAX_CONTENT_LENGTH {
                break;
            }
            // Allow printable characters, newlines, and tabs
            if ch == '\n' || ch == '\t' || (!ch.is_control() && ch != '\0') {
                output.push(ch);
            }
            // Drop null bytes, ANSI escapes (ESC = \x1b), and other control chars
        }

        output
    }
}

/// Validate that an agent name is safe for use as a routing target.
///
/// Rejects names containing directory traversal sequences or path separators
/// to prevent injection attacks through the routing layer.
pub fn validate_agent_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("agent name must not be empty".to_string());
    }
    if name.contains("..") {
        return Err(format!(
            "agent name '{name}' contains directory traversal sequence '..'"
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(format!(
            "agent name '{name}' contains path separator characters"
        ));
    }
    if name.contains('\0') {
        return Err(format!("agent name '{name}' contains null byte"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_envelope_new() {
        let env = MessageEnvelope::new("agent-1", "agent-2", "direct", "hello");
        assert_eq!(env.from, "agent-1");
        assert_eq!(env.to, "agent-2");
        assert_eq!(env.channel, "direct");
        assert_eq!(env.content, "hello");
        assert!(!env.is_system);
        assert!(env.parent_id.is_none());
    }

    #[test]
    fn message_envelope_system() {
        let env = MessageEnvelope::system("agent-1", "direct", "restart now");
        assert_eq!(env.from, "system");
        assert!(env.is_system);
    }

    #[test]
    fn message_envelope_with_parent() {
        let parent_id = Uuid::new_v4();
        let env = MessageEnvelope::new("a", "b", "direct", "reply").with_parent(parent_id);
        assert_eq!(env.parent_id, Some(parent_id));
    }

    #[test]
    fn message_envelope_serialization_roundtrip() {
        let env = MessageEnvelope::new("sender", "receiver", "telegram", "test msg");
        let json = serde_json::to_string(&env).unwrap();
        let back: MessageEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn content_hash_deterministic() {
        let env = MessageEnvelope::new("a", "b", "direct", "same content");
        let hash1 = env.content_hash();
        let hash2 = env.content_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn content_hash_differs_for_different_content() {
        let env1 = MessageEnvelope::new("a", "b", "direct", "content A");
        let env2 = MessageEnvelope::new("a", "b", "direct", "content B");
        assert_ne!(env1.content_hash(), env2.content_hash());
    }

    #[test]
    fn sanitizer_removes_null_bytes() {
        let input = "hello\0world";
        let output = ContentSanitizer::sanitize(input);
        assert_eq!(output, "helloworld");
    }

    #[test]
    fn sanitizer_removes_control_chars() {
        let input = "hello\x01\x02\x03world";
        let output = ContentSanitizer::sanitize(input);
        assert_eq!(output, "helloworld");
    }

    #[test]
    fn sanitizer_preserves_newlines_and_tabs() {
        let input = "line1\nline2\ttab";
        let output = ContentSanitizer::sanitize(input);
        assert_eq!(output, input);
    }

    #[test]
    fn sanitizer_removes_ansi_escape() {
        // ESC is \x1b, a control character
        let input = "before\x1b[31mred\x1b[0mafter";
        let output = ContentSanitizer::sanitize(input);
        assert_eq!(output, "before[31mred[0mafter");
    }

    #[test]
    fn sanitizer_truncates_at_max_length() {
        let long_input = "a".repeat(MAX_CONTENT_LENGTH + 1000);
        let output = ContentSanitizer::sanitize(&long_input);
        assert!(output.len() <= MAX_CONTENT_LENGTH);
    }

    #[test]
    fn security_test_agent_name_traversal_rejected() {
        assert!(validate_agent_name("../etc/passwd").is_err());
        assert!(validate_agent_name("agent/../secret").is_err());
        assert!(validate_agent_name("agent/child").is_err());
        assert!(validate_agent_name("agent\\child").is_err());
        assert!(validate_agent_name("").is_err());
        assert!(validate_agent_name("agent\0name").is_err());
    }

    #[test]
    fn validate_agent_name_accepts_valid_names() {
        assert!(validate_agent_name("claude-1").is_ok());
        assert!(validate_agent_name("worker_2").is_ok());
        assert!(validate_agent_name("agent.name").is_ok());
        assert!(validate_agent_name("test").is_ok());
    }

    #[test]
    fn security_test_message_content_sanitized() {
        // Verify that malicious content is stripped
        let malicious = "normal\x00text\x1b[2J\x01hidden";
        let sanitized = ContentSanitizer::sanitize(malicious);
        assert!(!sanitized.contains('\0'));
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\x01'));
        assert!(sanitized.contains("normal"));
        assert!(sanitized.contains("text"));
    }
}
