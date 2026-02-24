//! Gateway-native browser chat over WebSocket.
//!
//! Provides the data model for a browser-based chat widget that connects
//! to the Aegis control plane via WebSocket. The actual WebSocket endpoint
//! is served by `aegis-control`; this module defines the session tracking,
//! message types, and history buffer used by that endpoint.
//!
//! # Architecture
//!
//! - [`WebChatSession`]: tracks a connected browser client.
//! - [`ChatMessage`] / [`TypingIndicator`] / [`ConnectionStatus`]: WebSocket
//!   message types exchanged between browser and server.
//! - [`MessageHistory`]: bounded ring buffer for recent chat messages.
//! - [`WebChatRegistry`]: manages all active sessions.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrent WebChat sessions.
const MAX_SESSIONS: usize = 256;

/// Default message history capacity.
const DEFAULT_HISTORY_CAPACITY: usize = 500;

/// Maximum message text length.
const MAX_MESSAGE_LEN: usize = 8192;

/// Maximum display name length.
const MAX_DISPLAY_NAME_LEN: usize = 64;

/// Session idle timeout (no heartbeat/activity).
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// The role/source of a chat message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    /// Message from a human user via the browser.
    User,
    /// Message from an Aegis agent.
    Agent,
    /// System notification (join, leave, error).
    System,
}

/// A chat message exchanged over the WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Unique message ID.
    pub id: String,
    /// Who sent the message.
    pub role: MessageRole,
    /// Display name of the sender.
    pub sender: String,
    /// Message text content.
    pub text: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Optional agent name this message is directed at.
    pub target_agent: Option<String>,
}

impl ChatMessage {
    /// Create a new user message.
    pub fn user(sender: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            role: MessageRole::User,
            sender: sender.into(),
            text: text.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            target_agent: None,
        }
    }

    /// Create a new agent message.
    pub fn agent(agent_name: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            role: MessageRole::Agent,
            sender: agent_name.into(),
            text: text.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            target_agent: None,
        }
    }

    /// Create a system notification message.
    pub fn system(text: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            role: MessageRole::System,
            sender: "system".to_string(),
            text: text.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            target_agent: None,
        }
    }
}

/// A typing indicator event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingIndicator {
    /// Session ID of the user typing.
    pub session_id: String,
    /// Display name.
    pub display_name: String,
    /// Whether currently typing.
    pub is_typing: bool,
}

/// WebSocket frame types sent between client and server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    /// A chat message.
    Chat(ChatMessage),
    /// A typing indicator.
    Typing(TypingIndicator),
    /// Connection status update.
    Status {
        /// The session ID assigned by the server.
        session_id: String,
        /// Whether the connection is established.
        connected: bool,
        /// Number of other connected users.
        peer_count: usize,
    },
    /// Heartbeat ping.
    Ping {
        /// Server timestamp (millis since epoch).
        server_time: u64,
    },
    /// Heartbeat pong from client.
    Pong {
        /// The server_time echoed back.
        server_time: u64,
    },
    /// History replay (sent to new connections).
    History {
        /// Recent messages.
        messages: Vec<ChatMessage>,
    },
    /// Error from the server.
    Error {
        /// Error description.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Errors from webchat operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebChatError {
    /// Too many active sessions.
    TooManySessions { limit: usize },
    /// Session not found.
    SessionNotFound { session_id: String },
    /// Message validation failed.
    InvalidMessage { reason: String },
    /// Display name validation failed.
    InvalidDisplayName { reason: String },
}

impl std::fmt::Display for WebChatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManySessions { limit } => {
                write!(f, "webchat session limit of {limit} exceeded")
            }
            Self::SessionNotFound { session_id } => {
                write!(f, "webchat session {session_id:?} not found")
            }
            Self::InvalidMessage { reason } => {
                write!(f, "invalid webchat message: {reason}")
            }
            Self::InvalidDisplayName { reason } => {
                write!(f, "invalid display name: {reason}")
            }
        }
    }
}

impl std::error::Error for WebChatError {}

/// Validate a display name.
fn validate_display_name(name: &str) -> Result<(), WebChatError> {
    if name.is_empty() {
        return Err(WebChatError::InvalidDisplayName {
            reason: "display name cannot be empty".to_string(),
        });
    }
    if name.len() > MAX_DISPLAY_NAME_LEN {
        return Err(WebChatError::InvalidDisplayName {
            reason: format!("display name exceeds {MAX_DISPLAY_NAME_LEN} characters"),
        });
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(WebChatError::InvalidDisplayName {
            reason: "display name contains control characters".to_string(),
        });
    }
    Ok(())
}

/// Validate a message text.
fn validate_message_text(text: &str) -> Result<(), WebChatError> {
    if text.is_empty() {
        return Err(WebChatError::InvalidMessage {
            reason: "message text cannot be empty".to_string(),
        });
    }
    if text.len() > MAX_MESSAGE_LEN {
        return Err(WebChatError::InvalidMessage {
            reason: format!("message text exceeds {MAX_MESSAGE_LEN} characters"),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A connected browser chat session.
#[derive(Debug, Clone)]
pub struct WebChatSession {
    /// Unique session ID.
    session_id: String,
    /// User display name.
    display_name: String,
    /// When the session was created.
    connected_at: Instant,
    /// Last activity timestamp.
    last_activity: Instant,
    /// Whether the user is currently typing.
    is_typing: bool,
    /// Remote address (for logging, not authentication).
    remote_addr: Option<String>,
}

impl WebChatSession {
    /// Create a new session.
    fn new(display_name: String, remote_addr: Option<String>) -> Self {
        let now = Instant::now();
        Self {
            session_id: Uuid::new_v4().to_string(),
            display_name,
            connected_at: now,
            last_activity: now,
            is_typing: false,
            remote_addr,
        }
    }

    /// The session ID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// When the session was created.
    pub fn connected_at(&self) -> Instant {
        self.connected_at
    }

    /// Last activity time.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Whether the user is typing.
    pub fn is_typing(&self) -> bool {
        self.is_typing
    }

    /// Remote address, if known.
    pub fn remote_addr(&self) -> Option<&str> {
        self.remote_addr.as_deref()
    }

    /// Record activity (resets idle timer).
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Whether this session has exceeded the idle timeout.
    pub fn is_idle(&self) -> bool {
        self.last_activity.elapsed() > SESSION_IDLE_TIMEOUT
    }

    /// Set typing state.
    pub fn set_typing(&mut self, typing: bool) {
        self.is_typing = typing;
        self.touch();
    }
}

// ---------------------------------------------------------------------------
// Message history
// ---------------------------------------------------------------------------

/// Bounded ring buffer for recent chat messages.
#[derive(Debug)]
pub struct MessageHistory {
    /// Messages in chronological order.
    messages: Vec<ChatMessage>,
    /// Maximum capacity.
    capacity: usize,
}

impl MessageHistory {
    /// Create a new history with default capacity.
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            capacity: DEFAULT_HISTORY_CAPACITY,
        }
    }

    /// Create a new history with custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            messages: Vec::new(),
            capacity: capacity.max(1), // at least 1
        }
    }

    /// Add a message to the history.
    pub fn push(&mut self, message: ChatMessage) {
        if self.messages.len() >= self.capacity {
            self.messages.remove(0);
        }
        self.messages.push(message);
    }

    /// Get the most recent N messages.
    pub fn recent(&self, count: usize) -> &[ChatMessage] {
        let start = self.messages.len().saturating_sub(count);
        &self.messages[start..]
    }

    /// Get all messages.
    pub fn all(&self) -> &[ChatMessage] {
        &self.messages
    }

    /// Number of messages stored.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }
}

impl Default for MessageHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Manages all active WebChat sessions and shared message history.
#[derive(Debug)]
pub struct WebChatRegistry {
    /// Active sessions keyed by session ID.
    sessions: HashMap<String, WebChatSession>,
    /// Shared message history.
    history: MessageHistory,
}

impl WebChatRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            history: MessageHistory::new(),
        }
    }

    /// Create a registry with custom history capacity.
    pub fn with_history_capacity(capacity: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            history: MessageHistory::with_capacity(capacity),
        }
    }

    /// Register a new session and return its ID.
    pub fn connect(
        &mut self,
        display_name: impl Into<String>,
        remote_addr: Option<String>,
    ) -> Result<String, WebChatError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;

        if self.sessions.len() >= MAX_SESSIONS {
            return Err(WebChatError::TooManySessions {
                limit: MAX_SESSIONS,
            });
        }

        let session = WebChatSession::new(display_name.clone(), remote_addr);
        let session_id = session.session_id().to_string();

        debug!(session_id = %session_id, display_name = %display_name, "webchat session connected");

        self.sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    /// Disconnect a session.
    pub fn disconnect(&mut self, session_id: &str) -> Result<WebChatSession, WebChatError> {
        self.sessions
            .remove(session_id)
            .ok_or_else(|| WebChatError::SessionNotFound {
                session_id: session_id.to_string(),
            })
    }

    /// Get a session by ID.
    pub fn get_session(&self, session_id: &str) -> Option<&WebChatSession> {
        self.sessions.get(session_id)
    }

    /// Get a mutable session by ID.
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut WebChatSession> {
        self.sessions.get_mut(session_id)
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// List all session IDs.
    pub fn session_ids(&self) -> Vec<&str> {
        self.sessions.keys().map(|k| k.as_str()).collect()
    }

    /// Handle an incoming message from a session.
    ///
    /// Validates the message, records it in history, and returns the
    /// constructed `ChatMessage` for broadcasting to other sessions.
    pub fn handle_message(
        &mut self,
        session_id: &str,
        text: &str,
    ) -> Result<ChatMessage, WebChatError> {
        validate_message_text(text)?;

        let session =
            self.sessions
                .get_mut(session_id)
                .ok_or_else(|| WebChatError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?;

        session.touch();
        session.set_typing(false);

        let msg = ChatMessage::user(&session.display_name, text);
        self.history.push(msg.clone());
        Ok(msg)
    }

    /// Record an agent message and add to history.
    pub fn record_agent_message(&mut self, agent_name: &str, text: &str) -> ChatMessage {
        let msg = ChatMessage::agent(agent_name, text);
        self.history.push(msg.clone());
        msg
    }

    /// Record a system message and add to history.
    pub fn record_system_message(&mut self, text: &str) -> ChatMessage {
        let msg = ChatMessage::system(text);
        self.history.push(msg.clone());
        msg
    }

    /// Get the message history.
    pub fn history(&self) -> &MessageHistory {
        &self.history
    }

    /// Get recent messages for replaying to a new connection.
    pub fn recent_history(&self, count: usize) -> &[ChatMessage] {
        self.history.recent(count)
    }

    /// Remove idle sessions and return their IDs.
    pub fn reap_idle_sessions(&mut self) -> Vec<String> {
        let idle_ids: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_idle())
            .map(|(id, _)| id.clone())
            .collect();

        for id in &idle_ids {
            if let Some(session) = self.sessions.remove(id) {
                warn!(
                    session_id = %id,
                    display_name = %session.display_name,
                    "reaped idle webchat session"
                );
            }
        }

        idle_ids
    }
}

impl Default for WebChatRegistry {
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

    // -- ChatMessage constructors --

    #[test]
    fn chat_message_user() {
        let msg = ChatMessage::user("Alice", "hello");
        assert_eq!(msg.role, MessageRole::User);
        assert_eq!(msg.sender, "Alice");
        assert_eq!(msg.text, "hello");
        assert!(msg.target_agent.is_none());
        assert!(!msg.id.is_empty());
        assert!(!msg.timestamp.is_empty());
    }

    #[test]
    fn chat_message_agent() {
        let msg = ChatMessage::agent("claude-1", "response text");
        assert_eq!(msg.role, MessageRole::Agent);
        assert_eq!(msg.sender, "claude-1");
    }

    #[test]
    fn chat_message_system() {
        let msg = ChatMessage::system("user joined");
        assert_eq!(msg.role, MessageRole::System);
        assert_eq!(msg.sender, "system");
    }

    // -- ChatMessage serialization --

    #[test]
    fn chat_message_roundtrip() {
        let msg = ChatMessage::user("Alice", "hello");
        let json = serde_json::to_string(&msg).unwrap();
        let back: ChatMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, msg.id);
        assert_eq!(back.text, msg.text);
        assert_eq!(back.role, msg.role);
    }

    // -- WsMessage serialization --

    #[test]
    fn ws_message_chat_roundtrip() {
        let ws = WsMessage::Chat(ChatMessage::user("Alice", "hi"));
        let json = serde_json::to_string(&ws).unwrap();
        assert!(json.contains("\"type\":\"chat\""));
        let _back: WsMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn ws_message_typing_roundtrip() {
        let ws = WsMessage::Typing(TypingIndicator {
            session_id: "abc".to_string(),
            display_name: "Alice".to_string(),
            is_typing: true,
        });
        let json = serde_json::to_string(&ws).unwrap();
        assert!(json.contains("\"type\":\"typing\""));
    }

    #[test]
    fn ws_message_status_roundtrip() {
        let ws = WsMessage::Status {
            session_id: "s1".to_string(),
            connected: true,
            peer_count: 3,
        };
        let json = serde_json::to_string(&ws).unwrap();
        assert!(json.contains("\"type\":\"status\""));
        let _back: WsMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn ws_message_ping_pong_roundtrip() {
        let ping = WsMessage::Ping { server_time: 12345 };
        let json = serde_json::to_string(&ping).unwrap();
        let _back: WsMessage = serde_json::from_str(&json).unwrap();

        let pong = WsMessage::Pong { server_time: 12345 };
        let json = serde_json::to_string(&pong).unwrap();
        let _back: WsMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn ws_message_history_roundtrip() {
        let ws = WsMessage::History {
            messages: vec![ChatMessage::system("welcome")],
        };
        let json = serde_json::to_string(&ws).unwrap();
        assert!(json.contains("\"type\":\"history\""));
        let _back: WsMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn ws_message_error_roundtrip() {
        let ws = WsMessage::Error {
            message: "bad request".to_string(),
        };
        let json = serde_json::to_string(&ws).unwrap();
        let _back: WsMessage = serde_json::from_str(&json).unwrap();
    }

    // -- Validation --

    #[test]
    fn validate_display_name_valid() {
        assert!(validate_display_name("Alice").is_ok());
        assert!(validate_display_name("Bob Smith").is_ok());
    }

    #[test]
    fn validate_display_name_empty() {
        let err = validate_display_name("").unwrap_err();
        assert!(matches!(err, WebChatError::InvalidDisplayName { .. }));
    }

    #[test]
    fn validate_display_name_too_long() {
        let long = "a".repeat(MAX_DISPLAY_NAME_LEN + 1);
        let err = validate_display_name(&long).unwrap_err();
        assert!(matches!(err, WebChatError::InvalidDisplayName { .. }));
    }

    #[test]
    fn validate_display_name_control_chars() {
        let err = validate_display_name("alice\x00").unwrap_err();
        assert!(matches!(err, WebChatError::InvalidDisplayName { .. }));
    }

    #[test]
    fn validate_message_text_valid() {
        assert!(validate_message_text("hello world").is_ok());
    }

    #[test]
    fn validate_message_text_empty() {
        let err = validate_message_text("").unwrap_err();
        assert!(matches!(err, WebChatError::InvalidMessage { .. }));
    }

    #[test]
    fn validate_message_text_too_long() {
        let long = "a".repeat(MAX_MESSAGE_LEN + 1);
        let err = validate_message_text(&long).unwrap_err();
        assert!(matches!(err, WebChatError::InvalidMessage { .. }));
    }

    // -- WebChatSession --

    #[test]
    fn session_basics() {
        let session = WebChatSession::new("Alice".to_string(), Some("127.0.0.1".to_string()));
        assert_eq!(session.display_name(), "Alice");
        assert_eq!(session.remote_addr(), Some("127.0.0.1"));
        assert!(!session.is_typing());
        assert!(!session.is_idle());
        assert!(!session.session_id().is_empty());
    }

    #[test]
    fn session_typing_toggle() {
        let mut session = WebChatSession::new("Alice".to_string(), None);
        session.set_typing(true);
        assert!(session.is_typing());
        session.set_typing(false);
        assert!(!session.is_typing());
    }

    #[test]
    fn session_touch_updates_activity() {
        let mut session = WebChatSession::new("Alice".to_string(), None);
        let before = session.last_activity();
        // Tiny sleep to ensure time advances
        std::thread::sleep(Duration::from_millis(1));
        session.touch();
        assert!(session.last_activity() >= before);
    }

    // -- MessageHistory --

    #[test]
    fn history_push_and_recent() {
        let mut history = MessageHistory::new();
        assert!(history.is_empty());
        assert_eq!(history.len(), 0);

        history.push(ChatMessage::user("A", "msg1"));
        history.push(ChatMessage::user("B", "msg2"));
        history.push(ChatMessage::user("C", "msg3"));

        assert_eq!(history.len(), 3);
        assert_eq!(history.all().len(), 3);

        let recent = history.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].text, "msg2");
        assert_eq!(recent[1].text, "msg3");
    }

    #[test]
    fn history_overflow_drops_oldest() {
        let mut history = MessageHistory::with_capacity(3);
        history.push(ChatMessage::user("A", "msg1"));
        history.push(ChatMessage::user("B", "msg2"));
        history.push(ChatMessage::user("C", "msg3"));
        history.push(ChatMessage::user("D", "msg4"));

        assert_eq!(history.len(), 3);
        assert_eq!(history.all()[0].text, "msg2");
    }

    #[test]
    fn history_clear() {
        let mut history = MessageHistory::new();
        history.push(ChatMessage::system("test"));
        history.clear();
        assert!(history.is_empty());
    }

    #[test]
    fn history_recent_more_than_available() {
        let mut history = MessageHistory::new();
        history.push(ChatMessage::user("A", "msg1"));
        let recent = history.recent(100);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn history_default() {
        let history = MessageHistory::default();
        assert!(history.is_empty());
    }

    #[test]
    fn history_min_capacity() {
        let history = MessageHistory::with_capacity(0);
        // Should be clamped to at least 1
        assert_eq!(history.capacity, 1);
    }

    // -- WebChatRegistry --

    #[test]
    fn registry_connect_disconnect() {
        let mut reg = WebChatRegistry::new();
        assert_eq!(reg.session_count(), 0);

        let sid = reg.connect("Alice", Some("127.0.0.1".to_string())).unwrap();
        assert_eq!(reg.session_count(), 1);
        assert!(reg.get_session(&sid).is_some());

        let session = reg.disconnect(&sid).unwrap();
        assert_eq!(session.display_name(), "Alice");
        assert_eq!(reg.session_count(), 0);
    }

    #[test]
    fn registry_connect_invalid_name() {
        let mut reg = WebChatRegistry::new();
        let err = reg.connect("", None).unwrap_err();
        assert!(matches!(err, WebChatError::InvalidDisplayName { .. }));
    }

    #[test]
    fn registry_disconnect_nonexistent() {
        let mut reg = WebChatRegistry::new();
        let err = reg.disconnect("ghost").unwrap_err();
        assert!(matches!(err, WebChatError::SessionNotFound { .. }));
    }

    #[test]
    fn registry_handle_message() {
        let mut reg = WebChatRegistry::new();
        let sid = reg.connect("Alice", None).unwrap();

        let msg = reg.handle_message(&sid, "hello").unwrap();
        assert_eq!(msg.text, "hello");
        assert_eq!(msg.sender, "Alice");
        assert_eq!(msg.role, MessageRole::User);

        // Should be in history
        assert_eq!(reg.history().len(), 1);
    }

    #[test]
    fn registry_handle_message_invalid_text() {
        let mut reg = WebChatRegistry::new();
        let sid = reg.connect("Alice", None).unwrap();

        let err = reg.handle_message(&sid, "").unwrap_err();
        assert!(matches!(err, WebChatError::InvalidMessage { .. }));
    }

    #[test]
    fn registry_handle_message_unknown_session() {
        let mut reg = WebChatRegistry::new();
        let err = reg.handle_message("ghost", "hello").unwrap_err();
        assert!(matches!(err, WebChatError::SessionNotFound { .. }));
    }

    #[test]
    fn registry_record_agent_message() {
        let mut reg = WebChatRegistry::new();
        let msg = reg.record_agent_message("claude-1", "analysis complete");
        assert_eq!(msg.role, MessageRole::Agent);
        assert_eq!(msg.sender, "claude-1");
        assert_eq!(reg.history().len(), 1);
    }

    #[test]
    fn registry_record_system_message() {
        let mut reg = WebChatRegistry::new();
        let msg = reg.record_system_message("user joined");
        assert_eq!(msg.role, MessageRole::System);
        assert_eq!(reg.history().len(), 1);
    }

    #[test]
    fn registry_recent_history() {
        let mut reg = WebChatRegistry::new();
        reg.record_system_message("m1");
        reg.record_system_message("m2");
        reg.record_system_message("m3");

        let recent = reg.recent_history(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].text, "m2");
    }

    #[test]
    fn registry_session_ids() {
        let mut reg = WebChatRegistry::new();
        let s1 = reg.connect("Alice", None).unwrap();
        let s2 = reg.connect("Bob", None).unwrap();

        let mut ids = reg.session_ids();
        ids.sort();
        let mut expected = vec![s1.as_str(), s2.as_str()];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn registry_get_session_mut() {
        let mut reg = WebChatRegistry::new();
        let sid = reg.connect("Alice", None).unwrap();
        let session = reg.get_session_mut(&sid).unwrap();
        session.set_typing(true);
        assert!(reg.get_session(&sid).unwrap().is_typing());
    }

    #[test]
    fn registry_default() {
        let reg = WebChatRegistry::default();
        assert_eq!(reg.session_count(), 0);
    }

    #[test]
    fn registry_with_history_capacity() {
        let mut reg = WebChatRegistry::with_history_capacity(2);
        reg.record_system_message("m1");
        reg.record_system_message("m2");
        reg.record_system_message("m3");
        assert_eq!(reg.history().len(), 2);
    }

    // -- Error Display --

    #[test]
    fn error_display() {
        assert_eq!(
            WebChatError::TooManySessions { limit: 10 }.to_string(),
            "webchat session limit of 10 exceeded"
        );
        assert_eq!(
            WebChatError::SessionNotFound {
                session_id: "abc".to_string()
            }
            .to_string(),
            "webchat session \"abc\" not found"
        );
        assert_eq!(
            WebChatError::InvalidMessage {
                reason: "empty".to_string()
            }
            .to_string(),
            "invalid webchat message: empty"
        );
        assert_eq!(
            WebChatError::InvalidDisplayName {
                reason: "too long".to_string()
            }
            .to_string(),
            "invalid display name: too long"
        );
    }

    // -- MessageRole serde --

    #[test]
    fn message_role_serde() {
        let json = serde_json::to_string(&MessageRole::User).unwrap();
        assert_eq!(json, "\"user\"");
        let json = serde_json::to_string(&MessageRole::Agent).unwrap();
        assert_eq!(json, "\"agent\"");
        let json = serde_json::to_string(&MessageRole::System).unwrap();
        assert_eq!(json, "\"system\"");
    }
}
