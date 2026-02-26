//! Chat message data model.
//!
//! Defines the typed message structures used for rendering in the chat TUI.
//! Messages are created directly from user input and LLM responses rather
//! than parsed from daemon NDJSON output.

use std::time::Instant;

/// Role/sender of a chat message.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum MessageRole {
    /// User sent a message.
    User,
    /// Assistant (LLM) text response.
    Assistant,
    /// A tool call initiated by the assistant.
    ToolCall { tool_name: String, summary: String },
    /// System message (errors, status, etc.).
    System,
    /// Permission prompt requiring human decision.
    Permission {
        prompt: String,
        resolved: Option<bool>, // None=pending, Some(true)=approved, Some(false)=denied
        /// Diff/content preview lines shown before [Y]/[N].
        /// Line prefix determines color: `+` green, `-` red, `@` cyan, else dim.
        diff_preview: Vec<String>,
    },
    /// Session result (completion summary).
    Result { summary: String },
    /// A heartbeat-triggered autonomous check (displayed dimly in UI).
    Heartbeat,
}

/// A single message in the chat transcript.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ChatMessage {
    /// The role/type of this message.
    pub role: MessageRole,
    /// The display content of the message.
    pub content: String,
    /// When this message was created.
    pub timestamp: Instant,
    /// Whether this tool call section is expanded in the UI.
    pub expanded: bool,
}

impl ChatMessage {
    /// Create a new chat message with the given role and content.
    pub fn new(role: MessageRole, content: String) -> Self {
        Self {
            role,
            content,
            timestamp: Instant::now(),
            expanded: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_message_new() {
        let msg = ChatMessage::new(MessageRole::User, "hello".to_string());
        assert_eq!(msg.role, MessageRole::User);
        assert_eq!(msg.content, "hello");
        assert!(!msg.expanded);
    }

    #[test]
    fn chat_message_assistant() {
        let msg = ChatMessage::new(MessageRole::Assistant, "I can help.".to_string());
        assert_eq!(msg.role, MessageRole::Assistant);
        assert_eq!(msg.content, "I can help.");
    }

    #[test]
    fn chat_message_system() {
        let msg = ChatMessage::new(MessageRole::System, "Error: timeout".to_string());
        assert_eq!(msg.role, MessageRole::System);
        assert_eq!(msg.content, "Error: timeout");
    }

    #[test]
    fn expanded_default_false() {
        let msg = ChatMessage::new(MessageRole::Assistant, "test".to_string());
        assert!(!msg.expanded);
    }
}
