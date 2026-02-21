//! Chat message data model and output line parsing.
//!
//! The daemon formats NDJSON agent output into display lines via `ndjson_fmt.rs`.
//! These lines follow well-defined patterns (tool calls prefixed with `> `,
//! user messages prefixed with `You: `, permission tags like `[PENDING]`, etc.).
//! This module parses those display lines into typed [`ChatMessage`] values
//! suitable for rendering in the chat TUI.

use std::time::Instant;

/// Known tool names emitted by `ndjson_fmt::format_tool_use`.
///
/// The parser accepts any single-word tool name after `> `, but this list
/// can be used by the UI to distinguish known tools from custom ones.
#[allow(dead_code)]
pub const KNOWN_TOOLS: &[&str] = &[
    "Bash",
    "Read",
    "Write",
    "Edit",
    "Grep",
    "Glob",
    "Task",
    "WebSearch",
    "WebFetch",
    "LSP",
    "NotebookRead",
    "NotebookEdit",
    "TodoWrite",
    "TodoRead",
];

/// Role/sender of a chat message.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageRole {
    /// User sent a message to the agent.
    User,
    /// Assistant (agent) text response.
    Assistant,
    /// A tool call initiated by the assistant.
    ToolCall { tool_name: String, summary: String },
    /// System message (session start, compaction, nudge, attention, etc.).
    System,
    /// Permission prompt requiring human decision.
    Permission {
        prompt: String,
        resolved: Option<bool>, // None=pending, Some(true)=approved, Some(false)=denied
    },
    /// Session result (completion summary).
    Result { summary: String },
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

/// Extract (tool_name, summary) from a `"> Tool: summary"` formatted line.
///
/// Returns `None` if the line does not match the tool call pattern.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(tool_name_from_line("> Bash: ls -la"), Some(("Bash", "ls -la")));
/// assert_eq!(tool_name_from_line("> CustomTool"), Some(("CustomTool", "")));
/// assert_eq!(tool_name_from_line("plain text"), None);
/// ```
pub fn tool_name_from_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("> ")?;
    if rest.is_empty() {
        return None;
    }
    // Split on ": " to separate tool name from summary.
    if let Some((name, summary)) = rest.split_once(": ") {
        // Tool name must be a single word (no spaces).
        if !name.is_empty() && !name.contains(' ') {
            Some((name, summary))
        } else {
            None
        }
    } else {
        // No ": " separator -- tool name only, no summary.
        let name = rest.trim();
        if !name.is_empty() && !name.contains(' ') {
            Some((name, ""))
        } else {
            None
        }
    }
}

/// Classify a single output line into a [`MessageRole`].
fn classify_line(line: &str) -> MessageRole {
    // User input line (injected by daemon on send).
    if line.starts_with("You: ") {
        return MessageRole::User;
    }

    // Tool call: "> ToolName: summary" or "> ToolName".
    if let Some((tool_name, summary)) = tool_name_from_line(line) {
        return MessageRole::ToolCall {
            tool_name: tool_name.to_string(),
            summary: summary.to_string(),
        };
    }

    // Session start.
    if line.starts_with("Session started") {
        return MessageRole::System;
    }

    // Context compaction boundary.
    if line.starts_with("--- ") {
        return MessageRole::System;
    }

    // Result / done line.
    if line.starts_with("Done (") {
        return MessageRole::Result {
            summary: line.to_string(),
        };
    }

    // Error line.
    if line.starts_with("Error: ") {
        return MessageRole::System;
    }

    // Permission tags -- check contains since the tag can appear anywhere in the line.
    if line.contains("[APPROVED]") {
        return MessageRole::Permission {
            prompt: line.to_string(),
            resolved: Some(true),
        };
    }
    if line.contains("[DENIED]") {
        return MessageRole::Permission {
            prompt: line.to_string(),
            resolved: Some(false),
        };
    }
    if line.contains("[PENDING]") {
        return MessageRole::Permission {
            prompt: line.to_string(),
            resolved: None,
        };
    }

    // Nudge and attention are system-level notifications.
    if line.contains("[NUDGE") {
        return MessageRole::System;
    }
    if line.contains("[ATTENTION]") {
        return MessageRole::System;
    }

    // Everything else is assistant text.
    MessageRole::Assistant
}

/// Extract the content portion from a classified line.
///
/// For most roles this is the full line, but some roles strip a prefix.
fn extract_content(line: &str, role: &MessageRole) -> String {
    match role {
        MessageRole::User => line
            .strip_prefix("You: ")
            .unwrap_or(line)
            .to_string(),
        MessageRole::ToolCall { .. } => {
            // For tool calls, store the full `> Tool: summary` line as content
            // so the UI can render it however it likes.
            line.to_string()
        }
        _ => line.to_string(),
    }
}

/// Parse a sequence of daemon output lines into structured chat messages.
///
/// Consecutive assistant text lines are merged into a single [`ChatMessage`]
/// with newlines between them. All other message types produce one message
/// per line.
///
/// Empty lines are skipped entirely.
pub fn parse_output_lines(lines: &[String]) -> Vec<ChatMessage> {
    let mut messages: Vec<ChatMessage> = Vec::new();
    let mut assistant_buf: Vec<String> = Vec::new();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        let role = classify_line(line);

        if role == MessageRole::Assistant {
            assistant_buf.push(line.clone());
            continue;
        }

        // A non-assistant line breaks any assistant run -- flush it first.
        if !assistant_buf.is_empty() {
            let merged = assistant_buf.join("\n");
            messages.push(ChatMessage::new(MessageRole::Assistant, merged));
            assistant_buf.clear();
        }

        let content = extract_content(line, &role);
        messages.push(ChatMessage::new(role, content));
    }

    // Flush any trailing assistant lines.
    if !assistant_buf.is_empty() {
        let merged = assistant_buf.join("\n");
        messages.push(ChatMessage::new(MessageRole::Assistant, merged));
    }

    messages
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to convert &str slices into Vec<String>.
    fn lines(s: &[&str]) -> Vec<String> {
        s.iter().map(|l| l.to_string()).collect()
    }

    #[test]
    fn test_parse_user_message() {
        let msgs = parse_output_lines(&lines(&["You: hello"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, MessageRole::User);
        assert_eq!(msgs[0].content, "hello");
    }

    #[test]
    fn test_parse_tool_call() {
        let msgs = parse_output_lines(&lines(&["> Bash: ls -la"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].role,
            MessageRole::ToolCall {
                tool_name: "Bash".to_string(),
                summary: "ls -la".to_string(),
            }
        );
        assert_eq!(msgs[0].content, "> Bash: ls -la");
    }

    #[test]
    fn test_parse_tool_call_no_summary() {
        let msgs = parse_output_lines(&lines(&["> CustomTool"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].role,
            MessageRole::ToolCall {
                tool_name: "CustomTool".to_string(),
                summary: "".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_system_session() {
        let msgs = parse_output_lines(&lines(&["Session started (model: claude)"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, MessageRole::System);
        assert_eq!(msgs[0].content, "Session started (model: claude)");
    }

    #[test]
    fn test_parse_system_compact() {
        let msgs = parse_output_lines(&lines(&["--- context compacted ---"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, MessageRole::System);
        assert_eq!(msgs[0].content, "--- context compacted ---");
    }

    #[test]
    fn test_parse_result() {
        let msgs = parse_output_lines(&lines(&["Done (45s, $0.15, 5000in/1200out)"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].role,
            MessageRole::Result {
                summary: "Done (45s, $0.15, 5000in/1200out)".to_string(),
            }
        );
        assert_eq!(msgs[0].content, "Done (45s, $0.15, 5000in/1200out)");
    }

    #[test]
    fn test_parse_error() {
        let msgs = parse_output_lines(&lines(&["Error: something broke"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, MessageRole::System);
        assert_eq!(msgs[0].content, "Error: something broke");
    }

    #[test]
    fn test_parse_permission_approved() {
        let msgs = parse_output_lines(&lines(&["[APPROVED] FileRead /src"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].role,
            MessageRole::Permission {
                prompt: "[APPROVED] FileRead /src".to_string(),
                resolved: Some(true),
            }
        );
    }

    #[test]
    fn test_parse_permission_denied() {
        let msgs = parse_output_lines(&lines(&["[DENIED] Bash rm -rf"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].role,
            MessageRole::Permission {
                prompt: "[DENIED] Bash rm -rf".to_string(),
                resolved: Some(false),
            }
        );
    }

    #[test]
    fn test_parse_permission_pending() {
        let msgs = parse_output_lines(&lines(&["[PENDING] Allow write?"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].role,
            MessageRole::Permission {
                prompt: "[PENDING] Allow write?".to_string(),
                resolved: None,
            }
        );
    }

    #[test]
    fn test_parse_assistant_text() {
        let msgs = parse_output_lines(&lines(&["Hello, I can help with that."]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, MessageRole::Assistant);
        assert_eq!(msgs[0].content, "Hello, I can help with that.");
    }

    #[test]
    fn test_group_consecutive_assistant() {
        let msgs = parse_output_lines(&lines(&[
            "First line of response.",
            "Second line of response.",
            "Third line of response.",
        ]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, MessageRole::Assistant);
        assert_eq!(
            msgs[0].content,
            "First line of response.\nSecond line of response.\nThird line of response."
        );
    }

    #[test]
    fn test_tool_breaks_assistant_group() {
        let msgs = parse_output_lines(&lines(&[
            "Let me check that.",
            "One moment.",
            "> Read: .../src/main.rs",
            "Found the issue.",
        ]));
        assert_eq!(msgs.len(), 3);
        // First: merged assistant text.
        assert_eq!(msgs[0].role, MessageRole::Assistant);
        assert_eq!(msgs[0].content, "Let me check that.\nOne moment.");
        // Second: tool call.
        assert_eq!(
            msgs[1].role,
            MessageRole::ToolCall {
                tool_name: "Read".to_string(),
                summary: ".../src/main.rs".to_string(),
            }
        );
        // Third: new assistant text after the tool call.
        assert_eq!(msgs[2].role, MessageRole::Assistant);
        assert_eq!(msgs[2].content, "Found the issue.");
    }

    #[test]
    fn test_empty_lines_skipped() {
        let msgs = parse_output_lines(&lines(&["", "", ""]));
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_mixed_sequence() {
        let msgs = parse_output_lines(&lines(&[
            "You: hi",
            "Let me check.",
            "> Read: .../src/main.rs",
            "Found it.",
            "Done (1s, $0.01, 100in/50out)",
        ]));
        assert_eq!(msgs.len(), 5);
        assert_eq!(msgs[0].role, MessageRole::User);
        assert_eq!(msgs[0].content, "hi");
        assert_eq!(msgs[1].role, MessageRole::Assistant);
        assert_eq!(msgs[1].content, "Let me check.");
        assert_eq!(
            msgs[2].role,
            MessageRole::ToolCall {
                tool_name: "Read".to_string(),
                summary: ".../src/main.rs".to_string(),
            }
        );
        assert_eq!(msgs[3].role, MessageRole::Assistant);
        assert_eq!(msgs[3].content, "Found it.");
        assert_eq!(
            msgs[4].role,
            MessageRole::Result {
                summary: "Done (1s, $0.01, 100in/50out)".to_string(),
            }
        );
    }

    #[test]
    fn test_tool_name_extraction() {
        // Standard tool with summary.
        assert_eq!(
            tool_name_from_line("> Bash: ls -la"),
            Some(("Bash", "ls -la"))
        );

        // Tool without summary.
        assert_eq!(
            tool_name_from_line("> CustomTool"),
            Some(("CustomTool", ""))
        );

        // Known tools.
        assert_eq!(
            tool_name_from_line("> Read: .../src/main.rs"),
            Some(("Read", ".../src/main.rs"))
        );
        assert_eq!(
            tool_name_from_line("> Grep: /pattern/ in .../src"),
            Some(("Grep", "/pattern/ in .../src"))
        );
        assert_eq!(
            tool_name_from_line("> WebSearch: rust async tutorial"),
            Some(("WebSearch", "rust async tutorial"))
        );

        // Not a tool line.
        assert_eq!(tool_name_from_line("plain text"), None);
        assert_eq!(tool_name_from_line(""), None);

        // Just "> " with nothing after it.
        assert_eq!(tool_name_from_line("> "), None);
    }

    #[test]
    fn test_nudge_is_system() {
        let msgs = parse_output_lines(&lines(&["[NUDGE #3] sent stall nudge to agent"]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, MessageRole::System);
    }

    #[test]
    fn test_attention_is_system() {
        let msgs = parse_output_lines(&lines(&[
            "[ATTENTION] max nudges (5) exceeded, agent needs help",
        ]));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, MessageRole::System);
    }

    #[test]
    fn test_expanded_default_false() {
        let msg = ChatMessage::new(MessageRole::Assistant, "test".to_string());
        assert!(!msg.expanded);
    }

    #[test]
    fn test_empty_mixed_with_content() {
        let msgs = parse_output_lines(&lines(&[
            "",
            "Hello there.",
            "",
            "> Bash: echo hi",
            "",
        ]));
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, MessageRole::Assistant);
        assert_eq!(msgs[0].content, "Hello there.");
        assert_eq!(
            msgs[1].role,
            MessageRole::ToolCall {
                tool_name: "Bash".to_string(),
                summary: "echo hi".to_string(),
            }
        );
    }
}
