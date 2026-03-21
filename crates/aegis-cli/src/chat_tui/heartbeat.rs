//! Autonomous heartbeat thinking: periodic background LLM turns driven by
//! HEARTBEAT.md content.

use std::time::Instant;

use aegis_types::llm::{LlmMessage, LlmRole};

use super::message::{ChatMessage, MessageRole};

/// Maximum characters in an LLM response to still count as a no-op heartbeat ack.
pub const HEARTBEAT_ACK_MAX_CHARS: usize = 300;

/// Check if HEARTBEAT.md content has actionable items (not just template boilerplate).
pub fn is_heartbeat_content_actionable(content: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip empty, pure whitespace, markdown headers, horizontal rules, fenced code markers.
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("---")
            || trimmed.starts_with("```")
        {
            continue;
        }
        // Skip markdown emphasis-only lines (e.g. _Things to check..._)
        if trimmed.starts_with('_') && trimmed.ends_with('_') {
            continue;
        }
        // Skip known template boilerplate.
        let lower = trimmed.to_lowercase();
        if lower.contains("what goes here")
            || lower.contains("update this file")
            || lower.contains("keep this file empty")
            || lower.contains("persists across sessions")
            || lower.starts_with("if nothing needs attention")
            || lower.contains("heartbeat_ok")
        {
            continue;
        }
        // Skip lines that are only list items with generic descriptions (no checkboxes).
        if lower.starts_with("- ") && !lower.contains("- [ ]") && !lower.contains("- [x]") {
            // Heuristic: if the line looks like a template description, skip it.
            if lower.contains("recurring checks")
                || lower.contains("monitoring")
                || lower.contains("build status")
                || lower.contains("files or configs")
                || lower.contains("reminders about")
                || lower.contains("time-sensitive")
            {
                continue;
            }
        }
        // Found a non-boilerplate, non-empty line -- there's actionable content.
        return true;
    }
    false
}

/// Check if the most recent assistant response is a no-op heartbeat ack.
///
/// Returns false if tools were used during this heartbeat turn (even if
/// the final response says HEARTBEAT_OK), because tool use means real
/// work happened and the conversation entries shouldn't be pruned.
pub fn is_heartbeat_response_empty(
    messages: &[ChatMessage],
    _conversation: &[LlmMessage],
) -> bool {
    // Check if any tool calls happened since the heartbeat prompt.
    let heartbeat_idx = messages
        .iter()
        .rposition(|m| m.role == MessageRole::Heartbeat);
    if let Some(idx) = heartbeat_idx {
        let has_tool_calls = messages[idx..]
            .iter()
            .any(|m| matches!(m.role, MessageRole::ToolCall { .. }));
        if has_tool_calls {
            return false; // Tools ran -- not a simple no-op.
        }
    }

    let last_assistant = messages
        .iter()
        .rev()
        .find(|m| m.role == MessageRole::Assistant);
    match last_assistant {
        Some(msg) => {
            let text = msg.content.trim();
            if text.is_empty() {
                return true;
            }
            // Strip the HEARTBEAT_OK token and check remainder.
            let stripped = text
                .replace("HEARTBEAT_OK", "")
                .replace("heartbeat_ok", "")
                .replace("Heartbeat_OK", "")
                .trim()
                .to_string();
            stripped.len() < HEARTBEAT_ACK_MAX_CHARS
        }
        None => true,
    }
}

/// Remove the last heartbeat prompt + response from display messages and
/// LLM conversation history.
pub fn prune_last_heartbeat_exchange(
    messages: &mut Vec<ChatMessage>,
    conversation: &mut Vec<LlmMessage>,
) {
    // Prune display messages: remove trailing Heartbeat + Assistant pair.
    while let Some(msg) = messages.last() {
        if msg.role == MessageRole::Assistant || msg.role == MessageRole::Heartbeat {
            messages.pop();
        } else {
            break;
        }
    }

    // Prune LLM conversation: remove trailing user (heartbeat prompt) + assistant pair.
    while let Some(msg) = conversation.last() {
        if msg.role == LlmRole::Assistant {
            conversation.pop();
        } else if msg.role == LlmRole::User {
            // Check if this is a heartbeat prompt.
            if msg.content.starts_with("[HEARTBEAT") {
                conversation.pop();
            }
            break;
        } else {
            break;
        }
    }
}

/// Build the heartbeat prompt string.
pub fn build_heartbeat_prompt(
    heartbeat_content: &str,
    last_user_interaction: Instant,
    heartbeat_consecutive_ok: u32,
) -> String {
    let now = chrono::Local::now();
    let idle_secs = last_user_interaction.elapsed().as_secs();
    let idle_display = if idle_secs < 60 {
        format!("{idle_secs}s")
    } else if idle_secs < 3600 {
        format!("{}m {}s", idle_secs / 60, idle_secs % 60)
    } else {
        format!("{}h {}m", idle_secs / 3600, (idle_secs % 3600) / 60)
    };

    format!(
        "[HEARTBEAT -- autonomous check @ {}]\n\
         Time since last user message: {}\n\
         Consecutive idle heartbeats: {}\n\n\
         ---\n\n\
         {}",
        now.format("%Y-%m-%d %H:%M %Z"),
        idle_display,
        heartbeat_consecutive_ok,
        heartbeat_content.trim(),
    )
}
