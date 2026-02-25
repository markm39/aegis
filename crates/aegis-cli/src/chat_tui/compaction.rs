//! Context window management for the chat TUI.
//!
//! Bridges the generic compaction module in `aegis-pilot` with the chat
//! TUI's `LlmMessage` conversations. Estimates total token usage and
//! applies truncation when the conversation approaches the model's
//! context window limit.

use aegis_pilot::compaction::{self, CompactionStrategy, Message as CompactionMessage};
use aegis_types::llm::{LlmMessage, LlmRole};
use aegis_types::providers::ALL_PROVIDERS;

/// Fraction of the context window at which to trigger compaction.
const COMPACTION_THRESHOLD: f64 = 0.80;

/// Default context window for unknown models (conservative).
const DEFAULT_CONTEXT_WINDOW: usize = 128_000;

/// Look up the context window for a model by scanning the provider registry.
pub fn context_window_for_model(model: &str) -> usize {
    for provider in ALL_PROVIDERS {
        for m in provider.models {
            if m.id == model {
                let window = m.context_window as usize;
                return if window > 0 {
                    window
                } else {
                    DEFAULT_CONTEXT_WINDOW
                };
            }
        }
    }
    DEFAULT_CONTEXT_WINDOW
}

/// Estimate the total token count for a conversation.
pub fn estimate_conversation_tokens(messages: &[LlmMessage]) -> usize {
    messages
        .iter()
        .map(|m| {
            let role_tokens = compaction::estimate_tokens(&m.role.to_string());
            let content_tokens = compaction::estimate_tokens(&m.content);
            let tool_tokens: usize = m
                .tool_calls
                .iter()
                .map(|tc| {
                    compaction::estimate_tokens(&tc.name)
                        + compaction::estimate_tokens(
                            &serde_json::to_string(&tc.input).unwrap_or_default(),
                        )
                })
                .sum();
            role_tokens + content_tokens + tool_tokens
        })
        .sum()
}

/// Check whether the conversation should be compacted based on the model's
/// context window. Returns the estimated token count and the threshold.
pub fn should_compact(messages: &[LlmMessage], model: &str) -> (usize, usize) {
    let estimated = estimate_conversation_tokens(messages);
    let window = context_window_for_model(model);
    let threshold = (window as f64 * COMPACTION_THRESHOLD) as usize;
    (estimated, threshold)
}

/// Compact a conversation to fit within the model's context window.
///
/// Preserves the first message (typically system context injected by the
/// LLM on the first turn) and keeps the most recent messages that fit
/// within 80% of the context window.
///
/// Returns `None` if no compaction was needed.
pub fn compact_conversation(messages: &[LlmMessage], model: &str) -> Option<Vec<LlmMessage>> {
    let (estimated, threshold) = should_compact(messages, model);

    if estimated <= threshold {
        return None;
    }

    // Convert LlmMessages to compaction Messages.
    let compact_msgs: Vec<CompactionMessage> = messages
        .iter()
        .map(|m| CompactionMessage {
            role: m.role.to_string(),
            content: m.content.clone(),
        })
        .collect();

    let strategy = CompactionStrategy::Truncate {
        max_tokens: threshold,
    };
    let compacted = compaction::compact(&compact_msgs, &strategy);

    // Rebuild LlmMessages from compacted results.
    // We match by index to preserve tool_calls and tool_use_id.
    let mut result = Vec::with_capacity(compacted.len());

    // Always keep the first message from original (index 0).
    if let Some(first) = messages.first() {
        result.push(first.clone());
    }

    // The compaction result keeps messages from the tail. Find the
    // original messages that match the compacted tail.
    if compacted.len() > 1 {
        // The compacted tail corresponds to the last N-1 messages of the
        // original (where N = compacted.len()). The compaction module
        // keeps the first message + trailing messages that fit.
        let tail_count = compacted.len() - 1;
        let mut start_idx = messages.len().saturating_sub(tail_count);

        // Ensure we don't start on a Tool (tool_result) message, which
        // would orphan it from its preceding assistant+tool_use message.
        // Walk backward until we find a non-Tool message.
        while start_idx > 1
            && messages
                .get(start_idx)
                .map(|m| m.role == LlmRole::Tool)
                .unwrap_or(false)
        {
            start_idx -= 1;
        }

        for msg in &messages[start_idx..] {
            result.push(msg.clone());
        }
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::llm::LlmRole;

    #[test]
    fn context_window_known_model() {
        let window = context_window_for_model("claude-sonnet-4-20250514");
        assert!(
            window > 100_000,
            "expected large context window, got {window}"
        );
    }

    #[test]
    fn context_window_unknown_model() {
        let window = context_window_for_model("totally-unknown-model");
        assert_eq!(window, DEFAULT_CONTEXT_WINDOW);
    }

    #[test]
    fn estimate_tokens_empty() {
        assert_eq!(estimate_conversation_tokens(&[]), 0);
    }

    #[test]
    fn estimate_tokens_basic() {
        let msgs = vec![
            LlmMessage::user("Hello, how are you?"),
            LlmMessage::assistant("I'm doing well, thank you!"),
        ];
        let tokens = estimate_conversation_tokens(&msgs);
        assert!(tokens > 0);
    }

    #[test]
    fn should_compact_small_conversation() {
        let msgs = vec![LlmMessage::user("Hello"), LlmMessage::assistant("Hi there")];
        let (estimated, threshold) = should_compact(&msgs, "claude-sonnet-4-20250514");
        assert!(
            estimated < threshold,
            "small conversation should not trigger compaction"
        );
    }

    #[test]
    fn compact_returns_none_when_small() {
        let msgs = vec![LlmMessage::user("Hello"), LlmMessage::assistant("Hi there")];
        assert!(compact_conversation(&msgs, "claude-sonnet-4-20250514").is_none());
    }

    #[test]
    fn compact_truncates_large_conversation() {
        // Build a conversation large enough to exceed 80% of a small
        // "context window" by using an unknown model with 128K default.
        // Each message is ~1000 chars = ~250 tokens.
        let big_content = "x".repeat(1000);
        let mut msgs = vec![LlmMessage::user("system context")];
        for _ in 0..600 {
            msgs.push(LlmMessage::user(big_content.clone()));
            msgs.push(LlmMessage::assistant(big_content.clone()));
        }

        let result = compact_conversation(&msgs, "totally-unknown-model");
        assert!(result.is_some(), "large conversation should be compacted");

        let compacted = result.unwrap();
        assert!(
            compacted.len() < msgs.len(),
            "compacted should have fewer messages"
        );
        // First message preserved
        assert_eq!(compacted[0].role, LlmRole::User);
        assert_eq!(compacted[0].content, "system context");
    }
}
