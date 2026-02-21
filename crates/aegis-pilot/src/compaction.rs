//! Context window management via message compaction.
//!
//! Provides strategies for reducing context size when approaching
//! model token limits. Uses character-based estimation (~4 chars per token)
//! to avoid tokenizer dependencies.

/// Strategy for compacting a message history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactionStrategy {
    /// Drop oldest messages (after the first/system message) to fit within max_tokens.
    Truncate { max_tokens: usize },
    /// Keep the first `head` and last `tail` messages, dropping the middle.
    HeadTail { head: usize, tail: usize },
}

/// A simple message in a conversation history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Role of the message sender (e.g., "system", "user", "assistant").
    pub role: String,
    /// Content of the message.
    pub content: String,
}

/// Estimate token count from text using a ~4 chars/token heuristic.
pub fn estimate_tokens(text: &str) -> usize {
    // Ceiling division to avoid underestimating
    text.len().div_ceil(4)
}

/// Calculate the total estimated token count for a slice of messages.
pub fn total_tokens(messages: &[Message]) -> usize {
    messages
        .iter()
        .map(|m| estimate_tokens(&m.role) + estimate_tokens(&m.content))
        .sum()
}

/// Compact messages according to the given strategy.
///
/// Returns a new vector of messages that fits within the strategy's constraints.
pub fn compact(messages: &[Message], strategy: &CompactionStrategy) -> Vec<Message> {
    if messages.is_empty() {
        return Vec::new();
    }

    match strategy {
        CompactionStrategy::Truncate { max_tokens } => compact_truncate(messages, *max_tokens),
        CompactionStrategy::HeadTail { head, tail } => compact_head_tail(messages, *head, *tail),
    }
}

/// Truncate strategy: remove messages from index 1 onwards (preserving the
/// first message as system prompt) until the total token count fits.
fn compact_truncate(messages: &[Message], max_tokens: usize) -> Vec<Message> {
    let current_total = total_tokens(messages);
    if current_total <= max_tokens {
        return messages.to_vec();
    }

    // Always keep the first message (system prompt)
    if messages.len() <= 1 {
        return messages.to_vec();
    }

    // Start by including all messages, then remove from index 1 forward
    // until we fit within the budget.
    let first = &messages[0];
    let rest = &messages[1..];

    // Work backwards from the end of rest to find how many trailing
    // messages we can keep while staying under the token limit.
    let first_tokens = estimate_tokens(&first.role) + estimate_tokens(&first.content);
    let remaining_budget = max_tokens.saturating_sub(first_tokens);

    let mut kept = Vec::new();
    let mut accumulated = 0usize;

    // Keep messages from the end, as recent context is more valuable.
    for msg in rest.iter().rev() {
        let msg_tokens = estimate_tokens(&msg.role) + estimate_tokens(&msg.content);
        if accumulated + msg_tokens > remaining_budget {
            break;
        }
        accumulated += msg_tokens;
        kept.push(msg.clone());
    }

    kept.reverse();

    let mut result = vec![first.clone()];
    result.extend(kept);
    result
}

/// HeadTail strategy: keep the first `head` and last `tail` messages,
/// dropping everything in between.
fn compact_head_tail(messages: &[Message], head: usize, tail: usize) -> Vec<Message> {
    let len = messages.len();

    if head + tail >= len {
        // No messages to drop, return everything.
        return messages.to_vec();
    }

    let mut result = Vec::with_capacity(head + tail);
    result.extend_from_slice(&messages[..head]);
    result.extend_from_slice(&messages[len - tail..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(role: &str, content: &str) -> Message {
        Message {
            role: role.into(),
            content: content.into(),
        }
    }

    #[test]
    fn estimate_tokens_basic() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("a"), 1);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
        assert_eq!(estimate_tokens("abcdefgh"), 2);
        assert_eq!(estimate_tokens("abcdefghi"), 3);
    }

    #[test]
    fn total_tokens_sums_all_messages() {
        let msgs = vec![
            msg("system", "You are a helpful assistant."),
            msg("user", "Hello!"),
        ];
        let total = total_tokens(&msgs);
        // "system" = 6 chars -> div_ceil(4) = 2
        // "You are a helpful assistant." = 28 chars -> div_ceil(4) = 7 => msg1 = 9
        // "user" = 4 chars -> div_ceil(4) = 1
        // "Hello!" = 6 chars -> div_ceil(4) = 2 => msg2 = 3
        // total = 12
        assert_eq!(total, 12);
    }

    #[test]
    fn truncate_keeps_system_message() {
        let msgs = vec![
            msg("system", "System prompt that must be preserved"),
            msg("user", "Old message 1"),
            msg("assistant", "Old response 1"),
            msg("user", "Recent question"),
        ];

        let strategy = CompactionStrategy::Truncate { max_tokens: 20 };
        let result = compact(&msgs, &strategy);

        assert!(!result.is_empty());
        assert_eq!(result[0].role, "system");
        assert_eq!(result[0].content, "System prompt that must be preserved");
    }

    #[test]
    fn truncate_no_change_when_within_limit() {
        let msgs = vec![msg("system", "hi"), msg("user", "hey")];
        let strategy = CompactionStrategy::Truncate { max_tokens: 1000 };
        let result = compact(&msgs, &strategy);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn truncate_drops_old_keeps_recent() {
        let msgs = vec![
            msg("system", "sys"),
            msg("user", "msg1"),
            msg("assistant", "resp1"),
            msg("user", "msg2"),
            msg("assistant", "resp2"),
        ];

        // Set a tight limit that can fit system + last message or two
        let strategy = CompactionStrategy::Truncate { max_tokens: 8 };
        let result = compact(&msgs, &strategy);

        // First must be system
        assert_eq!(result[0].role, "system");
        // Should have dropped some old messages
        assert!(result.len() < msgs.len());
        // Last message in result should be the most recent
        assert_eq!(result.last().unwrap().content, "resp2");
    }

    #[test]
    fn head_tail_preserves_boundaries() {
        let msgs = vec![
            msg("system", "sys"),
            msg("user", "msg1"),
            msg("assistant", "resp1"),
            msg("user", "msg2"),
            msg("assistant", "resp2"),
            msg("user", "msg3"),
        ];

        let strategy = CompactionStrategy::HeadTail { head: 2, tail: 2 };
        let result = compact(&msgs, &strategy);

        assert_eq!(result.len(), 4);
        assert_eq!(result[0].content, "sys");
        assert_eq!(result[1].content, "msg1");
        assert_eq!(result[2].content, "resp2");
        assert_eq!(result[3].content, "msg3");
    }

    #[test]
    fn head_tail_no_drop_when_small() {
        let msgs = vec![msg("system", "sys"), msg("user", "msg1")];
        let strategy = CompactionStrategy::HeadTail { head: 2, tail: 2 };
        let result = compact(&msgs, &strategy);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn empty_messages() {
        let result = compact(&[], &CompactionStrategy::Truncate { max_tokens: 100 });
        assert!(result.is_empty());

        let result = compact(
            &[],
            &CompactionStrategy::HeadTail { head: 1, tail: 1 },
        );
        assert!(result.is_empty());
    }

    #[test]
    fn single_message_preserved() {
        let msgs = vec![msg("system", "Only message")];

        let result = compact(&msgs, &CompactionStrategy::Truncate { max_tokens: 1 });
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].content, "Only message");

        let result = compact(
            &msgs,
            &CompactionStrategy::HeadTail { head: 1, tail: 1 },
        );
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn total_tokens_empty() {
        assert_eq!(total_tokens(&[]), 0);
    }
}
