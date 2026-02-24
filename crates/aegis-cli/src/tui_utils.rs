//! Shared utility functions for TUI modules.
//!
//! Common text-editing and display helpers used across pilot_tui,
//! and onboard_tui. Extracted here to avoid duplication.

/// Find the byte position after deleting one word backward from `cursor`.
///
/// Skips trailing whitespace, then skips the word, returning the byte offset
/// of the start of the word. Used for Ctrl+W / Alt+Backspace handling.
pub fn delete_word_backward_pos(text: &str, cursor: usize) -> usize {
    text[..cursor]
        .char_indices()
        .rev()
        .skip_while(|(_, c)| c.is_whitespace())
        .skip_while(|(_, c)| !c.is_whitespace())
        .map(|(i, c)| i + c.len_utf8())
        .next()
        .unwrap_or(0)
}

/// Check whether a binary exists in `$PATH` using `which`.
pub fn binary_exists(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Truncate a string to `max_chars` characters, appending "..." if truncated.
///
/// Safe for multi-byte UTF-8 (truncates at char boundaries, not bytes).
pub fn truncate_str(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars {
        s.to_string()
    } else if max_chars <= 3 {
        s.chars().take(max_chars).collect()
    } else {
        let truncated: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_word_basic() {
        assert_eq!(delete_word_backward_pos("hello world", 11), 6);
        assert_eq!(delete_word_backward_pos("hello world", 5), 0);
        assert_eq!(delete_word_backward_pos("hello", 5), 0);
        assert_eq!(delete_word_backward_pos("hello  world", 12), 7);
        assert_eq!(delete_word_backward_pos("a b c", 5), 4);
    }

    #[test]
    fn delete_word_empty() {
        assert_eq!(delete_word_backward_pos("", 0), 0);
        assert_eq!(delete_word_backward_pos("hello", 0), 0);
    }

    #[test]
    fn truncate_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_long() {
        assert_eq!(truncate_str("hello world", 8), "hello...");
    }

    #[test]
    fn truncate_tiny_max() {
        assert_eq!(truncate_str("hello", 2), "he");
    }

    #[test]
    fn truncate_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }
}
