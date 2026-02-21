//! Auto-TTS modes and tagged text extraction.
//!
//! Controls when text-to-speech synthesis is triggered automatically,
//! with support for multiple modes: always, on inbound voice input,
//! or only for messages with explicit TTS markers.
//!
//! # Marker formats
//!
//! - Inline: `[[tts]]some text[[/tts]]`
//! - Block: `[[tts:start]]some text[[tts:end]]`
//!
//! Both formats can appear multiple times in a single message. Extracted
//! segments are concatenated with spaces.

use serde::{Deserialize, Serialize};

/// Automatic TTS synthesis mode.
///
/// Controls when outbound messages are automatically converted to speech.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AutoTtsMode {
    /// No automatic TTS. Synthesis must be triggered manually.
    #[default]
    Off,
    /// TTS every outbound message automatically.
    Always,
    /// TTS only after receiving voice input from the user.
    Inbound,
    /// TTS only when the message contains `[[tts]]` markers.
    Tagged,
}

impl std::fmt::Display for AutoTtsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoTtsMode::Off => write!(f, "off"),
            AutoTtsMode::Always => write!(f, "always"),
            AutoTtsMode::Inbound => write!(f, "inbound"),
            AutoTtsMode::Tagged => write!(f, "tagged"),
        }
    }
}

/// Determine whether a message should be synthesized to speech.
///
/// The decision depends on the current [`AutoTtsMode`]:
/// - `Off`: never synthesize.
/// - `Always`: always synthesize (returns `true` for any non-empty message).
/// - `Inbound`: synthesize only if the preceding input was voice
///   (`was_voice_input` is `true`).
/// - `Tagged`: synthesize only if the message contains TTS markers
///   (`[[tts]]` or `[[tts:start]]`).
pub fn should_synthesize(mode: &AutoTtsMode, message: &str, was_voice_input: bool) -> bool {
    match mode {
        AutoTtsMode::Off => false,
        AutoTtsMode::Always => !message.is_empty(),
        AutoTtsMode::Inbound => was_voice_input && !message.is_empty(),
        AutoTtsMode::Tagged => has_tts_markers(message),
    }
}

/// Extract text between TTS markers from a message.
///
/// Supports two marker formats:
/// - Inline: `[[tts]]text here[[/tts]]`
/// - Block: `[[tts:start]]text here[[tts:end]]`
///
/// Multiple marker pairs in a single message are all extracted and
/// concatenated with spaces. Returns `None` if no markers are found.
pub fn extract_tts_text(message: &str) -> Option<String> {
    let mut segments = Vec::new();

    // Extract inline markers: [[tts]]...[[/tts]]
    extract_between(message, "[[tts]]", "[[/tts]]", &mut segments);

    // Extract block markers: [[tts:start]]...[[tts:end]]
    extract_between(message, "[[tts:start]]", "[[tts:end]]", &mut segments);

    if segments.is_empty() {
        return None;
    }

    let joined = segments.join(" ").trim().to_string();
    if joined.is_empty() {
        return None;
    }

    Some(joined)
}

/// Check whether a message contains any TTS markers.
fn has_tts_markers(message: &str) -> bool {
    message.contains("[[tts]]") || message.contains("[[tts:start]]")
}

/// Extract text segments between `open` and `close` marker pairs.
///
/// Appends each found segment (trimmed) to `segments`. Handles multiple
/// occurrences by scanning forward after each match.
fn extract_between(message: &str, open: &str, close: &str, segments: &mut Vec<String>) {
    let mut search_from = 0;

    while let Some(start_idx) = message[search_from..].find(open) {
        let content_start = search_from + start_idx + open.len();
        if content_start >= message.len() {
            break;
        }

        if let Some(end_idx) = message[content_start..].find(close) {
            let content = &message[content_start..content_start + end_idx];
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                segments.push(trimmed.to_string());
            }
            search_from = content_start + end_idx + close.len();
        } else {
            // No closing marker found; stop searching for this pattern.
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- AutoTtsMode serialization --

    #[test]
    fn auto_tts_mode_default_is_off() {
        assert_eq!(AutoTtsMode::default(), AutoTtsMode::Off);
    }

    #[test]
    fn auto_tts_mode_display() {
        assert_eq!(AutoTtsMode::Off.to_string(), "off");
        assert_eq!(AutoTtsMode::Always.to_string(), "always");
        assert_eq!(AutoTtsMode::Inbound.to_string(), "inbound");
        assert_eq!(AutoTtsMode::Tagged.to_string(), "tagged");
    }

    #[test]
    fn auto_tts_mode_serialization_roundtrip() {
        for mode in [
            AutoTtsMode::Off,
            AutoTtsMode::Always,
            AutoTtsMode::Inbound,
            AutoTtsMode::Tagged,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: AutoTtsMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    // -- should_synthesize --

    #[test]
    fn should_synthesize_off_mode() {
        assert!(!should_synthesize(&AutoTtsMode::Off, "Hello", false));
        assert!(!should_synthesize(&AutoTtsMode::Off, "Hello", true));
        assert!(!should_synthesize(&AutoTtsMode::Off, "", false));
    }

    #[test]
    fn should_synthesize_always_mode() {
        assert!(should_synthesize(&AutoTtsMode::Always, "Hello", false));
        assert!(should_synthesize(&AutoTtsMode::Always, "Hello", true));
        // Empty message should not synthesize even in Always mode.
        assert!(!should_synthesize(&AutoTtsMode::Always, "", false));
    }

    #[test]
    fn should_synthesize_inbound_mode() {
        // Only synthesize when was_voice_input is true.
        assert!(should_synthesize(&AutoTtsMode::Inbound, "Hello", true));
        assert!(!should_synthesize(&AutoTtsMode::Inbound, "Hello", false));
        // Empty message with voice input should not synthesize.
        assert!(!should_synthesize(&AutoTtsMode::Inbound, "", true));
    }

    #[test]
    fn should_synthesize_tagged_mode() {
        // With inline markers.
        assert!(should_synthesize(
            &AutoTtsMode::Tagged,
            "Here is [[tts]]spoken text[[/tts]] and more.",
            false
        ));
        // With block markers.
        assert!(should_synthesize(
            &AutoTtsMode::Tagged,
            "Before [[tts:start]]spoken text[[tts:end]] after.",
            false
        ));
        // Without markers.
        assert!(!should_synthesize(
            &AutoTtsMode::Tagged,
            "No markers here.",
            false
        ));
        // Voice input does not matter for tagged mode.
        assert!(!should_synthesize(
            &AutoTtsMode::Tagged,
            "No markers here.",
            true
        ));
    }

    // -- extract_tts_text --

    #[test]
    fn extract_tts_text_inline_markers() {
        let msg = "Hello [[tts]]world[[/tts]] end";
        let result = extract_tts_text(msg);
        assert_eq!(result.as_deref(), Some("world"));
    }

    #[test]
    fn extract_tts_text_block_markers() {
        let msg = "Before [[tts:start]]spoken text here[[tts:end]] after.";
        let result = extract_tts_text(msg);
        assert_eq!(result.as_deref(), Some("spoken text here"));
    }

    #[test]
    fn extract_tts_text_multiple_inline() {
        let msg = "A [[tts]]first[[/tts]] B [[tts]]second[[/tts]] C";
        let result = extract_tts_text(msg);
        assert_eq!(result.as_deref(), Some("first second"));
    }

    #[test]
    fn extract_tts_text_multiple_block() {
        let msg = "[[tts:start]]one[[tts:end]] and [[tts:start]]two[[tts:end]]";
        let result = extract_tts_text(msg);
        assert_eq!(result.as_deref(), Some("one two"));
    }

    #[test]
    fn extract_tts_text_mixed_markers() {
        let msg = "[[tts]]inline[[/tts]] and [[tts:start]]block[[tts:end]]";
        let result = extract_tts_text(msg);
        assert_eq!(result.as_deref(), Some("inline block"));
    }

    #[test]
    fn extract_tts_text_no_markers() {
        let msg = "This has no TTS markers at all.";
        let result = extract_tts_text(msg);
        assert!(result.is_none());
    }

    #[test]
    fn extract_tts_text_empty_markers() {
        // Markers with only whitespace inside should return None.
        let msg = "[[tts]]   [[/tts]]";
        let result = extract_tts_text(msg);
        assert!(result.is_none());
    }

    #[test]
    fn extract_tts_text_unclosed_markers() {
        // Unclosed markers should be ignored (no match).
        let msg = "[[tts]]unclosed text without end marker";
        let result = extract_tts_text(msg);
        assert!(result.is_none());
    }

    #[test]
    fn extract_tts_text_nested_content() {
        // Text with special characters inside markers.
        let msg = "[[tts]]Hello, world! How's it going?[[/tts]]";
        let result = extract_tts_text(msg);
        assert_eq!(result.as_deref(), Some("Hello, world! How's it going?"));
    }

    #[test]
    fn extract_tts_text_multiline() {
        let msg = "[[tts:start]]Line one\nLine two[[tts:end]]";
        let result = extract_tts_text(msg);
        assert_eq!(result.as_deref(), Some("Line one\nLine two"));
    }

    #[test]
    fn extract_tts_text_empty_message() {
        let result = extract_tts_text("");
        assert!(result.is_none());
    }
}
