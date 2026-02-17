//! ANSI escape sequence stripping for clean text matching.
//!
//! Terminal output is full of ANSI escape codes for colors, cursor movement,
//! and other formatting. The adapter needs to pattern-match against clean text,
//! so we strip these sequences before feeding lines to the adapter.

/// Strip ANSI escape sequences from a byte slice, returning clean UTF-8 text.
///
/// Handles:
/// - CSI sequences: `ESC [ ... <final byte>`
/// - OSC sequences: `ESC ] ... ST` (where ST is `ESC \` or BEL)
/// - Simple two-byte escapes: `ESC <letter>`
/// - Bare CSI (`0x9B`) sequences
///
/// Non-UTF-8 bytes are replaced with the Unicode replacement character.
pub fn strip_ansi(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        match input[i] {
            // ESC
            0x1B => {
                i += 1;
                if i >= input.len() {
                    break;
                }
                match input[i] {
                    // CSI: ESC [
                    b'[' => {
                        i += 1;
                        // Skip parameter bytes (0x30-0x3F), intermediate bytes (0x20-0x2F)
                        while i < input.len() && (0x20..=0x3F).contains(&input[i]) {
                            i += 1;
                        }
                        // Skip final byte (0x40-0x7E)
                        if i < input.len() && (0x40..=0x7E).contains(&input[i]) {
                            i += 1;
                        }
                    }
                    // OSC: ESC ]
                    b']' => {
                        i += 1;
                        // Skip until ST (ESC \ or BEL)
                        while i < input.len() {
                            if input[i] == 0x07 {
                                // BEL
                                i += 1;
                                break;
                            }
                            if input[i] == 0x1B && i + 1 < input.len() && input[i + 1] == b'\\' {
                                i += 2;
                                break;
                            }
                            i += 1;
                        }
                    }
                    // Simple two-byte escape (e.g., ESC M, ESC 7, ESC 8)
                    0x20..=0x7E => {
                        i += 1;
                    }
                    _ => {
                        // Unknown escape, skip the byte after ESC
                        i += 1;
                    }
                }
            }
            // Bare CSI (0x9B) -- rare but valid
            0x9B => {
                i += 1;
                while i < input.len() && (0x20..=0x3F).contains(&input[i]) {
                    i += 1;
                }
                if i < input.len() && (0x40..=0x7E).contains(&input[i]) {
                    i += 1;
                }
            }
            // Carriage return -- skip (terminal lines use \r\n)
            b'\r' => {
                i += 1;
            }
            // Normal byte
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_unchanged() {
        assert_eq!(strip_ansi(b"hello world"), "hello world");
    }

    #[test]
    fn strips_color_codes() {
        // Bold red "error" then reset
        let input = b"\x1b[1;31merror\x1b[0m";
        assert_eq!(strip_ansi(input), "error");
    }

    #[test]
    fn strips_cursor_movement() {
        // Move cursor up 2 lines, then print text
        let input = b"\x1b[2Ahello";
        assert_eq!(strip_ansi(input), "hello");
    }

    #[test]
    fn strips_osc_with_bel() {
        // Set window title
        let input = b"\x1b]0;My Terminal\x07rest";
        assert_eq!(strip_ansi(input), "rest");
    }

    #[test]
    fn strips_osc_with_st() {
        let input = b"\x1b]0;title\x1b\\rest";
        assert_eq!(strip_ansi(input), "rest");
    }

    #[test]
    fn strips_carriage_return() {
        assert_eq!(strip_ansi(b"line\r\n"), "line\n");
    }

    #[test]
    fn handles_bare_csi() {
        let input = b"\x9b31mred\x9b0m";
        assert_eq!(strip_ansi(input), "red");
    }

    #[test]
    fn handles_empty_input() {
        assert_eq!(strip_ansi(b""), "");
    }

    #[test]
    fn handles_truncated_escape() {
        // ESC at end of input
        assert_eq!(strip_ansi(b"text\x1b"), "text");
    }

    #[test]
    fn preserves_newlines() {
        let input = b"\x1b[32mline1\n\x1b[0mline2\n";
        assert_eq!(strip_ansi(input), "line1\nline2\n");
    }

    #[test]
    fn complex_claude_code_like_output() {
        // Simulate typical Claude Code output with colors and formatting
        let input = b"\x1b[1m\x1b[36m\xe2\x97\x8f\x1b[0m Claude wants to use \x1b[1mBash\x1b[0m";
        let stripped = strip_ansi(input);
        assert!(stripped.contains("Claude wants to use"));
        assert!(stripped.contains("Bash"));
    }
}
