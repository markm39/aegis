//! Lightweight markdown-to-ratatui converter.
//!
//! Renders a subset of markdown into styled `Line`/`Span` sequences for display
//! in a terminal TUI. No external dependencies beyond ratatui.
//!
//! Supported syntax:
//! - `**bold**` and `__bold__`
//! - `` `inline code` ``
//! - `# Headers` (levels 1-3)
//! - Fenced code blocks (` ``` `)
//! - `- ` / `* ` bullet lists
//! - `1. ` numbered lists
//! - `> ` blockquotes (simple dim treatment)
//! - `[text](url)` links
//!
//! Unsupported syntax (images, tables, nested lists) passes through as plain text.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Style for code block content: light gray on dark gray.
const CODE_BLOCK_STYLE: Style = Style::new()
    .fg(Color::Rgb(180, 180, 180))
    .bg(Color::Rgb(40, 40, 40));

/// Style for the code fence lines themselves (``` markers).
const CODE_FENCE_STYLE: Style = Style::new().fg(Color::Rgb(100, 100, 100));

/// Render a markdown text block into styled ratatui Lines.
///
/// Handles the common patterns that LLM assistants produce: bold, inline code,
/// headers, fenced code blocks, bullet/numbered lists, blockquotes, and links.
///
/// Unsupported constructs (images, tables, nested lists) pass through as plain
/// text -- graceful degradation rather than breakage.
pub fn render_markdown(text: &str, base_style: Style) -> Vec<Line<'static>> {
    let mut result = Vec::new();
    let mut in_code_block = false;

    for raw_line in text.split('\n') {
        if is_code_fence(raw_line) {
            if in_code_block {
                // Closing fence
                result.push(Line::from(Span::styled(
                    raw_line.to_string(),
                    CODE_FENCE_STYLE,
                )));
                in_code_block = false;
            } else {
                // Opening fence
                result.push(Line::from(Span::styled(
                    raw_line.to_string(),
                    CODE_FENCE_STYLE,
                )));
                in_code_block = true;
            }
            continue;
        }

        if in_code_block {
            // Inside a code block: preserve whitespace exactly, no inline styling.
            result.push(Line::from(Span::styled(
                raw_line.to_string(),
                CODE_BLOCK_STYLE,
            )));
            continue;
        }

        // Outside code blocks: check for line-level patterns.
        if let Some((level, content)) = strip_header_prefix(raw_line) {
            let header_style = match level {
                1 => base_style
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
                _ => base_style
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            };
            // Apply inline styling within the header content, inheriting
            // the header's base style for non-formatted segments.
            let spans = style_inline(content, header_style);
            result.push(Line::from(spans));
        } else if let Some(content) = is_bullet(raw_line) {
            let mut spans = vec![Span::styled(
                "  - ".to_string(),
                base_style.fg(Color::DarkGray),
            )];
            spans.extend(style_inline(content, base_style));
            result.push(Line::from(spans));
        } else if let Some((num, content)) = is_numbered(raw_line) {
            let mut spans = vec![Span::styled(
                format!("  {num}. "),
                base_style.fg(Color::DarkGray),
            )];
            spans.extend(style_inline(content, base_style));
            result.push(Line::from(spans));
        } else if let Some(content) = is_blockquote(raw_line) {
            let mut spans = vec![Span::styled(
                "| ".to_string(),
                base_style.fg(Color::DarkGray),
            )];
            spans.extend(style_inline(
                content,
                base_style.add_modifier(Modifier::DIM),
            ));
            result.push(Line::from(spans));
        } else {
            let spans = style_inline(raw_line, base_style);
            result.push(Line::from(spans));
        }
    }

    result
}

/// Parse inline markdown formatting and return a sequence of styled `Span`s.
///
/// Recognises `**bold**`, `__bold__`, `` `code` ``, and `[text](url)`.
/// Everything else is emitted with the provided base style.
fn style_inline(text: &str, base: Style) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut bold = false;

    while i < len {
        // Check for **bold** or __bold__ toggle.
        if i + 1 < len
            && ((chars[i] == '*' && chars[i + 1] == '*')
                || (chars[i] == '_' && chars[i + 1] == '_'))
        {
            // Flush accumulated text.
            if !current.is_empty() {
                let style = if bold {
                    base.add_modifier(Modifier::BOLD)
                } else {
                    base
                };
                spans.push(Span::styled(std::mem::take(&mut current), style));
            }
            bold = !bold;
            i += 2;
            continue;
        }

        // Check for `inline code`.
        if chars[i] == '`' {
            // Flush accumulated text.
            if !current.is_empty() {
                let style = if bold {
                    base.add_modifier(Modifier::BOLD)
                } else {
                    base
                };
                spans.push(Span::styled(std::mem::take(&mut current), style));
            }
            // Collect everything until the closing backtick.
            i += 1;
            let mut code = String::new();
            while i < len && chars[i] != '`' {
                code.push(chars[i]);
                i += 1;
            }
            if i < len {
                i += 1; // skip closing backtick
            }
            spans.push(Span::styled(
                code,
                base.fg(Color::Yellow),
            ));
            continue;
        }

        // Check for [link text](url).
        if chars[i] == '[' {
            // Try to parse a markdown link.
            if let Some((link_text, url_end)) = try_parse_link(&chars, i) {
                // Flush accumulated text.
                if !current.is_empty() {
                    let style = if bold {
                        base.add_modifier(Modifier::BOLD)
                    } else {
                        base
                    };
                    spans.push(Span::styled(std::mem::take(&mut current), style));
                }
                spans.push(Span::styled(
                    link_text,
                    base.fg(Color::Cyan),
                ));
                i = url_end;
                continue;
            }
        }

        current.push(chars[i]);
        i += 1;
    }

    // Flush remaining text.
    if !current.is_empty() {
        let style = if bold {
            base.add_modifier(Modifier::BOLD)
        } else {
            base
        };
        spans.push(Span::styled(current, style));
    }

    // If the input was empty, still produce a single empty span so the
    // caller gets a valid (if blank) Line.
    if spans.is_empty() {
        spans.push(Span::styled(String::new(), base));
    }

    spans
}

/// Try to parse a `[text](url)` link starting at position `start` in `chars`.
///
/// Returns `Some((link_text, end_index))` if successful, where `end_index` is
/// the position just past the closing `)`. Returns `None` if the syntax does
/// not match.
fn try_parse_link(chars: &[char], start: usize) -> Option<(String, usize)> {
    // chars[start] should be '['
    if chars.get(start) != Some(&'[') {
        return None;
    }

    // Find the closing ']'.
    let mut i = start + 1;
    let mut link_text = String::new();
    while i < chars.len() && chars[i] != ']' {
        link_text.push(chars[i]);
        i += 1;
    }
    if i >= chars.len() {
        return None; // no closing ']'
    }
    i += 1; // skip ']'

    // Expect '(' immediately after ']'.
    if i >= chars.len() || chars[i] != '(' {
        return None;
    }
    i += 1; // skip '('

    // Find the closing ')'.
    while i < chars.len() && chars[i] != ')' {
        i += 1;
    }
    if i >= chars.len() {
        return None; // no closing ')'
    }
    i += 1; // skip ')'

    Some((link_text, i))
}

/// Returns `true` if the line is a code fence (starts with ` ``` `).
fn is_code_fence(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("```")
}

/// If the line is a markdown header, returns `(level, content)`.
///
/// Supports levels 1-3. Lines like `# Title` return `Some((1, "Title"))`.
fn strip_header_prefix(line: &str) -> Option<(u8, &str)> {
    if let Some(rest) = line.strip_prefix("### ") {
        Some((3, rest))
    } else if let Some(rest) = line.strip_prefix("## ") {
        Some((2, rest))
    } else if let Some(rest) = line.strip_prefix("# ") {
        Some((1, rest))
    } else {
        None
    }
}

/// If the line is a bullet list item (`- ` or `* `), returns the content.
fn is_bullet(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("- ") {
        Some(rest)
    } else if let Some(rest) = line.strip_prefix("* ") {
        Some(rest)
    } else {
        None
    }
}

/// If the line is a numbered list item (`1. `, `2. `, etc.), returns `(number, content)`.
fn is_numbered(line: &str) -> Option<(usize, &str)> {
    // Match digits followed by ". " at the start of the line.
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    if line[i..].starts_with(". ") {
        let num: usize = line[..i].parse().ok()?;
        Some((num, &line[i + 2..]))
    } else {
        None
    }
}

/// If the line is a blockquote (`> `), returns the content after the prefix.
fn is_blockquote(line: &str) -> Option<&str> {
    line.strip_prefix("> ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: collect all span content from a line into a single string.
    fn line_text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn plain_text_unchanged() {
        let lines = render_markdown("Hello world", Style::default());
        assert_eq!(lines.len(), 1);
        assert_eq!(line_text(&lines[0]), "Hello world");
    }

    #[test]
    fn bold_text_has_bold_modifier() {
        let lines = render_markdown("This is **bold** text", Style::default());
        assert_eq!(lines.len(), 1);
        let spans = &lines[0].spans;
        // Expect at least: "This is ", "bold", " text"
        assert!(spans.len() >= 3, "got {} spans: {:?}", spans.len(), spans);
        assert_eq!(spans[0].content.as_ref(), "This is ");
        assert!(spans[1].style.add_modifier.contains(Modifier::BOLD));
        assert_eq!(spans[1].content.as_ref(), "bold");
        assert_eq!(spans[2].content.as_ref(), " text");
    }

    #[test]
    fn underscore_bold() {
        let lines = render_markdown("__important__", Style::default());
        let spans = &lines[0].spans;
        assert!(spans[0].style.add_modifier.contains(Modifier::BOLD));
        assert_eq!(spans[0].content.as_ref(), "important");
    }

    #[test]
    fn inline_code_has_yellow() {
        let lines = render_markdown("Use `cargo build` here", Style::default());
        let spans = &lines[0].spans;
        assert!(
            spans.iter().any(|s| s.style.fg == Some(Color::Yellow)),
            "expected a yellow span for inline code"
        );
        // The code content should be "cargo build" (without backticks).
        let code_span = spans.iter().find(|s| s.style.fg == Some(Color::Yellow)).unwrap();
        assert_eq!(code_span.content.as_ref(), "cargo build");
    }

    #[test]
    fn header_level_1() {
        let lines = render_markdown("# My Header", Style::default());
        assert_eq!(lines.len(), 1);
        let spans = &lines[0].spans;
        assert!(spans[0].style.add_modifier.contains(Modifier::BOLD));
        assert_eq!(spans[0].style.fg, Some(Color::Cyan));
        assert_eq!(line_text(&lines[0]), "My Header");
    }

    #[test]
    fn header_level_2() {
        let lines = render_markdown("## Sub Header", Style::default());
        assert_eq!(lines.len(), 1);
        let spans = &lines[0].spans;
        assert!(spans[0].style.add_modifier.contains(Modifier::BOLD));
        assert_eq!(spans[0].style.fg, Some(Color::White));
        assert_eq!(line_text(&lines[0]), "Sub Header");
    }

    #[test]
    fn header_level_3() {
        let lines = render_markdown("### Sub Sub Header", Style::default());
        assert_eq!(lines.len(), 1);
        let spans = &lines[0].spans;
        assert!(spans[0].style.add_modifier.contains(Modifier::BOLD));
        assert_eq!(spans[0].style.fg, Some(Color::White));
    }

    #[test]
    fn code_block() {
        let text = "before\n```rust\nfn main() {}\n```\nafter";
        let lines = render_markdown(text, Style::default());
        assert_eq!(lines.len(), 5);

        // Line 0: "before" -- plain text
        assert_eq!(line_text(&lines[0]), "before");

        // Line 1: opening fence -- fence style
        assert_eq!(lines[1].spans[0].style.fg, Some(Color::Rgb(100, 100, 100)));

        // Line 2: code content -- code block style
        assert_eq!(lines[2].spans[0].style.fg, Some(Color::Rgb(180, 180, 180)));
        assert_eq!(lines[2].spans[0].style.bg, Some(Color::Rgb(40, 40, 40)));
        assert_eq!(line_text(&lines[2]), "fn main() {}");

        // Line 3: closing fence
        assert_eq!(lines[3].spans[0].style.fg, Some(Color::Rgb(100, 100, 100)));

        // Line 4: "after" -- plain text
        assert_eq!(line_text(&lines[4]), "after");
    }

    #[test]
    fn code_block_preserves_whitespace() {
        let text = "```\n  indented\n    more\n```";
        let lines = render_markdown(text, Style::default());
        assert_eq!(line_text(&lines[1]), "  indented");
        assert_eq!(line_text(&lines[2]), "    more");
    }

    #[test]
    fn bullet_list() {
        let text = "- item one\n- item two";
        let lines = render_markdown(text, Style::default());
        assert_eq!(lines.len(), 2);
        // Each line should start with the formatted bullet prefix.
        assert!(line_text(&lines[0]).starts_with("  - "));
        assert!(line_text(&lines[1]).starts_with("  - "));
        // Prefix span should be dim.
        assert_eq!(lines[0].spans[0].style.fg, Some(Color::DarkGray));
    }

    #[test]
    fn bullet_list_star() {
        let text = "* star bullet";
        let lines = render_markdown(text, Style::default());
        assert_eq!(lines.len(), 1);
        assert!(line_text(&lines[0]).starts_with("  - "));
    }

    #[test]
    fn numbered_list() {
        let text = "1. first\n2. second";
        let lines = render_markdown(text, Style::default());
        assert_eq!(lines.len(), 2);
        assert!(line_text(&lines[0]).starts_with("  1. "));
        assert!(line_text(&lines[1]).starts_with("  2. "));
        assert_eq!(lines[0].spans[0].style.fg, Some(Color::DarkGray));
    }

    #[test]
    fn link_shows_text_in_cyan() {
        let lines = render_markdown("See [docs](https://example.com)", Style::default());
        let spans = &lines[0].spans;
        let link_span = spans.iter().find(|s| s.style.fg == Some(Color::Cyan)).unwrap();
        assert_eq!(link_span.content.as_ref(), "docs");
    }

    #[test]
    fn link_url_discarded() {
        let lines = render_markdown("[click](http://x.com)", Style::default());
        let full = line_text(&lines[0]);
        // The URL should not appear in the rendered text.
        assert!(!full.contains("http"));
        assert!(full.contains("click"));
    }

    #[test]
    fn blockquote() {
        let lines = render_markdown("> quoted text", Style::default());
        assert_eq!(lines.len(), 1);
        assert!(line_text(&lines[0]).starts_with("| "));
        assert_eq!(lines[0].spans[0].style.fg, Some(Color::DarkGray));
    }

    #[test]
    fn multiline_text() {
        let text = "Line 1\nLine 2\nLine 3";
        let lines = render_markdown(text, Style::default());
        assert_eq!(lines.len(), 3);
        assert_eq!(line_text(&lines[0]), "Line 1");
        assert_eq!(line_text(&lines[1]), "Line 2");
        assert_eq!(line_text(&lines[2]), "Line 3");
    }

    #[test]
    fn empty_input() {
        let lines = render_markdown("", Style::default());
        // An empty string splits into a single empty line.
        assert_eq!(lines.len(), 1);
        assert_eq!(line_text(&lines[0]), "");
    }

    #[test]
    fn mixed_inline_styles() {
        let lines = render_markdown("**bold** and `code` together", Style::default());
        let spans = &lines[0].spans;
        // At minimum: "bold" (bold), " and " (plain), "code" (yellow), " together" (plain)
        assert!(spans.len() >= 4, "got {} spans: {:?}", spans.len(), spans);

        let bold_span = spans.iter().find(|s| s.content.as_ref() == "bold").unwrap();
        assert!(bold_span.style.add_modifier.contains(Modifier::BOLD));

        let code_span = spans.iter().find(|s| s.content.as_ref() == "code").unwrap();
        assert_eq!(code_span.style.fg, Some(Color::Yellow));
    }

    #[test]
    fn nested_bold_in_header() {
        let lines = render_markdown("# Header with **bold**", Style::default());
        assert_eq!(lines.len(), 1);
        // The entire header should be cyan.
        for span in &lines[0].spans {
            assert_eq!(span.style.fg, Some(Color::Cyan));
        }
        // The "bold" portion should also have BOLD modifier (all header spans
        // are bold, so "bold" also has it).
        let bold_span = lines[0]
            .spans
            .iter()
            .find(|s| s.content.as_ref() == "bold")
            .unwrap();
        assert!(bold_span.style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn inline_code_in_bullet() {
        let lines = render_markdown("- use `foo` here", Style::default());
        let spans = &lines[0].spans;
        let code_span = spans.iter().find(|s| s.style.fg == Some(Color::Yellow)).unwrap();
        assert_eq!(code_span.content.as_ref(), "foo");
    }

    #[test]
    fn unclosed_backtick_degrades_gracefully() {
        // An unclosed backtick should not panic; content after it is treated as code.
        let lines = render_markdown("text `unclosed", Style::default());
        assert_eq!(lines.len(), 1);
        let full = line_text(&lines[0]);
        assert_eq!(full, "text unclosed");
    }

    #[test]
    fn unclosed_bold_degrades_gracefully() {
        let lines = render_markdown("text **unclosed", Style::default());
        assert_eq!(lines.len(), 1);
        let full = line_text(&lines[0]);
        assert_eq!(full, "text unclosed");
    }

    #[test]
    fn broken_link_passes_through() {
        // A bracket without matching parens should pass through as plain text.
        let lines = render_markdown("[broken link", Style::default());
        let full = line_text(&lines[0]);
        assert_eq!(full, "[broken link");
    }

    #[test]
    fn code_fence_without_language() {
        let text = "```\nhello\n```";
        let lines = render_markdown(text, Style::default());
        assert_eq!(lines.len(), 3);
        assert_eq!(line_text(&lines[1]), "hello");
        assert_eq!(lines[1].spans[0].style.fg, Some(Color::Rgb(180, 180, 180)));
    }

    #[test]
    fn multiple_bold_segments() {
        let lines = render_markdown("**a** then **b**", Style::default());
        let spans = &lines[0].spans;
        let bold_spans: Vec<_> = spans
            .iter()
            .filter(|s| s.style.add_modifier.contains(Modifier::BOLD))
            .collect();
        assert_eq!(bold_spans.len(), 2);
        assert_eq!(bold_spans[0].content.as_ref(), "a");
        assert_eq!(bold_spans[1].content.as_ref(), "b");
    }

    #[test]
    fn helper_is_code_fence() {
        assert!(is_code_fence("```"));
        assert!(is_code_fence("```rust"));
        assert!(is_code_fence("  ```"));
        assert!(!is_code_fence("hello"));
        assert!(!is_code_fence("`` not a fence"));
    }

    #[test]
    fn helper_strip_header_prefix() {
        assert_eq!(strip_header_prefix("# Title"), Some((1, "Title")));
        assert_eq!(strip_header_prefix("## Sub"), Some((2, "Sub")));
        assert_eq!(strip_header_prefix("### Deep"), Some((3, "Deep")));
        assert_eq!(strip_header_prefix("#### Too deep"), None);
        assert_eq!(strip_header_prefix("Not a header"), None);
    }

    #[test]
    fn helper_is_bullet() {
        assert_eq!(is_bullet("- item"), Some("item"));
        assert_eq!(is_bullet("* item"), Some("item"));
        assert_eq!(is_bullet("not a bullet"), None);
    }

    #[test]
    fn helper_is_numbered() {
        assert_eq!(is_numbered("1. first"), Some((1, "first")));
        assert_eq!(is_numbered("42. answer"), Some((42, "answer")));
        assert_eq!(is_numbered("not numbered"), None);
        assert_eq!(is_numbered("1.no space"), None);
    }

    #[test]
    fn base_style_propagated() {
        let base = Style::default().fg(Color::Green);
        let lines = render_markdown("plain text", base);
        assert_eq!(lines[0].spans[0].style.fg, Some(Color::Green));
    }
}
