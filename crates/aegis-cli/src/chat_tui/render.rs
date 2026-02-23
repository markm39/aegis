//! Chat message rendering for the chat-centric TUI.
//!
//! Converts [`ChatMessage`] objects and UI chrome (header bar, status bar) into
//! styled ratatui [`Line`] objects ready for terminal display.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::message::{ChatMessage, MessageRole};

// ---------------------------------------------------------------------------
// Tool color mapping
// ---------------------------------------------------------------------------

/// Map a tool name to its display color.
pub fn tool_color(name: &str) -> Color {
    match name {
        "Bash" => Color::Rgb(253, 93, 177), // hot pink (Claude Code bash border)
        "Read" | "Write" | "Edit" | "Glob" | "NotebookRead" | "NotebookEdit" => Color::Cyan,
        "Grep" | "WebSearch" | "WebFetch" => Color::Rgb(177, 185, 249), // light purple-blue
        "Task" | "task" => Color::Rgb(215, 119, 87),                      // Claude brand color
        "LSP" => Color::Rgb(177, 185, 249),
        _ => Color::White,
    }
}

// ---------------------------------------------------------------------------
// Message rendering
// ---------------------------------------------------------------------------

/// Render a user message.
pub fn render_user_message(content: &str, _width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from("")); // blank separator
    lines.push(Line::from(Span::styled(
        "You:".to_string(),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    for line in content.lines() {
        lines.push(Line::from(Span::raw(format!("  {line}"))));
    }
    lines.push(Line::from("")); // blank separator
    lines
}

/// Render an assistant (LLM) text message.
pub fn render_assistant_message(content: &str, _width: u16) -> Vec<Line<'static>> {
    content
        .lines()
        .map(|line| Line::from(Span::raw(line.to_string())))
        .collect()
}

/// Render a tool call line.
pub fn render_tool_call(
    tool_name: &str,
    summary: &str,
    verdict: Option<&str>,
    width: u16,
) -> Vec<Line<'static>> {
    let prefix = Span::styled(" > ".to_string(), Style::default().fg(Color::DarkGray));
    let name_span = Span::styled(
        format!("{tool_name}: "),
        Style::default()
            .fg(tool_color(tool_name))
            .add_modifier(Modifier::BOLD),
    );
    let summary_span = Span::raw(summary.to_string());

    // Right-aligned verdict badge.
    let badge = match verdict {
        Some("allow") => Span::styled(" [ALLOW] ".to_string(), Style::default().fg(Color::Green)),
        Some("deny") => Span::styled(" [DENY] ".to_string(), Style::default().fg(Color::Red)),
        Some("ask") => Span::styled(" [ASK] ".to_string(), Style::default().fg(Color::Yellow)),
        _ => Span::raw(String::new()),
    };

    let content_len = 3 + tool_name.len() + 2 + summary.len();
    let badge_len = if verdict.is_some() { 9 } else { 0 };
    let padding = if (width as usize) > content_len + badge_len {
        " ".repeat(width as usize - content_len - badge_len)
    } else {
        " ".to_string()
    };

    vec![Line::from(vec![
        prefix,
        name_span,
        summary_span,
        Span::raw(padding),
        badge,
    ])]
}

/// Render a pending permission prompt.
pub fn render_permission_pending(prompt: &str, _width: u16) -> Vec<Line<'static>> {
    let border_style = Style::default().fg(Color::Yellow);
    let hint_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    vec![
        Line::from(Span::styled(
            " --- Permission Required ---".to_string(),
            border_style,
        )),
        Line::from(Span::styled(
            format!(" {prompt}"),
            Style::default().fg(Color::White),
        )),
        Line::from(vec![
            Span::styled(" [Y]".to_string(), hint_style),
            Span::raw(" Allow  ".to_string()),
            Span::styled("[N]".to_string(), hint_style),
            Span::raw(" Deny".to_string()),
        ]),
        Line::from(Span::styled(
            " ----------------------------".to_string(),
            border_style,
        )),
    ]
}

/// Render a resolved (approved or denied) permission line.
pub fn render_permission_resolved(prompt: &str, approved: bool) -> Vec<Line<'static>> {
    let (label, color) = if approved {
        ("[APPROVED]", Color::Green)
    } else {
        ("[DENIED]", Color::Red)
    };
    vec![Line::from(vec![
        Span::styled(format!(" {label} "), Style::default().fg(color)),
        Span::raw(prompt.to_string()),
    ])]
}

/// Render a system message (errors, status, etc.).
pub fn render_system_message(content: &str) -> Vec<Line<'static>> {
    vec![Line::from(Span::styled(
        format!("  {content}"),
        Style::default().fg(Color::DarkGray),
    ))]
}

/// Render a result/completion message.
pub fn render_result_message(content: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {content}"),
            Style::default().fg(Color::Green),
        )),
        Line::from(""),
    ]
}

// ---------------------------------------------------------------------------
// Dispatch: ChatMessage -> Lines
// ---------------------------------------------------------------------------

/// Render a [`ChatMessage`] into styled terminal lines.
pub fn render_message(msg: &ChatMessage, width: u16) -> Vec<Line<'static>> {
    match &msg.role {
        MessageRole::User => render_user_message(&msg.content, width),
        MessageRole::Assistant => render_assistant_message(&msg.content, width),
        MessageRole::ToolCall { tool_name, summary } => {
            render_tool_call(tool_name, summary, None, width)
        }
        MessageRole::System => render_system_message(&msg.content),
        MessageRole::Permission { prompt, resolved } => match resolved {
            None => render_permission_pending(prompt, width),
            Some(true) => render_permission_resolved(prompt, true),
            Some(false) => render_permission_resolved(prompt, false),
        },
        MessageRole::Result { summary } => render_result_message(summary),
    }
}

// ---------------------------------------------------------------------------
// Chrome: header and status bars
// ---------------------------------------------------------------------------

/// Render the chat header bar (single line at the top of the TUI).
///
/// Format:
/// ```text
///  Aegis | model-name | Connected      or
///  Aegis | model-name | Thinking...    or
///  Aegis | model-name | Disconnected
/// ```
pub fn render_header(
    model: &str,
    provider: Option<&str>,
    connected: bool,
    thinking: bool,
    _width: u16,
) -> Line<'static> {
    let (status_text, status_color) = if thinking {
        ("Thinking...".to_string(), Color::Yellow)
    } else if connected {
        ("Connected".to_string(), Color::Green)
    } else {
        ("Disconnected".to_string(), Color::DarkGray)
    };

    let model_display = match provider {
        Some(p) => format!("{model} ({p})"),
        None => model.to_string(),
    };

    Line::from(vec![
        Span::styled(
            " Aegis".to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | ".to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(
            model_display,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | ".to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(status_text, Style::default().fg(status_color)),
    ])
}

/// Render the status bar (single line at the bottom of the TUI).
///
/// Format:
/// ```text
///  model-name  /help
/// ```
/// Optional usage info for the status bar.
pub struct UsageInfo {
    /// Total tokens used this session.
    pub total_tokens: u64,
    /// Estimated cost in USD.
    pub cost_usd: f64,
}

pub fn render_status_bar(model: &str, _width: u16, usage: Option<&UsageInfo>) -> Line<'static> {
    let mut spans = vec![
        Span::styled(
            format!(" {model}"),
            Style::default().fg(Color::DarkGray),
        ),
    ];

    if let Some(u) = usage {
        spans.push(Span::raw("  ".to_string()));
        spans.push(Span::styled(
            format!("{}tok ${:.4}", u.total_tokens, u.cost_usd),
            Style::default().fg(Color::DarkGray),
        ));
    }

    spans.push(Span::raw("  ".to_string()));
    spans.push(Span::styled("/help".to_string(), Style::default().fg(Color::DarkGray)));

    Line::from(spans)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_color_bash_is_hot_pink() {
        assert_eq!(tool_color("Bash"), Color::Rgb(253, 93, 177));
    }

    #[test]
    fn tool_color_read_is_cyan() {
        assert_eq!(tool_color("Read"), Color::Cyan);
    }

    #[test]
    fn tool_color_unknown_is_white() {
        assert_eq!(tool_color("SomeNewTool"), Color::White);
    }

    // -- User message -------------------------------------------------------

    #[test]
    fn render_user_has_cyan_prefix() {
        let lines = render_user_message("hello", 80);
        // blank, "You:", "  hello", blank = 4 lines
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn render_user_multiline() {
        let lines = render_user_message("line one\nline two\nline three", 80);
        // blank, "You:", 3 content lines, blank = 6 lines
        assert_eq!(lines.len(), 6);
    }

    #[test]
    fn render_user_prefix_style() {
        let lines = render_user_message("hello", 80);
        let you_line = &lines[1];
        assert_eq!(you_line.spans[0].content.as_ref(), "You:");
        assert_eq!(you_line.spans[0].style.fg, Some(Color::Cyan));
    }

    // -- Assistant message ---------------------------------------------------

    #[test]
    fn render_assistant_plain_text() {
        let lines = render_assistant_message("Hello there.", 80);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].spans[0].content.as_ref(), "Hello there.");
    }

    #[test]
    fn render_assistant_multiline() {
        let lines = render_assistant_message("line 1\nline 2", 80);
        assert_eq!(lines.len(), 2);
    }

    // -- Tool call ----------------------------------------------------------

    #[test]
    fn render_tool_call_with_allow() {
        let lines = render_tool_call("Bash", "ls -la", Some("allow"), 80);
        assert_eq!(lines.len(), 1);
        let spans = &lines[0].spans;
        assert!(spans.iter().any(|s| s.content.contains("ALLOW")));
    }

    #[test]
    fn render_tool_call_no_verdict() {
        let lines = render_tool_call("Read", "main.rs", None, 80);
        assert_eq!(lines.len(), 1);
        let spans = &lines[0].spans;
        assert!(!spans.iter().any(|s| s.content.contains("ALLOW")));
    }

    // -- System message -----------------------------------------------------

    #[test]
    fn render_system_is_dim() {
        let lines = render_system_message("Error: timeout");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].spans[0].style.fg, Some(Color::DarkGray));
    }

    // -- Result message -----------------------------------------------------

    #[test]
    fn render_result_is_green() {
        let lines = render_result_message("Done (45s, $0.15)");
        assert!(lines.len() >= 1);
        let result_line = lines
            .iter()
            .find(|l| !l.spans.is_empty() && l.spans[0].content.contains("Done"))
            .unwrap();
        assert_eq!(result_line.spans[0].style.fg, Some(Color::Green));
    }

    #[test]
    fn render_result_has_blank_separators() {
        let lines = render_result_message("Done (1s)");
        assert_eq!(lines.len(), 3);
    }

    // -- Dispatch -----------------------------------------------------------

    #[test]
    fn render_message_dispatches_user() {
        let msg = ChatMessage::new(MessageRole::User, "test".to_string());
        let lines = render_message(&msg, 80);
        let all_text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(all_text.contains("You:"));
    }

    #[test]
    fn render_message_dispatches_assistant() {
        let msg = ChatMessage::new(MessageRole::Assistant, "Hello world".to_string());
        let lines = render_message(&msg, 80);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].spans[0].content.as_ref(), "Hello world");
    }

    #[test]
    fn render_message_dispatches_system() {
        let msg = ChatMessage::new(MessageRole::System, "Error occurred".to_string());
        let lines = render_message(&msg, 80);
        assert_eq!(lines[0].spans[0].style.fg, Some(Color::DarkGray));
    }

    // -- Header -------------------------------------------------------------

    #[test]
    fn render_header_connected() {
        let line = render_header("claude-sonnet-4-20250514", Some("anthropic"), true, false, 80);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("Aegis"));
        assert!(text.contains("claude-sonnet-4-20250514"));
        assert!(text.contains("(anthropic)"));
        assert!(text.contains("Connected"));
    }

    #[test]
    fn render_header_disconnected() {
        let line = render_header("gpt-4o", Some("openai"), false, false, 80);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("Disconnected"));
        assert!(text.contains("(openai)"));
    }

    #[test]
    fn render_header_no_provider() {
        let line = render_header("custom-model", None, true, false, 80);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("custom-model"));
        assert!(!text.contains("("));
    }

    #[test]
    fn render_header_thinking() {
        let line = render_header("claude-sonnet-4-20250514", None, true, true, 80);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("Thinking..."));
    }

    #[test]
    fn render_header_thinking_is_yellow() {
        let line = render_header("model", None, true, true, 80);
        let status_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("Thinking"))
            .unwrap();
        assert_eq!(status_span.style.fg, Some(Color::Yellow));
    }

    #[test]
    fn render_header_connected_is_green() {
        let line = render_header("model", None, true, false, 80);
        let status_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("Connected"))
            .unwrap();
        assert_eq!(status_span.style.fg, Some(Color::Green));
    }

    // -- Status bar ---------------------------------------------------------

    #[test]
    fn render_status_bar_shows_model() {
        let line = render_status_bar("claude-sonnet-4-20250514", 80, None);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("claude-sonnet-4-20250514"));
        assert!(text.contains("/help"));
    }

    #[test]
    fn render_status_bar_shows_usage() {
        let usage = UsageInfo {
            total_tokens: 12345,
            cost_usd: 0.0234,
        };
        let line = render_status_bar("gpt-4o", 80, Some(&usage));
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("12345tok"));
        assert!(text.contains("$0.0234"));
    }
}
