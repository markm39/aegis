//! Chat message rendering for the chat-centric TUI.
//!
//! Converts [`ChatMessage`] objects and UI chrome (header bar, status bar) into
//! styled ratatui [`Line`] objects ready for terminal display.
//!
//! Color mapping for tool names is kept consistent with the fleet TUI
//! (`fleet_tui/ui.rs:658-669`).

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::message::{ChatMessage, MessageRole};

// ---------------------------------------------------------------------------
// Tool color mapping
// ---------------------------------------------------------------------------

/// Map a tool name to its display color.
///
/// This palette matches the fleet TUI (`fleet_tui/ui.rs:658-669`) so colors
/// are consistent across both interfaces.
pub fn tool_color(name: &str) -> Color {
    match name {
        "Bash" => Color::Rgb(253, 93, 177), // hot pink (Claude Code bash border)
        "Read" | "Write" | "Edit" | "Glob" | "NotebookRead" | "NotebookEdit" => Color::Cyan,
        "Grep" | "WebSearch" | "WebFetch" => Color::Rgb(177, 185, 249), // light purple-blue
        "Task" => Color::Rgb(215, 119, 87),                             // Claude brand color
        "LSP" => Color::Rgb(177, 185, 249),
        _ => Color::White,
    }
}

// ---------------------------------------------------------------------------
// Message rendering
// ---------------------------------------------------------------------------

/// Render a user message.
///
/// Format:
/// ```text
///                         (blank line)
/// You:
///   <content line 1>
///   <content line 2>
///                         (blank line)
/// ```
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

/// Render an assistant (agent) text message.
///
/// For now this outputs plain white text. The markdown module will be plugged
/// in via `mod.rs` to add inline formatting later.
pub fn render_assistant_message(content: &str, _width: u16) -> Vec<Line<'static>> {
    content
        .lines()
        .map(|line| Line::from(Span::raw(line.to_string())))
        .collect()
}

/// Render a tool call line.
///
/// Format (single line, badge right-aligned to terminal width):
/// ```text
///  > ToolName: summary                              [ALLOW]
/// ```
///
/// The tool name is colored per [`tool_color`]. The verdict badge is green for
/// allow, red for deny, yellow for ask, or absent if `None`.
pub fn render_tool_call(
    tool_name: &str,
    summary: &str,
    verdict: Option<&str>, // "allow", "deny", "ask", or None
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

    // Calculate padding so the badge sits at the right edge.
    //   prefix (3) + "ToolName: " (name+2) + summary + padding + badge
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
///
/// Displayed as a yellow-bordered block with the prompt text and Y/N key
/// hints so the user knows how to respond.
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

/// Render a system message (session start, compaction, nudge, etc.).
///
/// Format: dim gray, indented two spaces.
pub fn render_system_message(content: &str) -> Vec<Line<'static>> {
    vec![Line::from(Span::styled(
        format!("  {content}"),
        Style::default().fg(Color::DarkGray),
    ))]
}

/// Render a result/completion message.
///
/// Format: green text with blank lines above and below for visual separation.
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
///
/// This is the main entry point used by the chat TUI layout code. It
/// dispatches to the type-specific render functions above based on the
/// message's role.
pub fn render_message(msg: &ChatMessage, width: u16) -> Vec<Line<'static>> {
    match &msg.role {
        MessageRole::User => render_user_message(&msg.content, width),
        MessageRole::Assistant => render_assistant_message(&msg.content, width),
        MessageRole::ToolCall { tool_name, summary } => {
            // No verdict info on the ChatMessage itself -- the security
            // overlay provides that separately. Render without badge.
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
///  Aegis | agent_name [Status] | mediation:mode | N pending
/// ```
pub fn render_header(
    agent_name: &str,
    status: &str,
    mediation: &str,
    pending_count: usize,
    _width: u16,
) -> Line<'static> {
    let status_color = match status {
        "Running" => Color::Green,
        "Stopped" => Color::DarkGray,
        "Crashed" | "Failed" => Color::Red,
        _ => Color::Yellow,
    };

    let mut spans = vec![
        Span::styled(
            " Aegis".to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | ".to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(
            agent_name.to_string(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ".to_string()),
        Span::styled(format!("[{status}]"), Style::default().fg(status_color)),
        Span::styled(" | ".to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("mediation:{mediation}"),
            Style::default().fg(Color::DarkGray),
        ),
    ];

    if pending_count > 0 {
        spans.push(Span::styled(
            " | ".to_string(),
            Style::default().fg(Color::DarkGray),
        ));
        spans.push(Span::styled(
            format!("{pending_count} pending"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }

    Line::from(spans)
}

/// Render the security-posture status bar (single line at the bottom).
///
/// Format:
/// ```text
///  policy:strict  audit:1247#ok  sandbox:on  2 agents  :help
/// ```
pub fn render_status_bar(
    policy_mode: &str,
    audit_count: u64,
    audit_ok: bool,
    sandbox_active: bool,
    agent_count: usize,
    _width: u16,
) -> Line<'static> {
    let audit_status = if audit_ok { "ok" } else { "TAMPERED" };
    let audit_color = if audit_ok { Color::Green } else { Color::Red };
    let sandbox_str = if sandbox_active { "on" } else { "off" };
    let sandbox_color = if sandbox_active {
        Color::Green
    } else {
        Color::Yellow
    };

    Line::from(vec![
        Span::styled(
            format!(" policy:{policy_mode}"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("  ".to_string()),
        Span::styled(
            format!("audit:{audit_count}#{audit_status}"),
            Style::default().fg(audit_color),
        ),
        Span::raw("  ".to_string()),
        Span::styled(
            format!("sandbox:{sandbox_str}"),
            Style::default().fg(sandbox_color),
        ),
        Span::raw("  ".to_string()),
        Span::styled(
            format!("{agent_count} agents"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("  ".to_string()),
        Span::styled(":help".to_string(), Style::default().fg(Color::DarkGray)),
    ])
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
    fn tool_color_write_is_cyan() {
        assert_eq!(tool_color("Write"), Color::Cyan);
    }

    #[test]
    fn tool_color_edit_is_cyan() {
        assert_eq!(tool_color("Edit"), Color::Cyan);
    }

    #[test]
    fn tool_color_glob_is_cyan() {
        assert_eq!(tool_color("Glob"), Color::Cyan);
    }

    #[test]
    fn tool_color_grep_is_purple() {
        assert_eq!(tool_color("Grep"), Color::Rgb(177, 185, 249));
    }

    #[test]
    fn tool_color_websearch_is_purple() {
        assert_eq!(tool_color("WebSearch"), Color::Rgb(177, 185, 249));
    }

    #[test]
    fn tool_color_webfetch_is_purple() {
        assert_eq!(tool_color("WebFetch"), Color::Rgb(177, 185, 249));
    }

    #[test]
    fn tool_color_task_is_brand() {
        assert_eq!(tool_color("Task"), Color::Rgb(215, 119, 87));
    }

    #[test]
    fn tool_color_lsp_is_purple() {
        assert_eq!(tool_color("LSP"), Color::Rgb(177, 185, 249));
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
    fn render_tool_call_with_deny() {
        let lines = render_tool_call("Write", "dangerous.rs", Some("deny"), 80);
        let spans = &lines[0].spans;
        assert!(spans.iter().any(|s| s.content.contains("DENY")));
    }

    #[test]
    fn render_tool_call_with_ask() {
        let lines = render_tool_call("Bash", "rm -rf /", Some("ask"), 80);
        let spans = &lines[0].spans;
        assert!(spans.iter().any(|s| s.content.contains("ASK")));
    }

    #[test]
    fn render_tool_call_no_verdict() {
        let lines = render_tool_call("Read", "main.rs", None, 80);
        assert_eq!(lines.len(), 1);
        let spans = &lines[0].spans;
        // No badge text.
        assert!(!spans.iter().any(|s| s.content.contains("ALLOW")));
        assert!(!spans.iter().any(|s| s.content.contains("DENY")));
    }

    #[test]
    fn render_tool_call_name_colored() {
        let lines = render_tool_call("Bash", "echo hi", None, 80);
        let name_span = &lines[0].spans[1]; // prefix is [0], name is [1]
        assert_eq!(name_span.style.fg, Some(Color::Rgb(253, 93, 177)));
    }

    #[test]
    fn render_tool_call_narrow_width() {
        // Should not panic even when width is very small.
        let lines = render_tool_call("Bash", "a very long command summary", Some("allow"), 10);
        assert_eq!(lines.len(), 1);
    }

    // -- Permission ---------------------------------------------------------

    #[test]
    fn render_permission_pending_shows_yn() {
        let lines = render_permission_pending("Allow file write?", 80);
        assert!(lines.len() >= 3);
        let all_text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(all_text.contains("[Y]"));
        assert!(all_text.contains("[N]"));
    }

    #[test]
    fn render_permission_pending_shows_prompt() {
        let lines = render_permission_pending("Allow file write?", 80);
        let all_text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(all_text.contains("Allow file write?"));
    }

    #[test]
    fn render_permission_resolved_approved() {
        let lines = render_permission_resolved("file write", true);
        assert_eq!(lines.len(), 1);
        let spans = &lines[0].spans;
        assert!(spans[0].content.contains("APPROVED"));
        assert_eq!(spans[0].style.fg, Some(Color::Green));
    }

    #[test]
    fn render_permission_resolved_denied() {
        let lines = render_permission_resolved("file write", false);
        assert_eq!(lines.len(), 1);
        let spans = &lines[0].spans;
        assert!(spans[0].content.contains("DENIED"));
        assert_eq!(spans[0].style.fg, Some(Color::Red));
    }

    // -- System message -----------------------------------------------------

    #[test]
    fn render_system_is_dim() {
        let lines = render_system_message("Session started");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].spans[0].style.fg, Some(Color::DarkGray));
    }

    #[test]
    fn render_system_indented() {
        let lines = render_system_message("Session started");
        assert!(lines[0].spans[0].content.starts_with("  "));
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
        // First and last lines are blank.
        assert!(lines[0].spans.is_empty() || lines[0].spans[0].content.is_empty());
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
    fn render_message_dispatches_tool_call() {
        let msg = ChatMessage::new(
            MessageRole::ToolCall {
                tool_name: "Bash".to_string(),
                summary: "echo hi".to_string(),
            },
            "> Bash: echo hi".to_string(),
        );
        let lines = render_message(&msg, 80);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn render_message_dispatches_pending_permission() {
        let msg = ChatMessage::new(
            MessageRole::Permission {
                prompt: "Allow write?".to_string(),
                resolved: None,
            },
            "[PENDING] Allow write?".to_string(),
        );
        let lines = render_message(&msg, 80);
        assert!(lines.len() >= 3);
    }

    #[test]
    fn render_message_dispatches_resolved_permission() {
        let msg = ChatMessage::new(
            MessageRole::Permission {
                prompt: "Allow write?".to_string(),
                resolved: Some(true),
            },
            "[APPROVED] Allow write?".to_string(),
        );
        let lines = render_message(&msg, 80);
        let all_text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(all_text.contains("APPROVED"));
    }

    #[test]
    fn render_message_dispatches_system() {
        let msg = ChatMessage::new(MessageRole::System, "Session started".to_string());
        let lines = render_message(&msg, 80);
        assert_eq!(lines[0].spans[0].style.fg, Some(Color::DarkGray));
    }

    #[test]
    fn render_message_dispatches_result() {
        let msg = ChatMessage::new(
            MessageRole::Result {
                summary: "Done (2s)".to_string(),
            },
            "Done (2s)".to_string(),
        );
        let lines = render_message(&msg, 80);
        assert_eq!(lines.len(), 3); // blank, content, blank
    }

    // -- Header -------------------------------------------------------------

    #[test]
    fn render_header_shows_agent_name() {
        let line = render_header("claude-1", "Running", "enforced", 2, 80);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("claude-1"));
        assert!(text.contains("Running"));
        assert!(text.contains("2 pending"));
    }

    #[test]
    fn render_header_no_pending() {
        let line = render_header("agent-0", "Stopped", "permissive", 0, 80);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("agent-0"));
        assert!(!text.contains("pending"));
    }

    #[test]
    fn render_header_running_is_green() {
        let line = render_header("a", "Running", "strict", 0, 80);
        let status_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("[Running]"))
            .unwrap();
        assert_eq!(status_span.style.fg, Some(Color::Green));
    }

    #[test]
    fn render_header_crashed_is_red() {
        let line = render_header("a", "Crashed", "strict", 0, 80);
        let status_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("[Crashed]"))
            .unwrap();
        assert_eq!(status_span.style.fg, Some(Color::Red));
    }

    // -- Status bar ---------------------------------------------------------

    #[test]
    fn render_status_bar_shows_posture() {
        let line = render_status_bar("strict", 1247, true, true, 2, 80);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("policy:strict"));
        assert!(text.contains("audit:1247#ok"));
        assert!(text.contains("sandbox:on"));
    }

    #[test]
    fn render_status_bar_tampered_audit() {
        let line = render_status_bar("strict", 500, false, true, 1, 80);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("TAMPERED"));
    }

    #[test]
    fn render_status_bar_sandbox_off() {
        let line = render_status_bar("permissive", 0, true, false, 0, 80);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("sandbox:off"));
    }

    #[test]
    fn render_status_bar_audit_ok_is_green() {
        let line = render_status_bar("strict", 100, true, true, 1, 80);
        let audit_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("audit:"))
            .unwrap();
        assert_eq!(audit_span.style.fg, Some(Color::Green));
    }

    #[test]
    fn render_status_bar_audit_tampered_is_red() {
        let line = render_status_bar("strict", 100, false, true, 1, 80);
        let audit_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("audit:"))
            .unwrap();
        assert_eq!(audit_span.style.fg, Some(Color::Red));
    }
}
