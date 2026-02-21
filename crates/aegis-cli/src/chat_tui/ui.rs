//! Layout assembly for the chat-centric TUI.
//!
//! Arranges the header, scrollable chat area, input box, and status bar
//! into a ratatui frame. Overlays the command bar on the status line
//! when command mode is active, and an agent picker popup when visible.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use super::markdown;
use super::message::MessageRole;
use super::render;
use super::ChatApp;
use super::InputMode;

use aegis_types::AgentStatus;

/// Draw the complete chat TUI frame.
pub fn draw(f: &mut Frame, app: &mut ChatApp) {
    let area = f.area();

    // Compute input height: 3 lines normally, grows if multi-line paste
    let newline_count = app.input_buffer.chars().filter(|c| *c == '\n').count();
    let input_height = (3 + newline_count).min(8) as u16;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),       // header
            Constraint::Min(5),          // chat area
            Constraint::Length(input_height), // input
            Constraint::Length(1),       // status bar / command bar
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    draw_chat_area(f, app, chunks[1]);
    draw_input_area(f, app, chunks[2]);

    if app.input_mode == InputMode::Command {
        draw_command_bar(f, app, chunks[3]);
    } else {
        draw_status_bar(f, app, chunks[3]);
    }

    // Agent picker overlay
    if app.agent_picker_visible {
        draw_agent_picker(f, app, area);
    }

    // Completion popup above command bar
    if app.input_mode == InputMode::Command && !app.command_completions.is_empty() {
        draw_completion_popup(f, app, chunks[3]);
    }
}

/// Draw the header bar.
fn draw_header(f: &mut Frame, app: &ChatApp, area: Rect) {
    let (agent_name, status_str, mediation) = match &app.active_agent {
        Some(name) => {
            let status = app
                .agents
                .iter()
                .find(|a| a.name == *name)
                .map(|a| format_agent_status(&a.status))
                .unwrap_or_else(|| "Unknown".to_string());
            let med = app.security.mediation_mode.clone();
            (name.as_str(), status, if med.is_empty() { "unknown".to_string() } else { med })
        }
        None => ("(no agent)", "Disconnected".to_string(), "unknown".to_string()),
    };

    let pending_count = app.pending_prompts.len();
    let header = render::render_header(
        agent_name,
        &status_str,
        &mediation,
        pending_count,
        area.width,
    );
    let para = Paragraph::new(vec![header])
        .style(Style::default().bg(Color::Rgb(30, 30, 30)));
    f.render_widget(para, area);
}

/// Draw the scrollable chat message area.
fn draw_chat_area(f: &mut Frame, app: &ChatApp, area: Rect) {
    if app.messages.is_empty() {
        let placeholder = if app.connected {
            if app.active_agent.is_some() {
                "Waiting for agent output..."
            } else {
                "No agent selected. Use :follow <agent> or :chat"
            }
        } else {
            "Not connected to daemon. Use :daemon start"
        };
        let para = Paragraph::new(Line::from(Span::styled(
            format!("  {placeholder}"),
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(para, area);
        return;
    }

    // Convert all messages to lines
    let mut all_lines: Vec<Line<'static>> = Vec::new();
    for msg in &app.messages {
        let lines = match &msg.role {
            MessageRole::Assistant => {
                // Pipe assistant content through markdown renderer
                markdown::render_markdown(&msg.content, Style::default())
            }
            _ => render::render_message(msg, area.width),
        };
        all_lines.extend(lines);
    }

    // Handle scrolling: scroll_offset=0 means bottom (latest)
    let total_lines = all_lines.len();
    let visible_height = area.height as usize;
    let scroll_from_top = if total_lines > visible_height {
        total_lines
            .saturating_sub(visible_height)
            .saturating_sub(app.scroll_offset)
    } else {
        0
    };

    let para = Paragraph::new(all_lines)
        .scroll((scroll_from_top as u16, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);

    // Scroll indicator
    if app.scroll_offset > 0 {
        let indicator = Span::styled(
            format!(" [{} lines above] ", app.scroll_offset),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::DIM),
        );
        let indicator_line = Paragraph::new(Line::from(indicator));
        // Render at the bottom of the chat area
        let indicator_area = Rect {
            x: area.x,
            y: area.y + area.height.saturating_sub(1),
            width: area.width,
            height: 1,
        };
        f.render_widget(indicator_line, indicator_area);
    }
}

/// Draw the input area with cursor.
fn draw_input_area(f: &mut Frame, app: &ChatApp, area: Rect) {
    let mode_indicator = match app.input_mode {
        InputMode::Chat => "> ",
        InputMode::Scroll => "SCROLL ",
        InputMode::Command => ": ",
    };

    let mut spans = vec![Span::styled(
        mode_indicator.to_string(),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )];

    // Build input text with cursor highlight
    let cursor_spans = build_cursor_spans(&app.input_buffer, app.input_cursor);
    spans.extend(cursor_spans);

    let input_para = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::Rgb(60, 60, 60))),
    );
    f.render_widget(input_para, area);

    // Show command result or error below input if present
    if let Some(ref result) = app.command_result {
        if area.height > 2 {
            let result_area = Rect {
                x: area.x,
                y: area.y + 2,
                width: area.width,
                height: 1,
            };
            let result_para = Paragraph::new(Line::from(Span::styled(
                format!("  {result}"),
                Style::default().fg(Color::DarkGray),
            )));
            f.render_widget(result_para, result_area);
        }
    } else if let Some(ref err) = app.last_error {
        if area.height > 2 {
            let err_area = Rect {
                x: area.x,
                y: area.y + 2,
                width: area.width,
                height: 1,
            };
            let err_para = Paragraph::new(Line::from(Span::styled(
                format!("  {err}"),
                Style::default().fg(Color::Red),
            )));
            f.render_widget(err_para, err_area);
        }
    }
}

/// Draw the status bar.
fn draw_status_bar(f: &mut Frame, app: &ChatApp, area: Rect) {
    let status = render::render_status_bar(
        &app.security.policy_mode,
        app.security.audit_entries,
        app.security.audit_chain_ok,
        app.security.sandbox_active,
        app.agents.len(),
        area.width,
    );
    let para = Paragraph::new(vec![status])
        .style(Style::default().bg(Color::Rgb(30, 30, 30)));
    f.render_widget(para, area);
}

/// Draw the command bar (replaces status bar when active).
fn draw_command_bar(f: &mut Frame, app: &ChatApp, area: Rect) {
    let mut spans = vec![Span::styled(
        ":".to_string(),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )];

    let cursor_spans = build_cursor_spans(&app.command_buffer, app.command_cursor);
    spans.extend(cursor_spans);

    let para = Paragraph::new(Line::from(spans))
        .style(Style::default().bg(Color::Rgb(30, 30, 30)));
    f.render_widget(para, area);
}

/// Draw a completion popup above the command bar.
fn draw_completion_popup(f: &mut Frame, app: &ChatApp, cmd_area: Rect) {
    let completions = &app.command_completions;
    let max_show = completions.len().min(8);
    if max_show == 0 {
        return;
    }

    let popup_height = max_show as u16;
    let popup_y = cmd_area.y.saturating_sub(popup_height);
    let popup_width = completions
        .iter()
        .map(|c| c.len())
        .max()
        .unwrap_or(10)
        .min(40) as u16
        + 4;

    let popup_area = Rect {
        x: cmd_area.x + 1, // offset past the ':'
        y: popup_y,
        width: popup_width.min(cmd_area.width),
        height: popup_height,
    };

    f.render_widget(Clear, popup_area);

    let lines: Vec<Line<'static>> = completions
        .iter()
        .take(max_show)
        .enumerate()
        .map(|(i, c)| {
            let style = if app.completion_idx == Some(i) {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(format!(" {c} "), style))
        })
        .collect();

    let para = Paragraph::new(lines)
        .style(Style::default().bg(Color::Rgb(40, 40, 40)));
    f.render_widget(para, popup_area);
}

/// Draw the agent picker overlay (centered popup).
fn draw_agent_picker(f: &mut Frame, app: &ChatApp, area: Rect) {
    let agents = &app.agents;
    if agents.is_empty() {
        return;
    }

    let popup_width = 50u16.min(area.width.saturating_sub(4));
    let popup_height = (agents.len() as u16 + 3).min(area.height.saturating_sub(4));

    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect {
        x,
        y,
        width: popup_width,
        height: popup_height,
    };

    f.render_widget(Clear, popup_area);

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(Span::styled(
        " Select Agent:".to_string(),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    for (i, agent) in agents.iter().enumerate() {
        let prefix = if i == app.agent_picker_selected {
            " > "
        } else {
            "   "
        };
        let status_str = format_agent_status(&agent.status);
        let pending_str = if agent.pending_count > 0 {
            format!("  {} pending", agent.pending_count)
        } else {
            "  -".to_string()
        };

        let style = if i == app.agent_picker_selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };

        lines.push(Line::from(vec![
            Span::styled(prefix.to_string(), style),
            Span::styled(
                format!("{:<16}", agent.name),
                style,
            ),
            Span::styled(format!("[{status_str}]"), style_for_status(&agent.status)),
            Span::styled(pending_str, Style::default().fg(Color::DarkGray)),
        ]));
    }

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Agents "),
        )
        .style(Style::default().bg(Color::Rgb(20, 20, 20)));
    f.render_widget(para, popup_area);
}

/// Build spans for text with a cursor highlight at the given position.
///
/// Text before the cursor is rendered in the default style. The character
/// at the cursor position is rendered with inverted colors. Text after
/// the cursor is rendered in the default style.
fn build_cursor_spans(text: &str, cursor: usize) -> Vec<Span<'static>> {
    let mut spans = Vec::new();

    if text.is_empty() {
        // Show block cursor on empty input
        spans.push(Span::styled(
            " ".to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(Color::White),
        ));
        return spans;
    }

    let (before, rest) = text.split_at(cursor.min(text.len()));

    if !before.is_empty() {
        spans.push(Span::raw(before.to_string()));
    }

    if rest.is_empty() {
        // Cursor at end: show block
        spans.push(Span::styled(
            " ".to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(Color::White),
        ));
    } else {
        // Cursor on a character: highlight it
        let mut chars = rest.chars();
        let cursor_char = chars.next().unwrap();
        spans.push(Span::styled(
            cursor_char.to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(Color::White),
        ));
        let after: String = chars.collect();
        if !after.is_empty() {
            spans.push(Span::raw(after));
        }
    }

    spans
}

/// Format an AgentStatus as a short string.
fn format_agent_status(status: &AgentStatus) -> String {
    match status {
        AgentStatus::Pending => "Pending".to_string(),
        AgentStatus::Running { .. } => "Running".to_string(),
        AgentStatus::Stopped { .. } => "Stopped".to_string(),
        AgentStatus::Crashed { .. } => "Crashed".to_string(),
        AgentStatus::Failed { .. } => "Failed".to_string(),
        AgentStatus::Stopping => "Stopping".to_string(),
        AgentStatus::Disabled => "Disabled".to_string(),
    }
}

/// Get a style color for an agent status.
fn style_for_status(status: &AgentStatus) -> Style {
    match status {
        AgentStatus::Running { .. } => Style::default().fg(Color::Green),
        AgentStatus::Stopped { .. } => Style::default().fg(Color::DarkGray),
        AgentStatus::Crashed { .. } | AgentStatus::Failed { .. } => {
            Style::default().fg(Color::Red)
        }
        AgentStatus::Pending | AgentStatus::Stopping => Style::default().fg(Color::Yellow),
        AgentStatus::Disabled => Style::default().fg(Color::DarkGray),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_spans_empty_input() {
        let spans = build_cursor_spans("", 0);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content.as_ref(), " ");
        // Should have inverted style
        assert_eq!(spans[0].style.fg, Some(Color::Black));
        assert_eq!(spans[0].style.bg, Some(Color::White));
    }

    #[test]
    fn cursor_spans_at_start() {
        let spans = build_cursor_spans("hello", 0);
        // No before text, cursor on 'h', after "ello"
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].content.as_ref(), "h"); // cursor char
        assert_eq!(spans[0].style.bg, Some(Color::White));
        assert_eq!(spans[1].content.as_ref(), "ello");
    }

    #[test]
    fn cursor_spans_at_middle() {
        let spans = build_cursor_spans("hello", 2);
        // before "he", cursor on 'l', after "lo"
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[0].content.as_ref(), "he");
        assert_eq!(spans[1].content.as_ref(), "l");
        assert_eq!(spans[1].style.bg, Some(Color::White));
        assert_eq!(spans[2].content.as_ref(), "lo");
    }

    #[test]
    fn cursor_spans_at_end() {
        let spans = build_cursor_spans("hello", 5);
        // before "hello", cursor block at end
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].content.as_ref(), "hello");
        assert_eq!(spans[1].content.as_ref(), " "); // block cursor
        assert_eq!(spans[1].style.bg, Some(Color::White));
    }

    #[test]
    fn format_status_running() {
        assert_eq!(
            format_agent_status(&AgentStatus::Running { pid: 1 }),
            "Running"
        );
    }

    #[test]
    fn format_status_stopped() {
        assert_eq!(
            format_agent_status(&AgentStatus::Stopped { exit_code: 0 }),
            "Stopped"
        );
    }

    #[test]
    fn format_status_pending() {
        assert_eq!(format_agent_status(&AgentStatus::Pending), "Pending");
    }
}
