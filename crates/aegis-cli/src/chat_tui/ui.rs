//! Layout assembly for the chat-centric TUI.
//!
//! Arranges the header, scrollable chat area, input box, and status bar
//! into a ratatui frame. Overlays the command bar on the status line
//! when command mode is active.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use super::markdown;
use super::message::MessageRole;
use super::render;
use super::{filter_model_items, ApprovalProfile, ChatApp, InputMode, Overlay};

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

    // Completion popup above command bar
    if app.input_mode == InputMode::Command && !app.command_completions.is_empty() {
        draw_completion_popup(f, app, chunks[3]);
    }

    // Overlay on top of everything
    if let Some(ref overlay) = app.overlay {
        draw_overlay(f, app, overlay, area);
    }
}

/// Draw the header bar.
fn draw_header(f: &mut Frame, app: &ChatApp, area: Rect) {
    let provider = resolve_provider_for_display(&app.model);
    let approval_label = super::approval_profile_label(&app.approval_profile);
    let header = render::render_header(
        &app.model,
        provider.as_deref(),
        app.connected,
        app.awaiting_response,
        Some(approval_label),
        area.width,
    );
    let para = Paragraph::new(vec![header])
        .style(Style::default().bg(Color::Rgb(30, 30, 30)));
    f.render_widget(para, area);
}

/// Look up the provider name for a model, for display in the header bar.
fn resolve_provider_for_display(model: &str) -> Option<String> {
    // Check exact match in the static provider catalog.
    for provider in aegis_types::providers::ALL_PROVIDERS {
        for m in provider.models {
            if m.id == model {
                return Some(provider.id.to_string());
            }
        }
    }
    // Fall back to prefix heuristic.
    let lower = model.to_lowercase();
    if lower.starts_with("claude-") {
        return Some("anthropic".into());
    }
    if lower.starts_with("gpt-")
        || lower.starts_with("o1-")
        || lower.starts_with("o3-")
        || lower.starts_with("o4-")
    {
        return Some("openai".into());
    }
    if lower.starts_with("gemini-") {
        return Some("google".into());
    }
    None
}

/// Draw the scrollable chat message area.
fn draw_chat_area(f: &mut Frame, app: &ChatApp, area: Rect) {
    if app.messages.is_empty() {
        let placeholder = if app.connected {
            "Type a message to start chatting..."
        } else {
            "Starting daemon... (or /daemon start)"
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
        InputMode::Command => "/ ",
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
    let usage = if app.show_usage && app.total_input_tokens + app.total_output_tokens > 0 {
        Some(render::UsageInfo {
            total_tokens: app.total_input_tokens + app.total_output_tokens,
            cost_usd: app.total_cost_usd,
        })
    } else {
        None
    };
    let status = render::render_status_bar(&app.model, area.width, usage.as_ref());
    let para = Paragraph::new(vec![status])
        .style(Style::default().bg(Color::Rgb(30, 30, 30)));
    f.render_widget(para, area);
}

/// Draw the command bar (replaces status bar when active).
fn draw_command_bar(f: &mut Frame, app: &ChatApp, area: Rect) {
    let mut spans = vec![Span::styled(
        "/".to_string(),
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

/// Compute a centered rectangle as a percentage of the parent area.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Dispatch overlay rendering based on the overlay type.
fn draw_overlay(f: &mut Frame, app: &ChatApp, overlay: &Overlay, area: Rect) {
    match overlay {
        Overlay::ModelPicker {
            items,
            filter,
            selected,
        } => draw_model_picker(f, items, filter, *selected, area),
        Overlay::SessionPicker { items, selected } => {
            draw_session_picker(f, items, *selected, area);
        }
        Overlay::Settings { selected } => {
            draw_settings(f, app, *selected, area);
        }
    }
}

/// Draw the model picker overlay with filter and scrollable list.
fn draw_model_picker(
    f: &mut Frame,
    items: &[(String, String)],
    filter: &str,
    selected: usize,
    area: Rect,
) {
    let popup = centered_rect(60, 70, area);
    f.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Model Picker (type to filter, Enter to select, Esc to cancel) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Rgb(25, 25, 25)));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    if inner.height < 3 {
        return;
    }

    // Filter input row
    let filter_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: 1,
    };
    let filter_display = if filter.is_empty() {
        Span::styled(
            " Filter...",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(
            format!(" {filter}"),
            Style::default().fg(Color::White),
        )
    };
    f.render_widget(Paragraph::new(Line::from(filter_display)), filter_area);

    // Separator
    let sep_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: 1,
    };
    let sep = Paragraph::new(Line::from(Span::styled(
        "\u{2500}".repeat(inner.width as usize),
        Style::default().fg(Color::Rgb(60, 60, 60)),
    )));
    f.render_widget(sep, sep_area);

    // Filtered item list
    let list_area = Rect {
        x: inner.x,
        y: inner.y + 2,
        width: inner.width,
        height: inner.height.saturating_sub(2),
    };

    let filtered = filter_model_items(items, filter);
    if filtered.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            " No matching models",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(msg, list_area);
        return;
    }

    // Scroll so selected item is visible.
    let visible = list_area.height as usize;
    let scroll_offset = if selected >= visible {
        selected - visible + 1
    } else {
        0
    };

    let lines: Vec<Line<'static>> = filtered
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible)
        .map(|(i, (id, label))| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            let text = format!(" {id:40} {label}");
            let truncated: String = text.chars().take(list_area.width as usize).collect();
            Line::from(Span::styled(truncated, style))
        })
        .collect();

    f.render_widget(Paragraph::new(lines), list_area);
}

/// Draw the session picker overlay.
fn draw_session_picker(
    f: &mut Frame,
    items: &[super::persistence::ConversationMeta],
    selected: usize,
    area: Rect,
) {
    let popup = centered_rect(70, 60, area);
    f.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Sessions (Enter to resume, d to delete, Esc to cancel) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Rgb(25, 25, 25)));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    if inner.height < 2 || items.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            " No saved sessions",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(msg, inner);
        return;
    }

    // Header row
    let header_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: 1,
    };
    let header = Paragraph::new(Line::from(Span::styled(
        format!(" {:8} {:30} {:>5}  {}", "ID", "Model", "Msgs", "Timestamp"),
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )));
    f.render_widget(header, header_area);

    let list_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: inner.height.saturating_sub(1),
    };

    let visible = list_area.height as usize;
    let scroll_offset = if selected >= visible {
        selected - visible + 1
    } else {
        0
    };

    let lines: Vec<Line<'static>> = items
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible)
        .map(|(i, m)| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            // Truncate timestamp to date portion for display.
            let ts: String = m.timestamp.chars().take(10).collect();
            let text = format!(
                " {:8} {:30} {:>5}  {}",
                m.id, m.model, m.message_count, ts,
            );
            let truncated: String = text.chars().take(inner.width as usize).collect();
            Line::from(Span::styled(truncated, style))
        })
        .collect();

    f.render_widget(Paragraph::new(lines), list_area);
}

/// Draw the settings overlay.
fn draw_settings(f: &mut Frame, app: &ChatApp, selected: usize, area: Rect) {
    let popup = centered_rect(50, 40, area);
    f.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Settings (arrows to navigate, Enter/Space to change, Esc to close) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Rgb(25, 25, 25)));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let settings: Vec<(&str, String)> = vec![
        (
            "Show Usage",
            if app.show_usage {
                "ON".to_string()
            } else {
                "OFF".to_string()
            },
        ),
        (
            "Thinking",
            match app.thinking_budget {
                None => "OFF".to_string(),
                Some(1024) => "Low (1024)".to_string(),
                Some(4096) => "Medium (4096)".to_string(),
                Some(16384) => "High (16384)".to_string(),
                Some(n) => format!("Custom ({n})"),
            },
        ),
        (
            "Approval",
            match &app.approval_profile {
                ApprovalProfile::Manual => "Manual".to_string(),
                ApprovalProfile::AutoApprove(risk) => format!("Auto ({risk:?})"),
                ApprovalProfile::FullAuto => "Full Auto".to_string(),
            },
        ),
    ];

    let lines: Vec<Line<'static>> = settings
        .into_iter()
        .enumerate()
        .map(|(i, (label, value))| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            let arrow = if i == selected { ">" } else { " " };
            Line::from(Span::styled(
                format!(" {arrow} {label:20} {value}"),
                style,
            ))
        })
        .collect();

    f.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_spans_empty_input() {
        let spans = build_cursor_spans("", 0);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content.as_ref(), " ");
        assert_eq!(spans[0].style.fg, Some(Color::Black));
        assert_eq!(spans[0].style.bg, Some(Color::White));
    }

    #[test]
    fn cursor_spans_at_start() {
        let spans = build_cursor_spans("hello", 0);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].content.as_ref(), "h");
        assert_eq!(spans[0].style.bg, Some(Color::White));
        assert_eq!(spans[1].content.as_ref(), "ello");
    }

    #[test]
    fn cursor_spans_at_middle() {
        let spans = build_cursor_spans("hello", 2);
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[0].content.as_ref(), "he");
        assert_eq!(spans[1].content.as_ref(), "l");
        assert_eq!(spans[1].style.bg, Some(Color::White));
        assert_eq!(spans[2].content.as_ref(), "lo");
    }

    #[test]
    fn cursor_spans_at_end() {
        let spans = build_cursor_spans("hello", 5);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].content.as_ref(), "hello");
        assert_eq!(spans[1].content.as_ref(), " ");
        assert_eq!(spans[1].style.bg, Some(Color::White));
    }
}
