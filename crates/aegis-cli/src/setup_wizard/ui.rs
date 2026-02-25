//! Shared rendering for setup wizard overlays.
//!
//! Both the chat TUI and onboarding wizard use these functions to render
//! setup wizard state as a centered popup.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::SetupStep;

/// Draw a setup wizard step as a centered popup overlay.
pub fn draw_setup_wizard(f: &mut Frame, step: &SetupStep, area: Rect) {
    let popup = centered_rect(65, 60, area);
    f.render_widget(Clear, popup);

    let title = format!(" {} ", step.title);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Rgb(25, 25, 25)));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    if inner.height < 4 {
        return;
    }

    let mut y = inner.y;

    // Instructions
    for line_text in &step.instructions {
        if y >= inner.y + inner.height {
            break;
        }
        let style = Style::default().fg(Color::White);
        let line = Line::from(Span::styled(format!("  {line_text}"), style));
        f.render_widget(
            Paragraph::new(line),
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: 1,
            },
        );
        y += 1;
    }

    // Blank line after instructions
    if !step.instructions.is_empty() {
        y += 1;
    }

    // Waiting spinner
    if step.is_waiting && y < inner.y + inner.height {
        let spinner_chars = ['-', '\\', '|', '/'];
        let idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis()
            / 250) as usize
            % spinner_chars.len();
        let spinner = spinner_chars[idx];

        let status_text = step.status.as_deref().unwrap_or("Working...");
        let line = Line::from(vec![
            Span::styled(
                format!("  {spinner} "),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(status_text.to_string(), Style::default().fg(Color::Yellow)),
        ]);
        f.render_widget(
            Paragraph::new(line),
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: 1,
            },
        );
        y += 1;
    }

    // Input fields (supports multiple with active highlighting)
    for (i, input) in step.inputs.iter().enumerate() {
        let is_active = i == step.active_input;

        if y >= inner.y + inner.height {
            break;
        }

        // Label
        let label_color = if is_active {
            Color::Cyan
        } else {
            Color::DarkGray
        };
        let label_line = Line::from(Span::styled(
            format!("  {}", input.label),
            Style::default()
                .fg(label_color)
                .add_modifier(Modifier::BOLD),
        ));
        f.render_widget(
            Paragraph::new(label_line),
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: 1,
            },
        );
        y += 1;

        if y >= inner.y + inner.height {
            break;
        }

        // Input line with optional cursor
        let display_text = if input.masked && !input.value.is_empty() {
            let chars: Vec<char> = input.value.chars().collect();
            if chars.len() > 4 {
                let hidden: String = "\u{2022}".repeat(chars.len() - 4);
                let visible: String = chars[chars.len() - 4..].iter().collect();
                format!("{hidden}{visible}")
            } else {
                input.value.clone()
            }
        } else {
            input.value.clone()
        };

        let prefix_style = Style::default()
            .fg(if is_active { Color::Cyan } else { Color::DarkGray })
            .add_modifier(Modifier::BOLD);

        let mut spans = vec![Span::styled("  > ".to_string(), prefix_style)];

        if is_active {
            let char_cursor = input.value[..input.cursor.min(input.value.len())]
                .chars()
                .count();
            let display_cursor = display_text
                .char_indices()
                .nth(char_cursor)
                .map(|(idx, _)| idx)
                .unwrap_or(display_text.len());
            spans.extend(build_cursor_spans(&display_text, display_cursor));
        } else {
            let text_style = if input.value.is_empty() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::White)
            };
            let shown = if input.value.is_empty() {
                "(empty)".to_string()
            } else {
                display_text
            };
            spans.push(Span::styled(shown, text_style));
        }

        f.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: 1,
            },
        );
        y += 1;

        // Small gap between fields (but not after last)
        if i + 1 < step.inputs.len() {
            y += 1;
        }
    }

    // Status message (non-waiting)
    if !step.is_waiting {
        if let Some(ref status) = step.status {
            if y < inner.y + inner.height {
                y += 1; // blank line before status
            }
            if y < inner.y + inner.height {
                let line = Line::from(Span::styled(
                    format!("  {status}"),
                    Style::default().fg(Color::Green),
                ));
                f.render_widget(
                    Paragraph::new(line),
                    Rect {
                        x: inner.x,
                        y,
                        width: inner.width,
                        height: 1,
                    },
                );
                y += 1;
            }
        }
    }

    // Error message
    if let Some(ref err) = step.error {
        if y < inner.y + inner.height {
            y += 1; // blank line before error
        }
        if y < inner.y + inner.height {
            let line = Line::from(Span::styled(
                format!("  {err}"),
                Style::default().fg(Color::Red),
            ));
            f.render_widget(
                Paragraph::new(line),
                Rect {
                    x: inner.x,
                    y,
                    width: inner.width,
                    height: 1,
                },
            );
            y += 1;
        }
    }

    // Help text at bottom
    let _ = y; // suppress unused warning
    let help_y = inner.y + inner.height - 1;
    if help_y > inner.y {
        let help_line = Line::from(Span::styled(
            format!("  {}", step.help),
            Style::default().fg(Color::DarkGray),
        ));
        f.render_widget(
            Paragraph::new(help_line),
            Rect {
                x: inner.x,
                y: help_y,
                width: inner.width,
                height: 1,
            },
        );
    }
}

/// Build spans for text with an inverted cursor block at the given byte offset.
fn build_cursor_spans(text: &str, cursor: usize) -> Vec<Span<'static>> {
    let mut spans = Vec::new();

    let mut pos = cursor.min(text.len());
    while pos > 0 && !text.is_char_boundary(pos) {
        pos -= 1;
    }

    if pos > 0 {
        spans.push(Span::styled(
            text[..pos].to_string(),
            Style::default().fg(Color::White),
        ));
    }

    if pos < text.len() {
        // Find the end of the current character.
        let mut end = pos + 1;
        while end < text.len() && !text.is_char_boundary(end) {
            end += 1;
        }
        spans.push(Span::styled(
            text[pos..end].to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
        if end < text.len() {
            spans.push(Span::styled(
                text[end..].to_string(),
                Style::default().fg(Color::White),
            ));
        }
    } else {
        // Cursor at end: show a block character.
        spans.push(Span::styled(
            " ".to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
    }

    spans
}

/// Create a centered rectangle within the given area.
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
