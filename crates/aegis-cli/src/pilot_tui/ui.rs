//! TUI rendering for the pilot dashboard.
//!
//! Draws the agent output feed, statistics panel, pending requests panel,
//! and status bar using ratatui widgets. The layout adapts based on whether
//! pending requests exist.
//!
//! Layout:
//! ```text
//! +----------------------------------------------------------+
//! | Pilot: command  [RUNNING]  Session: abc..  Config: name   |
//! +----------------------------------------------------------+
//! |                              |                            |
//! |  Agent Output (scrollable)   | Stats / Pending            |
//! |                              |                            |
//! +----------------------------------------------------------+
//! | status bar with keybindings                               |
//! +----------------------------------------------------------+
//! ```

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::{LineAnnotation, PilotApp, PilotMode};

/// Draw the full pilot TUI to the terminal frame.
pub fn draw(frame: &mut Frame, app: &PilotApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(0),     // Main content
            Constraint::Length(3),  // Status bar
        ])
        .split(frame.area());

    draw_header(frame, app, chunks[0]);
    draw_main(frame, app, chunks[1]);
    draw_status_bar(frame, app, chunks[2]);
}

/// Render the header bar with session info.
fn draw_header(frame: &mut Frame, app: &PilotApp, area: ratatui::layout::Rect) {
    let status_text = if app.child_alive { "RUNNING" } else { "EXITED" };
    let status_color = if app.child_alive { Color::Green } else { Color::Yellow };

    let short_session = if app.session_id.len() > 8 {
        format!("{}...", &app.session_id[..8])
    } else {
        app.session_id.clone()
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(" Pilot: ", Style::default().fg(Color::White)),
        Span::styled(
            &app.command,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  [", Style::default().fg(Color::DarkGray)),
        Span::styled(
            status_text,
            Style::default().fg(status_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled("]  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Session: ", Style::default().fg(Color::DarkGray)),
        Span::styled(short_session, Style::default().fg(Color::Cyan)),
        Span::styled("  Config: ", Style::default().fg(Color::DarkGray)),
        Span::styled(&app.config_name, Style::default().fg(Color::Cyan)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(header, area);
}

/// Render the main content area (output + side panel).
fn draw_main(frame: &mut Frame, app: &PilotApp, area: ratatui::layout::Rect) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);

    draw_output(frame, app, main_chunks[0]);
    draw_side_panel(frame, app, main_chunks[1]);
}

/// Render the agent output feed (scrollable).
fn draw_output(frame: &mut Frame, app: &PilotApp, area: ratatui::layout::Rect) {
    let focus_style = if !app.focus_pending {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let scroll_indicator = if app.scroll_offset > 0 {
        format!(" (+{} above) ", app.scroll_offset)
    } else {
        String::new()
    };

    let block = Block::default()
        .title(format!(
            " Agent Output ({} lines){scroll_indicator}",
            app.output_lines.len(),
        ))
        .borders(Borders::ALL)
        .border_style(focus_style);

    // Calculate inner height for visible_output
    let inner_height = area.height.saturating_sub(2) as usize;
    let visible = app.visible_output(inner_height);

    let items: Vec<ListItem> = visible
        .iter()
        .map(|line| {
            let ts = line.timestamp.format("%H:%M:%S");
            let mut spans = vec![
                Span::styled(
                    format!("[{ts}] "),
                    Style::default().fg(Color::DarkGray),
                ),
            ];

            match &line.annotation {
                Some(LineAnnotation::Approved { .. }) => {
                    spans.push(Span::styled(
                        &line.text,
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    ));
                }
                Some(LineAnnotation::Denied { .. }) => {
                    spans.push(Span::styled(
                        &line.text,
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                }
                Some(LineAnnotation::Nudge) => {
                    spans.push(Span::styled(
                        &line.text,
                        Style::default().fg(Color::Yellow),
                    ));
                }
                Some(LineAnnotation::Attention) => {
                    spans.push(Span::styled(
                        &line.text,
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                }
                None => {
                    spans.push(Span::styled(
                        &line.text,
                        Style::default().fg(Color::White),
                    ));
                }
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

/// Render the side panel (stats + pending requests).
fn draw_side_panel(frame: &mut Frame, app: &PilotApp, area: ratatui::layout::Rect) {
    if app.pending.is_empty() {
        // Full height for stats
        draw_stats(frame, app, area);
    } else {
        // Split between stats and pending
        let side_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        draw_stats(frame, app, side_chunks[0]);
        draw_pending(frame, app, side_chunks[1]);
    }
}

/// Render the statistics panel.
fn draw_stats(frame: &mut Frame, app: &PilotApp, area: ratatui::layout::Rect) {
    let block = Block::default()
        .title(" Statistics ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let text = vec![
        labeled_line("Approved:", app.stats.approved.to_string(), Color::Green, true),
        labeled_line("Denied:", app.stats.denied.to_string(), Color::Red, true),
        labeled_line("Uncertain:", app.stats.uncertain.to_string(), Color::Yellow, false),
        labeled_line("Nudges:", app.stats.nudges.to_string(), Color::Cyan, false),
        labeled_line("Lines:", app.stats.lines_processed.to_string(), Color::White, false),
        labeled_line(
            "Pending:",
            app.pending.len().to_string(),
            if app.pending.is_empty() { Color::DarkGray } else { Color::Yellow },
            !app.pending.is_empty(),
        ),
    ];

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

/// Render the pending requests panel.
fn draw_pending(frame: &mut Frame, app: &PilotApp, area: ratatui::layout::Rect) {
    let focus_style = if app.focus_pending {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default()
        .title(format!(" Pending ({}) ", app.pending.len()))
        .borders(Borders::ALL)
        .border_style(focus_style);

    let items: Vec<ListItem> = app
        .pending
        .iter()
        .enumerate()
        .map(|(i, info)| {
            let ts = info.received_at.format("%H:%M:%S");
            let truncated = if info.raw_prompt.len() > 40 {
                format!("{}...", &info.raw_prompt[..37])
            } else {
                info.raw_prompt.clone()
            };

            let line = Line::from(vec![
                Span::styled(
                    format!("[{ts}] "),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    truncated,
                    Style::default().fg(Color::White),
                ),
            ]);

            let style = if i == app.pending_selected && app.focus_pending {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(line).style(style)
        })
        .collect();

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

/// Render the status bar with keybinding hints and input buffer.
fn draw_status_bar(frame: &mut Frame, app: &PilotApp, area: ratatui::layout::Rect) {
    let content = match app.mode {
        PilotMode::Normal => {
            let mut hints = vec![
                Span::styled(" q", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(":quit ", Style::default().fg(Color::DarkGray)),
                Span::styled("j/k", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(":scroll ", Style::default().fg(Color::DarkGray)),
                Span::styled("G", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(":bottom ", Style::default().fg(Color::DarkGray)),
                Span::styled("i", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(":input ", Style::default().fg(Color::DarkGray)),
                Span::styled("n", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(":nudge ", Style::default().fg(Color::DarkGray)),
            ];
            if !app.pending.is_empty() {
                hints.extend_from_slice(&[
                    Span::styled("Tab", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::styled(":focus ", Style::default().fg(Color::DarkGray)),
                    Span::styled("a", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    Span::styled(":approve ", Style::default().fg(Color::DarkGray)),
                    Span::styled("d", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    Span::styled(":deny ", Style::default().fg(Color::DarkGray)),
                ]);
            }
            Line::from(hints)
        }
        PilotMode::InputMode => {
            Line::from(vec![
                Span::styled(" INPUT> ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(
                    &app.input_buffer,
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    "_",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK),
                ),
                Span::styled(
                    "  (Enter:send  Esc:cancel)",
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        }
    };

    let paragraph = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(paragraph, area);
}

/// Build a styled label-value line (reusable helper).
fn labeled_line<'a>(label: &str, value: impl Into<String>, color: Color, bold: bool) -> Line<'a> {
    let style = if bold {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(color)
    };
    Line::from(vec![
        Span::styled(format!("{label:<12} "), Style::default().fg(Color::White)),
        Span::styled(value.into(), style),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pilot_tui::PilotApp;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::sync::mpsc;

    fn make_test_app() -> PilotApp {
        let (tx, _rx) = mpsc::channel();
        PilotApp::new("test-session".into(), "test-config".into(), "echo".into(), tx)
    }

    #[test]
    fn draw_does_not_panic_empty() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = make_test_app();

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic with empty app");
    }

    #[test]
    fn draw_does_not_panic_with_output() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = make_test_app();

        use aegis_pilot::supervisor::PilotUpdate;
        for i in 0..20 {
            app.apply_update(PilotUpdate::OutputLine(format!("output line {i}")));
        }
        app.apply_update(PilotUpdate::PromptDecided {
            action: "FileRead".into(),
            decision: aegis_types::Decision::Allow,
            reason: "policy:default".into(),
        });

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic with output");
    }

    #[test]
    fn draw_does_not_panic_with_pending() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = make_test_app();

        use aegis_pilot::supervisor::PilotUpdate;
        app.apply_update(PilotUpdate::PendingPrompt {
            request_id: uuid::Uuid::new_v4(),
            raw_prompt: "Claude wants to use Bash: rm -rf /".into(),
        });

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic with pending requests");
    }

    #[test]
    fn draw_does_not_panic_in_input_mode() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = make_test_app();
        app.mode = crate::pilot_tui::PilotMode::InputMode;
        app.input_buffer = "some text".into();

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic in input mode");
    }

    #[test]
    fn draw_does_not_panic_child_exited() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = make_test_app();
        app.child_alive = false;

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic when child exited");
    }

    #[test]
    fn draw_does_not_panic_small_terminal() {
        let backend = TestBackend::new(40, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = make_test_app();

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic with small terminal");
    }
}
