//! TUI rendering for the monitor dashboard.
//!
//! Draws the audit feed, statistics panel, and help/info panel using
//! ratatui widgets. The layout splits the terminal vertically (70/30)
//! with the bottom half split horizontally for stats and keybindings.

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use aegis_ledger::AuditEntry;

use crate::app::{App, AppMode};

/// Render an audit entry as a styled ListItem.
fn entry_list_item(entry: &AuditEntry, selected: bool) -> ListItem<'static> {
    let ts = entry.timestamp.format("%H:%M:%S");
    let decision_color = if entry.decision == "Allow" {
        Color::Green
    } else {
        Color::Red
    };

    let line = Line::from(vec![
        Span::styled(
            format!("[{ts}] "),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("[{}] ", entry.decision),
            Style::default()
                .fg(decision_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} ", entry.principal),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(
            format!("{} ", entry.action_kind),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            entry.reason.clone(),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let style = if selected {
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    ListItem::new(line).style(style)
}

/// Draw the full dashboard to the terminal frame.
pub fn draw(frame: &mut Frame, app: &App) {
    match app.mode {
        AppMode::SessionList => {
            draw_session_list_view(frame, app);
            return;
        }
        AppMode::SessionDetail => {
            draw_session_detail_view(frame, app);
            return;
        }
        _ => {}
    }

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(frame.area());

    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    draw_audit_feed(frame, app, main_chunks[0]);
    draw_stats(frame, app, bottom_chunks[0]);
    draw_info(frame, app, bottom_chunks[1]);
}

/// Render the audit feed panel (top section).
fn draw_audit_feed(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let mode_label = match app.mode {
        AppMode::AuditFeed => "AUDIT",
        AppMode::PolicyView => "POLICY",
        AppMode::FilterMode => "FILTER",
        AppMode::SessionList => "SESSIONS",
        AppMode::SessionDetail => "SESSION",
    };

    let title = if app.filter_text.is_empty() {
        format!(" Aegis Audit Feed [{mode_label}] ")
    } else {
        format!(" Aegis Audit Feed [{mode_label}] filter: \"{}\" ", app.filter_text)
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let entries = app.filtered_entries();
    let items: Vec<ListItem> = entries
        .iter()
        .enumerate()
        .map(|(i, entry)| entry_list_item(entry, i == app.selected_index))
        .collect();

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

/// Render the statistics panel (bottom-left).
fn draw_stats(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default()
        .title(" Statistics ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let deny_rate = if app.total_count > 0 {
        app.deny_count as f64 / app.total_count as f64 * 100.0
    } else {
        0.0
    };

    let deny_rate_color = if deny_rate > 50.0 {
        Color::Red
    } else if deny_rate > 20.0 {
        Color::Yellow
    } else {
        Color::Green
    };

    let mut text = vec![
        Line::from(vec![
            Span::styled("Total:     ", Style::default().fg(Color::White)),
            Span::styled(
                app.total_count.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Allowed:   ", Style::default().fg(Color::White)),
            Span::styled(
                app.allow_count.to_string(),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::styled("Denied:    ", Style::default().fg(Color::White)),
            Span::styled(
                app.deny_count.to_string(),
                Style::default().fg(Color::Red),
            ),
        ]),
        Line::from(vec![
            Span::styled("Deny rate: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{deny_rate:.1}%"),
                Style::default()
                    .fg(deny_rate_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Sessions:  ", Style::default().fg(Color::White)),
            Span::styled(
                app.sessions.len().to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]),
    ];

    // Action distribution bar chart
    if !app.action_distribution.is_empty() {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            "Action Distribution",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )));

        let max_count = app
            .action_distribution
            .iter()
            .map(|(_, c)| *c)
            .max()
            .unwrap_or(1);

        // Available width for the bar (area width minus borders, label, count)
        let bar_width = 20usize;

        for (kind, count) in app.action_distribution.iter().take(6) {
            let filled = if max_count > 0 {
                (*count as f64 / max_count as f64 * bar_width as f64).round() as usize
            } else {
                0
            };
            let filled = filled.min(bar_width);
            let bar: String =
                "#".repeat(filled) + &".".repeat(bar_width - filled);

            text.push(Line::from(vec![
                Span::styled(
                    format!("{:<14} ", kind),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(bar, Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!(" {count}"),
                    Style::default().fg(Color::White),
                ),
            ]));
        }
    }

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

/// Render the info/help panel (bottom-right).
fn draw_info(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default()
        .title(" Keybindings ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let mut lines = vec![
        Line::from(Span::styled(
            "q       Quit",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "p       Policy view",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "s       Sessions view",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "a/Esc   Audit view",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "/       Filter mode",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "j/k     Navigate up/down",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "Enter   Drill into session",
            Style::default().fg(Color::White),
        )),
    ];

    if matches!(app.mode, AppMode::FilterMode) {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Filter: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                if app.filter_text.is_empty() {
                    "(empty)"
                } else {
                    &app.filter_text
                },
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            "Enter   Apply  |  Esc  Cancel",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

/// Render the full-screen session list view.
fn draw_session_list_view(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(frame.area());

    let block = Block::default()
        .title(" Sessions [s=list, Enter=detail, Esc=back] ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let items: Vec<ListItem> = app
        .sessions
        .iter()
        .enumerate()
        .map(|(i, session)| {
            let status_color = match session.exit_code {
                Some(0) => Color::Green,
                Some(_) => Color::Red,
                None => Color::Yellow,
            };

            let status_text = match session.exit_code {
                Some(code) => format!("exit:{code}"),
                None => "running".to_string(),
            };

            // Truncate session_id to first 8 chars for display
            let short_id = if session.session_id.len() >= 8 {
                &session.session_id[..8]
            } else {
                &session.session_id
            };

            // Format the start time -- just show the time portion if available
            let time_display = if session.start_time.len() > 11 {
                &session.start_time[11..19.min(session.start_time.len())]
            } else {
                &session.start_time
            };

            let deny_rate = if session.total_actions > 0 {
                session.denied_actions as f64 / session.total_actions as f64 * 100.0
            } else {
                0.0
            };

            let line = Line::from(vec![
                Span::styled(
                    format!("{short_id} "),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("[{time_display}] "),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{:<20} ", session.command),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    format!("{status_text:<10} "),
                    Style::default().fg(status_color),
                ),
                Span::styled(
                    format!(
                        "actions:{} denied:{} ({deny_rate:.0}%)",
                        session.total_actions, session.denied_actions,
                    ),
                    Style::default().fg(Color::Cyan),
                ),
            ]);

            let style = if i == app.session_selected {
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
    frame.render_widget(list, chunks[0]);

    // Bottom status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} sessions ", app.sessions.len()),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            "| Enter: view detail | Esc: back to audit | q: quit",
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(status, chunks[1]);
}

/// Render the full-screen session detail view.
fn draw_session_detail_view(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(frame.area());

    // Session header
    let header_block = Block::default()
        .title(" Session Detail ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let header_lines = if let Some(session) = &app.session_detail {
        let status_text = match session.exit_code {
            Some(0) => "exited (0)",
            Some(_) => "failed",
            None => "running",
        };
        let status_color = match session.exit_code {
            Some(0) => Color::Green,
            Some(_) => Color::Red,
            None => Color::Yellow,
        };

        vec![
            Line::from(vec![
                Span::styled("Session:  ", Style::default().fg(Color::White)),
                Span::styled(
                    &session.session_id,
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::styled("Command:  ", Style::default().fg(Color::White)),
                Span::styled(
                    &session.command,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Status:   ", Style::default().fg(Color::White)),
                Span::styled(status_text, Style::default().fg(status_color)),
            ]),
            Line::from(vec![
                Span::styled("Actions:  ", Style::default().fg(Color::White)),
                Span::styled(
                    format!(
                        "{} total, {} denied",
                        session.total_actions, session.denied_actions
                    ),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Started:  ", Style::default().fg(Color::White)),
                Span::styled(
                    &session.start_time,
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "No session selected",
            Style::default().fg(Color::Red),
        ))]
    };

    let header = Paragraph::new(header_lines).block(header_block);
    frame.render_widget(header, chunks[0]);

    // Session entries list
    let entries_block = Block::default()
        .title(format!(
            " Entries ({}) ",
            app.session_entries.len()
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let items: Vec<ListItem> = app
        .session_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| entry_list_item(entry, i == app.session_detail_selected))
        .collect();

    let list = List::new(items).block(entries_block);
    frame.render_widget(list, chunks[1]);

    // Bottom status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} entries ", app.session_entries.len()),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            "| Esc: back to sessions | a: audit view | q: quit",
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(status, chunks[2]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::test_helpers::sample_entry;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    #[test]
    fn draw_does_not_panic_with_empty_app() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("failed to create terminal");
        let app = App::new(PathBuf::from("/tmp/nonexistent.db"));

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic");
    }

    #[test]
    fn draw_does_not_panic_with_entries() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("failed to create terminal");
        let mut app = App::new(PathBuf::from("/tmp/nonexistent.db"));
        app.entries = vec![
            sample_entry("alice", "Allow", "FileRead"),
            sample_entry("bob", "Deny", "NetConnect"),
            sample_entry("charlie", "Allow", "FileWrite"),
        ];
        app.total_count = 3;
        app.allow_count = 2;
        app.deny_count = 1;

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic with entries");
    }

    #[test]
    fn draw_does_not_panic_in_filter_mode() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("failed to create terminal");
        let mut app = App::new(PathBuf::from("/tmp/nonexistent.db"));
        app.mode = AppMode::FilterMode;
        app.filter_text = "alice".to_string();

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic in filter mode");
    }

    #[test]
    fn draw_does_not_panic_in_policy_view() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("failed to create terminal");
        let mut app = App::new(PathBuf::from("/tmp/nonexistent.db"));
        app.mode = AppMode::PolicyView;

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic in policy view");
    }

    #[test]
    fn draw_does_not_panic_in_session_list_empty() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("failed to create terminal");
        let mut app = App::new(PathBuf::from("/tmp/nonexistent.db"));
        app.mode = AppMode::SessionList;

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic in empty session list");
    }

    #[test]
    fn draw_does_not_panic_in_session_list_with_sessions() {
        use crate::app::MonitorSession;

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("failed to create terminal");
        let mut app = App::new(PathBuf::from("/tmp/nonexistent.db"));
        app.mode = AppMode::SessionList;
        app.sessions = vec![
            MonitorSession {
                session_id: "aaaa-bbbb-cccc-dddd".to_string(),
                config_name: "test".to_string(),
                command: "echo hello".to_string(),
                start_time: "2026-01-01T12:34:56Z".to_string(),
                end_time: Some("2026-01-01T12:35:00Z".to_string()),
                exit_code: Some(0),
                total_actions: 10,
                denied_actions: 2,
            },
            MonitorSession {
                session_id: "eeee-ffff-0000-1111".to_string(),
                config_name: "test".to_string(),
                command: "cat /tmp/file".to_string(),
                start_time: "2026-01-01T12:40:00Z".to_string(),
                end_time: None,
                exit_code: None,
                total_actions: 3,
                denied_actions: 0,
            },
        ];

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic in session list with sessions");
    }

    #[test]
    fn draw_does_not_panic_in_session_detail() {
        use crate::app::MonitorSession;

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("failed to create terminal");
        let mut app = App::new(PathBuf::from("/tmp/nonexistent.db"));
        app.mode = AppMode::SessionDetail;
        app.session_detail = Some(MonitorSession {
            session_id: "aaaa-bbbb-cccc-dddd".to_string(),
            config_name: "test".to_string(),
            command: "echo hello".to_string(),
            start_time: "2026-01-01T12:34:56Z".to_string(),
            end_time: Some("2026-01-01T12:35:00Z".to_string()),
            exit_code: Some(0),
            total_actions: 10,
            denied_actions: 2,
        });
        app.session_entries = vec![
            sample_entry("alice", "Allow", "FileRead"),
            sample_entry("bob", "Deny", "NetConnect"),
        ];

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic in session detail");
    }

    #[test]
    fn draw_does_not_panic_in_session_detail_no_session() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("failed to create terminal");
        let mut app = App::new(PathBuf::from("/tmp/nonexistent.db"));
        app.mode = AppMode::SessionDetail;
        app.session_detail = None;

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic in session detail without session");
    }

    #[test]
    fn draw_stats_with_action_distribution() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("failed to create terminal");
        let mut app = App::new(PathBuf::from("/tmp/nonexistent.db"));
        app.total_count = 10;
        app.allow_count = 7;
        app.deny_count = 3;
        app.action_distribution = vec![
            ("FileRead".to_string(), 5),
            ("FileWrite".to_string(), 3),
            ("NetConnect".to_string(), 2),
        ];

        terminal
            .draw(|f| draw(f, &app))
            .expect("draw should not panic with action distribution");
    }
}
