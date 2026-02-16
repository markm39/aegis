/// TUI rendering for the monitor dashboard.
///
/// Draws the audit feed, statistics panel, and help/info panel using
/// ratatui widgets. The layout splits the terminal vertically (70/30)
/// with the bottom half split horizontally for stats and keybindings.
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::app::{App, AppMode};

/// Draw the full dashboard to the terminal frame.
pub fn draw(frame: &mut Frame, app: &App) {
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
        .map(|(i, entry)| {
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

            let style = if i == app.selected_index {
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

/// Render the statistics panel (bottom-left).
fn draw_stats(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default()
        .title(" Statistics ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let allow_pct = if app.total_count > 0 {
        (app.allow_count as f64 / app.total_count as f64 * 100.0) as u64
    } else {
        0
    };
    let deny_pct = if app.total_count > 0 {
        (app.deny_count as f64 / app.total_count as f64 * 100.0) as u64
    } else {
        0
    };

    let text = vec![
        Line::from(vec![
            Span::styled("Total:   ", Style::default().fg(Color::White)),
            Span::styled(
                app.total_count.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Allowed: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{} ({allow_pct}%)", app.allow_count),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::styled("Denied:  ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{} ({deny_pct}%)", app.deny_count),
                Style::default().fg(Color::Red),
            ),
        ]),
    ];

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use aegis_ledger::AuditEntry;
    use chrono::Utc;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn sample_entry(principal: &str, decision: &str, action_kind: &str) -> AuditEntry {
        AuditEntry {
            entry_id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            action_id: uuid::Uuid::new_v4(),
            action_kind: action_kind.to_string(),
            principal: principal.to_string(),
            decision: decision.to_string(),
            reason: "test reason".to_string(),
            policy_id: None,
            prev_hash: "genesis".to_string(),
            entry_hash: "abc123".to_string(),
        }
    }

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
}
