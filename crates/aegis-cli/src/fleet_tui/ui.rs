//! TUI rendering for the fleet dashboard.
//!
//! Draws the agent overview table or per-agent output view using ratatui.
//!
//! Layout (overview):
//! ```text
//! +--[ Aegis Fleet ]---- 2 running / 3 total -------+
//! |                                                   |
//! |  NAME       STATUS    TOOL        RESTARTS  DIR   |
//! |  > alpha    Running   ClaudeCode  0         /tmp  |
//! |    beta     Stopped   Codex       1         /tmp  |
//! |    gamma    Failed    ClaudeCode  5         /tmp  |
//! |                                                   |
//! +---------------------------------------------------+
//! | j/k: navigate  Enter: output  s/x/r: start/stop  |
//! +---------------------------------------------------+
//! ```
//!
//! Layout (agent detail):
//! ```text
//! +--[ alpha ]---- Running ---- ClaudeCode -----------+
//! | [output line 1]                                    |
//! | [output line 2]                                    |
//! | ...                                                |
//! +----------------------------------------------------+
//! | Esc: back  j/k: scroll  x: stop  r: restart       |
//! +----------------------------------------------------+
//! ```

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::prelude::Stylize;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table};
use ratatui::Frame;

use aegis_types::AgentStatus;

use super::{FleetApp, FleetView};

/// Draw the fleet TUI to the terminal frame.
pub fn draw(frame: &mut Frame, app: &FleetApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),   // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(frame.area());

    match app.view {
        FleetView::Overview => {
            draw_overview_header(frame, app, chunks[0]);
            draw_agent_table(frame, app, chunks[1]);
            draw_overview_status(frame, app, chunks[2]);
        }
        FleetView::AgentDetail => {
            draw_detail_header(frame, app, chunks[0]);
            draw_agent_output(frame, app, chunks[1]);
            draw_detail_status(frame, app, chunks[2]);
        }
    }
}

/// Render the overview header bar.
fn draw_overview_header(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let running = app.running_count();
    let total = app.agents.len();

    let connection_span = if app.connected {
        Span::styled(
            "CONNECTED",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "DISCONNECTED",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    };

    let header_line = Line::from(vec![
        Span::styled(" Aegis Fleet ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("  [", Style::default().fg(Color::DarkGray)),
        connection_span,
        Span::styled("]  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{running} running"),
            Style::default().fg(Color::Green),
        ),
        Span::styled(" / ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{total} total"),
            Style::default().fg(Color::White),
        ),
        Span::styled("  PID: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", app.daemon_pid),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled("  Uptime: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format_duration(app.daemon_uptime_secs),
            Style::default().fg(Color::Cyan),
        ),
    ]);

    let header = Paragraph::new(header_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(header, area);
}

/// Render the agent table.
fn draw_agent_table(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    if app.agents.is_empty() {
        let msg = if app.connected {
            "No agents configured. Add agents to daemon.toml and restart the daemon."
        } else if let Some(ref err) = app.last_error {
            err.as_str()
        } else {
            "Connecting to daemon..."
        };

        let empty = Paragraph::new(msg)
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Agents ")
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
        frame.render_widget(empty, area);
        return;
    }

    let header = Row::new(vec!["", "NAME", "STATUS", "TOOL", "RESTARTS", "DIR"])
        .style(
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    let rows: Vec<Row> = app
        .agents
        .iter()
        .enumerate()
        .map(|(i, agent)| {
            let selected = if i == app.agent_selected { ">" } else { " " };
            let (status_text, status_color) = status_display(&agent.status);
            let dir = truncate_path(&agent.working_dir, 30);

            let style = if i == app.agent_selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new(vec![
                selected.to_string(),
                agent.name.clone(),
                status_text.to_string(),
                agent.tool.clone(),
                agent.restart_count.to_string(),
                dir,
            ])
            .style(style)
            .fg(status_color)
        })
        .collect();

    let widths = [
        Constraint::Length(2),
        Constraint::Length(16),
        Constraint::Length(12),
        Constraint::Length(14),
        Constraint::Length(10),
        Constraint::Min(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Agents ")
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_widget(table, area);
}

/// Render the overview status bar with keybindings.
fn draw_overview_status(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let mut spans = vec![
        Span::styled(" j/k", Style::default().fg(Color::Yellow)),
        Span::styled(": navigate  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::styled(": output  ", Style::default().fg(Color::DarkGray)),
        Span::styled("s", Style::default().fg(Color::Green)),
        Span::styled(": start  ", Style::default().fg(Color::DarkGray)),
        Span::styled("x", Style::default().fg(Color::Red)),
        Span::styled(": stop  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::styled(": restart  ", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::DarkGray)),
        Span::styled(": quit (daemon stays running)", Style::default().fg(Color::DarkGray)),
    ];

    if let Some(ref err) = app.last_error {
        spans.push(Span::styled("  ", Style::default()));
        spans.push(Span::styled(
            truncate_str(err, 40),
            Style::default().fg(Color::Red),
        ));
    }

    let status = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(status, area);
}

/// Render the detail view header.
fn draw_detail_header(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    // Find the agent's current status from the list
    let (status_text, status_color) = app
        .agents
        .iter()
        .find(|a| a.name == app.detail_name)
        .map(|a| status_display(&a.status))
        .unwrap_or(("Unknown", Color::DarkGray));

    let tool = app
        .agents
        .iter()
        .find(|a| a.name == app.detail_name)
        .map(|a| a.tool.as_str())
        .unwrap_or("?");

    let header_line = Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            &app.detail_name,
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  [", Style::default().fg(Color::DarkGray)),
        Span::styled(
            status_text,
            Style::default().fg(status_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled("]  ", Style::default().fg(Color::DarkGray)),
        Span::styled(tool, Style::default().fg(Color::Cyan)),
        Span::styled(
            format!("  {} lines", app.detail_output.len()),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let header = Paragraph::new(header_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(header, area);
}

/// Render agent output lines.
fn draw_agent_output(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let inner_height = area.height.saturating_sub(2) as usize; // borders
    let lines = app.visible_output(inner_height);

    let items: Vec<ListItem> = lines
        .iter()
        .map(|line| {
            let style = if line.contains("[APPROVED]") {
                Style::default().fg(Color::Green)
            } else if line.contains("[DENIED]") {
                Style::default().fg(Color::Red)
            } else if line.contains("[PENDING]") {
                Style::default().fg(Color::Yellow)
            } else if line.contains("[NUDGE") {
                Style::default().fg(Color::Magenta)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Span::styled(*line, style))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Output ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(list, area);
}

/// Render the detail status bar.
fn draw_detail_status(frame: &mut Frame, _app: &FleetApp, area: ratatui::layout::Rect) {
    let spans = vec![
        Span::styled(" Esc", Style::default().fg(Color::Yellow)),
        Span::styled(": back  ", Style::default().fg(Color::DarkGray)),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::styled(": scroll  ", Style::default().fg(Color::DarkGray)),
        Span::styled("G", Style::default().fg(Color::Yellow)),
        Span::styled(": bottom  ", Style::default().fg(Color::DarkGray)),
        Span::styled("g", Style::default().fg(Color::Yellow)),
        Span::styled(": top  ", Style::default().fg(Color::DarkGray)),
        Span::styled("x", Style::default().fg(Color::Red)),
        Span::styled(": stop  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::styled(": restart  ", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::DarkGray)),
        Span::styled(": quit", Style::default().fg(Color::DarkGray)),
    ];

    let status = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(status, area);
}

/// Get display text and color for an agent status.
fn status_display(status: &AgentStatus) -> (&'static str, Color) {
    match status {
        AgentStatus::Running { .. } => ("Running", Color::Green),
        AgentStatus::Stopped { .. } => ("Stopped", Color::DarkGray),
        AgentStatus::Pending => ("Pending", Color::Cyan),
        AgentStatus::Crashed { .. } => ("Crashed", Color::Yellow),
        AgentStatus::Failed { .. } => ("Failed", Color::Red),
        AgentStatus::Disabled => ("Disabled", Color::DarkGray),
    }
}

/// Format a duration in seconds to a human-readable string.
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Truncate a path string, keeping the tail.
fn truncate_path(path: &str, max: usize) -> String {
    if path.len() <= max {
        path.to_string()
    } else {
        format!("...{}", &path[path.len() - (max - 3)..])
    }
}

/// Truncate a string with ellipsis.
fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max <= 3 {
        s[..max].to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(45), "45s");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(125), "2m 5s");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(7265), "2h 1m");
    }

    #[test]
    fn truncate_path_short() {
        assert_eq!(truncate_path("/tmp", 30), "/tmp");
    }

    #[test]
    fn truncate_path_long() {
        let p = "/very/long/path/to/some/directory";
        let t = truncate_path(p, 20);
        assert!(t.starts_with("..."));
        assert_eq!(t.len(), 20);
    }

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_long() {
        assert_eq!(truncate_str("hello world", 8), "hello...");
    }

    #[test]
    fn status_display_variants() {
        assert_eq!(status_display(&AgentStatus::Running { pid: 1 }).0, "Running");
        assert_eq!(status_display(&AgentStatus::Stopped { exit_code: 0 }).0, "Stopped");
        assert_eq!(status_display(&AgentStatus::Pending).0, "Pending");
        assert_eq!(status_display(&AgentStatus::Crashed { exit_code: 1, restart_in_secs: 5 }).0, "Crashed");
        assert_eq!(status_display(&AgentStatus::Failed { exit_code: 1, restart_count: 3 }).0, "Failed");
        assert_eq!(status_display(&AgentStatus::Disabled).0, "Disabled");
    }

    #[test]
    fn draw_does_not_panic_empty() {
        let app = FleetApp::new(None);
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_with_agents() {
        let mut app = FleetApp::new(None);
        app.connected = true;
        app.agents = vec![
            aegis_control::daemon::AgentSummary {
                name: "test-agent".into(),
                status: AgentStatus::Running { pid: 42 },
                tool: "ClaudeCode".into(),
                working_dir: "/tmp/test".into(),
                restart_count: 0,
            },
        ];
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_detail_view() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::AgentDetail;
        app.detail_name = "test-agent".into();
        app.detail_output.push_back("line 1".into());
        app.detail_output.push_back("[APPROVED] something".into());
        app.detail_output.push_back("[DENIED] other".into());
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_small_terminal() {
        let app = FleetApp::new(None);
        let backend = ratatui::backend::TestBackend::new(20, 5);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_disconnected_with_error() {
        let mut app = FleetApp::new(None);
        app.connected = false;
        app.last_error = Some("connection refused".into());
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }
}
