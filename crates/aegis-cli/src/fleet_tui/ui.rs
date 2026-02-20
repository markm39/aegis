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
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use aegis_types::AgentStatus;

use super::wizard::{AddAgentWizard, AgentTypeChoice, RestartChoice, ToolChoice, WizardStep};
use super::{FleetApp, FleetView};
use crate::tui_utils::truncate_str;

/// Maximum content lines before a wrapping text input stops growing.
const MAX_INPUT_WRAP_LINES: u16 = 6;

/// Estimate how many terminal rows a bordered text input needs when its content
/// wraps. Returns total widget height (content lines + 2 for borders), capped
/// at `max_content_lines` to prevent consuming the whole screen.
fn wrapped_input_height(content_len: usize, area_width: u16, max_content_lines: u16) -> u16 {
    let usable = area_width.saturating_sub(2) as usize;
    if usable == 0 {
        return 3;
    }
    let lines = if content_len == 0 {
        1
    } else {
        content_len.div_ceil(usable)
    };
    (lines as u16).min(max_content_lines) + 2
}

/// Draw the fleet TUI to the terminal frame.
pub fn draw(frame: &mut Frame, app: &FleetApp) {
    // If command mode is active, add a command bar at the bottom
    let has_command = app.command_mode || app.command_result.is_some();

    let cmd_bar_height = if has_command {
        if app.command_mode {
            // `:` prefix (1) + buffer + cursor placeholder (1)
            let content_len = 1 + app.command_buffer.len() + 1;
            wrapped_input_height(content_len, frame.area().width, MAX_INPUT_WRAP_LINES)
        } else if let Some(ref result) = app.command_result {
            let content_len = 1 + result.len();
            wrapped_input_height(content_len, frame.area().width, MAX_INPUT_WRAP_LINES)
        } else {
            3
        }
    } else {
        3
    };

    let chunks = if has_command {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),              // Header
                Constraint::Min(0),                 // Main content
                Constraint::Length(3),              // Status bar
                Constraint::Length(cmd_bar_height), // Command bar (dynamic)
            ])
            .split(frame.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Main content
                Constraint::Length(3), // Status bar
            ])
            .split(frame.area())
    };

    match app.view {
        FleetView::Overview => {
            draw_overview_header(frame, app, chunks[0]);
            draw_agent_table(frame, app, chunks[1]);
            draw_overview_status(frame, app, chunks[2]);
        }
        FleetView::AgentDetail => {
            draw_detail_header(frame, app, chunks[0]);

            // Split main area into output + input bar (dynamic height)
            let content_len = 3 + app.input_buffer.len() + 1; // " > " + buffer + cursor
            let input_height =
                wrapped_input_height(content_len, chunks[1].width, MAX_INPUT_WRAP_LINES);
            let detail_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(input_height)])
                .split(chunks[1]);
            draw_detail_main(frame, app, detail_chunks[0]);
            draw_input_bar(frame, app, detail_chunks[1]);

            draw_detail_status(frame, app, chunks[2]);
        }
        FleetView::AddAgent => {
            if let Some(ref wiz) = app.wizard {
                draw_wizard(frame, wiz, frame.area());
            }
        }
        FleetView::Help => {
            draw_help_view(frame, app, frame.area());
        }
    }

    // Draw command bar / result overlay if active
    if has_command && chunks.len() > 3 {
        draw_command_bar(frame, app, chunks[3]);
    }

    if app.context_editor.is_some() {
        draw_context_editor(frame, app, frame.area());
    }
}

/// Render the overview header bar.
fn draw_overview_header(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let running = app.running_count();
    let total = app.agents.len();

    let connection_span = if app.connected {
        Span::styled(
            "CONNECTED",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "DISCONNECTED",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    };

    let mut header_spans = vec![
        Span::styled(
            " Aegis Fleet ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  [", Style::default().fg(Color::DarkGray)),
        connection_span,
        Span::styled("]", Style::default().fg(Color::DarkGray)),
    ];

    if app.connected {
        header_spans.extend([
            Span::styled("  ", Style::default()),
            Span::styled(
                format!("{running} running"),
                Style::default().fg(Color::Green),
            ),
            Span::styled(" / ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{total} total"), Style::default().fg(Color::White)),
            Span::styled("  PID: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", app.daemon_pid),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled("  Uptime: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                super::format_uptime(app.daemon_uptime_secs),
                Style::default().fg(Color::Cyan),
            ),
        ]);
    }

    if let Some(ref goal) = app.fleet_goal {
        header_spans.push(Span::styled(
            "  Goal: ",
            Style::default().fg(Color::DarkGray),
        ));
        header_spans.push(Span::styled(
            truncate_str(goal, 40),
            Style::default().fg(Color::Yellow),
        ));
    }

    let header_line = Line::from(header_spans);

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
            "No agents configured. Type :add to create one, or :help for commands."
        } else if let Some(ref err) = app.last_error {
            err.as_str()
        } else {
            "Daemon not running. Type :daemon start to begin, or :help for commands."
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

    let header = Row::new(vec!["", "NAME", "ROLE", "STATUS", "PENDING", "TOOL", "DIR"]).style(
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .agents
        .iter()
        .enumerate()
        .map(|(i, agent)| {
            let marker = match (agent.attention_needed, i == app.agent_selected) {
                (true, true) => "!>",
                (true, false) => "! ",
                (false, true) => " >",
                (false, false) => "  ",
            };
            let (status_text, status_color) = status_display(&agent.status);
            let dir = truncate_path(&agent.working_dir, 30);
            let role = if agent.is_orchestrator {
                match agent.role.as_deref() {
                    Some(r) if !r.is_empty() => format!("ORCH: {r}"),
                    _ => "Orchestrator".to_string(),
                }
            } else {
                agent.role.as_deref().unwrap_or("-").to_string()
            };
            let pending = if agent.pending_count > 0 {
                format!("{}", agent.pending_count)
            } else {
                "-".to_string()
            };

            let style = if i == app.agent_selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Use attention color for the marker column
            let marker_color = if agent.attention_needed {
                Color::Yellow
            } else {
                status_color
            };

            Row::new(vec![
                ratatui::widgets::Cell::from(marker).style(Style::default().fg(marker_color)),
                ratatui::widgets::Cell::from(truncate_str(&agent.name, 16)),
                ratatui::widgets::Cell::from(truncate_str(&role, 16)),
                ratatui::widgets::Cell::from(status_text.to_string()),
                ratatui::widgets::Cell::from(pending).style(if agent.pending_count > 0 {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                }),
                ratatui::widgets::Cell::from(agent.tool.clone()),
                ratatui::widgets::Cell::from(dir),
            ])
            .style(style)
            .fg(status_color)
        })
        .collect();

    let widths = [
        Constraint::Length(2),
        Constraint::Length(16),
        Constraint::Length(18),
        Constraint::Length(12),
        Constraint::Length(9),
        Constraint::Length(14),
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

    let mut state = TableState::default().with_selected(Some(app.agent_selected));
    frame.render_stateful_widget(table, area, &mut state);
}

/// Render the overview status bar with keybindings.
fn draw_overview_status(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let mut spans = if app.connected {
        vec![
            Span::styled(
                " :",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" cmd  ", Style::default().fg(Color::DarkGray)),
            Span::styled("j/k", Style::default().fg(Color::Yellow)),
            Span::styled(" nav  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" chat  ", Style::default().fg(Color::DarkGray)),
            Span::styled("s", Style::default().fg(Color::Green)),
            Span::styled("/", Style::default().fg(Color::DarkGray)),
            Span::styled("x", Style::default().fg(Color::Red)),
            Span::styled("/", Style::default().fg(Color::DarkGray)),
            Span::styled("r", Style::default().fg(Color::Yellow)),
            Span::styled(
                " start/stop/restart  ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("a", Style::default().fg(Color::Cyan)),
            Span::styled(" add  ", Style::default().fg(Color::DarkGray)),
            Span::styled("?", Style::default().fg(Color::Cyan)),
            Span::styled(" help  ", Style::default().fg(Color::DarkGray)),
            Span::styled(":", Style::default().fg(Color::Yellow)),
            Span::styled("chat  ", Style::default().fg(Color::DarkGray)),
            Span::styled("q", Style::default().fg(Color::DarkGray)),
            Span::styled(" quit", Style::default().fg(Color::DarkGray)),
        ]
    } else {
        vec![
            Span::styled(" :", Style::default().fg(Color::Yellow)),
            Span::styled(": commands  ", Style::default().fg(Color::DarkGray)),
            Span::styled(":daemon start", Style::default().fg(Color::Green)),
            Span::styled("  ", Style::default()),
            Span::styled(":pilot", Style::default().fg(Color::Yellow)),
            Span::styled("  ", Style::default()),
            Span::styled(":wrap", Style::default().fg(Color::Yellow)),
            Span::styled("  ", Style::default()),
            Span::styled(":log", Style::default().fg(Color::Yellow)),
            Span::styled("  ", Style::default()),
            Span::styled(":help", Style::default().fg(Color::Cyan)),
            Span::styled("  ", Style::default()),
            Span::styled("q", Style::default().fg(Color::DarkGray)),
            Span::styled(": quit", Style::default().fg(Color::DarkGray)),
        ]
    };

    if let Some(ref err) = app.last_error {
        spans.push(Span::styled("  ", Style::default()));
        spans.push(Span::styled(
            truncate_str(err, 80),
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
        .unwrap_or(("Unknown".into(), Color::DarkGray));

    let agent_summary = app.agents.iter().find(|a| a.name == app.detail_name);

    let tool = agent_summary.map(|a| a.tool.as_str()).unwrap_or("?");

    let role = agent_summary.and_then(|a| a.role.as_deref());
    let is_orch = agent_summary.map(|a| a.is_orchestrator).unwrap_or(false);

    let mut header_spans = vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            &app.detail_name,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ];

    if is_orch {
        header_spans.push(Span::styled(
            "  [Orchestrator]",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ));
    }

    if let Some(r) = role {
        header_spans.push(Span::styled(
            format!("  [{r}]"),
            Style::default().fg(Color::Yellow),
        ));
    }

    // Build status bracket with PID or exit code detail
    let status_detail = agent_summary
        .map(|a| match &a.status {
            AgentStatus::Running { pid } => format!("  pid:{pid}"),
            AgentStatus::Stopped { exit_code } => format!("  exit:{exit_code}"),
            AgentStatus::Crashed { exit_code, .. } => format!("  exit:{exit_code}"),
            AgentStatus::Failed { exit_code, .. } => format!("  exit:{exit_code}"),
            _ => String::new(),
        })
        .unwrap_or_default();

    let restart_count = agent_summary.map(|a| a.restart_count).unwrap_or(0);

    header_spans.extend([
        Span::styled("  [", Style::default().fg(Color::DarkGray)),
        Span::styled(
            status_text,
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(status_detail, Style::default().fg(Color::DarkGray)),
        Span::styled("]  ", Style::default().fg(Color::DarkGray)),
        Span::styled(tool, Style::default().fg(Color::Cyan)),
        Span::styled(
            format!("  {} lines", app.detail_output.len()),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    if let Some(runtime) = app.detail_runtime.as_ref() {
        let auth_style = if runtime.auth_ready {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Red)
        };
        let auth_label = if runtime.auth_ready {
            "ready"
        } else {
            "missing"
        };
        header_spans.push(Span::styled(
            "  auth:",
            Style::default().fg(Color::DarkGray),
        ));
        header_spans.push(Span::styled(
            format!("{} ({})", runtime.auth_mode, auth_label),
            auth_style.add_modifier(Modifier::BOLD),
        ));
    }

    if restart_count > 0 {
        header_spans.push(Span::styled(
            format!("  restarts:{restart_count}"),
            Style::default().fg(Color::Yellow),
        ));
    }

    if !app.detail_pending.is_empty() {
        header_spans.push(Span::styled(
            format!("  [{} pending]", app.detail_pending.len()),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }

    if app.detail_attention {
        header_spans.push(Span::styled(
            "  [ATTENTION]",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }

    if let Some(fallback) = agent_summary.and_then(|a| a.fallback.as_ref()) {
        let summary = format_fallback_summary(fallback);
        header_spans.push(Span::styled(
            format!("  [fallback:{summary}]"),
            Style::default().fg(Color::DarkGray),
        ));
    }

    if let Some(caps) = &app.detail_runtime {
        let med_color = match caps.policy_mediation.as_str() {
            "enforced" => Color::Green,
            "partial" => Color::Yellow,
            _ => Color::Red,
        };
        header_spans.push(Span::styled(
            "  [mediation:",
            Style::default().fg(Color::DarkGray),
        ));
        header_spans.push(Span::styled(
            caps.policy_mediation.as_str(),
            Style::default().fg(med_color).add_modifier(Modifier::BOLD),
        ));
        header_spans.push(Span::styled("]", Style::default().fg(Color::DarkGray)));

        if let Some(session_id) = &caps.active_capture_session_id {
            let fps = caps.active_capture_target_fps.unwrap_or(0);
            header_spans.push(Span::styled(
                format!("  [capture:{session_id}@{fps}fps]"),
                Style::default().fg(Color::Cyan),
            ));
        }

        let auth_color = if caps.auth_ready {
            Color::Green
        } else {
            Color::Yellow
        };
        header_spans.push(Span::styled(
            format!("  [auth:{} ", caps.auth_mode),
            Style::default().fg(Color::DarkGray),
        ));
        header_spans.push(Span::styled(
            if caps.auth_ready {
                "ready"
            } else {
                "not-ready"
            },
            Style::default().fg(auth_color).add_modifier(Modifier::BOLD),
        ));
        header_spans.push(Span::styled("]", Style::default().fg(Color::DarkGray)));

        if let Some(action) = &caps.last_tool_action {
            let decision = caps
                .last_tool_decision
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let decision_color = if decision == "allow" {
                Color::Green
            } else {
                Color::Yellow
            };
            header_spans.push(Span::styled(
                "  [tool:",
                Style::default().fg(Color::DarkGray),
            ));
            header_spans.push(Span::styled(action, Style::default().fg(Color::White)));
            header_spans.push(Span::styled(" ", Style::default().fg(Color::DarkGray)));
            header_spans.push(Span::styled(
                decision,
                Style::default()
                    .fg(decision_color)
                    .add_modifier(Modifier::BOLD),
            ));
            header_spans.push(Span::styled("]", Style::default().fg(Color::DarkGray)));
        }
    }

    let header_line = Line::from(header_spans);

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

    let title = if app.detail_scroll > 0 {
        format!(" Chat (scroll +{}) ", app.detail_scroll)
    } else {
        " Chat ".to_string()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::DarkGray));

    if lines.is_empty() {
        let hint = if app.connected {
            "Waiting for output..."
        } else {
            "Disconnected. Start daemon with :daemon start"
        };
        let empty = Paragraph::new(hint)
            .style(Style::default().fg(Color::DarkGray))
            .block(block);
        frame.render_widget(empty, area);
        return;
    }

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
            } else if line.starts_with("You:") {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if line.starts_with("> Bash:") {
                Style::default().fg(Color::Rgb(253, 93, 177)) // hot pink (CC bash border)
            } else if line.starts_with("> Read:")
                || line.starts_with("> Write:")
                || line.starts_with("> Edit:")
                || line.starts_with("> Glob:")
            {
                Style::default().fg(Color::Cyan)
            } else if line.starts_with("> Grep:") || line.starts_with("> WebSearch:") {
                Style::default().fg(Color::Rgb(177, 185, 249)) // light purple-blue
            } else if line.starts_with("> Task:") {
                Style::default().fg(Color::Rgb(215, 119, 87)) // claude brand color
            } else if line.starts_with("> ") {
                Style::default().fg(Color::DarkGray)
            } else if line.starts_with("Done (") {
                Style::default().fg(Color::Green)
            } else if line.starts_with("Error:") {
                Style::default().fg(Color::Red)
            } else if line.starts_with("Session started") || line.starts_with("--- ") {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Span::styled(*line, style))
        })
        .collect();

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

/// Render the main content of the detail view (output + optional pending panel).
fn draw_detail_main(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    if app.detail_pending.is_empty() {
        // No pending prompts -- full width output
        draw_agent_output(frame, app, area);
    } else {
        // Split horizontally: output on the left, pending on the right
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(area);
        draw_agent_output(frame, app, split[0]);
        draw_pending_panel(frame, app, split[1]);
    }
}

/// Render the pending prompts panel.
fn draw_pending_panel(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = app
        .detail_pending
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let marker = if i == app.pending_selected && app.focus_pending {
                "> "
            } else {
                "  "
            };
            let style = if i == app.pending_selected && app.focus_pending {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Yellow)
            };
            let age = format!(" ({}s)", p.age_secs);
            ListItem::new(Line::from(vec![
                Span::styled(marker, style),
                Span::styled(
                    truncate_str(&p.raw_prompt, (area.width as usize).saturating_sub(12)),
                    style,
                ),
                Span::styled(age, Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();

    let border_color = if app.focus_pending {
        Color::Yellow
    } else {
        Color::DarkGray
    };

    let title = format!(" Pending ({}) ", app.detail_pending.len());
    let hints = if app.focus_pending {
        " a:approve d:deny "
    } else {
        " Tab:focus "
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_bottom(Line::from(hints).right_aligned())
            .border_style(Style::default().fg(border_color)),
    );
    frame.render_widget(list, area);
}

/// Render the text input bar at the bottom of the detail view.
fn draw_input_bar(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let mut cursor_pos = app.input_cursor.min(app.input_buffer.len());
    while cursor_pos > 0 && !app.input_buffer.is_char_boundary(cursor_pos) {
        cursor_pos -= 1;
    }
    let before = &app.input_buffer[..cursor_pos];
    let (cursor_char, after) = if cursor_pos < app.input_buffer.len() {
        let ch = app.input_buffer[cursor_pos..].chars().next().unwrap();
        let end = cursor_pos + ch.len_utf8();
        (&app.input_buffer[cursor_pos..end], &app.input_buffer[end..])
    } else {
        (" ", "")
    };

    let cursor_style = if app.input_mode {
        Style::default().fg(Color::Black).bg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let prefix_style = if app.input_mode {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let text_style = if app.input_mode {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let placeholder = if app.input_mode || !app.input_buffer.is_empty() {
        None
    } else {
        Some("Press i to chat".to_string())
    };

    let line = Line::from(vec![
        Span::styled(" > ", prefix_style),
        Span::styled(before, text_style),
        Span::styled(cursor_char, cursor_style),
        Span::styled(after, text_style),
        placeholder
            .as_deref()
            .map(|p| Span::styled(p, Style::default().fg(Color::DarkGray)))
            .unwrap_or_else(|| Span::styled("", Style::default())),
    ]);

    let title = if app.input_mode {
        " Orchestrator Chat "
    } else {
        " Orchestrator Chat (inactive) "
    };
    let border_color = if app.input_mode {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let bar = Paragraph::new(line).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(border_color)),
    );
    frame.render_widget(bar, area);
}

/// Render the detail status bar.
fn draw_detail_status(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let mut spans = vec![
        Span::styled(" Enter", Style::default().fg(Color::Cyan)),
        Span::styled(": send  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" Esc", Style::default().fg(Color::Yellow)),
        Span::styled(": nav  ", Style::default().fg(Color::DarkGray)),
        Span::styled("i", Style::default().fg(Color::Cyan)),
        Span::styled(": chat  ", Style::default().fg(Color::DarkGray)),
        Span::styled(":", Style::default().fg(Color::Yellow)),
        Span::styled(": cmd  ", Style::default().fg(Color::DarkGray)),
    ];

    if !app.detail_pending.is_empty() {
        spans.extend([
            Span::styled("a", Style::default().fg(Color::Green)),
            Span::styled(": approve  ", Style::default().fg(Color::DarkGray)),
            Span::styled("d", Style::default().fg(Color::Red)),
            Span::styled(": deny  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::styled(": focus  ", Style::default().fg(Color::DarkGray)),
        ]);
    }

    spans.extend([
        Span::styled(
            ":",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" cmd  ", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::styled(" back  ", Style::default().fg(Color::DarkGray)),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::styled(" scroll  ", Style::default().fg(Color::DarkGray)),
        Span::styled("n", Style::default().fg(Color::Magenta)),
        Span::styled(" nudge  ", Style::default().fg(Color::DarkGray)),
        Span::styled("p", Style::default().fg(Color::Yellow)),
        Span::styled(" pop  ", Style::default().fg(Color::DarkGray)),
        Span::styled("s", Style::default().fg(Color::Green)),
        Span::styled("/", Style::default().fg(Color::DarkGray)),
        Span::styled("x", Style::default().fg(Color::Red)),
        Span::styled("/", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::styled(" start/stop/restart", Style::default().fg(Color::DarkGray)),
    ]);

    if app.detail_attention {
        spans.push(Span::styled(
            "  ATTENTION",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }

    let status = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(status, area);
}

/// Render the command bar (: mode) or command result.
fn draw_command_bar(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    if app.command_mode {
        let mut cursor_pos = app.command_cursor.min(app.command_buffer.len());
        while cursor_pos > 0 && !app.command_buffer.is_char_boundary(cursor_pos) {
            cursor_pos -= 1;
        }
        let before = &app.command_buffer[..cursor_pos];
        let (cursor_char, after) = if cursor_pos < app.command_buffer.len() {
            let ch = app.command_buffer[cursor_pos..].chars().next().unwrap();
            let end = cursor_pos + ch.len_utf8();
            (
                &app.command_buffer[cursor_pos..end],
                &app.command_buffer[end..],
            )
        } else {
            (" ", "")
        };

        let mut spans = vec![
            Span::styled(
                ":",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(before, Style::default().fg(Color::White)),
            Span::styled(
                cursor_char,
                Style::default().fg(Color::Black).bg(Color::White),
            ),
            Span::styled(after, Style::default().fg(Color::White)),
        ];

        // Show completions hint with selected item highlighted
        if !app.command_completions.is_empty() {
            spans.push(Span::styled("  [", Style::default().fg(Color::DarkGray)));
            for (i, comp) in app.command_completions.iter().take(5).enumerate() {
                if i > 0 {
                    spans.push(Span::styled(" | ", Style::default().fg(Color::DarkGray)));
                }
                if app.completion_idx == Some(i) {
                    spans.push(Span::styled(
                        comp.clone(),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ));
                } else {
                    spans.push(Span::styled(
                        comp.clone(),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
            }
            if app.command_completions.len() > 5 {
                spans.push(Span::styled(
                    format!(" +{}", app.command_completions.len() - 5),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            spans.push(Span::styled("]", Style::default().fg(Color::DarkGray)));
        }

        let bar = Paragraph::new(Line::from(spans))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
        frame.render_widget(bar, area);
    } else if let Some(ref result) = app.command_result {
        let bar = Paragraph::new(Span::styled(
            format!(" {result}"),
            Style::default().fg(Color::DarkGray),
        ))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        frame.render_widget(bar, area);
    }
}

/// Draw the scrollable help view.
fn draw_help_view(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Help text
            Constraint::Length(3), // Footer
        ])
        .split(area);

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " Aegis Fleet ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  Help", Style::default().fg(Color::Cyan)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(header, chunks[0]);

    // Help text with scroll
    let help = super::command::help_text();
    let lines: Vec<Line> = help
        .lines()
        .skip(app.help_scroll)
        .map(|l| {
            if l.starts_with("  :") {
                // Command lines: highlight the command name
                let parts: Vec<&str> = l.splitn(2, "  ").collect();
                if parts.len() == 2 {
                    Line::from(vec![
                        Span::styled(parts[0], Style::default().fg(Color::Yellow)),
                        Span::styled(
                            format!("  {}", parts[1]),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ])
                } else {
                    Line::styled(l, Style::default().fg(Color::Yellow))
                }
            } else {
                Line::styled(l, Style::default().fg(Color::White))
            }
        })
        .collect();

    let content = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Commands ")
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(content, chunks[1]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" j/k", Style::default().fg(Color::Yellow)),
        Span::styled(": scroll  ", Style::default().fg(Color::DarkGray)),
        Span::styled("g/G", Style::default().fg(Color::Yellow)),
        Span::styled(": top/bottom  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc/q", Style::default().fg(Color::Yellow)),
        Span::styled(": back", Style::default().fg(Color::DarkGray)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(footer, chunks[2]);
}

/// Draw the add-agent wizard.
fn draw_wizard(frame: &mut Frame, wiz: &AddAgentWizard, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Content
            Constraint::Length(3), // Footer
        ])
        .split(area);

    // Header
    let is_custom = wiz.is_custom_tool();
    let is_orch = wiz.is_orchestrator();
    let step_num = wiz.step.number(is_custom, is_orch);
    let total = WizardStep::total(is_custom, is_orch);
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " Add Agent ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  Step {step_num}/{total}"),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(header, chunks[0]);

    // Content -- depends on current step
    match wiz.step {
        WizardStep::Tool => draw_wizard_tool(frame, wiz, chunks[1]),
        WizardStep::CustomCommand => draw_wizard_text(
            frame,
            "Custom Command (e.g. my-tool --flag)",
            &wiz.custom_command,
            wiz.custom_command_cursor,
            chunks[1],
        ),
        WizardStep::AgentType => draw_wizard_agent_type(frame, wiz, chunks[1]),
        WizardStep::Name => {
            draw_wizard_text(frame, "Agent Name", &wiz.name, wiz.name_cursor, chunks[1])
        }
        WizardStep::WorkingDir => draw_wizard_text(
            frame,
            "Working Directory",
            &wiz.working_dir,
            wiz.working_dir_cursor,
            chunks[1],
        ),
        WizardStep::Task => draw_wizard_multiline_text(
            frame,
            "Task / Prompt (optional, Enter to skip)",
            &wiz.task,
            wiz.task_cursor,
            chunks[1],
        ),
        WizardStep::Role => {
            let label = if wiz.is_orchestrator() {
                "Role (e.g. \"Technical Director\")"
            } else {
                "Role (optional, e.g. \"UX specialist\")"
            };
            draw_wizard_multiline_text(frame, label, &wiz.role, wiz.role_cursor, chunks[1]);
        }
        WizardStep::AgentGoal => {
            let label = if wiz.is_orchestrator() {
                "Goal (what this orchestrator should optimize for)"
            } else {
                "Goal (optional, what this agent should achieve)"
            };
            draw_wizard_multiline_text(
                frame,
                label,
                &wiz.agent_goal,
                wiz.agent_goal_cursor,
                chunks[1],
            );
        }
        WizardStep::Context => draw_wizard_multiline_text(
            frame,
            "Context (optional, constraints or instructions)",
            &wiz.context,
            wiz.context_cursor,
            chunks[1],
        ),
        WizardStep::BacklogPath => draw_wizard_text(
            frame,
            "Backlog Path (optional, path to roadmap/backlog file)",
            &wiz.backlog_path,
            wiz.backlog_path_cursor,
            chunks[1],
        ),
        WizardStep::ReviewInterval => draw_wizard_text(
            frame,
            "Review Interval (seconds between review cycles, default: 300)",
            &wiz.review_interval,
            wiz.review_interval_cursor,
            chunks[1],
        ),
        WizardStep::RestartPolicy => draw_wizard_restart(frame, wiz, chunks[1]),
        WizardStep::Confirm => draw_wizard_confirm(frame, wiz, chunks[1]),
    }

    // Footer -- Esc behavior depends on step (back-navigation):
    // Tool: Esc cancels wizard. All other steps: Esc goes back one step.
    let footer_text = match wiz.step {
        WizardStep::Tool | WizardStep::AgentType => "j/k: select  Enter: confirm  Esc: cancel",
        WizardStep::RestartPolicy => "j/k: select  Enter: confirm  Esc: back",
        WizardStep::Confirm => "Enter/y: create agent  n: cancel  Esc: back",
        _ => "Type to edit  Enter: next  Esc: back",
    };
    let footer_spans = if let Some(ref err) = wiz.validation_error {
        vec![
            Span::styled(format!(" {err}"), Style::default().fg(Color::Red)),
            Span::styled(
                format!("  {footer_text}"),
                Style::default().fg(Color::DarkGray),
            ),
        ]
    } else {
        vec![Span::styled(
            format!(" {footer_text}"),
            Style::default().fg(Color::DarkGray),
        )]
    };
    let footer = Paragraph::new(Line::from(footer_spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(footer, chunks[2]);
}

/// Draw tool selection step.
fn draw_wizard_tool(frame: &mut Frame, wiz: &AddAgentWizard, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = ToolChoice::ALL
        .iter()
        .enumerate()
        .map(|(i, tool)| {
            let marker = if i == wiz.tool_selected { "> " } else { "  " };
            let style = if i == wiz.tool_selected {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Line::from(vec![
                Span::styled(marker, style),
                Span::styled(tool.label(), style),
                Span::styled(
                    format!("  -- {}", tool.description()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Select Tool ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(list, area);
}

/// Draw agent type selection step (Worker vs Orchestrator).
fn draw_wizard_agent_type(frame: &mut Frame, wiz: &AddAgentWizard, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = AgentTypeChoice::ALL
        .iter()
        .enumerate()
        .map(|(i, choice)| {
            let marker = if i == wiz.agent_type_selected {
                "> "
            } else {
                "  "
            };
            let style = if i == wiz.agent_type_selected {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Line::from(vec![
                Span::styled(marker, style),
                Span::styled(choice.label(), style),
                Span::styled(
                    format!("  -- {}", choice.description()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Agent Type ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(list, area);
}

/// Draw a text input step with cursor.
fn draw_wizard_text(
    frame: &mut Frame,
    label: &str,
    text: &str,
    cursor: usize,
    area: ratatui::layout::Rect,
) {
    let mut cursor_pos = cursor.min(text.len());
    while cursor_pos > 0 && !text.is_char_boundary(cursor_pos) {
        cursor_pos -= 1;
    }
    let before = &text[..cursor_pos];
    let (cursor_char, after) = if cursor_pos < text.len() {
        let ch = text[cursor_pos..].chars().next().unwrap();
        let end = cursor_pos + ch.len_utf8();
        (&text[cursor_pos..end], &text[end..])
    } else {
        (" ", "")
    };

    let input_line = Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(before, Style::default().fg(Color::White)),
        Span::styled(
            cursor_char,
            Style::default().fg(Color::Black).bg(Color::White),
        ),
        Span::styled(after, Style::default().fg(Color::White)),
    ]);

    let content = Paragraph::new(vec![Line::from(""), input_line])
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {label} "))
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(content, area);
}

/// Draw a multi-line text input step with cursor and word-wrap.
///
/// Used for Task, Role, and AgentGoal fields which can contain long pasted text.
fn draw_wizard_multiline_text(
    frame: &mut Frame,
    label: &str,
    text: &str,
    cursor: usize,
    area: ratatui::layout::Rect,
) {
    let text_style = Style::default().fg(Color::White);
    let cursor_style = Style::default().fg(Color::Black).bg(Color::White);

    // Build title with char count for non-empty text
    let title = if text.is_empty() {
        format!(" {label} ")
    } else {
        format!(" {label}  [{} chars] ", text.chars().count())
    };

    let lines = build_multiline_input(text, cursor, text_style, cursor_style);

    let content = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(content, area);
}

/// Build multi-line `Line` spans from text with newlines, placing the cursor block.
fn build_multiline_input<'a>(
    text: &str,
    cursor: usize,
    text_style: Style,
    cursor_style: Style,
) -> Vec<Line<'a>> {
    let pos = cursor.min(text.len());

    if text.is_empty() {
        return vec![Line::from(Span::styled(" ", cursor_style))];
    }

    let mut result = Vec::new();
    let mut offset = 0;

    for segment in text.split('\n') {
        let seg_start = offset;
        let seg_end = offset + segment.len();

        if pos >= seg_start && pos <= seg_end {
            // Cursor is in this segment
            let local = pos - seg_start;
            // Clamp to char boundary
            let mut safe_local = local.min(segment.len());
            while safe_local > 0 && !segment.is_char_boundary(safe_local) {
                safe_local -= 1;
            }
            let mut spans = Vec::new();

            if safe_local > 0 {
                spans.push(Span::styled(segment[..safe_local].to_string(), text_style));
            }
            if safe_local < segment.len() {
                let ch = segment[safe_local..].chars().next().unwrap();
                let ch_end = safe_local + ch.len_utf8();
                spans.push(Span::styled(
                    segment[safe_local..ch_end].to_string(),
                    cursor_style,
                ));
                if ch_end < segment.len() {
                    spans.push(Span::styled(segment[ch_end..].to_string(), text_style));
                }
            } else {
                // Cursor at end of segment
                spans.push(Span::styled(" ".to_string(), cursor_style));
            }

            result.push(Line::from(spans));
        } else {
            result.push(Line::from(Span::styled(segment.to_string(), text_style)));
        }

        // +1 for the '\n' delimiter
        offset = seg_end + 1;
    }

    result
}

fn draw_context_editor(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let Some(editor) = &app.context_editor else {
        return;
    };
    let popup = centered_rect(80, 70, area);

    let title = format!(" Edit {} for {} ", editor.field, editor.agent);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .split(inner);

    let text_style = Style::default().fg(Color::White);
    let cursor_style = Style::default().fg(Color::Black).bg(Color::White);
    let lines = build_multiline_input(&editor.buffer, editor.cursor, text_style, cursor_style);
    let content = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(content, chunks[0]);

    let help = Line::from(vec![
        Span::styled("Ctrl+S", Style::default().fg(Color::Green)),
        Span::styled(" save  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]);
    let help_widget = Paragraph::new(help);
    frame.render_widget(help_widget, chunks[1]);
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
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

/// Draw restart policy selection.
fn draw_wizard_restart(frame: &mut Frame, wiz: &AddAgentWizard, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = RestartChoice::ALL
        .iter()
        .enumerate()
        .map(|(i, choice)| {
            let marker = if i == wiz.restart_selected {
                "> "
            } else {
                "  "
            };
            let style = if i == wiz.restart_selected {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Span::styled(format!("{marker}{}", choice.label()), style))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Restart Policy ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(list, area);
}

/// Draw the confirmation summary.
fn draw_wizard_confirm(frame: &mut Frame, wiz: &AddAgentWizard, area: ratatui::layout::Rect) {
    let tool_label = wiz.tool_choice().label();
    let type_label = wiz.agent_type_choice().label();
    let restart_label = wiz.restart_choice().label();
    let task_display = if wiz.task.trim().is_empty() {
        "(none)".to_string()
    } else {
        truncate_str(&wiz.task, 60)
    };
    let role_display = if wiz.role.trim().is_empty() {
        "(none)".to_string()
    } else {
        truncate_str(&wiz.role, 60)
    };
    let goal_display = if wiz.agent_goal.trim().is_empty() {
        "(none)".to_string()
    } else {
        truncate_str(&wiz.agent_goal, 60)
    };
    let context_display = if wiz.context.trim().is_empty() {
        "(none)".to_string()
    } else {
        truncate_str(&wiz.context, 60)
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Tool:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(tool_label, Style::default().fg(Color::Cyan)),
        ]),
    ];

    if wiz.is_custom_tool() {
        lines.push(Line::from(vec![
            Span::styled("  Command:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                truncate_str(&wiz.custom_command, 60),
                Style::default().fg(Color::White),
            ),
        ]));
    }

    let type_color = if wiz.is_orchestrator() {
        Color::Magenta
    } else {
        Color::White
    };
    lines.push(Line::from(vec![
        Span::styled("  Type:      ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            type_label,
            Style::default().fg(type_color).add_modifier(Modifier::BOLD),
        ),
    ]));

    lines.push(Line::from(vec![
        Span::styled("  Name:      ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            &wiz.name,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.extend([Line::from(vec![
        Span::styled("  Dir:       ", Style::default().fg(Color::DarkGray)),
        Span::styled(&wiz.working_dir, Style::default().fg(Color::White)),
    ])]);

    // Task only shown for workers
    if !wiz.is_orchestrator() {
        lines.push(Line::from(vec![
            Span::styled("  Task:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(task_display, Style::default().fg(Color::White)),
        ]));
    }

    lines.extend([
        Line::from(vec![
            Span::styled("  Role:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(role_display, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Goal:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(goal_display, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Context:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(context_display, Style::default().fg(Color::White)),
        ]),
    ]);

    // Orchestrator-specific fields
    if wiz.is_orchestrator() {
        let backlog = if wiz.backlog_path.trim().is_empty() {
            "(none)".to_string()
        } else {
            truncate_str(&wiz.backlog_path, 50)
        };
        let interval = if wiz.review_interval.trim().is_empty() {
            "300".to_string()
        } else {
            wiz.review_interval.trim().to_string()
        };
        lines.extend([
            Line::from(vec![
                Span::styled("  Backlog:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(backlog, Style::default().fg(Color::Magenta)),
            ]),
            Line::from(vec![
                Span::styled("  Interval:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{interval}s"), Style::default().fg(Color::Magenta)),
            ]),
        ]);
    }

    lines.extend([
        Line::from(vec![
            Span::styled("  Restart:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(restart_label, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Press Enter or 'y' to create, 'n' or Esc to cancel",
            Style::default().fg(Color::Yellow),
        )),
    ]);

    let content = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Confirm ")
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(content, area);
}

/// Get display text and color for an agent status.
fn status_display(status: &AgentStatus) -> (String, Color) {
    match status {
        AgentStatus::Running { .. } => ("Running".into(), Color::Green),
        AgentStatus::Stopped { .. } => ("Stopped".into(), Color::DarkGray),
        AgentStatus::Pending => ("Pending".into(), Color::Cyan),
        AgentStatus::Crashed {
            restart_in_secs, ..
        } => (format!("Crashed ({restart_in_secs}s)"), Color::Yellow),
        AgentStatus::Failed { .. } => ("Failed".into(), Color::Red),
        AgentStatus::Stopping => ("Stopping".into(), Color::Yellow),
        AgentStatus::Disabled => ("Disabled".into(), Color::DarkGray),
    }
}

fn format_fallback_summary(fallback: &aegis_control::daemon::ModelFallbackState) -> String {
    if fallback.active {
        let active = fallback.active_model.as_deref().unwrap_or("unknown");
        let selected = fallback.selected_model.as_deref().unwrap_or("unknown");
        let reason = fallback.reason.as_deref().unwrap_or("unknown");
        let raw = format!("{active} <- {selected}; {reason}");
        truncate_str(&raw, 42)
    } else if let Some(selected) = &fallback.selected_model {
        truncate_str(&format!("cleared {selected}"), 42)
    } else {
        "cleared".to_string()
    }
}

/// Truncate a path string, keeping the tail.
fn truncate_path(path: &str, max: usize) -> String {
    let char_count = path.chars().count();
    if char_count <= max {
        path.to_string()
    } else {
        let skip = char_count - (max.saturating_sub(3));
        let tail: String = path.chars().skip(skip).collect();
        format!("...{tail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_uptime_seconds() {
        assert_eq!(super::super::format_uptime(45), "45s");
    }

    #[test]
    fn format_uptime_minutes() {
        assert_eq!(super::super::format_uptime(125), "2m 5s");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(super::super::format_uptime(7265), "2h 1m");
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
    fn status_display_variants() {
        assert_eq!(
            status_display(&AgentStatus::Running { pid: 1 }).0,
            "Running"
        );
        assert_eq!(
            status_display(&AgentStatus::Stopped { exit_code: 0 }).0,
            "Stopped"
        );
        assert_eq!(status_display(&AgentStatus::Pending).0, "Pending");
        assert_eq!(
            status_display(&AgentStatus::Crashed {
                exit_code: 1,
                restart_in_secs: 5
            })
            .0,
            "Crashed (5s)"
        );
        assert_eq!(
            status_display(&AgentStatus::Failed {
                exit_code: 1,
                restart_count: 3
            })
            .0,
            "Failed"
        );
        assert_eq!(status_display(&AgentStatus::Stopping).0, "Stopping");
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
        app.agents = vec![aegis_control::daemon::AgentSummary {
            name: "test-agent".into(),
            status: AgentStatus::Running { pid: 42 },
            tool: "ClaudeCode".into(),
            working_dir: "/tmp/test".into(),
            role: None,
            restart_count: 0,
            pending_count: 0,
            attention_needed: false,
            is_orchestrator: false,
            attach_command: None,
            fallback: None,
        }];
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

    #[test]
    fn draw_does_not_panic_wizard_view() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::AddAgent;
        app.wizard = Some(crate::fleet_tui::wizard::AddAgentWizard::new());
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_detail_with_pending() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::AgentDetail;
        app.detail_name = "test-agent".into();
        app.detail_output.push_back("line 1".into());
        app.detail_pending = vec![
            aegis_control::daemon::PendingPromptSummary {
                request_id: "abc-123".into(),
                raw_prompt: "Allow Bash(rm -rf)?".into(),
                age_secs: 10,
            },
            aegis_control::daemon::PendingPromptSummary {
                request_id: "def-456".into(),
                raw_prompt: "Allow FileWrite?".into(),
                age_secs: 5,
            },
        ];
        app.focus_pending = true;
        app.pending_selected = 1;
        let backend = ratatui::backend::TestBackend::new(100, 30);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_input_mode() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::AgentDetail;
        app.detail_name = "test-agent".into();
        app.input_mode = true;
        app.input_buffer = "hello world".into();
        app.input_cursor = 5;
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_attention() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::AgentDetail;
        app.detail_name = "test-agent".into();
        app.detail_attention = true;
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_wizard_confirm() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::AddAgent;
        let mut wiz = crate::fleet_tui::wizard::AddAgentWizard::new();
        wiz.step = crate::fleet_tui::wizard::WizardStep::Confirm;
        wiz.name = "test-agent".into();
        wiz.working_dir = "/tmp/test".into();
        app.wizard = Some(wiz);
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_wizard_confirm_custom_tool() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::AddAgent;
        let mut wiz = crate::fleet_tui::wizard::AddAgentWizard::new();
        wiz.tool_selected = 4; // Custom
        wiz.custom_command = "my-tool --verbose --timeout 30".into();
        wiz.step = crate::fleet_tui::wizard::WizardStep::Confirm;
        wiz.name = "custom-agent".into();
        wiz.working_dir = "/tmp/test".into();
        app.wizard = Some(wiz);
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_help_view() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::Help;
        app.help_scroll = 0;
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_help_view_scrolled() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::Help;
        app.help_scroll = 10;
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn build_multiline_input_multibyte_cursor() {
        let text_style = Style::default().fg(Color::White);
        let cursor_style = Style::default().fg(Color::Black).bg(Color::White);
        // e-acute is 2 bytes in UTF-8
        let text = "a\u{00e9}b";
        // Cursor at byte 1 (on the e-acute char) -- should not panic
        let lines = build_multiline_input(text, 1, text_style, cursor_style);
        assert_eq!(lines.len(), 1);
        // Cursor at byte 3 (on 'b') -- should not panic
        let lines = build_multiline_input(text, 3, text_style, cursor_style);
        assert_eq!(lines.len(), 1);
        // Cursor at byte 2 (middle of e-acute) -- should clamp to boundary
        let lines = build_multiline_input(text, 2, text_style, cursor_style);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn build_multiline_input_with_newlines() {
        let text_style = Style::default().fg(Color::White);
        let cursor_style = Style::default().fg(Color::Black).bg(Color::White);
        let text = "line1\nline2\nline3";
        // Cursor in second line
        let lines = build_multiline_input(text, 8, text_style, cursor_style);
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn wrapped_input_height_basic() {
        // 80-wide area, 2 borders = 78 usable columns
        assert_eq!(wrapped_input_height(0, 80, 6), 3); // empty: 1 line + 2 borders
        assert_eq!(wrapped_input_height(78, 80, 6), 3); // exactly 1 line
        assert_eq!(wrapped_input_height(79, 80, 6), 4); // wraps to 2 lines
        assert_eq!(wrapped_input_height(156, 80, 6), 4); // exactly 2 lines
        assert_eq!(wrapped_input_height(157, 80, 6), 5); // wraps to 3 lines
    }

    #[test]
    fn wrapped_input_height_capped() {
        // Very long content should be capped at max_content_lines + 2
        assert_eq!(wrapped_input_height(10000, 80, 6), 8); // 6 + 2
    }

    #[test]
    fn wrapped_input_height_narrow() {
        // width=5, usable=3: ceil(10/3)=4, min(4,6)=4, +2=6
        assert_eq!(wrapped_input_height(10, 5, 6), 6);
        // width=2, usable=0: fallback to 3
        assert_eq!(wrapped_input_height(10, 2, 6), 3);
        // width=0: fallback to 3
        assert_eq!(wrapped_input_height(10, 0, 6), 3);
    }

    #[test]
    fn draw_does_not_panic_long_command_buffer() {
        let mut app = FleetApp::new(None);
        app.command_mode = true;
        app.command_buffer = "goal ".to_string() + &"x".repeat(200);
        app.command_cursor = app.command_buffer.len();
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_long_input_buffer() {
        let mut app = FleetApp::new(None);
        app.view = FleetView::AgentDetail;
        app.detail_name = "test-agent".into();
        app.input_mode = true;
        app.input_buffer = "x".repeat(200);
        app.input_cursor = 200;
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_long_command_result() {
        let mut app = FleetApp::new(None);
        app.command_result = Some("x".repeat(200));
        app.command_result_at = Some(std::time::Instant::now());
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_long_command_narrow_terminal() {
        let mut app = FleetApp::new(None);
        app.command_mode = true;
        app.command_buffer = "x".repeat(50);
        app.command_cursor = 50;
        let backend = ratatui::backend::TestBackend::new(20, 10);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
    }
}
