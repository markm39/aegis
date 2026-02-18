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

use super::wizard::{AddAgentWizard, RestartChoice, ToolChoice, WizardStep};
use super::{FleetApp, FleetView};

/// Draw the fleet TUI to the terminal frame.
pub fn draw(frame: &mut Frame, app: &FleetApp) {
    // If command mode is active, add a command bar at the bottom
    let has_command = app.command_mode || app.command_result.is_some();

    let chunks = if has_command {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),   // Main content
                Constraint::Length(3), // Status bar
                Constraint::Length(3), // Command bar
            ])
            .split(frame.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),   // Main content
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

            if app.input_mode {
                // Split main area into output + input bar
                let detail_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(0), Constraint::Length(3)])
                    .split(chunks[1]);
                draw_detail_main(frame, app, detail_chunks[0]);
                draw_input_bar(frame, app, detail_chunks[1]);
            } else {
                draw_detail_main(frame, app, chunks[1]);
            }

            draw_detail_status(frame, app, chunks[2]);
        }
        FleetView::AddAgent => {
            if let Some(ref wiz) = app.wizard {
                draw_wizard(frame, wiz, frame.area());
            }
        }
    }

    // Draw command bar / result overlay if active
    if has_command && chunks.len() > 3 {
        draw_command_bar(frame, app, chunks[3]);
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

    let mut header_spans = vec![
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
    ];

    if let Some(ref goal) = app.fleet_goal {
        header_spans.push(Span::styled("  Goal: ", Style::default().fg(Color::DarkGray)));
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

    let header = Row::new(vec!["", "NAME", "ROLE", "STATUS", "TOOL", "RESTARTS", "DIR"])
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
            let role = agent.role.as_deref().unwrap_or("-").to_string();

            let style = if i == app.agent_selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new(vec![
                selected.to_string(),
                agent.name.clone(),
                truncate_str(&role, 16),
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
        Constraint::Length(18),
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
        Span::styled("a", Style::default().fg(Color::Cyan)),
        Span::styled(": add  ", Style::default().fg(Color::DarkGray)),
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

    let agent_summary = app
        .agents
        .iter()
        .find(|a| a.name == app.detail_name);

    let tool = agent_summary
        .map(|a| a.tool.as_str())
        .unwrap_or("?");

    let role = agent_summary
        .and_then(|a| a.role.as_deref());

    let mut header_spans = vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            &app.detail_name,
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
    ];

    if let Some(r) = role {
        header_spans.push(Span::styled(
            format!("  [{r}]"),
            Style::default().fg(Color::Yellow),
        ));
    }

    header_spans.extend([
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

    if !app.detail_pending.is_empty() {
        header_spans.push(Span::styled(
            format!("  [{} pending]", app.detail_pending.len()),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }

    if app.detail_attention {
        header_spans.push(Span::styled(
            "  [ATTENTION]",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
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
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
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
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(border_color)),
    );
    frame.render_widget(list, area);
}

/// Render the text input bar at the bottom of the detail view.
fn draw_input_bar(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let cursor_pos = app.input_cursor.min(app.input_buffer.len());
    let before = &app.input_buffer[..cursor_pos];
    let cursor_char = app.input_buffer.get(cursor_pos..cursor_pos + 1).unwrap_or(" ");
    let after = if cursor_pos < app.input_buffer.len() {
        &app.input_buffer[cursor_pos + 1..]
    } else {
        ""
    };

    let line = Line::from(vec![
        Span::styled(" > ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(before, Style::default().fg(Color::White)),
        Span::styled(
            cursor_char,
            Style::default().fg(Color::Black).bg(Color::White),
        ),
        Span::styled(after, Style::default().fg(Color::White)),
    ]);

    let bar = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Send Input ")
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(bar, area);
}

/// Render the detail status bar.
fn draw_detail_status(frame: &mut Frame, app: &FleetApp, area: ratatui::layout::Rect) {
    let mut spans = vec![
        Span::styled(" Esc", Style::default().fg(Color::Yellow)),
        Span::styled(": back  ", Style::default().fg(Color::DarkGray)),
        Span::styled("i", Style::default().fg(Color::Cyan)),
        Span::styled(": input  ", Style::default().fg(Color::DarkGray)),
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
        Span::styled("n", Style::default().fg(Color::Magenta)),
        Span::styled(": nudge  ", Style::default().fg(Color::DarkGray)),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::styled(": scroll  ", Style::default().fg(Color::DarkGray)),
        Span::styled("x", Style::default().fg(Color::Red)),
        Span::styled(": stop  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::styled(": restart", Style::default().fg(Color::DarkGray)),
    ]);

    if app.detail_attention {
        spans.push(Span::styled("  ATTENTION", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
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
        let cursor_pos = app.command_cursor.min(app.command_buffer.len());
        let before = &app.command_buffer[..cursor_pos];
        let cursor_char = app.command_buffer.get(cursor_pos..cursor_pos + 1).unwrap_or(" ");
        let after = if cursor_pos < app.command_buffer.len() {
            &app.command_buffer[cursor_pos + 1..]
        } else {
            ""
        };

        let mut spans = vec![
            Span::styled(":", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(before, Style::default().fg(Color::White)),
            Span::styled(
                cursor_char,
                Style::default().fg(Color::Black).bg(Color::White),
            ),
            Span::styled(after, Style::default().fg(Color::White)),
        ];

        // Show completions hint
        if !app.command_completions.is_empty() {
            let hint = app.command_completions.iter().take(5).cloned().collect::<Vec<_>>().join(" | ");
            spans.push(Span::styled(
                format!("  [{hint}]"),
                Style::default().fg(Color::DarkGray),
            ));
        }

        let bar = Paragraph::new(Line::from(spans)).block(
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
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        frame.render_widget(bar, area);
    }
}

/// Draw the add-agent wizard.
fn draw_wizard(frame: &mut Frame, wiz: &AddAgentWizard, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),   // Content
            Constraint::Length(3), // Footer
        ])
        .split(area);

    // Header
    let step_num = wiz.step.number();
    let total = WizardStep::total();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " Add Agent ",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
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
        WizardStep::Name => draw_wizard_text(frame, "Agent Name", &wiz.name, wiz.name_cursor, chunks[1]),
        WizardStep::WorkingDir => draw_wizard_text(frame, "Working Directory", &wiz.working_dir, wiz.working_dir_cursor, chunks[1]),
        WizardStep::Task => draw_wizard_text(frame, "Task / Prompt (optional, Enter to skip)", &wiz.task, wiz.task_cursor, chunks[1]),
        WizardStep::Role => draw_wizard_text(frame, "Role (optional, e.g. \"UX specialist\")", &wiz.role, wiz.role_cursor, chunks[1]),
        WizardStep::AgentGoal => draw_wizard_text(frame, "Goal (optional, what this agent should achieve)", &wiz.agent_goal, wiz.agent_goal_cursor, chunks[1]),
        WizardStep::RestartPolicy => draw_wizard_restart(frame, wiz, chunks[1]),
        WizardStep::Confirm => draw_wizard_confirm(frame, wiz, chunks[1]),
    }

    // Footer
    let footer_text = match wiz.step {
        WizardStep::Tool | WizardStep::RestartPolicy => "j/k: select  Enter: confirm  Esc: cancel",
        WizardStep::Confirm => "Enter/y: create agent  n/Esc: cancel",
        _ => "Type to edit  Enter: next  Esc: cancel",
    };
    let footer = Paragraph::new(Span::styled(
        format!(" {footer_text}"),
        Style::default().fg(Color::DarkGray),
    ))
    .block(
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
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
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

/// Draw a text input step with cursor.
fn draw_wizard_text(
    frame: &mut Frame,
    label: &str,
    text: &str,
    cursor: usize,
    area: ratatui::layout::Rect,
) {
    let cursor_pos = cursor.min(text.len());
    let before = &text[..cursor_pos];
    let cursor_char = text.get(cursor_pos..cursor_pos + 1).unwrap_or(" ");
    let after = if cursor_pos < text.len() {
        &text[cursor_pos + 1..]
    } else {
        ""
    };

    let input_line = Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(before, Style::default().fg(Color::White)),
        Span::styled(
            cursor_char,
            Style::default()
                .fg(Color::Black)
                .bg(Color::White),
        ),
        Span::styled(after, Style::default().fg(Color::White)),
    ]);

    let content = Paragraph::new(vec![
        Line::from(""),
        input_line,
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {label} "))
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(content, area);
}

/// Draw restart policy selection.
fn draw_wizard_restart(frame: &mut Frame, wiz: &AddAgentWizard, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = RestartChoice::ALL
        .iter()
        .enumerate()
        .map(|(i, choice)| {
            let marker = if i == wiz.restart_selected { "> " } else { "  " };
            let style = if i == wiz.restart_selected {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
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

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Tool:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(tool_label, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("  Name:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(&wiz.name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Dir:       ", Style::default().fg(Color::DarkGray)),
            Span::styled(&wiz.working_dir, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Task:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(task_display, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Role:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(role_display, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Goal:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(goal_display, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Restart:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(restart_label, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Press Enter or 'y' to create, 'n' or Esc to cancel",
            Style::default().fg(Color::Yellow),
        )),
    ];

    let content = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Confirm ")
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(content, area);
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
                role: None,
                restart_count: 0,
                pending_count: 0,
                attention_needed: false,
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
}
