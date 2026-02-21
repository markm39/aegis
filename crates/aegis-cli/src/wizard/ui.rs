//! TUI rendering for the setup wizard.
//!
//! Draws each wizard step using ratatui widgets, matching the visual style
//! of the Aegis monitor dashboard (Cyan borders, Yellow labels, Green/Red
//! for allow/deny).

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use super::app::{WizardApp, WizardStep};
use super::model::{ActionPermission, ScopeRule, SecurityPreset};

/// Main draw function -- dispatches to the appropriate step renderer.
pub fn draw(f: &mut Frame, app: &WizardApp) {
    let area = f.area();

    // Outer layout: title bar + content + help bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(5),    // Content
            Constraint::Length(3), // Help
        ])
        .split(area);

    // Title bar with step progress
    let (step_num, step_total) = app.step_number();
    let step_name = match app.step {
        WizardStep::ConfigName => "Configuration Name",
        WizardStep::SecurityPreset => "Security Mode",
        WizardStep::ActionConfig => "Action Permissions",
        WizardStep::ScopeEditor => "Scope Rules",
        WizardStep::ProjectDir => "Project Directory",
        WizardStep::Summary => "Review",
        WizardStep::Done | WizardStep::Cancelled => "Complete",
    };

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "Aegis Setup",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Step {step_num} of {step_total}: {step_name}"),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(title, chunks[0]);

    // Content area
    match app.step {
        WizardStep::ConfigName => draw_config_name(f, app, chunks[1]),
        WizardStep::SecurityPreset => draw_security_preset(f, app, chunks[1]),
        WizardStep::ActionConfig => draw_action_config(f, app, chunks[1]),
        WizardStep::ScopeEditor => draw_scope_editor(f, app, chunks[1]),
        WizardStep::ProjectDir => draw_project_dir(f, app, chunks[1]),
        WizardStep::Summary => draw_summary(f, app, chunks[1]),
        WizardStep::Done | WizardStep::Cancelled => {}
    }

    // Help bar
    let help_text = match app.step {
        WizardStep::ConfigName => "Enter: continue  Esc: cancel",
        WizardStep::SecurityPreset => "j/k: navigate  Enter: select  Esc: back",
        WizardStep::ActionConfig => {
            "j/k: navigate  Space: toggle  Enter: edit scope rules  Tab: continue  Esc: back"
        }
        WizardStep::ScopeEditor if app.scope_editing => "Enter: add rule  Esc: cancel input",
        WizardStep::ScopeEditor => "a: add rule  d: delete  j/k: navigate  Esc: back",
        WizardStep::ProjectDir if app.dir_editing => "Enter: confirm  Esc: cancel input",
        WizardStep::ProjectDir => "j/k: navigate  Enter: select  Esc: back",
        WizardStep::Summary => "Enter: create config  Esc: go back  q: cancel",
        WizardStep::Done | WizardStep::Cancelled => "",
    };

    let help = Paragraph::new(Span::styled(
        help_text,
        Style::default().fg(Color::DarkGray),
    ))
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(help, chunks[2]);
}

fn draw_config_name(f: &mut Frame, app: &WizardApp, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Description
            Constraint::Length(3), // Input
            Constraint::Min(0),    // Spacer
        ])
        .split(area);

    let desc = Paragraph::new(Line::from(vec![
        Span::styled(
            "Choose a name for this configuration.",
            Style::default().fg(Color::White),
        ),
        Span::styled(
            " This will be used as the directory name under ~/.aegis/",
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(desc, chunks[0]);

    // Text input with cursor
    let spans = build_cursor_spans(&app.name_input, app.name_cursor);

    let input = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Name"),
    );
    f.render_widget(input, chunks[1]);
}

fn draw_security_preset(f: &mut Frame, app: &WizardApp, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Description
            Constraint::Min(5),    // List
        ])
        .split(area);

    let desc = Paragraph::new(Span::styled(
        "Choose a security mode. You can customize individual actions later with Custom.",
        Style::default().fg(Color::White),
    ));
    f.render_widget(desc, chunks[0]);

    let items: Vec<ListItem> = SecurityPreset::ALL
        .iter()
        .enumerate()
        .map(|(i, preset)| {
            let selected = i == app.preset_selected;
            let marker = if selected { "> " } else { "  " };

            let label_style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let line = Line::from(vec![
                Span::styled(marker, label_style),
                Span::styled(format!("{:<20}", preset.label()), label_style),
                Span::styled(
                    format!("  {}", preset.description()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Security Mode"),
    );
    f.render_widget(list, chunks[1]);
}

fn draw_action_config(f: &mut Frame, app: &WizardApp, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Description
            Constraint::Min(5),    // List
        ])
        .split(area);

    let desc = Paragraph::new(Span::styled(
        "Toggle actions with Space. Press Enter on any action to customize its scope rules.",
        Style::default().fg(Color::White),
    ));
    f.render_widget(desc, chunks[0]);

    let items: Vec<ListItem> = app
        .actions
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let selected = i == app.action_selected;
            let marker = if selected { "> " } else { "  " };

            let (checkbox, check_color) = match &entry.permission {
                ActionPermission::Allow => ("[x]", Color::Green),
                ActionPermission::Scoped(_) => ("[~]", Color::Yellow),
                ActionPermission::Deny => ("[ ]", Color::Red),
            };

            let label_style = if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let tag = if entry.meta.infrastructure {
                "  (infrastructure)"
            } else if entry.meta.recommended
                && !matches!(&entry.permission, ActionPermission::Scoped(r) if !r.is_empty())
            {
                "  (recommended)"
            } else {
                ""
            };

            // Show scope summary inline for scoped actions; description for others
            let (detail_text, detail_color) = match &entry.permission {
                ActionPermission::Scoped(rules) if !rules.is_empty() => {
                    (format_scope_inline(rules), Color::Yellow)
                }
                _ => (entry.meta.description.to_string(), Color::DarkGray),
            };

            let line = Line::from(vec![
                Span::styled(marker, label_style),
                Span::styled(format!("{checkbox} "), Style::default().fg(check_color)),
                Span::styled(format!("{:<18}", entry.meta.label), label_style),
                Span::styled(detail_text, Style::default().fg(detail_color)),
                Span::styled(tag, Style::default().fg(Color::DarkGray)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Action Permissions"),
    );
    f.render_widget(list, chunks[1]);
}

fn draw_scope_editor(f: &mut Frame, app: &WizardApp, area: ratatui::layout::Rect) {
    let entry = &app.actions[app.scope_action_index];
    let is_network = entry.meta.action == "NetConnect";

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Description
            Constraint::Min(5),    // Rules list
            Constraint::Length(3), // Input (if editing)
        ])
        .split(area);

    let hint = if is_network {
        "Add network hosts (e.g. api.openai.com or api.openai.com:443)"
    } else {
        "Add path patterns (e.g. /Users/me/project/**). Remove all to allow globally."
    };

    let desc = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Scope rules for ", Style::default().fg(Color::White)),
            Span::styled(
                entry.meta.action,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" ({})", entry.meta.label),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray))),
    ]);
    f.render_widget(desc, chunks[0]);

    // Rules list
    let rules = match &entry.permission {
        ActionPermission::Scoped(rules) => rules.as_slice(),
        _ => &[],
    };

    let items: Vec<ListItem> = if rules.is_empty() {
        vec![ListItem::new(Span::styled(
            "  No restrictions. Press 'a' to add a path restriction.",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                let selected = i == app.scope_selected;
                let marker = if selected { "> " } else { "  " };
                let text = match rule {
                    ScopeRule::PathPattern(p) => format!("Path: {p}"),
                    ScopeRule::Host(h) => format!("Host: {h} (any port)"),
                    ScopeRule::HostPort(h, port) => format!("Host: {h}:{port}"),
                };

                // Annotate auto-generated project-dir scopes
                let auto_label = if let ScopeRule::PathPattern(p) = rule {
                    if p.ends_with("/**") && rules.len() == 1 {
                        "  (auto: project dir)"
                    } else {
                        ""
                    }
                } else {
                    ""
                };

                let style = if selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                ListItem::new(Line::from(vec![
                    Span::styled(format!("{marker}{text}"), style),
                    Span::styled(auto_label, Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect()
    };

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Scope Rules"),
    );
    f.render_widget(list, chunks[1]);

    // Input area
    if app.scope_editing {
        let label = if is_network {
            "Host (or host:port)"
        } else {
            "Path pattern"
        };

        let spans = build_cursor_spans(&app.scope_input, app.scope_cursor);
        let input = Paragraph::new(Line::from(spans)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(label),
        );
        f.render_widget(input, chunks[2]);
    }
}

fn draw_project_dir(f: &mut Frame, app: &WizardApp, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Description
            Constraint::Min(5),    // List or input
        ])
        .split(area);

    let desc = Paragraph::new(Span::styled(
        "Select the directory to monitor. This is the sandbox root for the agent.",
        Style::default().fg(Color::White),
    ));
    f.render_widget(desc, chunks[0]);

    if app.dir_editing {
        let spans = build_cursor_spans(&app.dir_input, app.dir_cursor);
        let input = Paragraph::new(Line::from(spans)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title("Custom Path"),
        );
        f.render_widget(input, chunks[1]);
    } else {
        let items: Vec<ListItem> = app
            .dir_choices
            .iter()
            .enumerate()
            .map(|(i, (label, _path))| {
                let selected = i == app.dir_selected;
                let marker = if selected { "> " } else { "  " };
                let style = if selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Span::styled(format!("{marker}{label}"), style))
            })
            .collect();

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title("Project Directory"),
        );
        f.render_widget(list, chunks[1]);
    }
}

fn draw_summary(f: &mut Frame, app: &WizardApp, area: ratatui::layout::Rect) {
    let project_dir = if app.dir_selected < app.dir_choices.len() - 1 {
        app.dir_choices[app.dir_selected].1.display().to_string()
    } else {
        app.dir_input.clone()
    };

    let isolation_desc = match &app.isolation {
        aegis_types::IsolationConfig::Process => "Process (no kernel enforcement)",
        aegis_types::IsolationConfig::Seatbelt { .. } => "Seatbelt (macOS kernel sandbox)",
        aegis_types::IsolationConfig::None => "None",
    };

    let mut lines = vec![
        Line::from(""),
        labeled_line("Name:", &app.name_input, Color::Yellow, true),
        labeled_line("Directory:", &project_dir, Color::White, false),
        labeled_line("Isolation:", isolation_desc, Color::White, false),
        Line::from(""),
        Line::from(Span::styled(
            "Policy:",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    for entry in &app.actions {
        let (status, color) = match &entry.permission {
            ActionPermission::Allow => ("ALLOW", Color::Green),
            ActionPermission::Scoped(rules) if rules.is_empty() => ("ALLOW", Color::Green),
            ActionPermission::Scoped(_) => ("SCOPE", Color::Yellow),
            ActionPermission::Deny => ("DENY ", Color::Red),
        };

        let scope_detail = match &entry.permission {
            ActionPermission::Scoped(rules) if !rules.is_empty() => {
                let details: Vec<String> = rules
                    .iter()
                    .map(|r| match r {
                        ScopeRule::PathPattern(p) => p.clone(),
                        ScopeRule::Host(h) => format!("{h}:*"),
                        ScopeRule::HostPort(h, port) => format!("{h}:{port}"),
                    })
                    .collect();
                format!("  {}", details.join(", "))
            }
            _ => {
                if entry.meta.infrastructure {
                    "  (infrastructure)".to_string()
                } else {
                    String::new()
                }
            }
        };

        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                format!("[{status}]"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {:<18}", entry.meta.action),
                Style::default().fg(Color::White),
            ),
            Span::styled(scope_detail, Style::default().fg(Color::DarkGray)),
        ]));
    }

    let summary = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Configuration Summary"),
    );
    f.render_widget(summary, area);
}

/// Format scope rules for inline display in the action list.
fn format_scope_inline(rules: &[ScopeRule]) -> String {
    let formatted: Vec<String> = rules
        .iter()
        .map(|r| match r {
            ScopeRule::PathPattern(p) => truncate_path(p, 40),
            ScopeRule::Host(h) => format!("{h}:*"),
            ScopeRule::HostPort(h, port) => format!("{h}:{port}"),
        })
        .collect();
    match formatted.len() {
        0 => String::new(),
        1 => formatted[0].clone(),
        2 | 3 => formatted.join(", "),
        n => format!("{}, {} (+{} more)", formatted[0], formatted[1], n - 2),
    }
}

/// Truncate a path string for display, keeping the end visible.
fn truncate_path(path: &str, max_len: usize) -> String {
    if path.chars().count() <= max_len {
        return path.to_string();
    }
    let tail: String = path
        .chars()
        .rev()
        .take(max_len - 3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("...{tail}")
}

/// Build cursor-aware text input spans (before | cursor | after).
///
/// Produces Yellow text with an inverted Yellow cursor block at `cursor_pos`.
/// If the cursor is at the end of text, a trailing block cursor is shown.
fn build_cursor_spans(text: &str, cursor_pos: usize) -> Vec<Span<'_>> {
    let mut pos = cursor_pos.min(text.len());
    while pos > 0 && !text.is_char_boundary(pos) {
        pos -= 1;
    }
    let mut spans = Vec::new();
    if pos > 0 {
        spans.push(Span::styled(
            &text[..pos],
            Style::default().fg(Color::Yellow),
        ));
    }
    if pos < text.len() {
        let ch = text[pos..].chars().next().unwrap();
        let end = pos + ch.len_utf8();
        spans.push(Span::styled(
            &text[pos..end],
            Style::default().fg(Color::Black).bg(Color::Yellow),
        ));
        if end < text.len() {
            spans.push(Span::styled(
                &text[end..],
                Style::default().fg(Color::Yellow),
            ));
        }
    } else {
        spans.push(Span::styled(" ", Style::default().bg(Color::Yellow)));
    }
    spans
}

/// Build a styled label-value line (matching the monitor's pattern).
fn labeled_line<'a>(label: &str, value: &str, color: Color, bold: bool) -> Line<'a> {
    let style = if bold {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(color)
    };
    Line::from(vec![
        Span::styled(format!("  {label:<12} "), Style::default().fg(Color::White)),
        Span::styled(value.to_string(), style),
    ])
}
