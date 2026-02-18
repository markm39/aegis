//! TUI rendering for the onboarding wizard.
//!
//! Draws each wizard step using ratatui widgets, matching the visual style
//! of the existing Aegis TUIs (Cyan borders, Yellow labels, DarkGray chrome).

use std::time::Duration;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

/// How long the paste indicator stays visible.
const PASTE_INDICATOR_DURATION: Duration = Duration::from_secs(3);

use crate::fleet_tui::wizard::{RestartChoice, ToolChoice};

use super::app::{OnboardApp, OnboardStep, TelegramStatus};

/// Main draw function -- dispatches to the appropriate step renderer.
pub fn draw(f: &mut Frame, app: &OnboardApp) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(5),   // Content
            Constraint::Length(3), // Help
        ])
        .split(area);

    // Title bar with step progress
    let step_num = app.step.number();
    let step_total = OnboardStep::total();
    let step_name = app.step.label();

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "Aegis Onboarding",
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
        OnboardStep::Welcome => draw_welcome(f, app, chunks[1]),
        OnboardStep::Tool => draw_tool(f, app, chunks[1]),
        OnboardStep::CustomCommand => draw_custom_command(f, app, chunks[1]),
        OnboardStep::Name => draw_name(f, app, chunks[1]),
        OnboardStep::WorkingDir => draw_working_dir(f, app, chunks[1]),
        OnboardStep::Task => draw_task(f, app, chunks[1]),
        OnboardStep::RestartPolicy => draw_restart(f, app, chunks[1]),
        OnboardStep::TelegramOffer => draw_telegram_offer(f, app, chunks[1]),
        OnboardStep::TelegramToken => draw_telegram_token(f, app, chunks[1]),
        OnboardStep::TelegramProgress => draw_telegram_progress(f, app, chunks[1]),
        OnboardStep::Summary => draw_summary(f, app, chunks[1]),
        OnboardStep::Done | OnboardStep::Cancelled => {}
    }

    // Help bar
    let help_text = match app.step {
        OnboardStep::Welcome => "Enter: continue  Esc: cancel",
        OnboardStep::Tool => "j/k: navigate  Enter: select  Esc: back",
        OnboardStep::CustomCommand => "Enter: confirm  Esc: back",
        OnboardStep::Name => "Enter: confirm  Esc: back",
        OnboardStep::WorkingDir => "Enter: confirm  Esc: back",
        OnboardStep::Task => "Enter: continue (leave empty to skip)  Esc: back",
        OnboardStep::RestartPolicy => "j/k: navigate  Enter: select  Esc: back",
        OnboardStep::TelegramOffer => "j/k: navigate  Enter: select  Esc: back",
        OnboardStep::TelegramToken => "Enter: validate  Esc: back",
        OnboardStep::TelegramProgress => match &app.telegram_status {
            TelegramStatus::Complete { .. } => "Enter: continue  Esc: cancel",
            TelegramStatus::Failed(_) => "Enter: retry  Esc: cancel",
            _ => "Esc: cancel",
        },
        OnboardStep::Summary => "Enter: confirm  d: toggle daemon  Esc: back  q: cancel",
        OnboardStep::Done | OnboardStep::Cancelled => "",
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

fn draw_welcome(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let (status, color) = if app.aegis_dir_ok {
        ("OK", Color::Green)
    } else {
        ("FAILED", Color::Red)
    };

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Welcome to Aegis -- zero-trust runtime for AI agents.",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "This wizard will configure your first agent, optionally set up",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "Telegram notifications, write daemon.toml, and start the daemon.",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  System check: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("[{status}]"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Aegis dir:    ", Style::default().fg(Color::White)),
            Span::styled(&app.aegis_dir_path, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Press Enter to begin.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Welcome"),
    );
    f.render_widget(p, area);
}

fn draw_tool(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Description
            Constraint::Min(5),   // List
        ])
        .split(area);

    let desc = Paragraph::new(Span::styled(
        "Select the agent tool to supervise.",
        Style::default().fg(Color::White),
    ));
    f.render_widget(desc, chunks[0]);

    let items: Vec<ListItem> = ToolChoice::ALL
        .iter()
        .enumerate()
        .map(|(i, choice)| {
            let selected = i == app.tool_selected;
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
                Span::styled(format!("{:<20}", choice.label()), label_style),
                Span::styled(
                    format!("  {}", choice.description()),
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
            .title("Agent Tool"),
    );
    f.render_widget(list, chunks[1]);
}

fn draw_custom_command(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let indicator_height = paste_indicator_height(app);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),                // Description
            Constraint::Length(3),                // Input
            Constraint::Length(indicator_height),  // Paste indicator
            Constraint::Min(0),                   // Spacer
        ])
        .split(area);

    let desc = Paragraph::new(Span::styled(
        "Enter the full path to your custom agent command (e.g., /usr/local/bin/my-agent).",
        Style::default().fg(Color::White),
    ));
    f.render_widget(desc, chunks[0]);

    let spans = build_cursor_spans(&app.custom_command, app.custom_cursor);
    let input = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Command"),
    );
    f.render_widget(input, chunks[1]);

    draw_paste_indicator(f, app, chunks[2]);
}

fn draw_name(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let error_height = if app.name_error.is_some() { 1 } else { 0 };
    let indicator_height = paste_indicator_height(app);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),                // Description
            Constraint::Length(3),                // Input
            Constraint::Length(error_height),     // Error
            Constraint::Length(indicator_height), // Paste indicator
            Constraint::Min(0),                  // Spacer
        ])
        .split(area);

    let desc = Paragraph::new(Line::from(vec![
        Span::styled(
            "Choose a name for this agent.",
            Style::default().fg(Color::White),
        ),
        Span::styled(
            " Lowercase, hyphens, underscores.",
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(desc, chunks[0]);

    let spans = build_cursor_spans(&app.name, app.name_cursor);
    let input = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Agent Name"),
    );
    f.render_widget(input, chunks[1]);

    if let Some(err) = &app.name_error {
        let error = Paragraph::new(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        ));
        f.render_widget(error, chunks[2]);
    }

    draw_paste_indicator(f, app, chunks[3]);
}

fn draw_working_dir(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let error_height = if app.working_dir_error.is_some() {
        1
    } else {
        0
    };
    let indicator_height = paste_indicator_height(app);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),                // Description
            Constraint::Length(3),                // Input
            Constraint::Length(error_height),     // Error
            Constraint::Length(indicator_height), // Paste indicator
            Constraint::Min(0),                  // Spacer
        ])
        .split(area);

    let desc = Paragraph::new(Span::styled(
        "Enter the working directory for the agent.",
        Style::default().fg(Color::White),
    ));
    f.render_widget(desc, chunks[0]);

    let spans = build_cursor_spans(&app.working_dir, app.working_dir_cursor);
    let input = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Working Directory"),
    );
    f.render_widget(input, chunks[1]);

    if let Some(err) = &app.working_dir_error {
        let error = Paragraph::new(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        ));
        f.render_widget(error, chunks[2]);
    }

    draw_paste_indicator(f, app, chunks[3]);
}

fn draw_task(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let indicator_height = paste_indicator_height(app);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),                // Description
            Constraint::Min(5),                   // Input (expands to fill)
            Constraint::Length(indicator_height),  // Paste indicator
        ])
        .split(area);

    let desc = Paragraph::new(Line::from(vec![
        Span::styled(
            "Enter an initial task for the agent.",
            Style::default().fg(Color::White),
        ),
        Span::styled(
            " Optional -- press Enter to skip. Paste supported.",
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(desc, chunks[0]);

    // Multi-line input with word wrapping
    let char_count = app.task.len();
    let title = if char_count > 0 {
        format!("Task ({char_count} chars)")
    } else {
        "Task".to_string()
    };

    let lines = build_multiline_input(&app.task, app.task_cursor);
    let input = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(title),
        );
    f.render_widget(input, chunks[1]);

    draw_paste_indicator(f, app, chunks[2]);
}

fn draw_restart(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Description
            Constraint::Min(5),   // List
        ])
        .split(area);

    let desc = Paragraph::new(Span::styled(
        "Choose when the daemon should restart this agent.",
        Style::default().fg(Color::White),
    ));
    f.render_widget(desc, chunks[0]);

    let items: Vec<ListItem> = RestartChoice::ALL
        .iter()
        .enumerate()
        .map(|(i, choice)| {
            let selected = i == app.restart_selected;
            let marker = if selected { "> " } else { "  " };

            let label_style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            ListItem::new(Span::styled(
                format!("{marker}{}", choice.label()),
                label_style,
            ))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Restart Policy"),
    );
    f.render_widget(list, chunks[1]);
}

fn draw_telegram_offer(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Description
            Constraint::Min(5),   // List
        ])
        .split(area);

    let desc = Paragraph::new(vec![
        Line::from(Span::styled(
            "Telegram lets you receive agent notifications and send commands",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "from your phone. You can set this up later with `aegis telegram setup`.",
            Style::default().fg(Color::DarkGray),
        )),
    ]);
    f.render_widget(desc, chunks[0]);

    let choices = ["Yes, set up Telegram", "No, skip for now"];
    let items: Vec<ListItem> = choices
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let selected = i == app.telegram_offer_selected;
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
            .title("Telegram Notifications"),
    );
    f.render_widget(list, chunks[1]);
}

fn draw_telegram_token(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Instructions
            Constraint::Length(3), // Input
            Constraint::Min(0),   // Spacer
        ])
        .split(area);

    let instructions = Paragraph::new(vec![
        Line::from(Span::styled(
            "To get a Telegram bot token:",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "  1. Open Telegram and search for @BotFather",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  2. Send /newbot and follow the prompts",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  3. Copy the bot token (looks like 123456:ABC-DEF...)",
            Style::default().fg(Color::DarkGray),
        )),
    ]);
    f.render_widget(instructions, chunks[0]);

    let spans = build_cursor_spans(&app.telegram_token, app.telegram_token_cursor);
    let input = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Bot Token"),
    );
    f.render_widget(input, chunks[1]);
}

fn draw_telegram_progress(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let lines = match &app.telegram_status {
        TelegramStatus::Idle => vec![Line::from(Span::styled(
            "Preparing...",
            Style::default().fg(Color::DarkGray),
        ))],
        TelegramStatus::ValidatingToken => vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Validating bot token...",
                Style::default().fg(Color::Yellow),
            )),
        ],
        TelegramStatus::WaitingForChat { bot_username } => vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Connected to bot ", Style::default().fg(Color::Green)),
                Span::styled(
                    format!("@{bot_username}"),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  Waiting for you to send a message to the bot in Telegram...",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(Span::styled(
                "  Open Telegram, find your bot, and send any message.",
                Style::default().fg(Color::DarkGray),
            )),
        ],
        TelegramStatus::SendingConfirmation => vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Sending confirmation message...",
                Style::default().fg(Color::Yellow),
            )),
        ],
        TelegramStatus::Complete {
            bot_username,
            chat_id,
        } => vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Telegram setup complete!",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Bot:     ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("@{bot_username}"),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Chat ID: ", Style::default().fg(Color::White)),
                Span::styled(
                    chat_id.to_string(),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  Press Enter to continue.",
                Style::default().fg(Color::DarkGray),
            )),
        ],
        TelegramStatus::Failed(err) => vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Telegram setup failed:",
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                format!("  {err}"),
                Style::default().fg(Color::Red),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Press Enter to retry or Esc to skip.",
                Style::default().fg(Color::DarkGray),
            )),
        ],
    };

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Telegram Setup"),
    );
    f.render_widget(p, area);
}

fn draw_summary(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let tool_label = ToolChoice::ALL.get(app.tool_selected)
        .map(|t| t.label())
        .unwrap_or("Unknown");
    let restart_label = RestartChoice::ALL.get(app.restart_selected)
        .map(|r| r.label())
        .unwrap_or("Unknown");

    let task_display = if app.task.trim().is_empty() {
        "(none)".to_string()
    } else if app.task.chars().count() > 60 {
        let preview: String = app.task.chars().take(57).collect();
        format!("{preview}... [{} chars]", app.task.chars().count())
    } else {
        app.task.replace('\n', " ")
    };

    let telegram_display = match &app.telegram_result {
        Some((_, chat_id, bot_username)) => format!("@{bot_username} (chat {})", chat_id),
        None => "(not configured)".to_string(),
    };

    let daemon_display = if app.start_daemon {
        "Yes (press 'd' to toggle)"
    } else {
        "No  (press 'd' to toggle)"
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Review your configuration:",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        labeled_line("Tool:", tool_label, Color::Yellow),
        labeled_line("Name:", &app.name, Color::Yellow),
        labeled_line("Directory:", &app.working_dir, Color::White),
        labeled_line("Task:", &task_display, Color::White),
        labeled_line("Restart:", restart_label, Color::White),
        labeled_line("Telegram:", &telegram_display, Color::White),
        Line::from(""),
    ];

    if ToolChoice::ALL.get(app.tool_selected) == Some(&ToolChoice::Custom) {
        // Insert custom command line after Tool
        lines.insert(4, labeled_line("Command:", &app.custom_command, Color::White));
    }

    lines.push(labeled_line("Start daemon:", daemon_display, Color::Green));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press Enter to confirm and write daemon.toml.",
        Style::default().fg(Color::DarkGray),
    )));

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Summary"),
    );
    f.render_widget(p, area);
}

/// Build cursor-aware text input spans for a single-line field.
///
/// Produces Yellow text with an inverted Yellow cursor block at `cursor_pos`.
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
        spans.push(Span::styled(
            " ",
            Style::default().bg(Color::Yellow),
        ));
    }
    spans
}

/// Build cursor-aware Lines for a multi-line text field.
///
/// Splits text by newlines, finds which line the cursor is on, and applies
/// the inverted cursor block to the correct position. Each line becomes a
/// separate `Line` so `Paragraph::wrap()` handles visual wrapping.
fn build_multiline_input(text: &str, cursor_pos: usize) -> Vec<Line<'static>> {
    let mut pos = cursor_pos.min(text.len());
    while pos > 0 && !text.is_char_boundary(pos) {
        pos -= 1;
    }

    if text.is_empty() {
        return vec![Line::from(Span::styled(
            " ",
            Style::default().bg(Color::Yellow),
        ))];
    }

    let text_style = Style::default().fg(Color::Yellow);
    let cursor_style = Style::default().fg(Color::Black).bg(Color::Yellow);

    let mut result = Vec::new();
    let mut offset = 0;

    for segment in text.split('\n') {
        let seg_start = offset;
        let seg_end = offset + segment.len();

        if pos >= seg_start && pos <= seg_end {
            // Cursor is in this segment
            let local = pos - seg_start;
            let mut spans = Vec::new();

            if local > 0 {
                spans.push(Span::styled(segment[..local].to_string(), text_style));
            }
            if local < segment.len() {
                let ch = segment[local..].chars().next().unwrap();
                let end = local + ch.len_utf8();
                spans.push(Span::styled(
                    segment[local..end].to_string(),
                    cursor_style,
                ));
                if end < segment.len() {
                    spans.push(Span::styled(
                        segment[end..].to_string(),
                        text_style,
                    ));
                }
            } else {
                // Cursor at end of this segment
                spans.push(Span::styled(" ".to_string(), cursor_style));
            }

            result.push(Line::from(spans));
        } else {
            result.push(Line::from(Span::styled(
                segment.to_string(),
                text_style,
            )));
        }

        // +1 for the '\n' separator
        offset = seg_end + 1;
    }

    result
}

/// Return 1 if the paste indicator should be shown, 0 otherwise.
fn paste_indicator_height(app: &OnboardApp) -> u16 {
    match &app.paste_indicator {
        Some((_, when)) if when.elapsed() < PASTE_INDICATOR_DURATION => 1,
        _ => 0,
    }
}

/// Render the paste indicator line if active.
fn draw_paste_indicator(f: &mut Frame, app: &OnboardApp, area: Rect) {
    if let Some((msg, when)) = &app.paste_indicator {
        if when.elapsed() < PASTE_INDICATOR_DURATION {
            let indicator = Paragraph::new(Span::styled(
                format!("  {msg}"),
                Style::default().fg(Color::DarkGray),
            ));
            f.render_widget(indicator, area);
        }
    }
}

/// Build a styled label-value line for the summary.
fn labeled_line<'a>(label: &str, value: &str, color: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("  {label:<14} "),
            Style::default().fg(Color::White),
        ),
        Span::styled(value.to_string(), Style::default().fg(color)),
    ])
}
