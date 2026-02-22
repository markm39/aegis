//! TUI rendering for the onboarding wizard.
//!
//! Draws each of the 7 wizard steps using ratatui widgets, matching the visual
//! style of the existing Aegis TUIs (Cyan borders, Yellow labels, DarkGray chrome).

use std::time::Duration;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::fleet_tui::wizard::ToolChoice;

use super::app::{
    AgentField, ChannelPhase, HealthStatus, OnboardApp, OnboardStep, TelegramStatus,
};

/// How long the paste indicator stays visible.
const PASTE_INDICATOR_DURATION: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// Main draw
// ---------------------------------------------------------------------------

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

    // Title bar with progress
    let progress = app.progress_text();

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "Aegis Setup",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(progress, Style::default().fg(Color::DarkGray)),
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
        OnboardStep::AgentSetup => draw_agent_setup(f, app, chunks[1]),
        OnboardStep::ModelSelection => draw_model_selection(f, app, chunks[1]),
        OnboardStep::ChannelSetup => match app.channel_phase {
            ChannelPhase::Offer => draw_channel_offer(f, app, chunks[1]),
            ChannelPhase::TokenInput => draw_channel_token(f, app, chunks[1]),
            ChannelPhase::Validating => draw_channel_validating(f, app, chunks[1]),
        },
        OnboardStep::Summary => draw_summary(f, app, chunks[1]),
        OnboardStep::HealthCheck => draw_health_check(f, app, chunks[1]),
        OnboardStep::Done | OnboardStep::Cancelled => {}
    }

    // Help bar
    let help_text = match app.step {
        OnboardStep::Welcome => "Enter: continue  Esc: cancel",
        OnboardStep::AgentSetup => {
            "Tab: next field  Shift+Tab: prev  j/k: select tool  Enter: continue  Esc: back"
        }
        OnboardStep::ModelSelection => "j/k: navigate  Enter: select  Esc: back",
        OnboardStep::ChannelSetup => match app.channel_phase {
            ChannelPhase::Offer => "j/k: navigate  Enter: select  Esc: back",
            ChannelPhase::TokenInput => "Enter: validate  Esc: back",
            ChannelPhase::Validating => match &app.telegram_status {
                TelegramStatus::Complete { .. } => "Enter: continue  Esc: cancel",
                TelegramStatus::Failed(_) => "Enter: retry  Esc: cancel",
                _ => "Esc: cancel",
            },
        },
        OnboardStep::Summary => "Enter: confirm  d: toggle daemon  Esc: back  q: cancel",
        OnboardStep::HealthCheck => {
            let all_done = app.health_checks.iter().all(|c| {
                matches!(c.status, HealthStatus::Passed | HealthStatus::Failed(_))
            });
            if all_done {
                "Enter: continue"
            } else {
                "Waiting..."
            }
        }
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

// ---------------------------------------------------------------------------
// Step 1: Welcome
// ---------------------------------------------------------------------------

fn draw_welcome(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Aegis -- zero-trust runtime for AI agents.",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "This wizard will configure your first agent and start",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "the daemon. You can add more agents later from the TUI.",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Detected environment:",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
    ];

    // Tools
    lines.push(Line::from(Span::styled(
        "  Tools:",
        Style::default().fg(Color::White),
    )));
    for tool in &app.env_scan.tools {
        let (tag, color) = if tool.found {
            ("[OK]", Color::Green)
        } else {
            ("[--]", Color::DarkGray)
        };
        let suffix = if tool.found {
            String::new()
        } else {
            " (not found)".to_string()
        };
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(tag, Style::default().fg(color)),
            Span::styled(format!(" {}", tool.label), Style::default().fg(Color::White)),
            Span::styled(suffix, Style::default().fg(Color::DarkGray)),
        ]));
    }

    lines.push(Line::from(""));

    // API Keys
    lines.push(Line::from(Span::styled(
        "  API Keys:",
        Style::default().fg(Color::White),
    )));
    for provider in &app.env_scan.api_keys {
        let (tag, color) = if provider.present {
            ("[OK]", Color::Green)
        } else {
            ("[--]", Color::DarkGray)
        };
        let suffix = if provider.present {
            String::new()
        } else {
            " (not set)".to_string()
        };
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(tag, Style::default().fg(color)),
            Span::styled(
                format!(" {}", provider.env_var),
                Style::default().fg(Color::White),
            ),
            Span::styled(suffix, Style::default().fg(Color::DarkGray)),
        ]));
    }

    lines.push(Line::from(""));

    // Services
    lines.push(Line::from(Span::styled(
        "  Services:",
        Style::default().fg(Color::White),
    )));
    let (ollama_tag, ollama_color) = if app.env_scan.ollama_running {
        ("[OK]", Color::Green)
    } else {
        ("[--]", Color::DarkGray)
    };
    let ollama_suffix = if app.env_scan.ollama_running {
        " (localhost:11434)"
    } else {
        " (not running)"
    };
    lines.push(Line::from(vec![
        Span::raw("    "),
        Span::styled(ollama_tag, Style::default().fg(ollama_color)),
        Span::styled(" Ollama", Style::default().fg(Color::White)),
        Span::styled(ollama_suffix, Style::default().fg(Color::DarkGray)),
    ]));

    lines.push(Line::from(""));

    // Aegis dir
    let (dir_tag, dir_color) = if app.env_scan.aegis_dir_ok {
        ("[OK]", Color::Green)
    } else {
        ("[FAIL]", Color::Red)
    };
    lines.push(Line::from(vec![
        Span::styled("  Aegis dir: ", Style::default().fg(Color::White)),
        Span::styled(
            &app.env_scan.aegis_dir_path,
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(" "),
        Span::styled(dir_tag, Style::default().fg(dir_color)),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press Enter to begin.",
        Style::default().fg(Color::DarkGray),
    )));

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Welcome"),
    );
    f.render_widget(p, area);
}

// ---------------------------------------------------------------------------
// Step 2: Agent Setup (multi-field)
// ---------------------------------------------------------------------------

fn draw_agent_setup(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let is_custom = app.tool_choice() == ToolChoice::Custom;
    let tool_height = if is_custom { 8 } else { 7 };
    let indicator_height = paste_indicator_height(app);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(tool_height),   // Tool selection
            Constraint::Length(3),             // Name
            Constraint::Length(3),             // Working Dir
            Constraint::Length(3),             // Task
            Constraint::Length(indicator_height), // Paste indicator
            Constraint::Min(0),               // Spacer
        ])
        .split(area);

    draw_tool_field(f, app, chunks[0]);
    draw_name_field(f, app, chunks[1]);
    draw_working_dir_field(f, app, chunks[2]);
    draw_task_field(f, app, chunks[3]);

    if indicator_height > 0 {
        draw_paste_indicator(f, app, chunks[4]);
    }
}

/// Render the tool selection field with optional inline custom command input.
fn draw_tool_field(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let active = app.active_field == AgentField::Tool;
    let border_color = if active { Color::Cyan } else { Color::DarkGray };

    let mut items: Vec<ListItem> = ToolChoice::ALL
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

            // Check if this tool was detected in the environment
            let detected = app
                .env_scan
                .tools
                .iter()
                .any(|t| t.name == choice.label() && t.found);

            let mut spans = vec![
                Span::styled(marker, label_style),
                Span::styled(choice.label(), label_style),
            ];
            if detected {
                spans.push(Span::styled(
                    "  (detected)",
                    Style::default().fg(Color::DarkGray),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    // If Custom is selected, show inline command input
    if app.tool_choice() == ToolChoice::Custom {
        let cmd_spans = if active {
            let mut s = vec![Span::styled(
                "    Command: ",
                Style::default().fg(Color::DarkGray),
            )];
            s.extend(build_cursor_spans(&app.custom_command, app.custom_cursor));
            s
        } else {
            let display = if app.custom_command.is_empty() {
                "(none)".to_string()
            } else {
                app.custom_command.clone()
            };
            vec![
                Span::styled("    Command: ", Style::default().fg(Color::DarkGray)),
                Span::styled(display, Style::default().fg(Color::White)),
            ]
        };
        items.push(ListItem::new(Line::from(cmd_spans)));
    }

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title("Tool"),
    );
    f.render_widget(list, area);
}

/// Render the agent name text input field.
fn draw_name_field(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let active = app.active_field == AgentField::Name;
    let border_color = if active { Color::Cyan } else { Color::DarkGray };

    let content = if active {
        Line::from(build_cursor_spans(&app.name, app.name_cursor))
    } else {
        let display = if app.name.is_empty() {
            "(empty)"
        } else {
            &app.name
        };
        Line::from(Span::styled(display, Style::default().fg(Color::White)))
    };

    let mut lines = vec![content];

    if let Some(err) = &app.name_error {
        lines.push(Line::from(Span::styled(
            err.to_string(),
            Style::default().fg(Color::Red),
        )));
    }

    let input = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title("Name"),
    );
    f.render_widget(input, area);
}

/// Render the working directory text input field.
fn draw_working_dir_field(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let active = app.active_field == AgentField::WorkingDir;
    let border_color = if active { Color::Cyan } else { Color::DarkGray };

    let content = if active {
        Line::from(build_cursor_spans(&app.working_dir, app.working_dir_cursor))
    } else {
        let display = if app.working_dir.is_empty() {
            "(empty)"
        } else {
            &app.working_dir
        };
        Line::from(Span::styled(display, Style::default().fg(Color::White)))
    };

    let mut lines = vec![content];

    if let Some(err) = &app.working_dir_error {
        lines.push(Line::from(Span::styled(
            err.to_string(),
            Style::default().fg(Color::Red),
        )));
    }

    let input = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title("Working Directory"),
    );
    f.render_widget(input, area);
}

/// Render the task (optional) text input field.
fn draw_task_field(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let active = app.active_field == AgentField::Task;
    let border_color = if active { Color::Cyan } else { Color::DarkGray };

    let content = if active {
        Line::from(build_cursor_spans(&app.task, app.task_cursor))
    } else {
        let display = if app.task.is_empty() {
            "(optional)"
        } else {
            &app.task
        };
        Line::from(Span::styled(display, Style::default().fg(Color::White)))
    };

    let input = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title("Task (optional)"),
    );
    f.render_widget(input, area);
}

// ---------------------------------------------------------------------------
// Step 3: Model Selection
// ---------------------------------------------------------------------------

fn draw_model_selection(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Description
            Constraint::Min(5),   // List
        ])
        .split(area);

    let desc = Paragraph::new(Span::styled(
        "Select a default model provider:",
        Style::default().fg(Color::White),
    ));
    f.render_widget(desc, chunks[0]);

    let items: Vec<ListItem> = app
        .available_providers()
        .into_iter()
        .enumerate()
        .map(|(i, provider)| {
            let selected = i == app.provider_selected;
            let marker = if selected { "> " } else { "  " };

            let label_style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let detail = if provider.env_var == "OLLAMA" {
                "running on localhost".to_string()
            } else {
                format!("{} set", provider.env_var)
            };

            let line = Line::from(vec![
                Span::styled(marker, label_style),
                Span::styled(
                    format!("{} ({})", provider.label, provider.default_model),
                    label_style,
                ),
                Span::styled(
                    format!("     {detail}"),
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
            .title("Model Selection"),
    );
    f.render_widget(list, chunks[1]);
}

// ---------------------------------------------------------------------------
// Step 4: Channel Setup
// ---------------------------------------------------------------------------

/// Channel offer phase: ask the user if they want Telegram notifications.
fn draw_channel_offer(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Description
            Constraint::Min(5),   // List
        ])
        .split(area);

    let desc = Paragraph::new(vec![
        Line::from(Span::styled(
            "Set up remote notifications?",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "Get notified on your phone when agents need attention.",
            Style::default().fg(Color::DarkGray),
        )),
    ]);
    f.render_widget(desc, chunks[0]);

    let choices = ["Skip for now", "Yes, set up Telegram"];
    let items: Vec<ListItem> = choices
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let selected = i == app.channel_offer_selected;
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

    let mut list_lines: Vec<ListItem> = items;
    list_lines.push(ListItem::new(Line::from("")));
    list_lines.push(ListItem::new(Line::from(Span::styled(
        "  You can always add this later with :telegram in the hub.",
        Style::default().fg(Color::DarkGray),
    ))));

    let list = List::new(list_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Notifications"),
    );
    f.render_widget(list, chunks[1]);
}

/// Channel token input phase: paste the Telegram bot token.
fn draw_channel_token(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Instructions
            Constraint::Min(3),   // Token input
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

    let masked = mask_token(&app.telegram_token);
    let cursor = app.telegram_token_cursor.min(masked.len());
    let spans = build_cursor_spans(&masked, cursor);
    let input = Paragraph::new(Line::from(spans))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title("Bot Token"),
        );
    f.render_widget(input, chunks[1]);
}

/// Channel validating phase: show Telegram connection progress and status.
fn draw_channel_validating(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let elapsed = app
        .telegram_started_at
        .map(|t| t.elapsed())
        .unwrap_or_default();

    let lines = match &app.telegram_status {
        TelegramStatus::Idle => vec![Line::from(Span::styled(
            "  Preparing...",
            Style::default().fg(Color::DarkGray),
        ))],
        TelegramStatus::ValidatingToken => vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Validating bot token...",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("  ({:.0}s elapsed)", elapsed.as_secs_f64()),
                Style::default().fg(Color::DarkGray),
            )),
        ],
        TelegramStatus::WaitingForChat { bot_username } => {
            let remaining = 60u64.saturating_sub(elapsed.as_secs());
            vec![
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
                Line::from(Span::styled(
                    format!("  ({remaining}s remaining, Esc to cancel)"),
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        }
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
                Span::styled(chat_id.to_string(), Style::default().fg(Color::Yellow)),
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

// ---------------------------------------------------------------------------
// Step 5: Summary
// ---------------------------------------------------------------------------

fn draw_summary(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let tool_label = ToolChoice::ALL
        .get(app.tool_selected)
        .map(|t| t.label())
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
        Some((_, _, bot_username)) => format!("Telegram (@{bot_username})"),
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
    ];

    lines.push(labeled_line("Tool:", tool_label));
    if app.tool_choice() == ToolChoice::Custom {
        lines.push(labeled_line("Command:", &app.custom_command));
    }
    lines.push(labeled_line("Name:", &app.name));
    lines.push(labeled_line("Directory:", &app.working_dir));
    lines.push(labeled_line("Task:", &task_display));
    lines.push(labeled_line("Notifications:", &telegram_display));
    lines.push(labeled_line("Start daemon:", daemon_display));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press Enter to confirm and start.",
        Style::default().fg(Color::DarkGray),
    )));

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Review"),
    );
    f.render_widget(p, area);
}

// ---------------------------------------------------------------------------
// Step 6: Health Check
// ---------------------------------------------------------------------------

fn draw_health_check(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));

    for check in &app.health_checks {
        let (tag, color) = match &check.status {
            HealthStatus::Pending => ("[  ]  ", Color::DarkGray),
            HealthStatus::Running => ("[...]", Color::Yellow),
            HealthStatus::Passed => ("[OK]  ", Color::Green),
            HealthStatus::Failed(_) => ("[FAIL]", Color::Red),
        };

        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(tag, Style::default().fg(color)),
            Span::raw("  "),
            Span::styled(&check.label, Style::default().fg(Color::White)),
        ]));

        // Show error detail below failed checks
        if let HealthStatus::Failed(err) = &check.status {
            lines.push(Line::from(vec![
                Span::raw("           "),
                Span::styled(
                    format!("Error: {err}"),
                    Style::default().fg(Color::Red),
                ),
            ]));
        }
    }

    lines.push(Line::from(""));

    let all_done = app
        .health_checks
        .iter()
        .all(|c| matches!(c.status, HealthStatus::Passed | HealthStatus::Failed(_)));
    let any_failed = app
        .health_checks
        .iter()
        .any(|c| matches!(c.status, HealthStatus::Failed(_)));

    if all_done {
        let msg = if any_failed {
            "  Some checks failed. Press Enter to continue anyway."
        } else {
            "  All checks passed. Press Enter to continue."
        };
        lines.push(Line::from(Span::styled(
            msg,
            Style::default().fg(Color::DarkGray),
        )));
    }

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Health Check"),
    );
    f.render_widget(p, area);
}

// ---------------------------------------------------------------------------
// Helper: cursor-aware text rendering
// ---------------------------------------------------------------------------

/// Build cursor-aware text input spans for a single-line field.
///
/// Shows text in Yellow with an inverted cursor block (Black on White) at
/// `cursor_pos`. When the cursor is at the end of the text, a trailing
/// space block is shown as the cursor.
fn build_cursor_spans(text: &str, cursor_pos: usize) -> Vec<Span<'static>> {
    let cursor_style = Style::default().bg(Color::White).fg(Color::Black);

    if cursor_pos >= text.len() {
        // Cursor at end: show text + trailing cursor block
        let mut spans = Vec::new();
        if !text.is_empty() {
            spans.push(Span::raw(text.to_string()));
        }
        spans.push(Span::styled(" ", cursor_style));
        return spans;
    }

    let before = text[..cursor_pos].to_string();
    let c_end = text[cursor_pos..]
        .char_indices()
        .nth(1)
        .map(|(i, _)| cursor_pos + i)
        .unwrap_or(text.len());
    let at = text[cursor_pos..c_end].to_string();
    let after = text[c_end..].to_string();

    let mut spans = Vec::new();
    if !before.is_empty() {
        spans.push(Span::raw(before));
    }
    spans.push(Span::styled(at, cursor_style));
    if !after.is_empty() {
        spans.push(Span::raw(after));
    }
    spans
}

// ---------------------------------------------------------------------------
// Helper: labeled summary line
// ---------------------------------------------------------------------------

/// Build a styled label-value line for the summary screen.
fn labeled_line<'a>(label: &str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("  {label:<16}"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ])
}

// ---------------------------------------------------------------------------
// Helper: token masking
// ---------------------------------------------------------------------------

/// Mask a Telegram bot token for display, showing only the last 4 characters.
fn mask_token(token: &str) -> String {
    if token.len() <= 4 {
        "*".repeat(token.len())
    } else {
        let visible = &token[token.len() - 4..];
        let star_count = token.len().saturating_sub(7).min(20);
        format!("{}...{visible}", "*".repeat(star_count))
    }
}

// ---------------------------------------------------------------------------
// Helper: paste indicator
// ---------------------------------------------------------------------------

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
