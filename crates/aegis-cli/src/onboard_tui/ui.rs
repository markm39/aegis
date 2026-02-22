//! TUI rendering for the onboarding wizard.
//!
//! Two screens: Welcome (environment scan results) and ProviderSelection
//! (pick an LLM provider from the detected list).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::app::{all_providers, OnboardApp, OnboardStep};

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

    // Title bar with progress.
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

    // Content area.
    match app.step {
        OnboardStep::Welcome => draw_welcome(f, app, chunks[1]),
        OnboardStep::ProviderSelection => draw_provider_selection(f, app, chunks[1]),
        OnboardStep::Done | OnboardStep::Cancelled => {}
    }

    // Help bar.
    let help_text = match app.step {
        OnboardStep::Welcome => "Enter: continue  Esc: quit",
        OnboardStep::ProviderSelection => "j/k: navigate  Enter: select  Esc: back",
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
// Welcome screen
// ---------------------------------------------------------------------------

fn draw_welcome(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "                    Welcome to Aegis",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Detected providers:",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
    ];

    // API key providers.
    for provider in &app.env_scan.api_keys {
        let (tag, tag_color) = if provider.present {
            ("[OK]", Color::Green)
        } else {
            ("[--]", Color::DarkGray)
        };
        // Pad label + env_var to align tags.
        let label_part = format!(
            "    {} ({})",
            provider.label, provider.env_var
        );
        let pad_width = 46usize.saturating_sub(label_part.len());
        let padding = " ".repeat(pad_width);

        lines.push(Line::from(vec![
            Span::styled(label_part, Style::default().fg(Color::White)),
            Span::raw(padding),
            Span::styled(tag, Style::default().fg(tag_color)),
        ]));
    }

    // Ollama.
    let (ollama_tag, ollama_color) = if app.env_scan.ollama_running {
        ("[Running]", Color::Green)
    } else {
        ("[--]", Color::DarkGray)
    };
    let ollama_label = "    Ollama (localhost:11434)";
    let ollama_pad = 46usize.saturating_sub(ollama_label.len());
    lines.push(Line::from(vec![
        Span::styled(ollama_label, Style::default().fg(Color::White)),
        Span::raw(" ".repeat(ollama_pad)),
        Span::styled(ollama_tag, Style::default().fg(ollama_color)),
    ]));

    lines.push(Line::from(""));

    // Aegis directory.
    let (dir_tag, dir_color) = if app.env_scan.aegis_dir_ok {
        ("[OK]", Color::Green)
    } else {
        ("[FAIL]", Color::Red)
    };
    let dir_label = format!("  Aegis directory: {}", app.env_scan.aegis_dir_path);
    let dir_pad = 48usize.saturating_sub(dir_label.len());
    lines.push(Line::from(vec![
        Span::styled(dir_label, Style::default().fg(Color::White)),
        Span::raw(" ".repeat(dir_pad)),
        Span::styled(dir_tag, Style::default().fg(dir_color)),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press Enter to continue, Esc to quit",
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
// Provider Selection screen
// ---------------------------------------------------------------------------

fn draw_provider_selection(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let providers = all_providers(&app.env_scan);

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "                  Select a Provider",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    for (i, provider) in providers.iter().enumerate() {
        let selected = i == app.provider_selected;
        let marker = if selected { "  > " } else { "    " };

        let (label_color, model_color, status_color) = if !provider.present {
            (Color::DarkGray, Color::DarkGray, Color::DarkGray)
        } else if selected {
            (Color::Cyan, Color::Cyan, Color::Green)
        } else {
            (Color::White, Color::DarkGray, Color::Green)
        };

        let label_style = if selected && provider.present {
            Style::default()
                .fg(label_color)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(label_color)
        };

        // Build status tag.
        let status_tag = if provider.label == "Ollama" {
            if provider.present {
                "[Running]"
            } else {
                "[--]"
            }
        } else if provider.present {
            "[API Key Set]"
        } else {
            "[--]"
        };

        // Pad label + model to align status tags.
        let label_model = format!("{}{:<16}{:<24}", marker, provider.label, provider.default_model);
        let pad_width = 50usize.saturating_sub(label_model.len());
        let padding = " ".repeat(pad_width);

        lines.push(Line::from(vec![
            Span::styled(
                format!("{}{:<16}", marker, provider.label),
                label_style,
            ),
            Span::styled(
                format!("{:<24}", provider.default_model),
                Style::default().fg(model_color),
            ),
            Span::raw(padding),
            Span::styled(status_tag, Style::default().fg(status_color)),
        ]));
    }

    lines.push(Line::from(""));

    // Error message if present.
    if let Some(err) = &app.selection_error {
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        )));
        lines.push(Line::from(""));
    }

    lines.push(Line::from(Span::styled(
        "  j/k to navigate, Enter to select",
        Style::default().fg(Color::DarkGray),
    )));

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title("Provider"),
    );
    f.render_widget(p, area);
}
