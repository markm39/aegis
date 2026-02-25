//! TUI rendering for the onboarding wizard.
//!
//! Renders all 9 wizard steps with consistent layout: title bar, content area,
//! and help bar.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use aegis_types::provider_auth::{AuthFlowKind, auth_flows_for};
use aegis_types::providers::format_context_window;

use super::app::{
    BIND_OPTIONS, ConfigAction, GatewayField, OnboardApp, OnboardStep, ProviderSubStep,
    SecuritySubStep, filtered_providers,
};

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------

const CYAN: Color = Color::Cyan;
const GREEN: Color = Color::Green;
const RED: Color = Color::Red;
const YELLOW: Color = Color::Yellow;
const DIM: Color = Color::DarkGray;
const WHITE: Color = Color::White;

// ---------------------------------------------------------------------------
// Main draw
// ---------------------------------------------------------------------------

/// Draw the wizard to the terminal frame.
pub fn draw(f: &mut Frame, app: &OnboardApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(5),    // Content
            Constraint::Length(3), // Help
        ])
        .split(f.area());

    draw_title(f, app, chunks[0]);

    match app.step {
        OnboardStep::ConfigDetection => draw_config_detection(f, app, chunks[1]),
        OnboardStep::ProviderSelection => draw_provider_selection(f, app, chunks[1]),
        OnboardStep::WorkspaceConfig => draw_workspace_config(f, app, chunks[1]),
        OnboardStep::SecurityConfig => draw_security_config(f, app, chunks[1]),
        OnboardStep::GatewayConfig => draw_gateway_config(f, app, chunks[1]),
        OnboardStep::ChannelSelection => draw_channel_selection(f, app, chunks[1]),
        OnboardStep::ServiceInstall => draw_service_install(f, app, chunks[1]),
        OnboardStep::HealthCheck => draw_health_check(f, app, chunks[1]),
        OnboardStep::SkillSelection => draw_skill_selection(f, app, chunks[1]),
        OnboardStep::Finish => draw_finish(f, app, chunks[1]),
        OnboardStep::Cancelled => {}
    }

    draw_help(f, app, chunks[2]);
}

// ---------------------------------------------------------------------------
// Title bar
// ---------------------------------------------------------------------------

fn draw_title(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let progress = app.progress_text();
    let title = if progress.is_empty() {
        "Aegis Setup".to_string()
    } else {
        format!("Aegis Setup  |  {progress}")
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title(Span::styled(
            title,
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(block, area);
}

// ---------------------------------------------------------------------------
// Help bar
// ---------------------------------------------------------------------------

fn draw_help(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let help_text = match app.step {
        OnboardStep::ConfigDetection => {
            if app.existing_config {
                "j/k: navigate  Enter: select  Esc: quit"
            } else {
                "Enter: continue  Esc: quit"
            }
        }
        OnboardStep::ProviderSelection => match app.provider_sub_step {
            ProviderSubStep::SelectProvider => {
                if app.provider_searching {
                    "Type to search  Enter: confirm  Esc: cancel search"
                } else {
                    "j/k: navigate  /: search  a: authenticate  Enter: select  Esc: back"
                }
            }
            ProviderSubStep::SelectAuthMethod => "j/k: navigate  Enter: select  Esc: back",
            ProviderSubStep::EnterApiKey => "Enter: save key  Esc: cancel",
            ProviderSubStep::SetupTokenInput => "Enter: save token  Esc: cancel",
            ProviderSubStep::CliExtractResult => "Enter: continue  Esc: back",
            ProviderSubStep::DeviceFlowWaiting => "Waiting for authorization...  Esc: cancel",
            ProviderSubStep::PkceBrowserWaiting => "Waiting for browser callback...  Esc: cancel",
            ProviderSubStep::SelectModel => {
                if app.model_manual_active {
                    "Enter: confirm  Esc: back to list"
                } else {
                    "j/k: navigate  r: refresh  Enter: confirm  Esc: back"
                }
            }
        },
        OnboardStep::WorkspaceConfig => "Enter: confirm  Esc: back",
        OnboardStep::SecurityConfig => match app.security_sub_step {
            SecuritySubStep::PresetSelection => "j/k: navigate  Enter: select  Esc: back",
            SecuritySubStep::AiGuide => {
                if app.security_ai_pending {
                    "Waiting for response...  Esc: back to presets"
                } else {
                    "Type reply  Enter: send  Esc: back to presets"
                }
            }
            SecuritySubStep::IsolationBackend => "j/k: navigate  Enter: next  Esc: back",
            SecuritySubStep::NetworkRules => {
                "Type host  Enter: add/next  d: delete  j/k: scroll list  Esc: back"
            }
            SecuritySubStep::WritePaths => {
                "Type path  Enter: add/finish  d: delete  j/k: scroll list  Esc: back"
            }
        },
        OnboardStep::GatewayConfig => "Tab/Shift+Tab: next/prev field  Enter: continue  Esc: back",
        OnboardStep::ChannelSelection => "j/k: navigate  Space: toggle  Enter: continue  Esc: back",
        OnboardStep::ServiceInstall => "j/k: navigate  Enter: confirm  Esc: back",
        OnboardStep::HealthCheck => {
            if app.health_checked {
                "r: re-check  Enter: continue  Esc: back"
            } else {
                "Enter: run checks  Esc: back"
            }
        }
        OnboardStep::SkillSelection => {
            "j/k: navigate  Space: toggle  a: select all  Enter: finish  Esc: back"
        }
        OnboardStep::Finish => "Enter/q: exit to fleet TUI",
        OnboardStep::Cancelled => "",
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM));
    let para = Paragraph::new(Line::from(Span::styled(
        help_text,
        Style::default().fg(DIM),
    )))
    .block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Step 1: Config Detection
// ---------------------------------------------------------------------------

fn draw_config_detection(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Welcome");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Welcome to Aegis",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    if app.existing_config {
        lines.push(Line::from(Span::styled(
            "  Existing configuration found at:",
            Style::default().fg(WHITE),
        )));
        lines.push(Line::from(Span::styled(
            format!("  {}", aegis_types::daemon::daemon_config_path().display()),
            Style::default().fg(YELLOW),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  What would you like to do?",
            Style::default().fg(WHITE),
        )));
        lines.push(Line::from(""));

        for (i, action) in ConfigAction::ALL.iter().enumerate() {
            let marker = if i == app.config_action_selected {
                "> "
            } else {
                "  "
            };
            let style = if i == app.config_action_selected {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(WHITE)
            };
            lines.push(Line::from(Span::styled(
                format!("  {marker}{}", action.label()),
                style,
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  No existing configuration found.",
            Style::default().fg(WHITE),
        )));
        lines.push(Line::from(Span::styled(
            "  This wizard will guide you through setting up Aegis.",
            Style::default().fg(DIM),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Press Enter to begin.",
            Style::default().fg(WHITE),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Step 2: Provider Selection
// ---------------------------------------------------------------------------

fn draw_provider_selection(f: &mut Frame, app: &OnboardApp, area: Rect) {
    match app.provider_sub_step {
        ProviderSubStep::SelectProvider => draw_provider_list(f, app, area),
        ProviderSubStep::SelectAuthMethod => draw_auth_method_selection(f, app, area),
        ProviderSubStep::EnterApiKey => draw_api_key_input(f, app, area),
        ProviderSubStep::SetupTokenInput => draw_setup_token_input(f, app, area),
        ProviderSubStep::CliExtractResult => draw_cli_extract_result(f, app, area),
        ProviderSubStep::DeviceFlowWaiting => draw_device_flow_waiting(f, app, area),
        ProviderSubStep::PkceBrowserWaiting => draw_pkce_browser_waiting(f, app, area),
        ProviderSubStep::SelectModel => draw_model_selection(f, app, area),
    }
}

fn draw_provider_list(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Select Provider");

    let filtered = filtered_providers(app);
    let mut lines = vec![Line::from("")];

    // Search bar.
    if app.provider_searching {
        let search_spans = build_cursor_spans(&app.provider_search, app.provider_search_cursor);
        let mut search_line = vec![Span::styled("  Search: ", Style::default().fg(YELLOW))];
        search_line.extend(search_spans);
        lines.push(Line::from(search_line));
        lines.push(Line::from(""));
    }

    if filtered.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No providers match search.",
            Style::default().fg(DIM),
        )));
    } else {
        // Windowed rendering -- only show providers in the visible range.
        let visible_height = area.height.saturating_sub(7) as usize;
        let visible_height = visible_height.max(5);
        let end = (app.provider_scroll_offset + visible_height).min(filtered.len());

        let mut current_tier = None;
        for (pos, &idx) in filtered
            .iter()
            .enumerate()
            .take(end)
            .skip(app.provider_scroll_offset)
        {
            let provider = &app.providers[idx];
            let tier = provider.info.tier;

            if current_tier != Some(tier) {
                current_tier = Some(tier);
                if pos > app.provider_scroll_offset {
                    lines.push(Line::from(""));
                }
                lines.push(Line::from(Span::styled(
                    format!("  {:?}", tier),
                    Style::default()
                        .fg(YELLOW)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                )));
            }

            let is_selected = idx == app.provider_selected;
            let marker = if is_selected { "> " } else { "  " };

            let name_style = if !provider.available {
                Style::default().fg(DIM)
            } else if is_selected {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(WHITE)
            };

            let status_style = if provider.available {
                Style::default().fg(GREEN)
            } else {
                Style::default().fg(DIM)
            };

            let name = format!("  {marker}{:<20}", provider.info.display_name);
            let model_with_ctx = {
                let dm = provider.info.default_model;
                if dm.is_empty() {
                    "(dynamic)".to_string()
                } else if let Some(mi) = provider.info.models.iter().find(|m| m.id == dm) {
                    format!("{} {}", dm, format_context_window(mi.context_window))
                } else {
                    dm.to_string()
                }
            };
            let model = format!("{:<32}", model_with_ctx);
            let status = provider.detection_label;

            lines.push(Line::from(vec![
                Span::styled(name, name_style),
                Span::styled(
                    model,
                    if provider.available {
                        name_style
                    } else {
                        Style::default().fg(DIM)
                    },
                ),
                Span::styled(status, status_style),
            ]));
        }

        // Position indicator.
        if filtered.len() > visible_height {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!(
                    "  Showing {}-{} of {}",
                    app.provider_scroll_offset + 1,
                    end,
                    filtered.len()
                ),
                Style::default().fg(DIM),
            )));
        }
    }

    // Error message.
    if let Some(ref err) = app.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(RED),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_model_selection(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Select Model");

    let mut lines = vec![Line::from("")];

    let provider = match app.selected_provider() {
        Some(p) => p,
        None => {
            let para = Paragraph::new(lines).block(block);
            f.render_widget(para, area);
            return;
        }
    };

    lines.push(Line::from(Span::styled(
        format!("  Provider: {}", provider.info.display_name),
        Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    // Manual input mode -- show text input instead of list.
    if app.model_manual_active {
        lines.push(Line::from(Span::styled(
            "  Model ID:",
            Style::default().fg(WHITE),
        )));
        lines.push(Line::from(""));

        let cursor_spans = build_cursor_spans(&app.model_manual_input, app.model_manual_cursor);
        let mut input_line = vec![Span::styled("  ", Style::default())];
        input_line.extend(cursor_spans);
        lines.push(Line::from(input_line));

        let para = Paragraph::new(lines).block(block);
        f.render_widget(para, area);
        return;
    }

    // Column headers.
    lines.push(Line::from(vec![
        Span::styled("    ", Style::default()),
        Span::styled(format!("{:<36}", "MODEL"), Style::default().fg(DIM)),
        Span::styled(format!("{:<8}", "CTX"), Style::default().fg(DIM)),
        Span::styled("FLAGS", Style::default().fg(DIM)),
    ]));

    let mut row_idx: usize = 0;

    // Static models.
    for model in provider.info.models.iter() {
        let is_selected = row_idx == app.model_selected;
        let marker = if is_selected { "> " } else { "  " };
        let is_default = model.id == provider.info.default_model;

        let name = if is_default {
            format!("{} *", model.display_name)
        } else {
            model.display_name.to_string()
        };

        let ctx = format_context_window(model.context_window);

        let mut flags = String::new();
        if model.supports_thinking {
            flags.push_str("[R] ");
        }
        if model.supports_vision {
            flags.push_str("[V]");
        }

        let style = if is_selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(WHITE)
        };

        lines.push(Line::from(vec![
            Span::styled(format!("  {marker}"), style),
            Span::styled(format!("{:<36}", name), style),
            Span::styled(format!("{:<8}", ctx), style),
            Span::styled(flags, style),
        ]));

        row_idx += 1;
    }

    // Discovered models.
    if !app.discovered_models.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Discovered from API:",
            Style::default().fg(DIM),
        )));

        for model in &app.discovered_models {
            let is_selected = row_idx == app.model_selected;
            let marker = if is_selected { "> " } else { "  " };
            let ctx = format_context_window(model.context_window);

            let mut flags = String::new();
            if model.supports_thinking {
                flags.push_str("[R] ");
            }
            if model.supports_vision {
                flags.push_str("[V]");
            }

            let style = if is_selected {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(WHITE)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("  {marker}"), style),
                Span::styled(format!("{:<36}", model.display_name), style),
                Span::styled(format!("{:<8}", ctx), style),
                Span::styled(flags, style),
            ]));

            row_idx += 1;
        }
    }

    // Loading / error state.
    if app.model_loading {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Loading models from provider...",
            Style::default().fg(DIM),
        )));
    }
    if let Some(ref err) = app.model_loading_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(YELLOW),
        )));
    }

    // Manual entry row (always last).
    lines.push(Line::from(""));
    let is_manual_selected = row_idx == app.model_selected;
    let manual_marker = if is_manual_selected { "> " } else { "  " };
    let manual_style = if is_manual_selected {
        Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(DIM)
    };
    lines.push(Line::from(Span::styled(
        format!("  {manual_marker}Enter custom model ID..."),
        manual_style,
    )));

    // Legend.
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  [R] Reasoning  [V] Vision  * Default",
        Style::default().fg(DIM),
    )));

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_api_key_input(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Enter API Key");

    let mut lines = vec![Line::from("")];

    if let Some(provider) = app.selected_provider() {
        lines.push(Line::from(Span::styled(
            format!("  Provider: {}", provider.info.display_name),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )));

        if !provider.info.env_var.is_empty() {
            let env_var = provider.info.env_var;
            lines.push(Line::from(Span::styled(
                format!("  Environment variable: {env_var}"),
                Style::default().fg(DIM),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter your API key:",
        Style::default().fg(WHITE),
    )));
    lines.push(Line::from(""));

    // Masked key input with cursor.
    let masked: String = "*".repeat(app.api_key_input.len());
    let cursor_spans = build_cursor_spans(&masked, app.api_key_cursor);
    let mut input_line = vec![Span::styled("  ", Style::default())];
    input_line.extend(cursor_spans);
    lines.push(Line::from(input_line));

    // Error message.
    if let Some(ref err) = app.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(RED),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Auth method selection
// ---------------------------------------------------------------------------

fn draw_auth_method_selection(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Authentication Method");

    let mut lines = vec![Line::from("")];

    if let Some(provider) = app.selected_provider() {
        lines.push(Line::from(Span::styled(
            format!("  Provider: {}", provider.info.display_name),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            "  Choose how to authenticate:",
            Style::default().fg(WHITE),
        )));
        lines.push(Line::from(""));

        let flows = auth_flows_for(provider.info.id);
        for (i, flow) in flows.iter().enumerate() {
            let is_selected = i == app.auth_flow_selected;
            let marker = if is_selected { "> " } else { "  " };
            let (label, desc) = auth_flow_label(flow);

            let style = if is_selected {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(WHITE)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("  {marker}{label}"), style),
                Span::styled(format!("  {desc}"), Style::default().fg(DIM)),
            ]));
        }
    }

    if let Some(ref err) = app.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(RED),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_setup_token_input(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Setup Token");

    let mut lines = vec![Line::from("")];

    if let Some(provider) = app.selected_provider() {
        lines.push(Line::from(Span::styled(
            format!("  Provider: {}", provider.info.display_name),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  {}", app.setup_token_instructions),
        Style::default().fg(YELLOW),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Paste the resulting token below:",
        Style::default().fg(WHITE),
    )));
    lines.push(Line::from(""));

    // Masked token input with cursor.
    let masked: String = "*".repeat(app.setup_token_input.len());
    let cursor_spans = build_cursor_spans(&masked, app.setup_token_cursor);
    let mut input_line = vec![Span::styled("  ", Style::default())];
    input_line.extend(cursor_spans);
    lines.push(Line::from(input_line));

    if let Some(ref err) = app.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(RED),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_cli_extract_result(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Token Extraction");

    let mut lines = vec![Line::from("")];

    if let Some(provider) = app.selected_provider() {
        lines.push(Line::from(Span::styled(
            format!("  Provider: {}", provider.info.display_name),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )));
    }

    lines.push(Line::from(""));

    match &app.cli_extract_result {
        Some((cli_name, Some(_token))) => {
            lines.push(Line::from(Span::styled(
                format!("  [OK] Found token from {cli_name}"),
                Style::default().fg(GREEN),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Press Enter to continue.",
                Style::default().fg(WHITE),
            )));
        }
        Some((cli_name, None)) => {
            lines.push(Line::from(Span::styled(
                format!("  [!!] Could not extract token from {cli_name}"),
                Style::default().fg(RED),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  The CLI may not be installed or configured.",
                Style::default().fg(DIM),
            )));
            lines.push(Line::from(Span::styled(
                "  Press Esc to try another authentication method.",
                Style::default().fg(WHITE),
            )));
        }
        None => {
            lines.push(Line::from(Span::styled(
                "  Checking...",
                Style::default().fg(DIM),
            )));
        }
    }

    if let Some(ref err) = app.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(RED),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_device_flow_waiting(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Device Authorization");

    let mut lines = vec![Line::from("")];

    if let Some(provider) = app.selected_provider() {
        lines.push(Line::from(Span::styled(
            format!("  Provider: {}", provider.info.display_name),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )));
    }

    lines.push(Line::from(""));

    if let Some(ref state) = app.device_flow {
        lines.push(Line::from(Span::styled(
            "  Visit this URL in your browser:",
            Style::default().fg(WHITE),
        )));
        lines.push(Line::from(Span::styled(
            format!("  {}", state.response.verification_uri),
            Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Enter this code:",
            Style::default().fg(WHITE),
        )));
        lines.push(Line::from(Span::styled(
            format!("  {}", state.response.user_code),
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        // Spinner animation based on poll count.
        let spinner = match state.poll_count % 4 {
            0 => "|",
            1 => "/",
            2 => "-",
            _ => "\\",
        };
        lines.push(Line::from(Span::styled(
            format!("  {spinner} Waiting for authorization..."),
            Style::default().fg(DIM),
        )));
    }

    if let Some(ref err) = app.device_flow_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(RED),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_pkce_browser_waiting(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Browser Authorization");

    let mut lines = vec![Line::from("")];

    if let Some(provider) = app.selected_provider() {
        lines.push(Line::from(Span::styled(
            format!("  Provider: {}", provider.info.display_name),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  A browser window has been opened.",
        Style::default().fg(WHITE),
    )));
    lines.push(Line::from(Span::styled(
        "  Complete authorization in your browser.",
        Style::default().fg(WHITE),
    )));
    lines.push(Line::from(""));

    if let Some(ref url) = app.pkce_auth_url {
        lines.push(Line::from(Span::styled(
            "  If the browser didn't open, visit:",
            Style::default().fg(DIM),
        )));
        // Truncate long URLs for display.
        let display_url = if url.len() > 70 {
            format!("{}...", &url[..67])
        } else {
            url.clone()
        };
        lines.push(Line::from(Span::styled(
            format!("  {display_url}"),
            Style::default().fg(YELLOW),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Waiting for callback...",
        Style::default().fg(DIM),
    )));

    if let Some(ref err) = app.pkce_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(RED),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

/// Get a human-readable label and description for an auth flow kind.
fn auth_flow_label(flow: &AuthFlowKind) -> (String, String) {
    match flow {
        AuthFlowKind::ApiKey => ("Paste API Key".into(), "Enter your key manually".into()),
        AuthFlowKind::SetupToken { .. } => ("Setup Token".into(), "Paste a setup token".into()),
        AuthFlowKind::CliExtract { cli_name, .. } => (
            format!("Extract from {cli_name}"),
            "Auto-detect from installed CLI".into(),
        ),
        AuthFlowKind::DeviceFlow { .. } => (
            "OAuth Device Flow".into(),
            "Authorize via browser with a code".into(),
        ),
        AuthFlowKind::PkceBrowser { .. } => (
            "Browser OAuth".into(),
            "Authorize directly in your browser".into(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Step 3: Workspace Config
// ---------------------------------------------------------------------------

fn draw_workspace_config(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Workspace");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Workspace Directory",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Where should Aegis store agent workspaces and session data?",
            Style::default().fg(WHITE),
        )),
        Line::from(""),
    ];

    let cursor_spans = build_cursor_spans(&app.workspace_path, app.workspace_cursor);
    let mut input_line = vec![Span::styled("  ", Style::default())];
    input_line.extend(cursor_spans);
    lines.push(Line::from(input_line));

    if let Some(ref err) = app.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(RED),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Step 4: Security Config
// ---------------------------------------------------------------------------

fn draw_security_config(f: &mut Frame, app: &OnboardApp, area: Rect) {
    match app.security_sub_step {
        SecuritySubStep::PresetSelection => draw_security_preset(f, app, area),
        SecuritySubStep::AiGuide => draw_security_ai_guide(f, app, area),
        SecuritySubStep::IsolationBackend => draw_security_isolation(f, app, area),
        SecuritySubStep::NetworkRules => draw_security_network(f, app, area),
        SecuritySubStep::WritePaths => draw_security_paths(f, app, area),
    }
}

const PRESET_LABELS: [(&str, &str); 5] = [
    ("Configure with AI", "Let the LLM interview you and build a custom config (recommended)"),
    ("Observe Only", "Log activity; enforce nothing"),
    ("Read Only", "Reads allowed; writes and network blocked"),
    ("Full Lockdown", "Minimal access; most operations blocked"),
    ("Custom", "Configure specific permissions manually"),
];

const ISOLATION_LABELS: [(&str, &str); 4] = [
    ("Seatbelt (recommended)", "macOS kernel sandbox"),
    ("Docker", "Container isolation"),
    ("Process", "No OS isolation; observer + policy only"),
    ("None", "No isolation at all"),
];

fn draw_security_preset(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Security");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Security & Sandbox Configuration",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  The agent runs inside a macOS Seatbelt sandbox.",
            Style::default().fg(WHITE),
        )),
        Line::from(Span::styled(
            "  Choose a security level -- you can adjust it on the next screen.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];

    for (i, (label, desc)) in PRESET_LABELS.iter().enumerate() {
        let selected = i == app.security_preset_selected;
        let marker = if selected { "> " } else { "  " };
        let label_style = if selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(WHITE)
        };
        let desc_style = Style::default().fg(DIM);
        lines.push(Line::from(vec![
            Span::styled(format!("  {marker}{label:<20}", label = label), label_style),
            Span::styled(format!("  {desc}"), desc_style),
        ]));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn draw_security_ai_guide(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Security  >  Configure with AI");

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: history | status row (1 line) | input line (2 rows).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(2)])
        .split(inner);

    // ----- Chat history (ratatui wraps, we scroll to bottom) -----
    let mut lines: Vec<Line> = Vec::new();
    for (role, content) in &app.security_ai_messages {
        let (label, style) = if role == "user" {
            ("You", Style::default().fg(CYAN))
        } else {
            ("Aegis", Style::default().fg(WHITE).add_modifier(Modifier::BOLD))
        };
        lines.push(Line::from(Span::styled(format!("  {label}:"), style)));
        for chunk in content.split('\n') {
            lines.push(Line::from(Span::styled(
                format!("    {chunk}"),
                Style::default().fg(WHITE),
            )));
        }
        lines.push(Line::from(""));
    }

    // Let ratatui wrap and compute total visual lines, then scroll to bottom.
    let history_text = ratatui::text::Text::from(lines);
    let total_visual = Paragraph::new(history_text.clone())
        .wrap(Wrap { trim: false })
        .line_count(chunks[0].width);
    let visible_height = chunks[0].height as usize;
    let scroll_top = total_visual.saturating_sub(visible_height) as u16;
    f.render_widget(
        Paragraph::new(history_text)
            .wrap(Wrap { trim: false })
            .scroll((scroll_top, 0)),
        chunks[0],
    );

    // ----- Status / thinking row -----
    let status_line = if app.security_ai_pending {
        let elapsed_ms = app
            .security_ai_pending_since
            .map(|t| t.elapsed().as_millis())
            .unwrap_or(0);
        let frame = (elapsed_ms / 150) as usize % SPINNER_FRAMES.len();
        let spinner = SPINNER_FRAMES[frame];
        let elapsed_str = if elapsed_ms < 60_000 {
            format!("{}s", elapsed_ms / 1000)
        } else {
            format!("{}m {}s", elapsed_ms / 60_000, (elapsed_ms % 60_000) / 1000)
        };
        Line::from(vec![
            Span::styled(format!("  {spinner} "), Style::default().fg(Color::Yellow)),
            Span::styled("Working…  ", Style::default().fg(DIM)),
            Span::styled(format!("({elapsed_str})"), Style::default().fg(DIM)),
        ])
    } else if let Some(ref err) = app.security_ai_error {
        Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        ))
    } else {
        Line::from("")
    };
    f.render_widget(Paragraph::new(status_line), chunks[1]);

    // ----- Input box -----
    let input_block = Block::default()
        .borders(Borders::TOP)
        .border_style(if app.security_ai_pending {
            Style::default().fg(DIM)
        } else {
            Style::default().fg(Color::Rgb(60, 60, 60))
        });
    let prefix = Span::styled(
        "> ",
        Style::default()
            .fg(if app.security_ai_pending { DIM } else { CYAN })
            .add_modifier(Modifier::BOLD),
    );
    let input_text = &app.security_ai_input;
    let cursor_pos = app.security_ai_cursor;
    let (before, after) = input_text.split_at(cursor_pos.min(input_text.len()));
    let mut spans = vec![prefix, Span::styled(before, Style::default().fg(WHITE))];
    if !app.security_ai_pending {
        let cursor_char = after.chars().next().unwrap_or(' ');
        let rest = if after.is_empty() {
            ""
        } else {
            &after[cursor_char.len_utf8()..]
        };
        spans.push(Span::styled(
            cursor_char.to_string(),
            Style::default().fg(Color::Black).bg(WHITE).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(rest, Style::default().fg(WHITE)));
    } else {
        spans.push(Span::styled(after, Style::default().fg(DIM)));
    }
    let input_para = Paragraph::new(Line::from(spans)).block(input_block);
    f.render_widget(input_para, chunks[2]);
}

fn draw_security_isolation(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Security  >  Isolation Backend");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Choose the OS-level isolation mechanism.",
            Style::default().fg(WHITE),
        )),
        Line::from(""),
    ];

    for (i, (label, desc)) in ISOLATION_LABELS.iter().enumerate() {
        let selected = i == app.security_isolation_selected;
        let marker = if selected { "> " } else { "  " };
        let label_style = if selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(WHITE)
        };
        let desc_style = Style::default().fg(DIM);
        lines.push(Line::from(vec![
            Span::styled(format!("  {marker}{label:<28}", label = label), label_style),
            Span::styled(format!("  {desc}"), desc_style),
        ]));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_security_network(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Security  >  Network Access");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Add hosts the agent may connect to.",
            Style::default().fg(WHITE),
        )),
        Line::from(Span::styled(
            "  Empty list = block all outbound network.",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "  Press Enter with an empty field to proceed.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];

    // Text input.
    let cursor_spans =
        build_cursor_spans(&app.security_hosts_input, app.security_hosts_cursor);
    let mut input_line = vec![Span::styled("  Add host: ", Style::default().fg(YELLOW))];
    input_line.extend(cursor_spans);
    lines.push(Line::from(input_line));
    lines.push(Line::from(""));

    // Existing hosts list.
    if app.security_hosts.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (none -- all outbound network blocked)",
            Style::default().fg(DIM),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  Allowed hosts:",
            Style::default().fg(WHITE),
        )));
        for (i, host) in app.security_hosts.iter().enumerate() {
            let selected = i == app.security_hosts_selected;
            let style = if selected {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(GREEN)
            };
            let marker = if selected { "> " } else { "  " };
            lines.push(Line::from(Span::styled(
                format!("  {marker}* {host}"),
                style,
            )));
        }
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_security_paths(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Security  >  Filesystem Write Access");

    let workspace_display = if app.workspace_path.is_empty() {
        "~/.aegis/workspace".to_string()
    } else {
        app.workspace_path.clone()
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Add extra directories the agent may write to.",
            Style::default().fg(WHITE),
        )),
        Line::from(Span::styled(
            format!("  Workspace: {workspace_display}  (always writable)"),
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "  Press Enter with an empty field to finish.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];

    // Text input.
    let cursor_spans =
        build_cursor_spans(&app.security_paths_input, app.security_paths_cursor);
    let mut input_line = vec![Span::styled("  Add path: ", Style::default().fg(YELLOW))];
    input_line.extend(cursor_spans);
    lines.push(Line::from(input_line));
    lines.push(Line::from(""));

    // Existing paths list.
    if app.security_paths.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (none -- press Enter to continue)",
            Style::default().fg(DIM),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  Extra writable paths:",
            Style::default().fg(WHITE),
        )));
        for (i, path) in app.security_paths.iter().enumerate() {
            let selected = i == app.security_paths_selected;
            let style = if selected {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(GREEN)
            };
            let marker = if selected { "> " } else { "  " };
            lines.push(Line::from(Span::styled(
                format!("  {marker}* {path}"),
                style,
            )));
        }
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Step 5: Gateway Config
// ---------------------------------------------------------------------------

fn draw_gateway_config(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Gateway");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Control Server Configuration",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    // Port field.
    let port_active = app.gateway_field == GatewayField::Port;
    let port_label_style = if port_active {
        Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(WHITE)
    };
    lines.push(Line::from(Span::styled("  Port:", port_label_style)));

    if port_active {
        let cursor_spans = build_cursor_spans(&app.gateway_port, app.gateway_port_cursor);
        let mut input_line = vec![Span::styled("  ", Style::default())];
        input_line.extend(cursor_spans);
        lines.push(Line::from(input_line));
    } else {
        lines.push(Line::from(Span::styled(
            format!("  {}", app.gateway_port),
            Style::default().fg(DIM),
        )));
    }

    lines.push(Line::from(""));

    // Bind address field.
    let bind_active = app.gateway_field == GatewayField::BindAddress;
    let bind_label_style = if bind_active {
        Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(WHITE)
    };
    lines.push(Line::from(Span::styled(
        "  Bind Address:",
        bind_label_style,
    )));

    for (i, (addr, desc)) in BIND_OPTIONS.iter().enumerate() {
        let is_selected = i == app.gateway_bind_selected;
        let marker = if is_selected { "> " } else { "  " };
        let style = if bind_active && is_selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else if bind_active {
            Style::default().fg(WHITE)
        } else {
            Style::default().fg(DIM)
        };
        lines.push(Line::from(Span::styled(
            format!("  {marker}{addr} - {desc}"),
            style,
        )));
    }

    lines.push(Line::from(""));

    // Auth token field.
    let token_active = app.gateway_field == GatewayField::AuthToken;
    let token_label_style = if token_active {
        Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(WHITE)
    };
    lines.push(Line::from(Span::styled("  API Token:", token_label_style)));

    if token_active {
        let cursor_spans = build_cursor_spans(&app.gateway_token, app.gateway_token_cursor);
        let mut input_line = vec![Span::styled("  ", Style::default())];
        input_line.extend(cursor_spans);
        lines.push(Line::from(input_line));
    } else {
        let masked = if app.gateway_token.len() > 8 {
            format!(
                "{}...{}",
                &app.gateway_token[..4],
                &app.gateway_token[app.gateway_token.len() - 4..]
            )
        } else {
            app.gateway_token.clone()
        };
        lines.push(Line::from(Span::styled(
            format!("  {masked}"),
            Style::default().fg(DIM),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Step 5: Channel Selection
// ---------------------------------------------------------------------------

fn draw_channel_selection(f: &mut Frame, app: &OnboardApp, area: Rect) {
    // If a setup wizard is running inline, render it instead of the checkbox list.
    if app.channel_sub_step == super::app::ChannelSubStep::RunningSetup {
        if let Some(ref wizard) = app.channel_setup_wizard {
            crate::setup_wizard::ui::draw_setup_wizard(f, &wizard.current_step(), area);
            return;
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Channels");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Select Messaging Channels",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  Selected channels will be set up next",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];

    for (i, ch) in app.channels.iter().enumerate() {
        let is_selected = i == app.channel_selected;
        let marker = if is_selected { "> " } else { "  " };
        let checkbox = if ch.selected { "[x]" } else { "[ ]" };

        let style = if is_selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(WHITE)
        };

        let desc_style = Style::default().fg(DIM);

        lines.push(Line::from(vec![
            Span::styled(format!("  {marker}{checkbox} "), style),
            Span::styled(format!("{:<12}", ch.label), style),
            Span::styled(ch.description, desc_style),
        ]));
    }

    let selected_count = app.channels.iter().filter(|c| c.selected).count();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  {selected_count} channel(s) selected"),
        Style::default().fg(DIM),
    )));

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Step 6: Service Install
// ---------------------------------------------------------------------------

fn draw_service_install(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Service");

    let platform = if cfg!(target_os = "macos") {
        "macOS (launchd)"
    } else if cfg!(target_os = "linux") {
        "Linux (systemd)"
    } else {
        "Current platform"
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Daemon Service Installation",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  Platform: {platform}"),
            Style::default().fg(WHITE),
        )),
        Line::from(Span::styled(
            "  Install as a system service to auto-start on login.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];

    let options = ["Install service", "Skip"];
    for (i, opt) in options.iter().enumerate() {
        let is_selected = i == app.service_action_selected;
        let marker = if is_selected { "> " } else { "  " };
        let style = if is_selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(WHITE)
        };
        lines.push(Line::from(Span::styled(format!("  {marker}{opt}"), style)));
    }

    if let Some(ref status) = app.service_status {
        lines.push(Line::from(""));
        let color = if status.contains("failed") || status.contains("Failed") {
            RED
        } else {
            GREEN
        };
        lines.push(Line::from(Span::styled(
            format!("  {status}"),
            Style::default().fg(color),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Step 7: Health Check
// ---------------------------------------------------------------------------

fn draw_health_check(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Health");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Health Verification",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    if app.health_results.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Press Enter to run health checks.",
            Style::default().fg(WHITE),
        )));
    } else {
        for result in &app.health_results {
            let (icon, color) = if result.passed {
                ("[OK]", GREEN)
            } else {
                ("[!!]", RED)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {icon} "), Style::default().fg(color)),
                Span::styled(format!("{:<20}", result.label), Style::default().fg(WHITE)),
                Span::styled(&result.message, Style::default().fg(DIM)),
            ]));
        }

        let passed = app.health_results.iter().filter(|r| r.passed).count();
        let total = app.health_results.len();
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {passed}/{total} checks passed"),
            Style::default().fg(if passed == total { GREEN } else { YELLOW }),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Step 8: Skill Selection
// ---------------------------------------------------------------------------

fn draw_skill_selection(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Skills");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Select Skills to Install",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    if app.skills.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No skills found.",
            Style::default().fg(DIM),
        )));
    } else {
        // Show visible window of skills.
        let visible_height = area.height.saturating_sub(8) as usize;
        let visible_height = visible_height.max(5);
        let end = (app.skill_scroll_offset + visible_height).min(app.skills.len());

        let mut current_category = None;
        for i in app.skill_scroll_offset..end {
            let skill = &app.skills[i];

            // Category header.
            if current_category.as_ref() != Some(&skill.category) {
                current_category = Some(skill.category.clone());
                if i > app.skill_scroll_offset {
                    lines.push(Line::from(""));
                }
                lines.push(Line::from(Span::styled(
                    format!("  {}", skill.category.to_uppercase()),
                    Style::default()
                        .fg(YELLOW)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                )));
            }

            let is_selected = i == app.skill_selected;
            let marker = if is_selected { "> " } else { "  " };
            let checkbox = if skill.selected { "[x]" } else { "[ ]" };
            let installed_tag = if skill.installed { " [installed]" } else { "" };

            let style = if is_selected {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(WHITE)
            };

            let desc = if skill.description.is_empty() {
                String::new()
            } else {
                truncate_description(&skill.description, 40)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("  {marker}{checkbox} "), style),
                Span::styled(format!("{:<22}", skill.name), style),
                Span::styled(format!("{:<42}", desc), Style::default().fg(DIM)),
                Span::styled(installed_tag, Style::default().fg(GREEN)),
            ]));
        }

        let selected_count = app.skills.iter().filter(|s| s.selected).count();
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(
                "  {selected_count}/{} skill(s) selected  |  Showing {}-{} of {}",
                app.skills.len(),
                app.skill_scroll_offset + 1,
                end,
                app.skills.len()
            ),
            Style::default().fg(DIM),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Step 9: Finish
// ---------------------------------------------------------------------------

fn draw_finish(f: &mut Frame, app: &OnboardApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title("Setup Complete");

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Aegis Setup Complete",
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    // Summary.
    if let Some(provider) = app.selected_provider() {
        lines.push(Line::from(vec![
            Span::styled("  Provider:  ", Style::default().fg(WHITE)),
            Span::styled(provider.info.display_name, Style::default().fg(CYAN)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Model:     ", Style::default().fg(WHITE)),
            Span::styled(app.selected_model(), Style::default().fg(CYAN)),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled("  Gateway:   ", Style::default().fg(WHITE)),
        Span::styled(
            format!(
                "{}:{}",
                BIND_OPTIONS
                    .get(app.gateway_bind_selected)
                    .map(|(a, _)| *a)
                    .unwrap_or("127.0.0.1"),
                app.gateway_port
            ),
            Style::default().fg(CYAN),
        ),
    ]));

    let channel_count = app.channels.iter().filter(|c| c.selected).count();
    lines.push(Line::from(vec![
        Span::styled("  Channels:  ", Style::default().fg(WHITE)),
        Span::styled(
            format!("{channel_count} configured"),
            Style::default().fg(CYAN),
        ),
    ]));

    let skill_count = app.skills.iter().filter(|s| s.selected).count();
    lines.push(Line::from(vec![
        Span::styled("  Skills:    ", Style::default().fg(WHITE)),
        Span::styled(format!("{skill_count} selected"), Style::default().fg(CYAN)),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Configuration saved to ~/.aegis/daemon/daemon.toml",
        Style::default().fg(DIM),
    )));
    lines.push(Line::from(Span::styled(
        "  Daemon is starting. Press Enter to continue to the fleet TUI.",
        Style::default().fg(WHITE),
    )));

    if let Some(ref err) = app.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(RED),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Cursor rendering
// ---------------------------------------------------------------------------

/// Build spans for a text input with a visible cursor block.
/// Truncate a description string to fit within `max_len` characters.
fn truncate_description(desc: &str, max_len: usize) -> String {
    if desc.len() <= max_len {
        desc.to_string()
    } else {
        let truncated: String = desc.chars().take(max_len.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

///
/// Characters before the cursor are yellow, the character at the cursor is
/// rendered with inverted colors (black on yellow), and characters after are
/// yellow. If the cursor is at the end, a yellow block space is shown.
fn build_cursor_spans(text: &str, cursor_pos: usize) -> Vec<Span<'_>> {
    let mut pos = cursor_pos.min(text.len());
    // Clamp to char boundary.
    while pos > 0 && !text.is_char_boundary(pos) {
        pos -= 1;
    }

    let mut spans = Vec::new();

    // Before cursor.
    if pos > 0 {
        spans.push(Span::styled(&text[..pos], Style::default().fg(YELLOW)));
    }

    // At cursor.
    if pos < text.len() {
        let ch = text[pos..].chars().next().unwrap();
        let end = pos + ch.len_utf8();
        spans.push(Span::styled(
            &text[pos..end],
            Style::default().fg(Color::Black).bg(YELLOW),
        ));
        // After cursor.
        if end < text.len() {
            spans.push(Span::styled(&text[end..], Style::default().fg(YELLOW)));
        }
    } else {
        // At end of line: show cursor as space with background.
        spans.push(Span::styled(" ", Style::default().bg(YELLOW)));
    }

    spans
}
