/// Aegis Monitor -- a ratatui terminal dashboard for real-time audit log monitoring.
///
/// Provides a live-updating view of the Aegis audit ledger with filtering,
/// navigation, and aggregate statistics. Launch via `run_monitor()`.
mod app;
mod event;
mod ui;

use app::App;

/// Run the monitor TUI. This is the main entry point.
///
/// Initializes the terminal in raw/alternate-screen mode, runs the main
/// event loop (refreshing from the ledger on every tick), and restores
/// the terminal on exit.
pub fn run_monitor(ledger_path: std::path::PathBuf) -> anyhow::Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut app = App::new(ledger_path);
    let events = event::EventHandler::new(500);

    // Main loop: refresh data, draw, handle events.
    while app.running {
        app.refresh()?;
        terminal.draw(|f| ui::draw(f, &app))?;

        match events.next()? {
            event::AppEvent::Tick => {}
            event::AppEvent::Key(key) => app.handle_key(key),
            event::AppEvent::Quit => app.running = false,
        }
    }

    // Restore terminal to normal mode.
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use aegis_ledger::AuditEntry;

    /// Create a sample AuditEntry for testing.
    pub fn sample_entry(principal: &str, decision: &str, action_kind: &str) -> AuditEntry {
        AuditEntry {
            entry_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
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
}
