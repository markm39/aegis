//! Aegis Monitor -- a ratatui terminal dashboard for real-time audit log monitoring.
//!
//! Provides a live-updating view of the Aegis audit ledger with filtering,
//! navigation, and aggregate statistics. Launch via `run_monitor()` for a
//! single config or `run_dashboard()` for a multi-config home view.
mod app;
mod event;
mod ui;

use app::App;

pub use app::DashboardConfig;

/// Default tick rate (milliseconds) for the TUI event loop.
const DEFAULT_TICK_RATE_MS: u64 = 500;

/// Run the monitor TUI for a single configuration's ledger.
///
/// Initializes the terminal in raw/alternate-screen mode, runs the main
/// event loop (refreshing from the ledger on every tick), and restores
/// the terminal on exit.
pub fn run_monitor(ledger_path: std::path::PathBuf) -> anyhow::Result<()> {
    run_app(App::new(ledger_path))
}

/// Run the multi-config dashboard TUI.
///
/// Starts in Home mode showing all configurations. The user can select a
/// config to drill into its audit feed, then Esc back to Home.
pub fn run_dashboard(configs: Vec<DashboardConfig>) -> anyhow::Result<()> {
    run_app(App::new_dashboard(configs))
}

/// Shared TUI event loop: initialize terminal, run until quit, restore terminal.
fn run_app(mut app: App) -> anyhow::Result<()> {
    // Install panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stderr(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::cursor::Show,
        );
        original_hook(info);
    }));

    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let events = event::EventHandler::new(DEFAULT_TICK_RATE_MS);

    while app.running {
        app.refresh()?;
        terminal.draw(|f| ui::draw(f, &app))?;

        match events.next()? {
            event::AppEvent::Tick => {}
            event::AppEvent::Key(key) => app.handle_key(key),
        }
    }

    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    // Restore original panic hook
    let _ = std::panic::take_hook();

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
