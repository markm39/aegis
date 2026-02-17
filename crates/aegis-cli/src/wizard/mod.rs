//! TUI setup wizard for `aegis init`.
//!
//! Provides an interactive ratatui-based wizard for creating new Aegis
//! configurations. Matches the visual style of the Aegis monitor dashboard.

mod app;
pub mod model;
mod policy_gen;
mod ui;

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event as CrosstermEvent};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use app::WizardApp;
pub use model::WizardResult;

/// Tick rate for the wizard event loop (milliseconds).
const TICK_RATE_MS: u64 = 50;

/// Run the TUI setup wizard and return the result.
///
/// Initializes the terminal in raw/alternate-screen mode, runs the wizard
/// event loop, and restores the terminal on exit (including on error).
pub fn run_wizard() -> Result<WizardResult> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = WizardApp::new();
    let tick_rate = Duration::from_millis(TICK_RATE_MS);

    while app.running {
        terminal.draw(|f| ui::draw(f, &app))?;

        if event::poll(tick_rate)? {
            if let CrosstermEvent::Key(key) = event::read()? {
                // Only handle Press events (ignore Release/Repeat on some terminals)
                if key.kind == crossterm::event::KeyEventKind::Press {
                    app.handle_key(key);
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(app.result())
}
