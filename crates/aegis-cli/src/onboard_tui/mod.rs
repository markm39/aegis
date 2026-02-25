//! TUI onboarding wizard for first-run `aegis`.
//!
//! When `aegis` is invoked with nothing configured, this module provides a
//! ratatui-based wizard that lets the user pick an LLM provider, writes
//! daemon.toml, starts the daemon, and returns an `OnboardResult` indicating
//! success or cancellation.

pub mod app;
mod auth_flow;
mod callback_server;
mod ui;

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event as CrosstermEvent};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

pub use app::OnboardResult;

/// Tick rate for the wizard event loop (milliseconds).
const TICK_RATE_MS: u64 = 50;

/// Run the onboarding wizard TUI and return the result.
///
/// Initializes the terminal in raw/alternate-screen mode, runs the event
/// loop, and restores the terminal on exit.
pub fn run_onboard_wizard() -> Result<OnboardResult> {
    // Install panic hook to restore terminal on panic.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(io::stderr(), LeaveAlternateScreen, crossterm::cursor::Show,);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::style::Print("\x1b[r\x1b[0m\x1b[H\x1b[2J\x1b[3J\x1b[H"),
        EnterAlternateScreen,
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = app::OnboardApp::new();
    let tick_rate = Duration::from_millis(TICK_RATE_MS);

    while app.running {
        terminal.draw(|f| ui::draw(f, &app))?;

        if event::poll(tick_rate)? {
            if let CrosstermEvent::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }

        // Poll for background auth flow completions (device flow, PKCE).
        app.tick();
    }

    // Restore terminal.
    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(app.result())
}
