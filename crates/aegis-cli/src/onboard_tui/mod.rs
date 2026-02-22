//! TUI onboarding wizard for first-run `aegis`.
//!
//! When `aegis` is invoked with nothing configured, this module provides a
//! proper ratatui-based wizard (replacing the old plain stdin/stdout prompts).
//! It configures an agent, optionally sets up Telegram, writes daemon.toml,
//! starts the daemon, and returns an `OnboardResult` indicating success or
//! cancellation.

pub mod app;
mod ui;

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event as CrosstermEvent,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

pub use app::OnboardResult;

/// Tick rate for the wizard event loop (milliseconds).
const TICK_RATE_MS: u64 = 50;

/// Run the onboarding wizard TUI and return the result.
///
/// Initializes the terminal in raw/alternate-screen mode with bracketed
/// paste enabled, runs the event loop, and restores the terminal on exit.
pub fn run_onboard_wizard() -> Result<OnboardResult> {
    // Install panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(
            io::stderr(),
            LeaveAlternateScreen,
            DisableBracketedPaste,
            crossterm::cursor::Show,
        );
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = app::OnboardApp::new();
    let tick_rate = Duration::from_millis(TICK_RATE_MS);

    while app.running {
        terminal.draw(|f| ui::draw(f, &app))?;

        if event::poll(tick_rate)? {
            match event::read()? {
                CrosstermEvent::Key(key) => app.handle_key(key),
                CrosstermEvent::Paste(text) => app.handle_paste(&text),
                _ => {}
            }
        }

        // Check for async events each tick
        app.poll_telegram();
        app.poll_health();
    }

    // Restore terminal
    disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableBracketedPaste
    )?;
    terminal.show_cursor()?;

    Ok(app.result())
}
