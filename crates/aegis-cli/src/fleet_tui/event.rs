//! Terminal event handling for the fleet TUI.
//!
//! Reuses the same crossterm polling pattern as the pilot TUI:
//! short tick rate to keep the dashboard responsive while polling
//! the daemon for updated agent status.

use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};

/// Events produced by the terminal event loop.
pub enum AppEvent {
    /// No user input within the tick window; used to poll daemon updates.
    Tick,
    /// A key was pressed.
    Key(KeyEvent),
    /// Text was pasted (bracketed paste).
    Paste(String),
}

/// Polls crossterm for terminal events at a fixed tick rate.
pub struct EventHandler {
    tick_rate: Duration,
}

impl EventHandler {
    /// Create a new event handler with the given tick rate in milliseconds.
    pub fn new(tick_rate_ms: u64) -> Self {
        Self {
            tick_rate: Duration::from_millis(tick_rate_ms),
        }
    }

    /// Poll for the next event, blocking up to `tick_rate`.
    pub fn next(&self) -> anyhow::Result<AppEvent> {
        if event::poll(self.tick_rate)? {
            match event::read()? {
                CrosstermEvent::Key(key) => Ok(AppEvent::Key(key)),
                CrosstermEvent::Paste(text) => Ok(AppEvent::Paste(text)),
                _ => Ok(AppEvent::Tick),
            }
        } else {
            Ok(AppEvent::Tick)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_handler_construction() {
        let handler = EventHandler::new(200);
        assert_eq!(handler.tick_rate, Duration::from_millis(200));
    }
}
