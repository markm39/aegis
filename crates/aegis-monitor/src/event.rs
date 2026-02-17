//! Terminal event handling for the monitor TUI.
//!
//! Wraps crossterm's event polling to produce a simple stream of
//! `AppEvent` values (tick, key press, or quit).

use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};

/// Events produced by the terminal event loop.
pub enum AppEvent {
    /// No user input within the tick window; used to trigger a data refresh.
    Tick,
    /// A key was pressed.
    Key(KeyEvent),
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
    ///
    /// Returns `AppEvent::Tick` when no input arrives before the deadline,
    /// `AppEvent::Quit` when the user presses 'q', and `AppEvent::Key` for
    /// all other key presses.
    pub fn next(&self) -> anyhow::Result<AppEvent> {
        if event::poll(self.tick_rate)? {
            match event::read()? {
                CrosstermEvent::Key(key) => Ok(AppEvent::Key(key)),
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
        let handler = EventHandler::new(500);
        assert_eq!(handler.tick_rate, Duration::from_millis(500));
    }

    #[test]
    fn event_handler_zero_tick_rate() {
        let handler = EventHandler::new(0);
        assert_eq!(handler.tick_rate, Duration::from_millis(0));
    }
}
