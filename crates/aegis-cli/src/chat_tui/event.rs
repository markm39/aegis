//! Terminal event handling for the chat TUI.
//!
//! Reuses the same crossterm polling pattern as the fleet and pilot TUIs:
//! short tick rate to keep the interface responsive while polling for
//! agent output updates.

use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, MouseEvent};

/// Events produced by the terminal event loop.
pub enum AppEvent {
    /// A key was pressed.
    Key(KeyEvent),
    /// Text was pasted (bracketed paste).
    Paste(String),
    /// A mouse event (scroll, click, etc.).
    #[allow(dead_code)]
    Mouse(MouseEvent),
    /// No user input within the tick window; used to poll for updates.
    Tick,
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
                CrosstermEvent::Mouse(mouse) => Ok(AppEvent::Mouse(mouse)),
                _ => Ok(AppEvent::Tick),
            }
        } else {
            Ok(AppEvent::Tick)
        }
    }

    /// Drain all pending events, processing each with the given closure.
    ///
    /// The first poll blocks up to `tick_rate`; subsequent polls use zero
    /// timeout to coalesce rapid inputs (especially scroll) into one frame.
    pub fn drain(&self, mut handler: impl FnMut(AppEvent)) -> anyhow::Result<()> {
        let mut timeout = self.tick_rate;
        while event::poll(timeout)? {
            timeout = Duration::ZERO;
            let evt = match event::read()? {
                CrosstermEvent::Key(key) => AppEvent::Key(key),
                CrosstermEvent::Paste(text) => AppEvent::Paste(text),
                CrosstermEvent::Mouse(mouse) => AppEvent::Mouse(mouse),
                _ => AppEvent::Tick,
            };
            handler(evt);
        }
        Ok(())
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
