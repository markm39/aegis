//! Builder-style expect/assert API for terminal sessions.
//!
//! [`Expect`] wraps a [`TerminalSession`] and provides a fluent interface
//! for the common pattern of: wait for something, send something, assert
//! something. Methods are chainable and return `&mut Self` for ergonomic
//! test code.
//!
//! # Example
//!
//! ```no_run
//! # use aegis_harness::{Expect, TerminalSession, Key};
//! # use std::time::Duration;
//! # fn example() -> Result<(), aegis_harness::HarnessError> {
//! let mut session = TerminalSession::spawn("/bin/sh", &[])?;
//! Expect::new(&mut session)
//!     .timeout(Duration::from_secs(3))
//!     .wait_for_text("$")?
//!     .type_text("echo hello")?
//!     .send_key(Key::Enter)?
//!     .wait_for_text("hello")?
//!     .assert_screen_contains("hello")?;
//! # Ok(())
//! # }
//! ```

use std::time::{Duration, Instant};

use crate::error::HarnessError;
use crate::key::Key;
use crate::session::TerminalSession;
use crate::snapshot::ScreenSnapshot;

/// A builder for expect/assert operations on a terminal session.
pub struct Expect<'a> {
    session: &'a mut TerminalSession,
    timeout: Duration,
}

impl<'a> Expect<'a> {
    /// Create a new Expect wrapper with a default 5-second timeout.
    pub fn new(session: &'a mut TerminalSession) -> Self {
        Self {
            session,
            timeout: Duration::from_secs(5),
        }
    }

    /// Set the timeout for subsequent wait operations.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = duration;
        self
    }

    /// Wait until the screen contains the given text.
    ///
    /// Pumps PTY output in a loop until the text appears or the timeout
    /// expires. Returns an error with the screen contents if the text
    /// never appears.
    pub fn wait_for_text(&mut self, needle: &str) -> Result<&mut Self, HarnessError> {
        let deadline = Instant::now() + self.timeout;
        loop {
            self.session.pump()?;
            if self.session.screen_contains(needle) {
                return Ok(self);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout {
                    expected: needle.to_string(),
                    screen: self.session.screen_dump(),
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Wait until the screen text matches a regex pattern.
    ///
    /// Pumps PTY output in a loop until the pattern matches or the timeout
    /// expires.
    pub fn wait_for_pattern(&mut self, pattern: &str) -> Result<&mut Self, HarnessError> {
        let re = regex::Regex::new(pattern)?;
        let deadline = Instant::now() + self.timeout;
        loop {
            self.session.pump()?;
            if re.is_match(&self.session.screen_text()) {
                return Ok(self);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout {
                    expected: format!("pattern: {pattern}"),
                    screen: self.session.screen_dump(),
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Wait until the PTY has been idle (no new output) for `idle_time`.
    pub fn wait_for_idle(&mut self, idle_time: Duration) -> Result<&mut Self, HarnessError> {
        let deadline = Instant::now() + self.timeout;
        let mut last_data = Instant::now();
        loop {
            let n = self.session.pump()?;
            if n > 0 {
                last_data = Instant::now();
            } else if last_data.elapsed() >= idle_time {
                return Ok(self);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout {
                    expected: format!("idle for {idle_time:?}"),
                    screen: self.session.screen_dump(),
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Send a single key to the terminal.
    pub fn send_key(&mut self, key: Key) -> Result<&mut Self, HarnessError> {
        self.session.send_key(key)?;
        Ok(self)
    }

    /// Type text character by character.
    ///
    /// Each character is sent as a separate keystroke with a small delay
    /// between them, simulating realistic typing.
    pub fn type_text(&mut self, text: &str) -> Result<&mut Self, HarnessError> {
        for ch in text.chars() {
            self.session.send_key(Key::Char(ch))?;
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(self)
    }

    /// Send a line of text (appends newline).
    pub fn send_line(&mut self, text: &str) -> Result<&mut Self, HarnessError> {
        self.session.send_line(text)?;
        Ok(self)
    }

    /// Assert that the screen currently contains the given text.
    ///
    /// Does not wait -- checks the current screen state immediately.
    /// Pump the session first if you need to ensure output is up to date.
    pub fn assert_screen_contains(&self, needle: &str) -> Result<&Self, HarnessError> {
        if !self.session.screen_contains(needle) {
            return Err(HarnessError::AssertionFailed {
                message: format!("expected screen to contain: {needle:?}"),
                screen: self.session.screen_dump(),
            });
        }
        Ok(self)
    }

    /// Assert that the screen does NOT contain the given text.
    pub fn assert_screen_lacks(&self, needle: &str) -> Result<&Self, HarnessError> {
        if self.session.screen_contains(needle) {
            return Err(HarnessError::AssertionFailed {
                message: format!("expected screen NOT to contain: {needle:?}"),
                screen: self.session.screen_dump(),
            });
        }
        Ok(self)
    }

    /// Take a snapshot of the current screen state.
    pub fn snapshot(&self) -> ScreenSnapshot {
        self.session.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_for_text_on_echo() {
        let mut session =
            TerminalSession::spawn("/bin/echo", &["hello world".to_string()]).expect("spawn failed");

        Expect::new(&mut session)
            .timeout(Duration::from_secs(3))
            .wait_for_text("hello")
            .expect("should find 'hello' on screen");

        session.wait().ok();
    }

    #[test]
    fn assert_screen_contains_passes() {
        let mut session =
            TerminalSession::spawn("/bin/echo", &["assertion-test".to_string()]).expect("spawn failed");

        let mut expect = Expect::new(&mut session);
        expect
            .wait_for_text("assertion-test")
            .expect("should find text");
        expect
            .assert_screen_contains("assertion-test")
            .expect("assertion should pass");

        session.wait().ok();
    }

    #[test]
    fn assert_screen_lacks_passes() {
        let mut session =
            TerminalSession::spawn("/bin/echo", &["present".to_string()]).expect("spawn failed");

        let mut expect = Expect::new(&mut session);
        expect.wait_for_text("present").expect("should find text");
        expect
            .assert_screen_lacks("absent-string")
            .expect("absent string should not be on screen");

        session.wait().ok();
    }

    #[test]
    fn wait_for_pattern_with_regex() {
        let mut session =
            TerminalSession::spawn("/bin/echo", &["version 1.2.3".to_string()]).expect("spawn failed");

        Expect::new(&mut session)
            .timeout(Duration::from_secs(3))
            .wait_for_pattern(r"version \d+\.\d+\.\d+")
            .expect("should match version pattern");

        session.wait().ok();
    }

    #[test]
    fn timeout_returns_error_with_screen() {
        let mut session =
            TerminalSession::spawn("/bin/echo", &["actual".to_string()]).expect("spawn failed");

        let mut expect = Expect::new(&mut session)
            .timeout(Duration::from_millis(200));
        let result = expect.wait_for_text("nonexistent-text-xyz");

        match result {
            Err(HarnessError::Timeout { expected, screen }) => {
                assert_eq!(expected, "nonexistent-text-xyz");
                assert!(!screen.is_empty());
            }
            Ok(_) => panic!("expected Timeout error, got Ok"),
            Err(e) => panic!("expected Timeout error, got: {e}"),
        }

        session.wait().ok();
    }
}
