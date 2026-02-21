//! Terminal session management with PTY and terminal emulation.
//!
//! [`TerminalSession`] wraps a [`PtySession`](aegis_pilot::pty::PtySession)
//! with a [`vt100::Parser`] to provide a fully emulated terminal. This lets
//! you spawn a TUI application, send it keystrokes, and read back the
//! rendered screen contents -- exactly as a user would see them.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use aegis_pilot::pty::PtySession;

use crate::error::HarnessError;
use crate::key::Key;
use crate::snapshot::ScreenSnapshot;

/// Options for spawning a terminal session.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// The command to run.
    pub command: String,
    /// Arguments to pass to the command.
    pub args: Vec<String>,
    /// Working directory for the child process.
    pub working_dir: PathBuf,
    /// Additional environment variables for the child process.
    pub env: Vec<(String, String)>,
    /// Number of terminal rows (default: 24).
    pub rows: u16,
    /// Number of terminal columns (default: 80).
    pub cols: u16,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            command: String::new(),
            args: Vec::new(),
            working_dir: PathBuf::from("/tmp"),
            env: Vec::new(),
            rows: 24,
            cols: 80,
        }
    }
}

/// A terminal session with PTY and vt100 emulation.
///
/// Combines a PTY child process with a terminal emulator so you can:
/// - Spawn any command in a pseudo-terminal
/// - Send keystrokes and text input
/// - Read the rendered screen contents (as a user would see them)
/// - Wait for specific text to appear
/// - Take screen snapshots for assertions
pub struct TerminalSession {
    pty: PtySession,
    parser: vt100::Parser,
    rows: u16,
    cols: u16,
}

impl TerminalSession {
    /// Spawn a command in a PTY with default 80x24 terminal size.
    ///
    /// This is a convenience wrapper around [`spawn_with_options`](Self::spawn_with_options).
    pub fn spawn(command: &str, args: &[String]) -> Result<Self, HarnessError> {
        Self::spawn_with_options(SessionOptions {
            command: command.to_string(),
            args: args.to_vec(),
            ..SessionOptions::default()
        })
    }

    /// Spawn a command in a PTY with custom options.
    ///
    /// Sets the PTY window size so the child application sees the correct
    /// terminal dimensions (important for TUI apps that query terminal size).
    pub fn spawn_with_options(opts: SessionOptions) -> Result<Self, HarnessError> {
        let pty = PtySession::spawn(&opts.command, &opts.args, &opts.working_dir, &opts.env)?;

        // Set the PTY window size so the child sees correct dimensions.
        let ws = libc::winsize {
            ws_row: opts.rows,
            ws_col: opts.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // Safety: ioctl with TIOCSWINSZ is the standard way to set terminal size.
        // The master_fd is valid because we just spawned the PtySession.
        let ret = unsafe { libc::ioctl(pty.master_fd(), libc::TIOCSWINSZ, &ws) };
        if ret < 0 {
            return Err(HarnessError::Other(format!(
                "ioctl TIOCSWINSZ failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let parser = vt100::Parser::new(opts.rows, opts.cols, 0);

        Ok(Self {
            pty,
            parser,
            rows: opts.rows,
            cols: opts.cols,
        })
    }

    /// Read available PTY output and feed it to the terminal emulator.
    ///
    /// Returns the number of bytes read. Returns 0 if no data was available
    /// (the PTY is non-blocking).
    pub fn pump(&mut self) -> Result<usize, HarnessError> {
        let mut buf = [0u8; 4096];
        let n = self.pty.read(&mut buf)?;
        if n > 0 {
            self.parser.process(&buf[..n]);
        }
        Ok(n)
    }

    /// Pump PTY output until no new data arrives for `idle_time`.
    ///
    /// Reads in a loop, feeding data to the terminal emulator, until the
    /// PTY has been silent for at least `idle_time`. Useful for waiting
    /// until a command finishes producing output.
    pub fn pump_until_idle(&mut self, idle_time: Duration) -> Result<(), HarnessError> {
        let mut last_data = Instant::now();
        loop {
            let n = self.pump()?;
            if n > 0 {
                last_data = Instant::now();
            } else if last_data.elapsed() >= idle_time {
                return Ok(());
            } else {
                // Brief sleep to avoid busy-spinning
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// Get the full screen text from the terminal emulator.
    ///
    /// Returns the visible text on screen with rows joined by newlines.
    /// ANSI formatting is already parsed by vt100, so this is plain text.
    pub fn screen_text(&self) -> String {
        self.parser.screen().contents()
    }

    /// Check if the screen contains the given text.
    pub fn screen_contains(&self, needle: &str) -> bool {
        self.screen_text().contains(needle)
    }

    /// Check if the screen text matches a regex pattern.
    pub fn screen_matches(&self, pattern: &str) -> Result<bool, HarnessError> {
        let re = regex::Regex::new(pattern)?;
        Ok(re.is_match(&self.screen_text()))
    }

    /// Write raw bytes to the PTY (injected into the child's stdin).
    pub fn send_raw(&self, data: &[u8]) -> Result<(), HarnessError> {
        self.pty.write_all(data)?;
        Ok(())
    }

    /// Send a line of text to the child (appends newline).
    pub fn send_line(&self, text: &str) -> Result<(), HarnessError> {
        self.pty.send_line(text)?;
        Ok(())
    }

    /// Send a key to the child by encoding it as terminal bytes.
    pub fn send_key(&self, key: Key) -> Result<(), HarnessError> {
        self.pty.write_all(&key.to_bytes())?;
        Ok(())
    }

    /// Check if the child process is still running.
    pub fn is_alive(&self) -> bool {
        self.pty.is_alive()
    }

    /// Wait for the child process to exit and return the exit code.
    pub fn wait(self) -> Result<i32, HarnessError> {
        let code = self.pty.wait()?;
        Ok(code)
    }

    /// Take a snapshot of the current screen state.
    pub fn snapshot(&self) -> ScreenSnapshot {
        let screen = self.parser.screen();
        let text = screen.contents();
        let rows: Vec<String> = (0..self.rows)
            .map(|r| {
                screen
                    .rows_formatted(r, r + 1)
                    .next()
                    .map(|bytes| {
                        // rows_formatted returns ANSI-formatted bytes;
                        // use contents_between for plain text per row.
                        drop(bytes);
                        screen.contents_between(r, 0, r + 1, 0)
                    })
                    .unwrap_or_default()
            })
            .collect();
        let cursor_pos = screen.cursor_position();

        ScreenSnapshot {
            text,
            rows,
            cursor: cursor_pos,
            size: (self.rows, self.cols),
            timestamp: Instant::now(),
        }
    }

    /// Produce a bordered screen dump for debugging.
    ///
    /// Shows the terminal content within a border, plus cursor position
    /// and terminal dimensions. Useful in error messages.
    pub fn screen_dump(&self) -> String {
        self.snapshot().render()
    }

    /// Get the text of a specific screen row (zero-indexed).
    ///
    /// Returns an empty string if the row is out of bounds.
    pub fn row_text(&self, row: u16) -> String {
        let screen = self.parser.screen();
        if row < self.rows {
            screen.contents_between(row, 0, row + 1, 0)
        } else {
            String::new()
        }
    }

    /// Get the current cursor position as (row, col), zero-indexed.
    pub fn cursor_position(&self) -> (u16, u16) {
        self.parser.screen().cursor_position()
    }

    /// Get the terminal dimensions as (rows, cols).
    pub fn size(&self) -> (u16, u16) {
        (self.rows, self.cols)
    }

    /// Get a reference to the underlying PTY session.
    ///
    /// Exposed for advanced use cases (e.g., polling the master fd).
    pub fn pty(&self) -> &PtySession {
        &self.pty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_echo_and_read_screen() {
        let mut session =
            TerminalSession::spawn("/bin/echo", &["hello".to_string()]).expect("spawn failed");

        // Give the child time to write and pump output
        std::thread::sleep(Duration::from_millis(200));
        session.pump_until_idle(Duration::from_millis(100)).ok();

        assert!(
            session.screen_contains("hello"),
            "screen should contain 'hello', got: {}",
            session.screen_text()
        );

        session.wait().ok();
    }

    #[test]
    fn spawn_cat_and_send_line() {
        let mut session = TerminalSession::spawn("/bin/cat", &[]).expect("spawn failed");
        std::thread::sleep(Duration::from_millis(50));

        session.send_line("test-harness").expect("send_line failed");
        std::thread::sleep(Duration::from_millis(200));
        session.pump_until_idle(Duration::from_millis(100)).ok();

        assert!(
            session.screen_contains("test-harness"),
            "screen should contain 'test-harness', got: {}",
            session.screen_text()
        );

        // Send EOF to exit cat
        session.send_key(Key::Ctrl('d')).expect("send_key failed");
        let code = session.wait().expect("wait failed");
        assert_eq!(code, 0);
    }

    #[test]
    fn custom_terminal_size() {
        let opts = SessionOptions {
            command: "/usr/bin/tput".to_string(),
            args: vec!["lines".to_string()],
            rows: 40,
            cols: 120,
            ..SessionOptions::default()
        };
        let mut session = TerminalSession::spawn_with_options(opts).expect("spawn failed");
        std::thread::sleep(Duration::from_millis(200));
        session.pump_until_idle(Duration::from_millis(100)).ok();

        let (rows, cols) = session.size();
        assert_eq!(rows, 40);
        assert_eq!(cols, 120);
        session.wait().ok();
    }

    #[test]
    fn snapshot_captures_screen_state() {
        let mut session = TerminalSession::spawn("/bin/echo", &["snapshot-test".to_string()])
            .expect("spawn failed");
        std::thread::sleep(Duration::from_millis(200));
        session.pump_until_idle(Duration::from_millis(100)).ok();

        let snap = session.snapshot();
        assert!(snap.text.contains("snapshot-test"));
        assert_eq!(snap.size, (24, 80));
        session.wait().ok();
    }

    #[test]
    fn screen_dump_includes_border() {
        let mut session =
            TerminalSession::spawn("/bin/echo", &["dump-test".to_string()]).expect("spawn failed");
        std::thread::sleep(Duration::from_millis(200));
        session.pump_until_idle(Duration::from_millis(100)).ok();

        let dump = session.screen_dump();
        assert!(dump.contains("+"));
        assert!(dump.contains("cursor="));
        session.wait().ok();
    }
}
