//! PTY-based TUI integration test harness with terminal emulation.
//!
//! This crate lets you spawn terminal applications in a pseudo-terminal,
//! send keystrokes, and read back the rendered screen contents using a
//! `vt100` terminal emulator. It is designed for automated testing of
//! TUI applications where you need to verify what the user would see.
//!
//! # Overview
//!
//! - [`TerminalSession`]: spawns a command in a PTY with terminal emulation
//! - [`Expect`]: builder-style API for waiting, sending keys, and asserting
//! - [`Key`]: terminal key encoding (arrows, function keys, ctrl, alt, etc.)
//! - [`ScreenSnapshot`]: frozen capture of screen state for comparison
//! - [`HarnessError`]: error types for timeout, assertion failure, etc.
//!
//! # Example
//!
//! ```no_run
//! use aegis_harness::{TerminalSession, Expect, Key};
//! use std::time::Duration;
//!
//! let mut session = TerminalSession::spawn("/bin/echo", &["hello".into()]).unwrap();
//! Expect::new(&mut session)
//!     .timeout(Duration::from_secs(3))
//!     .wait_for_text("hello")
//!     .unwrap();
//! ```

pub mod error;
pub mod expect;
pub mod key;
pub mod session;
pub mod snapshot;

pub use error::HarnessError;
pub use expect::Expect;
pub use key::Key;
pub use session::{SessionOptions, TerminalSession};
pub use snapshot::ScreenSnapshot;
