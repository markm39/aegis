//! Error types for the harness crate.

/// Errors that can occur during test harness operations.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    /// Timed out waiting for expected content to appear on screen.
    #[error("timeout waiting for: {expected}")]
    Timeout {
        /// The text or pattern that was expected.
        expected: String,
        /// The screen contents at the time of timeout.
        screen: String,
    },
    /// A screen content assertion failed.
    #[error("assertion failed: {message}\nScreen contents:\n{screen}")]
    AssertionFailed {
        /// Description of what was expected.
        message: String,
        /// The screen contents at the time of failure.
        screen: String,
    },
    /// An error from the underlying PTY session.
    #[error("PTY error: {0}")]
    Pty(#[from] aegis_types::AegisError),
    /// An invalid regex pattern was provided.
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    /// The child process exited before the operation completed.
    #[error("child exited unexpectedly with code {code}")]
    ChildExited {
        /// The exit code of the child process.
        code: i32,
    },
    /// A catch-all for other errors.
    #[error("{0}")]
    Other(String),
}
