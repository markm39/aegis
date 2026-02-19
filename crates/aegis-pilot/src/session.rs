//! Agent session trait abstracting over PTY and tmux backends.
//!
//! The supervisor operates on any `AgentSession` implementation. This lets us
//! swap between direct PTY management and tmux-based sessions (which support
//! attaching from external terminals).

use aegis_types::AegisError;

/// Supported JSON stream tool kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    ClaudeCode,
    Codex,
}

/// Output stream type for an agent session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StreamKind {
    #[default]
    Plain,
    Json { tool: ToolKind },
}

/// Trait for an agent process session (PTY, tmux, etc.).
///
/// Provides the minimal interface the supervisor needs: reading output,
/// writing input, lifecycle management, and process identification.
pub trait AgentSession {
    /// Non-blocking read from the session's output stream.
    /// Returns `Ok(0)` if no data is available.
    fn read(&self, buf: &mut [u8]) -> Result<usize, AegisError>;

    /// Write all bytes to the session's input stream.
    fn write_all(&self, data: &[u8]) -> Result<(), AegisError>;

    /// Send a line of text followed by Enter (carriage return).
    fn send_line(&self, text: &str) -> Result<(), AegisError>;

    /// Send text using bracketed paste mode, then Enter.
    fn send_paste(&self, text: &str) -> Result<(), AegisError>;

    /// Poll for readable data with a timeout in milliseconds.
    /// Returns `true` if data is available.
    fn poll_readable(&self, timeout_ms: i32) -> Result<bool, AegisError>;

    /// Block until the session produces output or the timeout expires.
    fn wait_for_output(&self, timeout: std::time::Duration) -> Result<bool, AegisError>;

    /// Check if the child process is still alive.
    fn is_alive(&self) -> bool;

    /// Wait for the child to exit and return its exit code.
    fn wait(&self) -> Result<i32, AegisError>;

    /// Send SIGTERM to the child process.
    fn terminate(&self) -> Result<(), AegisError>;

    /// The child's process ID.
    fn pid(&self) -> u32;

    /// Identify the output stream type for formatting.
    fn stream_kind(&self) -> StreamKind {
        StreamKind::Plain
    }

    /// If the session supports external attach (e.g., tmux), return the
    /// attach command components. Returns None for direct PTY sessions.
    fn attach_command(&self) -> Option<Vec<String>> {
        None
    }

    /// If this is a JSON stream session, return the session ID for follow-ups.
    fn session_id(&self) -> Option<String> {
        None
    }
}
