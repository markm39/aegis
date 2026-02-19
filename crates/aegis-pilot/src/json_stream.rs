//! JSON stream session for Claude Code agents.
//!
//! Instead of interacting with Claude Code's TUI via PTY stdin injection,
//! this spawns Claude Code in print mode with `--output-format stream-json`.
//! The prompt is passed reliably as a `-p` CLI argument. Output arrives as
//! NDJSON on stdout.
//!
//! Follow-up messages use `--resume <session-id>` to continue the same
//! conversation. The user can `:pop` into the full interactive TUI via
//! `claude --resume <session-id>`.

use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use aegis_types::AegisError;

use crate::session::AgentSession;

/// Shell-quote a string with single quotes for safe shell expansion.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// An agent session backed by Claude Code's `--print --output-format stream-json`
/// mode. Output is structured NDJSON on stdout; input uses `--resume` for
/// follow-up messages.
pub struct JsonStreamSession {
    /// The running child process. Wrapped in Mutex because `AgentSession`
    /// methods take `&self` but we may need to call `try_wait()` etc.
    inner: Mutex<SessionInner>,
    /// Claude Code session ID for `--resume`.
    session_id: String,
    /// Working directory for spawning resume processes.
    working_dir: PathBuf,
    /// Base command (e.g., "claude").
    command: String,
    /// Base arguments that are always passed (permissions, output format, etc.).
    base_args: Vec<String>,
    /// Environment variables to set on child processes.
    env: Vec<(String, String)>,
}

struct SessionInner {
    child: Child,
    /// Raw fd for the child's stdout pipe, set to non-blocking.
    stdout_fd: std::os::fd::OwnedFd,
}

impl JsonStreamSession {
    /// Spawn Claude Code in print/stream-json mode with the given prompt.
    ///
    /// The process runs: `<command> <args...> -p "<prompt>" --session-id <uuid>
    /// --output-format stream-json --verbose`
    pub fn spawn(
        name: &str,
        command: &str,
        args: &[String],
        working_dir: &Path,
        env: &[(String, String)],
        prompt: &str,
    ) -> Result<Self, AegisError> {
        let session_id = uuid::Uuid::new_v4().to_string();

        // Build full argument list
        let mut full_args: Vec<String> = args.to_vec();
        full_args.extend([
            "--output-format".to_string(),
            "stream-json".to_string(),
            "--verbose".to_string(),
            "--session-id".to_string(),
            session_id.clone(),
            "-p".to_string(),
            prompt.to_string(),
        ]);

        // Preserve base_args for resume (everything except -p, --session-id, prompt)
        let base_args: Vec<String> = args.to_vec();

        let inner = Self::spawn_process(
            command,
            &full_args,
            working_dir,
            env,
        )?;

        tracing::info!(
            agent = name,
            session_id = session_id,
            pid = inner.child.id(),
            "spawned Claude Code in stream-json mode"
        );

        Ok(Self {
            inner: Mutex::new(inner),
            session_id,
            working_dir: working_dir.to_path_buf(),
            command: command.to_string(),
            base_args,
            env: env.to_vec(),
        })
    }

    /// Spawn a child process with piped stdout (non-blocking).
    fn spawn_process(
        command: &str,
        args: &[String],
        working_dir: &Path,
        env: &[(String, String)],
    ) -> Result<SessionInner, AegisError> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .current_dir(working_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Prevent Claude Code from refusing to start inside another CC session.
            .env_remove("CLAUDECODE");

        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn().map_err(|e| {
            AegisError::PilotError(format!("failed to spawn {command}: {e}"))
        })?;

        // Take ownership of stdout and set it non-blocking for poll-based reading.
        let stdout = child.stdout.take().ok_or_else(|| {
            AegisError::PilotError("child stdout not captured".into())
        })?;

        let raw_fd = stdout.as_raw_fd();

        // Set non-blocking
        let flags = fcntl(raw_fd, FcntlArg::F_GETFL)
            .map_err(|e| AegisError::PilotError(format!("fcntl F_GETFL: {e}")))?;
        let flags = OFlag::from_bits_truncate(flags);
        fcntl(raw_fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
            .map_err(|e| AegisError::PilotError(format!("fcntl F_SETFL: {e}")))?;

        // Transfer ownership of the fd. We need to prevent the ChildStdout from
        // closing it when dropped, so we leak it and manage via OwnedFd.
        use std::os::fd::FromRawFd;
        let owned_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd) };
        // Prevent ChildStdout from closing the fd we just took ownership of.
        std::mem::forget(stdout);

        Ok(SessionInner {
            child,
            stdout_fd: owned_fd,
        })
    }

    /// The Claude Code session ID (for `--resume`).
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Send a follow-up message by spawning a resume process.
    ///
    /// This replaces the current child with a new one that continues the
    /// conversation. The old child must have already exited.
    pub fn send_message(&self, text: &str) -> Result<(), AegisError> {
        let mut guard = self.inner.lock().map_err(|e| {
            AegisError::PilotError(format!("session lock poisoned: {e}"))
        })?;

        // Check if the current child has exited
        match guard.child.try_wait() {
            Ok(Some(_)) => {} // exited, good
            Ok(None) => {
                return Err(AegisError::PilotError(
                    "cannot send message: agent is still processing previous turn".into(),
                ));
            }
            Err(e) => {
                tracing::warn!(error = %e, "try_wait failed, proceeding anyway");
            }
        }

        // Build resume args
        let mut resume_args = self.base_args.clone();
        resume_args.extend([
            "--output-format".to_string(),
            "stream-json".to_string(),
            "--verbose".to_string(),
            "--resume".to_string(),
            self.session_id.clone(),
            "-p".to_string(),
            text.to_string(),
        ]);

        let new_inner = Self::spawn_process(
            &self.command,
            &resume_args,
            &self.working_dir,
            &self.env,
        )?;

        tracing::info!(
            session_id = self.session_id,
            pid = new_inner.child.id(),
            "spawned resume process for follow-up message"
        );

        *guard = new_inner;
        Ok(())
    }
}

impl AgentSession for JsonStreamSession {
    fn read(&self, buf: &mut [u8]) -> Result<usize, AegisError> {
        let guard = self.inner.lock().map_err(|e| {
            AegisError::PilotError(format!("session lock poisoned: {e}"))
        })?;

        let fd = guard.stdout_fd.as_raw_fd();
        match nix::unistd::read(fd, buf) {
            Ok(n) => Ok(n),
            Err(nix::errno::Errno::EAGAIN) => Ok(0), // no data available
            Err(nix::errno::Errno::EIO) => Ok(0),
            Err(e) => Err(AegisError::PilotError(format!("stdout read: {e}"))),
        }
    }

    fn write_all(&self, _data: &[u8]) -> Result<(), AegisError> {
        // No stdin pipe in stream-json mode. Follow-ups use send_message().
        Ok(())
    }

    fn send_line(&self, text: &str) -> Result<(), AegisError> {
        // For stream-json sessions, sending input means spawning a resume process.
        self.send_message(text)
    }

    fn send_paste(&self, text: &str) -> Result<(), AegisError> {
        // Same as send_line for this session type.
        self.send_message(text)
    }

    fn poll_readable(&self, timeout_ms: i32) -> Result<bool, AegisError> {
        let guard = self.inner.lock().map_err(|e| {
            AegisError::PilotError(format!("session lock poisoned: {e}"))
        })?;

        let borrowed = guard.stdout_fd.as_fd();
        let mut poll_fd = [PollFd::new(borrowed, PollFlags::POLLIN)];
        let timeout = if timeout_ms < 0 {
            PollTimeout::NONE
        } else {
            PollTimeout::try_from(timeout_ms as u32).unwrap_or(PollTimeout::MAX)
        };

        match nix::poll::poll(&mut poll_fd, timeout) {
            Ok(0) => Ok(false),
            Ok(_) => {
                let revents = poll_fd[0].revents().unwrap_or(PollFlags::empty());
                Ok(revents.contains(PollFlags::POLLIN)
                    || revents.contains(PollFlags::POLLHUP))
            }
            Err(nix::errno::Errno::EINTR) => Ok(false),
            Err(e) => Err(AegisError::PilotError(format!("poll stdout: {e}"))),
        }
    }

    fn wait_for_output(&self, timeout: std::time::Duration) -> Result<bool, AegisError> {
        let deadline = std::time::Instant::now() + timeout;
        let mut buf = [0u8; 4096];

        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let ms = remaining.as_millis().min(500) as i32;
            if self.poll_readable(ms)? {
                let _ = self.read(&mut buf);
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_alive(&self) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        matches!(guard.child.try_wait(), Ok(None))
    }

    fn wait(&self) -> Result<i32, AegisError> {
        let mut guard = self.inner.lock().map_err(|e| {
            AegisError::PilotError(format!("session lock poisoned: {e}"))
        })?;

        let status = guard.child.wait().map_err(|e| {
            AegisError::PilotError(format!("wait failed: {e}"))
        })?;

        Ok(status.code().unwrap_or(-1))
    }

    fn terminate(&self) -> Result<(), AegisError> {
        let guard = self.inner.lock().map_err(|e| {
            AegisError::PilotError(format!("session lock poisoned: {e}"))
        })?;

        signal::kill(Pid::from_raw(guard.child.id() as i32), Signal::SIGTERM)
            .map_err(|e| AegisError::PilotError(format!("kill SIGTERM: {e}")))
    }

    fn pid(&self) -> u32 {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        guard.child.id()
    }

    fn attach_command(&self) -> Option<Vec<String>> {
        // Include `cd <working_dir>` so the resume runs in the correct project
        // context -- Claude Code stores sessions under project-specific paths.
        let quoted_dir = shell_quote(&self.working_dir.display().to_string());
        Some(vec![
            format!("cd {quoted_dir} &&"),
            "claude".to_string(),
            "--resume".to_string(),
            self.session_id.clone(),
        ])
    }

    fn cc_session_id(&self) -> Option<&str> {
        Some(&self.session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_valid_uuid() {
        let id = uuid::Uuid::new_v4().to_string();
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn shell_quote_simple() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_spaces() {
        assert_eq!(shell_quote("/path/with spaces"), "'/path/with spaces'");
    }

    #[test]
    fn shell_quote_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }
}
