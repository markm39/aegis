//! Tmux-based agent session.
//!
//! Spawns the agent inside a tmux session, enabling external terminal attach
//! via `tmux attach-session`. Output is captured through a named pipe using
//! `tmux pipe-pane`, and input is sent via `tmux send-keys`.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use aegis_types::AegisError;

use crate::session::AgentSession;

/// Check whether tmux is available on the system.
pub fn tmux_available() -> bool {
    Command::new("tmux")
        .arg("-V")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// An agent process running inside a tmux session.
///
/// The session is named `aegis-<name>` and can be attached from any terminal
/// with `tmux attach-session -t aegis-<name>`.
pub struct TmuxSession {
    session_name: String,
    child_pid: u32,
    /// Named pipe (FIFO) receiving output from `tmux pipe-pane`.
    pipe_path: PathBuf,
    /// Read end of the pipe, set to non-blocking.
    pipe_fd: OwnedFd,
}

impl TmuxSession {
    /// Spawn a command inside a new tmux session.
    ///
    /// Creates a tmux session named `aegis-<name>`, runs the command inside it,
    /// and sets up a pipe-pane for output capture.
    pub fn spawn(
        name: &str,
        command: &str,
        args: &[String],
        working_dir: &Path,
        env: &[(String, String)],
    ) -> Result<Self, AegisError> {
        let session_name = format!("aegis-{name}");

        // Kill any stale session with this name
        let _ = Command::new("tmux")
            .args(["kill-session", "-t", &session_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        // Build the shell command string with env vars
        let mut shell_cmd = String::new();
        for (key, val) in env {
            // Simple shell escaping: single-quote the value
            let escaped = val.replace('\'', "'\\''");
            shell_cmd.push_str(&format!("export {key}='{escaped}'; "));
        }
        shell_cmd.push_str(command);
        for arg in args {
            let escaped = arg.replace('\'', "'\\''");
            shell_cmd.push_str(&format!(" '{escaped}'"));
        }

        // Create the tmux session with the command
        let status = Command::new("tmux")
            .args([
                "new-session",
                "-d",
                "-s",
                &session_name,
                "-x",
                "200",
                "-y",
                "50",
                "-c",
                &working_dir.to_string_lossy(),
            ])
            .arg(shell_cmd)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .status()
            .map_err(|e| AegisError::PilotError(format!("tmux new-session failed: {e}")))?;

        if !status.success() {
            return Err(AegisError::PilotError(format!(
                "tmux new-session exited with {status}"
            )));
        }

        // Get the pane PID
        let pid_output = Command::new("tmux")
            .args(["list-panes", "-t", &session_name, "-F", "#{pane_pid}"])
            .output()
            .map_err(|e| AegisError::PilotError(format!("tmux list-panes failed: {e}")))?;

        let pid_str = String::from_utf8_lossy(&pid_output.stdout)
            .trim()
            .to_string();
        let child_pid: u32 = pid_str
            .parse()
            .map_err(|e| AegisError::PilotError(format!("bad pane pid {pid_str:?}: {e}")))?;

        // Create a named pipe for output capture
        let pipe_dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let pipe_path = PathBuf::from(pipe_dir).join(format!("aegis-tmux-{name}.pipe"));

        // Remove stale pipe
        let _ = std::fs::remove_file(&pipe_path);

        // Create the FIFO
        nix::unistd::mkfifo(&pipe_path, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .map_err(|e| AegisError::PilotError(format!("mkfifo failed: {e}")))?;

        // Start pipe-pane to forward output to our FIFO.
        // The -o flag means output-only (don't capture input).
        let status = Command::new("tmux")
            .args([
                "pipe-pane",
                "-o",
                "-t",
                &session_name,
                &format!("cat >> '{}'", pipe_path.display()),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| AegisError::PilotError(format!("tmux pipe-pane failed: {e}")))?;

        if !status.success() {
            let _ = std::fs::remove_file(&pipe_path);
            return Err(AegisError::PilotError(format!(
                "tmux pipe-pane exited with {status}"
            )));
        }

        // Open the FIFO for reading in non-blocking mode.
        // O_RDONLY | O_NONBLOCK so open() doesn't block waiting for a writer.
        let raw_fd = nix::fcntl::open(
            &pipe_path,
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NONBLOCK,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|e| AegisError::PilotError(format!("open pipe failed: {e}")))?;

        let pipe_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(Self {
            session_name,
            child_pid,
            pipe_path,
            pipe_fd,
        })
    }

    /// The tmux session name (e.g., "aegis-ux-agent").
    pub fn session_name(&self) -> &str {
        &self.session_name
    }

    /// Send raw keys to the tmux pane via `tmux send-keys`.
    fn tmux_send_keys(&self, keys: &str) -> Result<(), AegisError> {
        let status = Command::new("tmux")
            .args(["send-keys", "-t", &self.session_name, "-l", keys])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| AegisError::PilotError(format!("tmux send-keys failed: {e}")))?;

        if !status.success() {
            return Err(AegisError::PilotError(format!(
                "tmux send-keys exited with {status}"
            )));
        }
        Ok(())
    }

    /// Send a special key (like Enter) to the tmux pane.
    fn tmux_send_special(&self, key: &str) -> Result<(), AegisError> {
        let status = Command::new("tmux")
            .args(["send-keys", "-t", &self.session_name, key])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| AegisError::PilotError(format!("tmux send-keys special failed: {e}")))?;

        if !status.success() {
            return Err(AegisError::PilotError(format!(
                "tmux send-keys special exited with {status}"
            )));
        }
        Ok(())
    }

    /// Check if the tmux session still exists.
    fn session_exists(&self) -> bool {
        Command::new("tmux")
            .args(["has-session", "-t", &self.session_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl AgentSession for TmuxSession {
    fn read(&self, buf: &mut [u8]) -> Result<usize, AegisError> {
        // Non-blocking read from the pipe-pane FIFO.
        let fd = self.pipe_fd.as_raw_fd();
        match nix::unistd::read(fd, buf) {
            Ok(n) => Ok(n),
            Err(nix::errno::Errno::EAGAIN) => Ok(0),
            Err(nix::errno::Errno::EIO) => Ok(0),
            Err(e) => Err(AegisError::PilotError(format!("pipe read: {e}"))),
        }
    }

    fn write_all(&self, data: &[u8]) -> Result<(), AegisError> {
        // Convert bytes to string and send via tmux send-keys.
        let text = String::from_utf8_lossy(data);
        self.tmux_send_keys(&text)
    }

    fn send_line(&self, text: &str) -> Result<(), AegisError> {
        self.tmux_send_keys(text)?;
        self.tmux_send_special("Enter")
    }

    fn send_paste(&self, text: &str) -> Result<(), AegisError> {
        // Use tmux's built-in bracketed paste support.
        // set-buffer + paste-buffer with -p flag sends in bracketed paste mode.
        let status = Command::new("tmux")
            .args(["set-buffer", "-b", "aegis-paste", text])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| AegisError::PilotError(format!("tmux set-buffer failed: {e}")))?;

        if !status.success() {
            return Err(AegisError::PilotError("tmux set-buffer failed".into()));
        }

        let status = Command::new("tmux")
            .args([
                "paste-buffer",
                "-b",
                "aegis-paste",
                "-t",
                &self.session_name,
                "-p",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| AegisError::PilotError(format!("tmux paste-buffer failed: {e}")))?;

        if !status.success() {
            return Err(AegisError::PilotError("tmux paste-buffer failed".into()));
        }

        // Give the TUI time to process the pasted text before pressing Enter.
        // Without this delay, Claude Code may not have finished ingesting the
        // paste event and Enter gets lost.
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Press Enter to submit
        self.tmux_send_special("Enter")
    }

    fn poll_readable(&self, timeout_ms: i32) -> Result<bool, AegisError> {
        let borrowed = self.pipe_fd.as_fd();
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
                Ok(revents.contains(PollFlags::POLLIN) || revents.contains(PollFlags::POLLHUP))
            }
            Err(nix::errno::Errno::EINTR) => Ok(false),
            Err(e) => Err(AegisError::PilotError(format!("poll pipe: {e}"))),
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
        // Check both the tmux session and the actual process.
        if !self.session_exists() {
            return false;
        }
        signal::kill(Pid::from_raw(self.child_pid as i32), None).is_ok()
    }

    fn wait(&self) -> Result<i32, AegisError> {
        // Poll until the tmux session ends.
        loop {
            if !self.session_exists() {
                // Session gone. Try to get exit code from the process.
                // Since we don't own the process (tmux does), we can't waitpid.
                // Return 0 for clean exit, -15 if the process is gone.
                return Ok(0);
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    fn terminate(&self) -> Result<(), AegisError> {
        // Send SIGTERM to the pane's process.
        signal::kill(Pid::from_raw(self.child_pid as i32), Signal::SIGTERM)
            .map_err(|e| AegisError::PilotError(format!("kill SIGTERM: {e}")))
    }

    fn pid(&self) -> u32 {
        self.child_pid
    }

    fn attach_command(&self) -> Option<Vec<String>> {
        Some(vec![
            "tmux".to_string(),
            "attach-session".to_string(),
            "-t".to_string(),
            self.session_name.clone(),
        ])
    }
}

impl Drop for TmuxSession {
    fn drop(&mut self) {
        // Clean up the pipe file.
        let _ = std::fs::remove_file(&self.pipe_path);
        // Don't kill the tmux session here -- the fleet manager handles lifecycle.
    }
}

use std::os::fd::AsFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tmux_availability_check() {
        // Just verify the function runs without panicking.
        let _ = tmux_available();
    }
}
