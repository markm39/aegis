//! Pseudo-terminal session management.
//!
//! Spawns a child process (the AI agent) in a PTY so we can intercept all
//! terminal I/O. The master end of the PTY is used for reading agent output
//! and injecting keystrokes.

use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::pty::openpty;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{self, ForkResult, Pid};

use aegis_types::AegisError;

/// A child process running in a pseudo-terminal.
pub struct PtySession {
    master: OwnedFd,
    child_pid: Pid,
}

impl PtySession {
    /// Spawn a command in a new PTY.
    ///
    /// The child process inherits the given environment and working directory.
    /// The master fd is set non-blocking for integration with `poll()`.
    pub fn spawn(
        command: &str,
        args: &[String],
        working_dir: &Path,
        env: &[(String, String)],
    ) -> Result<Self, AegisError> {
        let pty = openpty(None, None)
            .map_err(|e| AegisError::PilotError(format!("openpty failed: {e}")))?;

        // Safety: fork is unsafe but standard Unix practice for PTY management.
        // The child immediately exec's, so async-signal-safety is maintained.
        match unsafe { unistd::fork() } {
            Ok(ForkResult::Child) => {
                // Child process: set up the slave PTY as stdin/stdout/stderr.
                // IMPORTANT: errors must call _exit(), not return via ?, because
                // returning would propagate back to the caller in the child process,
                // causing two processes to run the same parent code path.
                // Run child setup in a closure so ? collects errors without
                // returning to the caller (which would be the child process
                // running the parent's code path -- a classic fork bug).
                let err = (|| -> Result<(), String> {
                    drop(pty.master);

                    unistd::setsid()
                        .map_err(|e| format!("setsid failed: {e}"))?;

                    // Set controlling terminal via ioctl TIOCSCTTY
                    unsafe {
                        if libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSCTTY as _, 0) < 0 {
                            let err = std::io::Error::last_os_error();
                            eprintln!("aegis-pilot: TIOCSCTTY failed: {err}");
                        }
                    }

                    unistd::dup2(pty.slave.as_raw_fd(), libc::STDIN_FILENO)
                        .map_err(|e| format!("dup2 stdin: {e}"))?;
                    unistd::dup2(pty.slave.as_raw_fd(), libc::STDOUT_FILENO)
                        .map_err(|e| format!("dup2 stdout: {e}"))?;
                    unistd::dup2(pty.slave.as_raw_fd(), libc::STDERR_FILENO)
                        .map_err(|e| format!("dup2 stderr: {e}"))?;

                    drop(pty.slave);

                    unistd::chdir(working_dir)
                        .map_err(|e| format!("chdir: {e}"))?;

                    for (key, value) in env {
                        std::env::set_var(key, value);
                    }

                    let c_command = CString::new(command.to_string())
                        .map_err(|e| format!("invalid command: {e}"))?;
                    let mut c_args: Vec<CString> = vec![c_command.clone()];
                    for arg in args {
                        c_args.push(
                            CString::new(arg.as_str())
                                .map_err(|e| format!("invalid arg: {e}"))?
                        );
                    }

                    unistd::execvp(&c_command, &c_args)
                        .map_err(|e| format!("exec failed: {e}"))?;

                    Ok(()) // unreachable: execvp replaces the process
                })();

                // If we get here, something failed before exec replaced the process.
                if let Err(e) = err {
                    eprintln!("aegis-pilot: child setup failed: {e}");
                }
                unsafe { libc::_exit(1) };
            }
            Ok(ForkResult::Parent { child }) => {
                // Parent: close the slave, keep the master
                drop(pty.slave);

                // Set master to non-blocking
                let flags = fcntl(pty.master.as_raw_fd(), FcntlArg::F_GETFL)
                    .map_err(|e| AegisError::PilotError(format!("fcntl F_GETFL: {e}")))?;
                let flags = OFlag::from_bits_truncate(flags);
                fcntl(
                    pty.master.as_raw_fd(),
                    FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
                )
                .map_err(|e| AegisError::PilotError(format!("fcntl F_SETFL: {e}")))?;

                Ok(Self {
                    master: pty.master,
                    child_pid: child,
                })
            }
            Err(e) => Err(AegisError::PilotError(format!("fork failed: {e}"))),
        }
    }

    /// Non-blocking read from the master PTY.
    ///
    /// Returns `Ok(0)` if no data is available (EAGAIN/EWOULDBLOCK).
    /// Returns `Err` on actual I/O errors.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, AegisError> {
        match unistd::read(self.master.as_raw_fd(), buf) {
            Ok(n) => Ok(n),
            Err(nix::errno::Errno::EAGAIN) => Ok(0),
            Err(nix::errno::Errno::EIO) => {
                // EIO on master means child closed the slave (exited)
                Ok(0)
            }
            Err(e) => Err(AegisError::PilotError(format!("pty read: {e}"))),
        }
    }

    /// Write all bytes to the master PTY (injecting into child's stdin).
    ///
    /// Retries on EAGAIN up to ~5 seconds before giving up. Without a limit,
    /// a child that stops reading stdin could cause this to spin forever,
    /// blocking the supervisor thread.
    pub fn write_all(&self, data: &[u8]) -> Result<(), AegisError> {
        let mut written = 0;
        let mut retries = 0u32;
        while written < data.len() {
            match unistd::write(&self.master, &data[written..]) {
                Ok(n) => {
                    written += n;
                    retries = 0;
                }
                Err(nix::errno::Errno::EAGAIN) => {
                    retries += 1;
                    if retries > 5000 {
                        return Err(AegisError::PilotError(
                            "pty write: buffer full after 5s of retries".into(),
                        ));
                    }
                    // Bail early if child exited (no point retrying a dead process)
                    if retries.is_multiple_of(100) && !self.is_alive() {
                        return Err(AegisError::PilotError(
                            "pty write: child exited during write".into(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(AegisError::PilotError(format!("pty write: {e}")));
                }
            }
        }
        Ok(())
    }

    /// Send a line of text to the child's stdin (appends carriage return).
    ///
    /// Uses `\r` (carriage return) instead of `\n` because TUI applications
    /// like Claude Code run in raw terminal mode where Enter = `\r`.
    pub fn send_line(&self, text: &str) -> Result<(), AegisError> {
        let mut data = text.as_bytes().to_vec();
        data.push(b'\r');
        self.write_all(&data)
    }

    /// Send text using bracketed paste mode, then press Enter.
    ///
    /// Wraps the text in `\x1b[200~`..`\x1b[201~` so TUI applications
    /// (like Claude Code) treat embedded newlines as literal text rather
    /// than as individual Enter keypresses. After the paste, sends `\r`
    /// to submit the input.
    pub fn send_paste(&self, text: &str) -> Result<(), AegisError> {
        let mut data = Vec::with_capacity(text.len() + 20);
        data.extend_from_slice(b"\x1b[200~");
        data.extend_from_slice(text.as_bytes());
        data.extend_from_slice(b"\x1b[201~");
        data.push(b'\r');
        self.write_all(&data)
    }

    /// Block until the child produces output or the timeout expires.
    ///
    /// Returns `true` if output was detected, `false` on timeout.
    /// Useful for waiting until a TUI application has fully initialized
    /// before injecting input.
    pub fn wait_for_output(&self, timeout: std::time::Duration) -> Result<bool, AegisError> {
        let deadline = std::time::Instant::now() + timeout;
        let mut buf = [0u8; 4096];

        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let ms = remaining.as_millis().min(500) as i32;
            if self.poll_readable(ms)? {
                // Drain available data so it doesn't accumulate
                let _ = self.read(&mut buf);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check if the child process is still alive.
    ///
    /// Uses `kill(pid, 0)` instead of `waitpid(WNOHANG)` to avoid reaping
    /// the child -- reaping discards the exit status, which would cause the
    /// subsequent `wait()` call to return ECHILD and default to exit code 0.
    pub fn is_alive(&self) -> bool {
        signal::kill(self.child_pid, None).is_ok()
    }

    /// Wait for the child to exit and return its exit code.
    ///
    /// Returns negative values for signal termination (-signum).
    pub fn wait(&self) -> Result<i32, AegisError> {
        loop {
            match waitpid(self.child_pid, None) {
                Ok(WaitStatus::Exited(_, code)) => return Ok(code),
                Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(-(sig as i32)),
                Ok(WaitStatus::StillAlive) => continue,
                Ok(_) => continue, // Stopped, continued, etc. -- keep waiting
                Err(nix::errno::Errno::ECHILD) => return Ok(0), // Already reaped
                Err(e) => {
                    return Err(AegisError::PilotError(format!("waitpid: {e}")));
                }
            }
        }
    }

    /// The raw file descriptor of the master PTY (for use with poll).
    pub fn master_fd(&self) -> RawFd {
        self.master.as_raw_fd()
    }

    /// The child's process ID.
    pub fn pid(&self) -> u32 {
        u32::try_from(self.child_pid.as_raw()).unwrap_or(0)
    }

    /// Poll the master fd for readability with a timeout.
    ///
    /// Returns `true` if data is available to read, `false` on timeout.
    pub fn poll_readable(&self, timeout_ms: i32) -> Result<bool, AegisError> {
        let borrowed = self.master.as_fd();
        let mut poll_fd = [PollFd::new(borrowed, PollFlags::POLLIN)];
        let timeout = if timeout_ms < 0 {
            PollTimeout::NONE
        } else {
            PollTimeout::try_from(timeout_ms as u32)
                .unwrap_or(PollTimeout::MAX)
        };

        match nix::poll::poll(&mut poll_fd, timeout) {
            Ok(0) => Ok(false),
            Ok(_) => {
                let revents = poll_fd[0].revents().unwrap_or(PollFlags::empty());
                // POLLIN means data available; POLLHUP means child closed
                Ok(revents.contains(PollFlags::POLLIN)
                    || revents.contains(PollFlags::POLLHUP))
            }
            Err(nix::errno::Errno::EINTR) => Ok(false), // Interrupted, treat as timeout
            Err(e) => Err(AegisError::PilotError(format!("poll: {e}"))),
        }
    }

    /// Send SIGTERM to the child process.
    pub fn terminate(&self) -> Result<(), AegisError> {
        signal::kill(self.child_pid, Signal::SIGTERM)
            .map_err(|e| AegisError::PilotError(format!("kill SIGTERM: {e}")))
    }
}

impl crate::session::AgentSession for PtySession {
    fn read(&self, buf: &mut [u8]) -> Result<usize, AegisError> {
        self.read(buf)
    }
    fn write_all(&self, data: &[u8]) -> Result<(), AegisError> {
        self.write_all(data)
    }
    fn send_line(&self, text: &str) -> Result<(), AegisError> {
        self.send_line(text)
    }
    fn send_paste(&self, text: &str) -> Result<(), AegisError> {
        self.send_paste(text)
    }
    fn poll_readable(&self, timeout_ms: i32) -> Result<bool, AegisError> {
        self.poll_readable(timeout_ms)
    }
    fn wait_for_output(&self, timeout: std::time::Duration) -> Result<bool, AegisError> {
        self.wait_for_output(timeout)
    }
    fn is_alive(&self) -> bool {
        self.is_alive()
    }
    fn wait(&self) -> Result<i32, AegisError> {
        self.wait()
    }
    fn terminate(&self) -> Result<(), AegisError> {
        self.terminate()
    }
    fn pid(&self) -> u32 {
        self.pid()
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // Attempt to terminate the child if still alive, then reap to avoid zombies.
        // Ignore errors -- we're in a destructor and best-effort cleanup is fine.
        if matches!(
            waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG)),
            Ok(WaitStatus::StillAlive)
        ) {
            let _ = signal::kill(self.child_pid, Signal::SIGTERM);

            // Poll for up to 2 seconds for graceful exit before resorting to SIGKILL.
            // Agent processes (like Claude Code) may need time to clean up.
            for _ in 0..40 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if !matches!(
                    waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG)),
                    Ok(WaitStatus::StillAlive)
                ) {
                    return; // Reaped successfully
                }
            }

            // Still alive after 2s: force kill and block until reaped.
            let _ = signal::kill(self.child_pid, Signal::SIGKILL);
            let _ = waitpid(self.child_pid, None);
        }
        // OwnedFd closes the master fd automatically when dropped.
    }
}

/// Create a `PtySession` from a pre-existing master fd and child pid.
///
/// Used in tests and by the supervisor when the PTY was set up externally.
///
/// # Safety
/// The caller must ensure `master_fd` is a valid open file descriptor
/// and `child_pid` is a valid process ID.
pub unsafe fn from_raw_parts(master_fd: RawFd, child_pid: i32) -> PtySession {
    PtySession {
        master: unsafe { OwnedFd::from_raw_fd(master_fd) },
        child_pid: Pid::from_raw(child_pid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn spawn_echo_and_read_output() {
        let session = PtySession::spawn(
            "/bin/echo",
            &["hello pilot".to_string()],
            &PathBuf::from("/tmp"),
            &[],
        )
        .expect("spawn failed");

        // Give the child a moment to write
        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut buf = [0u8; 1024];
        let mut output = Vec::new();

        // Read all available output
        loop {
            match session.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }

        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("hello pilot"),
            "expected 'hello pilot' in output: {text:?}"
        );

        let code = session.wait().expect("wait failed");
        assert_eq!(code, 0);
    }

    #[test]
    fn spawn_and_write_to_stdin() {
        // Use cat to echo back what we write
        let session = PtySession::spawn(
            "/bin/cat",
            &[],
            &PathBuf::from("/tmp"),
            &[],
        )
        .expect("spawn failed");

        std::thread::sleep(std::time::Duration::from_millis(50));
        session.send_line("test input").expect("write failed");
        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut buf = [0u8; 1024];
        let mut output = Vec::new();
        loop {
            match session.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }

        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("test input"),
            "expected 'test input' in output: {text:?}"
        );

        // Send EOF to cat
        session.write_all(&[0x04]).expect("EOF failed"); // Ctrl-D
        let code = session.wait().expect("wait failed");
        assert_eq!(code, 0);
    }

    #[test]
    fn poll_readable_returns_data() {
        let session = PtySession::spawn(
            "/bin/echo",
            &["poll test".to_string()],
            &PathBuf::from("/tmp"),
            &[],
        )
        .expect("spawn failed");

        // Should become readable quickly
        let readable = session.poll_readable(1000).expect("poll failed");
        assert!(readable, "expected data to be readable");

        session.wait().ok();
    }

    #[test]
    fn is_alive_and_exit_code() {
        // sleep 0 exits immediately
        let session = PtySession::spawn(
            "/bin/sleep",
            &["0".to_string()],
            &PathBuf::from("/tmp"),
            &[],
        )
        .expect("spawn failed");

        std::thread::sleep(std::time::Duration::from_millis(200));
        let code = session.wait().expect("wait failed");
        assert_eq!(code, 0);
    }
}
