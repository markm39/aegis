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
                // Child process: set up the slave PTY as stdin/stdout/stderr
                drop(pty.master);

                // Create a new session and set the slave as the controlling terminal
                unistd::setsid()
                    .map_err(|e| AegisError::PilotError(format!("setsid failed: {e}")))?;

                // Set controlling terminal via ioctl TIOCSCTTY
                unsafe {
                    if libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSCTTY as _, 0) < 0 {
                        let err = std::io::Error::last_os_error();
                        eprintln!("aegis-pilot: TIOCSCTTY failed: {err}");
                    }
                }

                // Redirect stdio to the slave PTY
                unistd::dup2(pty.slave.as_raw_fd(), libc::STDIN_FILENO)
                    .map_err(|e| AegisError::PilotError(format!("dup2 stdin: {e}")))?;
                unistd::dup2(pty.slave.as_raw_fd(), libc::STDOUT_FILENO)
                    .map_err(|e| AegisError::PilotError(format!("dup2 stdout: {e}")))?;
                unistd::dup2(pty.slave.as_raw_fd(), libc::STDERR_FILENO)
                    .map_err(|e| AegisError::PilotError(format!("dup2 stderr: {e}")))?;

                drop(pty.slave);

                // Set working directory
                unistd::chdir(working_dir)
                    .map_err(|e| AegisError::PilotError(format!("chdir: {e}")))?;

                // Set environment
                for (key, value) in env {
                    std::env::set_var(key, value);
                }

                // Exec the command
                let c_command = CString::new(command.to_string())
                    .map_err(|e| AegisError::PilotError(format!("invalid command: {e}")))?;
                let mut c_args: Vec<CString> = vec![c_command.clone()];
                for arg in args {
                    c_args.push(
                        CString::new(arg.as_str())
                            .map_err(|e| AegisError::PilotError(format!("invalid arg: {e}")))?
                    );
                }

                unistd::execvp(&c_command, &c_args)
                    .map_err(|e| AegisError::PilotError(format!("exec failed: {e}")))?;

                unreachable!("execvp returned Ok");
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
    pub fn write_all(&self, data: &[u8]) -> Result<(), AegisError> {
        let mut written = 0;
        while written < data.len() {
            match unistd::write(&self.master, &data[written..]) {
                Ok(n) => written += n,
                Err(nix::errno::Errno::EAGAIN) => {
                    // Briefly yield and retry
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(AegisError::PilotError(format!("pty write: {e}")));
                }
            }
        }
        Ok(())
    }

    /// Send a line of text to the child's stdin (appends newline).
    pub fn send_line(&self, text: &str) -> Result<(), AegisError> {
        let mut data = text.as_bytes().to_vec();
        data.push(b'\n');
        self.write_all(&data)
    }

    /// Check if the child process is still alive.
    pub fn is_alive(&self) -> bool {
        match waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => true,
            _ => false,
        }
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
        self.child_pid.as_raw() as u32
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
