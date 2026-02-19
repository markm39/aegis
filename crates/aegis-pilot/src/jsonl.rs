//! Generic JSONL session support for CLI tools that stream structured events.

use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use serde_json::Value;

use aegis_types::AegisError;

use crate::session::{StreamKind, ToolKind};
use crate::session::AgentSession;

/// Protocol behavior for JSONL-based tool sessions.
pub trait JsonlProtocol: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn stream_kind(&self) -> StreamKind;
    fn spawn_args(&self, base_args: &[String], prompt: &str) -> Vec<String>;
    fn resume_args(&self, base_args: &[String], session_id: &str, prompt: &str) -> Vec<String>;
    fn parse_session_id(&self, json: &Value) -> Option<String>;
    fn attach_command(&self, working_dir: &Path, session_id: &str, base_args: &[String]) -> Vec<String>;
}

struct SessionInner {
    child: Child,
    stdout_fd: std::os::fd::OwnedFd,
    stdin: Option<ChildStdin>,
}

/// JSONL session wrapper.
pub struct JsonlSession<P: JsonlProtocol> {
    protocol: P,
    inner: Mutex<SessionInner>,
    session_id: Mutex<Option<String>>,
    working_dir: PathBuf,
    command: String,
    base_args: Vec<String>,
    env: Vec<(String, String)>,
    line_buf: Mutex<String>,
}

impl<P: JsonlProtocol> JsonlSession<P> {
    pub fn spawn(
        name: &str,
        protocol: P,
        command: &str,
        base_args: &[String],
        working_dir: &Path,
        env: &[(String, String)],
        prompt: &str,
    ) -> Result<Self, AegisError> {
        let full_args = protocol.spawn_args(base_args, prompt);
        let inner = Self::spawn_process(command, &full_args, working_dir, env)?;

        tracing::info!(
            agent = name,
            pid = inner.child.id(),
            protocol = protocol.name(),
            "spawned JSONL session"
        );

        Ok(Self {
            protocol,
            inner: Mutex::new(inner),
            session_id: Mutex::new(None),
            working_dir: working_dir.to_path_buf(),
            command: command.to_string(),
            base_args: base_args.to_vec(),
            env: env.to_vec(),
            line_buf: Mutex::new(String::new()),
        })
    }

    fn spawn_process(
        command: &str,
        args: &[String],
        working_dir: &Path,
        env: &[(String, String)],
    ) -> Result<SessionInner, AegisError> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .current_dir(working_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_remove("CLAUDECODE");

        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn().map_err(|e| {
            AegisError::PilotError(format!("failed to spawn {command}: {e}"))
        })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            AegisError::PilotError("child stdout not captured".into())
        })?;

        let raw_fd = stdout.as_raw_fd();
        let flags = fcntl(raw_fd, FcntlArg::F_GETFL)
            .map_err(|e| AegisError::PilotError(format!("fcntl F_GETFL: {e}")))?;
        let flags = OFlag::from_bits_truncate(flags);
        fcntl(raw_fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
            .map_err(|e| AegisError::PilotError(format!("fcntl F_SETFL: {e}")))?;

        use std::os::fd::FromRawFd;
        let owned_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd) };
        std::mem::forget(stdout);

        let stdin = child.stdin.take();
        Ok(SessionInner {
            child,
            stdout_fd: owned_fd,
            stdin,
        })
    }

    fn update_session_id_from_text(&self, text: &str) {
        let mut buf = match self.line_buf.lock() {
            Ok(b) => b,
            Err(_) => return,
        };
        buf.push_str(text);

        let mut parts: Vec<&str> = buf.split('\n').collect();
        let trailing = if !buf.ends_with('\n') { parts.pop().unwrap_or("") } else { "" };

        for line in parts {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
                if let Some(id) = self.protocol.parse_session_id(&value) {
                    if let Ok(mut slot) = self.session_id.lock() {
                        if slot.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                            *slot = Some(id);
                        }
                    }
                }
            }
        }

        *buf = trailing.to_string();
    }

    fn send_via_stdin(inner: &mut SessionInner, text: &str) -> Result<(), AegisError> {
        if let Some(stdin) = inner.stdin.as_mut() {
            use std::io::Write;
            stdin.write_all(text.as_bytes()).map_err(|e| {
                AegisError::PilotError(format!("stdin write failed: {e}"))
            })?;
            stdin.write_all(b"\n").map_err(|e| {
                AegisError::PilotError(format!("stdin write failed: {e}"))
            })?;
            Ok(())
        } else {
            Err(AegisError::PilotError("stdin not available".into()))
        }
    }

    fn send_resume(&self, text: &str) -> Result<(), AegisError> {
        let session_id = self.session_id().ok_or_else(|| {
            AegisError::PilotError("cannot resume: session_id not yet available".into())
        })?;

        let resume_args = self.protocol.resume_args(&self.base_args, &session_id, text);
        let new_inner = Self::spawn_process(
            &self.command,
            &resume_args,
            &self.working_dir,
            &self.env,
        )?;

        let mut guard = self.inner.lock().map_err(|e| {
            AegisError::PilotError(format!("session lock poisoned: {e}"))
        })?;
        *guard = new_inner;
        Ok(())
    }
}

impl<P: JsonlProtocol> AgentSession for JsonlSession<P> {
    fn read(&self, buf: &mut [u8]) -> Result<usize, AegisError> {
        let guard = self.inner.lock().map_err(|e| {
            AegisError::PilotError(format!("session lock poisoned: {e}"))
        })?;

        let fd = guard.stdout_fd.as_raw_fd();
        match nix::unistd::read(fd, buf) {
            Ok(n) => {
                if n > 0 {
                    let text = String::from_utf8_lossy(&buf[..n]);
                    self.update_session_id_from_text(&text);
                }
                Ok(n)
            }
            Err(nix::errno::Errno::EAGAIN) => Ok(0),
            Err(nix::errno::Errno::EIO) => Ok(0),
            Err(e) => Err(AegisError::PilotError(format!("stdout read: {e}"))),
        }
    }

    fn write_all(&self, data: &[u8]) -> Result<(), AegisError> {
        let text = String::from_utf8_lossy(data);
        let mut guard = self.inner.lock().map_err(|e| {
            AegisError::PilotError(format!("session lock poisoned: {e}"))
        })?;
        Self::send_via_stdin(&mut guard, &text)
    }

    fn send_line(&self, text: &str) -> Result<(), AegisError> {
        let mut guard = self.inner.lock().map_err(|e| {
            AegisError::PilotError(format!("session lock poisoned: {e}"))
        })?;

        match guard.child.try_wait() {
            Ok(Some(_)) => {
                drop(guard);
                self.send_resume(text)
            }
            Ok(None) => Self::send_via_stdin(&mut guard, text),
            Err(e) => Err(AegisError::PilotError(format!("try_wait failed: {e}"))),
        }
    }

    fn send_paste(&self, text: &str) -> Result<(), AegisError> {
        self.send_line(text)
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

    fn stream_kind(&self) -> StreamKind {
        self.protocol.stream_kind()
    }

    fn attach_command(&self) -> Option<Vec<String>> {
        let id = self.session_id()?;
        Some(self.protocol.attach_command(&self.working_dir, &id, &self.base_args))
    }

    fn session_id(&self) -> Option<String> {
        self.session_id.lock().ok().and_then(|s| s.clone())
    }
}

/// Codex JSONL protocol.
pub struct CodexJsonProtocol;

impl JsonlProtocol for CodexJsonProtocol {
    fn name(&self) -> &str {
        "Codex"
    }

    fn stream_kind(&self) -> StreamKind {
        StreamKind::Json { tool: ToolKind::Codex }
    }

    fn spawn_args(&self, base_args: &[String], prompt: &str) -> Vec<String> {
        let mut args = vec!["exec".to_string(), "--json".to_string()];
        args.extend(base_args.iter().cloned());
        if !prompt.is_empty() {
            args.push(prompt.to_string());
        }
        args
    }

    fn resume_args(&self, base_args: &[String], session_id: &str, prompt: &str) -> Vec<String> {
        let mut args = vec![
            "exec".to_string(),
            "resume".to_string(),
            "--json".to_string(),
            session_id.to_string(),
        ];
        if !prompt.is_empty() {
            args.push(prompt.to_string());
        }
        args.extend(base_args.iter().cloned());
        args
    }

    fn parse_session_id(&self, json: &Value) -> Option<String> {
        let event_type = json.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if event_type == "thread.started" {
            return json.get("thread_id").and_then(|v| v.as_str()).map(|s| s.to_string());
        }
        json.get("session_id").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    fn attach_command(&self, working_dir: &Path, session_id: &str, _base_args: &[String]) -> Vec<String> {
        vec![
            "codex".to_string(),
            "resume".to_string(),
            "-C".to_string(),
            working_dir.to_string_lossy().to_string(),
            session_id.to_string(),
        ]
    }
}
