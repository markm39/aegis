//! Capture stream infrastructure, frame ring buffer, TUI bridge,
//! subagent session tracking, and directory-copy helpers.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use aegis_control::daemon::{FramePayload, TuiToolData};
use aegis_toolkit::contract::CaptureRegion as ToolkitCaptureRegion;
use aegis_types::daemon::AgentStatus;

use crate::fleet::Fleet;
use crate::toolkit_runtime::TuiRuntimeBridge;

pub(crate) const FRAME_RING_CAPACITY: usize = 5;
pub(crate) const CAPTURE_DEFAULT_FPS: u16 = 30;
pub(crate) const DEFAULT_SUBAGENT_DEPTH_LIMIT: u8 = 3;

/// Runtime-only record of a spawned subagent's lineage.
#[derive(Debug, Clone)]
pub(crate) struct SubagentSession {
    pub parent: String,
    pub depth: u8,
}

/// A single captured screen frame held in the ring buffer.
#[derive(Debug, Clone)]
pub(crate) struct CachedFrame {
    pub payload: FramePayload,
    pub frame_id: u64,
    pub captured_at: std::time::Instant,
}

/// Bridges the fleet's agent PTY output into the toolkit TUI runtime.
pub(crate) struct FleetTuiBridge<'a> {
    pub fleet: &'a Fleet,
    pub default_target: &'a str,
}

impl TuiRuntimeBridge for FleetTuiBridge<'_> {
    fn snapshot(&self, session_id: &str) -> Result<TuiToolData, String> {
        let target = if session_id.is_empty() {
            self.default_target
        } else {
            session_id
        };
        let lines = self.fleet.agent_output(target, 200)?;
        Ok(TuiToolData::Snapshot {
            target: target.to_string(),
            text: lines.join("\n"),
            cursor: [0, 0],
            size: [0, 0],
        })
    }

    fn send_input(&self, session_id: &str, text: &str) -> Result<TuiToolData, String> {
        let target = if session_id.is_empty() {
            self.default_target
        } else {
            session_id
        };
        self.fleet.send_to_agent(target, text)?;
        Ok(TuiToolData::Input {
            target: target.to_string(),
            sent: true,
        })
    }
}

/// Fixed-capacity ring buffer of recent capture frames.
pub(crate) struct FrameRing {
    frames: VecDeque<CachedFrame>,
    capacity: usize,
}

impl FrameRing {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            frames: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub(crate) fn push(&mut self, frame: CachedFrame) {
        if self.frames.len() >= self.capacity {
            self.frames.pop_front();
        }
        self.frames.push_back(frame);
    }

    pub(crate) fn latest(&self) -> Option<&CachedFrame> {
        self.frames.back()
    }
}

/// An active screen-capture stream owned by the daemon runtime.
#[allow(dead_code)]
pub(crate) struct CaptureStream {
    pub session_id: String,
    pub target_fps: u16,
    pub region: Option<ToolkitCaptureRegion>,
    pub stop: Arc<AtomicBool>,
    pub frames: Arc<Mutex<FrameRing>>,
    pub handle: std::thread::JoinHandle<()>,
}

impl CaptureStream {
    /// Signal the capture thread to stop and wait for it to exit.
    pub(crate) fn stop_and_join(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.handle.join();
    }
}

/// Recursively copy a directory tree from `src` to `dst`.
pub(crate) fn copy_dir_recursive(
    src: &std::path::Path,
    dst: &std::path::Path,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Human-readable label for an agent's current status.
pub(crate) fn status_label(status: &AgentStatus) -> String {
    match status {
        AgentStatus::Pending => "pending".to_string(),
        AgentStatus::Running { pid } => format!("running (pid {pid})"),
        AgentStatus::Stopped { exit_code } => format!("stopped (exit {exit_code})"),
        AgentStatus::Crashed {
            exit_code,
            restart_in_secs,
        } => format!("crashed (exit {exit_code}, restart in {restart_in_secs}s)"),
        AgentStatus::Failed {
            exit_code,
            restart_count,
        } => format!("failed (exit {exit_code}, restarts {restart_count})"),
        AgentStatus::Stopping => "stopping".to_string(),
        AgentStatus::Disabled => "disabled".to_string(),
        AgentStatus::Queued { lane } => format!("queued (lane {lane})"),
    }
}

/// Build the session key string for an agent's primary session.
pub(crate) fn session_key_for_agent(name: &str) -> String {
    format!("agent:{name}:main")
}

/// Parse an `agent:<name>:main` session key back into the agent name.
pub(crate) fn parse_session_key(session_key: &str) -> Option<String> {
    let trimmed = session_key.trim();
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() == 3 && parts[0] == "agent" && parts[2] == "main" {
        let name = parts[1].to_string();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    } else {
        None
    }
}
