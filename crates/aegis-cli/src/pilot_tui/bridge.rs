//! Control plane bridge for the pilot TUI.
//!
//! Connects the aegis-control Unix socket and HTTP servers to the pilot
//! supervisor. Action commands (approve, deny, input, nudge) are forwarded
//! to the supervisor via `SupervisorCommand`. Query commands (status, output)
//! are served directly from a [`SharedPilotState`] that the TUI keeps updated.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tracing::{info, warn};
use uuid::Uuid;

use aegis_control::command::{Command, CommandResponse, PilotStatus};
use aegis_control::server::{self, ControlServerConfig};
use aegis_pilot::supervisor::{PilotStats, SupervisorCommand};

/// Maximum recent output lines to keep for the control API.
const MAX_SHARED_OUTPUT: usize = 500;

/// Pilot state shared between the TUI thread and the control server thread.
///
/// The TUI updates this as it processes `PilotUpdate` events. The control
/// bridge reads it to serve Status and GetOutput queries without blocking
/// the supervisor.
pub struct SharedPilotState {
    pub stats: PilotStats,
    pub pending: Vec<SharedPendingInfo>,
    pub recent_output: VecDeque<String>,
    pub child_alive: bool,
    pub pid: u32,
    pub command: String,
    pub adapter: String,
    pub start_time: Instant,
    pub last_output_time: Instant,
}

/// Minimal pending request info for the control API.
pub struct SharedPendingInfo {
    pub request_id: Uuid,
    /// Stored for future list-pending control endpoint (Phase 4).
    #[allow(dead_code)]
    pub raw_prompt: String,
}

impl SharedPilotState {
    /// Create a new shared state for a pilot session.
    pub fn new(pid: u32, command: String, adapter: String) -> Self {
        let now = Instant::now();
        Self {
            stats: PilotStats::default(),
            pending: Vec::new(),
            recent_output: VecDeque::with_capacity(MAX_SHARED_OUTPUT),
            child_alive: true,
            pid,
            command,
            adapter,
            start_time: now,
            last_output_time: now,
        }
    }

    /// Append an output line, evicting the oldest if at capacity.
    pub fn push_output(&mut self, line: String) {
        if self.recent_output.len() >= MAX_SHARED_OUTPUT {
            self.recent_output.pop_front();
        }
        self.recent_output.push_back(line);
        self.last_output_time = Instant::now();
    }

    /// Register a new pending request.
    pub fn add_pending(&mut self, request_id: Uuid, raw_prompt: String) {
        self.pending.push(SharedPendingInfo {
            request_id,
            raw_prompt,
        });
    }

    /// Remove a resolved pending request.
    pub fn remove_pending(&mut self, request_id: Uuid) {
        self.pending.retain(|p| p.request_id != request_id);
    }
}

/// Start control servers and bridge in a background thread.
///
/// Returns a shutdown sender and join handle. Send `true` on the shutdown
/// sender to stop the servers gracefully.
pub fn start_control_thread(
    config: &ControlServerConfig,
    supervisor_tx: std::sync::mpsc::Sender<SupervisorCommand>,
    shared_state: Arc<Mutex<SharedPilotState>>,
) -> Result<
    (
        tokio::sync::watch::Sender<bool>,
        std::thread::JoinHandle<()>,
    ),
    anyhow::Error,
> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let config = config.clone();

    let handle = std::thread::Builder::new()
        .name("pilot-control".into())
        .spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    warn!("failed to create tokio runtime for control servers: {e}");
                    return;
                }
            };

            rt.block_on(async move {
                run_control_servers(config, supervisor_tx, shared_state, shutdown_rx).await;
            });
        })?;

    Ok((shutdown_tx, handle))
}

/// Run the control servers inside the tokio runtime.
///
/// Starts the Unix socket server (always) and the HTTP server (if configured),
/// plus a bridge task that processes incoming commands.
async fn run_control_servers(
    config: ControlServerConfig,
    supervisor_tx: std::sync::mpsc::Sender<SupervisorCommand>,
    shared_state: Arc<Mutex<SharedPilotState>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let (command_tx, command_rx) = server::command_channel(64);

    // Spawn the bridge task that processes commands
    let bridge_handle = tokio::spawn(run_bridge(command_rx, supervisor_tx, shared_state));

    // Spawn Unix socket server
    let unix_tx = command_tx.clone();
    let unix_shutdown = shutdown_rx.clone();
    let socket_path = config.socket_path.clone();
    let unix_handle = tokio::spawn(async move {
        if let Err(e) = server::unix::serve(&socket_path, unix_tx, unix_shutdown).await {
            warn!("unix socket server error: {e}");
        }
    });

    info!(socket = %config.socket_path.display(), "control: unix socket server started");

    // Optionally spawn HTTP server
    let http_handle = if !config.http_listen.is_empty() {
        let http_tx = command_tx.clone();
        let http_shutdown = shutdown_rx.clone();
        let listen = config.http_listen.clone();
        let api_key = config.api_key.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) =
                server::http::serve(&listen, http_tx, api_key, http_shutdown, None, None).await
            {
                warn!("http control server error: {e}");
            }
        });
        info!(listen = %config.http_listen, "control: http server started");
        Some(handle)
    } else {
        None
    };

    // Drop our copy of command_tx so the bridge task can detect when servers stop
    drop(command_tx);

    // Wait for all tasks
    let _ = unix_handle.await;
    if let Some(h) = http_handle {
        let _ = h.await;
    }
    let _ = bridge_handle.await;
}

/// Bridge task: receives commands from control servers and handles them.
async fn run_bridge(
    mut command_rx: server::CommandRx,
    supervisor_tx: std::sync::mpsc::Sender<SupervisorCommand>,
    shared_state: Arc<Mutex<SharedPilotState>>,
) {
    while let Some((command, resp_tx)) = command_rx.recv().await {
        let response = handle_control_command(&command, &supervisor_tx, &shared_state);
        let _ = resp_tx.send(response);
    }
}

/// Process a single control command.
///
/// Query commands (Status, GetOutput) read from shared state.
/// Action commands (Approve, Deny, SendInput, Nudge) forward to the supervisor.
fn handle_control_command(
    command: &Command,
    supervisor_tx: &std::sync::mpsc::Sender<SupervisorCommand>,
    shared_state: &Arc<Mutex<SharedPilotState>>,
) -> CommandResponse {
    match command {
        Command::Status => {
            let state = match shared_state.lock() {
                Ok(s) => s,
                Err(_) => return CommandResponse::error("state lock poisoned"),
            };
            let status = PilotStatus {
                command: state.command.clone(),
                pid: state.pid,
                alive: state.child_alive,
                uptime_secs: state.start_time.elapsed().as_secs(),
                idle_secs: state.last_output_time.elapsed().as_secs(),
                pending_count: state.pending.len(),
                approved: state.stats.approved,
                denied: state.stats.denied,
                nudges: state.stats.nudges,
                adapter: state.adapter.clone(),
            };
            match serde_json::to_value(&status) {
                Ok(data) => CommandResponse::ok_with_data("ok", data),
                Err(e) => CommandResponse::error(format!("serialization error: {e}")),
            }
        }

        Command::GetOutput { lines } => {
            let state = match shared_state.lock() {
                Ok(s) => s,
                Err(_) => return CommandResponse::error("state lock poisoned"),
            };
            let n = lines.unwrap_or(50);
            let output: Vec<&str> = state
                .recent_output
                .iter()
                .rev()
                .take(n)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .map(|s| s.as_str())
                .collect();
            CommandResponse::ok_with_data("ok", serde_json::json!({ "lines": output }))
        }

        Command::Approve { request_id } => {
            if supervisor_tx
                .send(SupervisorCommand::Approve {
                    request_id: *request_id,
                })
                .is_err()
            {
                return CommandResponse::error("supervisor disconnected");
            }
            CommandResponse::ok("approved")
        }

        Command::Deny { request_id, .. } => {
            if supervisor_tx
                .send(SupervisorCommand::Deny {
                    request_id: *request_id,
                })
                .is_err()
            {
                return CommandResponse::error("supervisor disconnected");
            }
            CommandResponse::ok("denied")
        }

        Command::SendInput { text } => {
            if supervisor_tx
                .send(SupervisorCommand::SendInput { text: text.clone() })
                .is_err()
            {
                return CommandResponse::error("supervisor disconnected");
            }
            CommandResponse::ok("input sent")
        }

        Command::Nudge { message } => {
            if supervisor_tx
                .send(SupervisorCommand::Nudge {
                    message: message.clone(),
                })
                .is_err()
            {
                return CommandResponse::error("supervisor disconnected");
            }
            CommandResponse::ok("nudge sent")
        }

        Command::UpdatePolicy => CommandResponse::error("policy hot-reload not yet supported"),

        Command::Shutdown { .. } => {
            // The TUI handles shutdown via 'q' key; control clients can't force it yet.
            // Future: signal the TUI's running flag via shared state.
            CommandResponse::error("remote shutdown not yet supported; press 'q' in the TUI")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_state_push_output() {
        let mut state = SharedPilotState::new(123, "claude".into(), "ClaudeCode".into());
        state.push_output("line 1".into());
        state.push_output("line 2".into());
        assert_eq!(state.recent_output.len(), 2);
        assert_eq!(state.recent_output[0], "line 1");
        assert_eq!(state.recent_output[1], "line 2");
    }

    #[test]
    fn shared_state_output_eviction() {
        let mut state = SharedPilotState::new(123, "claude".into(), "ClaudeCode".into());
        for i in 0..MAX_SHARED_OUTPUT + 50 {
            state.push_output(format!("line {i}"));
        }
        assert_eq!(state.recent_output.len(), MAX_SHARED_OUTPUT);
        // Oldest should be evicted
        assert_eq!(state.recent_output[0], "line 50");
    }

    #[test]
    fn shared_state_pending() {
        let mut state = SharedPilotState::new(123, "claude".into(), "ClaudeCode".into());
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        state.add_pending(id1, "Allow bash?".into());
        state.add_pending(id2, "Allow write?".into());
        assert_eq!(state.pending.len(), 2);

        state.remove_pending(id1);
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.pending[0].request_id, id2);
    }

    #[test]
    fn handle_status_command() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let state = Arc::new(Mutex::new(SharedPilotState::new(
            42,
            "claude".into(),
            "ClaudeCode".into(),
        )));

        let resp = handle_control_command(&Command::Status, &tx, &state);
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert_eq!(data["pid"], 42);
        assert_eq!(data["command"], "claude");
        assert_eq!(data["adapter"], "ClaudeCode");
        assert!(data["alive"].as_bool().unwrap());
    }

    #[test]
    fn handle_get_output_command() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let state = Arc::new(Mutex::new(SharedPilotState::new(
            1,
            "test".into(),
            "Auto".into(),
        )));
        {
            let mut s = state.lock().unwrap();
            for i in 0..10 {
                s.push_output(format!("line {i}"));
            }
        }

        let resp = handle_control_command(&Command::GetOutput { lines: Some(3) }, &tx, &state);
        assert!(resp.ok);
        let lines = resp.data.unwrap()["lines"].as_array().unwrap().clone();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line 7");
        assert_eq!(lines[2], "line 9");
    }

    #[test]
    fn handle_approve_command() {
        let (tx, rx) = std::sync::mpsc::channel();
        let state = Arc::new(Mutex::new(SharedPilotState::new(
            1,
            "test".into(),
            "Auto".into(),
        )));
        let id = Uuid::new_v4();

        let resp = handle_control_command(&Command::Approve { request_id: id }, &tx, &state);
        assert!(resp.ok);

        let cmd = rx.try_recv().unwrap();
        assert!(matches!(cmd, SupervisorCommand::Approve { request_id } if request_id == id));
    }

    #[test]
    fn handle_deny_command() {
        let (tx, rx) = std::sync::mpsc::channel();
        let state = Arc::new(Mutex::new(SharedPilotState::new(
            1,
            "test".into(),
            "Auto".into(),
        )));
        let id = Uuid::new_v4();

        let resp = handle_control_command(
            &Command::Deny {
                request_id: id,
                reason: Some("risky".into()),
            },
            &tx,
            &state,
        );
        assert!(resp.ok);

        let cmd = rx.try_recv().unwrap();
        assert!(matches!(cmd, SupervisorCommand::Deny { request_id } if request_id == id));
    }

    #[test]
    fn handle_send_input_command() {
        let (tx, rx) = std::sync::mpsc::channel();
        let state = Arc::new(Mutex::new(SharedPilotState::new(
            1,
            "test".into(),
            "Auto".into(),
        )));

        let resp = handle_control_command(
            &Command::SendInput {
                text: "hello".into(),
            },
            &tx,
            &state,
        );
        assert!(resp.ok);

        let cmd = rx.try_recv().unwrap();
        assert!(matches!(cmd, SupervisorCommand::SendInput { text } if text == "hello"));
    }

    #[test]
    fn handle_nudge_command() {
        let (tx, rx) = std::sync::mpsc::channel();
        let state = Arc::new(Mutex::new(SharedPilotState::new(
            1,
            "test".into(),
            "Auto".into(),
        )));

        let resp = handle_control_command(
            &Command::Nudge {
                message: Some("keep going".into()),
            },
            &tx,
            &state,
        );
        assert!(resp.ok);

        let cmd = rx.try_recv().unwrap();
        assert!(matches!(cmd, SupervisorCommand::Nudge { message: Some(m) } if m == "keep going"));
    }

    #[test]
    fn handle_unsupported_commands() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let state = Arc::new(Mutex::new(SharedPilotState::new(
            1,
            "test".into(),
            "Auto".into(),
        )));

        let resp = handle_control_command(&Command::UpdatePolicy, &tx, &state);
        assert!(!resp.ok);

        let resp = handle_control_command(&Command::Shutdown { message: None }, &tx, &state);
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_supervisor_disconnected() {
        let (tx, rx) = std::sync::mpsc::channel::<SupervisorCommand>();
        let state = Arc::new(Mutex::new(SharedPilotState::new(
            1,
            "test".into(),
            "Auto".into(),
        )));

        // Drop the receiver to simulate disconnection
        drop(rx);

        let resp = handle_control_command(
            &Command::Approve {
                request_id: Uuid::new_v4(),
            },
            &tx,
            &state,
        );
        assert!(!resp.ok);
        assert!(resp.message.contains("disconnected"));
    }
}
