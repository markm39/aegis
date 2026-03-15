//! Main session supervisor loop.
//!
//! Orchestrates the PTY session, agent adapter, stall detector, and output
//! buffer into a single poll-based event loop. Evaluates detected permission
//! prompts against Cedar policy and auto-approves or denies them.
//!
//! The supervisor communicates with external consumers through three optional
//! channels:
//! - `event_tx`: lightweight [`SessionEvent`] for webhooks and logging
//! - `update_tx`: richer [`SessionUpdate`] for the TUI (includes output lines)
//! - `command_rx`: [`SupervisorCommand`] for receiving approve/deny/input/nudge

use std::collections::HashMap;
use std::io::Write;
use std::sync::mpsc;
use std::time::Duration;

use aegis_policy::PolicyEngine;
use aegis_types::{Action, AegisError, Decision, SessionConfig, UncertainAction};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::adapter::{AgentAdapter, ScanResult};
use crate::output::OutputBuffer;
use crate::session::{AgentSession, StreamKind};
use crate::stall::{StallAction, StallDetector};

/// Statistics collected during an interactive probe session.
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    /// Number of prompts auto-approved.
    pub approved: u64,
    /// Number of prompts auto-denied.
    pub denied: u64,
    /// Number of uncertain prompts.
    pub uncertain: u64,
    /// Number of stall nudges sent.
    pub nudges: u64,
    /// Total output lines processed.
    pub lines_processed: u64,
}

/// Events emitted by the supervisor for external consumers (webhooks, logging).
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// A permission prompt was detected and auto-decided.
    PromptDecided {
        action: String,
        decision: Decision,
        reason: String,
    },
    /// A stall was detected and a nudge was sent.
    StallNudge { nudge_count: u32, idle_secs: u64 },
    /// Max nudges exceeded; agent needs human attention.
    AttentionNeeded { nudge_count: u32 },
    /// An uncertain prompt was encountered.
    UncertainPrompt { text: String, action_taken: String },
    /// The child process exited.
    ChildExited { exit_code: i32 },
}

/// Richer event type for the TUI, including output lines and pending prompts.
///
/// Unlike [`SessionEvent`] (which is for external logging), `SessionUpdate` carries
/// all the information the TUI needs to render the live session.
#[derive(Debug, Clone)]
pub enum SessionUpdate {
    /// A completed output line from the agent (ANSI-stripped).
    OutputLine(String),
    /// A permission prompt was detected and auto-decided.
    PromptDecided {
        action: String,
        decision: Decision,
        reason: String,
    },
    /// An uncertain prompt is pending human decision.
    PendingPrompt {
        request_id: Uuid,
        raw_prompt: String,
    },
    /// A pending prompt was resolved (approved or denied).
    PendingResolved { request_id: Uuid, approved: bool },
    /// A stall nudge was sent.
    StallNudge { nudge_count: u32 },
    /// Max nudges exceeded; agent needs human attention.
    AttentionNeeded { nudge_count: u32 },
    /// Agent resumed output after being stalled; attention no longer needed.
    StallResolved,
    /// The child process exited.
    ChildExited { exit_code: i32 },
    /// Periodic stats snapshot.
    Stats(SessionStats),
    /// The session supports external attach (e.g., tmux, or `claude --resume`).
    /// Contains the command components to attach (e.g., `["claude", "--resume", "<id>"]`).
    AttachCommand(Vec<String>),
    /// Session metadata (stream kind + optional session id).
    SessionInfo {
        kind: StreamKind,
        session_id: Option<String>,
    },
}

/// Commands sent to the supervisor from an external controller.
#[derive(Debug)]
pub enum SupervisorCommand {
    /// Approve a pending permission request.
    Approve { request_id: Uuid },
    /// Deny a pending permission request.
    Deny { request_id: Uuid },
    /// Send raw text to the agent's stdin.
    SendInput { text: String },
    /// Send a nudge to the agent (custom message or default).
    Nudge { message: Option<String> },
}

/// Info about a pending permission request held in the supervisor.
struct PendingInfo {
    /// The response string to send if approved (e.g. "y").
    approve_response: String,
    /// The response string to send if denied (e.g. "n").
    deny_response: String,
}

/// Configuration for the supervisor run loop.
pub struct SupervisorConfig {
    /// Session configuration (adapter, stall, control settings).
    pub session_config: SessionConfig,
    /// The agent principal name (for Cedar policy evaluation).
    pub principal: String,
    /// Whether to pass raw PTY output to stdout (interactive mode).
    pub interactive: bool,
}

/// Run the session supervisor loop.
///
/// This is the main entry point. It blocks until the child process exits.
///
/// # Arguments
/// - `pty`: the spawned PTY session
/// - `adapter`: the agent adapter for prompt detection
/// - `engine`: the Cedar policy engine for evaluating detected actions
/// - `config`: supervisor configuration
/// - `event_tx`: optional channel for emitting session events (webhooks, logging)
/// - `output_tx`: optional channel for mirroring completed output lines
///   to another consumer without sharing the ring buffer
/// - `update_tx`: optional channel for richer TUI updates
/// - `command_rx`: optional channel for receiving commands from a caller
///
/// Returns the child's exit code and session statistics.
#[allow(clippy::too_many_arguments)]
pub fn run(
    pty: &dyn AgentSession,
    adapter: &mut dyn AgentAdapter,
    engine: &PolicyEngine,
    config: &SupervisorConfig,
    event_tx: Option<&mpsc::Sender<SessionEvent>>,
    output_tx: Option<&mpsc::SyncSender<String>>,
    update_tx: Option<&mpsc::Sender<SessionUpdate>>,
    command_rx: Option<&mpsc::Receiver<SupervisorCommand>>,
) -> Result<(i32, SessionStats), AegisError> {
    let mut output_buf = OutputBuffer::new(config.session_config.output_buffer_lines);
    let mut stall = StallDetector::new(&config.session_config.stall);
    let mut stats = SessionStats::default();
    let mut read_buf = [0u8; 8192];
    let mut pending: HashMap<Uuid, PendingInfo> = HashMap::new();
    let mut last_session_id: Option<String> = None;
    let mut attach_sent = false;

    let poll_timeout_ms = std::cmp::max(
        std::cmp::min(
            config
                .session_config
                .stall
                .timeout_secs
                .saturating_mul(1000),
            5000, // Check at least every 5 seconds
        ) as i32,
        50, // Never busy-loop: minimum 50ms poll interval
    );

    // When TUI is driving, use a shorter poll timeout for responsiveness
    let poll_timeout_ms = if update_tx.is_some() {
        std::cmp::min(poll_timeout_ms, 200)
    } else {
        poll_timeout_ms
    };

    info!(
        adapter = adapter.name(),
        principal = config.principal,
        "session supervisor started"
    );

    // Publish stream kind/session id if available at start.
    if let Some(tx) = update_tx {
        let info = SessionUpdate::SessionInfo {
            kind: pty.stream_kind(),
            session_id: pty.session_id(),
        };
        let _ = tx.send(info);
    }

    loop {
        if let Some(tx) = update_tx {
            // Attach command may become available later (e.g., after session id is known).
            if !attach_sent {
                if let Some(cmd) = pty.attach_command() {
                    let _ = tx.send(SessionUpdate::AttachCommand(cmd));
                    attach_sent = true;
                }
            }

            let current_id = pty.session_id();
            if current_id.is_some() && current_id != last_session_id {
                last_session_id = current_id.clone();
                let _ = tx.send(SessionUpdate::SessionInfo {
                    kind: pty.stream_kind(),
                    session_id: current_id,
                });
            }
        }

        // Poll for data from the PTY
        let readable = pty.poll_readable(poll_timeout_ms)?;

        if readable {
            let n = pty.read(&mut read_buf)?;
            if n == 0 {
                // Child closed the PTY (exited)
                debug!("PTY read returned 0, child likely exited");
                break;
            }

            let chunk = &read_buf[..n];

            // Pass raw bytes to stdout in interactive mode
            if config.interactive {
                let _ = std::io::stdout().write_all(chunk);
                let _ = std::io::stdout().flush();
            }

            // Check stall state before resetting, then record activity.
            let was_stalled = stall.nudge_count() > 0;
            stall.activity();
            if was_stalled {
                send_update(update_tx, SessionUpdate::StallResolved);
            }

            // Feed into output buffer, get completed lines
            let lines = output_buf.feed(chunk);
            stats.lines_processed += lines.len() as u64;

            // Scan each completed line through the adapter
            for line in &lines {
                // Mirror to an external consumer such as a UI or reporter.
                if let Some(tx) = output_tx {
                    let _ = tx.send(line.clone());
                }

                // Mirror to TUI
                send_update(update_tx, SessionUpdate::OutputLine(line.clone()));

                let result = adapter.scan_line(line);
                handle_scan_result(
                    result,
                    pty,
                    adapter,
                    engine,
                    config,
                    &mut stats,
                    &mut pending,
                    event_tx,
                    update_tx,
                )?;
            }
        }

        // Check partial line for prompts that don't end with newline
        if let Some(partial) = output_buf.peek_partial() {
            let result = adapter.scan_partial(&partial);
            if !matches!(result, ScanResult::None) {
                // Consume the partial since the adapter matched it
                output_buf.flush_partial();
                handle_scan_result(
                    result,
                    pty,
                    adapter,
                    engine,
                    config,
                    &mut stats,
                    &mut pending,
                    event_tx,
                    update_tx,
                )?;
            }
        }

        // Drain pending commands from the caller or UI.
        if let Some(rx) = command_rx {
            while let Ok(cmd) = rx.try_recv() {
                handle_command(cmd, pty, &mut stats, &mut pending, &mut stall, update_tx)?;
            }
        }

        // Check stall detection
        match stall.check() {
            StallAction::Active => {}
            StallAction::Nudge(msg) => {
                info!(
                    nudge_count = stall.nudge_count(),
                    "stall detected, sending nudge"
                );
                pty.send_line(&msg)?;
                stats.nudges += 1;
                emit(
                    event_tx,
                    SessionEvent::StallNudge {
                        nudge_count: stall.nudge_count(),
                        idle_secs: stall.timeout().as_secs(),
                    },
                );
                send_update(
                    update_tx,
                    SessionUpdate::StallNudge {
                        nudge_count: stall.nudge_count(),
                    },
                );
            }
            StallAction::MaxNudgesExceeded => {
                warn!(
                    nudge_count = stall.nudge_count(),
                    "max nudges exceeded, agent needs attention"
                );
                emit(
                    event_tx,
                    SessionEvent::AttentionNeeded {
                        nudge_count: stall.nudge_count(),
                    },
                );
                send_update(
                    update_tx,
                    SessionUpdate::AttentionNeeded {
                        nudge_count: stall.nudge_count(),
                    },
                );
            }
        }

        // Check if child is still alive
        if !pty.is_alive() {
            // Drain remaining output
            loop {
                let n = pty.read(&mut read_buf)?;
                if n == 0 {
                    break;
                }
                if config.interactive {
                    let _ = std::io::stdout().write_all(&read_buf[..n]);
                }
                let lines = output_buf.feed(&read_buf[..n]);
                for line in &lines {
                    if let Some(tx) = output_tx {
                        let _ = tx.send(line.clone());
                    }
                    send_update(update_tx, SessionUpdate::OutputLine(line.clone()));
                }
                stats.lines_processed += lines.len() as u64;
            }

            // Flush any remaining partial line (e.g. a prompt without trailing newline)
            if let Some(remaining) = output_buf.flush_partial() {
                if let Some(tx) = output_tx {
                    let _ = tx.send(remaining.clone());
                }
                send_update(update_tx, SessionUpdate::OutputLine(remaining));
                stats.lines_processed += 1;
            }
            break;
        }
    }

    let exit_code = pty.wait()?;
    info!(exit_code, "child process exited");

    emit(event_tx, SessionEvent::ChildExited { exit_code });
    send_update(update_tx, SessionUpdate::ChildExited { exit_code });
    send_update(update_tx, SessionUpdate::Stats(stats.clone()));

    Ok((exit_code, stats))
}

/// Handle a scan result from the adapter.
#[allow(clippy::too_many_arguments)]
fn handle_scan_result(
    result: ScanResult,
    pty: &dyn AgentSession,
    adapter: &mut dyn AgentAdapter,
    engine: &PolicyEngine,
    config: &SupervisorConfig,
    stats: &mut SessionStats,
    pending: &mut HashMap<Uuid, PendingInfo>,
    event_tx: Option<&mpsc::Sender<SessionEvent>>,
    update_tx: Option<&mpsc::Sender<SessionUpdate>>,
) -> Result<(), AegisError> {
    match result {
        ScanResult::None | ScanResult::Partial => {}
        ScanResult::Prompt(detection) => {
            let action = Action::new(&config.principal, detection.action.clone());
            let verdict = engine.evaluate(&action);

            info!(
                action = %detection.action,
                decision = ?verdict.decision,
                reason = verdict.reason,
                "prompt detected, policy evaluated"
            );

            match verdict.decision {
                Decision::Allow => {
                    pty.send_line(&detection.approve_response)?;
                    stats.approved += 1;
                }
                Decision::Deny => {
                    pty.send_line(&detection.deny_response)?;
                    stats.denied += 1;

                    // Brief pause so the agent reads the denial before guidance.
                    // Keep short to avoid blocking the supervisor event loop.
                    std::thread::sleep(Duration::from_millis(50));
                    let guidance = format!(
                        "[aegis] Action denied by policy: {} -- {}. Continue working on the task, but avoid this type of action.",
                        detection.action, verdict.reason
                    );
                    pty.send_line(&guidance)?;
                }
            }

            adapter.reset();

            emit(
                event_tx,
                SessionEvent::PromptDecided {
                    action: format!("{}", detection.action),
                    decision: verdict.decision.clone(),
                    reason: verdict.reason.clone(),
                },
            );
            send_update(
                update_tx,
                SessionUpdate::PromptDecided {
                    action: format!("{}", detection.action),
                    decision: verdict.decision,
                    reason: verdict.reason,
                },
            );
        }
        ScanResult::Uncertain(text) => {
            let action_taken = match config.session_config.uncertain_action {
                UncertainAction::Deny => {
                    pty.send_line("n")?;
                    stats.denied += 1;

                    std::thread::sleep(Duration::from_millis(50));
                    pty.send_line("[aegis] Action denied (unrecognized prompt, default-deny policy). Continue working on the task.")?;
                    "denied"
                }
                UncertainAction::Allow => {
                    pty.send_line("y")?;
                    stats.approved += 1;
                    "allowed"
                }
                UncertainAction::Alert => {
                    // Create a pending request for human decision
                    let request_id = Uuid::new_v4();
                    pending.insert(
                        request_id,
                        PendingInfo {
                            approve_response: "y".to_string(),
                            deny_response: "n".to_string(),
                        },
                    );
                    send_update(
                        update_tx,
                        SessionUpdate::PendingPrompt {
                            request_id,
                            raw_prompt: text.clone(),
                        },
                    );
                    "alerted"
                }
            };

            warn!(
                text = text,
                action = action_taken,
                "uncertain prompt detected"
            );
            stats.uncertain += 1;
            adapter.reset();

            emit(
                event_tx,
                SessionEvent::UncertainPrompt {
                    text,
                    action_taken: action_taken.into(),
                },
            );
        }
    }
    Ok(())
}

/// Handle a command received from the caller or UI.
fn handle_command(
    cmd: SupervisorCommand,
    pty: &dyn AgentSession,
    stats: &mut SessionStats,
    pending: &mut HashMap<Uuid, PendingInfo>,
    stall: &mut StallDetector,
    update_tx: Option<&mpsc::Sender<SessionUpdate>>,
) -> Result<(), AegisError> {
    match cmd {
        SupervisorCommand::Approve { request_id } => {
            if let Some(info) = pending.remove(&request_id) {
                pty.send_line(&info.approve_response)?;
                let was_stalled = stall.nudge_count() > 0;
                stall.activity();
                if was_stalled {
                    send_update(update_tx, SessionUpdate::StallResolved);
                }
                stats.approved += 1;
                send_update(
                    update_tx,
                    SessionUpdate::PendingResolved {
                        request_id,
                        approved: true,
                    },
                );
                info!(%request_id, "pending request approved via command");
            } else {
                warn!(%request_id, "approve for unknown request");
            }
        }
        SupervisorCommand::Deny { request_id } => {
            if let Some(info) = pending.remove(&request_id) {
                pty.send_line(&info.deny_response)?;
                let was_stalled = stall.nudge_count() > 0;
                stall.activity();
                if was_stalled {
                    send_update(update_tx, SessionUpdate::StallResolved);
                }
                stats.denied += 1;

                std::thread::sleep(Duration::from_millis(500));
                pty.send_line("[aegis] Action denied by operator. Continue working on the task.")?;

                send_update(
                    update_tx,
                    SessionUpdate::PendingResolved {
                        request_id,
                        approved: false,
                    },
                );
                info!(%request_id, "pending request denied via command");
            } else {
                warn!(%request_id, "deny for unknown request");
            }
        }
        SupervisorCommand::SendInput { text } => {
            pty.send_line(&text)?;
            let was_stalled = stall.nudge_count() > 0;
            stall.activity();
            if was_stalled {
                send_update(update_tx, SessionUpdate::StallResolved);
            }
            info!(text, "input sent to agent via command");
        }
        SupervisorCommand::Nudge { message } => {
            let msg = message.unwrap_or_else(|| "Please continue working.".to_string());
            pty.send_line(&msg)?;
            stall.activity();
            stats.nudges += 1;
            info!("nudge sent to agent via command");
        }
    }
    Ok(())
}

fn emit(tx: Option<&mpsc::Sender<SessionEvent>>, event: SessionEvent) {
    if let Some(tx) = tx {
        let _ = tx.send(event);
    }
}

fn send_update(tx: Option<&mpsc::Sender<SessionUpdate>>, update: SessionUpdate) {
    if let Some(tx) = tx {
        let _ = tx.send(update);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_stats_default() {
        let stats = SessionStats::default();
        assert_eq!(stats.approved, 0);
        assert_eq!(stats.denied, 0);
        assert_eq!(stats.uncertain, 0);
        assert_eq!(stats.nudges, 0);
        assert_eq!(stats.lines_processed, 0);
    }

    #[test]
    fn supervisor_command_send_receive() {
        let (tx, rx) = mpsc::channel();
        let id = Uuid::new_v4();

        tx.send(SupervisorCommand::Approve { request_id: id })
            .unwrap();
        tx.send(SupervisorCommand::Deny { request_id: id }).unwrap();
        tx.send(SupervisorCommand::SendInput {
            text: "hello".into(),
        })
        .unwrap();
        tx.send(SupervisorCommand::Nudge { message: None }).unwrap();

        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 4);
    }

    #[test]
    fn session_update_variants() {
        let id = Uuid::new_v4();
        let updates: Vec<SessionUpdate> = vec![
            SessionUpdate::OutputLine("hello".into()),
            SessionUpdate::PromptDecided {
                action: "FileRead".into(),
                decision: Decision::Allow,
                reason: "ok".into(),
            },
            SessionUpdate::PendingPrompt {
                request_id: id,
                raw_prompt: "Allow?".into(),
            },
            SessionUpdate::PendingResolved {
                request_id: id,
                approved: true,
            },
            SessionUpdate::StallNudge { nudge_count: 1 },
            SessionUpdate::AttentionNeeded { nudge_count: 3 },
            SessionUpdate::ChildExited { exit_code: 0 },
            SessionUpdate::Stats(SessionStats::default()),
        ];
        assert_eq!(updates.len(), 8);
    }

    #[test]
    fn pending_info_approve_deny() {
        let mut pending: HashMap<Uuid, PendingInfo> = HashMap::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        pending.insert(
            id1,
            PendingInfo {
                approve_response: "y".into(),
                deny_response: "n".into(),
            },
        );
        pending.insert(
            id2,
            PendingInfo {
                approve_response: "yes".into(),
                deny_response: "no".into(),
            },
        );

        assert_eq!(pending.len(), 2);

        let info = pending.remove(&id1).unwrap();
        assert_eq!(info.approve_response, "y");

        let info = pending.remove(&id2).unwrap();
        assert_eq!(info.deny_response, "no");

        assert!(pending.is_empty());
    }
}
