//! Main pilot supervisor loop.
//!
//! Orchestrates the PTY session, agent adapter, stall detector, and output
//! buffer into a single poll-based event loop. Evaluates detected permission
//! prompts against Cedar policy and auto-approves or denies them.
//!
//! The supervisor communicates with external consumers through three optional
//! channels:
//! - `event_tx`: lightweight [`PilotEvent`] for webhooks and logging
//! - `update_tx`: richer [`PilotUpdate`] for the TUI (includes output lines)
//! - `command_rx`: [`SupervisorCommand`] for receiving approve/deny/input/nudge

use std::collections::HashMap;
use std::io::Write;
use std::sync::mpsc;
use std::time::Duration;

use aegis_policy::PolicyEngine;
use aegis_types::{Action, AegisError, Decision, PilotConfig, UncertainAction};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::adapter::{AgentAdapter, ScanResult};
use crate::output::OutputBuffer;
use crate::pty::PtySession;
use crate::stall::{StallAction, StallDetector};

/// Statistics collected during a pilot session.
#[derive(Debug, Clone, Default)]
pub struct PilotStats {
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
pub enum PilotEvent {
    /// A permission prompt was detected and auto-decided.
    PromptDecided {
        action: String,
        decision: Decision,
        reason: String,
    },
    /// A stall was detected and a nudge was sent.
    StallNudge {
        nudge_count: u32,
        idle_secs: u64,
    },
    /// Max nudges exceeded; agent needs human attention.
    AttentionNeeded {
        nudge_count: u32,
    },
    /// An uncertain prompt was encountered.
    UncertainPrompt {
        text: String,
        action_taken: String,
    },
    /// The child process exited.
    ChildExited {
        exit_code: i32,
    },
}

/// Richer event type for the TUI, including output lines and pending prompts.
///
/// Unlike [`PilotEvent`] (which is for external logging), `PilotUpdate` carries
/// all the information the TUI needs to render the live session.
#[derive(Debug, Clone)]
pub enum PilotUpdate {
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
    PendingResolved {
        request_id: Uuid,
        approved: bool,
    },
    /// A stall nudge was sent.
    StallNudge {
        nudge_count: u32,
    },
    /// Max nudges exceeded; agent needs human attention.
    AttentionNeeded {
        nudge_count: u32,
    },
    /// Agent resumed output after being stalled; attention no longer needed.
    StallResolved,
    /// The child process exited.
    ChildExited {
        exit_code: i32,
    },
    /// Periodic stats snapshot.
    Stats(PilotStats),
}

/// Commands sent to the supervisor from the TUI or control plane.
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
    /// Pilot configuration (adapter, stall, control settings).
    pub pilot_config: PilotConfig,
    /// The agent principal name (for Cedar policy evaluation).
    pub principal: String,
    /// Whether to pass raw PTY output to stdout (interactive mode).
    pub interactive: bool,
}

/// Run the pilot supervisor loop.
///
/// This is the main entry point. It blocks until the child process exits.
///
/// # Arguments
/// - `pty`: the spawned PTY session
/// - `adapter`: the agent adapter for prompt detection
/// - `engine`: the Cedar policy engine for evaluating detected actions
/// - `config`: supervisor configuration
/// - `event_tx`: optional channel for emitting pilot events (webhooks, logging)
/// - `output_tx`: optional channel for mirroring completed output lines
///   (used by the daemon to expose agent output without sharing the buffer)
/// - `update_tx`: optional channel for richer TUI updates
/// - `command_rx`: optional channel for receiving commands from TUI/control plane
///
/// Returns the child's exit code and session statistics.
#[allow(clippy::too_many_arguments)]
pub fn run(
    pty: &PtySession,
    adapter: &mut dyn AgentAdapter,
    engine: &PolicyEngine,
    config: &SupervisorConfig,
    event_tx: Option<&mpsc::Sender<PilotEvent>>,
    output_tx: Option<&mpsc::Sender<String>>,
    update_tx: Option<&mpsc::Sender<PilotUpdate>>,
    command_rx: Option<&mpsc::Receiver<SupervisorCommand>>,
) -> Result<(i32, PilotStats), AegisError> {
    let mut output_buf = OutputBuffer::new(config.pilot_config.output_buffer_lines);
    let mut stall = StallDetector::new(&config.pilot_config.stall);
    let mut stats = PilotStats::default();
    let mut read_buf = [0u8; 8192];
    let mut pending: HashMap<Uuid, PendingInfo> = HashMap::new();

    let poll_timeout_ms = std::cmp::max(
        std::cmp::min(
            config.pilot_config.stall.timeout_secs.saturating_mul(1000),
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
        "pilot supervisor started"
    );

    loop {
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
                send_update(update_tx, PilotUpdate::StallResolved);
            }

            // Feed into output buffer, get completed lines
            let lines = output_buf.feed(chunk);
            stats.lines_processed += lines.len() as u64;

            // Scan each completed line through the adapter
            for line in &lines {
                // Mirror to external consumer (daemon fleet manager)
                if let Some(tx) = output_tx {
                    let _ = tx.send(line.clone());
                }

                // Mirror to TUI
                send_update(update_tx, PilotUpdate::OutputLine(line.clone()));

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

        // Drain pending commands from the TUI or control plane
        if let Some(rx) = command_rx {
            while let Ok(cmd) = rx.try_recv() {
                handle_command(cmd, pty, &mut stats, &mut pending, &mut stall, update_tx)?;
            }
        }

        // Check stall detection
        match stall.check() {
            StallAction::Active => {}
            StallAction::Nudge(msg) => {
                info!(nudge_count = stall.nudge_count(), "stall detected, sending nudge");
                pty.send_line(&msg)?;
                stats.nudges += 1;
                emit(event_tx, PilotEvent::StallNudge {
                    nudge_count: stall.nudge_count(),
                    idle_secs: stall.timeout().as_secs(),
                });
                send_update(update_tx, PilotUpdate::StallNudge {
                    nudge_count: stall.nudge_count(),
                });
            }
            StallAction::MaxNudgesExceeded => {
                warn!(
                    nudge_count = stall.nudge_count(),
                    "max nudges exceeded, agent needs attention"
                );
                emit(event_tx, PilotEvent::AttentionNeeded {
                    nudge_count: stall.nudge_count(),
                });
                send_update(update_tx, PilotUpdate::AttentionNeeded {
                    nudge_count: stall.nudge_count(),
                });
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
                    send_update(update_tx, PilotUpdate::OutputLine(line.clone()));
                }
                stats.lines_processed += lines.len() as u64;
            }

            // Flush any remaining partial line (e.g. a prompt without trailing newline)
            if let Some(remaining) = output_buf.flush_partial() {
                if let Some(tx) = output_tx {
                    let _ = tx.send(remaining.clone());
                }
                send_update(update_tx, PilotUpdate::OutputLine(remaining));
                stats.lines_processed += 1;
            }
            break;
        }
    }

    let exit_code = pty.wait()?;
    info!(exit_code, "child process exited");

    emit(event_tx, PilotEvent::ChildExited { exit_code });
    send_update(update_tx, PilotUpdate::ChildExited { exit_code });
    send_update(update_tx, PilotUpdate::Stats(stats.clone()));

    Ok((exit_code, stats))
}

/// Handle a scan result from the adapter.
#[allow(clippy::too_many_arguments)]
fn handle_scan_result(
    result: ScanResult,
    pty: &PtySession,
    adapter: &mut dyn AgentAdapter,
    engine: &PolicyEngine,
    config: &SupervisorConfig,
    stats: &mut PilotStats,
    pending: &mut HashMap<Uuid, PendingInfo>,
    event_tx: Option<&mpsc::Sender<PilotEvent>>,
    update_tx: Option<&mpsc::Sender<PilotUpdate>>,
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

                    // Brief delay, then tell the agent why so it can adjust
                    std::thread::sleep(Duration::from_millis(500));
                    let guidance = format!(
                        "[aegis] Action denied by policy: {} -- {}. Continue working on the task, but avoid this type of action.",
                        detection.action, verdict.reason
                    );
                    pty.send_line(&guidance)?;
                }
            }

            adapter.reset();

            emit(event_tx, PilotEvent::PromptDecided {
                action: format!("{}", detection.action),
                decision: verdict.decision.clone(),
                reason: verdict.reason.clone(),
            });
            send_update(update_tx, PilotUpdate::PromptDecided {
                action: format!("{}", detection.action),
                decision: verdict.decision,
                reason: verdict.reason,
            });
        }
        ScanResult::Uncertain(text) => {
            let action_taken = match config.pilot_config.uncertain_action {
                UncertainAction::Deny => {
                    pty.send_line("n")?;
                    stats.denied += 1;

                    std::thread::sleep(Duration::from_millis(500));
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
                    pending.insert(request_id, PendingInfo {
                        approve_response: "y".to_string(),
                        deny_response: "n".to_string(),
                    });
                    send_update(update_tx, PilotUpdate::PendingPrompt {
                        request_id,
                        raw_prompt: text.clone(),
                    });
                    "alerted"
                }
            };

            warn!(text = text, action = action_taken, "uncertain prompt detected");
            stats.uncertain += 1;
            adapter.reset();

            emit(event_tx, PilotEvent::UncertainPrompt {
                text,
                action_taken: action_taken.into(),
            });
        }
    }
    Ok(())
}

/// Handle a command received from the TUI or control plane.
fn handle_command(
    cmd: SupervisorCommand,
    pty: &PtySession,
    stats: &mut PilotStats,
    pending: &mut HashMap<Uuid, PendingInfo>,
    stall: &mut StallDetector,
    update_tx: Option<&mpsc::Sender<PilotUpdate>>,
) -> Result<(), AegisError> {
    match cmd {
        SupervisorCommand::Approve { request_id } => {
            if let Some(info) = pending.remove(&request_id) {
                pty.send_line(&info.approve_response)?;
                stall.activity();
                stats.approved += 1;
                send_update(update_tx, PilotUpdate::PendingResolved {
                    request_id,
                    approved: true,
                });
                info!(%request_id, "pending request approved via command");
            } else {
                warn!(%request_id, "approve for unknown request");
            }
        }
        SupervisorCommand::Deny { request_id } => {
            if let Some(info) = pending.remove(&request_id) {
                pty.send_line(&info.deny_response)?;
                stall.activity();
                stats.denied += 1;

                std::thread::sleep(Duration::from_millis(500));
                pty.send_line("[aegis] Action denied by operator. Continue working on the task.")?;

                send_update(update_tx, PilotUpdate::PendingResolved {
                    request_id,
                    approved: false,
                });
                info!(%request_id, "pending request denied via command");
            } else {
                warn!(%request_id, "deny for unknown request");
            }
        }
        SupervisorCommand::SendInput { text } => {
            pty.send_line(&text)?;
            stall.activity();
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

fn emit(tx: Option<&mpsc::Sender<PilotEvent>>, event: PilotEvent) {
    if let Some(tx) = tx {
        let _ = tx.send(event);
    }
}

fn send_update(tx: Option<&mpsc::Sender<PilotUpdate>>, update: PilotUpdate) {
    if let Some(tx) = tx {
        let _ = tx.send(update);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pilot_stats_default() {
        let stats = PilotStats::default();
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

        tx.send(SupervisorCommand::Approve { request_id: id }).unwrap();
        tx.send(SupervisorCommand::Deny { request_id: id }).unwrap();
        tx.send(SupervisorCommand::SendInput { text: "hello".into() }).unwrap();
        tx.send(SupervisorCommand::Nudge { message: None }).unwrap();

        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 4);
    }

    #[test]
    fn pilot_update_variants() {
        let id = Uuid::new_v4();
        let updates: Vec<PilotUpdate> = vec![
            PilotUpdate::OutputLine("hello".into()),
            PilotUpdate::PromptDecided {
                action: "FileRead".into(),
                decision: Decision::Allow,
                reason: "ok".into(),
            },
            PilotUpdate::PendingPrompt {
                request_id: id,
                raw_prompt: "Allow?".into(),
            },
            PilotUpdate::PendingResolved {
                request_id: id,
                approved: true,
            },
            PilotUpdate::StallNudge { nudge_count: 1 },
            PilotUpdate::AttentionNeeded { nudge_count: 3 },
            PilotUpdate::ChildExited { exit_code: 0 },
            PilotUpdate::Stats(PilotStats::default()),
        ];
        assert_eq!(updates.len(), 8);
    }

    #[test]
    fn pending_info_approve_deny() {
        let mut pending: HashMap<Uuid, PendingInfo> = HashMap::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        pending.insert(id1, PendingInfo {
            approve_response: "y".into(),
            deny_response: "n".into(),
        });
        pending.insert(id2, PendingInfo {
            approve_response: "yes".into(),
            deny_response: "no".into(),
        });

        assert_eq!(pending.len(), 2);

        let info = pending.remove(&id1).unwrap();
        assert_eq!(info.approve_response, "y");

        let info = pending.remove(&id2).unwrap();
        assert_eq!(info.deny_response, "no");

        assert!(pending.is_empty());
    }
}
