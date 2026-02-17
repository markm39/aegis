//! Main pilot supervisor loop.
//!
//! Orchestrates the PTY session, agent adapter, stall detector, and output
//! buffer into a single poll-based event loop. Evaluates detected permission
//! prompts against Cedar policy and auto-approves or denies them.

use std::io::Write;
use std::sync::mpsc;

use aegis_policy::PolicyEngine;
use aegis_types::{Action, AegisError, Decision, PilotConfig, UncertainAction};
use tracing::{debug, info, warn};

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
/// - `event_tx`: optional channel for emitting pilot events
///
/// Returns the child's exit code and session statistics.
pub fn run(
    pty: &PtySession,
    adapter: &mut dyn AgentAdapter,
    engine: &PolicyEngine,
    config: &SupervisorConfig,
    event_tx: Option<&mpsc::Sender<PilotEvent>>,
) -> Result<(i32, PilotStats), AegisError> {
    let mut output_buf = OutputBuffer::new(config.pilot_config.output_buffer_lines);
    let mut stall = StallDetector::new(&config.pilot_config.stall);
    let mut stats = PilotStats::default();
    let mut read_buf = [0u8; 8192];

    let poll_timeout_ms = std::cmp::min(
        config.pilot_config.stall.timeout_secs * 1000,
        5000, // Check at least every 5 seconds
    ) as i32;

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

            // Record activity for stall detection
            stall.activity();

            // Feed into output buffer, get completed lines
            let lines = output_buf.feed(chunk);
            stats.lines_processed += lines.len() as u64;

            // Scan each completed line through the adapter
            for line in &lines {
                let result = adapter.scan_line(line);
                handle_scan_result(
                    result,
                    pty,
                    adapter,
                    engine,
                    config,
                    &mut stats,
                    event_tx,
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
                    event_tx,
                )?;
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
            }
            StallAction::MaxNudgesExceeded => {
                warn!(
                    nudge_count = stall.nudge_count(),
                    "max nudges exceeded, agent needs attention"
                );
                emit(event_tx, PilotEvent::AttentionNeeded {
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
                stats.lines_processed += lines.len() as u64;
            }
            break;
        }
    }

    let exit_code = pty.wait()?;
    info!(exit_code, "child process exited");

    emit(event_tx, PilotEvent::ChildExited { exit_code });

    Ok((exit_code, stats))
}

/// Handle a scan result from the adapter.
fn handle_scan_result(
    result: ScanResult,
    pty: &PtySession,
    adapter: &mut dyn AgentAdapter,
    engine: &PolicyEngine,
    config: &SupervisorConfig,
    stats: &mut PilotStats,
    event_tx: Option<&mpsc::Sender<PilotEvent>>,
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
                }
            }

            adapter.reset();

            emit(event_tx, PilotEvent::PromptDecided {
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
                    "denied"
                }
                UncertainAction::Allow => {
                    pty.send_line("y")?;
                    stats.approved += 1;
                    "allowed"
                }
                UncertainAction::Alert => {
                    // Don't respond -- wait for external input
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

fn emit(tx: Option<&mpsc::Sender<PilotEvent>>, event: PilotEvent) {
    if let Some(tx) = tx {
        let _ = tx.send(event);
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
}
