//! Agent slot: runtime state for a single supervised agent.
//!
//! Each agent in the fleet gets an `AgentSlot` that tracks its configuration,
//! status, restart count, thread handle, and recent output. The fleet manager
//! uses slots to monitor agent health and apply restart policies.

use std::collections::VecDeque;
use std::sync::atomic::AtomicU32;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use uuid::Uuid;

use aegis_pilot::supervisor::{PilotStats, PilotUpdate, SupervisorCommand};
use aegis_types::daemon::{AgentSlotConfig, AgentStatus};

use crate::lifecycle::SlotResult;

/// Information about a pending permission prompt awaiting human decision.
#[derive(Debug, Clone)]
pub struct PendingPromptInfo {
    /// Unique ID for this pending request (matches the supervisor's request_id).
    pub request_id: Uuid,
    /// The raw prompt text shown by the agent tool.
    pub raw_prompt: String,
    /// When this prompt was received.
    pub received_at: Instant,
}

/// Events from `drain_updates()` that should be forwarded to the notification
/// channel (Telegram). These represent the subset of `PilotUpdate` events that
/// are worth notifying the user about when they're away from the terminal.
#[derive(Debug)]
pub enum NotableEvent {
    /// A permission prompt needs human approval.
    PendingPrompt { request_id: Uuid, raw_prompt: String },
    /// Agent is stalled and needs human attention (max nudges exceeded).
    AttentionNeeded { nudge_count: u32 },
    /// A stall nudge was sent.
    StallNudge { nudge_count: u32 },
    /// The agent process exited.
    ChildExited { exit_code: i32 },
}

/// Runtime state for a single supervised agent in the fleet.
pub struct AgentSlot {
    /// Configuration for this slot.
    pub config: AgentSlotConfig,
    /// Current status.
    pub status: AgentStatus,
    /// Number of times this agent has been restarted.
    pub restart_count: u32,
    /// When the current run started (None if not running).
    pub started_at: Option<Instant>,
    /// Thread handle for the agent's lifecycle thread.
    pub thread_handle: Option<JoinHandle<SlotResult>>,
    /// Receiver for output lines from the supervisor.
    pub output_rx: Option<mpsc::Receiver<String>>,
    /// Recent output lines (bounded ring buffer).
    pub recent_output: Arc<Mutex<VecDeque<String>>>,
    /// Max output lines to retain.
    pub output_capacity: usize,
    /// Sender for commands to the supervisor (approve, deny, input, nudge).
    pub command_tx: Option<mpsc::Sender<SupervisorCommand>>,
    /// Receiver for rich updates from the supervisor (pending prompts, stats, etc.).
    pub update_rx: Option<mpsc::Receiver<PilotUpdate>>,
    /// Currently pending permission prompts awaiting human decision.
    pub pending_prompts: Vec<PendingPromptInfo>,
    /// Latest pilot stats snapshot from the supervisor.
    pub pilot_stats: Option<PilotStats>,
    /// Whether this agent needs human attention (max nudges exceeded).
    pub attention_needed: bool,
    /// Whether attention was triggered by stall detection (vs pending prompts).
    /// Prevents PendingResolved from clearing stall-based attention.
    pub stall_attention: bool,
    /// If set, the agent is in backoff and should not be restarted until this
    /// instant. Used to prevent crash loops from spinning hot.
    pub backoff_until: Option<Instant>,
    /// Shared child PID. The lifecycle thread writes this after spawning the
    /// PTY so that `stop_agent()` can send SIGTERM without blocking on join.
    /// A value of 0 means the child hasn't been spawned yet.
    pub child_pid: Arc<AtomicU32>,
    /// Shared audit session ID. The lifecycle thread writes this after starting
    /// the audit session so that state persistence can record it for crash recovery.
    pub session_id: Arc<Mutex<Option<uuid::Uuid>>>,
}

impl AgentSlot {
    /// Create a new slot from configuration.
    pub fn new(config: AgentSlotConfig) -> Self {
        let status = if config.enabled {
            AgentStatus::Pending
        } else {
            AgentStatus::Disabled
        };

        Self {
            config,
            status,
            restart_count: 0,
            started_at: None,
            thread_handle: None,
            output_rx: None,
            recent_output: Arc::new(Mutex::new(VecDeque::with_capacity(500))),
            output_capacity: 500,
            command_tx: None,
            update_rx: None,
            pending_prompts: Vec::new(),
            pilot_stats: None,
            attention_needed: false,
            stall_attention: false,
            backoff_until: None,
            child_pid: Arc::new(AtomicU32::new(0)),
            session_id: Arc::new(Mutex::new(None)),
        }
    }

    /// The slot's unique name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Whether the agent thread is still running.
    pub fn is_thread_alive(&self) -> bool {
        self.thread_handle
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    }

    /// Drain new output lines from the channel into the recent_output buffer.
    ///
    /// Returns the number of new lines drained.
    pub fn drain_output(&self) -> usize {
        let rx = match &self.output_rx {
            Some(rx) => rx,
            None => return 0,
        };

        let mut buf = match self.recent_output.lock() {
            Ok(buf) => buf,
            Err(_) => return 0,
        };

        let mut count = 0;
        while let Ok(line) = rx.try_recv() {
            if buf.len() >= self.output_capacity {
                buf.pop_front();
            }
            buf.push_back(line);
            count += 1;
        }
        count
    }

    /// Drain rich updates from the supervisor's update channel.
    ///
    /// Processes all pending `PilotUpdate` events:
    /// - `PendingPrompt`: adds to the pending prompts list
    /// - `PendingResolved`: removes from pending prompts
    /// - `AttentionNeeded`: sets the attention flag
    /// - `Stats`: updates the latest stats snapshot
    /// - Other variants are ignored (output is handled by `drain_output`)
    ///
    /// Returns notable events that should be forwarded to the notification
    /// channel (Telegram, etc.). The caller is responsible for converting
    /// these into outbound channel messages.
    pub fn drain_updates(&mut self) -> Vec<NotableEvent> {
        let rx = match &self.update_rx {
            Some(rx) => rx,
            None => return Vec::new(),
        };

        let mut notable = Vec::new();
        while let Ok(update) = rx.try_recv() {
            match update {
                PilotUpdate::PendingPrompt { request_id, raw_prompt } => {
                    self.pending_prompts.push(PendingPromptInfo {
                        request_id,
                        raw_prompt: raw_prompt.clone(),
                        received_at: Instant::now(),
                    });
                    notable.push(NotableEvent::PendingPrompt { request_id, raw_prompt });
                }
                PilotUpdate::PendingResolved { request_id, .. } => {
                    self.pending_prompts.retain(|p| p.request_id != request_id);
                    // Clear attention only if no more pending AND not stall-based
                    if self.pending_prompts.is_empty() && !self.stall_attention {
                        self.attention_needed = false;
                    }
                }
                PilotUpdate::AttentionNeeded { nudge_count } => {
                    self.attention_needed = true;
                    self.stall_attention = true;
                    notable.push(NotableEvent::AttentionNeeded { nudge_count });
                }
                PilotUpdate::StallNudge { nudge_count } => {
                    notable.push(NotableEvent::StallNudge { nudge_count });
                }
                PilotUpdate::StallResolved => {
                    self.stall_attention = false;
                    if self.pending_prompts.is_empty() {
                        self.attention_needed = false;
                    }
                }
                PilotUpdate::ChildExited { exit_code } => {
                    notable.push(NotableEvent::ChildExited { exit_code });
                }
                PilotUpdate::Stats(stats) => {
                    self.pilot_stats = Some(stats);
                }
                // OutputLine, PromptDecided are handled elsewhere
                _ => {}
            }
        }
        notable
    }

    /// Get the most recent N output lines.
    pub fn get_recent_output(&self, n: usize) -> Vec<String> {
        let buf = match self.recent_output.lock() {
            Ok(buf) => buf,
            Err(_) => return vec![],
        };

        buf.iter().rev().take(n).rev().cloned().collect()
    }

    /// Uptime in seconds (None if not running).
    pub fn uptime_secs(&self) -> Option<u64> {
        self.started_at.map(|t| t.elapsed().as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_pilot::supervisor::PilotStats;
    use aegis_types::daemon::{AgentToolConfig, RestartPolicy};
    use std::path::PathBuf;

    fn test_config(name: &str) -> AgentSlotConfig {
        AgentSlotConfig {
            name: name.to_string(),
            tool: AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: vec![],
            },
            working_dir: PathBuf::from("/tmp"),
            role: None,
            agent_goal: None,
            context: None,
            task: None,
            pilot: None,
            restart: RestartPolicy::OnFailure,
            max_restarts: 5,
            enabled: true,
        }
    }

    #[test]
    fn new_slot_is_pending_when_enabled() {
        let slot = AgentSlot::new(test_config("test"));
        assert_eq!(slot.status, AgentStatus::Pending);
        assert_eq!(slot.restart_count, 0);
        assert!(slot.started_at.is_none());
    }

    #[test]
    fn new_slot_is_disabled_when_not_enabled() {
        let mut config = test_config("test");
        config.enabled = false;
        let slot = AgentSlot::new(config);
        assert_eq!(slot.status, AgentStatus::Disabled);
    }

    #[test]
    fn drain_output_from_channel() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.output_rx = Some(rx);

        tx.send("line 1".into()).unwrap();
        tx.send("line 2".into()).unwrap();
        tx.send("line 3".into()).unwrap();

        let count = slot.drain_output();
        assert_eq!(count, 3);

        let lines = slot.get_recent_output(10);
        assert_eq!(lines, vec!["line 1", "line 2", "line 3"]);
    }

    #[test]
    fn output_respects_capacity() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.output_rx = Some(rx);
        slot.output_capacity = 3;

        for i in 0..5 {
            tx.send(format!("line {i}")).unwrap();
        }

        slot.drain_output();
        let lines = slot.get_recent_output(10);
        assert_eq!(lines, vec!["line 2", "line 3", "line 4"]);
    }

    #[test]
    fn no_thread_means_not_alive() {
        let slot = AgentSlot::new(test_config("test"));
        assert!(!slot.is_thread_alive());
    }

    #[test]
    fn uptime_none_when_not_started() {
        let slot = AgentSlot::new(test_config("test"));
        assert!(slot.uptime_secs().is_none());
    }

    #[test]
    fn drain_updates_pending_prompt() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        let id = Uuid::new_v4();
        tx.send(PilotUpdate::PendingPrompt {
            request_id: id,
            raw_prompt: "Allow Bash(rm -rf)?".into(),
        }).unwrap();

        let events = slot.drain_updates();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], NotableEvent::PendingPrompt { .. }));
        assert_eq!(slot.pending_prompts.len(), 1);
        assert_eq!(slot.pending_prompts[0].request_id, id);
        assert_eq!(slot.pending_prompts[0].raw_prompt, "Allow Bash(rm -rf)?");
    }

    #[test]
    fn drain_updates_pending_resolved() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        let id = Uuid::new_v4();
        tx.send(PilotUpdate::PendingPrompt {
            request_id: id,
            raw_prompt: "Allow write?".into(),
        }).unwrap();
        tx.send(PilotUpdate::PendingResolved {
            request_id: id,
            approved: true,
        }).unwrap();

        slot.drain_updates();
        assert!(slot.pending_prompts.is_empty());
    }

    #[test]
    fn drain_updates_attention_needed() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        assert!(!slot.attention_needed);
        tx.send(PilotUpdate::AttentionNeeded { nudge_count: 3 }).unwrap();

        let events = slot.drain_updates();
        assert!(slot.attention_needed);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], NotableEvent::AttentionNeeded { nudge_count: 3 }));
    }

    #[test]
    fn drain_updates_stats() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        let stats = PilotStats {
            approved: 5,
            denied: 2,
            uncertain: 1,
            nudges: 0,
            lines_processed: 100,
        };
        tx.send(PilotUpdate::Stats(stats)).unwrap();

        let events = slot.drain_updates();
        assert!(events.is_empty()); // Stats are not notable events
        let s = slot.pilot_stats.unwrap();
        assert_eq!(s.approved, 5);
        assert_eq!(s.denied, 2);
        assert_eq!(s.lines_processed, 100);
    }

    #[test]
    fn drain_updates_no_channel_returns_empty() {
        let mut slot = AgentSlot::new(test_config("test"));
        assert!(slot.drain_updates().is_empty());
    }

    #[test]
    fn drain_updates_child_exited_is_notable() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        tx.send(PilotUpdate::ChildExited { exit_code: 0 }).unwrap();

        let events = slot.drain_updates();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], NotableEvent::ChildExited { exit_code: 0 }));
    }

    #[test]
    fn drain_updates_stall_nudge_is_notable() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        tx.send(PilotUpdate::StallNudge { nudge_count: 2 }).unwrap();

        let events = slot.drain_updates();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], NotableEvent::StallNudge { nudge_count: 2 }));
    }

    #[test]
    fn attention_clears_when_prompts_resolved_no_stall() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        // Set attention via pending prompt only (no stall)
        let id = Uuid::new_v4();
        tx.send(PilotUpdate::PendingPrompt {
            request_id: id,
            raw_prompt: "prompt".into(),
        }).unwrap();
        slot.drain_updates();
        slot.attention_needed = true; // set by pending

        tx.send(PilotUpdate::PendingResolved {
            request_id: id,
            approved: true,
        }).unwrap();
        slot.drain_updates();
        assert!(!slot.attention_needed);
        assert!(slot.pending_prompts.is_empty());
    }

    #[test]
    fn stall_attention_persists_after_prompt_resolved() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        let id = Uuid::new_v4();
        tx.send(PilotUpdate::PendingPrompt {
            request_id: id,
            raw_prompt: "prompt".into(),
        }).unwrap();
        tx.send(PilotUpdate::AttentionNeeded { nudge_count: 3 }).unwrap();
        slot.drain_updates();
        assert!(slot.attention_needed);
        assert!(slot.stall_attention);

        // Resolving pending should NOT clear attention because stall caused it
        tx.send(PilotUpdate::PendingResolved {
            request_id: id,
            approved: true,
        }).unwrap();
        slot.drain_updates();
        assert!(slot.attention_needed, "stall-based attention should persist");
        assert!(slot.pending_prompts.is_empty());
    }

    #[test]
    fn stall_resolved_clears_attention() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        // Stall sets attention
        tx.send(PilotUpdate::AttentionNeeded { nudge_count: 3 }).unwrap();
        slot.drain_updates();
        assert!(slot.attention_needed);
        assert!(slot.stall_attention);

        // Agent resumes output -> stall resolved
        tx.send(PilotUpdate::StallResolved).unwrap();
        slot.drain_updates();
        assert!(!slot.stall_attention);
        assert!(!slot.attention_needed);
    }

    #[test]
    fn stall_resolved_keeps_attention_if_pending_prompts() {
        let (tx, rx) = mpsc::channel();
        let mut slot = AgentSlot::new(test_config("test"));
        slot.update_rx = Some(rx);

        // Pending prompt + stall both set attention
        let id = Uuid::new_v4();
        tx.send(PilotUpdate::PendingPrompt {
            request_id: id,
            raw_prompt: "Allow write?".into(),
        }).unwrap();
        tx.send(PilotUpdate::AttentionNeeded { nudge_count: 3 }).unwrap();
        slot.drain_updates();
        assert!(slot.attention_needed);
        assert!(slot.stall_attention);
        assert_eq!(slot.pending_prompts.len(), 1);

        // Stall resolved, but pending prompt remains
        tx.send(PilotUpdate::StallResolved).unwrap();
        slot.drain_updates();
        assert!(!slot.stall_attention);
        assert!(slot.attention_needed, "pending prompt still needs attention");
    }
}
