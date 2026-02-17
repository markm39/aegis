//! Agent slot: runtime state for a single supervised agent.
//!
//! Each agent in the fleet gets an `AgentSlot` that tracks its configuration,
//! status, restart count, thread handle, and recent output. The fleet manager
//! uses slots to monitor agent health and apply restart policies.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use aegis_types::daemon::{AgentSlotConfig, AgentStatus};

use crate::lifecycle::SlotResult;

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
}
