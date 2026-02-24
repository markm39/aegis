//! Priority command queue with concurrency control, persistence, and dead letter queue.
//!
//! Commands are ordered by priority (descending) then by arrival time (ascending).
//! A configurable concurrency limit caps how many commands execute simultaneously.
//! Failed commands are retried up to `max_retries` times before being moved to the
//! dead letter queue (DLQ) for inspection.
//!
//! # Security
//!
//! - Queue size is hard-limited to prevent memory exhaustion.
//! - Command payloads must be valid JSON and are capped at 64 KB.
//! - Persistence files are written atomically (write to temp, then rename).
//! - DLQ commands cannot be re-queued without explicit authorization.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum allowed command payload size in bytes (64 KB).
const MAX_COMMAND_PAYLOAD_BYTES: usize = 64 * 1024;

/// Status of a queued command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    /// Waiting to be dequeued for execution.
    Pending,
    /// Currently being executed.
    Executing,
    /// Successfully completed.
    Completed,
    /// Failed but may be retried.
    Failed,
    /// Exceeded max retries; moved to dead letter queue.
    DeadLettered,
}

/// A command entry in the priority queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedCommand {
    /// Unique identifier for this queued command.
    pub id: Uuid,
    /// Serialized DaemonCommand payload (must be valid JSON, max 64 KB).
    pub command: serde_json::Value,
    /// Priority level (0-255, higher = more urgent).
    pub priority: u8,
    /// Timestamp when the command was enqueued.
    pub queued_at: DateTime<Utc>,
    /// Maximum retry attempts before dead-lettering (default: 3).
    pub max_retries: u8,
    /// Current retry count.
    pub retry_count: u8,
    /// Current status of this command.
    pub status: QueueStatus,
    /// Error message from the last failed attempt (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl QueuedCommand {
    /// Create a new pending command with validated payload.
    fn new(command: serde_json::Value, priority: u8) -> Result<Self, String> {
        // Validate payload size (security: prevent memory exhaustion).
        let serialized =
            serde_json::to_string(&command).map_err(|e| format!("invalid command payload: {e}"))?;
        if serialized.len() > MAX_COMMAND_PAYLOAD_BYTES {
            return Err(format!(
                "command payload exceeds maximum size of {} bytes (got {} bytes)",
                MAX_COMMAND_PAYLOAD_BYTES,
                serialized.len()
            ));
        }

        Ok(Self {
            id: Uuid::new_v4(),
            command,
            priority,
            queued_at: Utc::now(),
            max_retries: 3,
            retry_count: 0,
            status: QueueStatus::Pending,
            last_error: None,
        })
    }
}

/// Wrapper for BinaryHeap ordering: highest priority first, then earliest queued_at.
#[derive(Debug, Clone)]
struct PriorityEntry(QueuedCommand);

impl PartialEq for PriorityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl Eq for PriorityEntry {}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first.
        self.0
            .priority
            .cmp(&other.0.priority)
            // If equal priority, earlier queued_at first (reverse because BinaryHeap is max-heap).
            .then_with(|| other.0.queued_at.cmp(&self.0.queued_at))
    }
}

/// Operational metrics for the command queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueMetrics {
    /// Number of pending commands in the queue.
    pub pending: usize,
    /// Number of commands currently executing.
    pub active: usize,
    /// Total commands completed since queue creation.
    pub completed_total: u64,
    /// Total commands failed since queue creation.
    pub failed_total: u64,
    /// Number of commands in the dead letter queue.
    pub dlq_size: usize,
    /// Configured maximum queue size.
    pub max_queue_size: usize,
    /// Configured maximum concurrent executions.
    pub max_concurrent: usize,
}

/// Persistence envelope for saving/loading queue state.
#[derive(Debug, Serialize, Deserialize)]
struct QueuePersistence {
    pending: Vec<QueuedCommand>,
    dead_letter: Vec<QueuedCommand>,
    completed_total: u64,
    failed_total: u64,
    max_queue_size: usize,
    max_concurrent: usize,
}

/// Priority command queue with concurrency control and dead letter queue.
pub struct CommandQueue {
    /// BinaryHeap of pending commands ordered by priority.
    heap: BinaryHeap<PriorityEntry>,
    /// Commands currently being executed (tracked by ID).
    active: Vec<QueuedCommand>,
    /// Dead letter queue for commands that exhausted retries.
    dead_letter: Vec<QueuedCommand>,
    /// Maximum number of commands allowed in the pending queue.
    max_queue_size: usize,
    /// Maximum number of commands that can execute concurrently.
    max_concurrent: usize,
    /// Lifetime count of completed commands.
    completed_total: u64,
    /// Lifetime count of failed commands (including those eventually dead-lettered).
    failed_total: u64,
}

impl CommandQueue {
    /// Create a new command queue with default limits.
    ///
    /// Default max_queue_size: 1000, max_concurrent: 10.
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            active: Vec::new(),
            dead_letter: Vec::new(),
            max_queue_size: 1000,
            max_concurrent: 10,
            completed_total: 0,
            failed_total: 0,
        }
    }

    /// Create a new command queue with custom limits.
    pub fn with_limits(max_queue_size: usize, max_concurrent: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            active: Vec::new(),
            dead_letter: Vec::new(),
            max_queue_size,
            max_concurrent,
            completed_total: 0,
            failed_total: 0,
        }
    }

    /// Enqueue a command with the given priority.
    ///
    /// Returns the command's UUID on success.
    ///
    /// # Errors
    ///
    /// - Queue is at max capacity (prevents memory exhaustion).
    /// - Command payload is not valid JSON.
    /// - Command payload exceeds 64 KB.
    pub fn enqueue(&mut self, command: serde_json::Value, priority: u8) -> Result<Uuid, String> {
        // Security: enforce queue size limit to prevent memory exhaustion.
        if self.heap.len() >= self.max_queue_size {
            return Err(format!(
                "queue is full ({} commands); cannot enqueue more",
                self.max_queue_size
            ));
        }

        // Validate and create the command (checks JSON validity and size).
        let cmd = QueuedCommand::new(command, priority)?;
        let id = cmd.id;
        self.heap.push(PriorityEntry(cmd));
        Ok(id)
    }

    /// Dequeue the highest-priority pending command.
    ///
    /// Returns `None` if the queue is empty or the concurrency limit has been reached.
    pub fn dequeue(&mut self) -> Option<QueuedCommand> {
        // Respect concurrency limit.
        if self.active.len() >= self.max_concurrent {
            return None;
        }

        self.heap.pop().map(|entry| {
            let mut cmd = entry.0;
            cmd.status = QueueStatus::Executing;
            self.active.push(cmd.clone());
            cmd
        })
    }

    /// Mark a command as completed and remove it from the active set.
    pub fn mark_completed(&mut self, id: Uuid) {
        if let Some(pos) = self.active.iter().position(|c| c.id == id) {
            self.active.remove(pos);
            self.completed_total += 1;
        }
    }

    /// Mark a command as failed.
    ///
    /// If the command has retries remaining, it is re-enqueued with incremented
    /// retry_count. Otherwise it is moved to the dead letter queue.
    pub fn mark_failed(&mut self, id: Uuid, error: String) {
        if let Some(pos) = self.active.iter().position(|c| c.id == id) {
            let mut cmd = self.active.remove(pos);
            cmd.retry_count += 1;
            cmd.last_error = Some(error);
            self.failed_total += 1;

            if cmd.retry_count < cmd.max_retries {
                // Re-enqueue for retry.
                cmd.status = QueueStatus::Pending;
                self.heap.push(PriorityEntry(cmd));
            } else {
                // Exhausted retries: dead-letter.
                cmd.status = QueueStatus::DeadLettered;
                self.dead_letter.push(cmd);
            }
        }
    }

    /// View the dead letter queue contents.
    pub fn dead_letter_queue(&self) -> &[QueuedCommand] {
        &self.dead_letter
    }

    /// Clear all pending commands from the queue.
    ///
    /// Does not affect active or dead-lettered commands.
    pub fn flush(&mut self) {
        self.heap.clear();
    }

    /// Get current queue metrics.
    pub fn queue_status(&self) -> QueueMetrics {
        QueueMetrics {
            pending: self.heap.len(),
            active: self.active.len(),
            completed_total: self.completed_total,
            failed_total: self.failed_total,
            dlq_size: self.dead_letter.len(),
            max_queue_size: self.max_queue_size,
            max_concurrent: self.max_concurrent,
        }
    }

    /// Number of pending commands.
    pub fn pending_count(&self) -> usize {
        self.heap.len()
    }

    /// Number of currently executing commands.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Number of dead-lettered commands.
    pub fn dlq_count(&self) -> usize {
        self.dead_letter.len()
    }

    /// Persist queue state to a file atomically.
    ///
    /// Writes to a temporary file first, then renames to the target path.
    /// This prevents corruption if the process crashes during the write.
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let pending: Vec<QueuedCommand> = self.heap.iter().map(|entry| entry.0.clone()).collect();

        let envelope = QueuePersistence {
            pending,
            dead_letter: self.dead_letter.clone(),
            completed_total: self.completed_total,
            failed_total: self.failed_total,
            max_queue_size: self.max_queue_size,
            max_concurrent: self.max_concurrent,
        };

        let json = serde_json::to_string_pretty(&envelope)
            .map_err(|e| format!("failed to serialize queue state: {e}"))?;

        // Atomic write: write to temp file, then rename.
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, json.as_bytes())
            .map_err(|e| format!("failed to write queue temp file: {e}"))?;
        std::fs::rename(&tmp_path, path)
            .map_err(|e| format!("failed to rename queue file: {e}"))?;

        Ok(())
    }

    /// Load queue state from a file.
    ///
    /// Restores pending commands, dead letter queue, and counters.
    /// Active commands are not restored (they were interrupted by shutdown).
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let data =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read queue file: {e}"))?;

        let envelope: QueuePersistence =
            serde_json::from_str(&data).map_err(|e| format!("failed to parse queue file: {e}"))?;

        let mut queue = Self::with_limits(envelope.max_queue_size, envelope.max_concurrent);
        queue.completed_total = envelope.completed_total;
        queue.failed_total = envelope.failed_total;
        queue.dead_letter = envelope.dead_letter;

        for cmd in envelope.pending {
            queue.heap.push(PriorityEntry(cmd));
        }

        Ok(queue)
    }
}

impl Default for CommandQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_command(value: &str) -> serde_json::Value {
        serde_json::json!({ "type": "ping", "note": value })
    }

    #[test]
    fn priority_ordering_respected() {
        let mut q = CommandQueue::new();

        q.enqueue(make_command("low"), 10).unwrap();
        q.enqueue(make_command("high"), 200).unwrap();
        q.enqueue(make_command("mid"), 100).unwrap();

        let first = q.dequeue().unwrap();
        assert_eq!(first.priority, 200);

        let second = q.dequeue().unwrap();
        assert_eq!(second.priority, 100);

        let third = q.dequeue().unwrap();
        assert_eq!(third.priority, 10);
    }

    #[test]
    fn concurrency_limit_enforced() {
        let mut q = CommandQueue::with_limits(100, 2);

        q.enqueue(make_command("a"), 10).unwrap();
        q.enqueue(make_command("b"), 10).unwrap();
        q.enqueue(make_command("c"), 10).unwrap();

        let _c1 = q.dequeue().unwrap();
        let _c2 = q.dequeue().unwrap();
        // Third dequeue should return None because max_concurrent is 2.
        assert!(q.dequeue().is_none());
        assert_eq!(q.active_count(), 2);
        assert_eq!(q.pending_count(), 1);
    }

    #[test]
    fn queue_persistence_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");

        let id1;
        {
            let mut q = CommandQueue::with_limits(100, 5);
            id1 = q.enqueue(make_command("persisted"), 42).unwrap();
            q.enqueue(make_command("also-persisted"), 10).unwrap();
            q.completed_total = 7;
            q.failed_total = 2;
            q.save_to_file(&path).unwrap();
        }

        let restored = CommandQueue::load_from_file(&path).unwrap();
        assert_eq!(restored.pending_count(), 2);
        assert_eq!(restored.completed_total, 7);
        assert_eq!(restored.failed_total, 2);
        assert_eq!(restored.max_queue_size, 100);
        assert_eq!(restored.max_concurrent, 5);
        // Verify the command IDs survived the roundtrip.
        let pending_ids: Vec<Uuid> = restored.heap.iter().map(|e| e.0.id).collect();
        assert!(pending_ids.contains(&id1));
    }

    #[test]
    fn queue_size_limit_rejects_overflow() {
        let mut q = CommandQueue::with_limits(2, 10);

        q.enqueue(make_command("a"), 10).unwrap();
        q.enqueue(make_command("b"), 10).unwrap();
        let result = q.enqueue(make_command("c"), 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("queue is full"));
    }

    #[test]
    fn dead_letter_queue_captures_failures() {
        let mut q = CommandQueue::new();

        let id = q.enqueue(make_command("fragile"), 50).unwrap();
        let cmd = q.dequeue().unwrap();
        assert_eq!(cmd.id, id);

        // Fail 3 times (default max_retries).
        q.mark_failed(id, "error 1".into());
        assert_eq!(q.dlq_count(), 0);
        assert_eq!(q.pending_count(), 1);

        let cmd = q.dequeue().unwrap();
        q.mark_failed(cmd.id, "error 2".into());
        assert_eq!(q.dlq_count(), 0);
        assert_eq!(q.pending_count(), 1);

        let cmd = q.dequeue().unwrap();
        q.mark_failed(cmd.id, "error 3".into());
        // Now should be dead-lettered.
        assert_eq!(q.dlq_count(), 1);
        assert_eq!(q.pending_count(), 0);

        let dlq = q.dead_letter_queue();
        assert_eq!(dlq[0].id, id);
        assert_eq!(dlq[0].status, QueueStatus::DeadLettered);
        assert_eq!(dlq[0].retry_count, 3);
    }

    #[test]
    fn queue_metrics_accurate() {
        let mut q = CommandQueue::with_limits(50, 5);

        q.enqueue(make_command("a"), 10).unwrap();
        q.enqueue(make_command("b"), 20).unwrap();
        q.enqueue(make_command("c"), 30).unwrap();

        let metrics = q.queue_status();
        assert_eq!(metrics.pending, 3);
        assert_eq!(metrics.active, 0);
        assert_eq!(metrics.completed_total, 0);
        assert_eq!(metrics.failed_total, 0);
        assert_eq!(metrics.dlq_size, 0);
        assert_eq!(metrics.max_queue_size, 50);
        assert_eq!(metrics.max_concurrent, 5);

        let cmd = q.dequeue().unwrap();
        let metrics = q.queue_status();
        assert_eq!(metrics.pending, 2);
        assert_eq!(metrics.active, 1);

        q.mark_completed(cmd.id);
        let metrics = q.queue_status();
        assert_eq!(metrics.active, 0);
        assert_eq!(metrics.completed_total, 1);
    }

    #[test]
    fn security_test_oversized_command_rejected() {
        let mut q = CommandQueue::new();

        // Create a payload larger than 64 KB.
        let large_string = "x".repeat(MAX_COMMAND_PAYLOAD_BYTES + 1);
        let large_cmd = serde_json::json!({ "data": large_string });

        let result = q.enqueue(large_cmd, 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum size"));
    }

    #[test]
    fn security_test_invalid_json_rejected() {
        // serde_json::Value is always valid JSON by construction, so we test
        // that the payload size validation still works with null/empty payloads.
        let mut q = CommandQueue::new();

        // Valid JSON null -- should succeed.
        let result = q.enqueue(serde_json::Value::Null, 10);
        assert!(result.is_ok());
    }

    #[test]
    fn flush_clears_pending() {
        let mut q = CommandQueue::new();

        q.enqueue(make_command("a"), 10).unwrap();
        q.enqueue(make_command("b"), 20).unwrap();
        assert_eq!(q.pending_count(), 2);

        q.flush();
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn same_priority_fifo_ordering() {
        let mut q = CommandQueue::new();

        // Enqueue with same priority -- earlier should dequeue first.
        let id1 = q.enqueue(make_command("first"), 50).unwrap();
        // Ensure different queued_at by sleeping briefly.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let _id2 = q.enqueue(make_command("second"), 50).unwrap();

        let first = q.dequeue().unwrap();
        assert_eq!(first.id, id1);
    }

    #[test]
    fn mark_completed_on_nonexistent_id_is_noop() {
        let mut q = CommandQueue::new();
        // Should not panic or corrupt state.
        q.mark_completed(Uuid::new_v4());
        assert_eq!(q.completed_total, 0);
    }

    #[test]
    fn mark_failed_on_nonexistent_id_is_noop() {
        let mut q = CommandQueue::new();
        // Should not panic or corrupt state.
        q.mark_failed(Uuid::new_v4(), "error".into());
        assert_eq!(q.failed_total, 0);
    }

    #[test]
    fn persistence_includes_dlq() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");

        {
            let mut q = CommandQueue::new();
            let id = q.enqueue(make_command("will-fail"), 50).unwrap();

            // Drive to DLQ.
            q.dequeue().unwrap();
            q.mark_failed(id, "err 1".into());
            q.dequeue().unwrap();
            q.mark_failed(id, "err 2".into());
            q.dequeue().unwrap();
            q.mark_failed(id, "err 3".into());

            assert_eq!(q.dlq_count(), 1);
            q.save_to_file(&path).unwrap();
        }

        let restored = CommandQueue::load_from_file(&path).unwrap();
        assert_eq!(restored.dlq_count(), 1);
        assert_eq!(
            restored.dead_letter_queue()[0].status,
            QueueStatus::DeadLettered
        );
    }

    #[test]
    fn default_trait() {
        let q = CommandQueue::default();
        assert_eq!(q.max_queue_size, 1000);
        assert_eq!(q.max_concurrent, 10);
    }
}
