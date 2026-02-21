//! Async audit pipeline with batch inserts and backpressure.
//!
//! [`AsyncAuditWriter`] wraps an [`AuditStore`] with a bounded async channel
//! and a background task that drains entries in batches. This decouples audit
//! producers from the synchronous SQLite writes, improving throughput under
//! high audit volumes.
//!
//! # Security properties
//!
//! - **Bounded channel prevents OOM:** The mpsc channel has a fixed capacity
//!   (default 4096). When full, `send()` returns an error instead of blocking,
//!   providing backpressure to callers.
//! - **Graceful shutdown drains all entries:** The `Shutdown` command causes the
//!   background task to drain every remaining entry before exiting, ensuring no
//!   audit data is lost.
//! - **Error resilience:** Individual insert failures are logged but do not stop
//!   the pipeline. The background task continues processing subsequent entries.
//! - **Entry ordering preserved:** Entries within a batch are inserted in the
//!   order they were received from the channel.

use std::path::Path;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info};

use aegis_types::{Action, AegisError, Verdict};

use crate::channel_audit::ChannelDirection;
use crate::fs_audit::FsOperation;
use crate::store::AuditStore;

/// Default bounded channel capacity.
const DEFAULT_CHANNEL_CAPACITY: usize = 4096;

/// Default number of entries per batch insert.
const DEFAULT_BATCH_SIZE: usize = 64;

/// Default flush interval -- flush even if the batch is not full.
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// Commands sent through the async channel to the background writer task.
#[derive(Debug)]
pub enum AuditCommand {
    /// Insert a standard action/verdict audit entry.
    InsertEntry {
        /// The action being audited.
        action: Action,
        /// The policy verdict for the action.
        verdict: Verdict,
    },
    /// Insert a channel audit entry (e.g., Telegram message metadata).
    InsertChannelAudit {
        /// Channel name (e.g., "telegram").
        channel_name: String,
        /// Message direction.
        direction: ChannelDirection,
        /// SHA-256 hex digest of the message content.
        message_hash: String,
        /// Number of recipients.
        recipient_count: u32,
        /// Whether the message had interactive buttons.
        has_buttons: bool,
    },
    /// Insert a filesystem audit entry.
    InsertFsAudit {
        /// Absolute file path (validated against directory traversal).
        path: String,
        /// SHA-256 hash of the file content before the operation.
        before_hash: Option<String>,
        /// SHA-256 hash of the file content after the operation.
        after_hash: Option<String>,
        /// Change in file size in bytes.
        size_delta: i64,
        /// The type of filesystem operation.
        operation: FsOperation,
    },
    /// Flush any pending batch immediately.
    Flush,
    /// Gracefully shut down: drain all remaining entries, then stop.
    Shutdown,
}

/// Configuration for the async audit pipeline.
#[derive(Debug, Clone)]
pub struct AsyncAuditConfig {
    /// Bounded channel capacity. When the channel is full, `send()` returns
    /// an error to provide backpressure. Default: 4096.
    pub channel_capacity: usize,
    /// Maximum number of entries per batch insert. Default: 64.
    pub batch_size: usize,
    /// Flush interval -- the background task flushes even if the batch is not
    /// full after this duration. Default: 100ms.
    pub flush_interval: Duration,
}

impl Default for AsyncAuditConfig {
    fn default() -> Self {
        Self {
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            batch_size: DEFAULT_BATCH_SIZE,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
        }
    }
}

/// An async wrapper around [`AuditStore`] that batches inserts via a bounded channel.
///
/// Send audit commands via [`send()`](AsyncAuditWriter::send) and they will be
/// processed in batches by a background tokio task. The channel is bounded to
/// prevent OOM under high load -- callers receive an error when the channel is full.
pub struct AsyncAuditWriter {
    tx: mpsc::Sender<AuditCommand>,
    handle: JoinHandle<()>,
}

impl AsyncAuditWriter {
    /// Start the async audit pipeline.
    ///
    /// Opens an [`AuditStore`] at the given path and spawns a background task
    /// that drains audit commands from the bounded channel in batches.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit store cannot be opened.
    pub fn start(db_path: &Path, config: AsyncAuditConfig) -> Result<Self, AegisError> {
        let store = AuditStore::open(db_path)?;
        let (tx, rx) = mpsc::channel(config.channel_capacity);

        let handle = tokio::spawn(writer_task(store, rx, config.batch_size, config.flush_interval));

        info!(
            capacity = config.channel_capacity,
            batch_size = config.batch_size,
            flush_interval_ms = config.flush_interval.as_millis() as u64,
            "async audit pipeline started"
        );

        Ok(Self { tx, handle })
    }

    /// Send an audit command to the background writer.
    ///
    /// Returns an error if the channel is full (backpressure) or if the
    /// background task has stopped.
    pub fn send(&self, cmd: AuditCommand) -> Result<(), AegisError> {
        self.tx.try_send(cmd).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => AegisError::LedgerError(
                "async audit channel full: backpressure applied".to_string(),
            ),
            mpsc::error::TrySendError::Closed(_) => AegisError::LedgerError(
                "async audit channel closed: background writer has stopped".to_string(),
            ),
        })
    }

    /// Shut down the pipeline gracefully, draining all pending entries.
    ///
    /// Sends a `Shutdown` command and waits for the background task to finish.
    /// This ensures no audit entries are lost.
    pub async fn shutdown(self) -> Result<(), AegisError> {
        // Use the async send for shutdown to ensure it gets queued even under load.
        self.tx
            .send(AuditCommand::Shutdown)
            .await
            .map_err(|_| {
                AegisError::LedgerError(
                    "async audit channel closed: could not send shutdown".to_string(),
                )
            })?;

        self.handle.await.map_err(|e| {
            AegisError::LedgerError(format!("async audit writer task panicked: {e}"))
        })
    }
}

/// Background task that drains the channel and batch-inserts entries.
///
/// Runs until a `Shutdown` command is received or the channel is closed.
/// Individual insert errors are logged but do not stop the task.
async fn writer_task(
    mut store: AuditStore,
    mut rx: mpsc::Receiver<AuditCommand>,
    batch_size: usize,
    flush_interval: Duration,
) {
    let mut batch: Vec<AuditCommand> = Vec::with_capacity(batch_size);
    let mut interval = tokio::time::interval(flush_interval);
    // The first tick completes immediately -- consume it so we don't
    // flush an empty batch right away.
    interval.tick().await;

    loop {
        tokio::select! {
            // Bias toward receiving commands to maximize batch fill before flushing.
            biased;

            maybe_cmd = rx.recv() => {
                match maybe_cmd {
                    Some(AuditCommand::Shutdown) => {
                        // Flush current batch, then drain remaining channel entries.
                        flush_batch(&mut store, &mut batch);
                        drain_remaining(&mut store, &mut rx, batch_size);
                        info!("async audit pipeline shut down gracefully");
                        return;
                    }
                    Some(AuditCommand::Flush) => {
                        flush_batch(&mut store, &mut batch);
                    }
                    Some(cmd) => {
                        batch.push(cmd);
                        if batch.len() >= batch_size {
                            flush_batch(&mut store, &mut batch);
                        }
                    }
                    None => {
                        // Channel closed (all senders dropped). Flush remaining and exit.
                        flush_batch(&mut store, &mut batch);
                        info!("async audit pipeline channel closed, flushed remaining entries");
                        return;
                    }
                }
            }
            _ = interval.tick() => {
                if !batch.is_empty() {
                    flush_batch(&mut store, &mut batch);
                }
            }
        }
    }
}

/// Drain all remaining commands from the channel after a shutdown signal.
fn drain_remaining(
    store: &mut AuditStore,
    rx: &mut mpsc::Receiver<AuditCommand>,
    batch_size: usize,
) {
    let mut batch: Vec<AuditCommand> = Vec::with_capacity(batch_size);

    // Close the channel so no new commands can be sent.
    rx.close();

    // Drain all buffered commands.
    while let Ok(cmd) = rx.try_recv() {
        match cmd {
            AuditCommand::Shutdown | AuditCommand::Flush => {
                // Ignore additional shutdown/flush commands during drain.
            }
            cmd => {
                batch.push(cmd);
                if batch.len() >= batch_size {
                    flush_batch(store, &mut batch);
                }
            }
        }
    }

    if !batch.is_empty() {
        flush_batch(store, &mut batch);
    }
}

/// Execute all commands in the batch against the store.
///
/// Each command is processed individually. Errors on individual inserts are
/// logged but do not stop processing -- the pipeline must be resilient to
/// transient SQLite errors.
fn flush_batch(store: &mut AuditStore, batch: &mut Vec<AuditCommand>) {
    if batch.is_empty() {
        return;
    }

    let count = batch.len();

    for cmd in batch.drain(..) {
        if let Err(e) = execute_command(store, cmd) {
            error!(error = %e, "async audit insert failed, continuing pipeline");
        }
    }

    tracing::trace!(count, "flushed audit batch");
}

/// Execute a single audit command against the store.
fn execute_command(store: &mut AuditStore, cmd: AuditCommand) -> Result<(), AegisError> {
    match cmd {
        AuditCommand::InsertEntry { action, verdict } => {
            store.append(&action, &verdict)?;
        }
        AuditCommand::InsertChannelAudit {
            channel_name,
            direction,
            message_hash,
            recipient_count,
            has_buttons,
        } => {
            store.insert_channel_audit(
                &channel_name,
                direction,
                &message_hash,
                recipient_count,
                has_buttons,
            )?;
        }
        AuditCommand::InsertFsAudit {
            path,
            before_hash,
            after_hash,
            size_delta,
            operation,
        } => {
            store.insert_fs_audit(
                &path,
                before_hash.as_deref(),
                after_hash.as_deref(),
                size_delta,
                operation,
            )?;
        }
        AuditCommand::Flush | AuditCommand::Shutdown => {
            // These are handled at the task level, not as individual commands.
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::ActionKind;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn sample_action(principal: &str) -> Action {
        Action::new(
            principal,
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        )
    }

    fn tmp_db() -> NamedTempFile {
        NamedTempFile::new().expect("failed to create temp file")
    }

    #[tokio::test]
    async fn async_pipeline_inserts_entries() {
        let tmp = tmp_db();
        let writer = AsyncAuditWriter::start(
            tmp.path(),
            AsyncAuditConfig::default(),
        )
        .unwrap();

        let action = sample_action("agent-1");
        let verdict = Verdict::allow(action.id, "ok", None);
        writer
            .send(AuditCommand::InsertEntry { action, verdict })
            .unwrap();

        writer.shutdown().await.unwrap();

        // Verify the entry was persisted.
        let store = AuditStore::open(tmp.path()).unwrap();
        let entries = store.query_last(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].principal, "agent-1");
    }

    #[tokio::test]
    async fn async_pipeline_batch_insert() {
        let tmp = tmp_db();
        let config = AsyncAuditConfig {
            batch_size: 4,
            ..Default::default()
        };
        let writer = AsyncAuditWriter::start(tmp.path(), config).unwrap();

        // Send more entries than a single batch to exercise batch boundaries.
        for i in 0..10 {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, format!("reason-{i}"), None);
            writer
                .send(AuditCommand::InsertEntry { action, verdict })
                .unwrap();
        }

        writer.shutdown().await.unwrap();

        let store = AuditStore::open(tmp.path()).unwrap();
        assert_eq!(store.count().unwrap(), 10);
    }

    #[tokio::test]
    async fn async_pipeline_backpressure() {
        let tmp = tmp_db();
        let config = AsyncAuditConfig {
            channel_capacity: 2,
            batch_size: 1,
            // Long flush interval so batches don't drain automatically.
            flush_interval: Duration::from_secs(60),
            ..Default::default()
        };
        let writer = AsyncAuditWriter::start(tmp.path(), config).unwrap();

        // Fill the channel. With capacity 2, the third send should fail.
        // We need to account for the background task potentially consuming
        // entries, so keep sending until we get a backpressure error.
        let mut backpressure_hit = false;
        for i in 0..100 {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, "ok", None);
            if writer
                .send(AuditCommand::InsertEntry { action, verdict })
                .is_err()
            {
                backpressure_hit = true;
                break;
            }
        }

        assert!(
            backpressure_hit,
            "expected backpressure error when channel is full"
        );

        writer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn async_pipeline_flush_on_interval() {
        let tmp = tmp_db();
        let config = AsyncAuditConfig {
            batch_size: 1000, // Large batch so it won't flush by size.
            flush_interval: Duration::from_millis(50),
            ..Default::default()
        };
        let writer = AsyncAuditWriter::start(tmp.path(), config).unwrap();

        let action = sample_action("interval-agent");
        let verdict = Verdict::allow(action.id, "ok", None);
        writer
            .send(AuditCommand::InsertEntry { action, verdict })
            .unwrap();

        // Wait for the flush interval to trigger.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The entry should be flushed by now, even though the batch wasn't full.
        // Verify by opening a separate connection.
        let store = AuditStore::open(tmp.path()).unwrap();
        let entries = store.query_last(10).unwrap();
        assert_eq!(entries.len(), 1, "entry should be flushed by interval timer");

        writer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn async_pipeline_graceful_shutdown() {
        let tmp = tmp_db();
        let config = AsyncAuditConfig {
            batch_size: 1000, // Large batch -- entries won't flush by size.
            flush_interval: Duration::from_secs(60), // Long interval -- won't flush by timer.
            ..Default::default()
        };
        let writer = AsyncAuditWriter::start(tmp.path(), config).unwrap();

        for i in 0..50 {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, format!("reason-{i}"), None);
            writer
                .send(AuditCommand::InsertEntry { action, verdict })
                .unwrap();
        }

        // Shutdown should drain all 50 entries before exiting.
        writer.shutdown().await.unwrap();

        let store = AuditStore::open(tmp.path()).unwrap();
        assert_eq!(store.count().unwrap(), 50);
    }

    #[tokio::test]
    async fn async_pipeline_continues_on_insert_error() {
        let tmp = tmp_db();
        let writer = AsyncAuditWriter::start(
            tmp.path(),
            AsyncAuditConfig::default(),
        )
        .unwrap();

        // Send an fs audit with an invalid path (relative -- will be rejected).
        writer
            .send(AuditCommand::InsertFsAudit {
                path: "relative/path.txt".to_string(),
                before_hash: None,
                after_hash: None,
                size_delta: 0,
                operation: FsOperation::Create,
            })
            .unwrap();

        // Send a valid entry after the error.
        let action = sample_action("survivor");
        let verdict = Verdict::allow(action.id, "ok", None);
        writer
            .send(AuditCommand::InsertEntry { action, verdict })
            .unwrap();

        writer.shutdown().await.unwrap();

        // The valid entry should have been inserted despite the earlier error.
        let store = AuditStore::open(tmp.path()).unwrap();
        let entries = store.query_last(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].principal, "survivor");
    }

    /// Security test: verify that ALL entries are drained on shutdown,
    /// even when they haven't been flushed by batch size or timer.
    /// This is critical -- lost audit entries could hide malicious actions.
    #[tokio::test]
    async fn async_pipeline_drains_on_shutdown() {
        let tmp = tmp_db();
        let config = AsyncAuditConfig {
            batch_size: 10000,
            flush_interval: Duration::from_secs(600),
            ..Default::default()
        };
        let writer = AsyncAuditWriter::start(tmp.path(), config).unwrap();

        let expected_count = 200;
        for i in 0..expected_count {
            let action = sample_action(&format!("agent-{i}"));
            let verdict = Verdict::allow(action.id, "ok", None);
            writer
                .send(AuditCommand::InsertEntry { action, verdict })
                .unwrap();
        }

        // Neither batch size (10000) nor timer (600s) would have triggered.
        // Shutdown MUST drain all 200 entries.
        writer.shutdown().await.unwrap();

        let store = AuditStore::open(tmp.path()).unwrap();
        let count = store.count().unwrap();
        assert_eq!(
            count, expected_count,
            "SECURITY: {expected_count} audit entries were sent but only {count} were persisted -- \
             audit data was lost on shutdown"
        );

        // Also verify the hash chain is intact.
        let report = store.verify_integrity().unwrap();
        assert!(
            report.valid,
            "SECURITY: audit hash chain is broken after shutdown drain: {}",
            report.message
        );
    }

    #[tokio::test]
    async fn async_pipeline_channel_audit() {
        let tmp = tmp_db();
        let writer = AsyncAuditWriter::start(
            tmp.path(),
            AsyncAuditConfig::default(),
        )
        .unwrap();

        writer
            .send(AuditCommand::InsertChannelAudit {
                channel_name: "telegram".to_string(),
                direction: ChannelDirection::Outbound,
                message_hash: "abc123def456".to_string(),
                recipient_count: 1,
                has_buttons: true,
            })
            .unwrap();

        writer.shutdown().await.unwrap();

        let store = AuditStore::open(tmp.path()).unwrap();
        let entries = store.query_channel_audit_last(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].channel_name, "telegram");
    }

    #[tokio::test]
    async fn async_pipeline_fs_audit() {
        let tmp = tmp_db();
        let writer = AsyncAuditWriter::start(
            tmp.path(),
            AsyncAuditConfig::default(),
        )
        .unwrap();

        writer
            .send(AuditCommand::InsertFsAudit {
                path: "/tmp/test.txt".to_string(),
                before_hash: None,
                after_hash: Some("deadbeef".to_string()),
                size_delta: 42,
                operation: FsOperation::Create,
            })
            .unwrap();

        writer.shutdown().await.unwrap();

        let store = AuditStore::open(tmp.path()).unwrap();
        let entries = store.query_fs_audit_last(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/tmp/test.txt");
    }
}
