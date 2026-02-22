//! Deferred and sleeping reply queue for delayed message delivery.
//!
//! Supports three deferral modes parsed from reply text:
//!
//! - `[[defer:30s]]` -- delay delivery by a fixed duration
//! - `[[sleep:next_heartbeat]]` -- queue for delivery on the next heartbeat cycle
//! - `[[schedule:2024-01-01T12:00:00Z]]` -- deliver at a specific UTC timestamp
//!
//! Deferred replies are persisted to a JSON file so they survive daemon restarts.
//!
//! # Security
//!
//! - Maximum defer duration is 24 hours (prevents unbounded resource growth).
//! - Maximum queue depth is 1000 entries (prevents memory exhaustion).
//! - Schedule timestamps must be in the future and within 30 days.
//! - Tokens are stripped from output before delivery.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

/// Maximum defer duration: 24 hours.
const MAX_DEFER_SECS: u64 = 86_400;

/// Maximum schedule horizon: 30 days from now.
const MAX_SCHEDULE_DAYS: i64 = 30;

/// Maximum number of deferred replies in the queue.
const MAX_QUEUE_DEPTH: usize = 1000;

/// The type of deferral applied to a reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeferralKind {
    /// Delay delivery by a fixed duration.
    Delay {
        /// Number of seconds to delay.
        delay_secs: u64,
    },
    /// Deliver on the next heartbeat cycle.
    NextHeartbeat,
    /// Deliver at a specific UTC timestamp.
    Scheduled {
        /// The target delivery time.
        deliver_at: DateTime<Utc>,
    },
}

/// A reply that has been deferred for later delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredReply {
    /// Unique identifier for this deferred reply.
    pub id: String,
    /// The agent that produced the reply.
    pub agent_name: String,
    /// The channel to deliver through (e.g., "telegram").
    pub channel: String,
    /// The reply text (with deferral token stripped).
    pub text: String,
    /// The kind of deferral.
    pub deferral: DeferralKind,
    /// When this reply was enqueued.
    pub enqueued_at: DateTime<Utc>,
    /// Computed absolute delivery time (for Delay and Scheduled kinds).
    /// For NextHeartbeat, this is `None` until a heartbeat resolves it.
    pub deliver_at: Option<DateTime<Utc>>,
}

/// Result of parsing a reply for deferral tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResult {
    /// No deferral token found; deliver immediately.
    Immediate(String),
    /// A deferral token was found and parsed.
    Deferred {
        /// The reply text with the token stripped.
        text: String,
        /// The parsed deferral kind.
        kind: DeferralKind,
    },
}

/// Parse a reply text for deferral tokens.
///
/// Recognizes:
/// - `[[defer:30s]]` or `[[defer:5m]]` or `[[defer:2h]]`
/// - `[[sleep:next_heartbeat]]`
/// - `[[schedule:2024-01-01T12:00:00Z]]`
///
/// The token is stripped from the returned text. Only the first token is
/// processed; additional tokens are left as-is.
pub fn parse_deferral(text: &str) -> Result<ParseResult, String> {
    // Try [[defer:...]]
    if let Some(rest) = find_and_extract(text, "[[defer:", "]]") {
        let (token_text, duration_str, stripped) = rest;
        let _ = token_text; // full token for reference
        let secs = parse_duration_str(duration_str)?;
        if secs > MAX_DEFER_SECS {
            return Err(format!(
                "defer duration too long: {secs}s > {MAX_DEFER_SECS}s maximum"
            ));
        }
        if secs == 0 {
            return Err("defer duration must be > 0".to_string());
        }
        return Ok(ParseResult::Deferred {
            text: stripped.trim().to_string(),
            kind: DeferralKind::Delay { delay_secs: secs },
        });
    }

    // Try [[sleep:next_heartbeat]]
    if let Some(rest) = find_and_extract(text, "[[sleep:", "]]") {
        let (_token_text, value, stripped) = rest;
        if value.trim() != "next_heartbeat" {
            return Err(format!(
                "unknown sleep target: '{}'. Only 'next_heartbeat' is supported.",
                value.trim()
            ));
        }
        return Ok(ParseResult::Deferred {
            text: stripped.trim().to_string(),
            kind: DeferralKind::NextHeartbeat,
        });
    }

    // Try [[schedule:...]]
    if let Some(rest) = find_and_extract(text, "[[schedule:", "]]") {
        let (_token_text, timestamp_str, stripped) = rest;
        let deliver_at: DateTime<Utc> = timestamp_str
            .trim()
            .parse()
            .map_err(|e| format!("invalid schedule timestamp: {e}"))?;

        let now = Utc::now();
        if deliver_at <= now {
            return Err("schedule timestamp must be in the future".to_string());
        }

        let max_future = now + chrono::Duration::days(MAX_SCHEDULE_DAYS);
        if deliver_at > max_future {
            return Err(format!(
                "schedule timestamp too far in the future (max {MAX_SCHEDULE_DAYS} days)"
            ));
        }

        return Ok(ParseResult::Deferred {
            text: stripped.trim().to_string(),
            kind: DeferralKind::Scheduled { deliver_at },
        });
    }

    Ok(ParseResult::Immediate(text.to_string()))
}

/// Find a token delimited by `prefix` and `suffix` in the text.
///
/// Returns `(full_token, inner_value, text_with_token_removed)`.
fn find_and_extract<'a>(
    text: &'a str,
    prefix: &str,
    suffix: &str,
) -> Option<(&'a str, &'a str, String)> {
    let start = text.find(prefix)?;
    let after_prefix = start + prefix.len();
    let rest = &text[after_prefix..];
    let end_offset = rest.find(suffix)?;
    let inner = &rest[..end_offset];
    let token_end = after_prefix + end_offset + suffix.len();
    let full_token = &text[start..token_end];

    let mut stripped = String::with_capacity(text.len());
    stripped.push_str(&text[..start]);
    stripped.push_str(&text[token_end..]);

    Some((full_token, inner, stripped))
}

/// Parse a human-readable duration string like "30s", "5m", "2h".
fn parse_duration_str(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }

    if let Some(n) = s.strip_suffix('s') {
        let val: u64 = n.trim().parse().map_err(|_| format!("invalid seconds: {n}"))?;
        return Ok(val);
    }
    if let Some(n) = s.strip_suffix('m') {
        let val: u64 = n.trim().parse().map_err(|_| format!("invalid minutes: {n}"))?;
        return Ok(val * 60);
    }
    if let Some(n) = s.strip_suffix('h') {
        let val: u64 = n.trim().parse().map_err(|_| format!("invalid hours: {n}"))?;
        return Ok(val * 3600);
    }

    Err(format!(
        "unrecognized duration format: '{s}'. Expected NNs, NNm, or NNh."
    ))
}

/// Queue for managing deferred replies with JSON persistence.
pub struct DeferredReplyQueue {
    /// The deferred replies, ordered by enqueue time.
    queue: VecDeque<DeferredReply>,
    /// Optional file path for JSON persistence.
    persist_path: Option<PathBuf>,
}

impl DeferredReplyQueue {
    /// Create a new empty queue without persistence.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            persist_path: None,
        }
    }

    /// Create a new queue with JSON file persistence.
    ///
    /// Loads existing entries from the file if it exists.
    pub fn with_persistence(path: &Path) -> Result<Self, String> {
        let mut queue = VecDeque::new();

        if path.exists() {
            let data = std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read deferred queue: {e}"))?;
            if !data.trim().is_empty() {
                let entries: Vec<DeferredReply> = serde_json::from_str(&data)
                    .map_err(|e| format!("failed to parse deferred queue: {e}"))?;
                queue.extend(entries);
                info!(count = queue.len(), path = %path.display(), "loaded deferred replies");
            }
        }

        Ok(Self {
            queue,
            persist_path: Some(path.to_path_buf()),
        })
    }

    /// Enqueue a deferred reply.
    ///
    /// Returns an error if the queue is at maximum capacity.
    pub fn enqueue(
        &mut self,
        agent_name: &str,
        channel: &str,
        text: &str,
        kind: DeferralKind,
    ) -> Result<String, String> {
        if self.queue.len() >= MAX_QUEUE_DEPTH {
            return Err(format!(
                "deferred reply queue full ({MAX_QUEUE_DEPTH} entries). \
                 Drain or increase capacity."
            ));
        }

        let now = Utc::now();
        let deliver_at = match &kind {
            DeferralKind::Delay { delay_secs } => {
                Some(now + chrono::Duration::seconds(*delay_secs as i64))
            }
            DeferralKind::NextHeartbeat => None,
            DeferralKind::Scheduled { deliver_at } => Some(*deliver_at),
        };

        let id = Uuid::new_v4().to_string();
        let reply = DeferredReply {
            id: id.clone(),
            agent_name: agent_name.to_string(),
            channel: channel.to_string(),
            text: text.to_string(),
            deferral: kind,
            enqueued_at: now,
            deliver_at,
        };

        self.queue.push_back(reply);
        self.persist();

        info!(id = %id, agent = %agent_name, "deferred reply enqueued");
        Ok(id)
    }

    /// Drain all replies that are ready for delivery based on the current time.
    ///
    /// Returns replies whose `deliver_at` is at or before `now`.
    /// Does NOT drain `NextHeartbeat` replies -- use [`drain_heartbeat`] for those.
    pub fn drain_ready(&mut self) -> Vec<DeferredReply> {
        let now = Utc::now();
        let mut ready = Vec::new();
        let mut remaining = VecDeque::with_capacity(self.queue.len());

        for reply in self.queue.drain(..) {
            match &reply.deliver_at {
                Some(at) if *at <= now => {
                    ready.push(reply);
                }
                _ => {
                    remaining.push_back(reply);
                }
            }
        }

        self.queue = remaining;

        if !ready.is_empty() {
            self.persist();
            info!(count = ready.len(), "drained ready deferred replies");
        }

        ready
    }

    /// Drain all replies waiting for the next heartbeat.
    ///
    /// Call this method when a heartbeat tick occurs to deliver sleeping replies.
    pub fn drain_heartbeat(&mut self) -> Vec<DeferredReply> {
        let mut ready = Vec::new();
        let mut remaining = VecDeque::with_capacity(self.queue.len());

        for reply in self.queue.drain(..) {
            if matches!(reply.deferral, DeferralKind::NextHeartbeat) {
                ready.push(reply);
            } else {
                remaining.push_back(reply);
            }
        }

        self.queue = remaining;

        if !ready.is_empty() {
            self.persist();
            info!(count = ready.len(), "drained heartbeat deferred replies");
        }

        ready
    }

    /// Remove a specific deferred reply by ID.
    ///
    /// Returns the removed reply, or `None` if not found.
    pub fn cancel(&mut self, id: &str) -> Option<DeferredReply> {
        let pos = self.queue.iter().position(|r| r.id == id)?;
        let reply = self.queue.remove(pos)?;
        self.persist();
        info!(id = %id, "deferred reply cancelled");
        Some(reply)
    }

    /// Get the number of entries in the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// List all deferred replies (read-only).
    pub fn list(&self) -> impl Iterator<Item = &DeferredReply> {
        self.queue.iter()
    }

    /// Persist the queue to the JSON file (if a path is configured).
    fn persist(&self) {
        if let Some(ref path) = self.persist_path {
            let entries: Vec<&DeferredReply> = self.queue.iter().collect();
            match serde_json::to_string_pretty(&entries) {
                Ok(json) => {
                    if let Err(e) = std::fs::write(path, json) {
                        warn!(error = %e, path = %path.display(), "failed to persist deferred queue");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to serialize deferred queue");
                }
            }
        }
    }
}

impl Default for DeferredReplyQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_deferral tests --

    #[test]
    fn parse_defer_seconds() {
        let result = parse_deferral("[[defer:30s]] Hello world").unwrap();
        match result {
            ParseResult::Deferred { text, kind } => {
                assert_eq!(text, "Hello world");
                assert_eq!(kind, DeferralKind::Delay { delay_secs: 30 });
            }
            _ => panic!("expected Deferred"),
        }
    }

    #[test]
    fn parse_defer_minutes() {
        let result = parse_deferral("[[defer:5m]] Delayed message").unwrap();
        match result {
            ParseResult::Deferred { text, kind } => {
                assert_eq!(text, "Delayed message");
                assert_eq!(kind, DeferralKind::Delay { delay_secs: 300 });
            }
            _ => panic!("expected Deferred"),
        }
    }

    #[test]
    fn parse_defer_hours() {
        let result = parse_deferral("[[defer:2h]] Long delay").unwrap();
        match result {
            ParseResult::Deferred { text, kind } => {
                assert_eq!(text, "Long delay");
                assert_eq!(kind, DeferralKind::Delay { delay_secs: 7200 });
            }
            _ => panic!("expected Deferred"),
        }
    }

    #[test]
    fn parse_defer_token_in_middle() {
        let result = parse_deferral("Before [[defer:10s]] After").unwrap();
        match result {
            ParseResult::Deferred { text, kind } => {
                assert_eq!(text, "Before  After");
                assert_eq!(kind, DeferralKind::Delay { delay_secs: 10 });
            }
            _ => panic!("expected Deferred"),
        }
    }

    #[test]
    fn parse_defer_zero_rejected() {
        let result = parse_deferral("[[defer:0s]] text");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be > 0"));
    }

    #[test]
    fn parse_defer_too_long_rejected() {
        let result = parse_deferral("[[defer:100000s]] text");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn parse_sleep_next_heartbeat() {
        let result = parse_deferral("[[sleep:next_heartbeat]] Queued for heartbeat").unwrap();
        match result {
            ParseResult::Deferred { text, kind } => {
                assert_eq!(text, "Queued for heartbeat");
                assert_eq!(kind, DeferralKind::NextHeartbeat);
            }
            _ => panic!("expected Deferred"),
        }
    }

    #[test]
    fn parse_sleep_unknown_target_rejected() {
        let result = parse_deferral("[[sleep:something_else]] text");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown sleep target"));
    }

    #[test]
    fn parse_schedule_valid() {
        // Use a date far enough in the future.
        let future = Utc::now() + chrono::Duration::hours(1);
        let ts = future.to_rfc3339();
        let input = format!("[[schedule:{ts}]] Scheduled message");

        let result = parse_deferral(&input).unwrap();
        match result {
            ParseResult::Deferred { text, kind } => {
                assert_eq!(text, "Scheduled message");
                match kind {
                    DeferralKind::Scheduled { deliver_at } => {
                        // Within 2 seconds of our target.
                        let diff = (deliver_at - future).num_seconds().unsigned_abs();
                        assert!(diff < 2);
                    }
                    _ => panic!("expected Scheduled"),
                }
            }
            _ => panic!("expected Deferred"),
        }
    }

    #[test]
    fn parse_schedule_past_rejected() {
        let past = Utc::now() - chrono::Duration::hours(1);
        let ts = past.to_rfc3339();
        let input = format!("[[schedule:{ts}]] text");
        let result = parse_deferral(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("in the future"));
    }

    #[test]
    fn parse_schedule_too_far_rejected() {
        let far_future = Utc::now() + chrono::Duration::days(60);
        let ts = far_future.to_rfc3339();
        let input = format!("[[schedule:{ts}]] text");
        let result = parse_deferral(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too far in the future"));
    }

    #[test]
    fn parse_no_token_is_immediate() {
        let result = parse_deferral("Just a normal message").unwrap();
        match result {
            ParseResult::Immediate(text) => {
                assert_eq!(text, "Just a normal message");
            }
            _ => panic!("expected Immediate"),
        }
    }

    #[test]
    fn parse_invalid_duration_format() {
        let result = parse_deferral("[[defer:abc]] text");
        assert!(result.is_err());
    }

    // -- DeferredReplyQueue tests --

    #[test]
    fn queue_enqueue_and_len() {
        let mut queue = DeferredReplyQueue::new();
        assert!(queue.is_empty());

        queue
            .enqueue("agent-1", "telegram", "Hello", DeferralKind::Delay { delay_secs: 10 })
            .unwrap();

        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());
    }

    #[test]
    fn queue_drain_ready_respects_time() {
        let mut queue = DeferredReplyQueue::new();

        // Enqueue a reply with 0-second delay (should be immediately ready -- but we
        // need to use deliver_at in the past). We'll test by using Scheduled with a past time.
        // Actually, delay_secs of 1 with a tiny wait won't work without sleeping.
        // Let's construct a DeferredReply manually with a past deliver_at.
        let past_reply = DeferredReply {
            id: "past-1".to_string(),
            agent_name: "agent-1".to_string(),
            channel: "telegram".to_string(),
            text: "Past reply".to_string(),
            deferral: DeferralKind::Delay { delay_secs: 1 },
            enqueued_at: Utc::now() - chrono::Duration::seconds(10),
            deliver_at: Some(Utc::now() - chrono::Duration::seconds(5)),
        };
        let future_reply = DeferredReply {
            id: "future-1".to_string(),
            agent_name: "agent-2".to_string(),
            channel: "telegram".to_string(),
            text: "Future reply".to_string(),
            deferral: DeferralKind::Delay { delay_secs: 3600 },
            enqueued_at: Utc::now(),
            deliver_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };
        let heartbeat_reply = DeferredReply {
            id: "hb-1".to_string(),
            agent_name: "agent-3".to_string(),
            channel: "telegram".to_string(),
            text: "Heartbeat reply".to_string(),
            deferral: DeferralKind::NextHeartbeat,
            enqueued_at: Utc::now(),
            deliver_at: None,
        };

        queue.queue.push_back(past_reply);
        queue.queue.push_back(future_reply);
        queue.queue.push_back(heartbeat_reply);

        assert_eq!(queue.len(), 3);

        // drain_ready should only get the past reply.
        let ready = queue.drain_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "past-1");

        // Remaining: future + heartbeat.
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn queue_drain_heartbeat() {
        let mut queue = DeferredReplyQueue::new();

        queue
            .enqueue("agent-1", "telegram", "Normal", DeferralKind::Delay { delay_secs: 60 })
            .unwrap();
        queue
            .enqueue("agent-2", "telegram", "Heartbeat", DeferralKind::NextHeartbeat)
            .unwrap();
        queue
            .enqueue("agent-3", "telegram", "Another HB", DeferralKind::NextHeartbeat)
            .unwrap();

        assert_eq!(queue.len(), 3);

        let hb = queue.drain_heartbeat();
        assert_eq!(hb.len(), 2);
        assert_eq!(hb[0].text, "Heartbeat");
        assert_eq!(hb[1].text, "Another HB");

        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn queue_cancel() {
        let mut queue = DeferredReplyQueue::new();

        let id = queue
            .enqueue("agent-1", "telegram", "Cancel me", DeferralKind::NextHeartbeat)
            .unwrap();

        assert_eq!(queue.len(), 1);

        let cancelled = queue.cancel(&id);
        assert!(cancelled.is_some());
        assert_eq!(cancelled.unwrap().text, "Cancel me");
        assert!(queue.is_empty());

        // Cancel nonexistent returns None.
        assert!(queue.cancel("nonexistent").is_none());
    }

    #[test]
    fn queue_max_depth_enforced() {
        let mut queue = DeferredReplyQueue::new();

        for i in 0..MAX_QUEUE_DEPTH {
            queue
                .enqueue(
                    "agent",
                    "ch",
                    &format!("msg-{i}"),
                    DeferralKind::NextHeartbeat,
                )
                .unwrap();
        }

        // Next enqueue should fail.
        let result = queue.enqueue("agent", "ch", "overflow", DeferralKind::NextHeartbeat);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("queue full"));
    }

    #[test]
    fn queue_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deferred.json");

        // Create and populate queue.
        {
            let mut queue = DeferredReplyQueue::with_persistence(&path).unwrap();
            queue
                .enqueue("agent-1", "telegram", "Persist me", DeferralKind::NextHeartbeat)
                .unwrap();
            queue
                .enqueue(
                    "agent-2",
                    "slack",
                    "And me",
                    DeferralKind::Delay { delay_secs: 60 },
                )
                .unwrap();
            assert_eq!(queue.len(), 2);
        }

        // Reload from disk.
        {
            let queue = DeferredReplyQueue::with_persistence(&path).unwrap();
            assert_eq!(queue.len(), 2);

            let entries: Vec<_> = queue.list().collect();
            assert_eq!(entries[0].text, "Persist me");
            assert_eq!(entries[1].text, "And me");
        }
    }

    #[test]
    fn queue_list_iterator() {
        let mut queue = DeferredReplyQueue::new();
        queue
            .enqueue("a1", "ch", "msg1", DeferralKind::NextHeartbeat)
            .unwrap();
        queue
            .enqueue("a2", "ch", "msg2", DeferralKind::NextHeartbeat)
            .unwrap();

        let texts: Vec<&str> = queue.list().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, vec!["msg1", "msg2"]);
    }

    #[test]
    fn deferral_kind_serde_roundtrip() {
        let kinds = vec![
            DeferralKind::Delay { delay_secs: 42 },
            DeferralKind::NextHeartbeat,
            DeferralKind::Scheduled {
                deliver_at: Utc::now(),
            },
        ];

        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: DeferralKind = serde_json::from_str(&json).unwrap();
            // For Scheduled, times may differ by subsecond precision in serde,
            // so we just check the tag matches.
            match (&kind, &back) {
                (DeferralKind::Delay { delay_secs: a }, DeferralKind::Delay { delay_secs: b }) => {
                    assert_eq!(a, b);
                }
                (DeferralKind::NextHeartbeat, DeferralKind::NextHeartbeat) => {}
                (
                    DeferralKind::Scheduled { deliver_at: a },
                    DeferralKind::Scheduled { deliver_at: b },
                ) => {
                    let diff = (*a - *b).num_seconds().unsigned_abs();
                    assert!(diff < 2);
                }
                _ => panic!("kind mismatch after roundtrip"),
            }
        }
    }

    #[test]
    fn parse_duration_str_valid() {
        assert_eq!(parse_duration_str("30s").unwrap(), 30);
        assert_eq!(parse_duration_str("5m").unwrap(), 300);
        assert_eq!(parse_duration_str("2h").unwrap(), 7200);
        assert_eq!(parse_duration_str(" 10s ").unwrap(), 10);
    }

    #[test]
    fn parse_duration_str_invalid() {
        assert!(parse_duration_str("").is_err());
        assert!(parse_duration_str("abc").is_err());
        assert!(parse_duration_str("30x").is_err());
        assert!(parse_duration_str("s").is_err());
    }
}
