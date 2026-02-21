//! Message routing engine for inter-agent and cross-channel communication.
//!
//! The [`MessageRouter`] maintains per-agent message queues and a thread
//! store for parent-child message tracking. All messages pass through
//! content sanitization and rate limiting before being enqueued.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use aegis_control::message_routing::{
    validate_agent_name, ContentSanitizer, MessageEnvelope,
};
use uuid::Uuid;

/// Maximum messages per minute per agent (default, configurable).
const DEFAULT_RATE_LIMIT: usize = 100;

/// Maximum messages stored per agent queue before oldest are dropped.
const MAX_QUEUE_SIZE: usize = 1000;

/// Maximum messages stored in the thread index.
const MAX_THREAD_STORE: usize = 10_000;

/// Per-agent rate limiter state.
struct RateWindow {
    /// Timestamps of recent messages within the current window.
    timestamps: VecDeque<Instant>,
    /// Maximum messages allowed per minute.
    limit: usize,
}

impl RateWindow {
    fn new(limit: usize) -> Self {
        Self {
            timestamps: VecDeque::new(),
            limit,
        }
    }

    /// Check if a new message is allowed and record it if so.
    fn check_and_record(&mut self, now: Instant) -> bool {
        let window = std::time::Duration::from_secs(60);
        // Prune timestamps older than the window
        while self.timestamps.front().is_some_and(|t| now.duration_since(*t) > window) {
            self.timestamps.pop_front();
        }
        if self.timestamps.len() >= self.limit {
            return false;
        }
        self.timestamps.push_back(now);
        true
    }
}

/// Message routing engine with per-agent queues and thread tracking.
pub struct MessageRouter {
    /// Per-agent message queues.
    queues: HashMap<String, VecDeque<MessageEnvelope>>,
    /// All stored messages indexed by ID for thread retrieval.
    messages_by_id: HashMap<Uuid, MessageEnvelope>,
    /// Thread index: parent_id -> list of child message IDs.
    thread_index: HashMap<Uuid, Vec<Uuid>>,
    /// Per-agent rate limiters.
    rate_limiters: HashMap<String, RateWindow>,
    /// Configurable rate limit (messages per minute per agent).
    rate_limit: usize,
}

impl MessageRouter {
    /// Create a new message router with the default rate limit.
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
            messages_by_id: HashMap::new(),
            thread_index: HashMap::new(),
            rate_limiters: HashMap::new(),
            rate_limit: DEFAULT_RATE_LIMIT,
        }
    }

    /// Create a new message router with a custom rate limit.
    pub fn with_rate_limit(rate_limit: usize) -> Self {
        Self {
            queues: HashMap::new(),
            messages_by_id: HashMap::new(),
            thread_index: HashMap::new(),
            rate_limiters: HashMap::new(),
            rate_limit,
        }
    }

    /// Route a message to the target agent's queue.
    ///
    /// Validates the agent name, sanitizes content, checks rate limits,
    /// and enqueues the message. Returns an error if validation or rate
    /// limiting fails.
    ///
    /// The caller is responsible for verifying that the target agent exists
    /// in the fleet before calling this method.
    pub fn route_message(&mut self, mut envelope: MessageEnvelope) -> Result<Uuid, String> {
        // Validate target agent name (security: prevent directory traversal)
        validate_agent_name(&envelope.to)?;
        validate_agent_name(&envelope.from)?;

        // Sanitize content from external channels
        envelope.content = ContentSanitizer::sanitize(&envelope.content);

        // Rate limit check
        let rate_window = self
            .rate_limiters
            .entry(envelope.from.clone())
            .or_insert_with(|| RateWindow::new(self.rate_limit));

        if !rate_window.check_and_record(Instant::now()) {
            return Err(format!(
                "rate limit exceeded for '{}': max {} messages per minute",
                envelope.from, self.rate_limit
            ));
        }

        let msg_id = envelope.id;

        // Store for thread tracking
        self.store_message(envelope.clone());

        // Enqueue for the target agent
        let queue = self
            .queues
            .entry(envelope.to.clone())
            .or_default();

        // Enforce queue size limit (drop oldest)
        while queue.len() >= MAX_QUEUE_SIZE {
            queue.pop_front();
        }
        queue.push_back(envelope);

        Ok(msg_id)
    }

    /// Inject a system message for an agent (no user attribution).
    ///
    /// Creates a system envelope and routes it. The caller should verify
    /// elevated Cedar policy permissions before calling this.
    pub fn inject_system_message(
        &mut self,
        agent_name: &str,
        content: &str,
    ) -> Result<Uuid, String> {
        let envelope = MessageEnvelope::system(agent_name, "direct", content);
        self.route_message(envelope)
    }

    /// Retrieve all messages in a thread rooted at the given message ID.
    ///
    /// Returns the root message plus all direct children (messages whose
    /// parent_id equals the given ID). Messages are returned in
    /// chronological order.
    pub fn get_thread(&self, message_id: Uuid) -> Vec<MessageEnvelope> {
        let mut thread = Vec::new();

        // Include the root message
        if let Some(root) = self.messages_by_id.get(&message_id) {
            thread.push(root.clone());
        }

        // Include all children
        if let Some(child_ids) = self.thread_index.get(&message_id) {
            for child_id in child_ids {
                if let Some(child) = self.messages_by_id.get(child_id) {
                    thread.push(child.clone());
                }
            }
        }

        // Sort by timestamp
        thread.sort_by_key(|m| m.timestamp);
        thread
    }

    /// Store a message for thread tracking.
    fn store_message(&mut self, envelope: MessageEnvelope) {
        let msg_id = envelope.id;

        // Update thread index if this message has a parent
        if let Some(parent_id) = envelope.parent_id {
            let children = self.thread_index.entry(parent_id).or_default();
            children.push(msg_id);
        }

        // Enforce global store size limit
        if self.messages_by_id.len() >= MAX_THREAD_STORE {
            // Evict the oldest message by finding the minimum timestamp.
            // This is O(n) but only triggers at the capacity boundary.
            if let Some(oldest_id) = self
                .messages_by_id
                .values()
                .min_by_key(|m| m.timestamp)
                .map(|m| m.id)
            {
                self.messages_by_id.remove(&oldest_id);
            }
        }

        self.messages_by_id.insert(msg_id, envelope);
    }

    /// Drain all pending messages for an agent.
    pub fn drain_queue(&mut self, agent_name: &str) -> Vec<MessageEnvelope> {
        self.queues
            .get_mut(agent_name)
            .map(|q| q.drain(..).collect())
            .unwrap_or_default()
    }

    /// Peek at the number of pending messages for an agent.
    pub fn queue_len(&self, agent_name: &str) -> usize {
        self.queues.get(agent_name).map(|q| q.len()).unwrap_or(0)
    }

    /// Get the last message ID routed to an agent, if any.
    pub fn last_message_id(&self, agent_name: &str) -> Option<Uuid> {
        self.queues
            .get(agent_name)
            .and_then(|q| q.back())
            .map(|m| m.id)
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_routes_to_correct_agent() {
        let mut router = MessageRouter::new();
        let env = MessageEnvelope::new("sender", "target-agent", "direct", "hello");
        let msg_id = router.route_message(env).unwrap();

        // Message should be in the target agent's queue
        assert_eq!(router.queue_len("target-agent"), 1);
        assert_eq!(router.queue_len("sender"), 0);

        let messages = router.drain_queue("target-agent");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, msg_id);
        assert_eq!(messages[0].content, "hello");
    }

    #[test]
    fn parent_child_threading_maintains_chain() {
        let mut router = MessageRouter::new();

        // Send parent message
        let parent = MessageEnvelope::new("agent-1", "agent-2", "direct", "initial question");
        let parent_id = router.route_message(parent).unwrap();

        // Send child replies
        let child1 = MessageEnvelope::new("agent-2", "agent-1", "direct", "reply 1")
            .with_parent(parent_id);
        let child1_id = router.route_message(child1).unwrap();

        let child2 = MessageEnvelope::new("agent-1", "agent-2", "direct", "reply 2")
            .with_parent(parent_id);
        let _child2_id = router.route_message(child2).unwrap();

        // Get the thread
        let thread = router.get_thread(parent_id);
        assert_eq!(thread.len(), 3);
        assert_eq!(thread[0].content, "initial question");
        assert_eq!(thread[1].content, "reply 1");
        assert_eq!(thread[2].content, "reply 2");

        // Verify child1 is not a thread root (no children under it)
        let child_thread = router.get_thread(child1_id);
        assert_eq!(child_thread.len(), 1); // only the message itself
    }

    #[test]
    fn message_injection_bypasses_user_attribution() {
        let mut router = MessageRouter::new();
        let msg_id = router
            .inject_system_message("target-agent", "system directive")
            .unwrap();

        let messages = router.drain_queue("target-agent");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, msg_id);
        assert_eq!(messages[0].from, "system");
        assert!(messages[0].is_system);
        assert_eq!(messages[0].content, "system directive");
    }

    #[test]
    fn invalid_routing_target_returns_error() {
        let mut router = MessageRouter::new();

        // Directory traversal in target
        let env = MessageEnvelope::new("sender", "../etc/passwd", "direct", "test");
        assert!(router.route_message(env).is_err());

        // Path separator in target
        let env = MessageEnvelope::new("sender", "agent/child", "direct", "test");
        assert!(router.route_message(env).is_err());

        // Empty target
        let env = MessageEnvelope::new("sender", "", "direct", "test");
        assert!(router.route_message(env).is_err());
    }

    #[test]
    fn channel_specific_formatting_applied() {
        // This test verifies that the content sanitization is applied during routing.
        let mut router = MessageRouter::new();
        let env = MessageEnvelope::new(
            "external-user",
            "agent-1",
            "telegram",
            "hello\x00world\x1b[31m",
        );
        router.route_message(env).unwrap();

        let messages = router.drain_queue("agent-1");
        assert_eq!(messages.len(), 1);
        // Null bytes and ANSI escapes should be stripped
        assert!(!messages[0].content.contains('\0'));
        assert!(!messages[0].content.contains('\x1b'));
        assert!(messages[0].content.contains("hello"));
    }

    #[test]
    fn rate_limiting_enforced() {
        let mut router = MessageRouter::with_rate_limit(5);

        // Send 5 messages (should all succeed)
        for i in 0..5 {
            let env = MessageEnvelope::new("sender", "target", "direct", format!("msg {i}"));
            assert!(router.route_message(env).is_ok());
        }

        // 6th message should be rate limited
        let env = MessageEnvelope::new("sender", "target", "direct", "msg 6");
        let result = router.route_message(env);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("rate limit"));
    }

    #[test]
    fn queue_drains_correctly() {
        let mut router = MessageRouter::new();

        let env1 = MessageEnvelope::new("a", "target", "direct", "msg1");
        let env2 = MessageEnvelope::new("b", "target", "direct", "msg2");
        router.route_message(env1).unwrap();
        router.route_message(env2).unwrap();

        assert_eq!(router.queue_len("target"), 2);

        let drained = router.drain_queue("target");
        assert_eq!(drained.len(), 2);
        assert_eq!(router.queue_len("target"), 0);
    }

    #[test]
    fn last_message_id_tracks_latest() {
        let mut router = MessageRouter::new();
        assert!(router.last_message_id("agent").is_none());

        let env1 = MessageEnvelope::new("a", "agent", "direct", "first");
        let _id1 = router.route_message(env1).unwrap();

        let env2 = MessageEnvelope::new("b", "agent", "direct", "second");
        let id2 = router.route_message(env2).unwrap();

        assert_eq!(router.last_message_id("agent"), Some(id2));
    }
}
