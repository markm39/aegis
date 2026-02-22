//! Per-sender session routing and isolation.
//!
//! The [`SessionRouter`] maps `(sender_id, channel_type)` pairs to active
//! session IDs, ensuring each sender gets their own session context. It
//! supports:
//!
//! - **Automatic routing:** Find or create sessions for incoming messages.
//! - **Thread binding:** Route thread-bound messages to the correct session.
//! - **Isolation:** Force a sender into their own isolated session.
//! - **Merging:** Combine two isolated sessions into one group (admin action).

use std::collections::HashMap;

use uuid::Uuid;

use aegis_ledger::AuditStore;
use aegis_types::AegisError;

/// Key for sender-session routing: (sender_id, channel_type).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SenderKey {
    /// The sender's unique identifier (e.g., Telegram user ID).
    pub sender_id: String,
    /// The channel type (e.g., "telegram", "slack").
    pub channel_type: String,
}

impl SenderKey {
    /// Create a new sender key.
    pub fn new(sender_id: impl Into<String>, channel_type: impl Into<String>) -> Self {
        Self {
            sender_id: sender_id.into(),
            channel_type: channel_type.into(),
        }
    }
}

/// Tracks which agent is handling which sender's session.
#[derive(Debug, Clone)]
pub struct AgentAssignment {
    /// The session ID for this sender.
    pub session_id: Uuid,
    /// The agent name handling this session.
    pub agent_name: String,
    /// Whether this session is isolated (won't be shared).
    pub isolated: bool,
}

/// Routes messages to the appropriate session based on sender and channel context.
///
/// Maintains an in-memory cache of active sender-to-session mappings with
/// optional agent assignments. Falls back to the audit store for persistent
/// session lookup when the cache misses.
pub struct SessionRouter {
    /// Active sender-to-session mappings.
    routes: HashMap<SenderKey, AgentAssignment>,
    /// Default config name used when creating new sessions.
    default_config: String,
}

impl SessionRouter {
    /// Create a new session router with the given default config name.
    pub fn new(default_config: impl Into<String>) -> Self {
        Self {
            routes: HashMap::new(),
            default_config: default_config.into(),
        }
    }

    /// Route a message to the appropriate session.
    ///
    /// Given a sender_id, channel_type, and optional thread_id, finds or
    /// creates the appropriate session:
    ///
    /// 1. Check the in-memory route cache.
    /// 2. If thread_id is provided, look for a thread-bound session in the store.
    /// 3. Look for a resumable session for this sender/channel pair in the store.
    /// 4. If nothing found, create a new session.
    ///
    /// Returns the session UUID and the agent name (if assigned).
    pub fn route_message(
        &mut self,
        store: &mut AuditStore,
        sender_id: &str,
        channel_type: &str,
        thread_id: Option<&str>,
        agent_name: &str,
    ) -> Result<Uuid, AegisError> {
        let key = SenderKey::new(sender_id, channel_type);

        // 1. Check the in-memory cache first.
        if let Some(assignment) = self.routes.get(&key) {
            return Ok(assignment.session_id);
        }

        // 2. If thread_id provided, look for thread-bound session.
        if let Some(tid) = thread_id {
            if let Some(session) = store.find_thread_session(tid)? {
                let assignment = AgentAssignment {
                    session_id: session.session_id,
                    agent_name: agent_name.to_string(),
                    isolated: false,
                };
                self.routes.insert(key, assignment);
                return Ok(session.session_id);
            }
        }

        // 3. Look for resumable session for this sender/channel.
        if let Some(session) = store.find_resumable_session(sender_id, channel_type)? {
            let assignment = AgentAssignment {
                session_id: session.session_id,
                agent_name: agent_name.to_string(),
                isolated: false,
            };
            self.routes.insert(key, assignment);
            return Ok(session.session_id);
        }

        // 4. Create a new session.
        let session_id = store.begin_session(
            &self.default_config,
            agent_name,
            &[],
            None,
        )?;

        // Set sender/channel/thread metadata on the new session.
        store.set_session_sender(session_id, sender_id, channel_type, thread_id)?;

        let assignment = AgentAssignment {
            session_id,
            agent_name: agent_name.to_string(),
            isolated: false,
        };
        self.routes.insert(key, assignment);

        tracing::info!(
            session_id = %session_id,
            sender_id,
            channel_type,
            agent_name,
            "created new routed session"
        );

        Ok(session_id)
    }

    /// Ensure a sender gets their own isolated session.
    ///
    /// If the sender already has a session in the cache, marks it as isolated.
    /// If not, creates a new isolated session. An isolated session won't be
    /// shared or merged with other sessions unless explicitly merged.
    pub fn isolate_session(
        &mut self,
        store: &mut AuditStore,
        sender_id: &str,
        channel_type: &str,
        agent_name: &str,
    ) -> Result<Uuid, AegisError> {
        let key = SenderKey::new(sender_id, channel_type);

        // If already assigned and isolated, return existing.
        if let Some(assignment) = self.routes.get(&key) {
            if assignment.isolated {
                return Ok(assignment.session_id);
            }
        }

        // Create a new isolated session.
        let session_id = store.begin_session(
            &self.default_config,
            agent_name,
            &[],
            Some("isolated"),
        )?;

        store.set_session_sender(session_id, sender_id, channel_type, None)?;

        let assignment = AgentAssignment {
            session_id,
            agent_name: agent_name.to_string(),
            isolated: true,
        };
        self.routes.insert(key, assignment);

        tracing::info!(
            session_id = %session_id,
            sender_id,
            channel_type,
            "created isolated session"
        );

        Ok(session_id)
    }

    /// Merge two sessions into one group.
    ///
    /// Sets both sessions to share the same group_id (the first session's ID
    /// if it has no group, or its existing group_id). This is an admin action
    /// to combine isolated sessions.
    pub fn merge_sessions(
        &mut self,
        store: &AuditStore,
        session_a: Uuid,
        session_b: Uuid,
    ) -> Result<Uuid, AegisError> {
        let a = store
            .get_session(&session_a)?
            .ok_or_else(|| AegisError::LedgerError(format!("session {session_a} not found")))?;

        let _b = store
            .get_session(&session_b)?
            .ok_or_else(|| AegisError::LedgerError(format!("session {session_b} not found")))?;

        // Use session A's group_id, or session A's own id if no group yet.
        let group_id = a.group_id.unwrap_or(session_a);

        // Update both sessions to share the group.
        store.set_session_group(session_a, group_id)?;
        store.set_session_group(session_b, group_id)?;

        // Update any cached route entries to remove isolation flags.
        for assignment in self.routes.values_mut() {
            if assignment.session_id == session_a || assignment.session_id == session_b {
                assignment.isolated = false;
            }
        }

        tracing::info!(
            group_id = %group_id,
            session_a = %session_a,
            session_b = %session_b,
            "merged sessions into group"
        );

        Ok(group_id)
    }

    /// Get the current route for a sender, if cached.
    pub fn get_route(&self, sender_id: &str, channel_type: &str) -> Option<&AgentAssignment> {
        let key = SenderKey::new(sender_id, channel_type);
        self.routes.get(&key)
    }

    /// Remove a route from the cache (e.g., when a session ends).
    pub fn remove_route(&mut self, sender_id: &str, channel_type: &str) {
        let key = SenderKey::new(sender_id, channel_type);
        self.routes.remove(&key);
    }

    /// List all active routes.
    pub fn list_routes(&self) -> Vec<(&SenderKey, &AgentAssignment)> {
        self.routes.iter().collect()
    }

    /// Clear all cached routes.
    pub fn clear(&mut self) {
        self.routes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn test_db() -> (NamedTempFile, AuditStore) {
        let tmp = NamedTempFile::new().expect("failed to create temp file");
        let store = AuditStore::open(tmp.path()).expect("failed to open store");
        (tmp, store)
    }

    #[test]
    fn route_message_creates_session() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        let session_id = router
            .route_message(&mut store, "user-1", "telegram", None, "agent-1")
            .unwrap();

        // Should have created a session
        let session = store.get_session(&session_id).unwrap().unwrap();
        assert_eq!(session.sender_id.as_deref(), Some("user-1"));
        assert_eq!(session.channel_type.as_deref(), Some("telegram"));
        assert!(session.resumable);
    }

    #[test]
    fn route_message_returns_cached_session() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        let id1 = router
            .route_message(&mut store, "user-1", "telegram", None, "agent-1")
            .unwrap();
        let id2 = router
            .route_message(&mut store, "user-1", "telegram", None, "agent-1")
            .unwrap();

        assert_eq!(id1, id2, "same sender should get same session from cache");
    }

    #[test]
    fn route_message_different_senders_get_different_sessions() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        let id1 = router
            .route_message(&mut store, "user-1", "telegram", None, "agent-1")
            .unwrap();
        let id2 = router
            .route_message(&mut store, "user-2", "telegram", None, "agent-1")
            .unwrap();

        assert_ne!(id1, id2, "different senders should get different sessions");
    }

    #[test]
    fn route_message_finds_resumable_session() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        // Create a session via the store directly (simulating a previous run)
        let existing_id = store
            .begin_session("test-config", "agent-1", &[], None)
            .unwrap();
        store
            .set_session_sender(existing_id, "user-1", "telegram", None)
            .unwrap();

        // Router should find and use the existing session
        let routed_id = router
            .route_message(&mut store, "user-1", "telegram", None, "agent-1")
            .unwrap();

        assert_eq!(routed_id, existing_id);
    }

    #[test]
    fn isolate_session_creates_isolated() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        let session_id = router
            .isolate_session(&mut store, "user-1", "telegram", "agent-1")
            .unwrap();

        let assignment = router.get_route("user-1", "telegram").unwrap();
        assert!(assignment.isolated);
        assert_eq!(assignment.session_id, session_id);

        let session = store.get_session(&session_id).unwrap().unwrap();
        assert_eq!(session.tag.as_deref(), Some("isolated"));
    }

    #[test]
    fn isolate_session_returns_existing_if_already_isolated() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        let id1 = router
            .isolate_session(&mut store, "user-1", "telegram", "agent-1")
            .unwrap();
        let id2 = router
            .isolate_session(&mut store, "user-1", "telegram", "agent-1")
            .unwrap();

        assert_eq!(id1, id2, "should reuse existing isolated session");
    }

    #[test]
    fn merge_sessions_sets_shared_group() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        let id_a = router
            .isolate_session(&mut store, "user-a", "telegram", "agent-1")
            .unwrap();
        let id_b = router
            .isolate_session(&mut store, "user-b", "telegram", "agent-1")
            .unwrap();

        let group_id = router.merge_sessions(&store, id_a, id_b).unwrap();

        let session_a = store.get_session(&id_a).unwrap().unwrap();
        let session_b = store.get_session(&id_b).unwrap().unwrap();

        assert_eq!(session_a.group_id, Some(group_id));
        assert_eq!(session_b.group_id, Some(group_id));

        // Isolation should be removed
        let route_a = router.get_route("user-a", "telegram").unwrap();
        assert!(!route_a.isolated);
    }

    #[test]
    fn merge_nonexistent_session_fails() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        let id_a = router
            .isolate_session(&mut store, "user-a", "telegram", "agent-1")
            .unwrap();

        let result = router.merge_sessions(&store, id_a, Uuid::new_v4());
        assert!(result.is_err());
    }

    #[test]
    fn remove_route_clears_cache() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        router
            .route_message(&mut store, "user-1", "telegram", None, "agent-1")
            .unwrap();

        assert!(router.get_route("user-1", "telegram").is_some());
        router.remove_route("user-1", "telegram");
        assert!(router.get_route("user-1", "telegram").is_none());
    }

    #[test]
    fn list_routes_returns_all_active() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        router
            .route_message(&mut store, "user-1", "telegram", None, "agent-1")
            .unwrap();
        router
            .route_message(&mut store, "user-2", "slack", None, "agent-2")
            .unwrap();

        let routes = router.list_routes();
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn clear_removes_all_routes() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        router
            .route_message(&mut store, "user-1", "telegram", None, "agent-1")
            .unwrap();
        router
            .route_message(&mut store, "user-2", "slack", None, "agent-2")
            .unwrap();

        assert_eq!(router.list_routes().len(), 2);
        router.clear();
        assert!(router.list_routes().is_empty());
    }

    #[test]
    fn route_message_with_thread_id() {
        let (_tmp, mut store) = test_db();
        let mut router = SessionRouter::new("test-config");

        // Create a session with a thread_id
        let existing_id = store
            .begin_session("test-config", "agent-1", &[], None)
            .unwrap();
        store
            .set_session_sender(existing_id, "user-1", "telegram", Some("thread-abc"))
            .unwrap();

        // Route with the same thread_id -- should find existing
        let routed_id = router
            .route_message(
                &mut store,
                "user-1",
                "telegram",
                Some("thread-abc"),
                "agent-1",
            )
            .unwrap();

        assert_eq!(routed_id, existing_id);
    }
}
