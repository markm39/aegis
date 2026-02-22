//! Broadcast groups for routing group chat messages to multiple agents.
//!
//! A [`BroadcastGroup`] fans out inbound messages from a group chat to
//! multiple agents simultaneously. Outbound messages from agents are sent
//! back to the group, with deduplication to prevent echo loops when
//! multiple agents respond in the same group.
//!
//! # Dispatch Strategies
//!
//! - [`DispatchStrategy::All`]: Every agent in the group receives each message.
//! - [`DispatchStrategy::RoundRobin`]: Messages rotate across agents in order.
//!
//! # Deduplication
//!
//! Each group maintains a ring buffer of recent message fingerprints (SHA-256
//! of the content). When an agent sends a message to the group, its
//! fingerprint is recorded. If the same content arrives as an inbound
//! message within the dedup window, it is suppressed to prevent echo loops.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Maximum number of agents in a single broadcast group.
const MAX_AGENTS_PER_GROUP: usize = 32;

/// Maximum number of groups in a broadcast group manager.
const MAX_GROUPS: usize = 128;

/// Maximum length for a group name.
const MAX_GROUP_NAME_LEN: usize = 64;

/// Maximum length for an agent name.
const MAX_AGENT_NAME_LEN: usize = 64;

/// Default deduplication window size (number of recent fingerprints to keep).
const DEFAULT_DEDUP_WINDOW_SIZE: usize = 100;

/// Default deduplication expiry duration.
const DEFAULT_DEDUP_EXPIRY: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Strategy for dispatching inbound messages to agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchStrategy {
    /// Every agent in the group receives each message.
    All,
    /// Messages rotate across agents in round-robin order.
    RoundRobin,
}

/// A routed message with target agent names.
#[derive(Debug, Clone)]
pub struct RoutedMessage {
    /// The message content.
    pub content: String,
    /// The source group name.
    pub group: String,
    /// Target agent names that should receive this message.
    pub targets: Vec<String>,
}

/// A fingerprinted message for dedup tracking.
#[derive(Debug, Clone)]
struct DedupEntry {
    /// SHA-256 fingerprint of the message content.
    fingerprint: [u8; 32],
    /// When this entry was recorded.
    timestamp: Instant,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a group or agent name: alphanumeric + dash/underscore, max length.
fn validate_name(name: &str, kind: &str, max_len: usize) -> Result<(), BroadcastError> {
    if name.is_empty() {
        return Err(BroadcastError::InvalidName {
            name: name.to_string(),
            reason: format!("{kind} name cannot be empty"),
        });
    }
    if name.len() > max_len {
        return Err(BroadcastError::InvalidName {
            name: name.to_string(),
            reason: format!("{kind} name exceeds maximum length of {max_len}"),
        });
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(BroadcastError::InvalidName {
            name: name.to_string(),
            reason: format!(
                "{kind} name may only contain ASCII letters, digits, hyphens, and underscores"
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from broadcast group operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastError {
    /// The group name or agent name is invalid.
    InvalidName { name: String, reason: String },
    /// The group already exists.
    GroupExists { name: String },
    /// The group does not exist.
    GroupNotFound { name: String },
    /// Too many agents in the group.
    TooManyAgents { group: String, limit: usize },
    /// Too many groups.
    TooManyGroups { limit: usize },
    /// The agent is already in the group.
    AgentAlreadyInGroup { group: String, agent: String },
    /// The agent is not in the group.
    AgentNotInGroup { group: String, agent: String },
    /// The message was deduplicated (echo suppression).
    Deduplicated,
}

impl std::fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName { name, reason } => {
                write!(f, "invalid name {name:?}: {reason}")
            }
            Self::GroupExists { name } => write!(f, "group {name:?} already exists"),
            Self::GroupNotFound { name } => write!(f, "group {name:?} not found"),
            Self::TooManyAgents { group, limit } => {
                write!(f, "group {group:?} exceeds agent limit of {limit}")
            }
            Self::TooManyGroups { limit } => {
                write!(f, "broadcast group limit of {limit} exceeded")
            }
            Self::AgentAlreadyInGroup { group, agent } => {
                write!(f, "agent {agent:?} already in group {group:?}")
            }
            Self::AgentNotInGroup { group, agent } => {
                write!(f, "agent {agent:?} not in group {group:?}")
            }
            Self::Deduplicated => write!(f, "message deduplicated (echo suppression)"),
        }
    }
}

impl std::error::Error for BroadcastError {}

// ---------------------------------------------------------------------------
// BroadcastGroup
// ---------------------------------------------------------------------------

/// A single broadcast group mapping a group chat to multiple agents.
#[derive(Debug)]
pub struct BroadcastGroup {
    /// Group name (validated).
    name: String,
    /// Agent names in this group.
    agents: Vec<String>,
    /// Dispatch strategy.
    strategy: DispatchStrategy,
    /// Round-robin index (only used with RoundRobin strategy).
    rr_index: usize,
    /// Recent message fingerprints for dedup.
    dedup_ring: VecDeque<DedupEntry>,
    /// Maximum dedup ring size.
    dedup_window_size: usize,
    /// Dedup expiry duration.
    dedup_expiry: Duration,
}

impl BroadcastGroup {
    /// Create a new broadcast group.
    pub fn new(
        name: impl Into<String>,
        strategy: DispatchStrategy,
    ) -> Result<Self, BroadcastError> {
        let name = name.into();
        validate_name(&name, "group", MAX_GROUP_NAME_LEN)?;

        Ok(Self {
            name,
            agents: Vec::new(),
            strategy,
            rr_index: 0,
            dedup_ring: VecDeque::new(),
            dedup_window_size: DEFAULT_DEDUP_WINDOW_SIZE,
            dedup_expiry: DEFAULT_DEDUP_EXPIRY,
        })
    }

    /// Create a new broadcast group with custom dedup settings.
    pub fn with_dedup(
        name: impl Into<String>,
        strategy: DispatchStrategy,
        dedup_window_size: usize,
        dedup_expiry: Duration,
    ) -> Result<Self, BroadcastError> {
        let name = name.into();
        validate_name(&name, "group", MAX_GROUP_NAME_LEN)?;

        Ok(Self {
            name,
            agents: Vec::new(),
            strategy,
            rr_index: 0,
            dedup_ring: VecDeque::new(),
            dedup_window_size,
            dedup_expiry,
        })
    }

    /// The group name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The dispatch strategy.
    pub fn strategy(&self) -> DispatchStrategy {
        self.strategy
    }

    /// List agents in this group.
    pub fn agents(&self) -> &[String] {
        &self.agents
    }

    /// Add an agent to this group.
    pub fn add_agent(&mut self, agent: impl Into<String>) -> Result<(), BroadcastError> {
        let agent = agent.into();
        validate_name(&agent, "agent", MAX_AGENT_NAME_LEN)?;

        if self.agents.len() >= MAX_AGENTS_PER_GROUP {
            return Err(BroadcastError::TooManyAgents {
                group: self.name.clone(),
                limit: MAX_AGENTS_PER_GROUP,
            });
        }
        if self.agents.contains(&agent) {
            return Err(BroadcastError::AgentAlreadyInGroup {
                group: self.name.clone(),
                agent,
            });
        }

        self.agents.push(agent);
        Ok(())
    }

    /// Remove an agent from this group.
    pub fn remove_agent(&mut self, agent: &str) -> Result<(), BroadcastError> {
        let pos = self.agents.iter().position(|a| a == agent);
        match pos {
            Some(idx) => {
                self.agents.remove(idx);
                // Adjust round-robin index if needed
                if self.rr_index > 0 && idx <= self.rr_index {
                    self.rr_index = self.rr_index.saturating_sub(1);
                }
                Ok(())
            }
            None => Err(BroadcastError::AgentNotInGroup {
                group: self.name.clone(),
                agent: agent.to_string(),
            }),
        }
    }

    /// Compute the SHA-256 fingerprint of a message.
    fn fingerprint(content: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hasher.finalize().into()
    }

    /// Record an outbound message fingerprint for dedup.
    ///
    /// Call this when an agent sends a message to the group, so that
    /// the same content arriving as an inbound message is suppressed.
    pub fn record_outbound(&mut self, content: &str) {
        let fp = Self::fingerprint(content);
        self.dedup_ring.push_back(DedupEntry {
            fingerprint: fp,
            timestamp: Instant::now(),
        });

        // Trim the ring buffer
        while self.dedup_ring.len() > self.dedup_window_size {
            self.dedup_ring.pop_front();
        }
    }

    /// Check if a message should be deduplicated (is an echo).
    ///
    /// Returns `true` if the message matches a recent outbound fingerprint
    /// and should be suppressed.
    pub fn is_echo(&self, content: &str) -> bool {
        let fp = Self::fingerprint(content);
        let now = Instant::now();

        self.dedup_ring.iter().any(|entry| {
            entry.fingerprint == fp && now.duration_since(entry.timestamp) < self.dedup_expiry
        })
    }

    /// Expire old dedup entries.
    pub fn expire_dedup(&mut self) {
        let now = Instant::now();
        while let Some(front) = self.dedup_ring.front() {
            if now.duration_since(front.timestamp) >= self.dedup_expiry {
                self.dedup_ring.pop_front();
            } else {
                break;
            }
        }
    }

    /// Route an inbound message to the appropriate agents based on strategy.
    ///
    /// Returns a `RoutedMessage` with the target agent names, or
    /// `Err(BroadcastError::Deduplicated)` if the message is an echo.
    pub fn route_inbound(&mut self, content: &str) -> Result<RoutedMessage, BroadcastError> {
        // Check dedup first
        if self.is_echo(content) {
            debug!(
                group = %self.name,
                "suppressing echo message (dedup hit)"
            );
            return Err(BroadcastError::Deduplicated);
        }

        // Expire old entries
        self.expire_dedup();

        if self.agents.is_empty() {
            warn!(group = %self.name, "no agents in broadcast group");
            return Ok(RoutedMessage {
                content: content.to_string(),
                group: self.name.clone(),
                targets: Vec::new(),
            });
        }

        let targets = match self.strategy {
            DispatchStrategy::All => self.agents.clone(),
            DispatchStrategy::RoundRobin => {
                let idx = self.rr_index % self.agents.len();
                self.rr_index = (self.rr_index + 1) % self.agents.len();
                vec![self.agents[idx].clone()]
            }
        };

        Ok(RoutedMessage {
            content: content.to_string(),
            group: self.name.clone(),
            targets,
        })
    }
}

// ---------------------------------------------------------------------------
// BroadcastGroupManager
// ---------------------------------------------------------------------------

/// Manages multiple broadcast groups.
///
/// Provides a registry of groups and routes messages to the correct group
/// based on group name lookup.
#[derive(Debug)]
pub struct BroadcastGroupManager {
    groups: HashMap<String, BroadcastGroup>,
}

impl BroadcastGroupManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Add a new broadcast group.
    pub fn add_group(&mut self, group: BroadcastGroup) -> Result<(), BroadcastError> {
        if self.groups.len() >= MAX_GROUPS {
            return Err(BroadcastError::TooManyGroups { limit: MAX_GROUPS });
        }
        if self.groups.contains_key(group.name()) {
            return Err(BroadcastError::GroupExists {
                name: group.name().to_string(),
            });
        }

        self.groups.insert(group.name().to_string(), group);
        Ok(())
    }

    /// Remove a broadcast group by name.
    pub fn remove_group(&mut self, name: &str) -> Result<BroadcastGroup, BroadcastError> {
        self.groups.remove(name).ok_or_else(|| BroadcastError::GroupNotFound {
            name: name.to_string(),
        })
    }

    /// Get a reference to a group by name.
    pub fn get_group(&self, name: &str) -> Option<&BroadcastGroup> {
        self.groups.get(name)
    }

    /// Get a mutable reference to a group by name.
    pub fn get_group_mut(&mut self, name: &str) -> Option<&mut BroadcastGroup> {
        self.groups.get_mut(name)
    }

    /// List all group names.
    pub fn list_groups(&self) -> Vec<&str> {
        self.groups.keys().map(|k| k.as_str()).collect()
    }

    /// Route an inbound message to the named group.
    pub fn route_to_group(
        &mut self,
        group_name: &str,
        content: &str,
    ) -> Result<RoutedMessage, BroadcastError> {
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| BroadcastError::GroupNotFound {
                name: group_name.to_string(),
            })?;

        group.route_inbound(content)
    }

    /// Record an outbound message from an agent in the named group (for dedup).
    pub fn record_outbound(
        &mut self,
        group_name: &str,
        content: &str,
    ) -> Result<(), BroadcastError> {
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| BroadcastError::GroupNotFound {
                name: group_name.to_string(),
            })?;

        group.record_outbound(content);
        Ok(())
    }

    /// Find all groups that a given agent belongs to.
    pub fn groups_for_agent(&self, agent: &str) -> Vec<&str> {
        self.groups
            .values()
            .filter(|g| g.agents.contains(&agent.to_string()))
            .map(|g| g.name())
            .collect()
    }
}

impl Default for BroadcastGroupManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Validation --

    #[test]
    fn test_valid_group_names() {
        assert!(BroadcastGroup::new("my-group", DispatchStrategy::All).is_ok());
        assert!(BroadcastGroup::new("group_123", DispatchStrategy::RoundRobin).is_ok());
        assert!(BroadcastGroup::new("A", DispatchStrategy::All).is_ok());
    }

    #[test]
    fn test_invalid_group_names() {
        assert!(BroadcastGroup::new("", DispatchStrategy::All).is_err());
        assert!(BroadcastGroup::new("has spaces", DispatchStrategy::All).is_err());
        assert!(BroadcastGroup::new("has.dot", DispatchStrategy::All).is_err());
        let long = "a".repeat(MAX_GROUP_NAME_LEN + 1);
        assert!(BroadcastGroup::new(&long, DispatchStrategy::All).is_err());
    }

    // -- Agent management --

    #[test]
    fn test_add_remove_agents() {
        let mut group = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        group.add_agent("agent-1").unwrap();
        group.add_agent("agent-2").unwrap();
        assert_eq!(group.agents().len(), 2);

        group.remove_agent("agent-1").unwrap();
        assert_eq!(group.agents().len(), 1);
        assert_eq!(group.agents()[0], "agent-2");
    }

    #[test]
    fn test_duplicate_agent_rejected() {
        let mut group = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        group.add_agent("agent-1").unwrap();
        let err = group.add_agent("agent-1").unwrap_err();
        assert!(matches!(err, BroadcastError::AgentAlreadyInGroup { .. }));
    }

    #[test]
    fn test_remove_nonexistent_agent() {
        let mut group = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        let err = group.remove_agent("ghost").unwrap_err();
        assert!(matches!(err, BroadcastError::AgentNotInGroup { .. }));
    }

    #[test]
    fn test_agent_limit() {
        let mut group = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        for i in 0..MAX_AGENTS_PER_GROUP {
            group.add_agent(format!("agent-{i}")).unwrap();
        }
        let err = group.add_agent("one-too-many").unwrap_err();
        assert!(matches!(err, BroadcastError::TooManyAgents { .. }));
    }

    // -- Dispatch strategies --

    #[test]
    fn test_all_strategy_routes_to_all() {
        let mut group = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        group.add_agent("agent-1").unwrap();
        group.add_agent("agent-2").unwrap();
        group.add_agent("agent-3").unwrap();

        let routed = group.route_inbound("hello").unwrap();
        assert_eq!(routed.targets.len(), 3);
        assert!(routed.targets.contains(&"agent-1".to_string()));
        assert!(routed.targets.contains(&"agent-2".to_string()));
        assert!(routed.targets.contains(&"agent-3".to_string()));
    }

    #[test]
    fn test_round_robin_strategy() {
        let mut group = BroadcastGroup::new("test", DispatchStrategy::RoundRobin).unwrap();
        group.add_agent("agent-1").unwrap();
        group.add_agent("agent-2").unwrap();
        group.add_agent("agent-3").unwrap();

        let r1 = group.route_inbound("msg1").unwrap();
        assert_eq!(r1.targets, vec!["agent-1"]);

        let r2 = group.route_inbound("msg2").unwrap();
        assert_eq!(r2.targets, vec!["agent-2"]);

        let r3 = group.route_inbound("msg3").unwrap();
        assert_eq!(r3.targets, vec!["agent-3"]);

        // Wraps around
        let r4 = group.route_inbound("msg4").unwrap();
        assert_eq!(r4.targets, vec!["agent-1"]);
    }

    // -- Deduplication --

    #[test]
    fn test_echo_dedup() {
        let mut group = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        group.add_agent("agent-1").unwrap();

        // Record outbound message
        group.record_outbound("hello world");

        // Same content as inbound should be suppressed
        let result = group.route_inbound("hello world");
        assert!(matches!(result, Err(BroadcastError::Deduplicated)));

        // Different content should pass through
        let result = group.route_inbound("different message");
        assert!(result.is_ok());
    }

    #[test]
    fn test_dedup_window_overflow() {
        let mut group = BroadcastGroup::with_dedup(
            "test",
            DispatchStrategy::All,
            5,  // small window
            Duration::from_secs(60),
        )
        .unwrap();
        group.add_agent("agent-1").unwrap();

        // Fill the window
        for i in 0..10 {
            group.record_outbound(&format!("msg-{i}"));
        }

        // Oldest entries should have been evicted
        assert!(group.dedup_ring.len() <= 5);

        // Early messages should no longer be in the dedup ring
        assert!(!group.is_echo("msg-0"));
        assert!(!group.is_echo("msg-1"));

        // Recent messages should still be deduplicated
        assert!(group.is_echo("msg-9"));
    }

    #[test]
    fn test_is_echo_with_no_outbound() {
        let group = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        assert!(!group.is_echo("anything"));
    }

    // -- Manager --

    #[test]
    fn test_manager_add_remove_groups() {
        let mut mgr = BroadcastGroupManager::new();

        let group = BroadcastGroup::new("group-1", DispatchStrategy::All).unwrap();
        mgr.add_group(group).unwrap();

        assert!(mgr.get_group("group-1").is_some());
        assert!(mgr.get_group("nonexistent").is_none());

        let removed = mgr.remove_group("group-1").unwrap();
        assert_eq!(removed.name(), "group-1");
        assert!(mgr.get_group("group-1").is_none());
    }

    #[test]
    fn test_manager_duplicate_group_rejected() {
        let mut mgr = BroadcastGroupManager::new();

        let g1 = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        mgr.add_group(g1).unwrap();

        let g2 = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        let err = mgr.add_group(g2).unwrap_err();
        assert!(matches!(err, BroadcastError::GroupExists { .. }));
    }

    #[test]
    fn test_manager_route_to_group() {
        let mut mgr = BroadcastGroupManager::new();

        let mut group = BroadcastGroup::new("dev-team", DispatchStrategy::All).unwrap();
        group.add_agent("claude-1").unwrap();
        group.add_agent("codex-1").unwrap();
        mgr.add_group(group).unwrap();

        let routed = mgr.route_to_group("dev-team", "fix the bug").unwrap();
        assert_eq!(routed.group, "dev-team");
        assert_eq!(routed.targets.len(), 2);
    }

    #[test]
    fn test_manager_route_to_nonexistent_group() {
        let mut mgr = BroadcastGroupManager::new();
        let err = mgr.route_to_group("ghost", "msg").unwrap_err();
        assert!(matches!(err, BroadcastError::GroupNotFound { .. }));
    }

    #[test]
    fn test_manager_record_outbound() {
        let mut mgr = BroadcastGroupManager::new();

        let mut group = BroadcastGroup::new("test", DispatchStrategy::All).unwrap();
        group.add_agent("agent-1").unwrap();
        mgr.add_group(group).unwrap();

        mgr.record_outbound("test", "agent response").unwrap();

        // Should now be deduplicated
        let result = mgr.route_to_group("test", "agent response");
        assert!(matches!(result, Err(BroadcastError::Deduplicated)));
    }

    #[test]
    fn test_manager_groups_for_agent() {
        let mut mgr = BroadcastGroupManager::new();

        let mut g1 = BroadcastGroup::new("group-1", DispatchStrategy::All).unwrap();
        g1.add_agent("claude-1").unwrap();
        g1.add_agent("codex-1").unwrap();
        mgr.add_group(g1).unwrap();

        let mut g2 = BroadcastGroup::new("group-2", DispatchStrategy::All).unwrap();
        g2.add_agent("claude-1").unwrap();
        mgr.add_group(g2).unwrap();

        let groups = mgr.groups_for_agent("claude-1");
        assert_eq!(groups.len(), 2);

        let groups = mgr.groups_for_agent("codex-1");
        assert_eq!(groups.len(), 1);

        let groups = mgr.groups_for_agent("nobody");
        assert!(groups.is_empty());
    }

    #[test]
    fn test_manager_list_groups() {
        let mut mgr = BroadcastGroupManager::new();

        let g1 = BroadcastGroup::new("alpha", DispatchStrategy::All).unwrap();
        let g2 = BroadcastGroup::new("beta", DispatchStrategy::RoundRobin).unwrap();
        mgr.add_group(g1).unwrap();
        mgr.add_group(g2).unwrap();

        let mut names = mgr.list_groups();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_empty_group_routes_to_no_targets() {
        let mut group = BroadcastGroup::new("empty", DispatchStrategy::All).unwrap();
        let routed = group.route_inbound("hello").unwrap();
        assert!(routed.targets.is_empty());
    }

    #[test]
    fn test_round_robin_with_agent_removal() {
        let mut group = BroadcastGroup::new("test", DispatchStrategy::RoundRobin).unwrap();
        group.add_agent("a").unwrap();
        group.add_agent("b").unwrap();
        group.add_agent("c").unwrap();

        // Advance to agent "b" (index 1)
        let _ = group.route_inbound("msg1"); // targets "a", advances to 1
        let r = group.route_inbound("msg2").unwrap(); // targets "b", advances to 2
        assert_eq!(r.targets, vec!["b"]);

        // Remove "a" (index 0) -- should adjust rr_index
        group.remove_agent("a").unwrap();
        // Now agents = ["b", "c"], rr_index was 2, adjusted to 1
        let r = group.route_inbound("msg3").unwrap();
        assert_eq!(r.targets, vec!["c"]);
    }

    #[test]
    fn test_default_manager() {
        let mgr = BroadcastGroupManager::default();
        assert!(mgr.list_groups().is_empty());
    }

    #[test]
    fn test_error_display() {
        let err = BroadcastError::GroupNotFound {
            name: "test".to_string(),
        };
        assert_eq!(err.to_string(), "group \"test\" not found");

        let err = BroadcastError::Deduplicated;
        assert_eq!(err.to_string(), "message deduplicated (echo suppression)");
    }

    #[test]
    fn test_routed_message_fields() {
        let msg = RoutedMessage {
            content: "hello".to_string(),
            group: "team".to_string(),
            targets: vec!["agent-1".to_string()],
        };
        assert_eq!(msg.content, "hello");
        assert_eq!(msg.group, "team");
        assert_eq!(msg.targets.len(), 1);
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let fp1 = BroadcastGroup::fingerprint("hello");
        let fp2 = BroadcastGroup::fingerprint("hello");
        assert_eq!(fp1, fp2);

        let fp3 = BroadcastGroup::fingerprint("different");
        assert_ne!(fp1, fp3);
    }
}
