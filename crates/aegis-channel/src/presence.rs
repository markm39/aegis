//! Online/idle/offline presence tracking for channel participants.
//!
//! Tracks per-user, per-channel presence status with automatic idle timeout
//! detection. Presence updates are timestamped and can be queried for
//! display in the fleet TUI or forwarded to external channels.
//!
//! # Design
//!
//! - [`PresenceStatus`]: the four possible states (Online, Idle, Offline, DoNotDisturb).
//! - [`PresenceEntry`]: a single user's status with timestamps.
//! - [`PresenceTracker`]: manages entries across users and channels, with
//!   automatic idle detection based on configurable timeouts.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::debug;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default idle timeout: if no activity for this duration, transition Online -> Idle.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

/// Default offline timeout: if no activity for this duration after going Idle, transition to Offline.
const DEFAULT_OFFLINE_TIMEOUT: Duration = Duration::from_secs(900); // 15 minutes

/// Maximum length for a user ID.
const MAX_USER_ID_LEN: usize = 128;

/// Maximum length for a channel identifier.
const MAX_CHANNEL_ID_LEN: usize = 128;

/// Maximum tracked users per tracker instance.
const MAX_TRACKED_USERS: usize = 10_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Presence status of a user in a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PresenceStatus {
    /// User is actively online.
    Online,
    /// User is online but idle (no recent activity).
    Idle,
    /// User is offline (disconnected or timed out).
    Offline,
    /// User has explicitly set do-not-disturb.
    DoNotDisturb,
}

impl std::fmt::Display for PresenceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Online => write!(f, "online"),
            Self::Idle => write!(f, "idle"),
            Self::Offline => write!(f, "offline"),
            Self::DoNotDisturb => write!(f, "do_not_disturb"),
        }
    }
}

/// A single user's presence entry for a specific channel.
#[derive(Debug, Clone)]
pub struct PresenceEntry {
    /// User identifier.
    user_id: String,
    /// Channel identifier.
    channel_id: String,
    /// Current status.
    status: PresenceStatus,
    /// When the status was last changed.
    status_changed_at: Instant,
    /// When we last received any activity from this user.
    last_activity: Instant,
    /// Optional status message (e.g., "in a meeting").
    status_message: Option<String>,
}

impl PresenceEntry {
    /// Create a new entry in Online status.
    fn new(user_id: String, channel_id: String) -> Self {
        let now = Instant::now();
        Self {
            user_id,
            channel_id,
            status: PresenceStatus::Online,
            status_changed_at: now,
            last_activity: now,
            status_message: None,
        }
    }

    /// The user ID.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The channel ID.
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    /// Current presence status.
    pub fn status(&self) -> PresenceStatus {
        self.status
    }

    /// When the status was last changed.
    pub fn status_changed_at(&self) -> Instant {
        self.status_changed_at
    }

    /// When the last activity was recorded.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Optional status message.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// How long the user has been in the current status.
    pub fn duration_in_status(&self) -> Duration {
        self.status_changed_at.elapsed()
    }

    /// How long since the last activity.
    pub fn time_since_activity(&self) -> Duration {
        self.last_activity.elapsed()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from presence tracking operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceError {
    /// User not found in tracker.
    UserNotFound { user_id: String, channel_id: String },
    /// Invalid user or channel ID.
    InvalidId { value: String, reason: String },
    /// Too many tracked users.
    TooManyUsers { limit: usize },
}

impl std::fmt::Display for PresenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserNotFound {
                user_id,
                channel_id,
            } => {
                write!(f, "user {user_id:?} not found in channel {channel_id:?}")
            }
            Self::InvalidId { value, reason } => {
                write!(f, "invalid ID {value:?}: {reason}")
            }
            Self::TooManyUsers { limit } => {
                write!(f, "presence tracker user limit of {limit} exceeded")
            }
        }
    }
}

impl std::error::Error for PresenceError {}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_id(value: &str, kind: &str, max_len: usize) -> Result<(), PresenceError> {
    if value.is_empty() {
        return Err(PresenceError::InvalidId {
            value: value.to_string(),
            reason: format!("{kind} cannot be empty"),
        });
    }
    if value.len() > max_len {
        return Err(PresenceError::InvalidId {
            value: value.to_string(),
            reason: format!("{kind} exceeds maximum length of {max_len}"),
        });
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(PresenceError::InvalidId {
            value: value.to_string(),
            reason: format!("{kind} contains control characters"),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracker configuration
// ---------------------------------------------------------------------------

/// Configuration for the presence tracker's timeout behavior.
#[derive(Debug, Clone)]
pub struct PresenceTimeouts {
    /// Duration of inactivity before transitioning Online -> Idle.
    pub idle_timeout: Duration,
    /// Duration of inactivity (total) before transitioning to Offline.
    pub offline_timeout: Duration,
}

impl Default for PresenceTimeouts {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            offline_timeout: DEFAULT_OFFLINE_TIMEOUT,
        }
    }
}

// ---------------------------------------------------------------------------
// PresenceTracker
// ---------------------------------------------------------------------------

/// Composite key for a user+channel pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PresenceKey {
    user_id: String,
    channel_id: String,
}

/// Tracks online/idle/offline status for users across channels.
///
/// Call [`PresenceTracker::record_activity`] whenever a user does something,
/// and [`PresenceTracker::tick`] periodically to transition idle users.
#[derive(Debug)]
pub struct PresenceTracker {
    /// All tracked entries.
    entries: HashMap<PresenceKey, PresenceEntry>,
    /// Timeout configuration.
    timeouts: PresenceTimeouts,
}

impl PresenceTracker {
    /// Create a new tracker with default timeouts.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            timeouts: PresenceTimeouts::default(),
        }
    }

    /// Create a tracker with custom timeouts.
    pub fn with_timeouts(timeouts: PresenceTimeouts) -> Self {
        Self {
            entries: HashMap::new(),
            timeouts,
        }
    }

    /// Record activity from a user in a channel.
    ///
    /// If the user is not yet tracked, they are added as Online.
    /// If they are tracked and Idle/DoNotDisturb, they transition to Online.
    pub fn record_activity(
        &mut self,
        user_id: &str,
        channel_id: &str,
    ) -> Result<PresenceStatus, PresenceError> {
        validate_id(user_id, "user_id", MAX_USER_ID_LEN)?;
        validate_id(channel_id, "channel_id", MAX_CHANNEL_ID_LEN)?;

        let key = PresenceKey {
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
        };

        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_activity = Instant::now();
            if entry.status == PresenceStatus::Idle || entry.status == PresenceStatus::Offline {
                let old = entry.status;
                entry.status = PresenceStatus::Online;
                entry.status_changed_at = Instant::now();
                debug!(
                    user_id = %user_id,
                    channel_id = %channel_id,
                    old = %old,
                    new = "online",
                    "presence status changed on activity"
                );
            }
            Ok(entry.status)
        } else {
            if self.entries.len() >= MAX_TRACKED_USERS {
                return Err(PresenceError::TooManyUsers {
                    limit: MAX_TRACKED_USERS,
                });
            }
            let entry = PresenceEntry::new(user_id.to_string(), channel_id.to_string());
            let status = entry.status;
            self.entries.insert(key, entry);
            debug!(
                user_id = %user_id,
                channel_id = %channel_id,
                "new presence entry: online"
            );
            Ok(status)
        }
    }

    /// Explicitly set a user's status.
    pub fn set_status(
        &mut self,
        user_id: &str,
        channel_id: &str,
        status: PresenceStatus,
    ) -> Result<(), PresenceError> {
        let key = PresenceKey {
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
        };

        let entry = self
            .entries
            .get_mut(&key)
            .ok_or_else(|| PresenceError::UserNotFound {
                user_id: user_id.to_string(),
                channel_id: channel_id.to_string(),
            })?;

        if entry.status != status {
            debug!(
                user_id = %user_id,
                channel_id = %channel_id,
                old = %entry.status,
                new = %status,
                "presence status explicitly set"
            );
            entry.status = status;
            entry.status_changed_at = Instant::now();
        }
        Ok(())
    }

    /// Set a status message for a user.
    pub fn set_status_message(
        &mut self,
        user_id: &str,
        channel_id: &str,
        message: Option<String>,
    ) -> Result<(), PresenceError> {
        let key = PresenceKey {
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
        };

        let entry = self
            .entries
            .get_mut(&key)
            .ok_or_else(|| PresenceError::UserNotFound {
                user_id: user_id.to_string(),
                channel_id: channel_id.to_string(),
            })?;

        entry.status_message = message;
        Ok(())
    }

    /// Mark a user as offline and remove from tracking.
    pub fn disconnect(
        &mut self,
        user_id: &str,
        channel_id: &str,
    ) -> Result<PresenceEntry, PresenceError> {
        let key = PresenceKey {
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
        };

        self.entries
            .remove(&key)
            .ok_or_else(|| PresenceError::UserNotFound {
                user_id: user_id.to_string(),
                channel_id: channel_id.to_string(),
            })
    }

    /// Get a user's presence entry.
    pub fn get(&self, user_id: &str, channel_id: &str) -> Option<&PresenceEntry> {
        let key = PresenceKey {
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
        };
        self.entries.get(&key)
    }

    /// Get a user's current status, or Offline if not tracked.
    pub fn status_of(&self, user_id: &str, channel_id: &str) -> PresenceStatus {
        self.get(user_id, channel_id)
            .map(|e| e.status)
            .unwrap_or(PresenceStatus::Offline)
    }

    /// List all users in a specific channel with their status.
    pub fn users_in_channel(&self, channel_id: &str) -> Vec<(&str, PresenceStatus)> {
        self.entries
            .iter()
            .filter(|(k, _)| k.channel_id == channel_id)
            .map(|(_, e)| (e.user_id.as_str(), e.status))
            .collect()
    }

    /// List all channels a user is present in.
    pub fn channels_for_user(&self, user_id: &str) -> Vec<(&str, PresenceStatus)> {
        self.entries
            .iter()
            .filter(|(k, _)| k.user_id == user_id)
            .map(|(_, e)| (e.channel_id.as_str(), e.status))
            .collect()
    }

    /// Count users by status in a channel.
    pub fn count_by_status(&self, channel_id: &str) -> HashMap<PresenceStatus, usize> {
        let mut counts = HashMap::new();
        for (_, entry) in self
            .entries
            .iter()
            .filter(|(k, _)| k.channel_id == channel_id)
        {
            *counts.entry(entry.status).or_insert(0) += 1;
        }
        counts
    }

    /// Total number of tracked user-channel pairs.
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }

    /// Tick the tracker: transition users based on inactivity timeouts.
    ///
    /// Call this periodically (e.g., every 30 seconds). Returns a list of
    /// status changes that occurred: `(user_id, channel_id, old_status, new_status)`.
    pub fn tick(&mut self) -> Vec<(String, String, PresenceStatus, PresenceStatus)> {
        let mut changes = Vec::new();

        for entry in self.entries.values_mut() {
            // DoNotDisturb is manually set -- don't auto-transition
            if entry.status == PresenceStatus::DoNotDisturb {
                continue;
            }

            let elapsed = entry.last_activity.elapsed();

            let new_status = if elapsed >= self.timeouts.offline_timeout {
                PresenceStatus::Offline
            } else if elapsed >= self.timeouts.idle_timeout {
                PresenceStatus::Idle
            } else {
                PresenceStatus::Online
            };

            if new_status != entry.status {
                let old = entry.status;
                entry.status = new_status;
                entry.status_changed_at = Instant::now();
                changes.push((
                    entry.user_id.clone(),
                    entry.channel_id.clone(),
                    old,
                    new_status,
                ));
            }
        }

        changes
    }

    /// Remove all offline entries (garbage collection).
    pub fn reap_offline(&mut self) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| e.status != PresenceStatus::Offline);
        before - self.entries.len()
    }

    /// Clear all tracked entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for PresenceTracker {
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

    // -- PresenceStatus --

    #[test]
    fn status_display() {
        assert_eq!(PresenceStatus::Online.to_string(), "online");
        assert_eq!(PresenceStatus::Idle.to_string(), "idle");
        assert_eq!(PresenceStatus::Offline.to_string(), "offline");
        assert_eq!(PresenceStatus::DoNotDisturb.to_string(), "do_not_disturb");
    }

    #[test]
    fn status_equality() {
        assert_eq!(PresenceStatus::Online, PresenceStatus::Online);
        assert_ne!(PresenceStatus::Online, PresenceStatus::Idle);
    }

    // -- Validation --

    #[test]
    fn validate_id_empty_rejected() {
        let err = validate_id("", "test", 64).unwrap_err();
        assert!(matches!(err, PresenceError::InvalidId { .. }));
    }

    #[test]
    fn validate_id_too_long_rejected() {
        let long = "a".repeat(65);
        let err = validate_id(&long, "test", 64).unwrap_err();
        assert!(matches!(err, PresenceError::InvalidId { .. }));
    }

    #[test]
    fn validate_id_control_chars_rejected() {
        let err = validate_id("user\x00id", "test", 64).unwrap_err();
        assert!(matches!(err, PresenceError::InvalidId { .. }));
    }

    #[test]
    fn validate_id_valid() {
        assert!(validate_id("user-123", "test", 64).is_ok());
        assert!(validate_id("channel_abc", "test", 64).is_ok());
    }

    // -- PresenceEntry --

    #[test]
    fn entry_new_is_online() {
        let entry = PresenceEntry::new("user1".to_string(), "chan1".to_string());
        assert_eq!(entry.user_id(), "user1");
        assert_eq!(entry.channel_id(), "chan1");
        assert_eq!(entry.status(), PresenceStatus::Online);
        assert!(entry.status_message().is_none());
    }

    #[test]
    fn entry_duration_in_status() {
        let entry = PresenceEntry::new("u".to_string(), "c".to_string());
        // Just created, should be very small
        assert!(entry.duration_in_status() < Duration::from_secs(1));
    }

    #[test]
    fn entry_time_since_activity() {
        let entry = PresenceEntry::new("u".to_string(), "c".to_string());
        assert!(entry.time_since_activity() < Duration::from_secs(1));
    }

    // -- PresenceTracker basics --

    #[test]
    fn tracker_record_activity_new_user() {
        let mut tracker = PresenceTracker::new();
        let status = tracker.record_activity("user1", "chan1").unwrap();
        assert_eq!(status, PresenceStatus::Online);
        assert_eq!(tracker.tracked_count(), 1);
    }

    #[test]
    fn tracker_record_activity_existing_user() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("user1", "chan1").unwrap();
        let status = tracker.record_activity("user1", "chan1").unwrap();
        assert_eq!(status, PresenceStatus::Online);
        assert_eq!(tracker.tracked_count(), 1);
    }

    #[test]
    fn tracker_record_activity_invalid_user_id() {
        let mut tracker = PresenceTracker::new();
        let err = tracker.record_activity("", "chan1").unwrap_err();
        assert!(matches!(err, PresenceError::InvalidId { .. }));
    }

    #[test]
    fn tracker_record_activity_invalid_channel_id() {
        let mut tracker = PresenceTracker::new();
        let err = tracker.record_activity("user1", "").unwrap_err();
        assert!(matches!(err, PresenceError::InvalidId { .. }));
    }

    // -- Status operations --

    #[test]
    fn tracker_set_status() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("user1", "chan1").unwrap();

        tracker
            .set_status("user1", "chan1", PresenceStatus::DoNotDisturb)
            .unwrap();

        assert_eq!(
            tracker.status_of("user1", "chan1"),
            PresenceStatus::DoNotDisturb
        );
    }

    #[test]
    fn tracker_set_status_nonexistent() {
        let mut tracker = PresenceTracker::new();
        let err = tracker
            .set_status("ghost", "chan1", PresenceStatus::Online)
            .unwrap_err();
        assert!(matches!(err, PresenceError::UserNotFound { .. }));
    }

    #[test]
    fn tracker_set_status_message() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("user1", "chan1").unwrap();

        tracker
            .set_status_message("user1", "chan1", Some("in a meeting".to_string()))
            .unwrap();

        let entry = tracker.get("user1", "chan1").unwrap();
        assert_eq!(entry.status_message(), Some("in a meeting"));
    }

    #[test]
    fn tracker_clear_status_message() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("user1", "chan1").unwrap();
        tracker
            .set_status_message("user1", "chan1", Some("busy".to_string()))
            .unwrap();
        tracker.set_status_message("user1", "chan1", None).unwrap();

        let entry = tracker.get("user1", "chan1").unwrap();
        assert!(entry.status_message().is_none());
    }

    // -- Status queries --

    #[test]
    fn tracker_status_of_untracked_is_offline() {
        let tracker = PresenceTracker::new();
        assert_eq!(
            tracker.status_of("nobody", "nowhere"),
            PresenceStatus::Offline
        );
    }

    #[test]
    fn tracker_get_returns_none_for_untracked() {
        let tracker = PresenceTracker::new();
        assert!(tracker.get("nobody", "nowhere").is_none());
    }

    // -- Disconnect --

    #[test]
    fn tracker_disconnect() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("user1", "chan1").unwrap();

        let entry = tracker.disconnect("user1", "chan1").unwrap();
        assert_eq!(entry.user_id(), "user1");
        assert_eq!(tracker.tracked_count(), 0);
    }

    #[test]
    fn tracker_disconnect_nonexistent() {
        let mut tracker = PresenceTracker::new();
        let err = tracker.disconnect("ghost", "chan1").unwrap_err();
        assert!(matches!(err, PresenceError::UserNotFound { .. }));
    }

    // -- Channel/user queries --

    #[test]
    fn tracker_users_in_channel() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("alice", "general").unwrap();
        tracker.record_activity("bob", "general").unwrap();
        tracker.record_activity("alice", "random").unwrap();

        let users = tracker.users_in_channel("general");
        assert_eq!(users.len(), 2);
        assert!(users.iter().any(|(u, _)| *u == "alice"));
        assert!(users.iter().any(|(u, _)| *u == "bob"));
    }

    #[test]
    fn tracker_channels_for_user() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("alice", "general").unwrap();
        tracker.record_activity("alice", "random").unwrap();
        tracker.record_activity("bob", "general").unwrap();

        let channels = tracker.channels_for_user("alice");
        assert_eq!(channels.len(), 2);
    }

    #[test]
    fn tracker_count_by_status() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("alice", "gen").unwrap();
        tracker.record_activity("bob", "gen").unwrap();
        tracker
            .set_status("bob", "gen", PresenceStatus::DoNotDisturb)
            .unwrap();

        let counts = tracker.count_by_status("gen");
        assert_eq!(*counts.get(&PresenceStatus::Online).unwrap_or(&0), 1);
        assert_eq!(*counts.get(&PresenceStatus::DoNotDisturb).unwrap_or(&0), 1);
    }

    // -- Tick (idle detection) --

    #[test]
    fn tracker_tick_transitions_idle() {
        let mut tracker = PresenceTracker::with_timeouts(PresenceTimeouts {
            idle_timeout: Duration::from_millis(0), // immediate idle
            offline_timeout: Duration::from_secs(999),
        });

        tracker.record_activity("user1", "chan1").unwrap();
        // Sleep briefly so elapsed > 0
        std::thread::sleep(Duration::from_millis(1));

        let changes = tracker.tick();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].0, "user1");
        assert_eq!(changes[0].2, PresenceStatus::Online);
        assert_eq!(changes[0].3, PresenceStatus::Idle);
    }

    #[test]
    fn tracker_tick_transitions_offline() {
        let mut tracker = PresenceTracker::with_timeouts(PresenceTimeouts {
            idle_timeout: Duration::from_millis(0),
            offline_timeout: Duration::from_millis(0),
        });

        tracker.record_activity("user1", "chan1").unwrap();
        std::thread::sleep(Duration::from_millis(1));

        let changes = tracker.tick();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].3, PresenceStatus::Offline);
    }

    #[test]
    fn tracker_tick_dnd_not_transitioned() {
        let mut tracker = PresenceTracker::with_timeouts(PresenceTimeouts {
            idle_timeout: Duration::from_millis(0),
            offline_timeout: Duration::from_millis(0),
        });

        tracker.record_activity("user1", "chan1").unwrap();
        tracker
            .set_status("user1", "chan1", PresenceStatus::DoNotDisturb)
            .unwrap();
        std::thread::sleep(Duration::from_millis(1));

        let changes = tracker.tick();
        assert!(changes.is_empty());
        assert_eq!(
            tracker.status_of("user1", "chan1"),
            PresenceStatus::DoNotDisturb
        );
    }

    #[test]
    fn tracker_tick_no_changes_when_active() {
        let mut tracker = PresenceTracker::new(); // default 5min timeout
        tracker.record_activity("user1", "chan1").unwrap();

        let changes = tracker.tick();
        assert!(changes.is_empty());
    }

    // -- Activity reactivates idle users --

    #[test]
    fn tracker_activity_reactivates_idle() {
        let mut tracker = PresenceTracker::with_timeouts(PresenceTimeouts {
            idle_timeout: Duration::from_millis(0),
            offline_timeout: Duration::from_secs(999),
        });

        tracker.record_activity("user1", "chan1").unwrap();
        std::thread::sleep(Duration::from_millis(1));
        tracker.tick(); // transition to Idle

        assert_eq!(tracker.status_of("user1", "chan1"), PresenceStatus::Idle);

        // Activity should bring back to Online
        let status = tracker.record_activity("user1", "chan1").unwrap();
        assert_eq!(status, PresenceStatus::Online);
    }

    // -- Reap offline --

    #[test]
    fn tracker_reap_offline() {
        let mut tracker = PresenceTracker::with_timeouts(PresenceTimeouts {
            idle_timeout: Duration::from_millis(0),
            offline_timeout: Duration::from_millis(0),
        });

        tracker.record_activity("user1", "chan1").unwrap();
        tracker.record_activity("user2", "chan1").unwrap();
        std::thread::sleep(Duration::from_millis(1));
        tracker.tick();

        let reaped = tracker.reap_offline();
        assert_eq!(reaped, 2);
        assert_eq!(tracker.tracked_count(), 0);
    }

    // -- Clear --

    #[test]
    fn tracker_clear() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("user1", "chan1").unwrap();
        tracker.clear();
        assert_eq!(tracker.tracked_count(), 0);
    }

    // -- Default --

    #[test]
    fn tracker_default() {
        let tracker = PresenceTracker::default();
        assert_eq!(tracker.tracked_count(), 0);
    }

    // -- PresenceTimeouts --

    #[test]
    fn timeouts_default() {
        let t = PresenceTimeouts::default();
        assert_eq!(t.idle_timeout, Duration::from_secs(300));
        assert_eq!(t.offline_timeout, Duration::from_secs(900));
    }

    // -- Error Display --

    #[test]
    fn error_display() {
        assert_eq!(
            PresenceError::UserNotFound {
                user_id: "u".to_string(),
                channel_id: "c".to_string(),
            }
            .to_string(),
            "user \"u\" not found in channel \"c\""
        );
        assert_eq!(
            PresenceError::InvalidId {
                value: "x".to_string(),
                reason: "bad".to_string(),
            }
            .to_string(),
            "invalid ID \"x\": bad"
        );
        assert_eq!(
            PresenceError::TooManyUsers { limit: 5 }.to_string(),
            "presence tracker user limit of 5 exceeded"
        );
    }

    // -- Multiple channels per user --

    #[test]
    fn tracker_same_user_different_channels() {
        let mut tracker = PresenceTracker::new();
        tracker.record_activity("alice", "chan1").unwrap();
        tracker.record_activity("alice", "chan2").unwrap();

        assert_eq!(tracker.tracked_count(), 2);
        assert_eq!(tracker.status_of("alice", "chan1"), PresenceStatus::Online);
        assert_eq!(tracker.status_of("alice", "chan2"), PresenceStatus::Online);

        tracker
            .set_status("alice", "chan1", PresenceStatus::Idle)
            .unwrap();
        assert_eq!(tracker.status_of("alice", "chan1"), PresenceStatus::Idle);
        assert_eq!(tracker.status_of("alice", "chan2"), PresenceStatus::Online);
    }
}
