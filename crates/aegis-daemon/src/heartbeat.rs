//! Heartbeat mechanism for keeping agents active.
//!
//! Provides a configurable periodic ping to supervised agents, tracking
//! last-activity timestamps per agent and optionally triggering deferred
//! reply delivery on each heartbeat cycle.
//!
//! # Usage
//!
//! ```ignore
//! let config = HeartbeatRunnerConfig {
//!     interval: Duration::from_secs(60),
//!     enabled: true,
//! };
//! let mut runner = HeartbeatRunner::new(config);
//! runner.register_agent("claude-1");
//! runner.record_activity("claude-1");
//!
//! for msg in runner.tick() {
//!     // send keepalive to agent
//! }
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Default heartbeat interval in seconds.
const DEFAULT_INTERVAL_SECS: u64 = 60;

/// Maximum allowed heartbeat interval (24 hours). Prevents misconfiguration.
const MAX_INTERVAL_SECS: u64 = 86_400;

/// Minimum allowed heartbeat interval (5 seconds). Prevents flooding.
const MIN_INTERVAL_SECS: u64 = 5;

/// Configuration for the heartbeat runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRunnerConfig {
    /// Interval between heartbeat ticks.
    #[serde(with = "duration_secs")]
    pub interval: Duration,
    /// Whether the heartbeat runner is enabled.
    pub enabled: bool,
}

impl Default for HeartbeatRunnerConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECS),
            enabled: true,
        }
    }
}

/// Validate a heartbeat interval.
///
/// Returns `Ok(())` if the interval is within the allowed range.
/// Returns `Err` with a descriptive message otherwise.
pub fn validate_interval(interval: Duration) -> Result<(), String> {
    let secs = interval.as_secs();
    if secs < MIN_INTERVAL_SECS {
        return Err(format!(
            "heartbeat interval too short: {secs}s < {MIN_INTERVAL_SECS}s minimum"
        ));
    }
    if secs > MAX_INTERVAL_SECS {
        return Err(format!(
            "heartbeat interval too long: {secs}s > {MAX_INTERVAL_SECS}s maximum"
        ));
    }
    Ok(())
}

/// Per-agent activity tracking state.
#[derive(Debug, Clone)]
struct AgentHeartbeatState {
    /// When this agent was registered.
    #[allow(dead_code)]
    registered_at: Instant,
    /// When the agent last showed activity (output, command, etc.).
    last_activity: Instant,
    /// When we last sent a keepalive to this agent.
    last_heartbeat_sent: Option<Instant>,
    /// How many heartbeats have been sent to this agent.
    heartbeat_count: u64,
}

/// A keepalive message to send to an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatMessage {
    /// The agent name/ID to send the keepalive to.
    pub agent_name: String,
    /// How long the agent has been idle (since last activity).
    pub idle_duration: Duration,
    /// The sequential heartbeat number for this agent.
    pub sequence: u64,
}

/// Heartbeat runner that tracks agent activity and generates keepalive messages.
///
/// Call [`tick`] periodically (at the configured interval) to get a list of
/// agents that need a keepalive message. The runner tracks last-activity
/// timestamps and only generates keepalives for agents that have been idle
/// since the last heartbeat.
pub struct HeartbeatRunner {
    config: HeartbeatRunnerConfig,
    agents: HashMap<String, AgentHeartbeatState>,
    last_tick: Option<Instant>,
}

impl HeartbeatRunner {
    /// Create a new heartbeat runner with the given configuration.
    pub fn new(config: HeartbeatRunnerConfig) -> Self {
        Self {
            config,
            agents: HashMap::new(),
            last_tick: None,
        }
    }

    /// Register an agent for heartbeat tracking.
    ///
    /// If the agent is already registered, this is a no-op.
    pub fn register_agent(&mut self, name: &str) {
        let now = Instant::now();
        self.agents
            .entry(name.to_string())
            .or_insert(AgentHeartbeatState {
                registered_at: now,
                last_activity: now,
                last_heartbeat_sent: None,
                heartbeat_count: 0,
            });
    }

    /// Remove an agent from heartbeat tracking.
    ///
    /// Returns `true` if the agent was registered and removed.
    pub fn unregister_agent(&mut self, name: &str) -> bool {
        self.agents.remove(name).is_some()
    }

    /// Record activity for an agent, resetting its idle timer.
    ///
    /// Returns `false` if the agent is not registered.
    pub fn record_activity(&mut self, name: &str) -> bool {
        if let Some(state) = self.agents.get_mut(name) {
            state.last_activity = Instant::now();
            true
        } else {
            false
        }
    }

    /// Get the idle duration for an agent (time since last activity).
    ///
    /// Returns `None` if the agent is not registered.
    pub fn idle_duration(&self, name: &str) -> Option<Duration> {
        self.agents.get(name).map(|s| s.last_activity.elapsed())
    }

    /// Check if it is time for a heartbeat tick.
    ///
    /// Returns `true` if enough time has elapsed since the last tick
    /// (or if no tick has happened yet).
    pub fn is_tick_due(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        match self.last_tick {
            None => true,
            Some(last) => last.elapsed() >= self.config.interval,
        }
    }

    /// Perform a heartbeat tick, returning keepalive messages for idle agents.
    ///
    /// An agent is considered "needing a keepalive" if it has been idle
    /// (no recorded activity) since the last heartbeat was sent to it,
    /// or if no heartbeat has ever been sent.
    ///
    /// This method updates internal timestamps. Call it at the configured
    /// interval (use [`is_tick_due`] to check).
    pub fn tick(&mut self) -> Vec<HeartbeatMessage> {
        if !self.config.enabled {
            return Vec::new();
        }

        let now = Instant::now();
        self.last_tick = Some(now);

        let mut messages = Vec::new();

        for (name, state) in &mut self.agents {
            // Send keepalive if: no heartbeat sent yet, OR agent has been
            // idle since the last heartbeat was sent.
            let needs_keepalive = match state.last_heartbeat_sent {
                None => true,
                Some(last_sent) => state.last_activity < last_sent,
            };

            if needs_keepalive {
                state.heartbeat_count += 1;
                state.last_heartbeat_sent = Some(now);

                messages.push(HeartbeatMessage {
                    agent_name: name.clone(),
                    idle_duration: now.duration_since(state.last_activity),
                    sequence: state.heartbeat_count,
                });
            }
        }

        // Sort by agent name for deterministic ordering in tests.
        messages.sort_by(|a, b| a.agent_name.cmp(&b.agent_name));
        messages
    }

    /// Get the number of registered agents.
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Get the total heartbeats sent to an agent.
    pub fn heartbeat_count(&self, name: &str) -> Option<u64> {
        self.agents.get(name).map(|s| s.heartbeat_count)
    }

    /// Check if the runner is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Update the heartbeat interval.
    ///
    /// Returns an error if the interval is out of the allowed range.
    pub fn set_interval(&mut self, interval: Duration) -> Result<(), String> {
        validate_interval(interval)?;
        self.config.interval = interval;
        Ok(())
    }

    /// Get the current heartbeat interval.
    pub fn interval(&self) -> Duration {
        self.config.interval
    }

    /// Enable or disable the heartbeat runner.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    /// List all registered agent names.
    pub fn registered_agents(&self) -> Vec<String> {
        let mut names: Vec<String> = self.agents.keys().cloned().collect();
        names.sort();
        names
    }
}

/// Serde helper for serializing Duration as seconds (u64).
mod duration_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn default_config_has_60s_interval() {
        let config = HeartbeatRunnerConfig::default();
        assert_eq!(config.interval, Duration::from_secs(60));
        assert!(config.enabled);
    }

    #[test]
    fn validate_interval_rejects_too_short() {
        assert!(validate_interval(Duration::from_secs(1)).is_err());
        assert!(validate_interval(Duration::from_secs(4)).is_err());
    }

    #[test]
    fn validate_interval_rejects_too_long() {
        assert!(validate_interval(Duration::from_secs(100_000)).is_err());
    }

    #[test]
    fn validate_interval_accepts_valid() {
        assert!(validate_interval(Duration::from_secs(5)).is_ok());
        assert!(validate_interval(Duration::from_secs(60)).is_ok());
        assert!(validate_interval(Duration::from_secs(3600)).is_ok());
        assert!(validate_interval(Duration::from_secs(86_400)).is_ok());
    }

    #[test]
    fn register_and_unregister_agents() {
        let mut runner = HeartbeatRunner::new(HeartbeatRunnerConfig::default());
        assert_eq!(runner.agent_count(), 0);

        runner.register_agent("agent-1");
        runner.register_agent("agent-2");
        assert_eq!(runner.agent_count(), 2);

        // Double register is no-op.
        runner.register_agent("agent-1");
        assert_eq!(runner.agent_count(), 2);

        assert!(runner.unregister_agent("agent-1"));
        assert_eq!(runner.agent_count(), 1);

        // Removing nonexistent returns false.
        assert!(!runner.unregister_agent("ghost"));
    }

    #[test]
    fn record_activity_returns_false_for_unknown_agent() {
        let mut runner = HeartbeatRunner::new(HeartbeatRunnerConfig::default());
        assert!(!runner.record_activity("unknown"));
    }

    #[test]
    fn record_activity_updates_timestamp() {
        let mut runner = HeartbeatRunner::new(HeartbeatRunnerConfig::default());
        runner.register_agent("agent-1");

        // Small sleep to create measurable idle time.
        thread::sleep(Duration::from_millis(10));

        let idle_before = runner.idle_duration("agent-1").unwrap();
        assert!(idle_before >= Duration::from_millis(10));

        runner.record_activity("agent-1");
        let idle_after = runner.idle_duration("agent-1").unwrap();
        assert!(idle_after < idle_before);
    }

    #[test]
    fn tick_generates_keepalives_for_idle_agents() {
        let config = HeartbeatRunnerConfig {
            interval: Duration::from_secs(5),
            enabled: true,
        };
        let mut runner = HeartbeatRunner::new(config);
        runner.register_agent("agent-1");
        runner.register_agent("agent-2");

        // First tick: all agents get keepalive (no heartbeat sent yet).
        let msgs = runner.tick();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].agent_name, "agent-1");
        assert_eq!(msgs[0].sequence, 1);
        assert_eq!(msgs[1].agent_name, "agent-2");
        assert_eq!(msgs[1].sequence, 1);

        // Second tick without activity: agents still idle, get another keepalive.
        let msgs = runner.tick();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].sequence, 2);

        // Record activity for agent-1 only.
        runner.record_activity("agent-1");

        // Third tick: only agent-2 gets keepalive (agent-1 is active).
        let msgs = runner.tick();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].agent_name, "agent-2");
        assert_eq!(msgs[0].sequence, 3);
    }

    #[test]
    fn tick_returns_empty_when_disabled() {
        let config = HeartbeatRunnerConfig {
            interval: Duration::from_secs(5),
            enabled: false,
        };
        let mut runner = HeartbeatRunner::new(config);
        runner.register_agent("agent-1");

        let msgs = runner.tick();
        assert!(msgs.is_empty());
    }

    #[test]
    fn is_tick_due_respects_interval() {
        let config = HeartbeatRunnerConfig {
            interval: Duration::from_millis(50),
            enabled: true,
        };
        let mut runner = HeartbeatRunner::new(config);

        // No tick yet, so it is due.
        assert!(runner.is_tick_due());

        runner.tick();

        // Just ticked, not due yet.
        assert!(!runner.is_tick_due());

        // Wait for interval to pass.
        thread::sleep(Duration::from_millis(60));
        assert!(runner.is_tick_due());
    }

    #[test]
    fn is_tick_due_returns_false_when_disabled() {
        let config = HeartbeatRunnerConfig {
            interval: Duration::from_millis(1),
            enabled: false,
        };
        let runner = HeartbeatRunner::new(config);
        assert!(!runner.is_tick_due());
    }

    #[test]
    fn heartbeat_count_tracks_per_agent() {
        let config = HeartbeatRunnerConfig {
            interval: Duration::from_secs(5),
            enabled: true,
        };
        let mut runner = HeartbeatRunner::new(config);
        runner.register_agent("agent-1");

        assert_eq!(runner.heartbeat_count("agent-1"), Some(0));

        runner.tick();
        assert_eq!(runner.heartbeat_count("agent-1"), Some(1));

        runner.tick();
        assert_eq!(runner.heartbeat_count("agent-1"), Some(2));

        assert_eq!(runner.heartbeat_count("unknown"), None);
    }

    #[test]
    fn set_interval_validates() {
        let mut runner = HeartbeatRunner::new(HeartbeatRunnerConfig::default());

        assert!(runner.set_interval(Duration::from_secs(30)).is_ok());
        assert_eq!(runner.interval(), Duration::from_secs(30));

        assert!(runner.set_interval(Duration::from_secs(1)).is_err());
        // Interval should not have changed.
        assert_eq!(runner.interval(), Duration::from_secs(30));
    }

    #[test]
    fn enable_disable_toggle() {
        let mut runner = HeartbeatRunner::new(HeartbeatRunnerConfig::default());
        assert!(runner.is_enabled());

        runner.set_enabled(false);
        assert!(!runner.is_enabled());

        runner.set_enabled(true);
        assert!(runner.is_enabled());
    }

    #[test]
    fn registered_agents_sorted() {
        let mut runner = HeartbeatRunner::new(HeartbeatRunnerConfig::default());
        runner.register_agent("zebra");
        runner.register_agent("alpha");
        runner.register_agent("middle");

        let names = runner.registered_agents();
        assert_eq!(names, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = HeartbeatRunnerConfig {
            interval: Duration::from_secs(120),
            enabled: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: HeartbeatRunnerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.interval, Duration::from_secs(120));
        assert!(back.enabled);
    }

    #[test]
    fn idle_duration_returns_none_for_unknown() {
        let runner = HeartbeatRunner::new(HeartbeatRunnerConfig::default());
        assert!(runner.idle_duration("unknown").is_none());
    }
}
