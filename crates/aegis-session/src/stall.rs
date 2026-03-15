//! Stall detection and nudge strategies.
//!
//! Tracks time since last agent output. When the configured timeout elapses,
//! sends nudge messages to the agent's stdin to prompt it to continue working.
//! After exhausting the configured number of nudges, signals that the agent
//! may need human intervention.

use std::time::{Duration, Instant};

use aegis_types::StallConfig;

/// Outcome of a stall check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StallAction {
    /// Agent is active (output received within timeout).
    Active,
    /// Agent is stalled; send this nudge message.
    Nudge(String),
    /// Max nudges exceeded; agent likely needs human attention.
    MaxNudgesExceeded,
}

/// Timer-based stall detector with nudge counting.
pub struct StallDetector {
    timeout: Duration,
    max_nudges: u32,
    nudge_message: String,
    last_activity: Instant,
    nudge_count: u32,
}

impl StallDetector {
    /// Create a new stall detector from configuration.
    pub fn new(config: &StallConfig) -> Self {
        Self {
            timeout: Duration::from_secs(config.timeout_secs),
            max_nudges: config.max_nudges,
            nudge_message: config.nudge_message.clone(),
            last_activity: Instant::now(),
            nudge_count: 0,
        }
    }

    /// Record that agent output was received, resetting the stall timer.
    pub fn activity(&mut self) {
        self.last_activity = Instant::now();
        self.nudge_count = 0;
    }

    /// Check whether the agent is stalled and return the appropriate action.
    ///
    /// Should be called periodically (e.g., when `poll()` times out).
    pub fn check(&mut self) -> StallAction {
        if self.last_activity.elapsed() < self.timeout {
            return StallAction::Active;
        }

        if self.nudge_count >= self.max_nudges {
            return StallAction::MaxNudgesExceeded;
        }

        self.nudge_count += 1;
        // Reset the timer so we wait another full timeout before the next nudge
        self.last_activity = Instant::now();
        StallAction::Nudge(self.nudge_message.clone())
    }

    /// Number of nudges sent so far in the current stall episode.
    pub fn nudge_count(&self) -> u32 {
        self.nudge_count
    }

    /// Duration since last activity.
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// The configured stall timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> StallConfig {
        StallConfig {
            timeout_secs: 0, // Immediate stall for testing
            max_nudges: 3,
            nudge_message: "keep going".into(),
        }
    }

    #[test]
    fn active_when_recent_output() {
        let config = StallConfig {
            timeout_secs: 60,
            max_nudges: 5,
            nudge_message: "continue".into(),
        };
        let mut detector = StallDetector::new(&config);
        detector.activity();
        assert_eq!(detector.check(), StallAction::Active);
    }

    #[test]
    fn nudges_on_stall() {
        let mut detector = StallDetector::new(&test_config());
        // With timeout_secs=0, should immediately stall
        std::thread::sleep(Duration::from_millis(1));

        match detector.check() {
            StallAction::Nudge(msg) => assert_eq!(msg, "keep going"),
            other => panic!("expected Nudge, got {other:?}"),
        }
        assert_eq!(detector.nudge_count(), 1);
    }

    #[test]
    fn max_nudges_exceeded() {
        let mut detector = StallDetector::new(&test_config());

        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(1));
            assert!(matches!(detector.check(), StallAction::Nudge(_)));
        }

        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(detector.check(), StallAction::MaxNudgesExceeded);
    }

    #[test]
    fn activity_resets_nudge_count() {
        let mut detector = StallDetector::new(&test_config());
        std::thread::sleep(Duration::from_millis(1));
        detector.check(); // nudge 1
        assert_eq!(detector.nudge_count(), 1);

        detector.activity();
        assert_eq!(detector.nudge_count(), 0);
    }
}
