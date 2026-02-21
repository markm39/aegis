//! Named execution lanes with configurable concurrency limits.
//!
//! Lanes partition concurrent agent execution into named groups, each with an
//! optional concurrency cap. Agents assigned to a lane must acquire a slot
//! before running; if the lane is full they are queued in priority order.
//!
//! Security invariants:
//! - Lane names are validated (alphanumeric + dash/underscore, max 64 chars).
//! - At most [`MAX_LANES`] lanes can exist (prevents unbounded allocation).
//! - Queued agents cannot bypass lane limits; the only path to execution is
//!   through [`LaneManager::acquire`].
//! - All acquire/release operations are designed for audit logging by callers.

use std::collections::HashMap;

use aegis_types::daemon::{validate_lane_name, LaneConfig, MAX_LANES};
use serde::{Deserialize, Serialize};

/// Default lane name used when an agent has no explicit lane assignment.
pub const DEFAULT_LANE: &str = "default";

/// A single execution lane with concurrency tracking.
#[derive(Debug, Clone)]
pub struct ExecutionLane {
    /// Lane name.
    pub name: String,
    /// Maximum concurrent agents (0 = unlimited).
    pub max_concurrent: usize,
    /// Number of agents currently holding a slot.
    pub current: usize,
    /// Priority (higher = more important, 0-255).
    pub priority: u8,
    /// Agents waiting for a slot, in insertion order.
    pub queued_agents: Vec<String>,
}

impl ExecutionLane {
    /// Whether this lane has capacity for another agent.
    fn has_capacity(&self) -> bool {
        self.max_concurrent == 0 || self.current < self.max_concurrent
    }
}

/// Snapshot of a lane's current utilization, suitable for serialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LaneStatus {
    /// Lane name.
    pub name: String,
    /// Number of agents currently holding a slot.
    pub current: usize,
    /// Maximum concurrent agents (0 = unlimited).
    pub max_concurrent: usize,
    /// Number of agents queued waiting for a slot.
    pub queued: usize,
    /// Lane priority.
    pub priority: u8,
    /// Utilization percentage (current / max * 100). 0.0 if unlimited.
    pub utilization_pct: f64,
}

/// Manages a set of named execution lanes.
///
/// Always contains at least the "default" lane with unlimited concurrency.
#[derive(Debug)]
pub struct LaneManager {
    lanes: HashMap<String, ExecutionLane>,
}

impl LaneManager {
    /// Create a new lane manager from configuration.
    ///
    /// Always includes the "default" lane with unlimited concurrency.
    /// If the config contains a lane named "default", it overrides the
    /// built-in defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - More than [`MAX_LANES`] lanes are configured.
    /// - Any lane name fails validation.
    pub fn new(configs: Vec<LaneConfig>) -> Result<Self, String> {
        if configs.len() > MAX_LANES {
            return Err(format!(
                "too many lanes: {} (max {MAX_LANES})",
                configs.len()
            ));
        }

        let mut lanes = HashMap::new();

        // Insert default lane first (may be overridden by config).
        lanes.insert(
            DEFAULT_LANE.to_string(),
            ExecutionLane {
                name: DEFAULT_LANE.to_string(),
                max_concurrent: 0,
                current: 0,
                priority: 0,
                queued_agents: Vec::new(),
            },
        );

        for cfg in configs {
            validate_lane_name(&cfg.name)?;
            lanes.insert(
                cfg.name.clone(),
                ExecutionLane {
                    name: cfg.name,
                    max_concurrent: cfg.max_concurrent,
                    current: 0,
                    priority: cfg.priority,
                    queued_agents: Vec::new(),
                },
            );
        }

        Ok(Self { lanes })
    }

    /// Try to acquire a slot in the named lane for the given agent.
    ///
    /// Returns `Ok(true)` if the slot was acquired (agent can proceed).
    /// Returns `Ok(false)` if the lane is full (agent has been queued).
    ///
    /// # Errors
    ///
    /// Returns an error if the lane does not exist or the name is invalid.
    pub fn acquire(&mut self, lane_name: &str, agent_name: &str) -> Result<bool, String> {
        validate_lane_name(lane_name)?;

        let lane = self
            .lanes
            .get_mut(lane_name)
            .ok_or_else(|| format!("lane {lane_name:?} does not exist"))?;

        if lane.has_capacity() {
            lane.current += 1;
            Ok(true)
        } else {
            // Queue the agent if not already queued.
            if !lane.queued_agents.contains(&agent_name.to_string()) {
                lane.queued_agents.push(agent_name.to_string());
            }
            Ok(false)
        }
    }

    /// Release a slot in the named lane.
    ///
    /// If agents are queued, returns the name of the next agent that should
    /// be started (dequeued in FIFO order).
    ///
    /// # Errors
    ///
    /// Returns an error if the lane does not exist or has no active slots.
    pub fn release(&mut self, lane_name: &str, agent_name: &str) -> Result<Option<String>, String> {
        validate_lane_name(lane_name)?;

        let lane = self
            .lanes
            .get_mut(lane_name)
            .ok_or_else(|| format!("lane {lane_name:?} does not exist"))?;

        if lane.current == 0 {
            return Err(format!(
                "lane {lane_name:?} has no active slots to release"
            ));
        }

        lane.current -= 1;

        // Also remove from queue if the releasing agent was somehow queued.
        lane.queued_agents.retain(|a| a != agent_name);

        // Dequeue the next waiting agent if the lane now has capacity.
        let next = if lane.has_capacity() && !lane.queued_agents.is_empty() {
            Some(lane.queued_agents.remove(0))
        } else {
            None
        };

        Ok(next)
    }

    /// Get the status of all lanes.
    pub fn lane_status(&self) -> Vec<LaneStatus> {
        let mut statuses: Vec<LaneStatus> = self
            .lanes
            .values()
            .map(|lane| {
                let utilization_pct = if lane.max_concurrent == 0 {
                    0.0
                } else {
                    (lane.current as f64 / lane.max_concurrent as f64) * 100.0
                };
                LaneStatus {
                    name: lane.name.clone(),
                    current: lane.current,
                    max_concurrent: lane.max_concurrent,
                    queued: lane.queued_agents.len(),
                    priority: lane.priority,
                    utilization_pct,
                }
            })
            .collect();
        statuses.sort_by(|a, b| a.name.cmp(&b.name));
        statuses
    }

    /// Get a reference to a specific lane.
    pub fn get_lane(&self, name: &str) -> Option<&ExecutionLane> {
        self.lanes.get(name)
    }

    /// Check if a lane has capacity for another agent.
    pub fn is_available(&self, lane_name: &str) -> bool {
        self.lanes
            .get(lane_name)
            .is_some_and(|lane| lane.has_capacity())
    }

    /// List agents queued for a specific lane.
    pub fn list_queued(&self, lane_name: &str) -> Vec<String> {
        self.lanes
            .get(lane_name)
            .map(|lane| lane.queued_agents.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_concurrency_limit_enforced() {
        let mut mgr = LaneManager::new(vec![LaneConfig {
            name: "build".into(),
            max_concurrent: 2,
            priority: 10,
        }])
        .unwrap();

        // First two agents acquire successfully.
        assert!(mgr.acquire("build", "agent-1").unwrap());
        assert!(mgr.acquire("build", "agent-2").unwrap());

        // Third agent is queued (returns false).
        assert!(!mgr.acquire("build", "agent-3").unwrap());

        // Verify queue state.
        assert_eq!(mgr.list_queued("build"), vec!["agent-3".to_string()]);
    }

    #[test]
    fn agent_assigned_to_configured_lane() {
        let mgr = LaneManager::new(vec![
            LaneConfig {
                name: "gpu".into(),
                max_concurrent: 1,
                priority: 50,
            },
            LaneConfig {
                name: "cpu".into(),
                max_concurrent: 4,
                priority: 10,
            },
        ])
        .unwrap();

        assert!(mgr.get_lane("gpu").is_some());
        assert!(mgr.get_lane("cpu").is_some());
        assert!(mgr.get_lane("default").is_some());
        assert!(mgr.get_lane("nonexistent").is_none());
    }

    #[test]
    fn default_lane_unlimited() {
        let mut mgr = LaneManager::new(vec![]).unwrap();

        // Default lane exists and is unlimited.
        let lane = mgr.get_lane("default").unwrap();
        assert_eq!(lane.max_concurrent, 0);
        assert!(mgr.is_available("default"));

        // Can acquire many slots without blocking.
        for i in 0..100 {
            assert!(mgr.acquire("default", &format!("agent-{i}")).unwrap());
        }
        assert!(mgr.is_available("default"));
    }

    #[test]
    fn lane_metrics_tracked() {
        let mut mgr = LaneManager::new(vec![LaneConfig {
            name: "test-lane".into(),
            max_concurrent: 3,
            priority: 5,
        }])
        .unwrap();

        mgr.acquire("test-lane", "a1").unwrap();
        mgr.acquire("test-lane", "a2").unwrap();

        let statuses = mgr.lane_status();
        let test_lane = statuses.iter().find(|s| s.name == "test-lane").unwrap();
        assert_eq!(test_lane.current, 2);
        assert_eq!(test_lane.max_concurrent, 3);
        assert_eq!(test_lane.queued, 0);
        assert_eq!(test_lane.priority, 5);
        // 2/3 = 66.67%
        assert!((test_lane.utilization_pct - 66.666).abs() < 1.0);

        let default = statuses.iter().find(|s| s.name == "default").unwrap();
        assert_eq!(default.utilization_pct, 0.0);
    }

    #[test]
    fn queued_start_proceeds_when_lane_frees() {
        let mut mgr = LaneManager::new(vec![LaneConfig {
            name: "narrow".into(),
            max_concurrent: 1,
            priority: 0,
        }])
        .unwrap();

        assert!(mgr.acquire("narrow", "a1").unwrap());
        assert!(!mgr.acquire("narrow", "a2").unwrap());
        assert!(!mgr.acquire("narrow", "a3").unwrap());

        // Release a1 -- a2 should be dequeued.
        let next = mgr.release("narrow", "a1").unwrap();
        assert_eq!(next.as_deref(), Some("a2"));

        // a2 is no longer in queue.
        assert_eq!(mgr.list_queued("narrow"), vec!["a3".to_string()]);
    }

    #[test]
    fn security_test_lane_name_validated() {
        // Path traversal.
        let result = LaneManager::new(vec![LaneConfig {
            name: "../etc".into(),
            max_concurrent: 1,
            priority: 0,
        }]);
        assert!(result.is_err());

        // Spaces.
        let result = LaneManager::new(vec![LaneConfig {
            name: "bad name".into(),
            max_concurrent: 1,
            priority: 0,
        }]);
        assert!(result.is_err());

        // Empty name.
        let result = LaneManager::new(vec![LaneConfig {
            name: "".into(),
            max_concurrent: 1,
            priority: 0,
        }]);
        assert!(result.is_err());

        // Too long.
        let long_name = "a".repeat(65);
        let result = LaneManager::new(vec![LaneConfig {
            name: long_name,
            max_concurrent: 1,
            priority: 0,
        }]);
        assert!(result.is_err());

        // Valid names succeed.
        assert!(LaneManager::new(vec![LaneConfig {
            name: "my-lane_123".into(),
            max_concurrent: 1,
            priority: 0,
        }])
        .is_ok());

        // Acquire with invalid lane name is rejected.
        let mut mgr = LaneManager::new(vec![]).unwrap();
        assert!(mgr.acquire("../bad", "agent").is_err());
    }

    #[test]
    fn security_test_max_lanes_enforced() {
        let configs: Vec<LaneConfig> = (0..=MAX_LANES)
            .map(|i| LaneConfig {
                name: format!("lane-{i}"),
                max_concurrent: 1,
                priority: 0,
            })
            .collect();
        let result = LaneManager::new(configs);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many lanes"));
    }

    #[test]
    fn release_nonexistent_lane_errors() {
        let mut mgr = LaneManager::new(vec![]).unwrap();
        assert!(mgr.release("nonexistent", "agent").is_err());
    }

    #[test]
    fn release_empty_lane_errors() {
        let mut mgr = LaneManager::new(vec![LaneConfig {
            name: "lane".into(),
            max_concurrent: 2,
            priority: 0,
        }])
        .unwrap();
        assert!(mgr.release("lane", "agent").is_err());
    }

    #[test]
    fn duplicate_queue_entry_prevented() {
        let mut mgr = LaneManager::new(vec![LaneConfig {
            name: "narrow".into(),
            max_concurrent: 1,
            priority: 0,
        }])
        .unwrap();

        assert!(mgr.acquire("narrow", "a1").unwrap());
        assert!(!mgr.acquire("narrow", "a2").unwrap());
        // Second acquire for same agent should not duplicate in queue.
        assert!(!mgr.acquire("narrow", "a2").unwrap());
        assert_eq!(mgr.list_queued("narrow"), vec!["a2".to_string()]);
    }

    #[test]
    fn default_lane_override_from_config() {
        let mgr = LaneManager::new(vec![LaneConfig {
            name: "default".into(),
            max_concurrent: 5,
            priority: 100,
        }])
        .unwrap();

        let lane = mgr.get_lane("default").unwrap();
        assert_eq!(lane.max_concurrent, 5);
        assert_eq!(lane.priority, 100);
    }

    #[test]
    fn lane_status_sorted_by_name() {
        let mgr = LaneManager::new(vec![
            LaneConfig {
                name: "zebra".into(),
                max_concurrent: 1,
                priority: 0,
            },
            LaneConfig {
                name: "alpha".into(),
                max_concurrent: 2,
                priority: 0,
            },
        ])
        .unwrap();

        let statuses = mgr.lane_status();
        let names: Vec<&str> = statuses.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "default", "zebra"]);
    }
}
