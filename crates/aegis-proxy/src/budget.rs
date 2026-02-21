//! Per-session budget tracking and enforcement.
//!
//! Provides a [`BudgetTracker`] that accumulates spend against a configured
//! budget ceiling, emitting [`BudgetStatus`] signals when thresholds are
//! crossed. Supports configurable warning thresholds and exceeded actions.

use serde::{Deserialize, Serialize};

/// What to do when the budget is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetAction {
    /// Log a warning but allow the session to continue.
    Warn,
    /// Stop the session / agent.
    Stop,
    /// Fire an alert (webhook / Telegram) but allow continuation.
    Alert,
}

/// Configuration for a session budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum budget in USD. `0.0` means unlimited.
    pub budget_usd: f64,
    /// Fraction of the budget at which to emit a warning (default `0.8`).
    pub warn_threshold: f64,
    /// What to do when the budget is exceeded.
    pub action_on_exceed: BudgetAction,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            budget_usd: 0.0,
            warn_threshold: 0.8,
            action_on_exceed: BudgetAction::Warn,
        }
    }
}

/// Status returned after recording a cost against the budget.
#[derive(Debug, Clone, PartialEq)]
pub enum BudgetStatus {
    /// Spend is within budget and below the warning threshold.
    Ok,
    /// Spend has crossed the warning threshold but not yet exceeded the budget.
    Warning {
        /// Current fraction of budget consumed (0.0 -- 1.0).
        utilization: f64,
    },
    /// Spend has exceeded the budget.
    Exceeded {
        /// Amount over budget in USD.
        overage: f64,
        /// The configured action for this condition.
        action: BudgetAction,
    },
}

/// Tracks cumulative spend against a budget ceiling.
///
/// All monetary values are in USD. Negative cost inputs are clamped to zero
/// to prevent budget manipulation.
#[derive(Debug, Clone)]
pub struct BudgetTracker {
    config: BudgetConfig,
    spent_usd: f64,
}

impl BudgetTracker {
    /// Create a new tracker with the given configuration.
    pub fn new(config: BudgetConfig) -> Self {
        Self {
            config,
            spent_usd: 0.0,
        }
    }

    /// Record a cost and return the resulting budget status.
    ///
    /// Negative `cost` values are clamped to zero to prevent budget underflow.
    pub fn record_cost(&mut self, cost: f64) -> BudgetStatus {
        // Security: clamp negative costs to prevent budget manipulation.
        let safe_cost = cost.max(0.0);
        self.spent_usd += safe_cost;

        // Unlimited budget never triggers warnings or exceeded.
        if self.config.budget_usd <= 0.0 {
            return BudgetStatus::Ok;
        }

        let utilization = self.utilization();

        if self.spent_usd > self.config.budget_usd {
            BudgetStatus::Exceeded {
                overage: self.spent_usd - self.config.budget_usd,
                action: self.config.action_on_exceed,
            }
        } else if utilization >= self.config.warn_threshold {
            BudgetStatus::Warning { utilization }
        } else {
            BudgetStatus::Ok
        }
    }

    /// Total amount spent so far in USD.
    pub fn spent(&self) -> f64 {
        self.spent_usd
    }

    /// Remaining budget in USD. Returns `f64::INFINITY` for unlimited budgets.
    pub fn remaining(&self) -> f64 {
        if self.config.budget_usd <= 0.0 {
            f64::INFINITY
        } else {
            (self.config.budget_usd - self.spent_usd).max(0.0)
        }
    }

    /// Fraction of budget consumed (0.0 -- 1.0+). Returns `0.0` for unlimited budgets.
    pub fn utilization(&self) -> f64 {
        if self.config.budget_usd <= 0.0 {
            0.0
        } else {
            self.spent_usd / self.config.budget_usd
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_tracker_ok() {
        let config = BudgetConfig {
            budget_usd: 10.0,
            warn_threshold: 0.8,
            action_on_exceed: BudgetAction::Stop,
        };
        let mut tracker = BudgetTracker::new(config);

        let status = tracker.record_cost(5.0);
        assert_eq!(status, BudgetStatus::Ok);
        assert!((tracker.spent() - 5.0).abs() < f64::EPSILON);
        assert!((tracker.remaining() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_budget_tracker_warning() {
        let config = BudgetConfig {
            budget_usd: 10.0,
            warn_threshold: 0.8,
            action_on_exceed: BudgetAction::Stop,
        };
        let mut tracker = BudgetTracker::new(config);

        // Spend $8.50 of $10 -> 85% utilization -> warning
        let status = tracker.record_cost(8.50);
        match status {
            BudgetStatus::Warning { utilization } => {
                assert!(
                    (utilization - 0.85).abs() < 1e-9,
                    "utilization should be 0.85, got {utilization}"
                );
            }
            other => panic!("expected Warning, got {other:?}"),
        }
    }

    #[test]
    fn test_budget_tracker_exceeded() {
        let config = BudgetConfig {
            budget_usd: 10.0,
            warn_threshold: 0.8,
            action_on_exceed: BudgetAction::Stop,
        };
        let mut tracker = BudgetTracker::new(config);

        let status = tracker.record_cost(12.0);
        match status {
            BudgetStatus::Exceeded { overage, action } => {
                assert!(
                    (overage - 2.0).abs() < 1e-9,
                    "overage should be $2.00, got {overage}"
                );
                assert_eq!(action, BudgetAction::Stop);
            }
            other => panic!("expected Exceeded, got {other:?}"),
        }
        assert!((tracker.remaining()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_budget_unlimited() {
        let config = BudgetConfig {
            budget_usd: 0.0,
            warn_threshold: 0.8,
            action_on_exceed: BudgetAction::Stop,
        };
        let mut tracker = BudgetTracker::new(config);

        // Even large amounts should stay Ok with unlimited budget
        let status = tracker.record_cost(1_000_000.0);
        assert_eq!(status, BudgetStatus::Ok);
        assert!(tracker.remaining().is_infinite());
        assert!((tracker.utilization()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_budget_cannot_go_negative() {
        let config = BudgetConfig {
            budget_usd: 10.0,
            warn_threshold: 0.8,
            action_on_exceed: BudgetAction::Warn,
        };
        let mut tracker = BudgetTracker::new(config);

        // Spend $5, then try to record negative cost to claw back
        tracker.record_cost(5.0);
        let status = tracker.record_cost(-100.0);

        // Negative cost should be clamped to 0; spent stays at $5
        assert_eq!(status, BudgetStatus::Ok);
        assert!(
            (tracker.spent() - 5.0).abs() < f64::EPSILON,
            "negative cost must not reduce spent, got {}",
            tracker.spent()
        );
    }

    #[test]
    fn test_budget_incremental_warning() {
        let config = BudgetConfig {
            budget_usd: 100.0,
            warn_threshold: 0.8,
            action_on_exceed: BudgetAction::Alert,
        };
        let mut tracker = BudgetTracker::new(config);

        // Below threshold
        assert_eq!(tracker.record_cost(50.0), BudgetStatus::Ok);
        // Still below threshold
        assert_eq!(tracker.record_cost(20.0), BudgetStatus::Ok);
        // Cross threshold at $80/100 = 80%
        match tracker.record_cost(10.0) {
            BudgetStatus::Warning { utilization } => {
                assert!((utilization - 0.8).abs() < 1e-9);
            }
            other => panic!("expected Warning, got {other:?}"),
        }
        // Exceed at $110/$100
        match tracker.record_cost(30.0) {
            BudgetStatus::Exceeded { overage, action } => {
                assert!((overage - 10.0).abs() < 1e-9);
                assert_eq!(action, BudgetAction::Alert);
            }
            other => panic!("expected Exceeded, got {other:?}"),
        }
    }
}
