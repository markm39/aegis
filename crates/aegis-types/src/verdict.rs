use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The authorization decision produced by the Cedar policy engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    /// The action is permitted by at least one `permit` policy.
    Allow,
    /// The action is denied (default-deny, or an explicit `forbid` policy matched).
    Deny,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "Allow"),
            Decision::Deny => write!(f, "Deny"),
        }
    }
}

/// A complete authorization verdict linking an action to its policy evaluation result.
///
/// Produced by `PolicyEngine::evaluate()` and recorded alongside the action
/// in the audit ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    /// The action this verdict applies to.
    pub action_id: Uuid,
    /// Whether the action was allowed or denied.
    pub decision: Decision,
    /// Human-readable explanation of why this decision was made.
    pub reason: String,
    /// The Cedar policy ID that produced the decision, if identifiable.
    pub policy_id: Option<String>,
    /// When the evaluation occurred.
    pub timestamp: DateTime<Utc>,
}

impl Verdict {
    /// Create an Allow verdict for the given action.
    pub fn allow(action_id: Uuid, reason: impl Into<String>, policy_id: Option<String>) -> Self {
        Self {
            action_id,
            decision: Decision::Allow,
            reason: reason.into(),
            policy_id,
            timestamp: Utc::now(),
        }
    }

    /// Create a Deny verdict for the given action.
    pub fn deny(action_id: Uuid, reason: impl Into<String>, policy_id: Option<String>) -> Self {
        Self {
            action_id,
            decision: Decision::Deny,
            reason: reason.into(),
            policy_id,
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_serialization_roundtrip() {
        let v = Verdict::allow(Uuid::new_v4(), "matched permit rule", Some("policy-1".into()));
        let json = serde_json::to_string(&v).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decision, Decision::Allow);
        assert_eq!(back.reason, "matched permit rule");
        assert_eq!(back.policy_id, Some("policy-1".into()));
    }

    #[test]
    fn decision_display() {
        assert_eq!(Decision::Allow.to_string(), "Allow");
        assert_eq!(Decision::Deny.to_string(), "Deny");
    }
}
