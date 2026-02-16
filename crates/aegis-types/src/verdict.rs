use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    Allow,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub action_id: Uuid,
    pub decision: Decision,
    pub reason: String,
    pub policy_id: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl Verdict {
    pub fn allow(action_id: Uuid, reason: impl Into<String>, policy_id: Option<String>) -> Self {
        Self {
            action_id,
            decision: Decision::Allow,
            reason: reason.into(),
            policy_id,
            timestamp: Utc::now(),
        }
    }

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
