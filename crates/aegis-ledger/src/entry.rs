//! AuditEntry: a single hash-chained audit log entry.
//!
//! Each entry records an action and its verdict, linked to the previous
//! entry via `prev_hash` to form a tamper-evident chain.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use aegis_types::{Action, AegisError, Verdict};

/// A single entry in the append-only audit ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    pub entry_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action_id: Uuid,
    pub action_kind: String,
    pub principal: String,
    pub decision: String,
    pub reason: String,
    pub policy_id: Option<String>,
    pub prev_hash: String,
    pub entry_hash: String,
}

impl AuditEntry {
    /// Create a new audit entry from an action, verdict, and the previous entry's hash.
    ///
    /// Computes `entry_hash = hex(SHA-256(entry_id || timestamp || action_id || action_kind || principal || decision || reason || prev_hash))`.
    pub fn new(action: &Action, verdict: &Verdict, prev_hash: String) -> Result<Self, AegisError> {
        let entry_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let action_kind = serde_json::to_string(&action.kind)
            .map_err(|e| AegisError::LedgerError(format!("failed to serialize action kind: {e}")))?;
        let decision = verdict.decision.to_string();

        let entry_hash = compute_hash(
            &entry_id,
            &timestamp,
            &action.id,
            &action_kind,
            &action.principal,
            &decision,
            &verdict.reason,
            &prev_hash,
        );

        Ok(Self {
            entry_id,
            timestamp,
            action_id: action.id,
            action_kind,
            principal: action.principal.clone(),
            decision,
            reason: verdict.reason.clone(),
            policy_id: verdict.policy_id.clone(),
            prev_hash,
            entry_hash,
        })
    }

    /// Recompute this entry's hash from its fields.
    ///
    /// Useful for integrity verification -- compare the result against
    /// `self.entry_hash` to detect tampering.
    pub fn recompute_hash(&self) -> String {
        compute_hash(
            &self.entry_id,
            &self.timestamp,
            &self.action_id,
            &self.action_kind,
            &self.principal,
            &self.decision,
            &self.reason,
            &self.prev_hash,
        )
    }
}

/// Compute the SHA-256 hash for an audit entry by concatenating all fields.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_hash(
    entry_id: &Uuid,
    timestamp: &DateTime<Utc>,
    action_id: &Uuid,
    action_kind: &str,
    principal: &str,
    decision: &str,
    reason: &str,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry_id.to_string());
    hasher.update(timestamp.to_rfc3339());
    hasher.update(action_id.to_string());
    hasher.update(action_kind);
    hasher.update(principal);
    hasher.update(decision);
    hasher.update(reason);
    hasher.update(prev_hash);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::ActionKind;
    use std::path::PathBuf;

    #[test]
    fn hash_is_deterministic() {
        let entry_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let action_id = Uuid::new_v4();
        let action_kind = "test";
        let principal = "agent-1";
        let decision = "Allow";
        let reason = "policy matched";
        let prev_hash = "genesis";

        let h1 = compute_hash(
            &entry_id,
            &timestamp,
            &action_id,
            action_kind,
            principal,
            decision,
            reason,
            prev_hash,
        );
        let h2 = compute_hash(
            &entry_id,
            &timestamp,
            &action_id,
            action_kind,
            principal,
            decision,
            reason,
            prev_hash,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_changes_with_different_input() {
        let entry_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let action_id = Uuid::new_v4();
        let prev_hash = "genesis";

        let h1 = compute_hash(
            &entry_id,
            &timestamp,
            &action_id,
            "kind-a",
            "agent",
            "Allow",
            "reason",
            prev_hash,
        );
        let h2 = compute_hash(
            &entry_id,
            &timestamp,
            &action_id,
            "kind-b",
            "agent",
            "Allow",
            "reason",
            prev_hash,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn new_entry_computes_hash() {
        let action = Action::new(
            "test-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let verdict = Verdict::allow(action.id, "ok", None);
        let entry = AuditEntry::new(&action, &verdict, "genesis".to_string()).unwrap();

        assert_eq!(entry.prev_hash, "genesis");
        assert!(!entry.entry_hash.is_empty());
        assert_eq!(entry.decision, "Allow");
        assert_eq!(entry.principal, "test-agent");
    }

    #[test]
    fn new_entry_records_deny() {
        let action = Action::new(
            "agent-x",
            ActionKind::NetConnect {
                host: "evil.com".into(),
                port: 443,
            },
        );
        let verdict = Verdict::deny(action.id, "blocked by policy", Some("pol-1".into()));
        let entry = AuditEntry::new(&action, &verdict, "abc123".to_string()).unwrap();

        assert_eq!(entry.decision, "Deny");
        assert_eq!(entry.reason, "blocked by policy");
        assert_eq!(entry.policy_id, Some("pol-1".into()));
    }

    #[test]
    fn entry_hash_matches_recomputation() {
        let action = Action::new(
            "agent",
            ActionKind::FileRead {
                path: PathBuf::from("/etc/passwd"),
            },
        );
        let verdict = Verdict::deny(action.id, "forbidden", None);
        let entry = AuditEntry::new(&action, &verdict, "prev".to_string()).unwrap();

        assert_eq!(entry.entry_hash, entry.recompute_hash());
    }
}
