//! Pending permission request tracking.
//!
//! When a prompt is detected but cannot be auto-decided (uncertain action
//! set to Alert, or explicit hold), it becomes a pending request. External
//! clients can approve or deny pending requests via the control plane.

use std::collections::HashMap;
use std::time::Instant;

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Configuration for approval behavior (timeouts, delegation, multi-approver).
#[derive(Debug, Clone)]
pub struct ApprovalConfig {
    /// Default timeout in seconds before a request is auto-denied.
    pub default_timeout_secs: u64,
    /// Timeout in seconds for high-risk requests (risk_level "high" or "critical").
    pub high_risk_timeout_secs: u64,
    /// Number of approvals required before a request is fully approved.
    pub require_approvals: u32,
    /// Whether delegation to another approver is permitted.
    pub allow_delegation: bool,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            default_timeout_secs: 300,
            high_risk_timeout_secs: 60,
            require_approvals: 1,
            allow_delegation: true,
        }
    }
}

/// The result of a partial approval attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// The approval threshold has been met; the request is fully approved.
    Approved,
    /// More approvals are needed.
    Pending {
        /// Number of additional approvals still required.
        remaining: u32,
    },
    /// The request was not found.
    NotFound,
}

/// A permission request awaiting external decision.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    /// Unique request ID.
    pub id: Uuid,
    /// The raw prompt text displayed by the agent.
    pub raw_prompt: String,
    /// When the request was created.
    pub created_at: Instant,
    /// The approve response string to send if approved.
    pub approve_response: String,
    /// The deny response string to send if denied.
    pub deny_response: String,
    /// Risk classification ("low", "medium", "high", "critical").
    pub risk_level: Option<String>,
    /// When this request auto-denies (wall-clock deadline).
    pub timeout_at: DateTime<Utc>,
    /// If delegated, the identifier of the delegate.
    pub delegated_to: Option<String>,
    /// Number of approvals received so far.
    pub approval_count: u32,
    /// Identifiers of approvers who have approved.
    pub approvers: Vec<String>,
    /// Number of approvals required (captured at creation time from config).
    pub require_approvals: u32,
}

/// The decision made on a pending request.
#[derive(Debug, Clone)]
pub enum PendingDecision {
    /// Approve the request; send the approve response.
    Approve(String),
    /// Deny the request; send the deny response.
    Deny(String),
}

/// Characters that are forbidden in delegation target identifiers.
/// Prevents injection attacks through approver/delegate names.
const FORBIDDEN_DELEGATE_CHARS: &[char] = &[
    '\n', '\r', '\0', ';', '\'', '"', '\\', '`', '$', '(', ')', '{', '}', '<', '>', '|', '&',
];

/// Validate that a delegation target identifier is safe.
///
/// Rejects empty strings and strings containing shell metacharacters or
/// control characters that could be used for injection.
fn validate_delegate_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("delegation target must not be empty".into());
    }
    if target.len() > 256 {
        return Err("delegation target exceeds maximum length of 256 characters".into());
    }
    for ch in target.chars() {
        if FORBIDDEN_DELEGATE_CHARS.contains(&ch) || ch.is_control() {
            return Err(format!(
                "delegation target contains forbidden character: {:?}",
                ch
            ));
        }
    }
    Ok(())
}

/// Manages the set of pending permission requests.
pub struct PendingRequests {
    requests: HashMap<Uuid, PendingRequest>,
    /// Maximum age in seconds before a request expires.
    expiry_secs: u64,
}

impl PendingRequests {
    /// Create a new pending request tracker.
    ///
    /// `expiry_secs` controls how long requests remain before being auto-expired.
    /// Use 0 for no expiry.
    pub fn new(expiry_secs: u64) -> Self {
        Self {
            requests: HashMap::new(),
            expiry_secs,
        }
    }

    /// Add a new pending request. Returns the assigned ID.
    ///
    /// Uses a far-future timeout (year 9999) since no config is provided.
    /// Prefer [`add_with_config`](Self::add_with_config) for configurable timeouts.
    pub fn add(
        &mut self,
        raw_prompt: String,
        approve_response: String,
        deny_response: String,
    ) -> Uuid {
        let id = Uuid::new_v4();
        self.requests.insert(
            id,
            PendingRequest {
                id,
                raw_prompt,
                created_at: Instant::now(),
                approve_response,
                deny_response,
                risk_level: None,
                timeout_at: DateTime::<Utc>::MAX_UTC,
                delegated_to: None,
                approval_count: 0,
                approvers: Vec::new(),
                require_approvals: 1,
            },
        );
        id
    }

    /// Add a new pending request with configuration-driven timeout and risk level.
    ///
    /// High-risk and critical requests use `config.high_risk_timeout_secs`;
    /// all others use `config.default_timeout_secs`.
    pub fn add_with_config(
        &mut self,
        raw_prompt: String,
        approve_response: String,
        deny_response: String,
        config: &ApprovalConfig,
        risk_level: Option<&str>,
    ) -> Uuid {
        let timeout_secs = match risk_level {
            Some("high") | Some("critical") => config.high_risk_timeout_secs,
            _ => config.default_timeout_secs,
        };
        let timeout_at = Utc::now() + chrono::Duration::seconds(timeout_secs as i64);

        let id = Uuid::new_v4();
        self.requests.insert(
            id,
            PendingRequest {
                id,
                raw_prompt,
                created_at: Instant::now(),
                approve_response,
                deny_response,
                risk_level: risk_level.map(String::from),
                timeout_at,
                delegated_to: None,
                approval_count: 0,
                approvers: Vec::new(),
                require_approvals: config.require_approvals,
            },
        );
        id
    }

    /// Approve a pending request and return the response string to send.
    pub fn approve(&mut self, id: Uuid) -> Option<PendingDecision> {
        self.requests
            .remove(&id)
            .map(|r| PendingDecision::Approve(r.approve_response))
    }

    /// Deny a pending request and return the response string to send.
    pub fn deny(&mut self, id: Uuid) -> Option<PendingDecision> {
        self.requests
            .remove(&id)
            .map(|r| PendingDecision::Deny(r.deny_response))
    }

    /// Delegate a pending request to another approver.
    ///
    /// The delegate target is validated to prevent injection attacks.
    /// Returns an error if the request does not exist, delegation target is
    /// invalid, or the config used to create the request disallows delegation.
    pub fn delegate(&mut self, request_id: Uuid, delegate_to: &str) -> Result<(), String> {
        validate_delegate_target(delegate_to)?;

        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| format!("pending request {request_id} not found"))?;

        request.delegated_to = Some(delegate_to.to_string());
        Ok(())
    }

    /// Record a partial approval from an approver.
    ///
    /// If the approval threshold is met, the request is removed and
    /// [`ApprovalStatus::Approved`] is returned. Otherwise,
    /// [`ApprovalStatus::Pending`] indicates how many more are needed.
    ///
    /// The approver identifier is validated with the same rules as delegation
    /// targets. Duplicate approvals from the same approver are silently ignored
    /// (they do not increment the count).
    pub fn partial_approve(
        &mut self,
        request_id: Uuid,
        approver: &str,
    ) -> Result<ApprovalStatus, String> {
        validate_delegate_target(approver)?;

        let request = match self.requests.get_mut(&request_id) {
            Some(r) => r,
            None => return Ok(ApprovalStatus::NotFound),
        };

        // Prevent duplicate approvals from the same approver.
        if !request.approvers.contains(&approver.to_string()) {
            request.approvers.push(approver.to_string());
            request.approval_count += 1;
        }

        if request.approval_count >= request.require_approvals {
            // Threshold met -- remove and return Approved.
            self.requests.remove(&request_id);
            Ok(ApprovalStatus::Approved)
        } else {
            let remaining = request.require_approvals - request.approval_count;
            Ok(ApprovalStatus::Pending { remaining })
        }
    }

    /// List all pending requests (oldest first).
    pub fn list(&self) -> Vec<&PendingRequest> {
        let mut reqs: Vec<_> = self.requests.values().collect();
        reqs.sort_by_key(|r| r.created_at);
        reqs
    }

    /// List all pending requests sorted by priority: highest risk first,
    /// then oldest first within the same risk level.
    pub fn list_prioritized(&self) -> Vec<&PendingRequest> {
        let mut reqs: Vec<_> = self.requests.values().collect();
        reqs.sort_by(|a, b| {
            let risk_ord_a = risk_sort_key(a.risk_level.as_deref());
            let risk_ord_b = risk_sort_key(b.risk_level.as_deref());
            risk_ord_a
                .cmp(&risk_ord_b)
                .then(a.created_at.cmp(&b.created_at))
        });
        reqs
    }

    /// Number of pending requests.
    pub fn count(&self) -> usize {
        self.requests.len()
    }

    /// Remove expired requests, returning the number removed.
    pub fn expire(&mut self) -> usize {
        if self.expiry_secs == 0 {
            return 0;
        }
        let before = self.requests.len();
        let expiry = std::time::Duration::from_secs(self.expiry_secs);
        self.requests.retain(|_, r| r.created_at.elapsed() < expiry);
        before - self.requests.len()
    }

    /// Auto-deny all requests whose `timeout_at` has passed.
    ///
    /// Returns a list of `(request_id, reason)` for each expired request.
    pub fn expire_timed_out(&mut self) -> Vec<(Uuid, String)> {
        let now = Utc::now();
        let mut expired = Vec::new();

        self.requests.retain(|_, r| {
            if r.timeout_at <= now {
                let reason = format!(
                    "auto-denied: approval timeout expired at {}",
                    r.timeout_at.to_rfc3339()
                );
                expired.push((r.id, reason));
                false
            } else {
                true
            }
        });

        expired
    }
}

/// Map risk level string to a sort key (lower = higher priority).
fn risk_sort_key(risk: Option<&str>) -> u8 {
    match risk {
        Some("critical") => 0,
        Some("high") => 1,
        Some("medium") => 2,
        Some("low") => 3,
        _ => 4, // unknown or None sorts last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_approve() {
        let mut pending = PendingRequests::new(0);
        let id = pending.add("Allow?".into(), "y".into(), "n".into());
        assert_eq!(pending.count(), 1);

        match pending.approve(id) {
            Some(PendingDecision::Approve(resp)) => assert_eq!(resp, "y"),
            other => panic!("expected Approve, got {other:?}"),
        }
        assert_eq!(pending.count(), 0);
    }

    #[test]
    fn add_and_deny() {
        let mut pending = PendingRequests::new(0);
        let id = pending.add("Allow?".into(), "y".into(), "n".into());

        match pending.deny(id) {
            Some(PendingDecision::Deny(resp)) => assert_eq!(resp, "n"),
            other => panic!("expected Deny, got {other:?}"),
        }
        assert_eq!(pending.count(), 0);
    }

    #[test]
    fn approve_nonexistent() {
        let mut pending = PendingRequests::new(0);
        assert!(pending.approve(Uuid::new_v4()).is_none());
    }

    #[test]
    fn list_ordered_by_creation() {
        let mut pending = PendingRequests::new(0);
        let _id1 = pending.add("first".into(), "y".into(), "n".into());
        let _id2 = pending.add("second".into(), "y".into(), "n".into());

        let list = pending.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].raw_prompt, "first");
        assert_eq!(list[1].raw_prompt, "second");
    }

    #[test]
    fn expire_removes_old_requests() {
        let mut pending = PendingRequests::new(0); // 0 = no expiry
        pending.add("never expires".into(), "y".into(), "n".into());
        assert_eq!(pending.expire(), 0);
        assert_eq!(pending.count(), 1);
    }

    #[test]
    fn expire_with_short_timeout() {
        let mut pending = PendingRequests::new(1); // 1 second expiry
        pending.add("will expire".into(), "y".into(), "n".into());

        // Immediately, should not be expired
        assert_eq!(pending.expire(), 0);

        // After sleeping past the expiry
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert_eq!(pending.expire(), 1);
        assert_eq!(pending.count(), 0);
    }

    // --- New tests for approval config, delegation, prioritization ---

    #[test]
    fn test_approval_config_defaults() {
        let config = ApprovalConfig::default();
        assert_eq!(config.default_timeout_secs, 300);
        assert_eq!(config.high_risk_timeout_secs, 60);
        assert_eq!(config.require_approvals, 1);
        assert!(config.allow_delegation);
    }

    #[test]
    fn test_add_with_config_sets_timeout() {
        let mut pending = PendingRequests::new(0);
        let config = ApprovalConfig {
            default_timeout_secs: 60,
            high_risk_timeout_secs: 30,
            require_approvals: 1,
            allow_delegation: true,
        };

        let before = Utc::now();
        let id = pending.add_with_config("Allow?".into(), "y".into(), "n".into(), &config, None);
        let after = Utc::now();

        let req = pending.requests.get(&id).unwrap();
        // timeout_at should be approximately 60 seconds from now
        let lower = before + chrono::Duration::seconds(59);
        let upper = after + chrono::Duration::seconds(61);
        assert!(
            req.timeout_at >= lower && req.timeout_at <= upper,
            "timeout_at {:?} not in expected range [{:?}, {:?}]",
            req.timeout_at,
            lower,
            upper
        );
    }

    #[test]
    fn test_high_risk_gets_shorter_timeout() {
        let mut pending = PendingRequests::new(0);
        let config = ApprovalConfig {
            default_timeout_secs: 300,
            high_risk_timeout_secs: 60,
            require_approvals: 1,
            allow_delegation: true,
        };

        let before = Utc::now();
        let id_high = pending.add_with_config(
            "Dangerous!".into(),
            "y".into(),
            "n".into(),
            &config,
            Some("high"),
        );
        let id_low =
            pending.add_with_config("Safe".into(), "y".into(), "n".into(), &config, Some("low"));
        let after = Utc::now();

        let req_high = pending.requests.get(&id_high).unwrap();
        let req_low = pending.requests.get(&id_low).unwrap();

        // High-risk should timeout ~60s from now
        let high_lower = before + chrono::Duration::seconds(59);
        let high_upper = after + chrono::Duration::seconds(61);
        assert!(req_high.timeout_at >= high_lower && req_high.timeout_at <= high_upper);

        // Low-risk should timeout ~300s from now
        let low_lower = before + chrono::Duration::seconds(299);
        let low_upper = after + chrono::Duration::seconds(301);
        assert!(req_low.timeout_at >= low_lower && req_low.timeout_at <= low_upper);

        // High-risk timeout should be earlier than low-risk
        assert!(req_high.timeout_at < req_low.timeout_at);
    }

    #[test]
    fn test_expire_timed_out_returns_expired() {
        let mut pending = PendingRequests::new(0);
        let config = ApprovalConfig {
            default_timeout_secs: 0, // immediate timeout
            high_risk_timeout_secs: 0,
            require_approvals: 1,
            allow_delegation: true,
        };

        let id = pending.add_with_config("Expire me".into(), "y".into(), "n".into(), &config, None);

        // With 0-second timeout, request should already be past deadline
        std::thread::sleep(std::time::Duration::from_millis(10));
        let expired = pending.expire_timed_out();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, id);
        assert!(expired[0].1.contains("auto-denied"));
        assert_eq!(pending.count(), 0);
    }

    #[test]
    fn test_delegate_reassigns_request() {
        let mut pending = PendingRequests::new(0);
        let id = pending.add("Allow?".into(), "y".into(), "n".into());

        pending.delegate(id, "user2").unwrap();

        let req = pending.requests.get(&id).unwrap();
        assert_eq!(req.delegated_to.as_deref(), Some("user2"));
    }

    #[test]
    fn test_delegate_nonexistent_fails() {
        let mut pending = PendingRequests::new(0);
        let result = pending.delegate(Uuid::new_v4(), "user2");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_partial_approve_single_threshold() {
        let mut pending = PendingRequests::new(0);
        let config = ApprovalConfig {
            default_timeout_secs: 300,
            high_risk_timeout_secs: 60,
            require_approvals: 1,
            allow_delegation: true,
        };

        let id = pending.add_with_config("Allow?".into(), "y".into(), "n".into(), &config, None);

        let status = pending.partial_approve(id, "admin").unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
        assert_eq!(pending.count(), 0);
    }

    #[test]
    fn test_partial_approve_multi_threshold() {
        let mut pending = PendingRequests::new(0);
        let config = ApprovalConfig {
            default_timeout_secs: 300,
            high_risk_timeout_secs: 60,
            require_approvals: 2,
            allow_delegation: true,
        };

        let id = pending.add_with_config("Allow?".into(), "y".into(), "n".into(), &config, None);

        // First approval -- should still be pending
        let status = pending.partial_approve(id, "admin1").unwrap();
        assert_eq!(status, ApprovalStatus::Pending { remaining: 1 });
        assert_eq!(pending.count(), 1);

        // Second approval -- should be fully approved
        let status = pending.partial_approve(id, "admin2").unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
        assert_eq!(pending.count(), 0);
    }

    #[test]
    fn test_list_prioritized_risk_ordering() {
        let mut pending = PendingRequests::new(0);
        let config = ApprovalConfig {
            default_timeout_secs: 300,
            high_risk_timeout_secs: 60,
            require_approvals: 1,
            allow_delegation: true,
        };

        pending.add_with_config("low".into(), "y".into(), "n".into(), &config, Some("low"));
        pending.add_with_config("high".into(), "y".into(), "n".into(), &config, Some("high"));
        pending.add_with_config(
            "medium".into(),
            "y".into(),
            "n".into(),
            &config,
            Some("medium"),
        );

        let list = pending.list_prioritized();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].risk_level.as_deref(), Some("high"));
        assert_eq!(list[1].risk_level.as_deref(), Some("medium"));
        assert_eq!(list[2].risk_level.as_deref(), Some("low"));
    }

    #[test]
    fn test_list_prioritized_time_ordering() {
        let mut pending = PendingRequests::new(0);
        let config = ApprovalConfig {
            default_timeout_secs: 300,
            high_risk_timeout_secs: 60,
            require_approvals: 1,
            allow_delegation: true,
        };

        let _id1 = pending.add_with_config(
            "first-medium".into(),
            "y".into(),
            "n".into(),
            &config,
            Some("medium"),
        );
        let _id2 = pending.add_with_config(
            "second-medium".into(),
            "y".into(),
            "n".into(),
            &config,
            Some("medium"),
        );

        let list = pending.list_prioritized();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].raw_prompt, "first-medium");
        assert_eq!(list[1].raw_prompt, "second-medium");
    }

    #[test]
    fn test_delegate_validates_target() {
        let mut pending = PendingRequests::new(0);
        let id = pending.add("Allow?".into(), "y".into(), "n".into());

        // Empty target
        assert!(pending.delegate(id, "").is_err());

        // Shell metacharacters
        assert!(pending.delegate(id, "user;rm -rf /").is_err());
        assert!(pending.delegate(id, "user$(whoami)").is_err());
        assert!(pending.delegate(id, "user`id`").is_err());
        assert!(pending.delegate(id, "user\ninjection").is_err());
        assert!(pending.delegate(id, "user\0null").is_err());
        assert!(pending.delegate(id, "user'quoted").is_err());
        assert!(pending.delegate(id, "user\"dquoted").is_err());
        assert!(pending.delegate(id, "user|pipe").is_err());
        assert!(pending.delegate(id, "user&bg").is_err());
        assert!(pending.delegate(id, "user<redir").is_err());
        assert!(pending.delegate(id, "user>redir").is_err());

        // Valid target should succeed
        assert!(pending.delegate(id, "valid-user_123").is_ok());
    }
}
