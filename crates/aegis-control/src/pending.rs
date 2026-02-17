//! Pending permission request tracking.
//!
//! When a prompt is detected but cannot be auto-decided (uncertain action
//! set to Alert, or explicit hold), it becomes a pending request. External
//! clients can approve or deny pending requests via the control plane.

use std::collections::HashMap;
use std::time::Instant;

use uuid::Uuid;

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
}

/// The decision made on a pending request.
#[derive(Debug, Clone)]
pub enum PendingDecision {
    /// Approve the request; send the approve response.
    Approve(String),
    /// Deny the request; send the deny response.
    Deny(String),
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
    pub fn add(
        &mut self,
        raw_prompt: String,
        approve_response: String,
        deny_response: String,
    ) -> Uuid {
        let id = Uuid::new_v4();
        self.requests.insert(id, PendingRequest {
            id,
            raw_prompt,
            created_at: Instant::now(),
            approve_response,
            deny_response,
        });
        id
    }

    /// Approve a pending request and return the response string to send.
    pub fn approve(&mut self, id: Uuid) -> Option<PendingDecision> {
        self.requests.remove(&id)
            .map(|r| PendingDecision::Approve(r.approve_response))
    }

    /// Deny a pending request and return the response string to send.
    pub fn deny(&mut self, id: Uuid) -> Option<PendingDecision> {
        self.requests.remove(&id)
            .map(|r| PendingDecision::Deny(r.deny_response))
    }

    /// List all pending requests (oldest first).
    pub fn list(&self) -> Vec<&PendingRequest> {
        let mut reqs: Vec<_> = self.requests.values().collect();
        reqs.sort_by_key(|r| r.created_at);
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
}
