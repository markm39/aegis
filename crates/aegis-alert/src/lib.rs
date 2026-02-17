//! Real-time webhook alerting for Aegis audit events.
//!
//! This crate evaluates audit events against configured [`AlertRule`]s and
//! dispatches HTTP POST webhooks when rules match. It provides:
//!
//! - [`AlertEvent`]: a lightweight struct carrying the fields needed for rule matching
//! - [`matcher`]: determines whether an event matches a rule's filters
//! - [`payload`]: constructs the JSON webhook payload
//! - [`dispatcher`]: runs the background alert evaluation loop with rate limiting
//! - [`log`]: records alert dispatch history in SQLite

pub mod dispatcher;
pub mod log;
pub mod matcher;
pub mod payload;

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A lightweight audit event passed through the alert channel.
///
/// Created from an `AuditEntry` at the `AuditStore::insert_entry()` call site.
/// Contains only the fields needed for alert rule matching and payload construction,
/// avoiding a dependency on the full `AuditEntry` type.
#[derive(Debug, Clone)]
pub struct AlertEvent {
    /// Unique identifier of the audit entry that triggered this event.
    pub entry_id: Uuid,
    /// When the audit entry was recorded.
    pub timestamp: DateTime<Utc>,
    /// The action kind name (e.g., "FileWrite", "NetConnect").
    pub action_kind: String,
    /// JSON-serialized action detail for the webhook payload.
    pub action_detail: String,
    /// The agent principal name.
    pub principal: String,
    /// The policy decision: "Allow" or "Deny".
    pub decision: String,
    /// Human-readable reason from the policy engine.
    pub reason: String,
    /// The Cedar policy ID that produced the verdict, if any.
    pub policy_id: Option<String>,
    /// The session ID this event belongs to, if any.
    pub session_id: Option<Uuid>,
}
