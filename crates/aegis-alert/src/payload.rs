//! Webhook JSON payload construction.
//!
//! Builds the JSON body POSTed to webhook URLs when an alert rule fires.
//! The payload is self-describing (includes a version field) and includes
//! a pre-formatted `text` field for direct use in Slack/chat messages.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::AlertEvent;

/// Top-level webhook payload sent to alert endpoints.
#[derive(Debug, Serialize)]
pub struct WebhookPayload {
    /// Payload schema version (currently "1").
    pub version: &'static str,
    /// Whether this is a test/connectivity-check payload.
    pub test: bool,
    /// Alert metadata.
    pub alert: AlertInfo,
    /// The audit event that triggered the alert.
    pub event: EventInfo,
    /// Contextual information about the Aegis session.
    pub context: ContextInfo,
    /// Pre-formatted human-readable summary.
    pub text: String,
}

/// Metadata about the alert itself.
#[derive(Debug, Serialize)]
pub struct AlertInfo {
    /// Unique ID for this alert dispatch.
    pub id: String,
    /// Name of the alert rule that fired.
    pub rule_name: String,
    /// When the alert was dispatched.
    pub fired_at: DateTime<Utc>,
}

/// The audit event that triggered the alert.
#[derive(Debug, Serialize)]
pub struct EventInfo {
    /// Audit entry ID.
    pub entry_id: String,
    /// When the audit event was recorded.
    pub timestamp: DateTime<Utc>,
    /// Action kind (e.g., "FileWrite").
    pub action_kind: String,
    /// Full JSON-serialized action detail.
    pub action_detail: String,
    /// Agent principal name.
    pub principal: String,
    /// Policy decision ("Allow" or "Deny").
    pub decision: String,
    /// Human-readable reason from the policy engine.
    pub reason: String,
    /// Cedar policy ID that produced the verdict.
    pub policy_id: Option<String>,
}

/// Contextual information about the Aegis configuration and session.
#[derive(Debug, Serialize)]
pub struct ContextInfo {
    /// Name of the Aegis config that produced this event.
    pub config_name: String,
    /// Session ID, if the event occurred within a session.
    pub session_id: Option<String>,
}

/// Build a webhook payload for a matched alert event.
///
/// `rule_name` is the name of the rule that fired, `config_name` is the
/// Aegis config name, and `event` is the audit event.
pub fn build_payload(
    rule_name: &str,
    config_name: &str,
    event: &AlertEvent,
    test: bool,
) -> WebhookPayload {
    let alert_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Extract a short path/target for the summary text.
    let target = extract_target(&event.action_detail, &event.action_kind);

    let decision_tag = event.decision.to_uppercase();
    let text = format!(
        "[{decision_tag}] {principal}: {action} {target} -- {reason} (rule: {rule})",
        principal = event.principal,
        action = event.action_kind,
        reason = event.reason,
        rule = rule_name,
    );

    WebhookPayload {
        version: "1",
        test,
        alert: AlertInfo {
            id: alert_id,
            rule_name: rule_name.to_string(),
            fired_at: now,
        },
        event: EventInfo {
            entry_id: event.entry_id.to_string(),
            timestamp: event.timestamp,
            action_kind: event.action_kind.clone(),
            action_detail: event.action_detail.clone(),
            principal: event.principal.clone(),
            decision: event.decision.clone(),
            reason: event.reason.clone(),
            policy_id: event.policy_id.clone(),
        },
        context: ContextInfo {
            config_name: config_name.to_string(),
            session_id: event.session_id.map(|s| s.to_string()),
        },
        text,
    }
}

/// Extract a human-readable target string from an action detail JSON.
///
/// For file actions, returns the path. For network actions, returns host:port.
/// Falls back to the action kind name if extraction fails.
fn extract_target(detail: &str, action_kind: &str) -> String {
    // Try path first (file actions)
    if let Some(start) = detail.find("\"path\":\"") {
        let rest = &detail[start + 8..];
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }
    // Try host:port (network actions)
    if let Some(start) = detail.find("\"host\":\"") {
        let rest = &detail[start + 8..];
        if let Some(end) = rest.find('"') {
            let host = &rest[..end];
            if let Some(port_start) = detail.find("\"port\":") {
                let port_rest = &detail[port_start + 7..];
                let port_end = port_rest
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(port_rest.len());
                let port = &port_rest[..port_end];
                return format!("{host}:{port}");
            }
            return host.to_string();
        }
    }
    action_kind.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_event() -> AlertEvent {
        AlertEvent {
            entry_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action_kind: "FileWrite".into(),
            action_detail: r#"{"FileWrite":{"path":"/etc/secrets/.env"}}"#.into(),
            principal: "my-agent".into(),
            decision: "Deny".into(),
            reason: "forbidden by policy".into(),
            policy_id: Some("deny-secrets".into()),
            session_id: Some(Uuid::new_v4()),
            pilot_context: None,
        }
    }

    #[test]
    fn payload_has_correct_structure() {
        let event = sample_event();
        let payload = build_payload("deny-alert", "my-config", &event, false);

        assert_eq!(payload.version, "1");
        assert!(!payload.test);
        assert_eq!(payload.alert.rule_name, "deny-alert");
        assert_eq!(payload.event.action_kind, "FileWrite");
        assert_eq!(payload.event.principal, "my-agent");
        assert_eq!(payload.event.decision, "Deny");
        assert_eq!(payload.context.config_name, "my-config");
        assert!(payload.context.session_id.is_some());
    }

    #[test]
    fn payload_text_format() {
        let event = sample_event();
        let payload = build_payload("deny-alert", "my-config", &event, false);

        assert!(payload.text.starts_with("[DENY]"));
        assert!(payload.text.contains("my-agent"));
        assert!(payload.text.contains("FileWrite"));
        assert!(payload.text.contains("/etc/secrets/.env"));
        assert!(payload.text.contains("(rule: deny-alert)"));
    }

    #[test]
    fn payload_test_flag() {
        let event = sample_event();
        let payload = build_payload("test-rule", "cfg", &event, true);
        assert!(payload.test);
    }

    #[test]
    fn payload_serializes_to_json() {
        let event = sample_event();
        let payload = build_payload("deny-alert", "my-config", &event, false);
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"version\":\"1\""));
        assert!(json.contains("\"rule_name\":\"deny-alert\""));
    }

    #[test]
    fn extract_target_file_path() {
        let detail = r#"{"FileWrite":{"path":"/tmp/foo.txt"}}"#;
        assert_eq!(extract_target(detail, "FileWrite"), "/tmp/foo.txt");
    }

    #[test]
    fn extract_target_network() {
        let detail = r#"{"NetConnect":{"host":"evil.com","port":443}}"#;
        assert_eq!(extract_target(detail, "NetConnect"), "evil.com:443");
    }

    #[test]
    fn extract_target_fallback() {
        let detail = r#"{"ProcessSpawn":{"command":"ls"}}"#;
        assert_eq!(extract_target(detail, "ProcessSpawn"), "ProcessSpawn");
    }
}
