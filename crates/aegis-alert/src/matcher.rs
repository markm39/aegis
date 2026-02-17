//! Rule matching: determines whether an [`AlertEvent`] matches an [`AlertRule`].
//!
//! Each filter field in a rule is optional. When present, it must match for the
//! rule to fire. When absent, that dimension is unconstrained. All present
//! filters must match (logical AND).

use aegis_types::AlertRule;
use glob::Pattern;

use crate::AlertEvent;

/// Check whether an alert event matches all filters of an alert rule.
///
/// Returns `true` if every specified filter in the rule matches the event.
/// Filters that are `None` or empty are treated as "match all".
pub fn matches(rule: &AlertRule, event: &AlertEvent) -> bool {
    if let Some(ref decision) = rule.decision {
        if !event.decision.eq_ignore_ascii_case(decision) {
            return false;
        }
    }

    if !rule.action_kinds.is_empty()
        && !rule
            .action_kinds
            .iter()
            .any(|k| k.eq_ignore_ascii_case(&event.action_kind))
    {
        return false;
    }

    if let Some(ref principal) = rule.principal {
        if event.principal != *principal {
            return false;
        }
    }

    if let Some(ref path_glob) = rule.path_glob {
        if let Ok(pattern) = Pattern::new(path_glob) {
            // Extract path from action_detail JSON. The detail is serialized as
            // e.g. {"FileWrite":{"path":"/foo/bar.txt"}} -- we do a simple
            // substring extraction to avoid a full JSON parse on every event.
            let path = extract_path_from_detail(&event.action_detail);
            match path {
                Some(p) => {
                    if !pattern.matches(&p) {
                        return false;
                    }
                }
                // No path in the action detail means the glob can't match.
                None => return false,
            }
        }
        // If the glob pattern is invalid, skip this filter (don't block alerts).
    }

    true
}

/// Extract a file path from a JSON action detail string.
///
/// Looks for `"path":"<value>"` in the JSON without doing a full parse.
/// Returns `None` if no path field is found.
fn extract_path_from_detail(detail: &str) -> Option<String> {
    let marker = "\"path\":\"";
    let start = detail.find(marker)? + marker.len();
    let rest = &detail[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
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
        }
    }

    fn rule_with_defaults() -> AlertRule {
        AlertRule {
            name: "test-rule".into(),
            webhook_url: "https://example.com/hook".into(),
            decision: None,
            action_kinds: vec![],
            path_glob: None,
            principal: None,
            cooldown_secs: 60,
        }
    }

    #[test]
    fn empty_filters_match_everything() {
        let rule = rule_with_defaults();
        assert!(matches(&rule, &sample_event()));
    }

    #[test]
    fn decision_filter_matches() {
        let mut rule = rule_with_defaults();
        rule.decision = Some("Deny".into());
        assert!(matches(&rule, &sample_event()));
    }

    #[test]
    fn decision_filter_rejects() {
        let mut rule = rule_with_defaults();
        rule.decision = Some("Allow".into());
        assert!(!matches(&rule, &sample_event()));
    }

    #[test]
    fn decision_filter_case_insensitive() {
        let mut rule = rule_with_defaults();
        rule.decision = Some("deny".into());
        assert!(matches(&rule, &sample_event()));
    }

    #[test]
    fn action_kinds_filter_matches() {
        let mut rule = rule_with_defaults();
        rule.action_kinds = vec!["FileWrite".into(), "FileDelete".into()];
        assert!(matches(&rule, &sample_event()));
    }

    #[test]
    fn action_kinds_filter_rejects() {
        let mut rule = rule_with_defaults();
        rule.action_kinds = vec!["NetConnect".into()];
        assert!(!matches(&rule, &sample_event()));
    }

    #[test]
    fn principal_filter_matches() {
        let mut rule = rule_with_defaults();
        rule.principal = Some("my-agent".into());
        assert!(matches(&rule, &sample_event()));
    }

    #[test]
    fn principal_filter_rejects() {
        let mut rule = rule_with_defaults();
        rule.principal = Some("other-agent".into());
        assert!(!matches(&rule, &sample_event()));
    }

    #[test]
    fn path_glob_matches() {
        let mut rule = rule_with_defaults();
        rule.path_glob = Some("**/.env*".into());
        assert!(matches(&rule, &sample_event()));
    }

    #[test]
    fn path_glob_rejects() {
        let mut rule = rule_with_defaults();
        rule.path_glob = Some("**/README.md".into());
        assert!(!matches(&rule, &sample_event()));
    }

    #[test]
    fn path_glob_no_path_in_event_rejects() {
        let mut event = sample_event();
        event.action_detail = r#"{"NetConnect":{"host":"evil.com","port":443}}"#.into();

        let mut rule = rule_with_defaults();
        rule.path_glob = Some("**/.env*".into());
        assert!(!matches(&rule, &event));
    }

    #[test]
    fn combined_filters_all_must_match() {
        let mut rule = rule_with_defaults();
        rule.decision = Some("Deny".into());
        rule.action_kinds = vec!["FileWrite".into()];
        rule.principal = Some("my-agent".into());
        rule.path_glob = Some("**/.env*".into());
        assert!(matches(&rule, &sample_event()));
    }

    #[test]
    fn combined_filters_one_mismatch_rejects() {
        let mut rule = rule_with_defaults();
        rule.decision = Some("Deny".into());
        rule.action_kinds = vec!["FileWrite".into()];
        rule.principal = Some("wrong-agent".into()); // mismatch
        rule.path_glob = Some("**/.env*".into());
        assert!(!matches(&rule, &sample_event()));
    }

    #[test]
    fn extract_path_works() {
        let detail = r#"{"FileWrite":{"path":"/tmp/foo.txt"}}"#;
        assert_eq!(
            extract_path_from_detail(detail),
            Some("/tmp/foo.txt".to_string())
        );
    }

    #[test]
    fn extract_path_missing_returns_none() {
        let detail = r#"{"NetConnect":{"host":"evil.com"}}"#;
        assert_eq!(extract_path_from_detail(detail), None);
    }
}
