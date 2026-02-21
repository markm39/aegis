//! Auto-reply rules engine for inbound messages.
//!
//! Matches inbound message text against configurable regex rules and
//! returns an action to take (reply, approve, deny, or forward).
//! Supports per-chat activation toggling and group/channel filtering.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Action to take when an auto-reply rule matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutoAction {
    /// Send a canned reply.
    Reply(String),
    /// Auto-approve the pending request (matches against request ID in text).
    Approve,
    /// Auto-deny the pending request.
    Deny,
    /// Forward the message text to a specific agent.
    Forward(String),
}

/// A single auto-reply rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoReplyRule {
    /// Regex pattern to match against inbound message text.
    pub pattern: String,
    /// Action to take when pattern matches.
    pub action: AutoAction,
    /// Optional response text (for Reply action, this overrides the action's text).
    #[serde(default)]
    pub response: Option<String>,
    /// Only apply in these group/channel IDs (empty = all).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Only apply in these channel names (empty = all).
    #[serde(default)]
    pub channels: Vec<String>,
}

/// Heartbeat configuration for periodic status messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatConfig {
    /// Interval in seconds between heartbeat messages.
    pub interval_secs: u64,
    /// Message template with variables: `{agent_count}`, `{pending_count}`, `{uptime}`.
    pub message_template: String,
}

impl HeartbeatConfig {
    /// Format the heartbeat template, replacing placeholders with provided values.
    ///
    /// Currently uses placeholder values since fleet data is not available in
    /// the channel layer. Pass `"N/A"` for unknown values.
    pub fn format_message(
        &self,
        agent_count: &str,
        pending_count: &str,
        uptime: &str,
    ) -> String {
        self.message_template
            .replace("{agent_count}", agent_count)
            .replace("{pending_count}", pending_count)
            .replace("{uptime}", uptime)
    }
}

/// A compiled auto-reply rule with pre-built regex.
struct CompiledRule {
    regex: regex::Regex,
    rule: AutoReplyRule,
}

/// Auto-reply engine that matches inbound text against compiled rules.
pub struct AutoReplyEngine {
    rules: Vec<CompiledRule>,
    /// Per-chat activation state (chat_id -> enabled).
    active_chats: HashMap<String, bool>,
}

impl AutoReplyEngine {
    /// Create a new engine from a list of rules.
    ///
    /// Rules with invalid regex patterns are silently skipped and logged.
    pub fn new(rules: Vec<AutoReplyRule>) -> Self {
        let compiled = rules
            .into_iter()
            .filter_map(|rule| {
                match regex::Regex::new(&rule.pattern) {
                    Ok(regex) => Some(CompiledRule { regex, rule }),
                    Err(e) => {
                        tracing::warn!(
                            pattern = %rule.pattern,
                            error = %e,
                            "skipping auto-reply rule with invalid regex"
                        );
                        None
                    }
                }
            })
            .collect();

        Self {
            rules: compiled,
            active_chats: HashMap::new(),
        }
    }

    /// Check if auto-reply is active for a given chat.
    ///
    /// Chats default to active (true) when not explicitly configured.
    pub fn is_active(&self, chat_id: &str) -> bool {
        self.active_chats.get(chat_id).copied().unwrap_or(true)
    }

    /// Activate or deactivate auto-reply for a chat.
    pub fn set_active(&mut self, chat_id: &str, active: bool) {
        self.active_chats.insert(chat_id.to_string(), active);
    }

    /// Match inbound text against rules. Returns the first matching action, or None.
    ///
    /// If `chat_id` is provided and auto-reply is not active for that chat,
    /// returns `None` immediately. Rules are checked in order; the first match wins.
    pub fn check(&self, text: &str, chat_id: Option<&str>) -> Option<&AutoAction> {
        // If chat_id is provided, check activation state
        if let Some(cid) = chat_id {
            if !self.is_active(cid) {
                return None;
            }
        }

        for compiled in &self.rules {
            // Check group/channel filters
            if !compiled.rule.groups.is_empty() {
                if let Some(cid) = chat_id {
                    if !compiled.rule.groups.iter().any(|g| g == cid) {
                        continue;
                    }
                } else {
                    // No chat_id provided but rule requires specific groups -- skip
                    continue;
                }
            }

            // Try regex match
            if compiled.regex.is_match(text) {
                return Some(&compiled.rule.action);
            }
        }

        None
    }

    /// Returns the number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_pattern_match() {
        let rules = vec![AutoReplyRule {
            pattern: r"^hello".to_string(),
            action: AutoAction::Reply("Hi there!".to_string()),
            response: None,
            groups: vec![],
            channels: vec![],
        }];
        let engine = AutoReplyEngine::new(rules);
        assert_eq!(
            engine.check("hello world", None),
            Some(&AutoAction::Reply("Hi there!".to_string()))
        );
        assert_eq!(engine.check("goodbye", None), None);
    }

    #[test]
    fn approve_action() {
        let rules = vec![AutoReplyRule {
            pattern: r"(?i)^yes$".to_string(),
            action: AutoAction::Approve,
            response: None,
            groups: vec![],
            channels: vec![],
        }];
        let engine = AutoReplyEngine::new(rules);
        assert_eq!(engine.check("YES", None), Some(&AutoAction::Approve));
        assert_eq!(engine.check("yes", None), Some(&AutoAction::Approve));
        assert_eq!(engine.check("yes please", None), None);
    }

    #[test]
    fn deny_action() {
        let rules = vec![AutoReplyRule {
            pattern: r"(?i)^no$".to_string(),
            action: AutoAction::Deny,
            response: None,
            groups: vec![],
            channels: vec![],
        }];
        let engine = AutoReplyEngine::new(rules);
        assert_eq!(engine.check("no", None), Some(&AutoAction::Deny));
    }

    #[test]
    fn forward_action() {
        let rules = vec![AutoReplyRule {
            pattern: r"@claude".to_string(),
            action: AutoAction::Forward("claude-1".to_string()),
            response: None,
            groups: vec![],
            channels: vec![],
        }];
        let engine = AutoReplyEngine::new(rules);
        assert_eq!(
            engine.check("hey @claude fix this", None),
            Some(&AutoAction::Forward("claude-1".to_string()))
        );
    }

    #[test]
    fn first_match_wins() {
        let rules = vec![
            AutoReplyRule {
                pattern: r"hello".to_string(),
                action: AutoAction::Reply("first".to_string()),
                response: None,
                groups: vec![],
                channels: vec![],
            },
            AutoReplyRule {
                pattern: r"hello".to_string(),
                action: AutoAction::Reply("second".to_string()),
                response: None,
                groups: vec![],
                channels: vec![],
            },
        ];
        let engine = AutoReplyEngine::new(rules);
        assert_eq!(
            engine.check("hello", None),
            Some(&AutoAction::Reply("first".to_string()))
        );
    }

    #[test]
    fn group_filtering_match() {
        let rules = vec![AutoReplyRule {
            pattern: r"test".to_string(),
            action: AutoAction::Approve,
            response: None,
            groups: vec!["chat-123".to_string()],
            channels: vec![],
        }];
        let engine = AutoReplyEngine::new(rules);
        // Matches when chat_id is in the groups list
        assert_eq!(
            engine.check("test", Some("chat-123")),
            Some(&AutoAction::Approve)
        );
        // Does not match when chat_id is not in the groups list
        assert_eq!(engine.check("test", Some("chat-999")), None);
        // Does not match when no chat_id is provided but groups are required
        assert_eq!(engine.check("test", None), None);
    }

    #[test]
    fn empty_groups_matches_all() {
        let rules = vec![AutoReplyRule {
            pattern: r"test".to_string(),
            action: AutoAction::Approve,
            response: None,
            groups: vec![],
            channels: vec![],
        }];
        let engine = AutoReplyEngine::new(rules);
        assert_eq!(
            engine.check("test", Some("any-chat")),
            Some(&AutoAction::Approve)
        );
        assert_eq!(engine.check("test", None), Some(&AutoAction::Approve));
    }

    #[test]
    fn chat_activation_toggle() {
        let rules = vec![AutoReplyRule {
            pattern: r"test".to_string(),
            action: AutoAction::Approve,
            response: None,
            groups: vec![],
            channels: vec![],
        }];
        let mut engine = AutoReplyEngine::new(rules);

        // Default: active
        assert!(engine.is_active("chat-1"));
        assert_eq!(
            engine.check("test", Some("chat-1")),
            Some(&AutoAction::Approve)
        );

        // Deactivate
        engine.set_active("chat-1", false);
        assert!(!engine.is_active("chat-1"));
        assert_eq!(engine.check("test", Some("chat-1")), None);

        // Reactivate
        engine.set_active("chat-1", true);
        assert!(engine.is_active("chat-1"));
        assert_eq!(
            engine.check("test", Some("chat-1")),
            Some(&AutoAction::Approve)
        );
    }

    #[test]
    fn deactivated_chat_does_not_block_other_chats() {
        let rules = vec![AutoReplyRule {
            pattern: r"test".to_string(),
            action: AutoAction::Approve,
            response: None,
            groups: vec![],
            channels: vec![],
        }];
        let mut engine = AutoReplyEngine::new(rules);
        engine.set_active("chat-1", false);

        // chat-1 is deactivated
        assert_eq!(engine.check("test", Some("chat-1")), None);
        // chat-2 is still active (default)
        assert_eq!(
            engine.check("test", Some("chat-2")),
            Some(&AutoAction::Approve)
        );
    }

    #[test]
    fn invalid_regex_is_skipped() {
        let rules = vec![
            AutoReplyRule {
                pattern: r"[invalid".to_string(),
                action: AutoAction::Reply("bad".to_string()),
                response: None,
                groups: vec![],
                channels: vec![],
            },
            AutoReplyRule {
                pattern: r"good".to_string(),
                action: AutoAction::Reply("ok".to_string()),
                response: None,
                groups: vec![],
                channels: vec![],
            },
        ];
        let engine = AutoReplyEngine::new(rules);
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(
            engine.check("good", None),
            Some(&AutoAction::Reply("ok".to_string()))
        );
    }

    #[test]
    fn no_rules_returns_none() {
        let engine = AutoReplyEngine::new(vec![]);
        assert_eq!(engine.check("anything", None), None);
    }

    #[test]
    fn heartbeat_config_format() {
        let cfg = HeartbeatConfig {
            interval_secs: 300,
            message_template: "Agents: {agent_count}, Pending: {pending_count}, Up: {uptime}"
                .to_string(),
        };
        let msg = cfg.format_message("3", "1", "2h 15m");
        assert_eq!(msg, "Agents: 3, Pending: 1, Up: 2h 15m");
    }

    #[test]
    fn heartbeat_config_roundtrip() {
        let cfg = HeartbeatConfig {
            interval_secs: 60,
            message_template: "Status: {agent_count} agents".to_string(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: HeartbeatConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn auto_reply_rule_roundtrip() {
        let rule = AutoReplyRule {
            pattern: r"^hello".to_string(),
            action: AutoAction::Reply("Hi!".to_string()),
            response: Some("override".to_string()),
            groups: vec!["g1".to_string()],
            channels: vec!["c1".to_string()],
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: AutoReplyRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rule);
    }

    #[test]
    fn auto_action_serde_variants() {
        let actions = vec![
            AutoAction::Reply("hi".to_string()),
            AutoAction::Approve,
            AutoAction::Deny,
            AutoAction::Forward("agent-1".to_string()),
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let back: AutoAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }
}
