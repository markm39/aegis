//! Auto-reply rules engine for inbound messages.
//!
//! Matches inbound message text against configurable regex rules and
//! returns an action to take (reply, approve, deny, or forward).
//! Supports per-chat activation toggling, group/channel filtering,
//! priority-based rule ordering, and SQLite-backed persistence.
//!
//! # Persistent Store
//!
//! [`AutoReplyStore`] provides SQLite-backed persistence for rules and
//! per-chat activation state. Rules survive daemon restarts.
//!
//! # Security
//!
//! - Regex patterns are validated before storing ([`validate_pattern`])
//! - Pattern length is capped at 500 chars to prevent complexity-based ReDoS
//! - Nested quantifiers (e.g. `(a+)+`) are rejected
//! - Response text is sanitized before sending ([`sanitize_response`])
//! - All SQL uses parameterized queries (no injection vectors)
//! - Per-chat rate limiting prevents auto-reply flooding

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use chrono::{DateTime, Utc};
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Security constants
// ---------------------------------------------------------------------------

/// Maximum allowed length for a regex pattern (prevents ReDoS via complexity).
const MAX_PATTERN_LENGTH: usize = 500;

/// Maximum auto-reply responses per chat per minute (rate limiting).
const MAX_REPLIES_PER_MINUTE: usize = 10;

/// Rate-limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Existing types (used by runner.rs and existing callers)
// ---------------------------------------------------------------------------

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

/// A single auto-reply rule (legacy in-memory format used by runner.rs).
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

// ---------------------------------------------------------------------------
// Persistent rule type
// ---------------------------------------------------------------------------

/// A persistent auto-reply rule with metadata (stored in SQLite).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistentAutoReplyRule {
    /// Unique identifier for the rule.
    pub id: String,
    /// Regex pattern to match against inbound message text.
    pub pattern: String,
    /// Response text to send when matched.
    pub response: String,
    /// Whether this rule is currently enabled.
    pub enabled: bool,
    /// Optional chat ID this rule is scoped to (None = global).
    pub chat_id: Option<i64>,
    /// Priority (higher = checked first). Range 0-255.
    pub priority: u8,
    /// When this rule was created.
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Security: Regex validation
// ---------------------------------------------------------------------------

/// Errors that can occur when validating or compiling a regex pattern.
#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    #[error("pattern exceeds maximum length of {MAX_PATTERN_LENGTH} characters (got {0})")]
    TooLong(usize),
    #[error("pattern contains nested quantifiers which may cause catastrophic backtracking")]
    NestedQuantifiers,
    #[error("invalid regex: {0}")]
    InvalidRegex(#[from] regex::Error),
}

/// Validate a regex pattern for safety before storing or compiling.
///
/// Security checks:
/// - Length limit to prevent complexity-based ReDoS
/// - Reject nested quantifiers like `(a+)+`, `(a*)*`, `(a?)+` etc.
/// - Verify the pattern compiles
pub fn validate_pattern(pattern: &str) -> Result<Regex, PatternError> {
    if pattern.len() > MAX_PATTERN_LENGTH {
        return Err(PatternError::TooLong(pattern.len()));
    }

    if has_nested_quantifiers(pattern) {
        return Err(PatternError::NestedQuantifiers);
    }

    let regex = Regex::new(pattern)?;
    Ok(regex)
}

/// Detect nested quantifiers in a pattern string.
///
/// Scans for groups containing quantifiers that are themselves quantified.
/// This is a conservative heuristic -- it may reject some safe patterns,
/// but it catches dangerous ones like `(a+)+`.
fn has_nested_quantifiers(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let len = chars.len();

    let mut group_stack: Vec<bool> = Vec::new();
    let mut i = 0;

    while i < len {
        match chars[i] {
            '\\' => {
                // Skip escaped character
                i += 2;
                continue;
            }
            '(' => {
                group_stack.push(false);
            }
            ')' => {
                let inner_has_quantifier = group_stack.pop().unwrap_or(false);
                if inner_has_quantifier {
                    let next = if i + 1 < len { Some(chars[i + 1]) } else { None };
                    if matches!(next, Some('+') | Some('*') | Some('?') | Some('{')) {
                        return true;
                    }
                }
            }
            '+' | '*' | '?' => {
                if let Some(last) = group_stack.last_mut() {
                    *last = true;
                }
            }
            '{' => {
                if let Some(last) = group_stack.last_mut() {
                    *last = true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Sanitize response text before sending to a channel.
///
/// Strips control characters (except newlines) and limits length to 4096 chars.
pub fn sanitize_response(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(4096)
        .collect()
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Per-chat rate limiter for auto-reply responses.
pub struct RateLimiter {
    windows: HashMap<i64, Vec<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new() -> Self {
        Self {
            windows: HashMap::new(),
        }
    }

    /// Check if a reply is allowed for the given chat_id.
    /// Returns true if under the rate limit, false if rate-limited.
    pub fn check_and_record(&mut self, chat_id: i64) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        let timestamps = self.windows.entry(chat_id).or_default();
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() >= MAX_REPLIES_PER_MINUTE {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Get the current count for a chat within the rate window.
    #[allow(dead_code)]
    pub fn current_count(&self, chat_id: i64) -> usize {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        self.windows
            .get(&chat_id)
            .map(|ts| ts.iter().filter(|t| now.duration_since(**t) < window).count())
            .unwrap_or(0)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SQLite-backed persistent store
// ---------------------------------------------------------------------------

/// SQL schema for the auto-reply rules database.
const STORE_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS auto_reply_rules (
        id TEXT PRIMARY KEY,
        pattern TEXT NOT NULL,
        response TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        chat_id INTEGER,
        priority INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_auto_reply_enabled ON auto_reply_rules(enabled);
    CREATE INDEX IF NOT EXISTS idx_auto_reply_priority ON auto_reply_rules(priority DESC);

    CREATE TABLE IF NOT EXISTS auto_reply_chat_state (
        chat_id INTEGER PRIMARY KEY,
        enabled INTEGER DEFAULT 1
    );
";

/// SQLite-backed persistent store for auto-reply rules and per-chat state.
pub struct AutoReplyStore {
    conn: Connection,
}

impl AutoReplyStore {
    /// Open (or create) the auto-reply store at the given path.
    ///
    /// Enables WAL mode and creates tables if they do not exist.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open auto-reply db '{}': {e}", path.display()))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("failed to set WAL mode: {e}"))?;

        conn.execute_batch(STORE_SCHEMA_SQL)
            .map_err(|e| format!("failed to create auto-reply schema: {e}"))?;

        info!(path = %path.display(), "auto-reply store opened");

        Ok(Self { conn })
    }

    /// Open an in-memory store (for testing).
    pub fn open_in_memory() -> Result<Self, String> {
        let conn =
            Connection::open_in_memory().map_err(|e| format!("failed to open in-memory db: {e}"))?;

        conn.execute_batch(STORE_SCHEMA_SQL)
            .map_err(|e| format!("failed to create auto-reply schema: {e}"))?;

        Ok(Self { conn })
    }

    /// Add a new auto-reply rule after validating the pattern.
    ///
    /// Returns the rule ID on success. The pattern is validated for safety
    /// (length limit, nested quantifier rejection, regex compilation).
    pub fn add_rule(
        &self,
        pattern: &str,
        response: &str,
        chat_id: Option<i64>,
        priority: u8,
    ) -> Result<String, String> {
        // Validate pattern for safety (ReDoS prevention)
        validate_pattern(pattern).map_err(|e| format!("pattern rejected: {e}"))?;

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let sanitized_response = sanitize_response(response);

        self.conn
            .execute(
                "INSERT INTO auto_reply_rules (id, pattern, response, enabled, chat_id, priority, created_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
                params![id, pattern, sanitized_response, chat_id, priority as i32, now],
            )
            .map_err(|e| format!("failed to insert rule: {e}"))?;

        info!(id = %id, pattern = %pattern, "auto-reply rule added");
        Ok(id)
    }

    /// Remove a rule by ID. Returns true if a rule was actually removed.
    pub fn remove_rule(&self, id: &str) -> Result<bool, String> {
        let affected = self
            .conn
            .execute("DELETE FROM auto_reply_rules WHERE id = ?1", params![id])
            .map_err(|e| format!("failed to delete rule: {e}"))?;

        if affected > 0 {
            info!(id = %id, "auto-reply rule removed");
        }
        Ok(affected > 0)
    }

    /// Toggle a rule's enabled state. Returns true if the rule was found.
    pub fn toggle_rule(&self, id: &str, enabled: bool) -> Result<bool, String> {
        let affected = self
            .conn
            .execute(
                "UPDATE auto_reply_rules SET enabled = ?1 WHERE id = ?2",
                params![enabled as i32, id],
            )
            .map_err(|e| format!("failed to toggle rule: {e}"))?;

        if affected > 0 {
            info!(id = %id, enabled = %enabled, "auto-reply rule toggled");
        }
        Ok(affected > 0)
    }

    /// List all rules, ordered by priority descending then created_at ascending.
    pub fn list_rules(&self) -> Result<Vec<PersistentAutoReplyRule>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, pattern, response, enabled, chat_id, priority, created_at
                 FROM auto_reply_rules
                 ORDER BY priority DESC, created_at ASC",
            )
            .map_err(|e| format!("failed to prepare list query: {e}"))?;

        let rules = stmt
            .query_map([], |row| {
                let enabled_int: i32 = row.get(3)?;
                let chat_id: Option<i64> = row.get(4)?;
                let priority_int: i32 = row.get(5)?;
                let created_at_str: String = row.get(6)?;

                let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(PersistentAutoReplyRule {
                    id: row.get(0)?,
                    pattern: row.get(1)?,
                    response: row.get(2)?,
                    enabled: enabled_int != 0,
                    chat_id,
                    priority: priority_int.clamp(0, 255) as u8,
                    created_at,
                })
            })
            .map_err(|e| format!("failed to query rules: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("failed to read rule row: {e}"))?;

        Ok(rules)
    }

    /// Get a single rule by ID.
    pub fn get_rule(&self, id: &str) -> Result<Option<PersistentAutoReplyRule>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, pattern, response, enabled, chat_id, priority, created_at
                 FROM auto_reply_rules WHERE id = ?1",
            )
            .map_err(|e| format!("failed to prepare get query: {e}"))?;

        let result = stmt
            .query_row(params![id], |row| {
                let enabled_int: i32 = row.get(3)?;
                let chat_id: Option<i64> = row.get(4)?;
                let priority_int: i32 = row.get(5)?;
                let created_at_str: String = row.get(6)?;

                let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(PersistentAutoReplyRule {
                    id: row.get(0)?,
                    pattern: row.get(1)?,
                    response: row.get(2)?,
                    enabled: enabled_int != 0,
                    chat_id,
                    priority: priority_int.clamp(0, 255) as u8,
                    created_at,
                })
            })
            .optional()
            .map_err(|e| format!("failed to get rule: {e}"))?;

        Ok(result)
    }

    /// Set per-chat auto-reply activation state.
    pub fn set_chat_enabled(&self, chat_id: i64, enabled: bool) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO auto_reply_chat_state (chat_id, enabled) VALUES (?1, ?2)
                 ON CONFLICT(chat_id) DO UPDATE SET enabled = excluded.enabled",
                params![chat_id, enabled as i32],
            )
            .map_err(|e| format!("failed to set chat state: {e}"))?;

        info!(chat_id = %chat_id, enabled = %enabled, "auto-reply chat state updated");
        Ok(())
    }

    /// Get per-chat auto-reply activation state (defaults to true if not set).
    pub fn is_chat_enabled(&self, chat_id: i64) -> Result<bool, String> {
        let result: Option<i32> = self
            .conn
            .query_row(
                "SELECT enabled FROM auto_reply_chat_state WHERE chat_id = ?1",
                params![chat_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to query chat state: {e}"))?;

        Ok(result.map(|v| v != 0).unwrap_or(true))
    }

    /// List all per-chat activation states.
    pub fn list_chat_states(&self) -> Result<HashMap<i64, bool>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT chat_id, enabled FROM auto_reply_chat_state")
            .map_err(|e| format!("failed to prepare chat state query: {e}"))?;

        let states = stmt
            .query_map([], |row| {
                let chat_id: i64 = row.get(0)?;
                let enabled: i32 = row.get(1)?;
                Ok((chat_id, enabled != 0))
            })
            .map_err(|e| format!("failed to query chat states: {e}"))?
            .collect::<Result<HashMap<_, _>, _>>()
            .map_err(|e| format!("failed to read chat state row: {e}"))?;

        Ok(states)
    }
}

// ---------------------------------------------------------------------------
// Compiled engine (in-memory matching, used by runner.rs)
// ---------------------------------------------------------------------------

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
            .filter_map(|rule| match regex::Regex::new(&rule.pattern) {
                Ok(regex) => Some(CompiledRule { regex, rule }),
                Err(e) => {
                    tracing::warn!(
                        pattern = %rule.pattern,
                        error = %e,
                        "skipping auto-reply rule with invalid regex"
                    );
                    None
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
        if let Some(cid) = chat_id {
            if !self.is_active(cid) {
                return None;
            }
        }

        for compiled in &self.rules {
            if !compiled.rule.groups.is_empty() {
                if let Some(cid) = chat_id {
                    if !compiled.rule.groups.iter().any(|g| g == cid) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

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

// ---------------------------------------------------------------------------
// Persistent engine (priority-ordered, rate-limited)
// ---------------------------------------------------------------------------

/// A compiled persistent rule with pre-built regex.
struct CompiledPersistentRule {
    regex: Regex,
    rule: PersistentAutoReplyRule,
}

/// Persistent auto-reply engine with priority ordering, rate limiting,
/// and per-chat activation. Built from [`AutoReplyStore`].
pub struct PersistentAutoReplyEngine {
    rules: Vec<CompiledPersistentRule>,
    active_chats: HashMap<String, bool>,
    rate_limiter: RateLimiter,
}

impl PersistentAutoReplyEngine {
    /// Create a new engine from a list of persistent rules.
    ///
    /// Rules with invalid or unsafe regex patterns are skipped and logged.
    /// Rules are sorted by priority descending (highest priority first).
    pub fn new(mut rules: Vec<PersistentAutoReplyRule>) -> Self {
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.created_at.cmp(&b.created_at)));

        let compiled = rules
            .into_iter()
            .filter(|rule| rule.enabled)
            .filter_map(|rule| match validate_pattern(&rule.pattern) {
                Ok(regex) => Some(CompiledPersistentRule { regex, rule }),
                Err(e) => {
                    warn!(
                        pattern = %rule.pattern,
                        error = %e,
                        "skipping auto-reply rule with unsafe or invalid regex"
                    );
                    None
                }
            })
            .collect();

        Self {
            rules: compiled,
            active_chats: HashMap::new(),
            rate_limiter: RateLimiter::new(),
        }
    }

    /// Create an engine from a store, loading all rules and chat states.
    pub fn from_store(store: &AutoReplyStore) -> Result<Self, String> {
        let rules = store.list_rules()?;
        let chat_states = store.list_chat_states()?;

        let mut engine = Self::new(rules);
        for (chat_id, enabled) in chat_states {
            engine.active_chats.insert(chat_id.to_string(), enabled);
        }

        Ok(engine)
    }

    /// Check if auto-reply is active for a given chat.
    pub fn is_active(&self, chat_id: &str) -> bool {
        self.active_chats.get(chat_id).copied().unwrap_or(true)
    }

    /// Activate or deactivate auto-reply for a chat.
    pub fn set_active(&mut self, chat_id: &str, active: bool) {
        self.active_chats.insert(chat_id.to_string(), active);
    }

    /// Match inbound text and return the response of the highest-priority
    /// matching rule.
    ///
    /// If `chat_id` is provided and auto-reply is not active for that chat,
    /// returns `None`. Rate limiting is enforced per chat.
    pub fn check(&mut self, text: &str, chat_id: Option<i64>) -> Option<String> {
        if let Some(cid) = chat_id {
            if !self.is_active(&cid.to_string()) {
                return None;
            }
        }

        if let Some(cid) = chat_id {
            if !self.rate_limiter.check_and_record(cid) {
                warn!(chat_id = %cid, "auto-reply rate limit exceeded");
                return None;
            }
        }

        for compiled in &self.rules {
            if let Some(rule_chat_id) = compiled.rule.chat_id {
                if let Some(cid) = chat_id {
                    if rule_chat_id != cid {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            if compiled.regex.is_match(text) {
                return Some(compiled.rule.response.clone());
            }
        }

        None
    }

    /// Match inbound text and return the full matching rule.
    pub fn check_rule(&self, text: &str, chat_id: Option<i64>) -> Option<&PersistentAutoReplyRule> {
        if let Some(cid) = chat_id {
            if !self.is_active(&cid.to_string()) {
                return None;
            }
        }

        for compiled in &self.rules {
            if let Some(rule_chat_id) = compiled.rule.chat_id {
                if let Some(cid) = chat_id {
                    if rule_chat_id != cid {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            if compiled.regex.is_match(text) {
                return Some(&compiled.rule);
            }
        }

        None
    }

    /// Returns the number of compiled (enabled + valid) rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // ===== Existing engine tests (preserved) =====

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
        assert_eq!(
            engine.check("test", Some("chat-123")),
            Some(&AutoAction::Approve)
        );
        assert_eq!(engine.check("test", Some("chat-999")), None);
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

        assert!(engine.is_active("chat-1"));
        assert_eq!(
            engine.check("test", Some("chat-1")),
            Some(&AutoAction::Approve)
        );

        engine.set_active("chat-1", false);
        assert!(!engine.is_active("chat-1"));
        assert_eq!(engine.check("test", Some("chat-1")), None);

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

        assert_eq!(engine.check("test", Some("chat-1")), None);
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

    // ===== New persistent store tests (6 required) =====

    #[test]
    fn auto_reply_rules_persist_across_restart() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        // Create store and insert a rule
        {
            let store = AutoReplyStore::open(&path).unwrap();
            let id = store.add_rule(r"^hello", "Hi there!", None, 10).unwrap();
            assert!(!id.is_empty());

            let rules = store.list_rules().unwrap();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].pattern, "^hello");
            assert_eq!(rules[0].response, "Hi there!");
        }

        // Reopen store (simulates daemon restart) and verify rule persists
        {
            let store = AutoReplyStore::open(&path).unwrap();
            let rules = store.list_rules().unwrap();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].pattern, "^hello");
            assert_eq!(rules[0].response, "Hi there!");
            assert!(rules[0].enabled);
            assert_eq!(rules[0].priority, 10);
        }
    }

    #[test]
    fn per_chat_activation_tracked() {
        let store = AutoReplyStore::open_in_memory().unwrap();

        // Default: enabled
        assert!(store.is_chat_enabled(12345).unwrap());

        // Disable for chat 12345
        store.set_chat_enabled(12345, false).unwrap();
        assert!(!store.is_chat_enabled(12345).unwrap());

        // Other chats are still enabled by default
        assert!(store.is_chat_enabled(99999).unwrap());

        // Re-enable
        store.set_chat_enabled(12345, true).unwrap();
        assert!(store.is_chat_enabled(12345).unwrap());

        // Verify list_chat_states
        let states = store.list_chat_states().unwrap();
        assert_eq!(states.get(&12345), Some(&true));
    }

    #[test]
    fn rule_priority_ordering() {
        let store = AutoReplyStore::open_in_memory().unwrap();

        // Add rules with different priorities
        store.add_rule(r"test", "low priority", None, 1).unwrap();
        store.add_rule(r"test", "high priority", None, 100).unwrap();
        store.add_rule(r"test", "medium priority", None, 50).unwrap();

        let rules = store.list_rules().unwrap();
        let mut engine = PersistentAutoReplyEngine::new(rules);

        // The highest-priority matching rule should win
        let result = engine.check("test message", Some(1));
        assert_eq!(result, Some("high priority".to_string()));
    }

    #[test]
    fn rule_crud_operations() {
        let store = AutoReplyStore::open_in_memory().unwrap();

        // Add
        let id = store.add_rule(r"^ping$", "pong", None, 5).unwrap();
        assert!(!id.is_empty());

        // List
        let rules = store.list_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, id);
        assert_eq!(rules[0].pattern, "^ping$");
        assert_eq!(rules[0].response, "pong");
        assert!(rules[0].enabled);
        assert_eq!(rules[0].priority, 5);

        // Get by ID
        let rule = store.get_rule(&id).unwrap().unwrap();
        assert_eq!(rule.pattern, "^ping$");

        // Toggle disable
        assert!(store.toggle_rule(&id, false).unwrap());
        let rule = store.get_rule(&id).unwrap().unwrap();
        assert!(!rule.enabled);

        // Toggle enable
        assert!(store.toggle_rule(&id, true).unwrap());
        let rule = store.get_rule(&id).unwrap().unwrap();
        assert!(rule.enabled);

        // Remove
        assert!(store.remove_rule(&id).unwrap());
        let rules = store.list_rules().unwrap();
        assert!(rules.is_empty());

        // Remove non-existent returns false
        assert!(!store.remove_rule(&id).unwrap());
    }

    #[test]
    fn daemon_loads_rules_on_startup() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        // First "startup": create rules
        {
            let store = AutoReplyStore::open(&path).unwrap();
            store.add_rule(r"^hello", "Hi!", None, 10).unwrap();
            store.add_rule(r"^bye", "Goodbye!", None, 5).unwrap();
            store.set_chat_enabled(42, false).unwrap();
        }

        // Second "startup": load rules into engine
        {
            let store = AutoReplyStore::open(&path).unwrap();
            let engine = PersistentAutoReplyEngine::from_store(&store).unwrap();

            assert_eq!(engine.rule_count(), 2);
            assert!(!engine.is_active("42"));
            assert!(engine.is_active("99"));
        }
    }

    #[test]
    fn security_test_regex_injection_rejected() {
        let store = AutoReplyStore::open_in_memory().unwrap();

        // Nested quantifiers (ReDoS vector): (a+)+ should be rejected
        let result = store.add_rule(r"(a+)+", "bad", None, 0);
        assert!(result.is_err(), "nested quantifiers (a+)+ must be rejected");
        assert!(
            result.unwrap_err().contains("nested quantifiers"),
            "error message should mention nested quantifiers"
        );

        // Another nested quantifier variant: (a*)*
        let result = store.add_rule(r"(a*)*", "bad", None, 0);
        assert!(result.is_err(), "nested quantifiers (a*)* must be rejected");

        // Pattern too long
        let long_pattern = "a".repeat(MAX_PATTERN_LENGTH + 1);
        let result = store.add_rule(&long_pattern, "bad", None, 0);
        assert!(result.is_err(), "pattern over 500 chars must be rejected");
        assert!(
            result.unwrap_err().contains("maximum length"),
            "error message should mention length"
        );

        // Invalid regex syntax
        let result = store.add_rule(r"[unclosed", "bad", None, 0);
        assert!(result.is_err(), "invalid regex must be rejected");

        // Valid patterns should still work
        let result = store.add_rule(r"^hello\s+world$", "ok", None, 0);
        assert!(result.is_ok(), "valid pattern should be accepted");

        // Simple quantifiers without nesting are fine
        let result = store.add_rule(r"ab+c", "ok", None, 0);
        assert!(result.is_ok(), "simple quantifier should be accepted");

        // Verify no bad rules were stored
        let rules = store.list_rules().unwrap();
        assert_eq!(rules.len(), 2, "only the two valid rules should be stored");
    }

    // ===== Pattern validation unit tests =====

    #[test]
    fn validate_pattern_rejects_nested_quantifiers() {
        assert!(validate_pattern(r"(a+)+").is_err());
        assert!(validate_pattern(r"(a*)*").is_err());
        assert!(validate_pattern(r"(a?)+").is_err());
        assert!(validate_pattern(r"(a+){2,}").is_err());
        assert!(validate_pattern(r"(x+y*)+").is_err());
    }

    #[test]
    fn validate_pattern_accepts_safe_patterns() {
        assert!(validate_pattern(r"^hello$").is_ok());
        assert!(validate_pattern(r"(?i)yes|no").is_ok());
        assert!(validate_pattern(r"\d{1,3}\.\d{1,3}").is_ok());
        assert!(validate_pattern(r"(abc)+").is_ok());
    }

    #[test]
    fn validate_pattern_rejects_too_long() {
        let long = "a".repeat(501);
        assert!(matches!(
            validate_pattern(&long),
            Err(PatternError::TooLong(501))
        ));
    }

    // ===== Rate limiter tests =====

    #[test]
    fn rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new();
        for _ in 0..MAX_REPLIES_PER_MINUTE {
            assert!(limiter.check_and_record(1));
        }
        assert!(!limiter.check_and_record(1));
    }

    #[test]
    fn rate_limiter_separate_chats() {
        let mut limiter = RateLimiter::new();
        for _ in 0..MAX_REPLIES_PER_MINUTE {
            assert!(limiter.check_and_record(1));
        }
        assert!(limiter.check_and_record(2));
    }

    // ===== Sanitization tests =====

    #[test]
    fn sanitize_strips_control_chars() {
        let input = "hello\x00world\x07foo\nbar";
        let result = sanitize_response(input);
        assert_eq!(result, "helloworldfoo\nbar");
    }

    #[test]
    fn sanitize_limits_length() {
        let long = "a".repeat(5000);
        let result = sanitize_response(&long);
        assert_eq!(result.len(), 4096);
    }

    // ===== Persistent engine tests =====

    #[test]
    fn persistent_engine_priority_ordering() {
        let rules = vec![
            PersistentAutoReplyRule {
                id: "1".into(),
                pattern: r"test".into(),
                response: "low".into(),
                enabled: true,
                chat_id: None,
                priority: 1,
                created_at: Utc::now(),
            },
            PersistentAutoReplyRule {
                id: "2".into(),
                pattern: r"test".into(),
                response: "high".into(),
                enabled: true,
                chat_id: None,
                priority: 100,
                created_at: Utc::now(),
            },
        ];
        let mut engine = PersistentAutoReplyEngine::new(rules);
        assert_eq!(engine.check("test", Some(1)), Some("high".to_string()));
    }

    #[test]
    fn persistent_engine_disabled_rules_skipped() {
        let rules = vec![PersistentAutoReplyRule {
            id: "1".into(),
            pattern: r"test".into(),
            response: "should not match".into(),
            enabled: false,
            chat_id: None,
            priority: 100,
            created_at: Utc::now(),
        }];
        let mut engine = PersistentAutoReplyEngine::new(rules);
        assert_eq!(engine.check("test", None), None);
    }

    #[test]
    fn persistent_engine_chat_scoped_rules() {
        let rules = vec![PersistentAutoReplyRule {
            id: "1".into(),
            pattern: r"test".into(),
            response: "scoped".into(),
            enabled: true,
            chat_id: Some(42),
            priority: 0,
            created_at: Utc::now(),
        }];
        let mut engine = PersistentAutoReplyEngine::new(rules);

        assert_eq!(engine.check("test", Some(42)), Some("scoped".to_string()));
        assert_eq!(engine.check("test", Some(99)), None);
        assert_eq!(engine.check("test", None), None);
    }

    #[test]
    fn persistent_engine_chat_activation() {
        let rules = vec![PersistentAutoReplyRule {
            id: "1".into(),
            pattern: r"test".into(),
            response: "ok".into(),
            enabled: true,
            chat_id: None,
            priority: 0,
            created_at: Utc::now(),
        }];
        let mut engine = PersistentAutoReplyEngine::new(rules);

        assert_eq!(engine.check("test", Some(1)), Some("ok".to_string()));

        engine.set_active("1", false);
        assert_eq!(engine.check("test", Some(1)), None);

        engine.set_active("1", true);
        assert_eq!(engine.check("test", Some(1)), Some("ok".to_string()));
    }

    #[test]
    fn persistent_engine_rate_limiting() {
        let rules = vec![PersistentAutoReplyRule {
            id: "1".into(),
            pattern: r"test".into(),
            response: "ok".into(),
            enabled: true,
            chat_id: None,
            priority: 0,
            created_at: Utc::now(),
        }];
        let mut engine = PersistentAutoReplyEngine::new(rules);

        for _ in 0..MAX_REPLIES_PER_MINUTE {
            assert_eq!(engine.check("test", Some(1)), Some("ok".to_string()));
        }
        assert_eq!(engine.check("test", Some(1)), None);
    }

    #[test]
    fn persistent_rule_roundtrip() {
        let rule = PersistentAutoReplyRule {
            id: Uuid::new_v4().to_string(),
            pattern: r"^hello".to_string(),
            response: "Hi!".to_string(),
            enabled: true,
            chat_id: Some(42),
            priority: 10,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: PersistentAutoReplyRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pattern, rule.pattern);
        assert_eq!(back.response, rule.response);
        assert_eq!(back.chat_id, rule.chat_id);
        assert_eq!(back.priority, rule.priority);
    }
}
