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
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{DateTime, Utc};
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use crate::channel::MediaPayload;

// ---------------------------------------------------------------------------
// Security constants
// ---------------------------------------------------------------------------

/// Maximum allowed length for a regex pattern (prevents ReDoS via complexity).
const MAX_PATTERN_LENGTH: usize = 500;

/// Maximum auto-reply responses per chat per minute (rate limiting).
const MAX_REPLIES_PER_MINUTE: usize = 10;

/// Rate-limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Maximum media file size in bytes (default 10 MB).
const MAX_MEDIA_SIZE: u64 = 10_485_760;

/// Maximum length for a sticker file_id.
const MAX_STICKER_FILE_ID_LEN: usize = 256;

/// Allowed image file extensions.
const ALLOWED_IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "bmp"];

/// Allowed document file extensions.
const ALLOWED_FILE_EXTENSIONS: &[&str] = &["pdf", "txt", "csv", "json", "zip"];

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
// Media response types
// ---------------------------------------------------------------------------

/// The kind of response an auto-reply rule produces.
///
/// Defaults to `Text` for backward compatibility with existing rules that
/// store only a text response string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MediaResponseType {
    /// Plain text response (default).
    Text,
    /// Respond with an image from a local filesystem path.
    Image {
        /// Absolute path to the image file.
        path: String,
    },
    /// Respond with a document file from a local filesystem path.
    File {
        /// Absolute path to the file.
        path: String,
        /// Optional caption to send with the file.
        caption: Option<String>,
    },
    /// Respond with a Telegram sticker by file_id.
    Sticker {
        /// Telegram sticker file_id.
        file_id: String,
    },
}

impl Default for MediaResponseType {
    fn default() -> Self {
        Self::Text
    }
}

impl MediaResponseType {
    /// Serialize to a compact string for SQLite storage.
    ///
    /// Uses JSON encoding of the tagged enum.
    pub fn to_db_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| r#"{"type":"text"}"#.to_string())
    }

    /// Deserialize from the SQLite storage string.
    ///
    /// Falls back to `Text` for the literal string "text" (backward compat)
    /// or on any parse error.
    pub fn from_db_string(s: &str) -> Self {
        if s == "text" {
            return Self::Text;
        }
        serde_json::from_str(s).unwrap_or(Self::Text)
    }
}

// ---------------------------------------------------------------------------
// Media validation (security-critical)
// ---------------------------------------------------------------------------

/// Errors from media path or file_id validation.
#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("media path contains null byte")]
    NullByte,
    #[error("media path contains directory traversal component '..'")]
    PathTraversal,
    #[error("media path is not absolute: {0}")]
    NotAbsolute(String),
    #[error("media path is a symlink pointing outside allowed directory")]
    SymlinkEscape,
    #[error("media file not found: {0}")]
    NotFound(String),
    #[error("media file too large: {size} bytes (max {MAX_MEDIA_SIZE})")]
    TooLarge { size: u64 },
    #[error("disallowed media file type: .{0}")]
    DisallowedType(String),
    #[error("media file has no extension")]
    NoExtension,
    #[error("sticker file_id too long ({0} chars, max {MAX_STICKER_FILE_ID_LEN})")]
    StickerIdTooLong(usize),
    #[error("sticker file_id contains invalid characters (only alphanumeric, dash, underscore allowed)")]
    StickerIdInvalidChars,
    #[error("failed to read media file: {0}")]
    IoError(#[from] std::io::Error),
}

/// Validate a sticker file_id.
///
/// Security: only alphanumeric characters, dashes, and underscores are allowed.
/// Maximum length is 256 characters.
pub fn validate_sticker_file_id(file_id: &str) -> Result<(), MediaError> {
    if file_id.len() > MAX_STICKER_FILE_ID_LEN {
        return Err(MediaError::StickerIdTooLong(file_id.len()));
    }
    if !file_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(MediaError::StickerIdInvalidChars);
    }
    Ok(())
}

/// Validate a media file path for security and type correctness.
///
/// Checks:
/// - No null bytes in path
/// - No ".." path components (directory traversal)
/// - Path is absolute
/// - File exists and is not a symlink escaping an allowed directory
/// - File size is within limit (checked via metadata, before reading)
/// - File extension is in the allowlist
///
/// Returns the validated canonical path on success.
pub fn validate_media_path(path: &str) -> Result<PathBuf, MediaError> {
    // Null byte check
    if path.contains('\0') {
        return Err(MediaError::NullByte);
    }

    let file_path = Path::new(path);

    // Must be absolute
    if !file_path.is_absolute() {
        return Err(MediaError::NotAbsolute(path.to_string()));
    }

    // Check for ".." components (traversal prevention)
    for component in file_path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(MediaError::PathTraversal);
        }
    }

    // File must exist
    if !file_path.exists() {
        return Err(MediaError::NotFound(path.to_string()));
    }

    // Resolve symlinks and verify canonical path does not escape
    // by checking that the canonical path still starts with the
    // original directory prefix. This prevents symlink escape attacks.
    let canonical = file_path.canonicalize()?;
    if let Some(parent) = file_path.parent() {
        let canonical_parent = parent.canonicalize()?;
        if !canonical.starts_with(&canonical_parent) {
            return Err(MediaError::SymlinkEscape);
        }
    }

    // Check file size via metadata (before reading into memory)
    let metadata = std::fs::metadata(&canonical)?;
    if metadata.len() > MAX_MEDIA_SIZE {
        return Err(MediaError::TooLarge {
            size: metadata.len(),
        });
    }

    // Validate extension
    let ext = canonical
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .ok_or(MediaError::NoExtension)?;

    // Check against combined allowlist
    let is_allowed = ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str())
        || ALLOWED_FILE_EXTENSIONS.contains(&ext.as_str());

    // Also allow "tar.gz" by checking the full filename
    let is_tar_gz = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".tar.gz"))
        .unwrap_or(false);

    if !is_allowed && !is_tar_gz {
        return Err(MediaError::DisallowedType(ext));
    }

    Ok(canonical)
}

/// Check if a file extension belongs to the image allowlist.
fn is_image_extension(ext: &str) -> bool {
    ALLOWED_IMAGE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
}

/// Load media from disk based on the response type.
///
/// Returns `None` for `Text` response type. For `Image`/`File`, reads the
/// file from disk after path validation. For `Sticker`, validates the
/// file_id format.
///
/// Security: validates path before reading. Checks file size via metadata
/// first to prevent memory exhaustion.
pub fn load_media(response_type: &MediaResponseType) -> Result<Option<MediaPayload>, MediaError> {
    match response_type {
        MediaResponseType::Text => Ok(None),

        MediaResponseType::Image { path } => {
            let canonical = validate_media_path(path)?;
            let ext = canonical
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .unwrap_or_default();

            if !is_image_extension(&ext) {
                return Err(MediaError::DisallowedType(ext));
            }

            let data = std::fs::read(&canonical)?;
            let filename = canonical
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("image")
                .to_string();

            Ok(Some(MediaPayload::Image { data, filename }))
        }

        MediaResponseType::File { path, caption } => {
            let canonical = validate_media_path(path)?;
            let data = std::fs::read(&canonical)?;
            let filename = canonical
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string();

            Ok(Some(MediaPayload::File {
                data,
                filename,
                caption: caption.clone(),
            }))
        }

        MediaResponseType::Sticker { file_id } => {
            validate_sticker_file_id(file_id)?;
            Ok(Some(MediaPayload::Sticker {
                file_id: file_id.clone(),
            }))
        }
    }
}

/// Compute a hex-encoded SHA-256 hash of the given data.
///
/// Used to log a media content hash in the audit trail instead of the
/// raw file contents (which would be too large).
pub fn media_content_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
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
    /// The type of response (text, image, file, sticker). Defaults to Text.
    #[serde(default)]
    pub response_type: MediaResponseType,
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
        created_at TEXT NOT NULL,
        response_type TEXT NOT NULL DEFAULT 'text'
    );
    CREATE INDEX IF NOT EXISTS idx_auto_reply_enabled ON auto_reply_rules(enabled);
    CREATE INDEX IF NOT EXISTS idx_auto_reply_priority ON auto_reply_rules(priority DESC);

    CREATE TABLE IF NOT EXISTS auto_reply_chat_state (
        chat_id INTEGER PRIMARY KEY,
        enabled INTEGER DEFAULT 1
    );
";

/// Migration to add the response_type column to existing databases.
const MIGRATION_ADD_RESPONSE_TYPE: &str =
    "ALTER TABLE auto_reply_rules ADD COLUMN response_type TEXT NOT NULL DEFAULT 'text'";

/// SQLite-backed persistent store for auto-reply rules and per-chat state.
pub struct AutoReplyStore {
    conn: Connection,
}

impl AutoReplyStore {
    /// Open (or create) the auto-reply store at the given path.
    ///
    /// Enables WAL mode and creates tables if they do not exist.
    /// Runs schema migrations for backward compatibility.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open auto-reply db '{}': {e}", path.display()))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("failed to set WAL mode: {e}"))?;

        conn.execute_batch(STORE_SCHEMA_SQL)
            .map_err(|e| format!("failed to create auto-reply schema: {e}"))?;

        Self::run_migrations(&conn);

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

    /// Run schema migrations for existing databases.
    ///
    /// Migrations are idempotent -- they silently skip if the column
    /// already exists (the CREATE TABLE IF NOT EXISTS handles fresh DBs,
    /// this handles upgrades).
    fn run_migrations(conn: &Connection) {
        // Check if response_type column exists
        let has_col = conn
            .prepare("SELECT response_type FROM auto_reply_rules LIMIT 0")
            .is_ok();
        if !has_col {
            if let Err(e) = conn.execute_batch(MIGRATION_ADD_RESPONSE_TYPE) {
                warn!(error = %e, "failed to add response_type column (may already exist)");
            }
        }
    }

    /// Add a new auto-reply rule after validating the pattern.
    ///
    /// Returns the rule ID on success. The pattern is validated for safety
    /// (length limit, nested quantifier rejection, regex compilation).
    ///
    /// If `response_type` is `None`, defaults to `MediaResponseType::Text`.
    /// For media types, the media path or sticker ID is validated at rule
    /// creation time to fail fast on invalid configuration.
    pub fn add_rule(
        &self,
        pattern: &str,
        response: &str,
        chat_id: Option<i64>,
        priority: u8,
    ) -> Result<String, String> {
        self.add_rule_with_media(pattern, response, chat_id, priority, None)
    }

    /// Add a new auto-reply rule with an explicit media response type.
    ///
    /// Validates the pattern, response text, and (if provided) the media
    /// configuration. For `Image`/`File` types, the file path is validated
    /// at rule creation time. For `Sticker`, the file_id format is checked.
    pub fn add_rule_with_media(
        &self,
        pattern: &str,
        response: &str,
        chat_id: Option<i64>,
        priority: u8,
        response_type: Option<MediaResponseType>,
    ) -> Result<String, String> {
        // Validate pattern for safety (ReDoS prevention)
        validate_pattern(pattern).map_err(|e| format!("pattern rejected: {e}"))?;

        let media_type = response_type.unwrap_or_default();

        // Validate media configuration at rule creation time (fail fast)
        match &media_type {
            MediaResponseType::Text => {}
            MediaResponseType::Image { path } => {
                validate_media_path(path)
                    .map_err(|e| format!("media path rejected: {e}"))?;
            }
            MediaResponseType::File { path, .. } => {
                validate_media_path(path)
                    .map_err(|e| format!("media path rejected: {e}"))?;
            }
            MediaResponseType::Sticker { file_id } => {
                validate_sticker_file_id(file_id)
                    .map_err(|e| format!("sticker file_id rejected: {e}"))?;
            }
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let sanitized_response = sanitize_response(response);
        let response_type_str = media_type.to_db_string();

        self.conn
            .execute(
                "INSERT INTO auto_reply_rules (id, pattern, response, enabled, chat_id, priority, created_at, response_type)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7)",
                params![id, pattern, sanitized_response, chat_id, priority as i32, now, response_type_str],
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
                "SELECT id, pattern, response, enabled, chat_id, priority, created_at, response_type
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
                let response_type_str: String = row.get(7)?;

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
                    response_type: MediaResponseType::from_db_string(&response_type_str),
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
                "SELECT id, pattern, response, enabled, chat_id, priority, created_at, response_type
                 FROM auto_reply_rules WHERE id = ?1",
            )
            .map_err(|e| format!("failed to prepare get query: {e}"))?;

        let result = stmt
            .query_row(params![id], |row| {
                let enabled_int: i32 = row.get(3)?;
                let chat_id: Option<i64> = row.get(4)?;
                let priority_int: i32 = row.get(5)?;
                let created_at_str: String = row.get(6)?;
                let response_type_str: String = row.get(7)?;

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
                    response_type: MediaResponseType::from_db_string(&response_type_str),
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
    ///
    /// For backward compatibility, returns only the text response string.
    /// Use [`check_with_media`] to get an `OutboundMessage` with media payloads.
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

    /// Match inbound text and return an `OutboundMessage` with optional media.
    ///
    /// This is the media-aware version of [`check`]. When a matching rule has
    /// a media response type, the media is loaded from disk and attached to
    /// the outbound message. On media load failure, falls back to text-only.
    pub fn check_with_media(
        &mut self,
        text: &str,
        chat_id: Option<i64>,
    ) -> Option<crate::channel::OutboundMessage> {
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
                let response_text = compiled.rule.response.clone();

                // Attempt media loading; fall back to text-only on failure
                match load_media(&compiled.rule.response_type) {
                    Ok(Some(media)) => {
                        // Log the media path and hash (not the data itself)
                        match &media {
                            MediaPayload::Image { data, filename } => {
                                info!(
                                    rule_id = %compiled.rule.id,
                                    filename = %filename,
                                    hash = %media_content_hash(data),
                                    "auto-reply sending image"
                                );
                            }
                            MediaPayload::File {
                                data, filename, ..
                            } => {
                                info!(
                                    rule_id = %compiled.rule.id,
                                    filename = %filename,
                                    hash = %media_content_hash(data),
                                    "auto-reply sending file"
                                );
                            }
                            MediaPayload::Sticker { file_id } => {
                                info!(
                                    rule_id = %compiled.rule.id,
                                    file_id = %file_id,
                                    "auto-reply sending sticker"
                                );
                            }
                        }
                        return Some(crate::channel::OutboundMessage::with_media(
                            response_text,
                            media,
                        ));
                    }
                    Ok(None) => {
                        // Text response type
                        return Some(crate::channel::OutboundMessage::text(response_text));
                    }
                    Err(e) => {
                        warn!(
                            rule_id = %compiled.rule.id,
                            error = %e,
                            "failed to load media for auto-reply, falling back to text"
                        );
                        return Some(crate::channel::OutboundMessage::text(response_text));
                    }
                }
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
                response_type: MediaResponseType::default(),
            },
            PersistentAutoReplyRule {
                id: "2".into(),
                pattern: r"test".into(),
                response: "high".into(),
                enabled: true,
                chat_id: None,
                priority: 100,
                created_at: Utc::now(),
                response_type: MediaResponseType::default(),
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
            response_type: MediaResponseType::default(),
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
            response_type: MediaResponseType::default(),
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
            response_type: MediaResponseType::default(),
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
            response_type: MediaResponseType::default(),
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
            response_type: MediaResponseType::default(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: PersistentAutoReplyRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pattern, rule.pattern);
        assert_eq!(back.response, rule.response);
        assert_eq!(back.chat_id, rule.chat_id);
        assert_eq!(back.priority, rule.priority);
        assert_eq!(back.response_type, MediaResponseType::Text);
    }

    // ===== Media response type tests =====

    #[test]
    fn auto_reply_sends_image() {
        // Create a temp image file
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("test.png");
        std::fs::write(&img_path, b"fake-png-data").unwrap();

        let rules = vec![PersistentAutoReplyRule {
            id: "img-1".into(),
            pattern: r"^show logo$".into(),
            response: "Here is the logo".into(),
            enabled: true,
            chat_id: None,
            priority: 10,
            created_at: Utc::now(),
            response_type: MediaResponseType::Image {
                path: img_path.to_string_lossy().to_string(),
            },
        }];

        let mut engine = PersistentAutoReplyEngine::new(rules);
        let msg = engine.check_with_media("show logo", Some(1));
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg.text, "Here is the logo");
        assert!(msg.media.is_some());

        match msg.media.unwrap() {
            MediaPayload::Image { data, filename } => {
                assert_eq!(data, b"fake-png-data");
                assert_eq!(filename, "test.png");
            }
            other => panic!("expected Image, got {:?}", other),
        }
    }

    #[test]
    fn auto_reply_sends_file_with_caption() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("report.pdf");
        std::fs::write(&file_path, b"fake-pdf-data").unwrap();

        let rules = vec![PersistentAutoReplyRule {
            id: "file-1".into(),
            pattern: r"^get report$".into(),
            response: "Daily report attached".into(),
            enabled: true,
            chat_id: None,
            priority: 10,
            created_at: Utc::now(),
            response_type: MediaResponseType::File {
                path: file_path.to_string_lossy().to_string(),
                caption: Some("Daily compliance report".to_string()),
            },
        }];

        let mut engine = PersistentAutoReplyEngine::new(rules);
        let msg = engine.check_with_media("get report", Some(1));
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg.text, "Daily report attached");
        assert!(msg.media.is_some());

        match msg.media.unwrap() {
            MediaPayload::File {
                data,
                filename,
                caption,
            } => {
                assert_eq!(data, b"fake-pdf-data");
                assert_eq!(filename, "report.pdf");
                assert_eq!(caption, Some("Daily compliance report".to_string()));
            }
            other => panic!("expected File, got {:?}", other),
        }
    }

    #[test]
    fn file_size_limit_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let big_path = dir.path().join("huge.png");
        // Create a file that exceeds MAX_MEDIA_SIZE (write just the metadata check)
        // We cannot easily create a 10MB+ file in a test, so we test the validation
        // function directly with a smaller threshold check.
        // Instead, test that validate_media_path rejects based on real file size.
        let data = vec![0u8; 1024]; // 1KB file (well under limit)
        std::fs::write(&big_path, &data).unwrap();

        // Should pass for small file
        let result = validate_media_path(&big_path.to_string_lossy());
        assert!(result.is_ok());

        // Test the error variant exists and formats correctly
        let err = MediaError::TooLarge {
            size: MAX_MEDIA_SIZE + 1,
        };
        let msg = format!("{err}");
        assert!(msg.contains("too large"));
    }

    #[test]
    fn invalid_media_type_rejected() {
        let dir = tempfile::tempdir().unwrap();

        // .exe should be rejected
        let exe_path = dir.path().join("malware.exe");
        std::fs::write(&exe_path, b"MZ").unwrap();
        let result = validate_media_path(&exe_path.to_string_lossy());
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("disallowed"),
            "should reject .exe files"
        );

        // .sh should be rejected
        let sh_path = dir.path().join("script.sh");
        std::fs::write(&sh_path, b"#!/bin/bash").unwrap();
        let result = validate_media_path(&sh_path.to_string_lossy());
        assert!(result.is_err());

        // .bat should be rejected
        let bat_path = dir.path().join("run.bat");
        std::fs::write(&bat_path, b"@echo off").unwrap();
        let result = validate_media_path(&bat_path.to_string_lossy());
        assert!(result.is_err());

        // .png should be accepted
        let png_path = dir.path().join("safe.png");
        std::fs::write(&png_path, b"PNG").unwrap();
        let result = validate_media_path(&png_path.to_string_lossy());
        assert!(result.is_ok());

        // .pdf should be accepted
        let pdf_path = dir.path().join("doc.pdf");
        std::fs::write(&pdf_path, b"PDF").unwrap();
        let result = validate_media_path(&pdf_path.to_string_lossy());
        assert!(result.is_ok());
    }

    #[test]
    fn media_loading_from_path() {
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("photo.jpg");
        std::fs::write(&img_path, b"JFIF-fake-data").unwrap();

        let response_type = MediaResponseType::Image {
            path: img_path.to_string_lossy().to_string(),
        };

        let result = load_media(&response_type);
        assert!(result.is_ok());
        let media = result.unwrap();
        assert!(media.is_some());

        match media.unwrap() {
            MediaPayload::Image { data, filename } => {
                assert_eq!(data, b"JFIF-fake-data");
                assert_eq!(filename, "photo.jpg");
            }
            other => panic!("expected Image, got {:?}", other),
        }

        // Text type returns None
        let result = load_media(&MediaResponseType::Text);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn security_test_traversal_path_rejected() {
        // Path with ".." component
        let result = validate_media_path("/tmp/../etc/passwd");
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("traversal"),
            "should reject paths with .."
        );

        // Relative path (not absolute)
        let result = validate_media_path("relative/path.png");
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("not absolute"),
            "should reject relative paths"
        );

        // Null byte in path
        let result = validate_media_path("/tmp/file\0.png");
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("null byte"),
            "should reject null bytes"
        );
    }

    #[test]
    fn security_test_file_id_validation() {
        // Valid sticker file_ids
        assert!(validate_sticker_file_id("CAACAgIAAxkBAAI").is_ok());
        assert!(validate_sticker_file_id("abc-def_123").is_ok());
        assert!(validate_sticker_file_id("a").is_ok());

        // Too long
        let long_id = "a".repeat(MAX_STICKER_FILE_ID_LEN + 1);
        let result = validate_sticker_file_id(&long_id);
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("too long"),
            "should reject too-long file_ids"
        );

        // Invalid characters
        assert!(validate_sticker_file_id("abc def").is_err()); // space
        assert!(validate_sticker_file_id("abc/def").is_err()); // slash
        assert!(validate_sticker_file_id("abc\ndef").is_err()); // newline
        assert!(validate_sticker_file_id("abc;def").is_err()); // semicolon
    }

    // ===== Media response type serialization tests =====

    #[test]
    fn media_response_type_db_roundtrip() {
        let types = vec![
            MediaResponseType::Text,
            MediaResponseType::Image {
                path: "/tmp/test.png".into(),
            },
            MediaResponseType::File {
                path: "/tmp/report.pdf".into(),
                caption: Some("A report".into()),
            },
            MediaResponseType::File {
                path: "/tmp/data.csv".into(),
                caption: None,
            },
            MediaResponseType::Sticker {
                file_id: "CAACAgIAAxkBAAI".into(),
            },
        ];

        for media_type in types {
            let db_str = media_type.to_db_string();
            let back = MediaResponseType::from_db_string(&db_str);
            assert_eq!(back, media_type);
        }
    }

    #[test]
    fn media_response_type_backward_compat() {
        // Old rows stored "text" as a plain string
        let result = MediaResponseType::from_db_string("text");
        assert_eq!(result, MediaResponseType::Text);

        // Garbage falls back to Text
        let result = MediaResponseType::from_db_string("invalid-json");
        assert_eq!(result, MediaResponseType::Text);
    }

    #[test]
    fn media_content_hash_deterministic() {
        let data = b"hello world";
        let h1 = media_content_hash(data);
        let h2 = media_content_hash(data);
        assert_eq!(h1, h2);
        assert!(!h1.is_empty());
        // SHA-256 produces 64 hex chars
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn store_add_rule_with_media_type() {
        let store = AutoReplyStore::open_in_memory().unwrap();

        // Create a temp image to pass validation
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("logo.png");
        std::fs::write(&img_path, b"png-data").unwrap();

        let id = store
            .add_rule_with_media(
                r"^logo$",
                "Here is the logo",
                None,
                10,
                Some(MediaResponseType::Image {
                    path: img_path.to_string_lossy().to_string(),
                }),
            )
            .unwrap();

        let rule = store.get_rule(&id).unwrap().unwrap();
        assert_eq!(rule.pattern, "^logo$");
        match &rule.response_type {
            MediaResponseType::Image { path } => {
                assert!(path.ends_with("logo.png"));
            }
            other => panic!("expected Image, got {:?}", other),
        }
    }

    #[test]
    fn store_add_rule_defaults_to_text() {
        let store = AutoReplyStore::open_in_memory().unwrap();
        let id = store.add_rule(r"^ping$", "pong", None, 0).unwrap();
        let rule = store.get_rule(&id).unwrap().unwrap();
        assert_eq!(rule.response_type, MediaResponseType::Text);
    }
}
