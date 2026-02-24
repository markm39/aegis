//! DM-level access control for messaging channels.
//!
//! Provides role-based access control (Admin/User/Viewer) with per-command
//! permission checks and token-bucket rate limiting. Every access denial
//! is logged to the audit trail.
//!
//! ## Security design
//!
//! - **Default deny**: unknown users receive the `Viewer` role (most restrictive).
//! - **Rate limiting**: mandatory for all roles via a per-user token bucket.
//! - **Identifier validation**: rejects null bytes, control characters, and
//!   identifiers exceeding 64 characters.
//! - **Constant-time comparison**: identifier lookups in admin_ids use
//!   constant-time byte comparison to prevent timing side-channels.
//! - **Audit logging**: every denied access attempt is logged with full context.

use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

use subtle::ConstantTimeEq;
use tracing::warn;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length for a chat identifier string.
const MAX_IDENTIFIER_LEN: usize = 64;

/// Maximum burst size for the token bucket (instant commands before throttle).
const MAX_BURST: u32 = 5;

/// Default rate limit per minute for Admin role.
const ADMIN_RATE_LIMIT: u32 = 60;

/// Default rate limit per minute for User role.
const USER_RATE_LIMIT: u32 = 30;

/// Default rate limit per minute for Viewer role.
const VIEWER_RATE_LIMIT: u32 = 10;

/// Commands that require Admin role (only Admin can execute these).
pub const ADMIN_COMMANDS: &[&str] = &["stop", "goal", "config", "add", "remove", "context"];

/// Commands available to User role (in addition to Viewer commands).
///
/// This list contains the commands unique to the User role. Users can also
/// execute all VIEWER_COMMANDS. For the complete set of User-accessible
/// commands, combine this with VIEWER_COMMANDS.
pub const USER_COMMANDS: &[&str] = &["approve", "deny", "nudge", "input", "output"];

/// Commands available to Viewer role (read-only).
pub const VIEWER_COMMANDS: &[&str] = &["status", "help"];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by access control checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControlError {
    /// The user does not have permission to execute the command.
    AccessDenied {
        identifier: String,
        command: String,
        role: ChannelRole,
        reason: String,
    },
    /// The user has exceeded their rate limit.
    RateLimited {
        identifier: String,
        retry_after_secs: u64,
    },
    /// The provided identifier is invalid.
    InvalidIdentifier { identifier: String, reason: String },
}

impl fmt::Display for AccessControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessControlError::AccessDenied { reason, .. } => {
                write!(f, "access denied: {reason}")
            }
            AccessControlError::RateLimited {
                retry_after_secs, ..
            } => {
                write!(f, "rate limited: retry after {retry_after_secs}s")
            }
            AccessControlError::InvalidIdentifier { reason, .. } => {
                write!(f, "invalid identifier: {reason}")
            }
        }
    }
}

impl std::error::Error for AccessControlError {}

// ---------------------------------------------------------------------------
// Chat identifiers
// ---------------------------------------------------------------------------

/// A typed chat identifier for different messaging platforms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChatIdentifier {
    /// Telegram numeric user/chat ID.
    Telegram(i64),
    /// Slack user or channel ID (alphanumeric).
    Slack(String),
    /// Discord user or channel ID (alphanumeric).
    Discord(String),
    /// Generic string identifier for other platforms.
    Generic(String),
}

impl ChatIdentifier {
    /// Return the normalized string representation used as a HashMap key.
    pub fn normalized(&self) -> String {
        match self {
            ChatIdentifier::Telegram(id) => format!("telegram:{id}"),
            ChatIdentifier::Slack(id) => format!("slack:{id}"),
            ChatIdentifier::Discord(id) => format!("discord:{id}"),
            ChatIdentifier::Generic(id) => format!("generic:{id}"),
        }
    }
}

impl fmt::Display for ChatIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.normalized())
    }
}

/// Validate a raw identifier string.
///
/// Rejects:
/// - Empty identifiers
/// - Identifiers longer than 64 characters
/// - Null bytes (`\0`)
/// - Control characters (ASCII 0x00-0x1F, 0x7F)
pub fn validate_identifier(identifier: &str) -> Result<(), AccessControlError> {
    if identifier.is_empty() {
        return Err(AccessControlError::InvalidIdentifier {
            identifier: String::new(),
            reason: "identifier cannot be empty".into(),
        });
    }

    if identifier.len() > MAX_IDENTIFIER_LEN {
        return Err(AccessControlError::InvalidIdentifier {
            identifier: identifier.chars().take(16).collect::<String>() + "...",
            reason: format!("identifier exceeds maximum length of {MAX_IDENTIFIER_LEN} characters"),
        });
    }

    if identifier.contains('\0') {
        return Err(AccessControlError::InvalidIdentifier {
            identifier: identifier.replace('\0', ""),
            reason: "identifier contains null bytes".into(),
        });
    }

    if identifier.chars().any(|c| c.is_ascii_control()) {
        return Err(AccessControlError::InvalidIdentifier {
            identifier: identifier
                .chars()
                .filter(|c| !c.is_ascii_control())
                .collect(),
            reason: "identifier contains control characters".into(),
        });
    }

    Ok(())
}

/// Validate a platform-specific identifier.
///
/// - Telegram: must be parseable as i64 (numeric)
/// - Slack/Discord: must be alphanumeric (plus hyphens and underscores), max 64 chars
/// - Generic: basic validation only (no null/control chars, length check)
pub fn validate_chat_identifier(id: &ChatIdentifier) -> Result<(), AccessControlError> {
    match id {
        ChatIdentifier::Telegram(_) => {
            // Telegram IDs are already typed as i64, always valid.
            Ok(())
        }
        ChatIdentifier::Slack(s) | ChatIdentifier::Discord(s) => {
            validate_identifier(s)?;
            if !s
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(AccessControlError::InvalidIdentifier {
                    identifier: s.clone(),
                    reason: "platform identifier must be alphanumeric (plus hyphens/underscores)"
                        .into(),
                });
            }
            Ok(())
        }
        ChatIdentifier::Generic(s) => validate_identifier(s),
    }
}

// ---------------------------------------------------------------------------
// Roles and permissions
// ---------------------------------------------------------------------------

/// Access control role, ordered by privilege level.
///
/// `Admin` > `User` > `Viewer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChannelRole {
    /// Read-only access: can view status and help only.
    Viewer = 0,
    /// Operational access: can approve/deny, nudge, send input/output.
    User = 1,
    /// Full access: all commands including stop, goal, config, add/remove.
    Admin = 2,
}

impl ChannelRole {
    /// Check whether this role permits the given command.
    pub fn permits(&self, command: &str) -> bool {
        let cmd = command.to_lowercase();
        let cmd_str = cmd.as_str();
        match self {
            ChannelRole::Admin => true,
            ChannelRole::User => {
                USER_COMMANDS.contains(&cmd_str) || VIEWER_COMMANDS.contains(&cmd_str)
            }
            ChannelRole::Viewer => VIEWER_COMMANDS.contains(&cmd_str),
        }
    }

    /// Return the default rate limit per minute for this role.
    pub fn default_rate_limit(&self) -> u32 {
        match self {
            ChannelRole::Admin => ADMIN_RATE_LIMIT,
            ChannelRole::User => USER_RATE_LIMIT,
            ChannelRole::Viewer => VIEWER_RATE_LIMIT,
        }
    }
}

impl fmt::Display for ChannelRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelRole::Admin => write!(f, "Admin"),
            ChannelRole::User => write!(f, "User"),
            ChannelRole::Viewer => write!(f, "Viewer"),
        }
    }
}

/// Per-user permission configuration.
#[derive(Debug, Clone)]
pub struct UserPermission {
    /// The user's role.
    pub role: ChannelRole,
    /// Optional override for allowed commands. `None` means use role defaults.
    pub allowed_commands: Option<Vec<String>>,
    /// Commands per minute rate limit.
    pub rate_limit_per_minute: u32,
}

impl UserPermission {
    /// Create a permission entry with role defaults.
    pub fn from_role(role: ChannelRole) -> Self {
        Self {
            role,
            allowed_commands: None,
            rate_limit_per_minute: role.default_rate_limit(),
        }
    }

    /// Check whether this permission allows the given command.
    pub fn permits(&self, command: &str) -> bool {
        if let Some(ref allowed) = self.allowed_commands {
            let cmd = command.to_lowercase();
            allowed.iter().any(|a| a.to_lowercase() == cmd)
        } else {
            self.role.permits(command)
        }
    }
}

// ---------------------------------------------------------------------------
// Rate tracking (token bucket)
// ---------------------------------------------------------------------------

/// Token-bucket rate tracker for a single user.
#[derive(Debug, Clone)]
struct RateTracker {
    /// Current token count.
    tokens: f64,
    /// Maximum tokens (burst capacity).
    max_tokens: u32,
    /// Tokens refilled per second.
    refill_rate: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl RateTracker {
    /// Create a new rate tracker with the given rate limit (commands per minute).
    fn new(rate_per_minute: u32) -> Self {
        Self {
            tokens: MAX_BURST as f64,
            max_tokens: MAX_BURST,
            refill_rate: rate_per_minute as f64 / 60.0,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns `Ok(())` if allowed, or
    /// `Err(retry_after_secs)` if rate-limited.
    fn try_consume(&mut self) -> Result<(), u64> {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate how long until one token is available.
            let deficit = 1.0 - self.tokens;
            let secs = if self.refill_rate > 0.0 {
                (deficit / self.refill_rate).ceil() as u64
            } else {
                60 // If rate is 0, suggest 60s (should never happen).
            };
            Err(secs.max(1))
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens as f64);
            self.last_refill = now;
        }
    }
}

// ---------------------------------------------------------------------------
// Access control
// ---------------------------------------------------------------------------

/// Channel access control engine.
///
/// Manages per-user roles, permissions, and rate limits for messaging
/// channel commands. All denials are logged via `tracing::warn`.
pub struct ChannelAccessControl {
    /// Per-user permission map. Key is the normalized identifier string.
    permissions: HashMap<String, UserPermission>,
    /// Default role for unknown users (fail-closed: `Viewer`).
    default_role: ChannelRole,
    /// Identifiers that are automatically promoted to Admin.
    admin_ids: Vec<String>,
    /// Per-user rate trackers. Key is the normalized identifier string.
    rate_tracker: HashMap<String, RateTracker>,
}

impl ChannelAccessControl {
    /// Create a new access control instance with default-deny configuration.
    pub fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            default_role: ChannelRole::Viewer,
            admin_ids: Vec::new(),
            rate_tracker: HashMap::new(),
        }
    }

    /// Create from an `AccessControlConfig` (deserialized from TOML).
    pub fn from_config(config: &aegis_types::config::AccessControlConfig) -> Self {
        let default_role = match config.default_role.to_lowercase().as_str() {
            "admin" => ChannelRole::Admin,
            "user" => ChannelRole::User,
            _ => ChannelRole::Viewer, // fail closed
        };

        let mut permissions = HashMap::new();

        // Register admin IDs.
        for id in &config.admin_ids {
            let perm = UserPermission {
                role: ChannelRole::Admin,
                allowed_commands: None,
                rate_limit_per_minute: config.rate_limit_per_minute.unwrap_or(ADMIN_RATE_LIMIT),
            };
            permissions.insert(id.clone(), perm);
        }

        // Register user IDs.
        for id in &config.user_ids {
            let perm = UserPermission {
                role: ChannelRole::User,
                allowed_commands: None,
                rate_limit_per_minute: config.rate_limit_per_minute.unwrap_or(USER_RATE_LIMIT),
            };
            permissions.insert(id.clone(), perm);
        }

        Self {
            permissions,
            default_role,
            admin_ids: config.admin_ids.clone(),
            rate_tracker: HashMap::new(),
        }
    }

    /// Check whether the given identifier is allowed to execute the command.
    ///
    /// Performs in order:
    /// 1. Identifier validation
    /// 2. Role/permission lookup
    /// 3. Command authorization
    /// 4. Rate limit check
    ///
    /// All denials are logged to the audit trail via `tracing::warn`.
    pub fn check_access(
        &mut self,
        identifier: &str,
        command: &str,
    ) -> Result<(), AccessControlError> {
        // 1. Validate identifier.
        validate_identifier(identifier)?;

        // 2. Look up permission (or use default role).
        let permission = self.resolve_permission(identifier);

        // 3. Check command authorization.
        if !permission.permits(command) {
            let err = AccessControlError::AccessDenied {
                identifier: identifier.to_string(),
                command: command.to_string(),
                role: permission.role,
                reason: format!(
                    "role {} does not permit command '{}'",
                    permission.role, command
                ),
            };
            warn!(
                identifier = identifier,
                command = command,
                role = %permission.role,
                "access denied: insufficient permissions"
            );
            return Err(err);
        }

        // 4. Rate limit check.
        let rate_limit = permission.rate_limit_per_minute;
        let tracker = self
            .rate_tracker
            .entry(identifier.to_string())
            .or_insert_with(|| RateTracker::new(rate_limit));

        if let Err(retry_after) = tracker.try_consume() {
            let err = AccessControlError::RateLimited {
                identifier: identifier.to_string(),
                retry_after_secs: retry_after,
            };
            warn!(
                identifier = identifier,
                command = command,
                retry_after_secs = retry_after,
                "access denied: rate limited"
            );
            return Err(err);
        }

        Ok(())
    }

    /// Get the effective role for an identifier.
    pub fn get_role(&self, identifier: &str) -> ChannelRole {
        // Check explicit permissions first.
        if let Some(perm) = self.permissions.get(identifier) {
            return perm.role;
        }

        // Check admin_ids with constant-time comparison.
        if self.is_admin_id(identifier) {
            return ChannelRole::Admin;
        }

        self.default_role
    }

    /// Set the role for an identifier, creating a permission entry if needed.
    pub fn set_role(&mut self, identifier: &str, role: ChannelRole) {
        let entry = self
            .permissions
            .entry(identifier.to_string())
            .or_insert_with(|| UserPermission::from_role(role));
        entry.role = role;
        // Update rate limit to match new role if it was at the old default.
        entry.rate_limit_per_minute = role.default_rate_limit();
    }

    /// Check whether an identifier has Admin role.
    pub fn is_admin(&self, identifier: &str) -> bool {
        self.get_role(identifier) == ChannelRole::Admin
    }

    /// Resolve the effective permission for an identifier.
    fn resolve_permission(&self, identifier: &str) -> UserPermission {
        // Check explicit permissions first.
        if let Some(perm) = self.permissions.get(identifier) {
            return perm.clone();
        }

        // Check admin_ids with constant-time comparison.
        if self.is_admin_id(identifier) {
            return UserPermission::from_role(ChannelRole::Admin);
        }

        // Fall back to default role.
        UserPermission::from_role(self.default_role)
    }

    /// Check if an identifier matches any admin_id using constant-time comparison.
    ///
    /// Iterates all admin_ids to prevent timing side-channels from revealing
    /// which (or how many) admin IDs exist.
    fn is_admin_id(&self, identifier: &str) -> bool {
        let id_bytes = identifier.as_bytes();
        let mut found = false;

        for admin_id in &self.admin_ids {
            let admin_bytes = admin_id.as_bytes();
            // subtle::ConstantTimeEq only works on same-length slices.
            // We still need to iterate all entries to prevent timing leaks
            // on the number of admin_ids.
            if id_bytes.len() == admin_bytes.len() && id_bytes.ct_eq(admin_bytes).into() {
                found = true;
            }
        }

        found
    }
}

impl Default for ChannelAccessControl {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an access control with one admin and one user.
    fn setup_ac() -> ChannelAccessControl {
        let mut ac = ChannelAccessControl::new();
        ac.admin_ids = vec!["admin-001".to_string()];
        ac.set_role("admin-001", ChannelRole::Admin);
        ac.set_role("user-001", ChannelRole::User);
        ac
    }

    #[test]
    fn test_admin_can_execute_all_commands() {
        let mut ac = setup_ac();
        // Pre-seed rate tracker with enough tokens for all test commands.
        let mut tracker = RateTracker::new(600);
        tracker.tokens = 20.0;
        tracker.max_tokens = 20;
        ac.rate_tracker.insert("admin-001".to_string(), tracker);

        for cmd in &[
            "stop", "goal", "approve", "status", "help", "config", "deny",
        ] {
            assert!(
                ac.check_access("admin-001", cmd).is_ok(),
                "admin should be able to execute '{cmd}'"
            );
        }
    }

    #[test]
    fn test_user_cannot_stop_agent() {
        let mut ac = setup_ac();
        let result = ac.check_access("user-001", "stop");
        assert!(result.is_err(), "user should not be able to stop agents");
        match result.unwrap_err() {
            AccessControlError::AccessDenied { command, role, .. } => {
                assert_eq!(command, "stop");
                assert_eq!(role, ChannelRole::User);
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_viewer_can_only_status() {
        let mut ac = ChannelAccessControl::new();
        ac.set_role("viewer-001", ChannelRole::Viewer);

        assert!(ac.check_access("viewer-001", "status").is_ok());
        assert!(ac.check_access("viewer-001", "help").is_ok());

        for cmd in &[
            "approve", "deny", "stop", "goal", "nudge", "input", "output",
        ] {
            assert!(
                ac.check_access("viewer-001", cmd).is_err(),
                "viewer should not be able to execute '{cmd}'"
            );
        }
    }

    #[test]
    fn test_unknown_user_gets_default_role() {
        let mut ac = ChannelAccessControl::new();
        // Default role is Viewer (fail closed).
        assert_eq!(ac.get_role("unknown-user"), ChannelRole::Viewer);
        assert!(ac.check_access("unknown-user", "status").is_ok());
        assert!(ac.check_access("unknown-user", "approve").is_err());
    }

    #[test]
    fn test_rate_limit_enforcement() {
        let mut ac = ChannelAccessControl::new();
        ac.set_role("rate-user", ChannelRole::Admin);

        // Burst of MAX_BURST (5) should succeed.
        for i in 0..MAX_BURST {
            assert!(
                ac.check_access("rate-user", "status").is_ok(),
                "request {i} within burst should succeed"
            );
        }

        // Next request should be rate-limited (no time has passed).
        let result = ac.check_access("rate-user", "status");
        assert!(result.is_err(), "should be rate-limited after burst");
        match result.unwrap_err() {
            AccessControlError::RateLimited {
                retry_after_secs, ..
            } => {
                assert!(retry_after_secs >= 1, "retry_after should be at least 1s");
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn test_access_denial_includes_details() {
        let mut ac = ChannelAccessControl::new();
        ac.set_role("detail-user", ChannelRole::Viewer);

        let result = ac.check_access("detail-user", "stop");
        match result.unwrap_err() {
            AccessControlError::AccessDenied {
                identifier,
                command,
                role,
                reason,
            } => {
                assert_eq!(identifier, "detail-user");
                assert_eq!(command, "stop");
                assert_eq!(role, ChannelRole::Viewer);
                assert!(!reason.is_empty());
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_admin_ids_auto_promoted() {
        let mut ac = ChannelAccessControl::new();
        ac.admin_ids = vec!["auto-admin-42".to_string()];

        assert_eq!(ac.get_role("auto-admin-42"), ChannelRole::Admin);
        assert!(ac.is_admin("auto-admin-42"));
        assert!(ac.check_access("auto-admin-42", "stop").is_ok());
    }

    #[test]
    fn test_set_role_overrides_default() {
        let mut ac = ChannelAccessControl::new();
        assert_eq!(ac.get_role("promoted"), ChannelRole::Viewer);

        ac.set_role("promoted", ChannelRole::User);
        assert_eq!(ac.get_role("promoted"), ChannelRole::User);
        assert!(ac.check_access("promoted", "approve").is_ok());
    }

    #[test]
    fn test_identifier_validation_rejects_null_bytes() {
        let result = validate_identifier("user\0bad");
        match result.unwrap_err() {
            AccessControlError::InvalidIdentifier { reason, .. } => {
                assert!(reason.contains("null"));
            }
            other => panic!("expected InvalidIdentifier, got {other:?}"),
        }
    }

    #[test]
    fn test_identifier_validation_rejects_excessive_length() {
        let long_id = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        let result = validate_identifier(&long_id);
        assert!(matches!(
            result,
            Err(AccessControlError::InvalidIdentifier { .. })
        ));
    }

    #[test]
    fn test_identifier_validation_rejects_control_chars() {
        let result = validate_identifier("user\x07bell");
        match result.unwrap_err() {
            AccessControlError::InvalidIdentifier { reason, .. } => {
                assert!(reason.contains("control"));
            }
            other => panic!("expected InvalidIdentifier, got {other:?}"),
        }
    }

    #[test]
    fn test_identifier_validation_accepts_valid() {
        assert!(validate_identifier("user-123").is_ok());
        assert!(validate_identifier("telegram:42").is_ok());
        assert!(validate_identifier("a").is_ok());
        assert!(validate_identifier(&"x".repeat(MAX_IDENTIFIER_LEN)).is_ok());
    }

    #[test]
    fn test_identifier_validation_rejects_empty() {
        let result = validate_identifier("");
        assert!(matches!(
            result,
            Err(AccessControlError::InvalidIdentifier { .. })
        ));
    }

    #[test]
    fn test_rate_limit_prevents_brute_force() {
        let mut ac = ChannelAccessControl::new();
        ac.set_role("brute-user", ChannelRole::Admin);

        let mut allowed = 0u32;
        let mut denied = 0u32;

        for _ in 0..100 {
            match ac.check_access("brute-user", "status") {
                Ok(()) => allowed += 1,
                Err(AccessControlError::RateLimited { .. }) => denied += 1,
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }

        // Only the burst (5) should have been allowed, all others denied.
        assert_eq!(allowed, MAX_BURST, "only burst should be allowed");
        assert_eq!(denied, 100 - MAX_BURST, "rest should be rate-limited");
    }

    #[test]
    fn test_fail_closed_on_unknown_user() {
        // Unknown users must get the most restrictive role (Viewer).
        // They must not be able to execute any privileged command.
        let mut ac = ChannelAccessControl::new();

        // Verify admin commands are denied.
        for cmd in ADMIN_COMMANDS {
            assert!(
                ac.check_access("totally-unknown", cmd).is_err(),
                "unknown user should be denied '{cmd}'"
            );
        }

        // Verify user commands are denied.
        for cmd in &["approve", "deny", "nudge", "input", "output"] {
            assert!(
                ac.check_access("totally-unknown", cmd).is_err(),
                "unknown user should be denied '{cmd}'"
            );
        }

        // Only viewer commands should work.
        // Need a fresh instance since the previous calls consumed rate tokens.
        let mut ac2 = ChannelAccessControl::new();
        assert!(ac2.check_access("totally-unknown", "status").is_ok());
        assert!(ac2.check_access("totally-unknown", "help").is_ok());
    }

    #[test]
    fn test_chat_identifier_normalized() {
        assert_eq!(
            ChatIdentifier::Telegram(12345).normalized(),
            "telegram:12345"
        );
        assert_eq!(
            ChatIdentifier::Slack("U12345".into()).normalized(),
            "slack:U12345"
        );
        assert_eq!(
            ChatIdentifier::Discord("12345".into()).normalized(),
            "discord:12345"
        );
        assert_eq!(
            ChatIdentifier::Generic("foo".into()).normalized(),
            "generic:foo"
        );
    }

    #[test]
    fn test_chat_identifier_validation_telegram() {
        assert!(validate_chat_identifier(&ChatIdentifier::Telegram(12345)).is_ok());
        assert!(validate_chat_identifier(&ChatIdentifier::Telegram(-1)).is_ok());
    }

    #[test]
    fn test_chat_identifier_validation_slack_valid() {
        assert!(validate_chat_identifier(&ChatIdentifier::Slack("U12345".into())).is_ok());
        assert!(validate_chat_identifier(&ChatIdentifier::Slack("C_abc-123".into())).is_ok());
    }

    #[test]
    fn test_chat_identifier_validation_slack_invalid() {
        let result = validate_chat_identifier(&ChatIdentifier::Slack("bad id!".into()));
        assert!(matches!(
            result,
            Err(AccessControlError::InvalidIdentifier { .. })
        ));
    }

    #[test]
    fn test_chat_identifier_validation_discord_valid() {
        assert!(validate_chat_identifier(&ChatIdentifier::Discord("123456789".into())).is_ok());
    }

    #[test]
    fn test_chat_identifier_validation_discord_invalid() {
        let result = validate_chat_identifier(&ChatIdentifier::Discord("bad<id>".into()));
        assert!(matches!(
            result,
            Err(AccessControlError::InvalidIdentifier { .. })
        ));
    }

    #[test]
    fn test_role_ordering() {
        assert!(ChannelRole::Admin > ChannelRole::User);
        assert!(ChannelRole::User > ChannelRole::Viewer);
        assert!(ChannelRole::Admin > ChannelRole::Viewer);
    }

    #[test]
    fn test_role_display() {
        assert_eq!(ChannelRole::Admin.to_string(), "Admin");
        assert_eq!(ChannelRole::User.to_string(), "User");
        assert_eq!(ChannelRole::Viewer.to_string(), "Viewer");
    }

    #[test]
    fn test_user_permission_custom_allowed_commands() {
        let perm = UserPermission {
            role: ChannelRole::Viewer,
            allowed_commands: Some(vec!["status".into(), "approve".into()]),
            rate_limit_per_minute: 10,
        };
        assert!(perm.permits("status"));
        assert!(perm.permits("approve"));
        assert!(!perm.permits("stop"));
    }

    #[test]
    fn test_from_config() {
        let config = aegis_types::config::AccessControlConfig {
            default_role: "viewer".into(),
            admin_ids: vec!["admin-1".into()],
            user_ids: vec!["user-1".into()],
            rate_limit_per_minute: Some(45),
        };

        let ac = ChannelAccessControl::from_config(&config);
        assert_eq!(ac.get_role("admin-1"), ChannelRole::Admin);
        assert_eq!(ac.get_role("user-1"), ChannelRole::User);
        assert_eq!(ac.get_role("unknown"), ChannelRole::Viewer);
        assert_eq!(ac.default_role, ChannelRole::Viewer);
    }

    #[test]
    fn test_from_config_default_admin() {
        let config = aegis_types::config::AccessControlConfig {
            default_role: "admin".into(),
            admin_ids: vec![],
            user_ids: vec![],
            rate_limit_per_minute: None,
        };

        let ac = ChannelAccessControl::from_config(&config);
        assert_eq!(ac.default_role, ChannelRole::Admin);
    }

    #[test]
    fn test_from_config_invalid_role_fails_closed() {
        let config = aegis_types::config::AccessControlConfig {
            default_role: "superuser".into(), // invalid
            admin_ids: vec![],
            user_ids: vec![],
            rate_limit_per_minute: None,
        };

        let ac = ChannelAccessControl::from_config(&config);
        // Invalid role should fail closed to Viewer.
        assert_eq!(ac.default_role, ChannelRole::Viewer);
    }

    #[test]
    fn test_error_display() {
        let err = AccessControlError::AccessDenied {
            identifier: "user-1".into(),
            command: "stop".into(),
            role: ChannelRole::User,
            reason: "insufficient permissions".into(),
        };
        assert!(err.to_string().contains("access denied"));

        let err = AccessControlError::RateLimited {
            identifier: "user-1".into(),
            retry_after_secs: 5,
        };
        assert!(err.to_string().contains("rate limited"));
        assert!(err.to_string().contains("5s"));

        let err = AccessControlError::InvalidIdentifier {
            identifier: "bad".into(),
            reason: "too short".into(),
        };
        assert!(err.to_string().contains("invalid identifier"));
    }

    #[test]
    fn test_check_access_with_invalid_identifier() {
        let mut ac = ChannelAccessControl::new();
        let result = ac.check_access("user\0injected", "status");
        assert!(matches!(
            result,
            Err(AccessControlError::InvalidIdentifier { .. })
        ));
    }

    #[test]
    fn test_user_can_execute_user_commands() {
        let mut ac = setup_ac();
        for cmd in &["approve", "deny", "nudge", "input", "output"] {
            assert!(
                ac.check_access("user-001", cmd).is_ok(),
                "user should be able to execute '{cmd}'"
            );
        }
    }

    #[test]
    fn test_user_can_execute_viewer_commands() {
        let mut ac = setup_ac();
        assert!(ac.check_access("user-001", "status").is_ok());
        assert!(ac.check_access("user-001", "help").is_ok());
    }

    #[test]
    fn test_constant_time_admin_check() {
        // Verify that admin_ids uses constant-time comparison.
        // We test this indirectly by ensuring the lookup works correctly
        // for both matching and non-matching IDs.
        let mut ac = ChannelAccessControl::new();
        ac.admin_ids = vec!["secret-admin-id".to_string()];

        assert!(ac.is_admin("secret-admin-id"));
        assert!(!ac.is_admin("secret-admin-ix")); // one char diff
        assert!(!ac.is_admin("secret-admin-i")); // shorter
        assert!(!ac.is_admin("secret-admin-idd")); // longer
        assert!(!ac.is_admin("")); // empty
    }

    #[test]
    fn test_rate_tracker_refill() {
        let mut tracker = RateTracker::new(60); // 1 per second

        // Consume all burst tokens.
        for _ in 0..MAX_BURST {
            assert!(tracker.try_consume().is_ok());
        }

        // Should be rate-limited now.
        assert!(tracker.try_consume().is_err());

        // Manually advance the last_refill to simulate time passing.
        tracker.last_refill = Instant::now() - std::time::Duration::from_secs(2);

        // After 2 seconds at 1/sec rate, should have ~2 tokens.
        assert!(tracker.try_consume().is_ok());
    }

    #[test]
    fn test_role_permits_case_insensitive() {
        assert!(ChannelRole::Admin.permits("STOP"));
        assert!(ChannelRole::Admin.permits("Stop"));
        assert!(ChannelRole::User.permits("APPROVE"));
        assert!(ChannelRole::Viewer.permits("STATUS"));
    }
}
