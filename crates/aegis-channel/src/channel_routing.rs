//! Per-channel command routing with allowlists, blocklists, and aliases.
//!
//! Each messaging channel (Telegram, Slack, Discord, etc.) can have its own
//! command set: which commands are allowed, which are blocked, and what
//! aliases map to which commands. The [`ChannelCommandRouter`] resolves
//! raw user input into validated command names, enforcing security
//! constraints at every step.
//!
//! # Security
//!
//! - All command names and channel types are validated (alphanumeric + dash/underscore only).
//! - Null bytes, control characters, and shell metacharacters are rejected.
//! - Alias targets must reference real commands, not other aliases (no loops).
//! - Fail closed: if routing fails for any reason, the command is denied.
//! - All blocked/denied commands are logged for audit trail.

use std::collections::HashMap;

use thiserror::Error;
use tracing::warn;

/// Maximum length for a channel type identifier.
const MAX_CHANNEL_TYPE_LEN: usize = 32;

/// Maximum length for a command name.
const MAX_COMMAND_NAME_LEN: usize = 64;

/// Errors from channel command routing.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChannelRoutingError {
    /// The command is explicitly blocked for this channel.
    #[error("command {command:?} is blocked on channel {channel:?}")]
    CommandBlocked { command: String, channel: String },

    /// The command is not in the channel's allowlist.
    #[error("command {command:?} is not allowed on channel {channel:?}")]
    CommandNotAllowed { command: String, channel: String },

    /// The command name is invalid (bad characters, too long, etc.).
    #[error("invalid command {command:?}: {reason}")]
    InvalidCommand { command: String, reason: String },

    /// The channel type is unknown and no default is configured.
    #[error("unknown channel {channel:?}")]
    UnknownChannel { channel: String },
}

/// Validate that a string contains only safe characters for a command name
/// or channel type: alphanumeric, dash, underscore.
///
/// Rejects null bytes, control characters, path traversal sequences, and
/// shell metacharacters.
fn validate_identifier(value: &str, kind: &str, max_len: usize) -> Result<(), ChannelRoutingError> {
    if value.is_empty() {
        return Err(ChannelRoutingError::InvalidCommand {
            command: value.to_string(),
            reason: format!("{kind} cannot be empty"),
        });
    }

    if value.len() > max_len {
        return Err(ChannelRoutingError::InvalidCommand {
            command: value.to_string(),
            reason: format!("{kind} exceeds maximum length of {max_len} characters"),
        });
    }

    // Reject null bytes and control characters explicitly
    if value.bytes().any(|b| b == 0 || b < 0x20) {
        return Err(ChannelRoutingError::InvalidCommand {
            command: value.to_string(),
            reason: format!("{kind} contains null bytes or control characters"),
        });
    }

    // Reject path traversal
    if value.contains("..") || value.contains('/') || value.contains('\\') {
        return Err(ChannelRoutingError::InvalidCommand {
            command: value.to_string(),
            reason: format!("{kind} contains path traversal sequences"),
        });
    }

    // Only allow alphanumeric, dash, underscore
    if !value
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ChannelRoutingError::InvalidCommand {
            command: value.to_string(),
            reason: format!(
                "{kind} may only contain letters, digits, hyphens, and underscores"
            ),
        });
    }

    Ok(())
}

/// Validate a channel type identifier.
fn validate_channel_type(channel: &str) -> Result<(), ChannelRoutingError> {
    validate_identifier(channel, "channel type", MAX_CHANNEL_TYPE_LEN)
}

/// Validate a command name.
fn validate_command_name(command: &str) -> Result<(), ChannelRoutingError> {
    validate_identifier(command, "command name", MAX_COMMAND_NAME_LEN)
}

/// Sanitize raw input by stripping null bytes and control characters.
///
/// Returns the cleaned string. This is a defense-in-depth measure -- the
/// validator will still reject the cleaned string if it contains
/// unexpected characters.
fn sanitize_input(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .collect()
}

/// A set of command routing rules for a specific channel type.
///
/// Controls which commands are available, blocked, and aliased on a
/// particular messaging channel.
#[derive(Debug, Clone)]
pub struct ChannelCommandSet {
    /// Channel type identifier (e.g., "telegram", "slack", "discord").
    channel_type: String,
    /// If `Some`, only these commands are allowed. `None` means all
    /// non-blocked commands are allowed.
    allowed_commands: Option<Vec<String>>,
    /// Commands that are always denied on this channel.
    blocked_commands: Vec<String>,
    /// Shorthand aliases mapping to real command names.
    aliases: HashMap<String, String>,
}

impl ChannelCommandSet {
    /// Create a new command set for the given channel type.
    ///
    /// # Errors
    ///
    /// Returns an error if any channel type, command name, or alias is invalid.
    /// Also returns an error if any alias target references another alias
    /// (preventing alias loops).
    pub fn new(
        channel_type: String,
        allowed_commands: Option<Vec<String>>,
        blocked_commands: Vec<String>,
        aliases: HashMap<String, String>,
    ) -> Result<Self, ChannelRoutingError> {
        validate_channel_type(&channel_type)?;

        if let Some(ref allowed) = allowed_commands {
            for cmd in allowed {
                validate_command_name(cmd)?;
            }
        }

        for cmd in &blocked_commands {
            validate_command_name(cmd)?;
        }

        for (alias_name, alias_target) in &aliases {
            validate_command_name(alias_name)?;
            validate_command_name(alias_target)?;
        }

        // Prevent alias chains: no alias target may be another alias key.
        for target in aliases.values() {
            if aliases.contains_key(target) {
                return Err(ChannelRoutingError::InvalidCommand {
                    command: target.clone(),
                    reason: "alias target must not reference another alias (prevents loops)"
                        .to_string(),
                });
            }
        }

        Ok(Self {
            channel_type,
            allowed_commands,
            blocked_commands,
            aliases,
        })
    }

    /// The channel type this set applies to.
    pub fn channel_type(&self) -> &str {
        &self.channel_type
    }
}

/// Routes commands to the appropriate channel-specific command set.
///
/// Holds per-channel command sets and a default set. When resolving a
/// command, looks up the channel's set first; falls back to the default
/// if the channel is not explicitly configured.
#[derive(Debug, Clone)]
pub struct ChannelCommandRouter {
    /// Per-channel command sets, keyed by channel type.
    channel_sets: HashMap<String, ChannelCommandSet>,
    /// Default command set used when a channel has no explicit configuration.
    default_set: ChannelCommandSet,
}

impl ChannelCommandRouter {
    /// Create a new router with per-channel sets and a default set.
    ///
    /// # Errors
    ///
    /// Returns an error if any channel set has a duplicate channel type.
    pub fn new(
        sets: Vec<ChannelCommandSet>,
        default_set: ChannelCommandSet,
    ) -> Result<Self, ChannelRoutingError> {
        let mut channel_sets = HashMap::new();
        for set in sets {
            if channel_sets.contains_key(&set.channel_type) {
                return Err(ChannelRoutingError::InvalidCommand {
                    command: set.channel_type.clone(),
                    reason: format!(
                        "duplicate channel command set for {:?}",
                        set.channel_type
                    ),
                });
            }
            channel_sets.insert(set.channel_type.clone(), set);
        }

        Ok(Self {
            channel_sets,
            default_set,
        })
    }

    /// Create a permissive default router that allows all commands.
    pub fn permissive() -> Self {
        let default_set = ChannelCommandSet {
            channel_type: "default".to_string(),
            allowed_commands: None,
            blocked_commands: Vec::new(),
            aliases: HashMap::new(),
        };
        Self {
            channel_sets: HashMap::new(),
            default_set,
        }
    }

    /// Resolve a raw command string for a given channel.
    ///
    /// 1. Strips leading "/" from the raw command.
    /// 2. Sanitizes the input (removes null bytes, control chars).
    /// 3. Looks up the channel's command set (falls back to default).
    /// 4. Resolves aliases.
    /// 5. Checks the blocklist.
    /// 6. Checks the allowlist.
    /// 7. Returns the resolved command name.
    ///
    /// # Errors
    ///
    /// Returns an error if the command is blocked, not allowed, or invalid.
    pub fn resolve_command(
        &self,
        channel: &str,
        raw_cmd: &str,
    ) -> Result<String, ChannelRoutingError> {
        // Sanitize first
        let sanitized = sanitize_input(raw_cmd);

        // Strip leading "/"
        let cmd = sanitized.strip_prefix('/').unwrap_or(&sanitized);

        // Extract just the command name (before any space/arguments)
        let cmd_name = cmd.split_whitespace().next().unwrap_or(cmd);

        // Validate the command name
        validate_command_name(cmd_name)?;

        // Find the channel's command set (fall back to default)
        let set = self.channel_sets.get(channel).unwrap_or(&self.default_set);

        // Resolve aliases (one level only -- chains are prevented at construction)
        let resolved = set
            .aliases
            .get(cmd_name)
            .cloned()
            .unwrap_or_else(|| cmd_name.to_string());

        // Check blocklist
        if set.blocked_commands.contains(&resolved) {
            warn!(
                channel = channel,
                command = %resolved,
                "blocked command attempted"
            );
            return Err(ChannelRoutingError::CommandBlocked {
                command: resolved,
                channel: channel.to_string(),
            });
        }

        // Check allowlist
        if let Some(ref allowed) = set.allowed_commands {
            if !allowed.contains(&resolved) {
                warn!(
                    channel = channel,
                    command = %resolved,
                    "command not in allowlist"
                );
                return Err(ChannelRoutingError::CommandNotAllowed {
                    command: resolved,
                    channel: channel.to_string(),
                });
            }
        }

        Ok(resolved)
    }

    /// Check whether a command is allowed on a given channel.
    ///
    /// Convenience wrapper around [`resolve_command`](Self::resolve_command)
    /// that returns a boolean instead of the resolved name.
    pub fn is_command_allowed(&self, channel: &str, command: &str) -> bool {
        self.resolve_command(channel, command).is_ok()
    }

    /// List all commands available on a given channel.
    ///
    /// If the channel has an allowlist, returns those commands (minus blocked).
    /// If no allowlist is configured, returns an empty vec (meaning "all
    /// non-blocked commands are allowed" -- the caller must interpret this).
    pub fn list_available_commands(&self, channel: &str) -> Vec<String> {
        let set = self.channel_sets.get(channel).unwrap_or(&self.default_set);

        match &set.allowed_commands {
            Some(allowed) => allowed
                .iter()
                .filter(|cmd| !set.blocked_commands.contains(cmd))
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }
}

/// Build a [`ChannelCommandRouter`] from a [`ChannelRoutingConfig`].
///
/// Converts the serializable config types into validated runtime routing
/// structures.
pub fn router_from_config(
    config: &aegis_types::config::ChannelRoutingConfig,
) -> Result<ChannelCommandRouter, ChannelRoutingError> {
    let default_set = ChannelCommandSet::new(
        "default".to_string(),
        config.default_allowed.clone(),
        config.default_blocked.clone(),
        HashMap::new(),
    )?;

    let mut sets = Vec::new();
    for (channel_type, channel_config) in &config.channels {
        let set = ChannelCommandSet::new(
            channel_type.clone(),
            channel_config.allowed.clone(),
            channel_config.blocked.clone().unwrap_or_default(),
            channel_config.aliases.clone().unwrap_or_default(),
        )?;
        sets.push(set);
    }

    ChannelCommandRouter::new(sets, default_set)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a router with telegram allowing only status/approve,
    /// blocking "stop", with alias "s" -> "status".
    fn test_router() -> ChannelCommandRouter {
        let telegram = ChannelCommandSet::new(
            "telegram".to_string(),
            Some(vec![
                "status".to_string(),
                "approve".to_string(),
                "deny".to_string(),
            ]),
            vec!["stop".to_string()],
            {
                let mut m = HashMap::new();
                m.insert("s".to_string(), "status".to_string());
                m.insert("a".to_string(), "approve".to_string());
                m
            },
        )
        .unwrap();

        let default_set = ChannelCommandSet::new(
            "default".to_string(),
            None,
            vec!["dangerous".to_string()],
            HashMap::new(),
        )
        .unwrap();

        ChannelCommandRouter::new(vec![telegram], default_set).unwrap()
    }

    // -- Required tests --

    #[test]
    fn test_channel_command_allowlist_filtering() {
        let router = test_router();

        // Commands in allowlist pass
        assert!(router.resolve_command("telegram", "status").is_ok());
        assert!(router.resolve_command("telegram", "/status").is_ok());
        assert!(router.resolve_command("telegram", "approve").is_ok());

        // Commands not in allowlist are rejected
        let err = router.resolve_command("telegram", "nudge").unwrap_err();
        assert!(
            matches!(err, ChannelRoutingError::CommandNotAllowed { .. }),
            "expected CommandNotAllowed, got {err:?}"
        );
    }

    #[test]
    fn test_per_channel_alias_resolution() {
        let router = test_router();

        // Alias "s" resolves to "status" for telegram
        let resolved = router.resolve_command("telegram", "s").unwrap();
        assert_eq!(resolved, "status");

        // Alias "a" resolves to "approve"
        let resolved = router.resolve_command("telegram", "/a").unwrap();
        assert_eq!(resolved, "approve");
    }

    #[test]
    fn test_blocked_command_returns_error() {
        let router = test_router();

        let err = router.resolve_command("telegram", "stop").unwrap_err();
        match err {
            ChannelRoutingError::CommandBlocked { command, channel } => {
                assert_eq!(command, "stop");
                assert_eq!(channel, "telegram");
            }
            other => panic!("expected CommandBlocked, got {other:?}"),
        }
    }

    #[test]
    fn test_default_fallback() {
        let router = test_router();

        // Unknown channel uses default command set (no allowlist, blocks "dangerous")
        let resolved = router.resolve_command("slack", "status").unwrap();
        assert_eq!(resolved, "status");

        let resolved = router.resolve_command("slack", "nudge").unwrap();
        assert_eq!(resolved, "nudge");

        // "dangerous" is blocked in the default set
        let err = router.resolve_command("slack", "dangerous").unwrap_err();
        assert!(
            matches!(err, ChannelRoutingError::CommandBlocked { .. }),
            "expected CommandBlocked, got {err:?}"
        );
    }

    #[test]
    fn test_alias_chain_prevention() {
        // Alias "a" -> "b", "b" -> "status" should be rejected (chain)
        let mut aliases = HashMap::new();
        aliases.insert("a".to_string(), "b".to_string());
        aliases.insert("b".to_string(), "status".to_string());

        let result = ChannelCommandSet::new(
            "telegram".to_string(),
            None,
            Vec::new(),
            aliases,
        );

        assert!(result.is_err(), "alias chains should be rejected");
        match result.unwrap_err() {
            ChannelRoutingError::InvalidCommand { reason, .. } => {
                assert!(
                    reason.contains("alias target must not reference another alias"),
                    "wrong error reason: {reason}"
                );
            }
            other => panic!("expected InvalidCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_command_name_validation() {
        // Reject special characters
        assert!(validate_command_name("status").is_ok());
        assert!(validate_command_name("my-command").is_ok());
        assert!(validate_command_name("cmd_123").is_ok());

        // Reject shell metacharacters
        assert!(validate_command_name("cmd;ls").is_err());
        assert!(validate_command_name("cmd|ls").is_err());
        assert!(validate_command_name("cmd&ls").is_err());
        assert!(validate_command_name("cmd$(ls)").is_err());
        assert!(validate_command_name("cmd`ls`").is_err());

        // Reject path traversal
        assert!(validate_command_name("../etc").is_err());
        assert!(validate_command_name("foo/bar").is_err());

        // Reject null bytes (sanitize_input strips them before validation,
        // but direct validation should still catch them)
        assert!(validate_command_name("cmd\0name").is_err());

        // Reject excessive length
        let long = "a".repeat(MAX_COMMAND_NAME_LEN + 1);
        assert!(validate_command_name(&long).is_err());

        // Empty is rejected
        assert!(validate_command_name("").is_err());
    }

    #[test]
    fn test_channel_type_validation() {
        assert!(validate_channel_type("telegram").is_ok());
        assert!(validate_channel_type("my-channel").is_ok());
        assert!(validate_channel_type("chan_123").is_ok());

        // Reject special characters
        assert!(validate_channel_type("tel gram").is_err());
        assert!(validate_channel_type("chan.type").is_err());

        // Reject excessive length
        let long = "a".repeat(MAX_CHANNEL_TYPE_LEN + 1);
        assert!(validate_channel_type(&long).is_err());

        // Empty is rejected
        assert!(validate_channel_type("").is_err());
    }

    #[test]
    fn test_command_injection_prevention() {
        let router = test_router();

        // Path traversal in command
        let err = router.resolve_command("slack", "../etc/passwd").unwrap_err();
        assert!(matches!(err, ChannelRoutingError::InvalidCommand { .. }));

        // Null bytes in direct validation are rejected
        assert!(validate_command_name("cmd\0injection").is_err());

        // Null bytes in router are sanitized away (defense in depth):
        // "cmd\0injection" becomes "cmdinjection" which is safe
        let resolved = router.resolve_command("slack", "cmd\0injection").unwrap();
        assert_eq!(resolved, "cmdinjection");

        // Shell metacharacters
        let err = router.resolve_command("slack", "cmd;rm -rf /").unwrap_err();
        assert!(matches!(err, ChannelRoutingError::InvalidCommand { .. }));

        let err = router.resolve_command("slack", "cmd|cat /etc/passwd").unwrap_err();
        assert!(matches!(err, ChannelRoutingError::InvalidCommand { .. }));

        let err = router.resolve_command("slack", "$(whoami)").unwrap_err();
        assert!(matches!(err, ChannelRoutingError::InvalidCommand { .. }));

        // Backticks
        let err = router.resolve_command("slack", "`id`").unwrap_err();
        assert!(matches!(err, ChannelRoutingError::InvalidCommand { .. }));

        // Unicode exploits (non-alphanumeric)
        let err = router
            .resolve_command("slack", "cmd\u{200B}name")
            .unwrap_err();
        assert!(matches!(err, ChannelRoutingError::InvalidCommand { .. }));
    }

    #[test]
    fn test_channel_specific_formatting_applied() {
        // Verify that the correct command set is selected per channel type
        let telegram = ChannelCommandSet::new(
            "telegram".to_string(),
            Some(vec!["status".to_string()]),
            Vec::new(),
            HashMap::new(),
        )
        .unwrap();

        let slack = ChannelCommandSet::new(
            "slack".to_string(),
            Some(vec!["approve".to_string()]),
            Vec::new(),
            HashMap::new(),
        )
        .unwrap();

        let default_set = ChannelCommandSet::new(
            "default".to_string(),
            None,
            Vec::new(),
            HashMap::new(),
        )
        .unwrap();

        let router = ChannelCommandRouter::new(vec![telegram, slack], default_set).unwrap();

        // Telegram: "status" allowed, "approve" not
        assert!(router.resolve_command("telegram", "status").is_ok());
        assert!(router.resolve_command("telegram", "approve").is_err());

        // Slack: "approve" allowed, "status" not
        assert!(router.resolve_command("slack", "approve").is_ok());
        assert!(router.resolve_command("slack", "status").is_err());

        // Unknown channel: default allows everything
        assert!(router.resolve_command("discord", "anything").is_ok());
    }

    #[test]
    fn test_is_command_allowed() {
        let router = test_router();

        assert!(router.is_command_allowed("telegram", "status"));
        assert!(router.is_command_allowed("telegram", "/status"));
        assert!(!router.is_command_allowed("telegram", "stop"));
        assert!(!router.is_command_allowed("telegram", "nudge"));
    }

    #[test]
    fn test_list_available_commands() {
        let router = test_router();

        // Telegram has an allowlist with "stop" blocked
        let mut cmds = router.list_available_commands("telegram");
        cmds.sort();
        // "stop" is blocked, so only "status", "approve", "deny" remain
        // But "stop" is not in the allowlist either, so it wouldn't appear anyway.
        assert_eq!(cmds, vec!["approve", "deny", "status"]);

        // Unknown channel uses default (no allowlist) -> returns empty vec
        let cmds = router.list_available_commands("unknown");
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_sanitize_input() {
        assert_eq!(sanitize_input("hello"), "hello");
        assert_eq!(sanitize_input("he\0llo"), "hello");
        assert_eq!(sanitize_input("he\nllo"), "hello");
        assert_eq!(sanitize_input("he\rllo"), "hello");
        assert_eq!(sanitize_input("\x01\x02cmd"), "cmd");
    }

    #[test]
    fn test_slash_stripping() {
        let router = test_router();

        // Both with and without "/" should work
        let r1 = router.resolve_command("telegram", "/status").unwrap();
        let r2 = router.resolve_command("telegram", "status").unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r1, "status");
    }

    #[test]
    fn test_permissive_router() {
        let router = ChannelCommandRouter::permissive();

        // Everything should be allowed
        assert!(router.is_command_allowed("telegram", "status"));
        assert!(router.is_command_allowed("slack", "approve"));
        assert!(router.is_command_allowed("discord", "anything"));
    }

    #[test]
    fn test_duplicate_channel_set_rejected() {
        let set1 = ChannelCommandSet::new(
            "telegram".to_string(),
            None,
            Vec::new(),
            HashMap::new(),
        )
        .unwrap();

        let set2 = ChannelCommandSet::new(
            "telegram".to_string(),
            None,
            Vec::new(),
            HashMap::new(),
        )
        .unwrap();

        let default = ChannelCommandSet::new(
            "default".to_string(),
            None,
            Vec::new(),
            HashMap::new(),
        )
        .unwrap();

        let result = ChannelCommandRouter::new(vec![set1, set2], default);
        assert!(result.is_err());
    }

    #[test]
    fn test_router_from_config() {
        use aegis_types::config::{ChannelCommandSetConfig, ChannelRoutingConfig};

        let config = ChannelRoutingConfig {
            default_allowed: None,
            default_blocked: vec!["dangerous".to_string()],
            channels: {
                let mut m = HashMap::new();
                m.insert(
                    "telegram".to_string(),
                    ChannelCommandSetConfig {
                        allowed: Some(vec!["status".to_string(), "approve".to_string()]),
                        blocked: Some(vec!["stop".to_string()]),
                        aliases: Some({
                            let mut a = HashMap::new();
                            a.insert("s".to_string(), "status".to_string());
                            a
                        }),
                    },
                );
                m
            },
        };

        let router = router_from_config(&config).unwrap();

        // Telegram: alias works
        assert_eq!(
            router.resolve_command("telegram", "s").unwrap(),
            "status"
        );
        // Telegram: blocked
        assert!(router.resolve_command("telegram", "stop").is_err());
        // Default: blocks "dangerous"
        assert!(router.resolve_command("slack", "dangerous").is_err());
        // Default: allows non-blocked
        assert!(router.resolve_command("slack", "status").is_ok());
    }

    #[test]
    fn test_blocked_overrides_allowlist() {
        // If a command is in both the allowlist and blocklist, it should be blocked.
        let set = ChannelCommandSet::new(
            "telegram".to_string(),
            Some(vec!["status".to_string(), "stop".to_string()]),
            vec!["stop".to_string()],
            HashMap::new(),
        )
        .unwrap();

        let default = ChannelCommandSet::new(
            "default".to_string(),
            None,
            Vec::new(),
            HashMap::new(),
        )
        .unwrap();

        let router = ChannelCommandRouter::new(vec![set], default).unwrap();

        // "stop" is in the allowlist but also blocked -> should be blocked
        let err = router.resolve_command("telegram", "stop").unwrap_err();
        assert!(matches!(err, ChannelRoutingError::CommandBlocked { .. }));

        // "status" is allowed
        assert!(router.resolve_command("telegram", "status").is_ok());
    }

    #[test]
    fn test_alias_to_blocked_command_is_blocked() {
        // Alias "x" -> "stop", and "stop" is blocked.
        let set = ChannelCommandSet::new(
            "telegram".to_string(),
            None,
            vec!["stop".to_string()],
            {
                let mut m = HashMap::new();
                m.insert("x".to_string(), "stop".to_string());
                m
            },
        )
        .unwrap();

        let default = ChannelCommandSet::new(
            "default".to_string(),
            None,
            Vec::new(),
            HashMap::new(),
        )
        .unwrap();

        let router = ChannelCommandRouter::new(vec![set], default).unwrap();

        // Using the alias should still be blocked
        let err = router.resolve_command("telegram", "x").unwrap_err();
        assert!(matches!(err, ChannelRoutingError::CommandBlocked { .. }));
    }

    #[test]
    fn test_command_with_arguments_extracts_name() {
        let router = test_router();

        // "status agent-1" should extract "status" as the command name
        let resolved = router.resolve_command("telegram", "status agent-1").unwrap();
        assert_eq!(resolved, "status");

        // "/approve abc-123" should extract "approve"
        let resolved = router.resolve_command("telegram", "/approve abc-123").unwrap();
        assert_eq!(resolved, "approve");
    }
}
