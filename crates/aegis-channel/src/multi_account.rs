//! Multi-account support for channel types.
//!
//! Allows multiple accounts (tokens, credentials) per channel type. For
//! example, two Telegram bots or three Slack workspaces can run
//! simultaneously, each with its own polling loop and message routing.
//!
//! # Architecture
//!
//! - [`AccountEntry`]: a single account with name, token, active status.
//! - [`AccountRegistry`]: manages accounts per channel type, with lookup
//!   by name and iteration for active accounts.
//! - Routing is by account name: callers specify which account to use
//!   when sending or receiving messages.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::debug;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum account name length.
const MAX_ACCOUNT_NAME_LEN: usize = 64;

/// Maximum channel type name length.
const MAX_CHANNEL_TYPE_LEN: usize = 64;

/// Maximum number of accounts per channel type.
const MAX_ACCOUNTS_PER_CHANNEL: usize = 16;

/// Maximum number of channel types in a registry.
const MAX_CHANNEL_TYPES: usize = 32;

/// Maximum token length (prevent accidentally storing huge blobs).
const MAX_TOKEN_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// AccountEntry
// ---------------------------------------------------------------------------

/// Account status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Account is active and should be polled.
    Active,
    /// Account is paused (temporarily disabled).
    Paused,
    /// Account is disabled (permanently off until re-enabled).
    Disabled,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// A single account entry for a channel type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntry {
    /// Human-readable account name (e.g., "personal-bot", "work-bot").
    name: String,
    /// Channel type (e.g., "telegram", "slack", "discord").
    channel_type: String,
    /// Authentication token or credential.
    ///
    /// This is stored as an opaque string. The channel backend interprets
    /// it (API token, OAuth token, etc.).
    #[serde(skip_serializing)]
    token: String,
    /// Current status.
    status: AccountStatus,
    /// When this account was registered.
    #[serde(skip)]
    registered_at: Option<Instant>,
    /// When the status was last changed.
    #[serde(skip)]
    status_changed_at: Option<Instant>,
    /// Optional label/description.
    label: Option<String>,
    /// Whether this is the default account for its channel type.
    is_default: bool,
}

impl AccountEntry {
    /// Create a new active account entry.
    fn new(name: String, channel_type: String, token: String) -> Self {
        let now = Instant::now();
        Self {
            name,
            channel_type,
            token,
            status: AccountStatus::Active,
            registered_at: Some(now),
            status_changed_at: Some(now),
            label: None,
            is_default: false,
        }
    }

    /// The account name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The channel type.
    pub fn channel_type(&self) -> &str {
        &self.channel_type
    }

    /// The authentication token.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Current status.
    pub fn status(&self) -> AccountStatus {
        self.status
    }

    /// Whether the account is currently active.
    pub fn is_active(&self) -> bool {
        self.status == AccountStatus::Active
    }

    /// Whether this is the default account for its channel type.
    pub fn is_default(&self) -> bool {
        self.is_default
    }

    /// Optional label.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// When this account was registered.
    pub fn registered_at(&self) -> Option<Instant> {
        self.registered_at
    }

    /// When the status was last changed.
    pub fn status_changed_at(&self) -> Option<Instant> {
        self.status_changed_at
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from multi-account operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    /// Invalid name.
    InvalidName { value: String, reason: String },
    /// Account already exists.
    AccountExists { name: String, channel_type: String },
    /// Account not found.
    AccountNotFound { name: String, channel_type: String },
    /// Too many accounts for this channel type.
    TooManyAccounts { channel_type: String, limit: usize },
    /// Too many channel types.
    TooManyChannelTypes { limit: usize },
    /// Invalid token.
    InvalidToken { reason: String },
    /// No default account set.
    NoDefault { channel_type: String },
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName { value, reason } => {
                write!(f, "invalid account name {value:?}: {reason}")
            }
            Self::AccountExists { name, channel_type } => {
                write!(
                    f,
                    "account {name:?} already exists for channel type {channel_type:?}"
                )
            }
            Self::AccountNotFound { name, channel_type } => {
                write!(
                    f,
                    "account {name:?} not found for channel type {channel_type:?}"
                )
            }
            Self::TooManyAccounts {
                channel_type,
                limit,
            } => {
                write!(
                    f,
                    "account limit of {limit} exceeded for channel type {channel_type:?}"
                )
            }
            Self::TooManyChannelTypes { limit } => {
                write!(f, "channel type limit of {limit} exceeded")
            }
            Self::InvalidToken { reason } => {
                write!(f, "invalid token: {reason}")
            }
            Self::NoDefault { channel_type } => {
                write!(
                    f,
                    "no default account set for channel type {channel_type:?}"
                )
            }
        }
    }
}

impl std::error::Error for AccountError {}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_name(value: &str, kind: &str, max_len: usize) -> Result<(), AccountError> {
    if value.is_empty() {
        return Err(AccountError::InvalidName {
            value: value.to_string(),
            reason: format!("{kind} cannot be empty"),
        });
    }
    if value.len() > max_len {
        return Err(AccountError::InvalidName {
            value: value.to_string(),
            reason: format!("{kind} exceeds maximum length of {max_len}"),
        });
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AccountError::InvalidName {
            value: value.to_string(),
            reason: format!(
                "{kind} may only contain ASCII letters, digits, hyphens, and underscores"
            ),
        });
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), AccountError> {
    if token.is_empty() {
        return Err(AccountError::InvalidToken {
            reason: "token cannot be empty".to_string(),
        });
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(AccountError::InvalidToken {
            reason: format!("token exceeds maximum length of {MAX_TOKEN_LEN}"),
        });
    }
    if token
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r')
    {
        return Err(AccountError::InvalidToken {
            reason: "token contains control characters".to_string(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AccountRegistry
// ---------------------------------------------------------------------------

/// Manages multiple accounts across channel types.
///
/// Accounts are organized by channel type. Each channel type can have
/// multiple accounts, one of which can be marked as the default.
#[derive(Debug)]
pub struct AccountRegistry {
    /// Accounts indexed by (channel_type, account_name).
    accounts: HashMap<String, HashMap<String, AccountEntry>>,
}

impl AccountRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    /// Register a new account.
    pub fn add_account(
        &mut self,
        name: impl Into<String>,
        channel_type: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<(), AccountError> {
        let name = name.into();
        let channel_type = channel_type.into();
        let token = token.into();

        validate_name(&name, "account name", MAX_ACCOUNT_NAME_LEN)?;
        validate_name(&channel_type, "channel type", MAX_CHANNEL_TYPE_LEN)?;
        validate_token(&token)?;

        // Check if adding a new channel type would exceed the limit
        if !self.accounts.contains_key(&channel_type) && self.accounts.len() >= MAX_CHANNEL_TYPES {
            return Err(AccountError::TooManyChannelTypes {
                limit: MAX_CHANNEL_TYPES,
            });
        }

        let channel_accounts = self.accounts.entry(channel_type.clone()).or_default();

        if channel_accounts.len() >= MAX_ACCOUNTS_PER_CHANNEL {
            return Err(AccountError::TooManyAccounts {
                channel_type: channel_type.clone(),
                limit: MAX_ACCOUNTS_PER_CHANNEL,
            });
        }

        if channel_accounts.contains_key(&name) {
            return Err(AccountError::AccountExists { name, channel_type });
        }

        let is_first = channel_accounts.is_empty();
        let mut entry = AccountEntry::new(name.clone(), channel_type.clone(), token);
        // First account for a channel type is automatically the default
        if is_first {
            entry.is_default = true;
        }

        debug!(
            account = %name,
            channel_type = %channel_type,
            is_default = is_first,
            "registered account"
        );

        channel_accounts.insert(name, entry);
        Ok(())
    }

    /// Remove an account.
    pub fn remove_account(
        &mut self,
        name: &str,
        channel_type: &str,
    ) -> Result<AccountEntry, AccountError> {
        let channel_accounts =
            self.accounts
                .get_mut(channel_type)
                .ok_or_else(|| AccountError::AccountNotFound {
                    name: name.to_string(),
                    channel_type: channel_type.to_string(),
                })?;

        let entry = channel_accounts
            .remove(name)
            .ok_or_else(|| AccountError::AccountNotFound {
                name: name.to_string(),
                channel_type: channel_type.to_string(),
            })?;

        // If we removed the default, promote the first remaining account
        if entry.is_default {
            if let Some(first) = channel_accounts.values_mut().next() {
                first.is_default = true;
                debug!(
                    account = %first.name,
                    channel_type = %channel_type,
                    "promoted to default after removal"
                );
            }
        }

        // Clean up empty channel type
        if channel_accounts.is_empty() {
            self.accounts.remove(channel_type);
        }

        Ok(entry)
    }

    /// Get an account by name and channel type.
    pub fn get_account(&self, name: &str, channel_type: &str) -> Option<&AccountEntry> {
        self.accounts
            .get(channel_type)
            .and_then(|accts| accts.get(name))
    }

    /// Get a mutable account by name and channel type.
    pub fn get_account_mut(&mut self, name: &str, channel_type: &str) -> Option<&mut AccountEntry> {
        self.accounts
            .get_mut(channel_type)
            .and_then(|accts| accts.get_mut(name))
    }

    /// Get the default account for a channel type.
    pub fn default_account(&self, channel_type: &str) -> Option<&AccountEntry> {
        self.accounts
            .get(channel_type)
            .and_then(|accts| accts.values().find(|a| a.is_default))
    }

    /// Set an account as the default for its channel type.
    pub fn set_default(&mut self, name: &str, channel_type: &str) -> Result<(), AccountError> {
        let channel_accounts =
            self.accounts
                .get_mut(channel_type)
                .ok_or_else(|| AccountError::AccountNotFound {
                    name: name.to_string(),
                    channel_type: channel_type.to_string(),
                })?;

        if !channel_accounts.contains_key(name) {
            return Err(AccountError::AccountNotFound {
                name: name.to_string(),
                channel_type: channel_type.to_string(),
            });
        }

        // Clear existing default
        for entry in channel_accounts.values_mut() {
            entry.is_default = false;
        }

        // Set new default
        if let Some(entry) = channel_accounts.get_mut(name) {
            entry.is_default = true;
        }

        debug!(
            account = %name,
            channel_type = %channel_type,
            "set as default account"
        );

        Ok(())
    }

    /// Set the status of an account.
    pub fn set_status(
        &mut self,
        name: &str,
        channel_type: &str,
        status: AccountStatus,
    ) -> Result<(), AccountError> {
        let entry = self.get_account_mut(name, channel_type).ok_or_else(|| {
            AccountError::AccountNotFound {
                name: name.to_string(),
                channel_type: channel_type.to_string(),
            }
        })?;

        if entry.status != status {
            debug!(
                account = %name,
                channel_type = %channel_type,
                old = %entry.status,
                new = %status,
                "account status changed"
            );
            entry.status = status;
            entry.status_changed_at = Some(Instant::now());
        }
        Ok(())
    }

    /// Set the label for an account.
    pub fn set_label(
        &mut self,
        name: &str,
        channel_type: &str,
        label: Option<String>,
    ) -> Result<(), AccountError> {
        let entry = self.get_account_mut(name, channel_type).ok_or_else(|| {
            AccountError::AccountNotFound {
                name: name.to_string(),
                channel_type: channel_type.to_string(),
            }
        })?;

        entry.label = label;
        Ok(())
    }

    /// Update the token for an account.
    pub fn update_token(
        &mut self,
        name: &str,
        channel_type: &str,
        new_token: impl Into<String>,
    ) -> Result<(), AccountError> {
        let new_token = new_token.into();
        validate_token(&new_token)?;

        let entry = self.get_account_mut(name, channel_type).ok_or_else(|| {
            AccountError::AccountNotFound {
                name: name.to_string(),
                channel_type: channel_type.to_string(),
            }
        })?;

        entry.token = new_token;
        debug!(
            account = %name,
            channel_type = %channel_type,
            "account token updated"
        );
        Ok(())
    }

    /// List all accounts for a channel type.
    pub fn accounts_for_channel(&self, channel_type: &str) -> Vec<&AccountEntry> {
        self.accounts
            .get(channel_type)
            .map(|accts| accts.values().collect())
            .unwrap_or_default()
    }

    /// List all active accounts for a channel type.
    pub fn active_accounts(&self, channel_type: &str) -> Vec<&AccountEntry> {
        self.accounts
            .get(channel_type)
            .map(|accts| accts.values().filter(|a| a.is_active()).collect())
            .unwrap_or_default()
    }

    /// List all registered channel types.
    pub fn channel_types(&self) -> Vec<&str> {
        self.accounts.keys().map(|k| k.as_str()).collect()
    }

    /// Total number of accounts across all channel types.
    pub fn total_accounts(&self) -> usize {
        self.accounts.values().map(|accts| accts.len()).sum()
    }

    /// List all account names for a channel type.
    pub fn account_names(&self, channel_type: &str) -> Vec<&str> {
        self.accounts
            .get(channel_type)
            .map(|accts| accts.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default()
    }
}

impl Default for AccountRegistry {
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

    // -- AccountStatus --

    #[test]
    fn account_status_display() {
        assert_eq!(AccountStatus::Active.to_string(), "active");
        assert_eq!(AccountStatus::Paused.to_string(), "paused");
        assert_eq!(AccountStatus::Disabled.to_string(), "disabled");
    }

    #[test]
    fn account_status_serde() {
        let json = serde_json::to_string(&AccountStatus::Active).unwrap();
        assert_eq!(json, "\"active\"");
        let back: AccountStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AccountStatus::Active);
    }

    // -- Validation --

    #[test]
    fn validate_name_valid() {
        assert!(validate_name("my-bot", "test", 64).is_ok());
        assert!(validate_name("bot_123", "test", 64).is_ok());
    }

    #[test]
    fn validate_name_empty() {
        let err = validate_name("", "test", 64).unwrap_err();
        assert!(matches!(err, AccountError::InvalidName { .. }));
    }

    #[test]
    fn validate_name_too_long() {
        let long = "a".repeat(65);
        let err = validate_name(&long, "test", 64).unwrap_err();
        assert!(matches!(err, AccountError::InvalidName { .. }));
    }

    #[test]
    fn validate_name_special_chars() {
        let err = validate_name("bot@name", "test", 64).unwrap_err();
        assert!(matches!(err, AccountError::InvalidName { .. }));
    }

    #[test]
    fn validate_token_valid() {
        assert!(validate_token("xoxb-123-456-abc").is_ok());
    }

    #[test]
    fn validate_token_empty() {
        let err = validate_token("").unwrap_err();
        assert!(matches!(err, AccountError::InvalidToken { .. }));
    }

    #[test]
    fn validate_token_too_long() {
        let long = "a".repeat(MAX_TOKEN_LEN + 1);
        let err = validate_token(&long).unwrap_err();
        assert!(matches!(err, AccountError::InvalidToken { .. }));
    }

    #[test]
    fn validate_token_control_chars() {
        let err = validate_token("token\x00value").unwrap_err();
        assert!(matches!(err, AccountError::InvalidToken { .. }));
    }

    #[test]
    fn validate_token_newlines_allowed() {
        // Multiline tokens (e.g., PEM keys) should be allowed
        assert!(validate_token("line1\nline2\r\nline3").is_ok());
    }

    // -- AccountEntry --

    #[test]
    fn account_entry_basics() {
        let entry = AccountEntry::new(
            "my-bot".to_string(),
            "telegram".to_string(),
            "token123".to_string(),
        );
        assert_eq!(entry.name(), "my-bot");
        assert_eq!(entry.channel_type(), "telegram");
        assert_eq!(entry.token(), "token123");
        assert_eq!(entry.status(), AccountStatus::Active);
        assert!(entry.is_active());
        assert!(!entry.is_default());
        assert!(entry.label().is_none());
        assert!(entry.registered_at().is_some());
        assert!(entry.status_changed_at().is_some());
    }

    #[test]
    fn account_entry_serde_skips_token() {
        let entry = AccountEntry::new(
            "bot".to_string(),
            "slack".to_string(),
            "secret-token".to_string(),
        );
        let json = serde_json::to_string(&entry).unwrap();
        // Token should NOT appear in serialized output
        assert!(!json.contains("secret-token"));
        assert!(json.contains("bot"));
    }

    // -- AccountRegistry basics --

    #[test]
    fn registry_add_and_get() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "token1").unwrap();

        let acct = reg.get_account("bot-1", "telegram").unwrap();
        assert_eq!(acct.name(), "bot-1");
        assert_eq!(acct.token(), "token1");
        assert!(acct.is_default()); // first account is default
    }

    #[test]
    fn registry_add_duplicate_rejected() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();
        let err = reg.add_account("bot-1", "telegram", "t2").unwrap_err();
        assert!(matches!(err, AccountError::AccountExists { .. }));
    }

    #[test]
    fn registry_same_name_different_channel() {
        let mut reg = AccountRegistry::new();
        reg.add_account("primary", "telegram", "t1").unwrap();
        reg.add_account("primary", "slack", "s1").unwrap();

        assert!(reg.get_account("primary", "telegram").is_some());
        assert!(reg.get_account("primary", "slack").is_some());
        assert_eq!(reg.total_accounts(), 2);
    }

    #[test]
    fn registry_remove_account() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();

        let removed = reg.remove_account("bot-1", "telegram").unwrap();
        assert_eq!(removed.name(), "bot-1");
        assert!(reg.get_account("bot-1", "telegram").is_none());
        assert_eq!(reg.total_accounts(), 0);
    }

    #[test]
    fn registry_remove_nonexistent() {
        let mut reg = AccountRegistry::new();
        let err = reg.remove_account("ghost", "telegram").unwrap_err();
        assert!(matches!(err, AccountError::AccountNotFound { .. }));
    }

    #[test]
    fn registry_remove_default_promotes_next() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();
        reg.add_account("bot-2", "telegram", "t2").unwrap();

        assert!(reg.get_account("bot-1", "telegram").unwrap().is_default());
        reg.remove_account("bot-1", "telegram").unwrap();

        // bot-2 should now be default
        assert!(reg.get_account("bot-2", "telegram").unwrap().is_default());
    }

    // -- Default account --

    #[test]
    fn registry_default_account() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();
        reg.add_account("bot-2", "telegram", "t2").unwrap();

        let default = reg.default_account("telegram").unwrap();
        assert_eq!(default.name(), "bot-1"); // first is default
    }

    #[test]
    fn registry_set_default() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();
        reg.add_account("bot-2", "telegram", "t2").unwrap();

        reg.set_default("bot-2", "telegram").unwrap();

        let default = reg.default_account("telegram").unwrap();
        assert_eq!(default.name(), "bot-2");
        assert!(!reg.get_account("bot-1", "telegram").unwrap().is_default());
    }

    #[test]
    fn registry_set_default_nonexistent() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();
        let err = reg.set_default("ghost", "telegram").unwrap_err();
        assert!(matches!(err, AccountError::AccountNotFound { .. }));
    }

    #[test]
    fn registry_default_account_none_when_empty() {
        let reg = AccountRegistry::new();
        assert!(reg.default_account("telegram").is_none());
    }

    // -- Status management --

    #[test]
    fn registry_set_status() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();

        reg.set_status("bot-1", "telegram", AccountStatus::Paused)
            .unwrap();

        let acct = reg.get_account("bot-1", "telegram").unwrap();
        assert_eq!(acct.status(), AccountStatus::Paused);
        assert!(!acct.is_active());
    }

    #[test]
    fn registry_set_status_nonexistent() {
        let mut reg = AccountRegistry::new();
        let err = reg
            .set_status("ghost", "telegram", AccountStatus::Active)
            .unwrap_err();
        assert!(matches!(err, AccountError::AccountNotFound { .. }));
    }

    // -- Label --

    #[test]
    fn registry_set_label() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();

        reg.set_label("bot-1", "telegram", Some("Personal bot".to_string()))
            .unwrap();

        let acct = reg.get_account("bot-1", "telegram").unwrap();
        assert_eq!(acct.label(), Some("Personal bot"));
    }

    // -- Token update --

    #[test]
    fn registry_update_token() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "old-token").unwrap();

        reg.update_token("bot-1", "telegram", "new-token").unwrap();

        let acct = reg.get_account("bot-1", "telegram").unwrap();
        assert_eq!(acct.token(), "new-token");
    }

    #[test]
    fn registry_update_token_invalid() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();

        let err = reg.update_token("bot-1", "telegram", "").unwrap_err();
        assert!(matches!(err, AccountError::InvalidToken { .. }));
    }

    // -- Listing --

    #[test]
    fn registry_accounts_for_channel() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();
        reg.add_account("bot-2", "telegram", "t2").unwrap();
        reg.add_account("slack-1", "slack", "s1").unwrap();

        let tg = reg.accounts_for_channel("telegram");
        assert_eq!(tg.len(), 2);

        let sl = reg.accounts_for_channel("slack");
        assert_eq!(sl.len(), 1);

        let none = reg.accounts_for_channel("discord");
        assert!(none.is_empty());
    }

    #[test]
    fn registry_active_accounts() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();
        reg.add_account("bot-2", "telegram", "t2").unwrap();
        reg.set_status("bot-2", "telegram", AccountStatus::Paused)
            .unwrap();

        let active = reg.active_accounts("telegram");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name(), "bot-1");
    }

    #[test]
    fn registry_channel_types() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();
        reg.add_account("slack-1", "slack", "s1").unwrap();

        let mut types = reg.channel_types();
        types.sort();
        assert_eq!(types, vec!["slack", "telegram"]);
    }

    #[test]
    fn registry_account_names() {
        let mut reg = AccountRegistry::new();
        reg.add_account("bot-1", "telegram", "t1").unwrap();
        reg.add_account("bot-2", "telegram", "t2").unwrap();

        let mut names = reg.account_names("telegram");
        names.sort();
        assert_eq!(names, vec!["bot-1", "bot-2"]);
    }

    #[test]
    fn registry_total_accounts() {
        let mut reg = AccountRegistry::new();
        assert_eq!(reg.total_accounts(), 0);

        reg.add_account("b1", "telegram", "t1").unwrap();
        reg.add_account("s1", "slack", "s1").unwrap();
        assert_eq!(reg.total_accounts(), 2);
    }

    // -- Limits --

    #[test]
    fn registry_account_limit_per_channel() {
        let mut reg = AccountRegistry::new();
        for i in 0..MAX_ACCOUNTS_PER_CHANNEL {
            reg.add_account(format!("bot-{i}"), "telegram", format!("t{i}"))
                .unwrap();
        }
        let err = reg
            .add_account("one-too-many", "telegram", "t_extra")
            .unwrap_err();
        assert!(matches!(err, AccountError::TooManyAccounts { .. }));
    }

    // -- Default trait --

    #[test]
    fn registry_default() {
        let reg = AccountRegistry::default();
        assert_eq!(reg.total_accounts(), 0);
    }

    // -- Error Display --

    #[test]
    fn error_display() {
        assert_eq!(
            AccountError::AccountNotFound {
                name: "x".to_string(),
                channel_type: "y".to_string(),
            }
            .to_string(),
            "account \"x\" not found for channel type \"y\""
        );
        assert_eq!(
            AccountError::NoDefault {
                channel_type: "tg".to_string()
            }
            .to_string(),
            "no default account set for channel type \"tg\""
        );
        assert_eq!(
            AccountError::TooManyChannelTypes { limit: 5 }.to_string(),
            "channel type limit of 5 exceeded"
        );
    }
}
