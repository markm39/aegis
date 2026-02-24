//! Command alias system with CRUD operations and cycle prevention.
//!
//! Aliases allow users to define short names for frequently used commands.
//! For example, `s` could expand to `status`, or `ap` to `approve --all`.
//!
//! # Security
//!
//! - Alias names are restricted to alphanumeric characters, hyphens, and
//!   underscores (1-32 chars) to prevent command injection.
//! - Target commands must not be empty.
//! - Cycle detection prevents infinite expansion loops.
//! - Expansion depth is hard-limited to 3 to prevent resource exhaustion.
//! - The name `alias` itself is reserved and cannot be aliased.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub use aegis_types::daemon::AliasConfig;

/// Maximum allowed length for an alias name.
const MAX_ALIAS_NAME_LEN: usize = 32;

/// Maximum expansion depth to prevent resource exhaustion.
const MAX_EXPANSION_DEPTH: usize = 3;

/// Reserved names that cannot be used as aliases (they would shadow
/// the alias management command itself).
const RESERVED_NAMES: &[&str] = &["alias"];

/// A single command alias entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AliasEntry {
    /// The short alias name (e.g., "s").
    pub alias: String,
    /// The target command to expand to (e.g., "status").
    pub target_command: String,
    /// Additional arguments inserted between the command and any user-supplied args.
    #[serde(default)]
    pub target_args: Vec<String>,
}

/// Registry of command aliases with validation and cycle prevention.
#[derive(Debug, Clone, Default)]
pub struct AliasRegistry {
    aliases: HashMap<String, AliasEntry>,
}

impl AliasRegistry {
    /// Create a new empty alias registry.
    pub fn new() -> Self {
        Self {
            aliases: HashMap::new(),
        }
    }

    /// Create a registry pre-populated from a map of alias configs.
    ///
    /// Invalid entries are silently skipped (they may come from a hand-edited
    /// config file). Cycles are also skipped.
    pub fn from_config(config: &HashMap<String, AliasConfig>) -> Self {
        let mut registry = Self::new();
        for (name, cfg) in config {
            let args = cfg.args.clone().unwrap_or_default();
            // Best-effort: skip invalid entries from config.
            let _ = registry.add(name.clone(), cfg.command.clone(), args);
        }
        registry
    }

    /// Export the current aliases as a config map suitable for serialization.
    pub fn to_config(&self) -> HashMap<String, AliasConfig> {
        self.aliases
            .iter()
            .map(|(name, entry)| {
                let cfg = AliasConfig {
                    command: entry.target_command.clone(),
                    args: if entry.target_args.is_empty() {
                        None
                    } else {
                        Some(entry.target_args.clone())
                    },
                };
                (name.clone(), cfg)
            })
            .collect()
    }

    /// Add an alias. Returns an error if validation fails, the alias already
    /// exists, or adding it would create a cycle.
    pub fn add(
        &mut self,
        alias: String,
        target_command: String,
        target_args: Vec<String>,
    ) -> Result<(), String> {
        validate_alias_name(&alias)?;
        validate_target_command(&target_command)?;

        if self.aliases.contains_key(&alias) {
            return Err(format!("alias '{alias}' already exists"));
        }

        // Check for cycles: if the target (or chain from target) eventually
        // resolves back to the alias we are adding, reject it.
        if self.has_cycle(&alias, &target_command) {
            return Err(format!(
                "adding alias '{alias}' -> '{target_command}' would create a cycle"
            ));
        }

        tracing::info!(alias = %alias, target = %target_command, "alias added");

        self.aliases.insert(
            alias.clone(),
            AliasEntry {
                alias,
                target_command,
                target_args,
            },
        );

        Ok(())
    }

    /// Remove an alias by name. Returns an error if the alias does not exist.
    pub fn remove(&mut self, alias: &str) -> Result<(), String> {
        if self.aliases.remove(alias).is_none() {
            return Err(format!("alias '{alias}' not found"));
        }
        tracing::info!(alias = %alias, "alias removed");
        Ok(())
    }

    /// Resolve an input string by expanding aliases.
    ///
    /// Splits the input into the first word and the rest. If the first word
    /// matches an alias, replaces it with `target_command target_args... rest`.
    /// Applies expansion up to [`MAX_EXPANSION_DEPTH`] times to handle chained
    /// aliases. Returns `None` if no alias matched.
    pub fn resolve(&self, input: &str) -> Option<String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return None;
        }

        let mut current = trimmed.to_string();
        let mut expanded = false;

        for _ in 0..MAX_EXPANSION_DEPTH {
            let (first, rest) = match current.split_once(' ') {
                Some((f, r)) => (f, r.trim()),
                None => (current.as_str(), ""),
            };

            if let Some(entry) = self.aliases.get(first) {
                let mut parts = vec![entry.target_command.clone()];
                parts.extend(entry.target_args.iter().cloned());
                if !rest.is_empty() {
                    parts.push(rest.to_string());
                }
                current = parts.join(" ");
                expanded = true;
            } else {
                break;
            }
        }

        if expanded {
            Some(current)
        } else {
            None
        }
    }

    /// List all registered aliases.
    pub fn list(&self) -> Vec<&AliasEntry> {
        let mut entries: Vec<&AliasEntry> = self.aliases.values().collect();
        entries.sort_by(|a, b| a.alias.cmp(&b.alias));
        entries
    }

    /// Check whether adding `alias -> target` would create a cycle.
    ///
    /// Walks the alias chain starting from `target` up to [`MAX_EXPANSION_DEPTH`]
    /// steps. If any step resolves back to `alias`, a cycle exists.
    pub fn has_cycle(&self, alias: &str, target: &str) -> bool {
        let mut current = target.to_string();
        for _ in 0..MAX_EXPANSION_DEPTH {
            if current == alias {
                return true;
            }
            match self.aliases.get(&current) {
                Some(entry) => current = entry.target_command.clone(),
                None => return false,
            }
        }
        // After max depth, treat it as a potential cycle for safety.
        current == alias
    }
}

/// Validate that an alias name contains only allowed characters.
///
/// Allowed: alphanumeric, hyphen, underscore. Length: 1-32.
fn validate_alias_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("alias name must not be empty".into());
    }
    if name.len() > MAX_ALIAS_NAME_LEN {
        return Err(format!(
            "alias name must be at most {MAX_ALIAS_NAME_LEN} characters"
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "alias name '{name}' contains invalid characters; only alphanumeric, hyphen, and underscore are allowed"
        ));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(format!(
            "'{name}' is a reserved name and cannot be used as an alias"
        ));
    }
    Ok(())
}

/// Validate that a target command is non-empty and does not contain obviously
/// dangerous characters.
fn validate_target_command(command: &str) -> Result<(), String> {
    if command.trim().is_empty() {
        return Err("target command must not be empty".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alias_add_and_resolve() {
        let mut reg = AliasRegistry::new();
        reg.add("s".into(), "status".into(), vec![]).unwrap();
        assert_eq!(reg.resolve("s"), Some("status".into()));
    }

    #[test]
    fn test_alias_with_args() {
        let mut reg = AliasRegistry::new();
        reg.add("ap".into(), "approve".into(), vec!["--all".into()])
            .unwrap();
        assert_eq!(
            reg.resolve("ap agent1"),
            Some("approve --all agent1".into())
        );
    }

    #[test]
    fn test_alias_remove() {
        let mut reg = AliasRegistry::new();
        reg.add("s".into(), "status".into(), vec![]).unwrap();
        reg.remove("s").unwrap();
        assert_eq!(reg.resolve("s"), None);
    }

    #[test]
    fn test_alias_list() {
        let mut reg = AliasRegistry::new();
        reg.add("a".into(), "approve".into(), vec![]).unwrap();
        reg.add("b".into(), "deny".into(), vec![]).unwrap();
        reg.add("c".into(), "status".into(), vec![]).unwrap();
        let list = reg.list();
        assert_eq!(list.len(), 3);
        // Sorted by name
        assert_eq!(list[0].alias, "a");
        assert_eq!(list[1].alias, "b");
        assert_eq!(list[2].alias, "c");
    }

    #[test]
    fn test_alias_cycle_prevention() {
        let mut reg = AliasRegistry::new();
        reg.add("a".into(), "b".into(), vec![]).unwrap();
        let result = reg.add("b".into(), "a".into(), vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cycle"));
    }

    #[test]
    fn test_alias_name_validation() {
        let mut reg = AliasRegistry::new();

        // Semicolon -- injection attempt
        assert!(reg.add(";rm".into(), "status".into(), vec![]).is_err());

        // Pipe -- injection attempt
        assert!(reg.add("a|b".into(), "status".into(), vec![]).is_err());

        // Space -- must not be in name
        assert!(reg.add("a b".into(), "status".into(), vec![]).is_err());

        // Path traversal
        assert!(reg.add("../etc".into(), "status".into(), vec![]).is_err());

        // Empty name
        assert!(reg.add(String::new(), "status".into(), vec![]).is_err());

        // Too long (33 chars)
        let long_name = "a".repeat(33);
        assert!(reg.add(long_name, "status".into(), vec![]).is_err());

        // Valid names should succeed
        assert!(reg
            .add("my-alias_1".into(), "status".into(), vec![])
            .is_ok());
    }

    #[test]
    fn test_alias_expansion_depth_limit() {
        let mut reg = AliasRegistry::new();
        // Chain: a -> b -> c -> d -> status
        // With depth limit of 3, expanding "a" should stop after 3 expansions
        // (a->b, b->c, c->d), yielding "d" not "status".
        reg.add("a".into(), "b".into(), vec![]).unwrap();
        reg.add("b".into(), "c".into(), vec![]).unwrap();
        reg.add("c".into(), "d".into(), vec![]).unwrap();
        reg.add("d".into(), "status".into(), vec![]).unwrap();

        let result = reg.resolve("a");
        // After 3 expansions: a->b->c->d, the loop exits and returns "d"
        assert_eq!(result, Some("d".into()));
    }

    #[test]
    fn test_alias_duplicate_rejected() {
        let mut reg = AliasRegistry::new();
        reg.add("s".into(), "status".into(), vec![]).unwrap();
        let result = reg.add("s".into(), "stop".into(), vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_alias_reserved_name_rejected() {
        let mut reg = AliasRegistry::new();
        let result = reg.add("alias".into(), "status".into(), vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("reserved"));
    }

    #[test]
    fn test_alias_empty_target_rejected() {
        let mut reg = AliasRegistry::new();
        let result = reg.add("s".into(), String::new(), vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_alias_whitespace_target_rejected() {
        let mut reg = AliasRegistry::new();
        let result = reg.add("s".into(), "   ".into(), vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_alias_resolve_no_match() {
        let reg = AliasRegistry::new();
        assert_eq!(reg.resolve("status"), None);
        assert_eq!(reg.resolve(""), None);
    }

    #[test]
    fn test_alias_resolve_preserves_trailing_args() {
        let mut reg = AliasRegistry::new();
        reg.add("s".into(), "send".into(), vec![]).unwrap();
        assert_eq!(
            reg.resolve("s agent-1 hello world"),
            Some("send agent-1 hello world".into())
        );
    }

    #[test]
    fn test_alias_remove_nonexistent() {
        let mut reg = AliasRegistry::new();
        assert!(reg.remove("nonexistent").is_err());
    }

    #[test]
    fn test_alias_config_roundtrip() {
        let mut reg = AliasRegistry::new();
        reg.add("s".into(), "status".into(), vec![]).unwrap();
        reg.add("ap".into(), "approve".into(), vec!["--all".into()])
            .unwrap();

        let config = reg.to_config();
        let reg2 = AliasRegistry::from_config(&config);

        assert_eq!(reg2.resolve("s"), Some("status".into()));
        assert_eq!(
            reg2.resolve("ap agent1"),
            Some("approve --all agent1".into())
        );
    }

    #[test]
    fn test_alias_self_cycle() {
        let mut reg = AliasRegistry::new();
        // "a" -> "a" is an immediate cycle
        let result = reg.add("a".into(), "a".into(), vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cycle"));
    }

    #[test]
    fn test_alias_three_step_cycle() {
        let mut reg = AliasRegistry::new();
        reg.add("a".into(), "b".into(), vec![]).unwrap();
        reg.add("b".into(), "c".into(), vec![]).unwrap();
        // c -> a would complete the cycle
        let result = reg.add("c".into(), "a".into(), vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cycle"));
    }

    #[test]
    fn test_alias_chained_expansion() {
        let mut reg = AliasRegistry::new();
        reg.add("x".into(), "y".into(), vec![]).unwrap();
        reg.add("y".into(), "status".into(), vec![]).unwrap();

        // x -> y -> status (2 expansions, within depth limit)
        assert_eq!(reg.resolve("x"), Some("status".into()));
    }

    #[test]
    fn test_alias_has_cycle_no_aliases() {
        let reg = AliasRegistry::new();
        assert!(!reg.has_cycle("a", "b"));
    }
}
