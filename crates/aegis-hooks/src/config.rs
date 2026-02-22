//! Configuration types for the `hooks.toml` manifest.
//!
//! Users place a `hooks.toml` file in their `.aegis/hooks/` directory
//! to explicitly configure hook scripts. This provides more control than
//! convention-based discovery: custom timeouts, explicit event binding,
//! glob patterns for events, and per-hook enable/disable.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level structure of a `hooks.toml` manifest file.
///
/// ```toml
/// [[hooks]]
/// event = "pre_tool_use"
/// script = "check_permissions.sh"
/// timeout_ms = 5000
/// enabled = true
///
/// [[hooks]]
/// event = "on_*"
/// script = "logger.py"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HooksManifest {
    /// List of hook entries defined in the manifest.
    #[serde(default)]
    pub hooks: Vec<HookEntry>,
}

/// A single hook entry in `hooks.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEntry {
    /// Event name or glob pattern to match against event names.
    ///
    /// Standard event names: `pre_tool_use`, `post_tool_use`, `on_message`,
    /// `on_approval`, `on_agent_start`, `on_agent_stop`, `on_error`.
    ///
    /// Glob patterns are supported: `pre_*` matches `pre_tool_use`,
    /// `on_*` matches all `on_` prefixed events.
    pub event: String,

    /// Path to the hook script, relative to the hooks directory.
    pub script: PathBuf,

    /// Maximum execution time in milliseconds. Defaults to 10000 (10 seconds).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Whether this hook is enabled. Defaults to true.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_timeout_ms() -> u64 {
    10_000
}

fn default_enabled() -> bool {
    true
}

impl HookEntry {
    /// Check whether this entry's event pattern matches a given event name.
    ///
    /// Supports exact matches and simple glob patterns with `*` as a
    /// wildcard for zero or more characters.
    pub fn matches_event(&self, event_name: &str) -> bool {
        glob_match(&self.event, event_name)
    }
}

/// Simple glob matching with `*` as the only wildcard character.
///
/// Supports patterns like `pre_*`, `*_use`, `on_agent_*`, or exact matches.
/// Does not support `?`, `[...]`, or `**`.
fn glob_match(pattern: &str, text: &str) -> bool {
    // Fast path: no wildcards means exact match.
    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts: Vec<&str> = pattern.split('*').collect();

    // Edge case: pattern is just "*".
    if parts.len() == 1 && parts[0].is_empty() {
        return true;
    }

    let mut pos = 0;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if let Some(found) = text[pos..].find(part) {
            // First segment must match at the start if pattern doesn't start with *.
            if i == 0 && found != 0 {
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }

    // Last segment must match at the end if pattern doesn't end with *.
    if let Some(last) = parts.last() {
        if !last.is_empty() && !text.ends_with(last) {
            return false;
        }
    }

    true
}

/// Parse a `hooks.toml` manifest from a string.
pub fn parse_manifest(content: &str) -> Result<HooksManifest, toml::de::Error> {
    toml::from_str(content)
}

/// Load a `hooks.toml` manifest from a file path.
pub fn load_manifest(path: &std::path::Path) -> Result<HooksManifest, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    parse_manifest(&content).map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_manifest() {
        let toml = r#"
[[hooks]]
event = "pre_tool_use"
script = "check_permissions.sh"
timeout_ms = 5000
enabled = true

[[hooks]]
event = "on_message"
script = "filter_messages.py"
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert_eq!(manifest.hooks.len(), 2);
        assert_eq!(manifest.hooks[0].event, "pre_tool_use");
        assert_eq!(
            manifest.hooks[0].script,
            PathBuf::from("check_permissions.sh")
        );
        assert_eq!(manifest.hooks[0].timeout_ms, 5000);
        assert!(manifest.hooks[0].enabled);

        assert_eq!(manifest.hooks[1].event, "on_message");
        assert_eq!(manifest.hooks[1].timeout_ms, 10_000); // default
        assert!(manifest.hooks[1].enabled); // default
    }

    #[test]
    fn parse_empty_manifest() {
        let toml = "";
        let manifest = parse_manifest(toml).unwrap();
        assert!(manifest.hooks.is_empty());
    }

    #[test]
    fn disabled_hook() {
        let toml = r#"
[[hooks]]
event = "on_error"
script = "notify.sh"
enabled = false
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert!(!manifest.hooks[0].enabled);
    }

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("pre_tool_use", "pre_tool_use"));
        assert!(!glob_match("pre_tool_use", "post_tool_use"));
    }

    #[test]
    fn glob_wildcard_prefix() {
        assert!(glob_match("*_use", "pre_tool_use"));
        assert!(glob_match("*_use", "post_tool_use"));
        assert!(!glob_match("*_use", "on_message"));
    }

    #[test]
    fn glob_wildcard_suffix() {
        assert!(glob_match("pre_*", "pre_tool_use"));
        assert!(glob_match("on_*", "on_message"));
        assert!(glob_match("on_*", "on_agent_start"));
        assert!(!glob_match("pre_*", "post_tool_use"));
    }

    #[test]
    fn glob_wildcard_middle() {
        assert!(glob_match("on_*_start", "on_agent_start"));
        assert!(!glob_match("on_*_start", "on_agent_stop"));
    }

    #[test]
    fn glob_star_only() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn hook_entry_matches_event() {
        let entry = HookEntry {
            event: "on_*".to_string(),
            script: PathBuf::from("logger.py"),
            timeout_ms: 10_000,
            enabled: true,
        };
        assert!(entry.matches_event("on_message"));
        assert!(entry.matches_event("on_agent_start"));
        assert!(!entry.matches_event("pre_tool_use"));
    }
}
