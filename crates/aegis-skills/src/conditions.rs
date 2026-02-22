//! Conditional skill loading based on runtime environment.
//!
//! Skills can declare load conditions that must be satisfied before the skill
//! is activated. This avoids loading skills that depend on missing binaries,
//! unsupported platforms, or disabled configuration flags.

use serde::{Deserialize, Serialize};

/// A condition that must be met for a skill to be loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum LoadCondition {
    /// Load only if the named environment variable is set (non-empty).
    EnvVarSet(String),
    /// Load only if the named binary exists on `$PATH`.
    BinaryExists(String),
    /// Load only on the specified platform.
    PlatformIs(Platform),
    /// Load only if the named configuration flag is "true".
    ConfigFlag(String),
}

/// Target platform for conditional loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// macOS / Darwin
    Macos,
    /// Linux
    Linux,
    /// Windows
    Windows,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Macos => write!(f, "macos"),
            Platform::Linux => write!(f, "linux"),
            Platform::Windows => write!(f, "windows"),
        }
    }
}

/// Check whether all conditions are satisfied.
///
/// Returns `true` if `conditions` is empty or every condition passes.
pub fn check_conditions(conditions: &[LoadCondition]) -> bool {
    conditions.iter().all(check_single)
}

/// Evaluate a single load condition, returning a (condition, passed, reason) triple.
///
/// Useful for showing the user which conditions failed and why.
pub fn evaluate_conditions(conditions: &[LoadCondition]) -> Vec<(LoadCondition, bool, String)> {
    conditions
        .iter()
        .map(|c| {
            let passed = check_single(c);
            let reason = describe_result(c, passed);
            (c.clone(), passed, reason)
        })
        .collect()
}

fn check_single(condition: &LoadCondition) -> bool {
    match condition {
        LoadCondition::EnvVarSet(name) => {
            std::env::var(name)
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        }
        LoadCondition::BinaryExists(name) => binary_in_path(name),
        LoadCondition::PlatformIs(platform) => current_platform() == Some(*platform),
        LoadCondition::ConfigFlag(key) => {
            // Check environment variable AEGIS_FLAG_<KEY> as the config flag source.
            let env_key = format!("AEGIS_FLAG_{}", key.to_uppercase().replace('-', "_"));
            std::env::var(&env_key)
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false)
        }
    }
}

fn describe_result(condition: &LoadCondition, passed: bool) -> String {
    match condition {
        LoadCondition::EnvVarSet(name) => {
            if passed {
                format!("environment variable {name} is set")
            } else {
                format!("environment variable {name} is not set")
            }
        }
        LoadCondition::BinaryExists(name) => {
            if passed {
                format!("binary '{name}' found on PATH")
            } else {
                format!("binary '{name}' not found on PATH")
            }
        }
        LoadCondition::PlatformIs(platform) => {
            if passed {
                format!("running on {platform}")
            } else {
                format!("not running on {platform} (current: {})", current_platform_name())
            }
        }
        LoadCondition::ConfigFlag(key) => {
            if passed {
                format!("config flag '{key}' is enabled")
            } else {
                format!("config flag '{key}' is not enabled")
            }
        }
    }
}

/// Check if a binary exists on PATH.
fn binary_in_path(name: &str) -> bool {
    // Reject names with path separators to prevent traversal
    if name.contains('/') || name.contains('\\') {
        return false;
    }

    let path_var = std::env::var("PATH").unwrap_or_default();
    let sep = if cfg!(windows) { ';' } else { ':' };

    for dir in path_var.split(sep) {
        let candidate = std::path::Path::new(dir).join(name);
        if candidate.is_file() {
            return true;
        }
        // On Windows, also check with .exe extension
        if cfg!(windows) {
            let with_ext = candidate.with_extension("exe");
            if with_ext.is_file() {
                return true;
            }
        }
    }

    false
}

/// Detect the current platform.
fn current_platform() -> Option<Platform> {
    if cfg!(target_os = "macos") {
        Some(Platform::Macos)
    } else if cfg!(target_os = "linux") {
        Some(Platform::Linux)
    } else if cfg!(target_os = "windows") {
        Some(Platform::Windows)
    } else {
        None
    }
}

/// Human-readable name for the current platform.
fn current_platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_conditions_pass() {
        assert!(check_conditions(&[]));
    }

    #[test]
    fn test_env_var_set_passes_when_set() {
        std::env::set_var("AEGIS_TEST_COND_VAR", "hello");
        let conditions = vec![LoadCondition::EnvVarSet("AEGIS_TEST_COND_VAR".into())];
        assert!(check_conditions(&conditions));
        std::env::remove_var("AEGIS_TEST_COND_VAR");
    }

    #[test]
    fn test_env_var_set_fails_when_unset() {
        std::env::remove_var("AEGIS_TEST_MISSING_VAR_XYZ");
        let conditions = vec![LoadCondition::EnvVarSet("AEGIS_TEST_MISSING_VAR_XYZ".into())];
        assert!(!check_conditions(&conditions));
    }

    #[test]
    fn test_env_var_set_fails_when_empty() {
        std::env::set_var("AEGIS_TEST_EMPTY_VAR", "");
        let conditions = vec![LoadCondition::EnvVarSet("AEGIS_TEST_EMPTY_VAR".into())];
        assert!(!check_conditions(&conditions));
        std::env::remove_var("AEGIS_TEST_EMPTY_VAR");
    }

    #[test]
    fn test_binary_exists_common_binary() {
        // "sh" should exist on all Unix-like systems
        if cfg!(unix) {
            let conditions = vec![LoadCondition::BinaryExists("sh".into())];
            assert!(check_conditions(&conditions));
        }
    }

    #[test]
    fn test_binary_exists_missing_binary() {
        let conditions = vec![LoadCondition::BinaryExists(
            "this-binary-does-not-exist-aegis-test-12345".into(),
        )];
        assert!(!check_conditions(&conditions));
    }

    #[test]
    fn test_binary_exists_rejects_path_traversal() {
        // Should reject names with path separators
        assert!(!binary_in_path("../bin/sh"));
        assert!(!binary_in_path("/usr/bin/sh"));
    }

    #[test]
    fn test_platform_is_current() {
        let current = if cfg!(target_os = "macos") {
            Platform::Macos
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            return; // skip on other platforms
        };

        let conditions = vec![LoadCondition::PlatformIs(current)];
        assert!(check_conditions(&conditions));
    }

    #[test]
    fn test_platform_is_wrong() {
        // Pick a platform that is not the current one
        let wrong = if cfg!(target_os = "macos") {
            Platform::Linux
        } else {
            Platform::Macos
        };

        let conditions = vec![LoadCondition::PlatformIs(wrong)];
        assert!(!check_conditions(&conditions));
    }

    #[test]
    fn test_config_flag_enabled() {
        std::env::set_var("AEGIS_FLAG_TEST_ENABLED_XY", "true");
        let conditions = vec![LoadCondition::ConfigFlag("test-enabled-xy".into())];
        assert!(check_conditions(&conditions));
        std::env::remove_var("AEGIS_FLAG_TEST_ENABLED_XY");
    }

    #[test]
    fn test_config_flag_disabled() {
        std::env::set_var("AEGIS_FLAG_TEST_DISABLED_XY", "false");
        let conditions = vec![LoadCondition::ConfigFlag("test-disabled-xy".into())];
        assert!(!check_conditions(&conditions));
        std::env::remove_var("AEGIS_FLAG_TEST_DISABLED_XY");
    }

    #[test]
    fn test_multiple_conditions_all_must_pass() {
        std::env::set_var("AEGIS_TEST_MULTI_1", "yes");
        std::env::remove_var("AEGIS_TEST_MULTI_2");

        let conditions = vec![
            LoadCondition::EnvVarSet("AEGIS_TEST_MULTI_1".into()),
            LoadCondition::EnvVarSet("AEGIS_TEST_MULTI_2".into()),
        ];
        assert!(!check_conditions(&conditions));

        std::env::set_var("AEGIS_TEST_MULTI_2", "yes");
        assert!(check_conditions(&conditions));

        std::env::remove_var("AEGIS_TEST_MULTI_1");
        std::env::remove_var("AEGIS_TEST_MULTI_2");
    }

    #[test]
    fn test_evaluate_conditions_returns_details() {
        std::env::set_var("AEGIS_TEST_EVAL_VAR", "yes");
        let conditions = vec![
            LoadCondition::EnvVarSet("AEGIS_TEST_EVAL_VAR".into()),
            LoadCondition::BinaryExists("nonexistent-binary-xyz".into()),
        ];

        let results = evaluate_conditions(&conditions);
        assert_eq!(results.len(), 2);
        assert!(results[0].1); // first passes
        assert!(!results[1].1); // second fails
        assert!(results[0].2.contains("is set"));
        assert!(results[1].2.contains("not found"));

        std::env::remove_var("AEGIS_TEST_EVAL_VAR");
    }

    #[test]
    fn test_condition_serialization_roundtrip() {
        let conditions = vec![
            LoadCondition::EnvVarSet("MY_VAR".into()),
            LoadCondition::BinaryExists("git".into()),
            LoadCondition::PlatformIs(Platform::Macos),
            LoadCondition::ConfigFlag("experimental".into()),
        ];

        let json = serde_json::to_string(&conditions).unwrap();
        let back: Vec<LoadCondition> = serde_json::from_str(&json).unwrap();
        assert_eq!(conditions, back);
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::Macos.to_string(), "macos");
        assert_eq!(Platform::Linux.to_string(), "linux");
        assert_eq!(Platform::Windows.to_string(), "windows");
    }
}
