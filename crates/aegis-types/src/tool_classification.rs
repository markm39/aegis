//! Risk classification for agent actions with configurable overrides.
//!
//! Every [`ActionKind`] receives a default risk tier via [`classify_action`].
//! Operators can layer [`ClassificationOverrides`] to promote or demote
//! specific tools/commands, and [`AutoApprovalConfig`] gates which tiers
//! may bypass human review.
//!
//! This module lives in `aegis-types` (the foundation crate) so every
//! downstream crate can classify actions without pulling in `aegis-toolkit`.
//! The [`ActionRisk`] enum mirrors `aegis_toolkit::RiskTag` conceptually but
//! is intentionally independent to avoid circular dependencies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ActionKind;

// ---------------------------------------------------------------------------
// ActionRisk enum
// ---------------------------------------------------------------------------

/// Five-tier risk classification for agent actions.
///
/// Ordered from least to most dangerous. Use [`ActionRisk::risk_rank`] for
/// numeric comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRisk {
    /// Read-only, no side effects (e.g., reading a file, listing a directory).
    Informational,
    /// Minimal side effects, easily reversible (e.g., creating a directory).
    Low,
    /// Meaningful side effects but generally recoverable (e.g., writing a file).
    Medium,
    /// Significant side effects, hard to reverse (e.g., deleting a file, spawning a process).
    High,
    /// Destructive or irreversible operations requiring explicit approval.
    Critical,
}

impl ActionRisk {
    /// Numeric rank for ordering comparisons.
    ///
    /// `Informational = 0`, `Low = 1`, `Medium = 2`, `High = 3`, `Critical = 4`.
    pub fn risk_rank(self) -> u8 {
        match self {
            ActionRisk::Informational => 0,
            ActionRisk::Low => 1,
            ActionRisk::Medium => 2,
            ActionRisk::High => 3,
            ActionRisk::Critical => 4,
        }
    }
}

impl PartialOrd for ActionRisk {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ActionRisk {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.risk_rank().cmp(&other.risk_rank())
    }
}

impl std::fmt::Display for ActionRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionRisk::Informational => write!(f, "Informational"),
            ActionRisk::Low => write!(f, "Low"),
            ActionRisk::Medium => write!(f, "Medium"),
            ActionRisk::High => write!(f, "High"),
            ActionRisk::Critical => write!(f, "Critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Default classification
// ---------------------------------------------------------------------------

/// Return the default risk tier for an action kind.
///
/// This is the baseline classification applied when no operator overrides
/// are configured. The mapping is intentionally conservative -- actions with
/// side effects default to `Medium` or above.
pub fn classify_action(action: &ActionKind) -> ActionRisk {
    match action {
        ActionKind::FileRead { .. } => ActionRisk::Informational,
        ActionKind::DirList { .. } => ActionRisk::Informational,
        ActionKind::DirCreate { .. } => ActionRisk::Low,
        ActionKind::FileWrite { .. } => ActionRisk::Medium,
        ActionKind::NetConnect { .. } => ActionRisk::Medium,
        ActionKind::NetRequest { .. } => ActionRisk::Medium,
        ActionKind::ToolCall { .. } => ActionRisk::Medium,
        ActionKind::FileDelete { .. } => ActionRisk::High,
        ActionKind::ProcessSpawn { .. } => ActionRisk::High,
        ActionKind::ProcessExit { .. } => ActionRisk::Informational,
        ActionKind::ApiUsage { .. } => ActionRisk::Low,
        ActionKind::SkillScan { .. } => ActionRisk::Informational,
        ActionKind::MemoryCapture { .. } => ActionRisk::Medium,
    }
}

// ---------------------------------------------------------------------------
// ClassificationOverrides
// ---------------------------------------------------------------------------

/// Operator-configured overrides that re-classify specific tools or commands.
///
/// Overrides are keyed by tool name (for `ToolCall`) or command name (for
/// `ProcessSpawn`). All other action kinds use their default classification
/// unless a match is found.
///
/// # Examples
///
/// ```
/// use aegis_types::tool_classification::{ClassificationOverrides, ActionRisk};
/// use aegis_types::ActionKind;
///
/// let overrides = ClassificationOverrides::new()
///     .with_override("bash", ActionRisk::Critical)
///     .with_override("read_file", ActionRisk::Informational);
///
/// let bash_call = ActionKind::ToolCall {
///     tool: "bash".into(),
///     args: serde_json::json!({"cmd": "rm -rf /"}),
/// };
/// assert_eq!(overrides.classify(&bash_call), ActionRisk::Critical);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationOverrides {
    overrides: HashMap<String, ActionRisk>,
}

impl ClassificationOverrides {
    /// Create an empty set of overrides (all actions use defaults).
    pub fn new() -> Self {
        Self {
            overrides: HashMap::new(),
        }
    }

    /// Add an override for a tool or command name.
    pub fn with_override(mut self, name: &str, risk: ActionRisk) -> Self {
        self.overrides.insert(name.to_owned(), risk);
        self
    }

    /// Classify an action, checking overrides first and falling back to
    /// [`classify_action`].
    ///
    /// Override lookup rules:
    /// - `ToolCall` -- looks up by `tool` name
    /// - `ProcessSpawn` -- looks up by `command` name
    /// - All other variants -- no override key, always falls back to default
    pub fn classify(&self, action: &ActionKind) -> ActionRisk {
        let override_key = match action {
            ActionKind::ToolCall { tool, .. } => Some(tool.as_str()),
            ActionKind::ProcessSpawn { command, .. } => Some(command.as_str()),
            _ => None,
        };

        if let Some(key) = override_key {
            if let Some(&risk) = self.overrides.get(key) {
                return risk;
            }
        }

        classify_action(action)
    }
}

impl Default for ClassificationOverrides {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AutoApprovalConfig
// ---------------------------------------------------------------------------

/// Controls which risk tiers may be auto-approved without human review.
///
/// Any action whose classified risk is at or below `max_auto_approve_risk`
/// is eligible for automatic approval. Actions above the threshold require
/// explicit human approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoApprovalConfig {
    /// Maximum risk tier that can be auto-approved. Defaults to `Low`.
    pub max_auto_approve_risk: ActionRisk,
}

impl AutoApprovalConfig {
    /// Returns `true` if the given risk tier should be auto-approved.
    pub fn should_auto_approve(&self, risk: ActionRisk) -> bool {
        risk <= self.max_auto_approve_risk
    }
}

impl Default for AutoApprovalConfig {
    fn default() -> Self {
        Self {
            max_auto_approve_risk: ActionRisk::Low,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -- Default classification tests --

    #[test]
    fn test_file_read_classified_informational() {
        let action = ActionKind::FileRead {
            path: PathBuf::from("/etc/passwd"),
        };
        assert_eq!(classify_action(&action), ActionRisk::Informational);
    }

    #[test]
    fn test_dir_list_classified_informational() {
        let action = ActionKind::DirList {
            path: PathBuf::from("/tmp"),
        };
        assert_eq!(classify_action(&action), ActionRisk::Informational);
    }

    #[test]
    fn test_file_write_classified_medium() {
        let action = ActionKind::FileWrite {
            path: PathBuf::from("/tmp/out.txt"),
        };
        assert_eq!(classify_action(&action), ActionRisk::Medium);
    }

    #[test]
    fn test_file_delete_classified_high() {
        let action = ActionKind::FileDelete {
            path: PathBuf::from("/tmp/old.log"),
        };
        assert_eq!(classify_action(&action), ActionRisk::High);
    }

    #[test]
    fn test_process_spawn_classified_high() {
        let action = ActionKind::ProcessSpawn {
            command: "rm".into(),
            args: vec!["-rf".into(), "/tmp/junk".into()],
        };
        assert_eq!(classify_action(&action), ActionRisk::High);
    }

    #[test]
    fn test_process_exit_classified_informational() {
        let action = ActionKind::ProcessExit {
            command: "ls".into(),
            exit_code: 0,
        };
        assert_eq!(classify_action(&action), ActionRisk::Informational);
    }

    #[test]
    fn test_net_connect_classified_medium() {
        let action = ActionKind::NetConnect {
            host: "example.com".into(),
            port: 443,
        };
        assert_eq!(classify_action(&action), ActionRisk::Medium);
    }

    #[test]
    fn test_tool_call_default_medium() {
        let action = ActionKind::ToolCall {
            tool: "some_tool".into(),
            args: serde_json::json!({}),
        };
        assert_eq!(classify_action(&action), ActionRisk::Medium);
    }

    #[test]
    fn test_api_usage_classified_low() {
        let action = ActionKind::ApiUsage {
            provider: "anthropic".into(),
            model: "claude-sonnet-4-5-20250929".into(),
            endpoint: "/v1/messages".into(),
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        assert_eq!(classify_action(&action), ActionRisk::Low);
    }

    // -- Override tests --

    #[test]
    fn test_custom_override_applied() {
        let overrides = ClassificationOverrides::new()
            .with_override("bash", ActionRisk::Critical);

        let action = ActionKind::ToolCall {
            tool: "bash".into(),
            args: serde_json::json!({"cmd": "rm -rf /"}),
        };
        assert_eq!(overrides.classify(&action), ActionRisk::Critical);
    }

    #[test]
    fn test_override_does_not_affect_others() {
        let overrides = ClassificationOverrides::new()
            .with_override("bash", ActionRisk::Critical);

        let action = ActionKind::ToolCall {
            tool: "read_file".into(),
            args: serde_json::json!({}),
        };
        // read_file has no override, so it falls back to the ToolCall default.
        assert_eq!(overrides.classify(&action), ActionRisk::Medium);
    }

    // -- Auto-approval tests --

    #[test]
    fn test_auto_approve_at_or_below() {
        let config = AutoApprovalConfig {
            max_auto_approve_risk: ActionRisk::Low,
        };
        assert!(config.should_auto_approve(ActionRisk::Informational));
        assert!(config.should_auto_approve(ActionRisk::Low));
    }

    #[test]
    fn test_auto_approve_above_rejected() {
        let config = AutoApprovalConfig {
            max_auto_approve_risk: ActionRisk::Low,
        };
        assert!(!config.should_auto_approve(ActionRisk::Medium));
        assert!(!config.should_auto_approve(ActionRisk::High));
        assert!(!config.should_auto_approve(ActionRisk::Critical));
    }

    // -- Ordering test --

    #[test]
    fn test_action_risk_ordering() {
        assert!(ActionRisk::Informational < ActionRisk::Low);
        assert!(ActionRisk::Low < ActionRisk::Medium);
        assert!(ActionRisk::Medium < ActionRisk::High);
        assert!(ActionRisk::High < ActionRisk::Critical);

        // Transitivity
        assert!(ActionRisk::Informational < ActionRisk::Critical);
    }

    // -- Security test --

    #[test]
    fn test_destructive_actions_never_informational() {
        // Verify that the DEFAULT classification (without overrides) for
        // destructive action kinds is High or above.
        let file_delete = ActionKind::FileDelete {
            path: PathBuf::from("/important/data"),
        };
        let process_spawn = ActionKind::ProcessSpawn {
            command: "rm".into(),
            args: vec![],
        };

        assert!(
            classify_action(&file_delete) >= ActionRisk::High,
            "FileDelete must default to High or above, got {:?}",
            classify_action(&file_delete)
        );
        assert!(
            classify_action(&process_spawn) >= ActionRisk::High,
            "ProcessSpawn must default to High or above, got {:?}",
            classify_action(&process_spawn)
        );
    }
}
