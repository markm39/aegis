//! Data model for the TUI setup wizard.
//!
//! Defines the permission model used to configure per-action Cedar policies.
//! Each Cedar action gets an `ActionEntry` with metadata (label, description,
//! recommendation) and a configurable `ActionPermission`.

use std::path::PathBuf;

use aegis_types::IsolationConfig;

/// How an action is permitted in the generated Cedar policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionPermission {
    /// Permit unconditionally (no `when` clause).
    Allow,
    /// No permit statement -- default-deny blocks it.
    Deny,
    /// Permit with scope constraints (generates `when` clauses).
    Scoped(Vec<ScopeRule>),
}

/// A scope constraint narrowing where an action is permitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRule {
    /// File path glob pattern, e.g. "/Users/me/project/*".
    PathPattern(String),
    /// Network host (any port), e.g. "api.openai.com".
    Host(String),
    /// Network host:port, e.g. ("api.openai.com", 443).
    HostPort(String, u16),
}

/// Static metadata for a single Cedar action.
#[derive(Debug, Clone)]
pub struct ActionMeta {
    /// Cedar action name (e.g. "FileRead").
    pub action: &'static str,
    /// Short display label.
    pub label: &'static str,
    /// One-line description of what this action controls.
    pub description: &'static str,
    /// Whether this action is recommended for most use cases.
    pub recommended: bool,
    /// Infrastructure actions (ProcessSpawn, ProcessExit) are always included.
    pub infrastructure: bool,
}

impl ActionMeta {
    /// Whether this action operates on the filesystem and should be
    /// auto-scoped to the project directory.
    pub fn is_file_action(&self) -> bool {
        matches!(
            self.action,
            "FileRead" | "FileWrite" | "FileDelete" | "DirCreate" | "DirList"
        )
    }
}

/// A configurable action entry: metadata + current permission setting.
#[derive(Debug, Clone)]
pub struct ActionEntry {
    pub meta: ActionMeta,
    pub permission: ActionPermission,
}

/// All 9 Cedar actions with their metadata.
pub const ACTION_METAS: &[ActionMeta] = &[
    ActionMeta {
        action: "FileRead",
        label: "Read files",
        description: "Read file contents in the project directory",
        recommended: true,
        infrastructure: false,
    },
    ActionMeta {
        action: "FileWrite",
        label: "Write files",
        description: "Create or modify files",
        recommended: false,
        infrastructure: false,
    },
    ActionMeta {
        action: "FileDelete",
        label: "Delete files",
        description: "Remove files from disk",
        recommended: false,
        infrastructure: false,
    },
    ActionMeta {
        action: "DirCreate",
        label: "Create directories",
        description: "Create new directories",
        recommended: false,
        infrastructure: false,
    },
    ActionMeta {
        action: "DirList",
        label: "List directories",
        description: "List directory contents and metadata",
        recommended: true,
        infrastructure: false,
    },
    ActionMeta {
        action: "NetConnect",
        label: "Network access",
        description: "Make outbound network connections",
        recommended: false,
        infrastructure: false,
    },
    ActionMeta {
        action: "ToolCall",
        label: "Tool invocations",
        description: "Call external tools and plugins",
        recommended: false,
        infrastructure: false,
    },
    ActionMeta {
        action: "ProcessSpawn",
        label: "Spawn processes",
        description: "Launch subprocesses (required for most agents)",
        recommended: true,
        infrastructure: true,
    },
    ActionMeta {
        action: "ProcessExit",
        label: "Process lifecycle",
        description: "Process termination events (always needed)",
        recommended: true,
        infrastructure: true,
    },
];

/// Build the default action entries with recommended defaults.
pub fn default_action_entries() -> Vec<ActionEntry> {
    ACTION_METAS
        .iter()
        .map(|meta| {
            let permission = if meta.recommended || meta.infrastructure {
                ActionPermission::Allow
            } else {
                ActionPermission::Deny
            };
            ActionEntry {
                meta: meta.clone(),
                permission,
            }
        })
        .collect()
}

/// Apply a security preset to action entries.
pub fn apply_preset(entries: &mut [ActionEntry], preset: SecurityPreset) {
    match preset {
        SecurityPreset::ObserveOnly => {
            for entry in entries.iter_mut() {
                entry.permission = ActionPermission::Allow;
            }
        }
        SecurityPreset::ReadOnly => {
            for entry in entries.iter_mut() {
                entry.permission = match entry.meta.action {
                    "FileRead" | "DirList" | "ProcessSpawn" | "ProcessExit" => {
                        ActionPermission::Allow
                    }
                    _ => ActionPermission::Deny,
                };
            }
        }
        SecurityPreset::FullLockdown => {
            for entry in entries.iter_mut() {
                entry.permission = match entry.meta.action {
                    "ProcessSpawn" | "ProcessExit" => ActionPermission::Allow,
                    _ => ActionPermission::Deny,
                };
            }
        }
        SecurityPreset::Custom => {
            // Reset to recommended defaults
            let defaults = default_action_entries();
            entries.clone_from_slice(&defaults);
        }
    }
}

/// Quick-start security presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPreset {
    /// Log everything, enforce nothing.
    ObserveOnly,
    /// Allow reads, block writes.
    ReadOnly,
    /// Block everything except process lifecycle.
    FullLockdown,
    /// Pick specific capabilities.
    Custom,
}

impl SecurityPreset {
    pub const ALL: &[SecurityPreset] = &[
        SecurityPreset::ObserveOnly,
        SecurityPreset::ReadOnly,
        SecurityPreset::FullLockdown,
        SecurityPreset::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SecurityPreset::ObserveOnly => "Observe only",
            SecurityPreset::ReadOnly => "Read-only sandbox",
            SecurityPreset::FullLockdown => "Full lockdown",
            SecurityPreset::Custom => "Custom",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            SecurityPreset::ObserveOnly => {
                "Log all activity, enforce nothing (recommended for first run)"
            }
            SecurityPreset::ReadOnly => "Allow reads, block writes and network access",
            SecurityPreset::FullLockdown => "Block everything except process lifecycle",
            SecurityPreset::Custom => "Pick specific capabilities and set granular scopes",
        }
    }

    /// Map preset to isolation config.
    pub fn isolation(self) -> IsolationConfig {
        match self {
            SecurityPreset::ObserveOnly => IsolationConfig::Process,
            SecurityPreset::ReadOnly | SecurityPreset::FullLockdown => {
                if cfg!(target_os = "macos") {
                    IsolationConfig::Seatbelt {
                        profile_overrides: None,
                    }
                } else {
                    IsolationConfig::Process
                }
            }
            SecurityPreset::Custom => IsolationConfig::Process, // updated later based on actions
        }
    }
}

/// Result returned by the wizard to the caller.
pub struct WizardResult {
    /// Whether the user cancelled the wizard.
    pub cancelled: bool,
    /// Configuration name.
    pub name: String,
    /// Generated Cedar policy text.
    pub policy_text: String,
    /// Project directory to monitor.
    pub project_dir: PathBuf,
    /// Isolation config.
    pub isolation: IsolationConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_entries_have_correct_count() {
        let entries = default_action_entries();
        assert_eq!(entries.len(), 9);
    }

    #[test]
    fn default_entries_recommended_are_allowed() {
        let entries = default_action_entries();
        for entry in &entries {
            if entry.meta.recommended || entry.meta.infrastructure {
                assert_eq!(
                    entry.permission,
                    ActionPermission::Allow,
                    "{} should be allowed by default",
                    entry.meta.action
                );
            }
        }
    }

    #[test]
    fn observe_only_allows_everything() {
        let mut entries = default_action_entries();
        apply_preset(&mut entries, SecurityPreset::ObserveOnly);
        for entry in &entries {
            assert_eq!(
                entry.permission,
                ActionPermission::Allow,
                "{} should be allowed in observe-only",
                entry.meta.action
            );
        }
    }

    #[test]
    fn full_lockdown_only_allows_process() {
        let mut entries = default_action_entries();
        apply_preset(&mut entries, SecurityPreset::FullLockdown);
        for entry in &entries {
            let expected = match entry.meta.action {
                "ProcessSpawn" | "ProcessExit" => ActionPermission::Allow,
                _ => ActionPermission::Deny,
            };
            assert_eq!(
                entry.permission, expected,
                "{} has wrong permission in full lockdown",
                entry.meta.action
            );
        }
    }

    #[test]
    fn read_only_allows_read_and_list() {
        let mut entries = default_action_entries();
        apply_preset(&mut entries, SecurityPreset::ReadOnly);
        for entry in &entries {
            let expected = match entry.meta.action {
                "FileRead" | "DirList" | "ProcessSpawn" | "ProcessExit" => ActionPermission::Allow,
                _ => ActionPermission::Deny,
            };
            assert_eq!(
                entry.permission, expected,
                "{} has wrong permission in read-only",
                entry.meta.action
            );
        }
    }

    #[test]
    fn preset_labels_are_nonempty() {
        for preset in SecurityPreset::ALL {
            assert!(!preset.label().is_empty());
            assert!(!preset.description().is_empty());
        }
    }

    #[test]
    fn action_metas_have_unique_actions() {
        let mut seen = std::collections::HashSet::new();
        for meta in ACTION_METAS {
            assert!(
                seen.insert(meta.action),
                "duplicate action: {}",
                meta.action
            );
        }
    }

    #[test]
    fn action_meta_is_file_action() {
        let file_actions = [
            "FileRead",
            "FileWrite",
            "FileDelete",
            "DirCreate",
            "DirList",
        ];
        let non_file_actions = ["NetConnect", "ToolCall", "ProcessSpawn", "ProcessExit"];

        for meta in ACTION_METAS {
            if file_actions.contains(&meta.action) {
                assert!(
                    meta.is_file_action(),
                    "{} should be a file action",
                    meta.action
                );
            } else if non_file_actions.contains(&meta.action) {
                assert!(
                    !meta.is_file_action(),
                    "{} should not be a file action",
                    meta.action
                );
            } else {
                panic!("unexpected action: {}", meta.action);
            }
        }
    }
}
