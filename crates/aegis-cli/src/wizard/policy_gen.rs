//! Cedar policy generation from wizard action configurations.
//!
//! Converts the wizard's `ActionEntry` selections into valid Cedar policy
//! text with optional `when` clauses for scoped permissions.

use super::model::{ActionEntry, ActionPermission, ScopeRule};

/// Generate Cedar policy text from a list of configured actions.
///
/// Actions with `Deny` permission produce no statements (default-deny
/// handles them). Actions with `Allow` get unconditional permits.
/// Actions with `Scoped` rules get one permit per scope with a `when` clause.
pub fn generate_policy(entries: &[ActionEntry]) -> String {
    let mut policy = String::new();

    for entry in entries {
        match &entry.permission {
            ActionPermission::Deny => {}
            ActionPermission::Allow => {
                write_permit(&mut policy, entry.meta.action, None);
            }
            ActionPermission::Scoped(rules) => {
                if rules.is_empty() {
                    // No scopes = allow globally
                    write_permit(&mut policy, entry.meta.action, None);
                } else {
                    for rule in rules {
                        let when_clause = scope_to_when(rule);
                        write_permit(&mut policy, entry.meta.action, Some(&when_clause));
                    }
                }
            }
        }
    }

    policy
}

/// Write a single Cedar permit statement.
fn write_permit(out: &mut String, action: &str, when_clause: Option<&str>) {
    out.push_str("permit(\n");
    out.push_str("    principal,\n");
    out.push_str(&format!("    action == Aegis::Action::\"{action}\",\n"));
    out.push_str("    resource\n");
    out.push(')');

    if let Some(clause) = when_clause {
        out.push_str(" when {\n");
        out.push_str(&format!("    {clause}\n"));
        out.push('}');
    }

    out.push_str(";\n\n");
}

/// Convert a ScopeRule into a Cedar `when` clause body.
fn scope_to_when(rule: &ScopeRule) -> String {
    match rule {
        ScopeRule::PathPattern(pattern) => {
            format!("resource.path like \"{pattern}\"")
        }
        ScopeRule::Host(host) => {
            // Match host with any port: "host:*"
            format!("resource.path like \"{host}:*\"")
        }
        ScopeRule::HostPort(host, port) => {
            format!("resource.path == \"{host}:{port}\"")
        }
    }
}

/// Determine isolation config based on action permissions.
///
/// If any action is denied or scoped, use Seatbelt (macOS) for enforcement.
/// If everything is allowed, Process isolation is sufficient.
pub fn needs_kernel_enforcement(entries: &[ActionEntry]) -> bool {
    entries
        .iter()
        .any(|e| !matches!(e.permission, ActionPermission::Allow))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wizard::model::{apply_preset, default_action_entries, ActionMeta, SecurityPreset};

    #[test]
    fn observe_only_generates_permit_all_equivalent() {
        let mut entries = default_action_entries();
        apply_preset(&mut entries, SecurityPreset::ObserveOnly);
        let policy = generate_policy(&entries);
        // Should have 9 permit statements
        let count = policy.matches("permit(").count();
        assert_eq!(count, 9, "observe-only should produce 9 permits");
    }

    #[test]
    fn full_lockdown_generates_only_process_permits() {
        let mut entries = default_action_entries();
        apply_preset(&mut entries, SecurityPreset::FullLockdown);
        let policy = generate_policy(&entries);
        assert!(policy.contains("ProcessSpawn"));
        assert!(policy.contains("ProcessExit"));
        assert!(!policy.contains("FileRead"));
        assert!(!policy.contains("NetConnect"));
    }

    #[test]
    fn scoped_action_generates_when_clause() {
        let entries = vec![ActionEntry {
            meta: ActionMeta {
                action: "FileRead",
                label: "Read files",
                description: "test",
                recommended: true,
                infrastructure: false,
            },
            permission: ActionPermission::Scoped(vec![ScopeRule::PathPattern(
                "/Users/me/project/*".to_string(),
            )]),
        }];
        let policy = generate_policy(&entries);
        assert!(policy.contains("when {"));
        assert!(policy.contains("resource.path like \"/Users/me/project/*\""));
    }

    #[test]
    fn multiple_scopes_generate_multiple_permits() {
        let entries = vec![ActionEntry {
            meta: ActionMeta {
                action: "NetConnect",
                label: "Network",
                description: "test",
                recommended: false,
                infrastructure: false,
            },
            permission: ActionPermission::Scoped(vec![
                ScopeRule::Host("api.openai.com".to_string()),
                ScopeRule::HostPort("example.com".to_string(), 443),
            ]),
        }];
        let policy = generate_policy(&entries);
        let permit_count = policy.matches("permit(").count();
        assert_eq!(permit_count, 2, "two scopes should produce two permits");
        assert!(policy.contains("api.openai.com:*"));
        assert!(policy.contains("example.com:443"));
    }

    #[test]
    fn empty_scoped_means_allow_globally() {
        let entries = vec![ActionEntry {
            meta: ActionMeta {
                action: "FileRead",
                label: "Read",
                description: "test",
                recommended: true,
                infrastructure: false,
            },
            permission: ActionPermission::Scoped(vec![]),
        }];
        let policy = generate_policy(&entries);
        assert!(policy.contains("FileRead"));
        assert!(!policy.contains("when"));
    }

    #[test]
    fn denied_actions_produce_no_output() {
        let entries = vec![ActionEntry {
            meta: ActionMeta {
                action: "FileDelete",
                label: "Delete",
                description: "test",
                recommended: false,
                infrastructure: false,
            },
            permission: ActionPermission::Deny,
        }];
        let policy = generate_policy(&entries);
        assert!(policy.is_empty());
    }

    #[test]
    fn generated_policy_parses_as_valid_cedar() {
        let mut entries = default_action_entries();
        apply_preset(&mut entries, SecurityPreset::ReadOnly);
        let policy = generate_policy(&entries);
        let pset: Result<cedar_policy::PolicySet, _> = policy.parse();
        assert!(pset.is_ok(), "generated policy should parse: {pset:?}");
    }

    #[test]
    fn scoped_policy_parses_as_valid_cedar() {
        let entries = vec![
            ActionEntry {
                meta: ActionMeta {
                    action: "FileRead",
                    label: "Read",
                    description: "test",
                    recommended: true,
                    infrastructure: false,
                },
                permission: ActionPermission::Scoped(vec![ScopeRule::PathPattern(
                    "/tmp/test/*".to_string(),
                )]),
            },
            ActionEntry {
                meta: ActionMeta {
                    action: "ProcessExit",
                    label: "Exit",
                    description: "test",
                    recommended: true,
                    infrastructure: true,
                },
                permission: ActionPermission::Allow,
            },
        ];
        let policy = generate_policy(&entries);
        let pset: Result<cedar_policy::PolicySet, _> = policy.parse();
        assert!(pset.is_ok(), "scoped policy should parse: {pset:?}");
    }

    #[test]
    fn needs_enforcement_when_something_denied() {
        let mut entries = default_action_entries();
        apply_preset(&mut entries, SecurityPreset::ReadOnly);
        assert!(needs_kernel_enforcement(&entries));
    }

    #[test]
    fn no_enforcement_when_all_allowed() {
        let mut entries = default_action_entries();
        apply_preset(&mut entries, SecurityPreset::ObserveOnly);
        assert!(!needs_kernel_enforcement(&entries));
    }
}
