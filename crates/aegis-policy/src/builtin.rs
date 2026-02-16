//! Built-in Cedar policies for the Aegis namespace.
//!
//! These provide sensible defaults: a default-deny policy and a read-only
//! allow policy.

/// Default-deny policy: forbids everything unless another policy explicitly permits it.
pub const DEFAULT_DENY: &str = r#"forbid(principal, action, resource);"#;

/// Read-only allow policy: permits FileRead and DirList actions for any agent.
/// Also permits ProcessSpawn and ProcessExit for accurate audit logging.
pub const ALLOW_READ_ONLY: &str = r#"
permit(
    principal,
    action == Aegis::Action::"FileRead",
    resource
);

permit(
    principal,
    action == Aegis::Action::"DirList",
    resource
);

permit(
    principal,
    action == Aegis::Action::"ProcessSpawn",
    resource
);

permit(
    principal,
    action == Aegis::Action::"ProcessExit",
    resource
);
"#;

/// Look up a built-in policy by name.
///
/// Supported names:
/// - `"default-deny"` -> [`DEFAULT_DENY`]
/// - `"allow-read-only"` -> [`ALLOW_READ_ONLY`]
///
/// Returns `None` if the name is not recognized.
pub fn get_builtin_policy(name: &str) -> Option<&'static str> {
    match name {
        "default-deny" => Some(DEFAULT_DENY),
        "allow-read-only" => Some(ALLOW_READ_ONLY),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn default_deny_parses_as_valid_policy() {
        let pset = cedar_policy::PolicySet::from_str(DEFAULT_DENY);
        assert!(pset.is_ok(), "DEFAULT_DENY should parse: {pset:?}");
    }

    #[test]
    fn allow_read_only_parses_as_valid_policy() {
        let pset = cedar_policy::PolicySet::from_str(ALLOW_READ_ONLY);
        assert!(pset.is_ok(), "ALLOW_READ_ONLY should parse: {pset:?}");
    }

    #[test]
    fn get_builtin_known_names() {
        assert!(get_builtin_policy("default-deny").is_some());
        assert!(get_builtin_policy("allow-read-only").is_some());
    }

    #[test]
    fn get_builtin_unknown_name_returns_none() {
        assert!(get_builtin_policy("nonexistent").is_none());
        assert!(get_builtin_policy("").is_none());
    }
}
