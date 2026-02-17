//! Built-in Cedar policies for the Aegis namespace.
//!
//! These provide sensible defaults: a default-deny policy, a read-only
//! allow policy, and a permit-all policy for observe-only mode.

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

/// Allow read-write policy: permits file reads, writes, directory operations,
/// and process lifecycle. Denies network access and tool calls.
pub const ALLOW_READ_WRITE: &str = r#"
permit(
    principal,
    action == Aegis::Action::"FileRead",
    resource
);

permit(
    principal,
    action == Aegis::Action::"FileWrite",
    resource
);

permit(
    principal,
    action == Aegis::Action::"FileDelete",
    resource
);

permit(
    principal,
    action == Aegis::Action::"DirCreate",
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

/// CI runner policy: permits file reads, writes, directory operations,
/// process lifecycle. Denies network access and tool calls.
/// Same as allow-read-write (CI pipelines rarely need outbound network).
pub const CI_RUNNER: &str = ALLOW_READ_WRITE;

/// Data science policy: permits everything except tool calls.
/// Suitable for data workflows that need file and network access.
pub const DATA_SCIENCE: &str = r#"
permit(
    principal,
    action == Aegis::Action::"FileRead",
    resource
);

permit(
    principal,
    action == Aegis::Action::"FileWrite",
    resource
);

permit(
    principal,
    action == Aegis::Action::"FileDelete",
    resource
);

permit(
    principal,
    action == Aegis::Action::"DirCreate",
    resource
);

permit(
    principal,
    action == Aegis::Action::"DirList",
    resource
);

permit(
    principal,
    action == Aegis::Action::"NetConnect",
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

/// Permit-all policy: allows every action. Used for observe-only mode
/// where Aegis logs all file operations but enforces no restrictions.
pub const PERMIT_ALL: &str = r#"permit(principal, action, resource);"#;

/// Look up a built-in policy by name.
///
/// Supported names:
/// - `"default-deny"` -> [`DEFAULT_DENY`]
/// - `"allow-read-only"` -> [`ALLOW_READ_ONLY`]
/// - `"permit-all"` -> [`PERMIT_ALL`]
///
/// Returns `None` if the name is not recognized.
pub fn get_builtin_policy(name: &str) -> Option<&'static str> {
    match name {
        "default-deny" => Some(DEFAULT_DENY),
        "allow-read-only" => Some(ALLOW_READ_ONLY),
        "allow-read-write" => Some(ALLOW_READ_WRITE),
        "ci-runner" => Some(CI_RUNNER),
        "data-science" => Some(DATA_SCIENCE),
        "permit-all" => Some(PERMIT_ALL),
        _ => None,
    }
}

/// List all available builtin policy template names.
pub fn list_builtin_policies() -> &'static [&'static str] {
    &[
        "default-deny",
        "allow-read-only",
        "allow-read-write",
        "ci-runner",
        "data-science",
        "permit-all",
    ]
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
    fn permit_all_parses_as_valid_policy() {
        let pset = cedar_policy::PolicySet::from_str(PERMIT_ALL);
        assert!(pset.is_ok(), "PERMIT_ALL should parse: {pset:?}");
    }

    #[test]
    fn allow_read_write_parses_as_valid_policy() {
        let pset = cedar_policy::PolicySet::from_str(ALLOW_READ_WRITE);
        assert!(pset.is_ok(), "ALLOW_READ_WRITE should parse: {pset:?}");
    }

    #[test]
    fn data_science_parses_as_valid_policy() {
        let pset = cedar_policy::PolicySet::from_str(DATA_SCIENCE);
        assert!(pset.is_ok(), "DATA_SCIENCE should parse: {pset:?}");
    }

    #[test]
    fn get_builtin_known_names() {
        for name in list_builtin_policies() {
            assert!(
                get_builtin_policy(name).is_some(),
                "builtin policy '{name}' should be resolvable"
            );
        }
    }

    #[test]
    fn list_builtin_policies_returns_all() {
        let names = list_builtin_policies();
        assert!(names.contains(&"default-deny"));
        assert!(names.contains(&"allow-read-only"));
        assert!(names.contains(&"allow-read-write"));
        assert!(names.contains(&"ci-runner"));
        assert!(names.contains(&"data-science"));
        assert!(names.contains(&"permit-all"));
    }

    #[test]
    fn get_builtin_unknown_name_returns_none() {
        assert!(get_builtin_policy("nonexistent").is_none());
        assert!(get_builtin_policy("").is_none());
    }
}
