//! Cedar policy engine for Aegis authorization.
//!
//! Wraps the Cedar `PolicySet`, `Schema`, and `Authorizer` to provide
//! a single `evaluate()` method that maps Aegis `Action`s to Cedar
//! authorization requests and returns `Verdict`s.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request, RestrictedExpression, Schema,
};

use aegis_types::{Action, ActionKind, AegisError, Verdict};

use crate::builtin::DEFAULT_DENY;
use crate::schema::default_schema;

/// The core policy engine that evaluates Aegis actions against Cedar policies.
pub struct PolicyEngine {
    policy_set: PolicySet,
    schema: Schema,
}

impl PolicyEngine {
    /// Create a new `PolicyEngine` by loading all `.cedar` files from `policy_dir`.
    ///
    /// If no schema is provided, the default Aegis schema is used. If the
    /// directory does not exist or contains no `.cedar` files, the engine
    /// falls back to the built-in `DEFAULT_DENY` policy.
    pub fn new(policy_dir: &Path, schema: Option<Schema>) -> Result<Self, AegisError> {
        let schema = match schema {
            Some(s) => s,
            None => default_schema()?,
        };

        let policy_set = load_policies_from_dir(policy_dir)?;

        Ok(Self { policy_set, schema })
    }

    /// Create a `PolicyEngine` from a Cedar policy string.
    ///
    /// Useful for testing or when policies are not stored on disk.
    pub fn from_policies(policies: &str, schema: Option<Schema>) -> Result<Self, AegisError> {
        let schema = match schema {
            Some(s) => s,
            None => default_schema()?,
        };

        let policy_set = PolicySet::from_str(policies)
            .map_err(|e| AegisError::PolicyError(format!("failed to parse policies: {e}")))?;

        Ok(Self { policy_set, schema })
    }

    /// Evaluate an `Action` against the loaded Cedar policies.
    ///
    /// Converts the action into Cedar entities and a request, runs the
    /// authorizer, and returns a `Verdict`.
    pub fn evaluate(&self, action: &Action) -> Verdict {
        match self.evaluate_inner(action) {
            Ok(verdict) => verdict,
            Err(e) => {
                tracing::error!(action_id = %action.id, error = %e, "policy evaluation failed");
                Verdict::deny(action.id, format!("policy evaluation error: {e}"), None)
            }
        }
    }

    /// Get a reference to the underlying Cedar `PolicySet`.
    ///
    /// Useful for inspecting loaded policies, e.g. when compiling Cedar
    /// policies to another format like Seatbelt SBPL profiles.
    pub fn policy_set(&self) -> &PolicySet {
        &self.policy_set
    }

    /// Probe whether the loaded policies permit a given action type.
    ///
    /// Constructs a synthetic action and evaluates it. Returns `true` if
    /// the policy set would allow any agent to perform this action on any
    /// resource. Useful for compile-time policy inspection (e.g. deciding
    /// which Seatbelt SBPL rules to generate).
    pub fn permits_action(&self, action_name: &str) -> bool {
        let probe_path = || std::path::PathBuf::from("/__probe__");
        let action = Action::new(
            "__probe__",
            match action_name {
                "FileRead" => ActionKind::FileRead { path: probe_path() },
                "FileWrite" => ActionKind::FileWrite { path: probe_path() },
                "FileDelete" => ActionKind::FileDelete { path: probe_path() },
                "DirCreate" => ActionKind::DirCreate { path: probe_path() },
                "DirList" => ActionKind::DirList { path: probe_path() },
                "NetConnect" => ActionKind::NetConnect {
                    host: "__probe__".into(),
                    port: 0,
                },
                "ToolCall" => ActionKind::ToolCall {
                    tool: "__probe__".into(),
                    args: serde_json::Value::Null,
                },
                "ProcessSpawn" => ActionKind::ProcessSpawn {
                    command: "__probe__".into(),
                    args: vec![],
                },
                "ProcessExit" => ActionKind::ProcessExit {
                    command: "__probe__".into(),
                    exit_code: 0,
                },
                _ => return false,
            },
        );
        let verdict = self.evaluate(&action);
        verdict.decision == aegis_types::Decision::Allow
    }

    /// Reload policies from the given directory, replacing the current policy set.
    pub fn reload(&mut self, policy_dir: &Path) -> Result<(), AegisError> {
        let new_policy_set = load_policies_from_dir(policy_dir)?;
        self.policy_set = new_policy_set;
        Ok(())
    }

    /// Inner evaluation that can return errors, keeping the public API clean.
    fn evaluate_inner(&self, action: &Action) -> Result<Verdict, AegisError> {
        let (action_name, resource_path) = extract_action_info(&action.kind)?;

        // Build entity UIDs
        let principal_uid = build_entity_uid("Aegis::Agent", &action.principal)?;
        let action_uid = build_entity_uid("Aegis::Action", action_name)?;
        let resource_uid = build_entity_uid("Aegis::Resource", resource_path)?;

        // Build the Resource entity with "path" attribute
        let resource_entity = Entity::new(
            resource_uid.clone(),
            HashMap::from([(
                "path".to_string(),
                RestrictedExpression::new_string(resource_path.to_string()),
            )]),
            HashSet::new(),
        )
        .map_err(|e| AegisError::PolicyError(format!("failed to create resource entity: {e}")))?;

        // Build the Agent entity (no attributes)
        let principal_entity = Entity::new_no_attrs(principal_uid.clone(), HashSet::new());

        // Build entities collection including action entities from schema
        let mut entities = Entities::from_entities(
            vec![principal_entity, resource_entity],
            Some(&self.schema),
        )
        .map_err(|e| AegisError::PolicyError(format!("failed to build entities: {e}")))?;

        // Add action entities from the schema
        let action_entities = self
            .schema
            .action_entities()
            .map_err(|e| AegisError::PolicyError(format!("failed to get action entities: {e}")))?;
        for entity in action_entities.iter() {
            entities = entities
                .add_entities(std::iter::once(entity.clone()), Some(&self.schema))
                .map_err(|e| {
                    AegisError::PolicyError(format!("failed to add action entity: {e}"))
                })?;
        }

        // Build the request (no schema validation -- we handle schema ourselves)
        let context = Context::empty();
        let request = Request::new(principal_uid, action_uid, resource_uid, context, None)
            .map_err(|e| AegisError::PolicyError(format!("failed to create request: {e}")))?;

        // Evaluate
        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&request, &self.policy_set, &entities);

        Ok(verdict_from_response(action, &response))
    }
}

/// Convert a Cedar authorization response into an Aegis `Verdict`.
///
/// Extracts the determining policy IDs from diagnostics and builds a
/// human-readable reason string describing why the decision was made.
fn verdict_from_response(action: &Action, response: &cedar_policy::Response) -> Verdict {
    let reason_policies: Vec<String> = response
        .diagnostics()
        .reason()
        .map(|pid| pid.to_string())
        .collect();

    let policy_id = reason_policies.first().cloned();
    let reason_str = if reason_policies.is_empty() {
        match response.decision() {
            cedar_policy::Decision::Allow => "allowed by policy".to_string(),
            cedar_policy::Decision::Deny => "denied: no permit policy matched".to_string(),
        }
    } else {
        format!(
            "{} by policies: {}",
            match response.decision() {
                cedar_policy::Decision::Allow => "allowed",
                cedar_policy::Decision::Deny => "denied",
            },
            reason_policies.join(", ")
        )
    };

    match response.decision() {
        cedar_policy::Decision::Allow => Verdict::allow(action.id, reason_str, policy_id),
        cedar_policy::Decision::Deny => Verdict::deny(action.id, reason_str, policy_id),
    }
}

/// Extract the Cedar action name and resource path from an `ActionKind`.
///
/// Returns an error if a path cannot be converted to UTF-8, since Cedar
/// policies operate on string-based resource identifiers and silently
/// substituting a placeholder could bypass policy rules.
fn extract_action_info(kind: &ActionKind) -> Result<(&str, &str), AegisError> {
    match kind {
        ActionKind::FileRead { path } => Ok(("FileRead", require_utf8(path)?)),
        ActionKind::FileWrite { path } => Ok(("FileWrite", require_utf8(path)?)),
        ActionKind::FileDelete { path } => Ok(("FileDelete", require_utf8(path)?)),
        ActionKind::DirCreate { path } => Ok(("DirCreate", require_utf8(path)?)),
        ActionKind::DirList { path } => Ok(("DirList", require_utf8(path)?)),
        ActionKind::NetConnect { host, .. } => Ok(("NetConnect", host.as_str())),
        ActionKind::NetRequest { url, .. } => Ok(("NetConnect", url.as_str())),
        ActionKind::ToolCall { tool, .. } => Ok(("ToolCall", tool.as_str())),
        ActionKind::ProcessSpawn { command, .. } => Ok(("ProcessSpawn", command.as_str())),
        ActionKind::ProcessExit { command, .. } => Ok(("ProcessExit", command.as_str())),
    }
}

/// Require a path to be valid UTF-8, returning an error otherwise.
fn require_utf8(path: &std::path::Path) -> Result<&str, AegisError> {
    path.to_str().ok_or_else(|| {
        AegisError::PolicyError(format!("non-UTF8 path: {}", path.display()))
    })
}

/// Build a Cedar `EntityUid` from a type name string and an id string.
fn build_entity_uid(type_name: &str, id: &str) -> Result<EntityUid, AegisError> {
    let tn = EntityTypeName::from_str(type_name)
        .map_err(|e| AegisError::PolicyError(format!("invalid entity type name '{type_name}': {e}")))?;
    let eid = EntityId::new(id);
    Ok(EntityUid::from_type_name_and_id(tn, eid))
}

/// Load all `.cedar` files from a directory into a `PolicySet`.
///
/// Falls back to `DEFAULT_DENY` if the directory does not exist or contains no
/// `.cedar` files.
fn load_policies_from_dir(dir: &Path) -> Result<PolicySet, AegisError> {
    if !dir.exists() || !dir.is_dir() {
        tracing::info!(
            path = %dir.display(),
            "policy directory not found, using default-deny"
        );
        return PolicySet::from_str(DEFAULT_DENY)
            .map_err(|e| AegisError::PolicyError(format!("failed to parse default-deny: {e}")));
    }

    let mut policy_texts = Vec::new();

    let entries = std::fs::read_dir(dir)
        .map_err(|e| AegisError::PolicyError(format!("failed to read policy directory: {e}")))?;

    for entry in entries {
        let entry = entry
            .map_err(|e| AegisError::PolicyError(format!("failed to read directory entry: {e}")))?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "cedar") {
            let content = std::fs::read_to_string(&path).map_err(|e| {
                AegisError::PolicyError(format!(
                    "failed to read policy file '{}': {e}",
                    path.display()
                ))
            })?;
            policy_texts.push(content);
        }
    }

    if policy_texts.is_empty() {
        tracing::info!(
            path = %dir.display(),
            "no .cedar files found, using default-deny"
        );
        return PolicySet::from_str(DEFAULT_DENY)
            .map_err(|e| AegisError::PolicyError(format!("failed to parse default-deny: {e}")));
    }

    let combined = policy_texts.join("\n");
    PolicySet::from_str(&combined)
        .map_err(|e| AegisError::PolicyError(format!("failed to parse policies: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::Decision;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn file_read_action(principal: &str, path: &str) -> Action {
        Action::new(
            principal,
            ActionKind::FileRead {
                path: PathBuf::from(path),
            },
        )
    }

    fn file_write_action(principal: &str, path: &str) -> Action {
        Action::new(
            principal,
            ActionKind::FileWrite {
                path: PathBuf::from(path),
            },
        )
    }

    fn dir_list_action(principal: &str, path: &str) -> Action {
        Action::new(
            principal,
            ActionKind::DirList {
                path: PathBuf::from(path),
            },
        )
    }

    // Test 1: Default-deny policy returns Deny for any action
    #[test]
    fn default_deny_denies_everything() {
        let engine =
            PolicyEngine::from_policies(DEFAULT_DENY, None).expect("should create engine");

        let action = file_read_action("agent-1", "/tmp/secret.txt");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Deny);
    }

    // Test 2: Explicit permit rule returns Allow for matching action
    #[test]
    fn explicit_permit_allows_matching_action() {
        let policies = r#"
            permit(
                principal,
                action == Aegis::Action::"FileRead",
                resource
            );
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");

        let action = file_read_action("agent-1", "/tmp/readme.txt");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Allow);
    }

    // Test 3: Permit + deny interaction: explicit deny overrides permit
    #[test]
    fn explicit_deny_overrides_permit() {
        let policies = r#"
            permit(
                principal,
                action == Aegis::Action::"FileRead",
                resource
            );
            forbid(
                principal,
                action == Aegis::Action::"FileRead",
                resource
            );
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");

        let action = file_read_action("agent-1", "/tmp/secret.txt");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Deny);
    }

    // Test 4: Policy reload picks up new policies
    #[test]
    fn policy_reload_picks_up_changes() {
        let tmpdir = TempDir::new().expect("should create tmpdir");

        // Start with default-deny (empty dir)
        let mut engine =
            PolicyEngine::new(tmpdir.path(), None).expect("should create engine from empty dir");

        let action = file_read_action("agent-1", "/tmp/test.txt");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Deny, "should deny initially");

        // Write a permit policy to the directory
        let policy_path = tmpdir.path().join("allow-reads.cedar");
        std::fs::write(
            &policy_path,
            r#"permit(principal, action == Aegis::Action::"FileRead", resource);"#,
        )
        .expect("should write policy file");

        // Reload
        engine
            .reload(tmpdir.path())
            .expect("should reload policies");

        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Allow, "should allow after reload");
    }

    // Test 5: from_policies constructor works
    #[test]
    fn from_policies_constructor() {
        let policies = r#"
            permit(
                principal,
                action == Aegis::Action::"DirList",
                resource
            );
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");

        let action = dir_list_action("agent-1", "/home");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Allow);
    }

    // Test 6: Invalid policy string returns an error
    #[test]
    fn invalid_policy_string_errors() {
        let result = PolicyEngine::from_policies("this is not valid cedar {{{", None);
        assert!(result.is_err(), "should fail to parse invalid policies");
    }

    // Test 7: Different action kinds are correctly mapped
    #[test]
    fn action_kinds_correctly_mapped() {
        // Permit everything for testing
        let policies = r#"
            permit(principal, action, resource);
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");

        // FileRead
        let v = engine.evaluate(&file_read_action("a", "/f"));
        assert_eq!(v.decision, Decision::Allow);

        // FileWrite
        let v = engine.evaluate(&file_write_action("a", "/f"));
        assert_eq!(v.decision, Decision::Allow);

        // FileDelete
        let v = engine.evaluate(&Action::new(
            "a",
            ActionKind::FileDelete {
                path: PathBuf::from("/f"),
            },
        ));
        assert_eq!(v.decision, Decision::Allow);

        // DirCreate
        let v = engine.evaluate(&Action::new(
            "a",
            ActionKind::DirCreate {
                path: PathBuf::from("/d"),
            },
        ));
        assert_eq!(v.decision, Decision::Allow);

        // DirList
        let v = engine.evaluate(&dir_list_action("a", "/d"));
        assert_eq!(v.decision, Decision::Allow);

        // NetConnect
        let v = engine.evaluate(&Action::new(
            "a",
            ActionKind::NetConnect {
                host: "example.com".into(),
                port: 443,
            },
        ));
        assert_eq!(v.decision, Decision::Allow);

        // ToolCall
        let v = engine.evaluate(&Action::new(
            "a",
            ActionKind::ToolCall {
                tool: "bash".into(),
                args: serde_json::json!({}),
            },
        ));
        assert_eq!(v.decision, Decision::Allow);

        // ProcessSpawn
        let v = engine.evaluate(&Action::new(
            "a",
            ActionKind::ProcessSpawn {
                command: "ls".into(),
                args: vec!["-la".into()],
            },
        ));
        assert_eq!(v.decision, Decision::Allow);
    }

    // Test: default-deny denies writes even when reads are allowed
    #[test]
    fn read_only_policy_denies_writes() {
        let engine = PolicyEngine::from_policies(
            crate::builtin::ALLOW_READ_ONLY,
            None,
        )
        .expect("should create engine");

        let read_action = file_read_action("agent-1", "/tmp/file.txt");
        let verdict = engine.evaluate(&read_action);
        assert_eq!(verdict.decision, Decision::Allow, "reads should be allowed");

        let list_action = dir_list_action("agent-1", "/tmp");
        let verdict = engine.evaluate(&list_action);
        assert_eq!(verdict.decision, Decision::Allow, "dir list should be allowed");

        let write_action = file_write_action("agent-1", "/tmp/file.txt");
        let verdict = engine.evaluate(&write_action);
        assert_eq!(verdict.decision, Decision::Deny, "writes should be denied");
    }

    // Test: engine from nonexistent directory uses default-deny
    #[test]
    fn nonexistent_dir_uses_default_deny() {
        let engine = PolicyEngine::new(Path::new("/nonexistent/path/to/policies"), None)
            .expect("should create engine with default-deny");

        let action = file_read_action("agent-1", "/tmp/file.txt");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Deny);
    }

    // Test: empty directory uses default-deny
    #[test]
    fn empty_dir_uses_default_deny() {
        let tmpdir = TempDir::new().expect("should create tmpdir");
        let engine =
            PolicyEngine::new(tmpdir.path(), None).expect("should create engine from empty dir");

        let action = file_read_action("agent-1", "/tmp/file.txt");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Deny);
    }

    // Test: ProcessExit action evaluates correctly
    #[test]
    fn process_exit_action_evaluates() {
        let policies = r#"
            permit(principal, action, resource);
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");

        let action = Action::new(
            "a",
            ActionKind::ProcessExit {
                command: "echo".into(),
                exit_code: 0,
            },
        );
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Allow);
    }

    // Test: permits_action returns true for permitted actions
    #[test]
    fn permits_action_returns_true_for_permitted() {
        let policies = r#"
            permit(principal, action == Aegis::Action::"FileRead", resource);
            permit(principal, action == Aegis::Action::"DirList", resource);
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");

        assert!(engine.permits_action("FileRead"));
        assert!(engine.permits_action("DirList"));
        assert!(!engine.permits_action("FileWrite"));
        assert!(!engine.permits_action("NetConnect"));
        assert!(!engine.permits_action("ProcessSpawn"));
    }

    // Test: permits_action returns false for default-deny
    #[test]
    fn permits_action_default_deny() {
        let engine =
            PolicyEngine::from_policies(DEFAULT_DENY, None).expect("should create engine");

        assert!(!engine.permits_action("FileRead"));
        assert!(!engine.permits_action("FileWrite"));
        assert!(!engine.permits_action("NetConnect"));
    }

    // Test: permits_action returns true for permit-all
    #[test]
    fn permits_action_permit_all() {
        let policies = r#"
            permit(principal, action, resource);
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");

        assert!(engine.permits_action("FileRead"));
        assert!(engine.permits_action("FileWrite"));
        assert!(engine.permits_action("NetConnect"));
        assert!(engine.permits_action("ProcessSpawn"));
        assert!(engine.permits_action("ProcessExit"));
    }

    // Test: permits_action returns false for unknown action name
    #[test]
    fn permits_action_unknown_action() {
        let policies = r#"
            permit(principal, action, resource);
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");
        assert!(!engine.permits_action("NonexistentAction"));
    }

    // Test: policy_set() exposes the underlying PolicySet
    #[test]
    fn policy_set_accessor() {
        let policies = r#"
            permit(principal, action == Aegis::Action::"FileRead", resource);
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");
        let ps = engine.policy_set();
        // PolicySet should have exactly one policy
        assert_eq!(ps.policies().count(), 1);
    }

    // Test: NetRequest maps to NetConnect action
    #[test]
    fn net_request_maps_to_net_connect() {
        let policies = r#"
            permit(principal, action == Aegis::Action::"NetConnect", resource);
        "#;
        let engine = PolicyEngine::from_policies(policies, None).expect("should create engine");

        let action = Action::new(
            "agent-1",
            ActionKind::NetRequest {
                method: "GET".into(),
                url: "https://example.com".into(),
            },
        );
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Allow);
    }
}
