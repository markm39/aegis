//! Cedar schema definitions for the Aegis namespace.
//!
//! Defines entity types (Agent, Resource) and actions (FileRead, FileWrite, etc.)
//! that model the Aegis security domain.

/// The Cedar schema for the Aegis namespace in Cedar schema format.
///
/// Entity types:
/// - `Agent`: represents an AI agent principal
/// - `Resource`: represents a target resource with a `path` attribute
///
/// Actions:
/// - FileRead, FileWrite, FileDelete, DirCreate, DirList, NetConnect,
///   ToolCall, ProcessSpawn, ProcessExit, ApiUsage -- each applying to principal Agent and resource Resource
pub const AEGIS_SCHEMA: &str = r#"
namespace Aegis {
    entity Agent = {};
    entity Resource = {
        "path": String,
    };

    action "FileRead" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "FileWrite" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "FileDelete" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "DirCreate" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "DirList" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "NetConnect" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "ToolCall" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "ProcessSpawn" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "ProcessExit" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "ApiUsage" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "SessionSend" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "SessionList" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "SessionHistory" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
    action "SubagentSpawn" appliesTo {
        principal: [Agent],
        resource: [Resource],
    };
}
"#;

/// Parse the default Aegis Cedar schema into a `cedar_policy::Schema`.
///
/// Returns `Err` if the schema text is invalid (should not happen with the
/// built-in schema).
pub fn default_schema() -> Result<cedar_policy::Schema, aegis_types::AegisError> {
    let (schema, warnings) =
        cedar_policy::Schema::from_cedarschema_str(AEGIS_SCHEMA).map_err(|e| {
            aegis_types::AegisError::PolicyError(format!("failed to parse Aegis schema: {e}"))
        })?;

    for warning in warnings {
        tracing::warn!(%warning, "Cedar schema warning");
    }

    Ok(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_parses_successfully() {
        let schema = default_schema().expect("default schema should parse");
        // Verify we can extract action entities from the schema
        let _actions = schema
            .action_entities()
            .expect("should have action entities");
    }

    #[test]
    fn schema_contains_expected_principals() {
        let schema = default_schema().expect("default schema should parse");
        let principals: Vec<String> = schema.principals().map(|p| p.to_string()).collect();
        assert!(
            principals.iter().any(|p| p == "Aegis::Agent"),
            "schema should contain Aegis::Agent as a principal type, got: {principals:?}"
        );
    }

    #[test]
    fn schema_contains_expected_resources() {
        let schema = default_schema().expect("default schema should parse");
        let resources: Vec<String> = schema.resources().map(|r| r.to_string()).collect();
        assert!(
            resources.iter().any(|r| r == "Aegis::Resource"),
            "schema should contain Aegis::Resource as a resource type, got: {resources:?}"
        );
    }

    #[test]
    fn schema_contains_all_action_types() {
        // Every ActionKind variant must have a corresponding action in the Cedar schema.
        // If you add a new ActionKind, add it here too -- otherwise policy evaluation
        // will silently fail for that action type.
        let expected_actions = [
            "FileRead",
            "FileWrite",
            "FileDelete",
            "DirCreate",
            "DirList",
            "NetConnect",
            "ToolCall",
            "ProcessSpawn",
            "ProcessExit",
            "ApiUsage",
            "SessionSend",
            "SessionList",
            "SessionHistory",
            "SubagentSpawn",
        ];

        let schema_text = AEGIS_SCHEMA;
        for action in &expected_actions {
            assert!(
                schema_text.contains(&format!("action \"{action}\"")),
                "schema should contain action '{action}'"
            );
        }
    }
}
