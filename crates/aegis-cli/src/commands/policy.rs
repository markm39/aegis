use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};

use aegis_policy::builtin::get_builtin_policy;
use aegis_policy::default_schema;
use aegis_policy::PolicyEngine;
use aegis_types::{Action, ActionKind};

use crate::commands::init::load_config;

/// Run `aegis policy validate --path FILE`.
///
/// Reads a .cedar file, parses it as a PolicySet, loads the default schema,
/// and validates.
pub fn validate(path: &Path) -> Result<()> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;

    // Attempt to parse as a PolicySet
    let policy_set = match cedar_policy::PolicySet::from_str(&content) {
        Ok(ps) => ps,
        Err(e) => {
            println!("INVALID: failed to parse policy file");
            println!("  Error: {e}");
            return Ok(());
        }
    };

    let policy_count = policy_set.policies().count();

    // Load the default schema and validate
    let schema = default_schema().context("failed to load Aegis schema")?;
    let validation_result =
        cedar_policy::Validator::new(schema).validate(&policy_set, cedar_policy::ValidationMode::Strict);

    if validation_result.validation_passed() {
        println!("VALID: {} policies parsed and validated successfully", policy_count);
    } else {
        println!("INVALID: policy parsed but has validation errors:");
        for error in validation_result.validation_errors() {
            println!("  - {error}");
        }
    }

    Ok(())
}

/// Run `aegis policy list --config NAME`.
///
/// Lists all .cedar files in the first policy path, showing filenames and
/// first lines.
pub fn list(config_name: &str) -> Result<()> {
    let config = load_config(config_name)?;

    let policy_dir = config
        .policy_paths
        .first()
        .context("no policy paths configured")?;

    if !policy_dir.exists() {
        println!("No policy directory found at {}", policy_dir.display());
        return Ok(());
    }

    let entries = fs::read_dir(policy_dir)
        .with_context(|| format!("failed to read directory: {}", policy_dir.display()))?;

    let mut found = false;
    for entry in entries {
        let entry = entry.context("failed to read directory entry")?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "cedar") {
            found = true;
            let filename = path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();

            let first_line = fs::read_to_string(&path)
                .ok()
                .and_then(|content| {
                    content
                        .lines()
                        .find(|line| !line.trim().is_empty())
                        .map(|line| line.trim().to_string())
                })
                .unwrap_or_else(|| "(empty)".to_string());

            println!("  {filename}: {first_line}");
        }
    }

    if !found {
        println!("No .cedar files found in {}", policy_dir.display());
    }

    Ok(())
}

/// Run `aegis policy generate --template NAME`.
///
/// Looks up a builtin policy by name and prints it to stdout.
pub fn generate(template_name: &str) -> Result<()> {
    match get_builtin_policy(template_name) {
        Some(policy_text) => {
            print!("{policy_text}");
            Ok(())
        }
        None => {
            bail!(
                "unknown policy template '{template_name}'; valid options: default-deny, allow-read-only"
            );
        }
    }
}

/// Run `aegis policy test NAME --action ACTION --resource RESOURCE`.
///
/// Evaluates a Cedar policy against a hypothetical request without running
/// anything. Shows the decision and reason.
pub fn test_policy(config_name: &str, action_name: &str, resource: &str) -> Result<()> {
    let config = load_config(config_name)?;

    let policy_dir = config
        .policy_paths
        .first()
        .context("no policy paths configured")?;

    let engine =
        PolicyEngine::new(policy_dir, None).context("failed to initialize policy engine")?;

    let action_kind = parse_action_kind(action_name, resource)?;
    let action = Action::new(&config.name, action_kind);
    let verdict = engine.evaluate(&action);

    let decision_str = if verdict.decision == aegis_types::Decision::Allow {
        "ALLOW"
    } else {
        "DENY"
    };

    println!("Policy evaluation:");
    println!(
        "  Principal:  Aegis::Agent::\"{}\"",
        config.name
    );
    println!(
        "  Action:     Aegis::Action::\"{action_name}\""
    );
    println!("  Resource:   Aegis::Resource::\"{resource}\"");
    println!("  Decision:   {decision_str}");
    println!("  Reason:     {}", verdict.reason);

    Ok(())
}

/// Parse a CLI action name and resource into an `ActionKind`.
fn parse_action_kind(action_name: &str, resource: &str) -> Result<ActionKind> {
    match action_name {
        "FileRead" => Ok(ActionKind::FileRead {
            path: PathBuf::from(resource),
        }),
        "FileWrite" => Ok(ActionKind::FileWrite {
            path: PathBuf::from(resource),
        }),
        "FileDelete" => Ok(ActionKind::FileDelete {
            path: PathBuf::from(resource),
        }),
        "DirCreate" => Ok(ActionKind::DirCreate {
            path: PathBuf::from(resource),
        }),
        "DirList" => Ok(ActionKind::DirList {
            path: PathBuf::from(resource),
        }),
        "NetConnect" => Ok(ActionKind::NetConnect {
            host: resource.to_string(),
            port: 443,
        }),
        "ToolCall" => Ok(ActionKind::ToolCall {
            tool: resource.to_string(),
            args: serde_json::Value::Null,
        }),
        "ProcessSpawn" => Ok(ActionKind::ProcessSpawn {
            command: resource.to_string(),
            args: vec![],
        }),
        "ProcessExit" => Ok(ActionKind::ProcessExit {
            command: resource.to_string(),
            exit_code: 0,
        }),
        _ => bail!(
            "unknown action '{action_name}'; valid actions: FileRead, FileWrite, FileDelete, DirCreate, DirList, NetConnect, ToolCall, ProcessSpawn, ProcessExit"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_action_kind_file_read() {
        let kind = parse_action_kind("FileRead", "/tmp/test.txt").unwrap();
        assert!(matches!(kind, ActionKind::FileRead { .. }));
    }

    #[test]
    fn parse_action_kind_net_connect() {
        let kind = parse_action_kind("NetConnect", "example.com").unwrap();
        assert!(matches!(kind, ActionKind::NetConnect { .. }));
    }

    #[test]
    fn parse_action_kind_unknown_fails() {
        let result = parse_action_kind("Unknown", "/tmp");
        assert!(result.is_err());
    }

    #[test]
    fn parse_all_valid_actions() {
        let actions = [
            "FileRead",
            "FileWrite",
            "FileDelete",
            "DirCreate",
            "DirList",
            "NetConnect",
            "ToolCall",
            "ProcessSpawn",
            "ProcessExit",
        ];
        for action in actions {
            assert!(
                parse_action_kind(action, "/resource").is_ok(),
                "should parse {action}"
            );
        }
    }
}
