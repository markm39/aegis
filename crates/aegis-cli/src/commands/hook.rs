//! Hook handlers for Claude Code integration.
//!
//! Claude Code fires hooks at well-defined lifecycle points. Aegis registers
//! as a `PreToolUse` hook so that every tool call is evaluated against Cedar
//! policy before execution.
//!
//! The flow:
//! 1. Claude Code fires `PreToolUse`, passing `{tool_name, tool_input}` on stdin
//! 2. `aegis hook pre-tool-use` reads stdin, sends `EvaluateToolUse` to the daemon
//! 3. The daemon evaluates Cedar policy and returns allow/deny
//! 4. This command outputs `{"permissionDecision": "allow"}` or exits with code 2

use std::io::{self, Read};

use aegis_control::daemon::{DaemonClient, DaemonCommand, ToolUseVerdict};

/// Handle a `PreToolUse` hook invocation from Claude Code.
///
/// Reads the hook payload from stdin, queries the daemon for a Cedar policy
/// verdict, and outputs the result in Claude Code's expected format.
/// Falls back to allow if the daemon is unreachable (matching the
/// `--dangerously-skip-permissions` baseline).
pub fn pre_tool_use() -> anyhow::Result<()> {
    // Read the hook payload from stdin
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let payload: serde_json::Value = serde_json::from_str(&input)
        .unwrap_or_else(|_| serde_json::Value::Null);

    let tool_name = payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let tool_input = payload
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    // Get agent name from environment (set by the daemon/driver when spawning)
    let agent_name = std::env::var("AEGIS_AGENT_NAME")
        .unwrap_or_else(|_| "unknown".to_string());

    // Try to reach the daemon for policy evaluation
    let client = DaemonClient::default_path();
    let verdict = match client.send(&DaemonCommand::EvaluateToolUse {
        agent: agent_name,
        tool_name: tool_name.to_string(),
        tool_input,
    }) {
        Ok(resp) if resp.ok => {
            // Parse the verdict from response data
            resp.data
                .and_then(|d| serde_json::from_value::<ToolUseVerdict>(d).ok())
                .unwrap_or(ToolUseVerdict {
                    decision: "allow".to_string(),
                    reason: "could not parse daemon response".to_string(),
                })
        }
        Ok(resp) => {
            // Daemon returned an error -- default to allow
            eprintln!("aegis: policy evaluation error: {}", resp.message);
            ToolUseVerdict {
                decision: "allow".to_string(),
                reason: format!("daemon error: {}", resp.message),
            }
        }
        Err(e) => {
            // Daemon unreachable -- default to allow (dangerously-skip-permissions baseline)
            eprintln!("aegis: daemon unreachable, defaulting to allow: {e}");
            ToolUseVerdict {
                decision: "allow".to_string(),
                reason: format!("daemon unreachable: {e}"),
            }
        }
    };

    if verdict.decision == "deny" {
        // Claude Code interprets exit code 2 as "block this tool use"
        eprintln!("aegis: denied {tool_name}: {}", verdict.reason);
        let output = serde_json::json!({
            "permissionDecision": "deny",
            "reason": verdict.reason,
        });
        println!("{}", serde_json::to_string(&output)?);
        std::process::exit(2);
    }

    // Allow: output the permission decision as JSON
    let output = serde_json::json!({
        "permissionDecision": "allow",
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

/// Generate the Claude Code settings JSON fragment that registers the aegis hook.
///
/// Returns a JSON object suitable for merging into `.claude/settings.json`:
/// ```json
/// {
///   "hooks": {
///     "PreToolUse": [
///       { "type": "command", "command": "aegis hook pre-tool-use" }
///     ]
///   }
/// }
/// ```
pub fn generate_hook_settings() -> serde_json::Value {
    serde_json::json!({
        "hooks": {
            "PreToolUse": [
                {
                    "type": "command",
                    "command": "aegis hook pre-tool-use"
                }
            ]
        }
    })
}

/// Print the hook settings JSON to stdout (for `aegis hook show-settings`).
pub fn show_settings() -> anyhow::Result<()> {
    let settings = generate_hook_settings();
    println!("{}", serde_json::to_string_pretty(&settings)?);
    println!();
    println!("Add this to your project's .claude/settings.json or");
    println!("~/.claude/settings.json to enable Aegis policy enforcement.");
    Ok(())
}

/// Install the hook settings into a project's .claude/settings.json.
///
/// Creates or merges the hooks configuration. Existing non-aegis hooks
/// are preserved.
pub fn install_settings(project_dir: Option<&std::path::Path>) -> anyhow::Result<()> {
    let base = match project_dir {
        Some(dir) => dir.to_path_buf(),
        None => std::env::current_dir()?,
    };

    let claude_dir = base.join(".claude");
    std::fs::create_dir_all(&claude_dir)?;

    let settings_path = claude_dir.join("settings.json");

    // Load existing settings or start fresh
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Merge hooks
    let hook_entry = serde_json::json!({
        "type": "command",
        "command": "aegis hook pre-tool-use"
    });

    let hooks = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("settings.json is not a JSON object"))?
        .entry("hooks")
        .or_insert(serde_json::json!({}));

    let pre_tool_use = hooks
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("hooks is not a JSON object"))?
        .entry("PreToolUse")
        .or_insert(serde_json::json!([]));

    let hooks_array = pre_tool_use
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("PreToolUse is not an array"))?;

    // Check if aegis hook is already registered
    let already_installed = hooks_array.iter().any(|entry| {
        entry.get("command")
            .and_then(|v| v.as_str())
            .is_some_and(|cmd| cmd.contains("aegis hook"))
    });

    if already_installed {
        println!("Aegis hook already installed in {}", settings_path.display());
        return Ok(());
    }

    hooks_array.push(hook_entry);

    // Write back
    let output = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, output)?;

    println!("Aegis hook installed in {}", settings_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_hook_settings_structure() {
        let settings = generate_hook_settings();
        let hooks = settings.get("hooks").expect("should have hooks key");
        let pre = hooks.get("PreToolUse").expect("should have PreToolUse");
        let arr = pre.as_array().expect("PreToolUse should be array");
        assert_eq!(arr.len(), 1);
        let entry = &arr[0];
        assert_eq!(entry.get("type").unwrap().as_str().unwrap(), "command");
        assert!(entry.get("command").unwrap().as_str().unwrap().contains("aegis hook"));
    }

    #[test]
    fn install_settings_creates_file() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_settings(Some(tmpdir.path())).expect("should install");

        let settings_path = tmpdir.path().join(".claude").join("settings.json");
        assert!(settings_path.exists());

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let hooks = settings.get("hooks").unwrap();
        let pre = hooks.get("PreToolUse").unwrap().as_array().unwrap();
        assert_eq!(pre.len(), 1);
    }

    #[test]
    fn install_settings_idempotent() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_settings(Some(tmpdir.path())).expect("first install");
        install_settings(Some(tmpdir.path())).expect("second install");

        let content = std::fs::read_to_string(
            tmpdir.path().join(".claude").join("settings.json"),
        )
        .unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "should not duplicate hook entry");
    }

    #[test]
    fn install_settings_preserves_existing() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let claude_dir = tmpdir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Write existing settings with some other config
        let existing = serde_json::json!({
            "model": "claude-sonnet-4-5-20250929",
            "hooks": {
                "PostToolUse": [
                    {"type": "command", "command": "echo done"}
                ]
            }
        });
        std::fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        install_settings(Some(tmpdir.path())).expect("should install");

        let content = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Model should be preserved
        assert_eq!(settings["model"].as_str().unwrap(), "claude-sonnet-4-5-20250929");
        // PostToolUse hook should be preserved
        assert_eq!(settings["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
        // PreToolUse hook should be added
        assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }
}
