//! Hook handlers for AI coding tool integration.
//!
//! AI coding tools (Claude Code, Cursor) fire hooks at well-defined lifecycle
//! points. Aegis registers as a pre-tool-use hook so that every tool call is
//! evaluated against Cedar policy before execution.
//!
//! The flow:
//! 1. The tool fires a pre-tool-use event, passing JSON on stdin
//! 2. `aegis hook pre-tool-use` auto-detects the format (Claude Code vs Cursor)
//! 3. Sends `EvaluateToolUse` to the daemon for Cedar policy evaluation
//! 4. Outputs the verdict in the caller's expected format (exit 0 + JSON)

use std::io::{self, Read};

use aegis_control::daemon::{DaemonClient, DaemonCommand, ToolUseVerdict};
use aegis_control::hooks;

/// Which tool is calling us, determined by the stdin payload shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookFormat {
    /// Claude Code: `PreToolUse` event with `tool_name` + `tool_input`.
    ClaudeCode,
    /// Cursor: per-operation events (`beforeShellExecution`, `beforeReadFile`, etc.)
    Cursor,
}

/// Parsed hook input, normalized to a common format regardless of caller.
struct HookInput {
    format: HookFormat,
    tool_name: String,
    tool_input: serde_json::Value,
}

/// Parse the hook payload from stdin and auto-detect the calling tool.
///
/// Detection uses the `hook_event_name` field:
/// - `"PreToolUse"` -> Claude Code
/// - `"beforeShellExecution"` / `"beforeReadFile"` / `"beforeMCPExecution"` -> Cursor
/// - Anything else -> falls back to Claude Code format
fn parse_hook_input(payload: &serde_json::Value) -> HookInput {
    let event_name = payload
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match event_name {
        "beforeShellExecution" => {
            let command = payload
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            HookInput {
                format: HookFormat::Cursor,
                tool_name: "Bash".to_string(),
                tool_input: serde_json::json!({ "command": command }),
            }
        }
        "beforeReadFile" => {
            let file_path = payload
                .get("file_path")
                .or_else(|| payload.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            HookInput {
                format: HookFormat::Cursor,
                tool_name: "Read".to_string(),
                tool_input: serde_json::json!({ "file_path": file_path }),
            }
        }
        "beforeMCPExecution" => {
            // MCP tool calls from Cursor -- extract the tool name and input
            let tool = payload
                .get("mcp_tool_name")
                .or_else(|| payload.get("tool_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("mcp_tool")
                .to_string();
            let input = payload
                .get("mcp_tool_input")
                .or_else(|| payload.get("tool_input"))
                .cloned()
                .unwrap_or(serde_json::json!({}));
            HookInput {
                format: HookFormat::Cursor,
                tool_name: tool,
                tool_input: input,
            }
        }
        _ => {
            // Claude Code format (default)
            let tool_name = payload
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let tool_input = payload
                .get("tool_input")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            HookInput {
                format: HookFormat::ClaudeCode,
                tool_name,
                tool_input,
            }
        }
    }
}

/// Format an allow response in the caller's expected dialect.
fn format_allow(format: HookFormat) -> serde_json::Value {
    match format {
        HookFormat::ClaudeCode => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }),
        HookFormat::Cursor => serde_json::json!({
            "continue": true,
            "permission": "allow",
        }),
    }
}

/// Format a deny response in the caller's expected dialect.
///
/// For Claude Code, `permissionDecisionReason` is shown directly to the model
/// so it can adapt its approach (e.g. try a different tool).
fn format_deny(format: HookFormat, tool_name: &str, reason: &str) -> serde_json::Value {
    match format {
        HookFormat::ClaudeCode => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": format!(
                    "Aegis policy denied this {tool_name} call: {reason}. \
                     Try a different approach that doesn't require this tool."
                ),
            }
        }),
        HookFormat::Cursor => serde_json::json!({
            "continue": false,
            "permission": "deny",
            "agentMessage": format!("Blocked by Aegis policy: {reason}"),
        }),
    }
}

/// Handle a pre-tool-use hook invocation from Claude Code or Cursor.
///
/// Reads the hook payload from stdin, auto-detects the format, queries the
/// daemon for a Cedar policy verdict, and outputs the result in the caller's
/// expected format. Falls back to allow if the daemon is unreachable (matching
/// the `--dangerously-skip-permissions` baseline).
pub fn pre_tool_use() -> anyhow::Result<()> {
    // Read the hook payload from stdin (capped at 10 MB to prevent memory exhaustion)
    let mut input = String::new();
    io::stdin().take(10 * 1024 * 1024).read_to_string(&mut input)?;

    let payload: serde_json::Value = serde_json::from_str(&input)
        .unwrap_or_else(|_| serde_json::Value::Null);

    let hook_input = parse_hook_input(&payload);

    // Get agent name from environment (set by the daemon/driver when spawning)
    let agent_name = std::env::var("AEGIS_AGENT_NAME")
        .unwrap_or_else(|_| "unknown".to_string());

    // Try to reach the daemon for policy evaluation.
    // AEGIS_SOCKET_PATH allows the daemon to point hooks at a non-default socket.
    let client = match std::env::var("AEGIS_SOCKET_PATH") {
        Ok(path) => DaemonClient::new(path.into()),
        Err(_) => DaemonClient::default_path(),
    };
    let verdict = match client.send(&DaemonCommand::EvaluateToolUse {
        agent: agent_name,
        tool_name: hook_input.tool_name.clone(),
        tool_input: hook_input.tool_input,
    }) {
        Ok(resp) if resp.ok => {
            resp.data
                .and_then(|d| serde_json::from_value::<ToolUseVerdict>(d).ok())
                .unwrap_or(ToolUseVerdict {
                    decision: "allow".to_string(),
                    reason: "could not parse daemon response".to_string(),
                })
        }
        Ok(resp) => {
            eprintln!("aegis: policy evaluation error: {}", resp.message);
            ToolUseVerdict {
                decision: "allow".to_string(),
                reason: format!("daemon error: {}", resp.message),
            }
        }
        Err(e) => {
            eprintln!("aegis: daemon unreachable, defaulting to allow: {e}");
            ToolUseVerdict {
                decision: "allow".to_string(),
                reason: format!("daemon unreachable: {e}"),
            }
        }
    };

    if verdict.decision == "deny" {
        eprintln!("aegis: denied {}: {}", hook_input.tool_name, verdict.reason);
        let output = format_deny(hook_input.format, &hook_input.tool_name, &verdict.reason);
        println!("{}", serde_json::to_string(&output)?);
        return Ok(());
    }

    let output = format_allow(hook_input.format);
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

/// Generate the Claude Code settings JSON fragment that registers the aegis hook.
///
/// Delegates to `aegis_control::hooks::generate_hook_settings()` -- the single
/// source of truth for hook configuration format.
pub fn generate_hook_settings() -> serde_json::Value {
    hooks::generate_hook_settings()
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

/// Install the hook settings into a project's `.claude/settings.json`.
///
/// Creates or merges the hooks configuration. Existing non-aegis hooks
/// are preserved. Delegates to `aegis_control::hooks::install_project_hooks()`.
pub fn install_settings(project_dir: Option<&std::path::Path>) -> anyhow::Result<()> {
    let base = match project_dir {
        Some(dir) => dir.to_path_buf(),
        None => std::env::current_dir()?,
    };

    let settings_path = base.join(".claude").join("settings.json");
    let already_exists = settings_path.exists();

    hooks::install_project_hooks(&base)
        .map_err(|e| anyhow::anyhow!(e))?;

    if already_exists {
        // Check if it was a no-op (already installed)
        println!("Aegis hook installed in {}", settings_path.display());
    } else {
        println!("Aegis hook installed in {}", settings_path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_claude_code_format() {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"}
        });
        let input = parse_hook_input(&payload);
        assert_eq!(input.format, HookFormat::ClaudeCode);
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input["command"], "ls -la");
    }

    #[test]
    fn parse_cursor_shell_format() {
        let payload = serde_json::json!({
            "hook_event_name": "beforeShellExecution",
            "command": "git status",
            "cwd": "/tmp"
        });
        let input = parse_hook_input(&payload);
        assert_eq!(input.format, HookFormat::Cursor);
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input["command"], "git status");
    }

    #[test]
    fn parse_cursor_read_format() {
        let payload = serde_json::json!({
            "hook_event_name": "beforeReadFile",
            "file_path": "/etc/passwd"
        });
        let input = parse_hook_input(&payload);
        assert_eq!(input.format, HookFormat::Cursor);
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.tool_input["file_path"], "/etc/passwd");
    }

    #[test]
    fn parse_cursor_mcp_format() {
        let payload = serde_json::json!({
            "hook_event_name": "beforeMCPExecution",
            "mcp_tool_name": "github_search",
            "mcp_tool_input": {"query": "aegis"}
        });
        let input = parse_hook_input(&payload);
        assert_eq!(input.format, HookFormat::Cursor);
        assert_eq!(input.tool_name, "github_search");
        assert_eq!(input.tool_input["query"], "aegis");
    }

    #[test]
    fn parse_unknown_defaults_to_claude_code() {
        let payload = serde_json::json!({
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/foo"}
        });
        let input = parse_hook_input(&payload);
        assert_eq!(input.format, HookFormat::ClaudeCode);
        assert_eq!(input.tool_name, "Read");
    }

    #[test]
    fn format_allow_claude_code() {
        let output = format_allow(HookFormat::ClaudeCode);
        let hso = &output["hookSpecificOutput"];
        assert_eq!(hso["hookEventName"], "PreToolUse");
        assert_eq!(hso["permissionDecision"], "allow");
    }

    #[test]
    fn format_allow_cursor() {
        let output = format_allow(HookFormat::Cursor);
        assert_eq!(output["continue"], true);
        assert_eq!(output["permission"], "allow");
    }

    #[test]
    fn format_deny_claude_code() {
        let output = format_deny(HookFormat::ClaudeCode, "Bash", "forbidden path");
        let hso = &output["hookSpecificOutput"];
        assert_eq!(hso["hookEventName"], "PreToolUse");
        assert_eq!(hso["permissionDecision"], "deny");
        let reason = hso["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("Bash"), "reason should mention tool name");
        assert!(reason.contains("forbidden path"), "reason should include policy reason");
    }

    #[test]
    fn format_deny_cursor() {
        let output = format_deny(HookFormat::Cursor, "Bash", "forbidden path");
        assert_eq!(output["continue"], false);
        assert_eq!(output["permission"], "deny");
        assert!(output["agentMessage"]
            .as_str()
            .unwrap()
            .contains("forbidden path"));
    }

    #[test]
    fn generate_hook_settings_structure() {
        let settings = generate_hook_settings();
        let hooks = settings.get("hooks").expect("should have hooks key");
        let pre = hooks.get("PreToolUse").expect("should have PreToolUse");
        let arr = pre.as_array().expect("PreToolUse should be array");
        assert_eq!(arr.len(), 1);
        // Nested: matcher group -> hooks array -> handler
        let group = &arr[0];
        let inner = group.get("hooks").expect("matcher group should have hooks array");
        let handlers = inner.as_array().expect("should be array");
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0]["type"].as_str().unwrap(), "command");
        assert!(handlers[0]["command"].as_str().unwrap().contains("aegis hook"));
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
