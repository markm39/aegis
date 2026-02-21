//! Hook handlers for AI coding tool integration.
//!
//! AI coding tools (Claude Code) fire hooks at well-defined lifecycle
//! points. Aegis registers as a pre-tool-use hook so that every tool call is
//! evaluated against Cedar policy before execution.
//!
//! The flow:
//! 1. The tool fires a pre-tool-use event, passing JSON on stdin
//! 2. `aegis hook pre-tool-use` auto-detects the format (Claude Code)
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
    // Placeholder for future hook formats.
}

/// Parsed hook input, normalized to a common format regardless of caller.
struct HookInput {
    format: HookFormat,
    tool_name: String,
    tool_input: serde_json::Value,
}

/// Whether hook fallback behavior should fail open.
///
/// Defaults to fail-closed for safety. Set `AEGIS_HOOK_FAIL_OPEN=1` (or
/// true/yes/on) only for lower-trust development workflows.
fn hook_fail_open_enabled() -> bool {
    std::env::var("AEGIS_HOOK_FAIL_OPEN")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Build a fallback verdict for control-plane failures.
fn fallback_verdict(reason: String) -> ToolUseVerdict {
    if hook_fail_open_enabled() {
        ToolUseVerdict {
            decision: "allow".to_string(),
            reason: format!("{reason} (allowed due to AEGIS_HOOK_FAIL_OPEN)"),
        }
    } else {
        ToolUseVerdict {
            decision: "deny".to_string(),
            reason: format!("{reason} (denied by fail-closed hook policy)"),
        }
    }
}

/// Parse the hook payload from stdin and auto-detect the calling tool.
///
/// Detection uses the `hook_event_name` field:
/// - `"PreToolUse"` -> Claude Code
/// - Anything else -> falls back to Claude Code format
fn parse_hook_input(payload: &serde_json::Value) -> HookInput {
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

/// Format an allow response in the caller's expected dialect.
fn format_allow(format: HookFormat) -> serde_json::Value {
    match format {
        HookFormat::ClaudeCode => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
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
    }
}

/// Handle a pre-tool-use hook invocation from Claude Code.
///
/// Reads the hook payload from stdin, auto-detects the format, queries the
/// daemon for a Cedar policy verdict, and outputs the result in the caller's
/// expected format. Falls back to fail-closed deny when the daemon is
/// unreachable unless `AEGIS_HOOK_FAIL_OPEN` is explicitly enabled.
pub fn pre_tool_use() -> anyhow::Result<()> {
    // Read the hook payload from stdin (capped at 10 MB to prevent memory exhaustion)
    let mut input = String::new();
    io::stdin()
        .take(10 * 1024 * 1024)
        .read_to_string(&mut input)?;

    let payload: serde_json::Value =
        serde_json::from_str(&input).unwrap_or_else(|_| serde_json::Value::Null);

    let hook_input = parse_hook_input(&payload);

    // Get agent name from environment (set by the daemon/driver when spawning)
    let agent_name = std::env::var("AEGIS_AGENT_NAME").unwrap_or_else(|_| "unknown".to_string());

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
        Ok(resp) if resp.ok => resp
            .data
            .and_then(|d| serde_json::from_value::<ToolUseVerdict>(d).ok())
            .unwrap_or_else(|| fallback_verdict("could not parse daemon response".to_string())),
        Ok(resp) => {
            eprintln!("aegis: policy evaluation error: {}", resp.message);
            fallback_verdict(format!("daemon error: {}", resp.message))
        }
        Err(e) => {
            eprintln!("aegis: daemon unreachable: {e}");
            fallback_verdict(format!("daemon unreachable: {e}"))
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

/// Parsed PostToolUse input from Claude Code.
///
/// Contains the tool name, input, and the tool's output after execution.
/// PostToolUse is purely observational -- it never blocks execution.
struct PostToolUseInput {
    tool_name: String,
    tool_input: serde_json::Value,
    _tool_output: serde_json::Value,
}

/// Parse a PostToolUse payload from stdin.
fn parse_post_tool_use_input(payload: &serde_json::Value) -> PostToolUseInput {
    let tool_name = payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let tool_input = payload
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let tool_output = payload
        .get("tool_output")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    PostToolUseInput {
        tool_name,
        tool_input,
        _tool_output: tool_output,
    }
}

/// Format the PostToolUse response JSON.
///
/// PostToolUse hooks are observational -- the response simply acknowledges receipt.
fn format_post_tool_use_response() -> serde_json::Value {
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse"
        }
    })
}

/// Handle a post-tool-use hook invocation from Claude Code.
///
/// Reads the hook payload from stdin, records the tool result for
/// observability, and outputs an acknowledgement. PostToolUse is purely
/// observational -- it never blocks execution and always exits successfully.
pub fn post_tool_use() -> anyhow::Result<()> {
    // Read the hook payload from stdin (capped at 10 MB)
    let mut input = String::new();
    io::stdin()
        .take(10 * 1024 * 1024)
        .read_to_string(&mut input)?;

    let payload: serde_json::Value =
        serde_json::from_str(&input).unwrap_or_else(|_| serde_json::Value::Null);

    let hook_input = parse_post_tool_use_input(&payload);

    let agent_name = std::env::var("AEGIS_AGENT_NAME").unwrap_or_else(|_| "unknown".to_string());

    // Try to record the tool result with the daemon (best-effort).
    // Uses EvaluateToolUse for now; the lead will swap to RecordToolResult.
    let client = match std::env::var("AEGIS_SOCKET_PATH") {
        Ok(path) => DaemonClient::new(path.into()),
        Err(_) => DaemonClient::default_path(),
    };
    match client.send(&DaemonCommand::EvaluateToolUse {
        agent: agent_name,
        tool_name: hook_input.tool_name.clone(),
        tool_input: hook_input.tool_input,
    }) {
        Ok(_) => {
            eprintln!("aegis: recorded tool result: {}", hook_input.tool_name);
        }
        Err(e) => {
            // Best-effort: log but do not fail
            eprintln!(
                "aegis: could not record tool result for {}: {e}",
                hook_input.tool_name
            );
        }
    }

    // Always output success and exit 0
    let output = format_post_tool_use_response();
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

/// Handle a Claude Code `Stop` hook event (session end).
///
/// Fired when a Claude Code session terminates. Records the session end
/// event in the audit ledger via the daemon for lifecycle tracking.
/// This is purely observational -- always exits successfully.
pub fn session_end() -> anyhow::Result<()> {
    let agent_name = std::env::var("AEGIS_AGENT_NAME").unwrap_or_else(|_| "unknown".to_string());

    // Read stdin (Stop hook may or may not send a payload)
    let mut input = String::new();
    let _ = io::stdin().take(1024 * 1024).read_to_string(&mut input);

    // Notify daemon of session end (best-effort)
    let client = match std::env::var("AEGIS_SOCKET_PATH") {
        Ok(path) => DaemonClient::new(path.into()),
        Err(_) => DaemonClient::default_path(),
    };

    match client.send(&DaemonCommand::StopAgent {
        name: agent_name.clone(),
    }) {
        Ok(_) => {
            eprintln!("aegis: session end recorded for {agent_name}");
        }
        Err(e) => {
            eprintln!("aegis: could not record session end for {agent_name}: {e}");
        }
    }

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

    hooks::install_project_hooks(&base).map_err(|e| anyhow::anyhow!(e))?;

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
    fn format_deny_claude_code() {
        let output = format_deny(HookFormat::ClaudeCode, "Bash", "forbidden path");
        let hso = &output["hookSpecificOutput"];
        assert_eq!(hso["hookEventName"], "PreToolUse");
        assert_eq!(hso["permissionDecision"], "deny");
        let reason = hso["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("Bash"), "reason should mention tool name");
        assert!(
            reason.contains("forbidden path"),
            "reason should include policy reason"
        );
    }

    #[test]
    fn generate_hook_settings_structure() {
        let settings = generate_hook_settings();
        let hooks = settings.get("hooks").expect("should have hooks key");

        // PreToolUse
        let pre = hooks.get("PreToolUse").expect("should have PreToolUse");
        let pre_arr = pre.as_array().expect("PreToolUse should be array");
        assert_eq!(pre_arr.len(), 1);
        let pre_group = &pre_arr[0];
        let pre_inner = pre_group
            .get("hooks")
            .expect("matcher group should have hooks array");
        let pre_handlers = pre_inner.as_array().expect("should be array");
        assert_eq!(pre_handlers.len(), 1);
        assert_eq!(pre_handlers[0]["type"].as_str().unwrap(), "command");
        assert!(pre_handlers[0]["command"]
            .as_str()
            .unwrap()
            .contains("aegis hook pre-tool-use"));

        // PostToolUse
        let post = hooks.get("PostToolUse").expect("should have PostToolUse");
        let post_arr = post.as_array().expect("PostToolUse should be array");
        assert_eq!(post_arr.len(), 1);
        let post_group = &post_arr[0];
        let post_inner = post_group
            .get("hooks")
            .expect("matcher group should have hooks array");
        let post_handlers = post_inner.as_array().expect("should be array");
        assert_eq!(post_handlers.len(), 1);
        assert_eq!(post_handlers[0]["type"].as_str().unwrap(), "command");
        assert!(post_handlers[0]["command"]
            .as_str()
            .unwrap()
            .contains("aegis hook post-tool-use"));
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

        let content =
            std::fs::read_to_string(tmpdir.path().join(".claude").join("settings.json")).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "should not duplicate hook entry");
    }

    #[test]
    fn install_settings_preserves_existing() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let claude_dir = tmpdir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Write existing settings with some other config and a non-aegis PostToolUse hook
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
        assert_eq!(
            settings["model"].as_str().unwrap(),
            "claude-sonnet-4-5-20250929"
        );
        // PostToolUse should have existing non-aegis entry plus aegis entry
        assert_eq!(
            settings["hooks"]["PostToolUse"].as_array().unwrap().len(),
            2,
            "should have both existing and aegis PostToolUse entries"
        );
        // PreToolUse hook should be added
        assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn parse_post_tool_use_payload() {
        let payload = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "tool_output": "file1.txt\nfile2.txt"
        });
        let input = parse_post_tool_use_input(&payload);
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input["command"], "ls -la");
        assert_eq!(input._tool_output, "file1.txt\nfile2.txt");
    }

    #[test]
    fn parse_post_tool_use_missing_fields() {
        let payload = serde_json::json!({
            "hook_event_name": "PostToolUse"
        });
        let input = parse_post_tool_use_input(&payload);
        assert_eq!(input.tool_name, "unknown");
        assert_eq!(input.tool_input, serde_json::json!({}));
        assert!(input._tool_output.is_null());
    }

    #[test]
    fn format_post_tool_use_response_structure() {
        let output = format_post_tool_use_response();
        let hso = &output["hookSpecificOutput"];
        assert_eq!(hso["hookEventName"], "PostToolUse");
        // Should not contain permissionDecision (PostToolUse is observational)
        assert!(hso.get("permissionDecision").is_none());
    }
}
