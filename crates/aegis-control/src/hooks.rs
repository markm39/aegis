//! Shared hook settings for Claude Code integration.
//!
//! Claude Code's `PreToolUse` and `PostToolUse` hooks let Aegis intercept tool
//! calls at two lifecycle points:
//! - **PreToolUse**: evaluates each tool call against Cedar policy before execution
//! - **PostToolUse**: observes tool results after execution for audit/telemetry
//!
//! These functions generate and install the hook configuration that registers
//! `aegis hook pre-tool-use` and `aegis hook post-tool-use` as hook handlers.
//!
//! Two install targets:
//! - `.claude/settings.json` -- project-level, committed to VCS (manual install via CLI)
//! - `.claude/settings.local.json` -- local override, not committed (daemon-managed)

use std::path::{Path, PathBuf};

/// Generate the Claude Code settings JSON fragment that registers aegis hooks.
///
/// Returns a JSON object suitable for merging into `.claude/settings.json` or
/// `.claude/settings.local.json`. Both `PreToolUse` and `PostToolUse` arrays
/// contain matcher groups, each with an inner `hooks` array of handlers --
/// this is the three-level nesting that Claude Code requires
/// (event -> matcher group -> handler).
///
/// ```json
/// {
///   "hooks": {
///     "PreToolUse": [
///       { "hooks": [{ "type": "command", "command": "aegis hook pre-tool-use" }] }
///     ],
///     "PostToolUse": [
///       { "hooks": [{ "type": "command", "command": "aegis hook post-tool-use" }] }
///     ]
///   }
/// }
/// ```
pub fn generate_hook_settings() -> serde_json::Value {
    serde_json::json!({
        "hooks": {
            "PreToolUse": [
                pre_tool_use_matcher_group()
            ],
            "PostToolUse": [
                post_tool_use_matcher_group()
            ]
        }
    })
}

/// A matcher group entry for the PreToolUse array.
///
/// No `matcher` field means "match all tools." The inner `hooks` array
/// contains one handler that calls `aegis hook pre-tool-use`.
fn pre_tool_use_matcher_group() -> serde_json::Value {
    serde_json::json!({
        "hooks": [
            {
                "type": "command",
                "command": "aegis hook pre-tool-use"
            }
        ]
    })
}

/// A matcher group entry for the PostToolUse array.
///
/// No `matcher` field means "match all tools." The inner `hooks` array
/// contains one handler that calls `aegis hook post-tool-use`.
pub fn post_tool_use_matcher_group() -> serde_json::Value {
    serde_json::json!({
        "hooks": [
            {
                "type": "command",
                "command": "aegis hook post-tool-use"
            }
        ]
    })
}

/// Check if the aegis hook is already registered in a PreToolUse array.
///
/// Handles both the correct nested format (matcher groups with inner `hooks`)
/// and the legacy flat format (bare handler objects) for robustness.
fn is_aegis_hook_installed(pre_tool_use_array: &[serde_json::Value]) -> bool {
    pre_tool_use_array.iter().any(|entry| {
        // Check nested format: entry.hooks[].command
        if let Some(inner_hooks) = entry.get("hooks").and_then(|v| v.as_array()) {
            return inner_hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|v| v.as_str())
                    .is_some_and(|cmd| cmd.contains("aegis hook"))
            });
        }
        // Check legacy flat format: entry.command
        entry
            .get("command")
            .and_then(|v| v.as_str())
            .is_some_and(|cmd| cmd.contains("aegis hook"))
    })
}

/// Install hook settings for a daemon-managed agent.
///
/// Writes to `.claude/settings.local.json` in the given working directory.
/// This file is a local override that is not committed to version control,
/// making it safe for the daemon to own without affecting project settings.
///
/// The function is idempotent: if the aegis hook is already registered, it
/// does nothing. Existing settings keys (model, other hooks) are preserved.
pub fn install_daemon_hooks(working_dir: &Path) -> Result<(), String> {
    let claude_dir = working_dir.join(".claude");
    std::fs::create_dir_all(&claude_dir)
        .map_err(|e| format!("failed to create .claude directory: {e}"))?;

    let settings_path = claude_dir.join("settings.local.json");

    // Load existing settings or start fresh
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("failed to read {}: {e}", settings_path.display()))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("invalid JSON in {}: {e}", settings_path.display()))?
    } else {
        serde_json::json!({})
    };

    // Ensure settings is an object
    let obj = settings
        .as_object_mut()
        .ok_or_else(|| "settings.local.json is not a JSON object".to_string())?;

    // Navigate to hooks object, creating intermediate keys as needed
    let hooks = obj.entry("hooks").or_insert(serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| "hooks is not a JSON object".to_string())?;

    let mut changed = false;

    // Install PreToolUse hook
    {
        let pre_tool_use = hooks_obj
            .entry("PreToolUse")
            .or_insert(serde_json::json!([]));
        let pre_array = pre_tool_use
            .as_array_mut()
            .ok_or_else(|| "PreToolUse is not an array".to_string())?;
        if !is_aegis_hook_installed(pre_array) {
            pre_array.push(pre_tool_use_matcher_group());
            changed = true;
        }
    }

    // Install PostToolUse hook
    {
        let post_tool_use = hooks_obj
            .entry("PostToolUse")
            .or_insert(serde_json::json!([]));
        let post_array = post_tool_use
            .as_array_mut()
            .ok_or_else(|| "PostToolUse is not an array".to_string())?;
        if !is_aegis_hook_installed(post_array) {
            post_array.push(post_tool_use_matcher_group());
            changed = true;
        }
    }

    if !changed {
        return Ok(());
    }

    // Write back
    let output = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("failed to serialize settings: {e}"))?;
    std::fs::write(&settings_path, output)
        .map_err(|e| format!("failed to write {}: {e}", settings_path.display()))?;

    Ok(())
}

/// Install hook settings into a project's `.claude/settings.json`.
///
/// Unlike `install_daemon_hooks` (which targets `settings.local.json`),
/// this targets the project-level settings file that may be committed to
/// version control. Used by the `aegis hook install` CLI command.
///
/// The function is idempotent and preserves existing settings.
pub fn install_project_hooks(project_dir: &Path) -> Result<(), String> {
    let claude_dir = project_dir.join(".claude");
    std::fs::create_dir_all(&claude_dir)
        .map_err(|e| format!("failed to create .claude directory: {e}"))?;

    let settings_path = claude_dir.join("settings.json");

    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("failed to read {}: {e}", settings_path.display()))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("invalid JSON in {}: {e}", settings_path.display()))?
    } else {
        serde_json::json!({})
    };

    let obj = settings
        .as_object_mut()
        .ok_or_else(|| "settings.json is not a JSON object".to_string())?;

    let hooks = obj.entry("hooks").or_insert(serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| "hooks is not a JSON object".to_string())?;

    let mut changed = false;

    // Install PreToolUse hook
    {
        let pre_tool_use = hooks_obj
            .entry("PreToolUse")
            .or_insert(serde_json::json!([]));
        let pre_array = pre_tool_use
            .as_array_mut()
            .ok_or_else(|| "PreToolUse is not an array".to_string())?;
        if !is_aegis_hook_installed(pre_array) {
            pre_array.push(pre_tool_use_matcher_group());
            changed = true;
        }
    }

    // Install PostToolUse hook
    {
        let post_tool_use = hooks_obj
            .entry("PostToolUse")
            .or_insert(serde_json::json!([]));
        let post_array = post_tool_use
            .as_array_mut()
            .ok_or_else(|| "PostToolUse is not an array".to_string())?;
        if !is_aegis_hook_installed(post_array) {
            post_array.push(post_tool_use_matcher_group());
            changed = true;
        }
    }

    if !changed {
        return Ok(());
    }

    let output = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("failed to serialize settings: {e}"))?;
    std::fs::write(&settings_path, output)
        .map_err(|e| format!("failed to write {}: {e}", settings_path.display()))?;

    Ok(())
}

/// Current schema version for daemon-managed OpenClaw bridge metadata.
pub const OPENCLAW_BRIDGE_VERSION: u32 = 1;

/// Path to daemon-managed OpenClaw bridge marker JSON.
pub fn openclaw_bridge_marker_path(working_dir: &Path) -> PathBuf {
    working_dir
        .join(".aegis")
        .join("openclaw")
        .join("bridge.json")
}

/// Path to daemon-managed OpenClaw config JSON.
pub fn openclaw_bridge_config_path(working_dir: &Path) -> PathBuf {
    working_dir
        .join(".aegis")
        .join("openclaw")
        .join("openclaw.json")
}

/// Return true when the daemon-managed OpenClaw bridge marker is present and valid.
pub fn openclaw_bridge_connected(working_dir: &Path) -> bool {
    let marker_path = openclaw_bridge_marker_path(working_dir);
    let Ok(raw) = std::fs::read_to_string(marker_path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let connected = value
        .get("connected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    version == OPENCLAW_BRIDGE_VERSION as u64 && connected
}

/// Return true when daemon-managed OpenClaw bridge artifacts are present.
pub fn openclaw_bridge_installed(working_dir: &Path) -> bool {
    let marker_path = openclaw_bridge_marker_path(working_dir);
    let config_path = openclaw_bridge_config_path(working_dir);
    let hook_md = working_dir
        .join("hooks")
        .join("aegis-policy-gate")
        .join("HOOK.md");
    let hook_handler = working_dir
        .join("hooks")
        .join("aegis-policy-gate")
        .join("handler.ts");
    marker_path.exists() && config_path.exists() && hook_md.exists() && hook_handler.exists()
}

/// Install a daemon-managed OpenClaw bridge bundle for strict policy mediation.
///
/// This creates:
/// - workspace hook metadata/handler under `hooks/aegis-policy-gate/`
/// - a daemon-owned OpenClaw config at `.aegis/openclaw/openclaw.json`
/// - a bridge marker file at `.aegis/openclaw/bridge.json`
pub fn install_openclaw_daemon_bridge(working_dir: &Path, agent_name: &str) -> Result<(), String> {
    let hook_dir = working_dir.join("hooks").join("aegis-policy-gate");
    std::fs::create_dir_all(&hook_dir)
        .map_err(|e| format!("failed to create OpenClaw hook dir: {e}"))?;

    let hook_md = hook_dir.join("HOOK.md");
    let hook_md_body = r#"---
name: aegis-policy-gate
description: "Aegis daemon policy bridge for OpenClaw"
metadata: { "openclaw": { "events": ["command:new", "gateway:startup"] } }
---

# Aegis Policy Gate

Managed by Aegis daemon. Do not edit manually.
"#;
    std::fs::write(&hook_md, hook_md_body)
        .map_err(|e| format!("failed to write {}: {e}", hook_md.display()))?;

    let hook_handler = hook_dir.join("handler.ts");
    let hook_handler_body = r#"const handler = async (event) => {
  if (!event || typeof event !== "object") {
    return;
  }
  const marker = process.env.AEGIS_OPENCLAW_BRIDGE_MARKER;
  if (!marker) {
    return;
  }
  try {
    const fs = await import("node:fs/promises");
    const payload = JSON.stringify(
      {
        version: 1,
        connected: true,
        updated_at_utc: new Date().toISOString(),
      },
      null,
      2,
    );
    await fs.writeFile(marker, payload, "utf8");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[aegis-policy-gate] marker update failed: ${msg}`);
  }
};

export default handler;
"#;
    std::fs::write(&hook_handler, hook_handler_body)
        .map_err(|e| format!("failed to write {}: {e}", hook_handler.display()))?;

    let bridge_dir = working_dir.join(".aegis").join("openclaw");
    std::fs::create_dir_all(&bridge_dir)
        .map_err(|e| format!("failed to create OpenClaw bridge dir: {e}"))?;

    let marker_path = openclaw_bridge_marker_path(working_dir);
    let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");
    let marker = serde_json::json!({
        "version": OPENCLAW_BRIDGE_VERSION,
        "connected": false,
        "installed": true,
        "agent": agent_name,
        "socket_path": socket_path.to_string_lossy(),
        "installed_at_utc": chrono::Utc::now().to_rfc3339(),
    });
    let marker_json = serde_json::to_string_pretty(&marker)
        .map_err(|e| format!("failed to serialize OpenClaw bridge marker: {e}"))?;
    std::fs::write(&marker_path, marker_json)
        .map_err(|e| format!("failed to write {}: {e}", marker_path.display()))?;

    let config_path = openclaw_bridge_config_path(working_dir);
    let config = serde_json::json!({
        "hooks": {
            "internal": {
                "enabled": true,
                "entries": {
                    "aegis-policy-gate": {
                        "enabled": true,
                        "env": {
                            "AEGIS_AGENT_NAME": agent_name,
                            "AEGIS_SOCKET_PATH": socket_path.to_string_lossy(),
                            "AEGIS_OPENCLAW_BRIDGE_MARKER": marker_path.to_string_lossy(),
                            "AEGIS_OPENCLAW_BRIDGE_REQUIRED": "1"
                        }
                    }
                }
            }
        }
    });
    let config_json = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("failed to serialize OpenClaw bridge config: {e}"))?;
    std::fs::write(&config_path, config_json)
        .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_hook_settings_structure() {
        let settings = generate_hook_settings();
        let hooks = settings.get("hooks").expect("should have hooks key");

        // Verify PreToolUse
        let pre = hooks.get("PreToolUse").expect("should have PreToolUse");
        let pre_arr = pre.as_array().expect("PreToolUse should be array");
        assert_eq!(pre_arr.len(), 1);
        let pre_group = &pre_arr[0];
        let pre_inner = pre_group
            .get("hooks")
            .expect("matcher group should have hooks array");
        let pre_handlers = pre_inner.as_array().expect("hooks should be array");
        assert_eq!(pre_handlers.len(), 1);
        assert_eq!(
            pre_handlers[0].get("type").unwrap().as_str().unwrap(),
            "command"
        );
        assert!(pre_handlers[0]
            .get("command")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("aegis hook pre-tool-use"));

        // Verify PostToolUse
        let post = hooks.get("PostToolUse").expect("should have PostToolUse");
        let post_arr = post.as_array().expect("PostToolUse should be array");
        assert_eq!(post_arr.len(), 1);
        let post_group = &post_arr[0];
        let post_inner = post_group
            .get("hooks")
            .expect("matcher group should have hooks array");
        let post_handlers = post_inner.as_array().expect("hooks should be array");
        assert_eq!(post_handlers.len(), 1);
        assert_eq!(
            post_handlers[0].get("type").unwrap().as_str().unwrap(),
            "command"
        );
        assert!(post_handlers[0]
            .get("command")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("aegis hook post-tool-use"));
    }

    #[test]
    fn install_daemon_hooks_creates_file() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_daemon_hooks(tmpdir.path()).expect("should install");

        let settings_path = tmpdir.path().join(".claude").join("settings.local.json");
        assert!(settings_path.exists());

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

        // PreToolUse installed
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        let pre_handlers = pre[0]["hooks"].as_array().unwrap();
        assert_eq!(pre_handlers.len(), 1);
        assert!(pre_handlers[0]["command"]
            .as_str()
            .unwrap()
            .contains("aegis hook pre-tool-use"));

        // PostToolUse installed
        let post = settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 1);
        let post_handlers = post[0]["hooks"].as_array().unwrap();
        assert_eq!(post_handlers.len(), 1);
        assert!(post_handlers[0]["command"]
            .as_str()
            .unwrap()
            .contains("aegis hook post-tool-use"));
    }

    #[test]
    fn install_daemon_hooks_idempotent() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_daemon_hooks(tmpdir.path()).expect("first install");
        install_daemon_hooks(tmpdir.path()).expect("second install");

        let content =
            std::fs::read_to_string(tmpdir.path().join(".claude").join("settings.local.json"))
                .unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "should not duplicate PreToolUse hook entry");
        let post = settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 1, "should not duplicate PostToolUse hook entry");
    }

    #[test]
    fn install_daemon_hooks_preserves_existing() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let claude_dir = tmpdir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Write existing settings with other config and a non-aegis PostToolUse hook
        let existing = serde_json::json!({
            "model": "claude-sonnet-4-5-20250929",
            "hooks": {
                "PostToolUse": [
                    {"type": "command", "command": "echo done"}
                ]
            }
        });
        std::fs::write(
            claude_dir.join("settings.local.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        install_daemon_hooks(tmpdir.path()).expect("should install");

        let content = std::fs::read_to_string(claude_dir.join("settings.local.json")).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Model should be preserved
        assert_eq!(
            settings["model"].as_str().unwrap(),
            "claude-sonnet-4-5-20250929"
        );
        // PostToolUse should have the existing non-aegis entry plus the new aegis entry
        assert_eq!(
            settings["hooks"]["PostToolUse"].as_array().unwrap().len(),
            2,
            "should have both existing and aegis PostToolUse entries"
        );
        // PreToolUse hook should be added
        assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn install_project_hooks_creates_file() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_project_hooks(tmpdir.path()).expect("should install");

        let settings_path = tmpdir.path().join(".claude").join("settings.json");
        assert!(settings_path.exists());

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        let post = settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 1);
    }

    #[test]
    fn install_project_hooks_idempotent() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_project_hooks(tmpdir.path()).expect("first install");
        install_project_hooks(tmpdir.path()).expect("second install");

        let content =
            std::fs::read_to_string(tmpdir.path().join(".claude").join("settings.json")).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "should not duplicate PreToolUse hook entry");
        let post = settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 1, "should not duplicate PostToolUse hook entry");
    }

    #[test]
    fn is_aegis_hook_installed_detection() {
        // Nested format (correct)
        let hooks = vec![serde_json::json!({
            "hooks": [{
                "type": "command",
                "command": "aegis hook pre-tool-use"
            }]
        })];
        assert!(is_aegis_hook_installed(&hooks));

        // Legacy flat format (still detected for robustness)
        let flat = vec![serde_json::json!({
            "type": "command",
            "command": "aegis hook pre-tool-use"
        })];
        assert!(is_aegis_hook_installed(&flat));

        let empty: Vec<serde_json::Value> = vec![];
        assert!(!is_aegis_hook_installed(&empty));

        let other = vec![serde_json::json!({
            "hooks": [{
                "type": "command",
                "command": "echo hello"
            }]
        })];
        assert!(!is_aegis_hook_installed(&other));
    }

    #[test]
    fn openclaw_bridge_connected_false_when_missing() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        assert!(!openclaw_bridge_connected(tmpdir.path()));
    }

    #[test]
    fn install_openclaw_daemon_bridge_creates_bundle() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_openclaw_daemon_bridge(tmpdir.path(), "openclaw-1").expect("install bridge");

        let marker = openclaw_bridge_marker_path(tmpdir.path());
        let config = openclaw_bridge_config_path(tmpdir.path());
        let hook_md = tmpdir
            .path()
            .join("hooks")
            .join("aegis-policy-gate")
            .join("HOOK.md");
        let hook_handler = tmpdir
            .path()
            .join("hooks")
            .join("aegis-policy-gate")
            .join("handler.ts");

        assert!(marker.exists(), "marker should exist");
        assert!(config.exists(), "bridge config should exist");
        assert!(hook_md.exists(), "hook metadata should exist");
        assert!(hook_handler.exists(), "hook handler should exist");
        assert!(openclaw_bridge_installed(tmpdir.path()));
        assert!(!openclaw_bridge_connected(tmpdir.path()));

        let config_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(config).unwrap()).unwrap();
        assert_eq!(
            config_json["hooks"]["internal"]["enabled"].as_bool(),
            Some(true)
        );
        assert_eq!(
            config_json["hooks"]["internal"]["entries"]["aegis-policy-gate"]["enabled"]
                .as_bool(),
            Some(true)
        );
    }
}
