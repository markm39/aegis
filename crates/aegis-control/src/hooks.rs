//! Shared hook settings for Claude Code integration.
//!
//! Claude Code's `PreToolUse` hooks let Aegis intercept every tool call and
//! evaluate it against Cedar policy before execution. These functions generate
//! and install the hook configuration that registers `aegis hook pre-tool-use`
//! as the policy enforcement point.
//!
//! Two install targets:
//! - `.claude/settings.json` -- project-level, committed to VCS (manual install via CLI)
//! - `.claude/settings.local.json` -- local override, not committed (daemon-managed)

use std::path::Path;

/// Generate the Claude Code settings JSON fragment that registers the aegis hook.
///
/// Returns a JSON object suitable for merging into `.claude/settings.json` or
/// `.claude/settings.local.json`. The `PreToolUse` array contains matcher groups,
/// each with an inner `hooks` array of handlers -- this is the three-level
/// nesting that Claude Code requires (event -> matcher group -> handler).
///
/// ```json
/// {
///   "hooks": {
///     "PreToolUse": [
///       {
///         "hooks": [
///           { "type": "command", "command": "aegis hook pre-tool-use" }
///         ]
///       }
///     ]
///   }
/// }
/// ```
pub fn generate_hook_settings() -> serde_json::Value {
    serde_json::json!({
        "hooks": {
            "PreToolUse": [
                matcher_group()
            ]
        }
    })
}

/// A matcher group entry for the PreToolUse array.
///
/// No `matcher` field means "match all tools." The inner `hooks` array
/// contains one handler that calls `aegis hook pre-tool-use`.
fn matcher_group() -> serde_json::Value {
    serde_json::json!({
        "hooks": [
            {
                "type": "command",
                "command": "aegis hook pre-tool-use"
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
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Ensure settings is an object
    let obj = settings
        .as_object_mut()
        .ok_or_else(|| "settings.local.json is not a JSON object".to_string())?;

    // Navigate to hooks.PreToolUse, creating intermediate keys as needed
    let hooks = obj
        .entry("hooks")
        .or_insert(serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| "hooks is not a JSON object".to_string())?;

    let pre_tool_use = hooks_obj
        .entry("PreToolUse")
        .or_insert(serde_json::json!([]));

    let hooks_array = pre_tool_use
        .as_array_mut()
        .ok_or_else(|| "PreToolUse is not an array".to_string())?;

    // Skip if already installed
    if is_aegis_hook_installed(hooks_array) {
        return Ok(());
    }

    hooks_array.push(matcher_group());

    // Write back
    let output = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("failed to serialize settings: {e}"))?;
    std::fs::write(&settings_path, output)
        .map_err(|e| format!("failed to write {}: {e}", settings_path.display()))?;

    Ok(())
}

/// The Cursor hook events that Aegis intercepts.
const CURSOR_HOOK_EVENTS: &[&str] = &[
    "beforeShellExecution",
    "beforeReadFile",
    "beforeMCPExecution",
];

/// Generate the Cursor hooks JSON config that registers the aegis hook.
fn cursor_hook_entry() -> serde_json::Value {
    serde_json::json!({
        "command": "aegis hook pre-tool-use"
    })
}

/// Check if the aegis hook is already registered in a Cursor hooks array.
///
/// Cursor hook entries use `{"command": "..."}` (no `type` field).
fn is_aegis_cursor_hook_installed(hooks_array: &[serde_json::Value]) -> bool {
    hooks_array.iter().any(|entry| {
        entry
            .get("command")
            .and_then(|v| v.as_str())
            .is_some_and(|cmd| cmd.contains("aegis hook"))
    })
}

/// Install hook settings for a daemon-managed Cursor agent.
///
/// Writes to `.cursor/hooks.json` in the given working directory. Cursor
/// uses per-event hook arrays (`beforeShellExecution`, `beforeReadFile`,
/// `beforeMCPExecution`) rather than Claude Code's unified `PreToolUse`.
///
/// The function is idempotent: if the aegis hook is already registered in
/// each event array, it does nothing. Existing hooks are preserved.
pub fn install_cursor_hooks(working_dir: &Path) -> Result<(), String> {
    let cursor_dir = working_dir.join(".cursor");
    std::fs::create_dir_all(&cursor_dir)
        .map_err(|e| format!("failed to create .cursor directory: {e}"))?;

    let hooks_path = cursor_dir.join("hooks.json");

    // Load existing hooks or start fresh
    let mut config: serde_json::Value = if hooks_path.exists() {
        let content = std::fs::read_to_string(&hooks_path)
            .map_err(|e| format!("failed to read {}: {e}", hooks_path.display()))?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let obj = config
        .as_object_mut()
        .ok_or_else(|| "hooks.json is not a JSON object".to_string())?;

    // Ensure version field exists
    obj.entry("version")
        .or_insert(serde_json::json!(1));

    // Navigate to hooks object
    let hooks = obj
        .entry("hooks")
        .or_insert(serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| "hooks is not a JSON object".to_string())?;

    // Register aegis hook in each Cursor event array
    for event_name in CURSOR_HOOK_EVENTS {
        let event_hooks = hooks_obj
            .entry(*event_name)
            .or_insert(serde_json::json!([]));

        let event_array = event_hooks
            .as_array_mut()
            .ok_or_else(|| format!("{event_name} is not an array"))?;

        if !is_aegis_cursor_hook_installed(event_array) {
            event_array.push(cursor_hook_entry());
        }
    }

    // Write back
    let output = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("failed to serialize hooks: {e}"))?;
    std::fs::write(&hooks_path, output)
        .map_err(|e| format!("failed to write {}: {e}", hooks_path.display()))?;

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
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let obj = settings
        .as_object_mut()
        .ok_or_else(|| "settings.json is not a JSON object".to_string())?;

    let hooks = obj
        .entry("hooks")
        .or_insert(serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| "hooks is not a JSON object".to_string())?;

    let pre_tool_use = hooks_obj
        .entry("PreToolUse")
        .or_insert(serde_json::json!([]));

    let hooks_array = pre_tool_use
        .as_array_mut()
        .ok_or_else(|| "PreToolUse is not an array".to_string())?;

    if is_aegis_hook_installed(hooks_array) {
        return Ok(());
    }

    hooks_array.push(matcher_group());

    let output = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("failed to serialize settings: {e}"))?;
    std::fs::write(&settings_path, output)
        .map_err(|e| format!("failed to write {}: {e}", settings_path.display()))?;

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
        // Each entry is a matcher group with inner "hooks" array
        let group = &arr[0];
        let inner = group.get("hooks").expect("matcher group should have hooks array");
        let handlers = inner.as_array().expect("hooks should be array");
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].get("type").unwrap().as_str().unwrap(), "command");
        assert!(handlers[0]
            .get("command")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("aegis hook"));
    }

    #[test]
    fn install_daemon_hooks_creates_file() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_daemon_hooks(tmpdir.path()).expect("should install");

        let settings_path = tmpdir.path().join(".claude").join("settings.local.json");
        assert!(settings_path.exists());

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        // Nested: matcher group -> hooks array -> handler
        let handlers = pre[0]["hooks"].as_array().unwrap();
        assert_eq!(handlers.len(), 1);
        assert!(handlers[0]["command"]
            .as_str()
            .unwrap()
            .contains("aegis hook"));
    }

    #[test]
    fn install_daemon_hooks_idempotent() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_daemon_hooks(tmpdir.path()).expect("first install");
        install_daemon_hooks(tmpdir.path()).expect("second install");

        let content = std::fs::read_to_string(
            tmpdir.path().join(".claude").join("settings.local.json"),
        )
        .unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "should not duplicate hook entry");
    }

    #[test]
    fn install_daemon_hooks_preserves_existing() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let claude_dir = tmpdir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Write existing settings with other config
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

        let content =
            std::fs::read_to_string(claude_dir.join("settings.local.json")).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Model should be preserved
        assert_eq!(
            settings["model"].as_str().unwrap(),
            "claude-sonnet-4-5-20250929"
        );
        // PostToolUse hook should be preserved
        assert_eq!(
            settings["hooks"]["PostToolUse"].as_array().unwrap().len(),
            1
        );
        // PreToolUse hook should be added
        assert_eq!(
            settings["hooks"]["PreToolUse"].as_array().unwrap().len(),
            1
        );
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
    }

    #[test]
    fn install_project_hooks_idempotent() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_project_hooks(tmpdir.path()).expect("first install");
        install_project_hooks(tmpdir.path()).expect("second install");

        let content = std::fs::read_to_string(
            tmpdir.path().join(".claude").join("settings.json"),
        )
        .unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "should not duplicate hook entry");
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

    // ── Cursor hook tests ──────────────────────────────────────────────

    #[test]
    fn install_cursor_hooks_creates_file() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_cursor_hooks(tmpdir.path()).expect("should install");

        let hooks_path = tmpdir.path().join(".cursor").join("hooks.json");
        assert!(hooks_path.exists());

        let content = std::fs::read_to_string(&hooks_path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(config["version"], 1);

        for event in CURSOR_HOOK_EVENTS {
            let arr = config["hooks"][event].as_array()
                .unwrap_or_else(|| panic!("{event} should be an array"));
            assert_eq!(arr.len(), 1, "{event} should have one hook");
            assert!(arr[0]["command"].as_str().unwrap().contains("aegis hook"));
        }
    }

    #[test]
    fn install_cursor_hooks_idempotent() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_cursor_hooks(tmpdir.path()).expect("first install");
        install_cursor_hooks(tmpdir.path()).expect("second install");

        let content = std::fs::read_to_string(
            tmpdir.path().join(".cursor").join("hooks.json"),
        )
        .unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();

        for event in CURSOR_HOOK_EVENTS {
            let arr = config["hooks"][event].as_array().unwrap();
            assert_eq!(arr.len(), 1, "{event} should not have duplicate hooks");
        }
    }

    #[test]
    fn install_cursor_hooks_preserves_existing() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let cursor_dir = tmpdir.path().join(".cursor");
        std::fs::create_dir_all(&cursor_dir).unwrap();

        // Write existing hooks with some other config
        let existing = serde_json::json!({
            "version": 1,
            "hooks": {
                "afterFileEdit": [
                    {"command": "echo edited"}
                ]
            }
        });
        std::fs::write(
            cursor_dir.join("hooks.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        install_cursor_hooks(tmpdir.path()).expect("should install");

        let content =
            std::fs::read_to_string(cursor_dir.join("hooks.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Existing afterFileEdit hook should be preserved
        assert_eq!(
            config["hooks"]["afterFileEdit"].as_array().unwrap().len(),
            1
        );
        // Aegis hooks should be added to all three events
        for event in CURSOR_HOOK_EVENTS {
            assert_eq!(
                config["hooks"][event].as_array().unwrap().len(),
                1,
                "{event} should have aegis hook"
            );
        }
    }

    #[test]
    fn is_aegis_cursor_hook_installed_detection() {
        let hooks = vec![serde_json::json!({
            "command": "aegis hook pre-tool-use"
        })];
        assert!(is_aegis_cursor_hook_installed(&hooks));

        let empty: Vec<serde_json::Value> = vec![];
        assert!(!is_aegis_cursor_hook_installed(&empty));

        let other = vec![serde_json::json!({
            "command": "echo hello"
        })];
        assert!(!is_aegis_cursor_hook_installed(&other));
    }
}
