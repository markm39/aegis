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
/// `.claude/settings.local.json`:
///
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

/// The hook entry that gets registered in settings files.
fn hook_entry() -> serde_json::Value {
    serde_json::json!({
        "type": "command",
        "command": "aegis hook pre-tool-use"
    })
}

/// Check if the aegis hook is already registered in a hooks array.
fn is_aegis_hook_installed(hooks_array: &[serde_json::Value]) -> bool {
    hooks_array.iter().any(|entry| {
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

    hooks_array.push(hook_entry());

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

    hooks_array.push(hook_entry());

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
        let entry = &arr[0];
        assert_eq!(entry.get("type").unwrap().as_str().unwrap(), "command");
        assert!(entry
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
        let hooks = settings.get("hooks").unwrap();
        let pre = hooks.get("PreToolUse").unwrap().as_array().unwrap();
        assert_eq!(pre.len(), 1);
        assert!(pre[0]
            .get("command")
            .unwrap()
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
        let hooks = vec![serde_json::json!({
            "type": "command",
            "command": "aegis hook pre-tool-use"
        })];
        assert!(is_aegis_hook_installed(&hooks));

        let empty: Vec<serde_json::Value> = vec![];
        assert!(!is_aegis_hook_installed(&empty));

        let other = vec![serde_json::json!({
            "type": "command",
            "command": "echo hello"
        })];
        assert!(!is_aegis_hook_installed(&other));
    }
}
