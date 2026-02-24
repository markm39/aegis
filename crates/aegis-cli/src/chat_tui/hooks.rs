//! Chat TUI lifecycle hooks.
//!
//! Fires hook events at key points in the chat TUI lifecycle. Hooks are
//! loaded from `~/.aegis/hooks/` and executed as fire-and-forget background
//! processes. This bridges the chat TUI's synchronous event loop with the
//! existing `HookRegistry` infrastructure.

use serde::Serialize;

/// Lifecycle events fired by the chat TUI.
///
/// Each event is serialized to JSON and passed to matching hook scripts
/// on stdin.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatHookEvent {
    /// Fires when a new session starts (including after /new).
    SessionStart {
        session_id: String,
    },
    /// Fires before /new clears the conversation.
    BeforeReset {
        session_id: String,
        message_count: usize,
    },
    /// Fires before a tool is executed.
    BeforeToolCall {
        tool_name: String,
        tool_input: serde_json::Value,
    },
    /// Fires after a tool executes.
    AfterToolCall {
        tool_name: String,
        result_preview: String,
    },
    /// Fires when the session ends (quit/Ctrl+C).
    SessionEnd {
        session_id: String,
        message_count: usize,
    },
}

/// Fire a hook event in a background thread (fire-and-forget).
///
/// Scans `~/.aegis/hooks/` for hook directories whose `manifest.toml`
/// matches the event's trigger type. Each matching hook is executed as a
/// subprocess with the event JSON on stdin.
///
/// This is non-blocking: the function returns immediately and hooks run
/// in the background. Errors are logged via tracing but do not propagate.
pub fn fire_hook_event(event: ChatHookEvent) {
    let event_json = match serde_json::to_string(&event) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!(error = %e, "failed to serialize hook event");
            return;
        }
    };

    let trigger = event_trigger_name(&event);

    std::thread::spawn(move || {
        let hooks_dir = aegis_control::hooks::default_hooks_dir();
        if !hooks_dir.exists() {
            return;
        }

        let entries = match std::fs::read_dir(&hooks_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let manifest_path = path.join("manifest.toml");
            if !manifest_path.exists() {
                continue;
            }
            // Quick check: does this hook's trigger match our event?
            if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                if !manifest_matches_trigger(&content, &trigger) {
                    continue;
                }
                // Find the entry point.
                let entry_point = extract_entry_point(&content, &path);
                if let Some(script) = entry_point {
                    execute_hook_script(&script, &path, &event_json);
                }
            }
        }
    });
}

/// Map a ChatHookEvent to a trigger name string for manifest matching.
fn event_trigger_name(event: &ChatHookEvent) -> String {
    match event {
        ChatHookEvent::SessionStart { .. } => "session_start".to_string(),
        ChatHookEvent::BeforeReset { .. } => "before_reset".to_string(),
        ChatHookEvent::BeforeToolCall { .. } => "pre_tool_use".to_string(),
        ChatHookEvent::AfterToolCall { .. } => "post_tool_use".to_string(),
        ChatHookEvent::SessionEnd { .. } => "on_exit".to_string(),
    }
}

/// Check if a manifest.toml's trigger field matches the given trigger name.
///
/// Does a lightweight string check rather than full TOML parsing for speed.
/// Matches both exact trigger names and custom trigger variants.
fn manifest_matches_trigger(manifest_content: &str, trigger: &str) -> bool {
    // Parse just enough of the TOML to check the trigger.
    if let Ok(value) = manifest_content.parse::<toml::Value>() {
        if let Some(t) = value.get("trigger").and_then(|v| v.as_str()) {
            return t == trigger;
        }
        // Also check for custom trigger variant: { custom = "trigger_name" }
        if let Some(table) = value.get("trigger").and_then(|v| v.as_table()) {
            if let Some(custom) = table.get("custom").and_then(|v| v.as_str()) {
                return custom == trigger;
            }
        }
    }
    false
}

/// Extract the entry point path from a manifest.toml.
fn extract_entry_point(manifest_content: &str, hook_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let value: toml::Value = manifest_content.parse().ok()?;
    let entry = value.get("entry_point")?.as_str()?;
    let full_path = hook_dir.join(entry);
    if full_path.exists() {
        Some(full_path)
    } else {
        None
    }
}

/// Execute a hook script as a subprocess with event JSON on stdin.
fn execute_hook_script(
    script_path: &std::path::Path,
    hook_dir: &std::path::Path,
    event_json: &str,
) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Determine interpreter based on file extension.
    let ext = script_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let mut cmd = match ext {
        "py" => {
            let mut c = Command::new("python3");
            c.arg(script_path);
            c
        }
        "js" | "mjs" => {
            let mut c = Command::new("node");
            c.arg(script_path);
            c
        }
        "ts" => {
            let mut c = Command::new("npx");
            c.args(["tsx", &script_path.to_string_lossy()]);
            c
        }
        "sh" | "bash" | "" => {
            let mut c = Command::new("sh");
            c.arg(script_path);
            c
        }
        _ => {
            // Try to execute directly.
            Command::new(script_path)
        }
    };

    cmd.current_dir(hook_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Set restricted environment.
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    cmd.env("AEGIS_HOOK_EVENT", event_json);

    match cmd.spawn() {
        Ok(mut child) => {
            let event_bytes = event_json.as_bytes().to_vec();
            tracing::debug!(
                script = %script_path.display(),
                "fired hook"
            );
            // Reaper thread: write stdin, then wait to prevent zombies.
            std::thread::spawn(move || {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(&event_bytes);
                    // Drop stdin so the child sees EOF.
                }
                let _ = child.wait();
            });
        }
        Err(e) => {
            tracing::debug!(
                script = %script_path.display(),
                error = %e,
                "failed to spawn hook process"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serialization() {
        let event = ChatHookEvent::SessionStart {
            session_id: "abc123".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"session_start\""));
        assert!(json.contains("\"session_id\":\"abc123\""));
    }

    #[test]
    fn event_trigger_names() {
        assert_eq!(
            event_trigger_name(&ChatHookEvent::SessionStart {
                session_id: "x".into()
            }),
            "session_start"
        );
        assert_eq!(
            event_trigger_name(&ChatHookEvent::BeforeReset {
                session_id: "x".into(),
                message_count: 5,
            }),
            "before_reset"
        );
        assert_eq!(
            event_trigger_name(&ChatHookEvent::BeforeToolCall {
                tool_name: "bash".into(),
                tool_input: serde_json::json!({}),
            }),
            "pre_tool_use"
        );
        assert_eq!(
            event_trigger_name(&ChatHookEvent::AfterToolCall {
                tool_name: "bash".into(),
                result_preview: "ok".into(),
            }),
            "post_tool_use"
        );
        assert_eq!(
            event_trigger_name(&ChatHookEvent::SessionEnd {
                session_id: "x".into(),
                message_count: 10,
            }),
            "on_exit"
        );
    }

    #[test]
    fn manifest_matching() {
        let content = r#"
name = "test-hook"
trigger = "session_start"
entry_point = "handler.sh"
"#;
        assert!(manifest_matches_trigger(content, "session_start"));
        assert!(!manifest_matches_trigger(content, "on_exit"));
    }

    #[test]
    fn manifest_matching_custom_trigger() {
        // Custom trigger in table form: trigger = { custom = "before_reset" }
        let content = r#"
name = "reset-hook"
entry_point = "handler.sh"

[trigger]
custom = "before_reset"
"#;
        assert!(manifest_matches_trigger(content, "before_reset"));
        assert!(!manifest_matches_trigger(content, "session_start"));
    }
}
