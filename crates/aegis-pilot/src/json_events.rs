//! Shared JSON event formatting and prompt detection for supervised tools.

use std::path::PathBuf;

use serde_json::Value;

use aegis_types::ActionKind;

use crate::adapter::PromptDetection;
use crate::session::ToolKind;

/// Format a single JSON event line for display.
pub fn format_json_line(tool: ToolKind, raw: &str) -> Vec<String> {
    match tool {
        ToolKind::Codex => format_codex_json_line(raw),
        ToolKind::ClaudeCode => Vec::new(),
    }
}

/// Detect a JSON approval prompt and build a `PromptDetection`.
pub fn detect_json_prompt(tool: ToolKind, raw: &str) -> Option<PromptDetection> {
    if tool != ToolKind::Codex {
        return None;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let value: Value = serde_json::from_str(trimmed).ok()?;
    if !is_approval_event(&value) {
        return None;
    }

    let action = build_action(&value);
    Some(PromptDetection {
        action,
        raw_prompt: raw.to_string(),
        approve_response: "y".into(),
        deny_response: "n".into(),
    })
}

fn is_approval_event(value: &Value) -> bool {
    let event_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
    if event_type.contains("approval") || event_type.contains("permission") || event_type.contains("confirm") {
        return true;
    }

    let requires = value.get("requires_approval")
        .or_else(|| value.get("needs_approval"))
        .or_else(|| value.get("approval_required"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if requires {
        return true;
    }

    if let Some(item) = value.get("item") {
        let requires = item.get("requires_approval")
            .or_else(|| item.get("needs_approval"))
            .or_else(|| item.get("approval_required"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if requires {
            return true;
        }
    }

    false
}

fn build_action(value: &Value) -> ActionKind {
    if let Some(cmd) = value.get("item")
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .or_else(|| value.get("command").and_then(|v| v.as_str()))
    {
        let parts: Vec<&str> = cmd.splitn(2, char::is_whitespace).collect();
        let program = parts.first().unwrap_or(&"").to_string();
        let args = parts.get(1).map(|s| vec![s.to_string()]).unwrap_or_default();
        return ActionKind::ProcessSpawn { command: program, args };
    }

    if let Some(path) = value.get("file_path").and_then(|v| v.as_str())
        .or_else(|| value.get("path").and_then(|v| v.as_str()))
        .or_else(|| value.get("item").and_then(|v| v.get("file_path")).and_then(|v| v.as_str()))
        .or_else(|| value.get("item").and_then(|v| v.get("path")).and_then(|v| v.as_str()))
    {
        return ActionKind::FileWrite { path: PathBuf::from(path) };
    }

    if let Some(tool_name) = value.get("tool_name").and_then(|v| v.as_str())
        .or_else(|| value.get("name").and_then(|v| v.as_str()))
        .or_else(|| value.get("item").and_then(|v| v.get("tool_name")).and_then(|v| v.as_str()))
        .or_else(|| value.get("item").and_then(|v| v.get("name")).and_then(|v| v.as_str()))
    {
        let args = value.get("input")
            .or_else(|| value.get("arguments"))
            .cloned()
            .unwrap_or_else(|| Value::Null);
        return ActionKind::ToolCall { tool: tool_name.to_string(), args };
    }

    ActionKind::ToolCall { tool: "codex".to_string(), args: value.clone() }
}

fn format_codex_json_line(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return vec![];
    }

    let obj: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return vec![raw.to_string()],
    };

    let event_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match event_type {
        "thread.started" => {
            let id = obj.get("thread_id").and_then(|v| v.as_str()).unwrap_or("unknown");
            vec![format!("Session started (thread_id: {id})")]
        }
        "turn.completed" => {
            let input = obj.get("usage").and_then(|u| u.get("input_tokens")).and_then(|v| v.as_u64()).unwrap_or(0);
            let output = obj.get("usage").and_then(|u| u.get("output_tokens")).and_then(|v| v.as_u64()).unwrap_or(0);
            if input > 0 || output > 0 {
                vec![format!("Done ({input}in/{output}out)")]
            } else {
                vec!["Done".to_string()]
            }
        }
        "turn.failed" | "error" => {
            let msg = obj.get("error").and_then(|v| v.get("message")).and_then(|v| v.as_str())
                .or_else(|| obj.get("message").and_then(|v| v.as_str()))
                .unwrap_or("unknown error");
            vec![format!("Error: {msg}")]
        }
        _ => {
            if let Some(item) = obj.get("item") {
                if let Some(lines) = format_item_event(item) {
                    return lines;
                }
            }
            if let Some(lines) = extract_text_lines(&obj) {
                return lines;
            }
            vec![]
        }
    }
}

fn format_item_event(item: &Value) -> Option<Vec<String>> {
    let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
    match item_type {
        "agent_message" | "reasoning" => {
            let text = item.get("text").and_then(|v| v.as_str()).unwrap_or("");
            if text.trim().is_empty() {
                None
            } else {
                Some(text.lines().map(|l| l.to_string()).collect())
            }
        }
        "command_execution" => {
            let command = item.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let status = item.get("status").and_then(|v| v.as_str()).unwrap_or("");
            if !command.is_empty() {
                if status == "completed" {
                    Some(vec![format!("> Bash: {command}")])
                } else {
                    Some(vec![format!("> Bash (running): {command}")])
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_text_lines(obj: &Value) -> Option<Vec<String>> {
    if let Some(delta) = obj.get("delta").and_then(|v| v.as_str()) {
        return Some(delta.lines().map(|l| l.to_string()).collect());
    }
    if let Some(text) = obj.get("text").and_then(|v| v.as_str()) {
        return Some(text.lines().map(|l| l.to_string()).collect());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_codex_approval_event() {
        let raw = r#"{"type":"approval.requested","command":"ls -1a"}"#;
        let detection = detect_json_prompt(ToolKind::Codex, raw).expect("expected prompt");
        match detection.action {
            ActionKind::ProcessSpawn { command, args } => {
                assert_eq!(command, "ls");
                assert_eq!(args, vec!["-1a".to_string()]);
            }
            _ => panic!("unexpected action kind"),
        }
    }

    #[test]
    fn ignore_command_execution_without_approval() {
        let raw = r#"{"type":"item.started","item":{"type":"command_execution","command":"ls"}} "#;
        assert!(detect_json_prompt(ToolKind::Codex, raw).is_none());
    }

    #[test]
    fn format_command_execution() {
        let raw = r#"{"type":"item.started","item":{"type":"command_execution","command":"ls -la","status":"running"}} "#;
        let lines = format_json_line(ToolKind::Codex, raw);
        assert_eq!(lines, vec!["> Bash (running): ls -la".to_string()]);
    }
}
