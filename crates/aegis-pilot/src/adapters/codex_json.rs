//! Codex JSON adapter for detecting approval prompts from JSONL events.

use std::path::PathBuf;

use serde_json::Value;

use aegis_types::ActionKind;

use crate::adapter::{AgentAdapter, PromptDetection, ScanResult};

/// Adapter for Codex JSONL events.
pub struct CodexJsonAdapter;

impl CodexJsonAdapter {
    pub fn new() -> Self {
        Self
    }

    fn is_approval_event(&self, value: &Value) -> bool {
        let t = value.get("type").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        if t.contains("approval") || t.contains("permission") || t.contains("confirm") {
            return true;
        }
        value.get("requires_approval").and_then(|v| v.as_bool()).unwrap_or(false)
            || value.get("needs_approval").and_then(|v| v.as_bool()).unwrap_or(false)
    }

    fn build_action(&self, value: &Value) -> ActionKind {
        if let Some(cmd) = value.get("command").and_then(|v| v.as_str()) {
            let parts: Vec<&str> = cmd.splitn(2, char::is_whitespace).collect();
            let program = parts.first().unwrap_or(&"").to_string();
            let args = parts.get(1).map(|s| vec![s.to_string()]).unwrap_or_default();
            return ActionKind::ProcessSpawn { command: program, args };
        }
        if let Some(path) = value.get("file_path").and_then(|v| v.as_str())
            .or_else(|| value.get("path").and_then(|v| v.as_str()))
        {
            return ActionKind::FileWrite { path: PathBuf::from(path) };
        }
        if let Some(tool_name) = value.get("tool_name").and_then(|v| v.as_str())
            .or_else(|| value.get("name").and_then(|v| v.as_str()))
        {
            let args = value.get("input")
                .or_else(|| value.get("arguments"))
                .cloned()
                .unwrap_or_else(|| Value::Null);
            return ActionKind::ToolCall { tool: tool_name.to_string(), args };
        }
        ActionKind::ToolCall { tool: "codex".to_string(), args: value.clone() }
    }
}

impl Default for CodexJsonAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentAdapter for CodexJsonAdapter {
    fn name(&self) -> &str {
        "CodexJson"
    }

    fn scan_line(&mut self, line: &str) -> ScanResult {
        let value: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return ScanResult::None,
        };

        if !self.is_approval_event(&value) {
            return ScanResult::None;
        }

        let action = self.build_action(&value);
        let detection = PromptDetection {
            action,
            raw_prompt: line.to_string(),
            approve_response: "y".into(),
            deny_response: "n".into(),
        };

        ScanResult::Prompt(detection)
    }

    fn scan_partial(&mut self, partial: &str) -> ScanResult {
        self.scan_line(partial)
    }

    fn reset(&mut self) {}
}
