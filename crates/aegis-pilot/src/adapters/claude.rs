//! Claude Code adapter for detecting permission prompts.
//!
//! Claude Code asks for permission before executing tools like Bash, Read,
//! Write, Edit, WebFetch, etc. The prompt format is:
//!
//! ```text
//! Claude wants to use Bash
//!   Command: ls -la /tmp
//! Allow? (y/n)
//! ```
//!
//! The adapter is stateful: it accumulates lines when it sees "wants to use"
//! and completes the detection when it sees the "Allow?" prompt or the partial
//! line contains "Allow?".

use std::path::PathBuf;

use regex::Regex;

use aegis_types::ActionKind;

use crate::adapter::{AgentAdapter, PromptDetection, ScanResult};

/// States for the multi-line prompt detection state machine.
#[derive(Debug, Clone)]
enum State {
    /// Waiting for a "wants to use" trigger line.
    Idle,
    /// Accumulating tool details after seeing the trigger.
    Accumulating {
        tool: String,
        lines: Vec<String>,
    },
}

/// Adapter for Claude Code's permission prompt format.
pub struct ClaudeCodeAdapter {
    state: State,
    re_wants_to_use: Regex,
    re_command: Regex,
    re_file: Regex,
    re_url: Regex,
    re_allow: Regex,
}

impl ClaudeCodeAdapter {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            re_wants_to_use: Regex::new(r"(?i)wants?\s+to\s+use\s+(\w+)").unwrap(),
            re_command: Regex::new(r"(?i)^\s*Command:\s*(.+)$").unwrap(),
            re_file: Regex::new(r"(?i)^\s*(?:File|Path):\s*(.+)$").unwrap(),
            re_url: Regex::new(r"(?i)^\s*URL:\s*(.+)$").unwrap(),
            re_allow: Regex::new(r"(?i)Allow\?").unwrap(),
        }
    }

    /// Extract the ActionKind from accumulated prompt lines.
    fn extract_action(&self, tool: &str, lines: &[String]) -> ActionKind {
        match tool.to_lowercase().as_str() {
            "bash" => {
                let command = self.extract_field(&self.re_command, lines)
                    .unwrap_or_default();
                // Parse the command into program + args
                let parts: Vec<&str> = command.splitn(2, char::is_whitespace).collect();
                let program = parts.first().unwrap_or(&"").to_string();
                let args = parts.get(1)
                    .map(|a| vec![a.to_string()])
                    .unwrap_or_default();
                ActionKind::ProcessSpawn { command: program, args }
            }
            "read" => {
                let path = self.extract_field(&self.re_file, lines)
                    .unwrap_or_default();
                ActionKind::FileRead { path: PathBuf::from(path) }
            }
            "write" | "edit" | "notebookedit" => {
                let path = self.extract_field(&self.re_file, lines)
                    .unwrap_or_default();
                ActionKind::FileWrite { path: PathBuf::from(path) }
            }
            "webfetch" => {
                let url = self.extract_field(&self.re_url, lines)
                    .unwrap_or_default();
                ActionKind::NetRequest {
                    method: "GET".into(),
                    url,
                }
            }
            "websearch" => ActionKind::ToolCall {
                tool: "WebSearch".into(),
                args: serde_json::Value::Null,
            },
            _ => {
                // Glob, Grep, LSP, Task, etc. -- map to ToolCall
                ActionKind::ToolCall {
                    tool: tool.to_string(),
                    args: serde_json::Value::Null,
                }
            }
        }
    }

    /// Search accumulated lines for a regex match and return the first capture group.
    fn extract_field(&self, re: &Regex, lines: &[String]) -> Option<String> {
        for line in lines {
            if let Some(caps) = re.captures(line) {
                if let Some(m) = caps.get(1) {
                    return Some(m.as_str().trim().to_string());
                }
            }
        }
        None
    }

    /// Build a PromptDetection from current state.
    fn build_detection(&self, tool: &str, lines: &[String]) -> PromptDetection {
        let action = self.extract_action(tool, lines);
        let raw_prompt = lines.join("\n");
        PromptDetection {
            action,
            raw_prompt,
            approve_response: "y".into(),
            deny_response: "n".into(),
        }
    }

    /// Check if a line contains the Allow? prompt (the completion signal).
    fn is_allow_prompt(&self, text: &str) -> bool {
        self.re_allow.is_match(text)
    }
}

impl AgentAdapter for ClaudeCodeAdapter {
    fn name(&self) -> &str {
        "ClaudeCode"
    }

    fn scan_line(&mut self, line: &str) -> ScanResult {
        // Pre-compute regex matches to avoid borrow conflicts with &mut self.state
        let has_allow = self.re_allow.is_match(line);
        let tool_capture = self.re_wants_to_use.captures(line).map(|c| c[1].to_string());

        match &mut self.state {
            State::Idle => {
                if let Some(tool) = tool_capture {
                    if has_allow {
                        let detection = self.build_detection(&tool, &[line.to_string()]);
                        return ScanResult::Prompt(detection);
                    }
                    self.state = State::Accumulating {
                        tool,
                        lines: vec![line.to_string()],
                    };
                    ScanResult::Partial
                } else if has_allow {
                    // Bare "Allow?" without a preceding "wants to use" -- uncertain
                    ScanResult::Uncertain(line.to_string())
                } else {
                    ScanResult::None
                }
            }
            State::Accumulating { tool, lines } => {
                lines.push(line.to_string());

                if has_allow {
                    let tool = tool.clone();
                    let lines = lines.clone();
                    let detection = self.build_detection(&tool, &lines);
                    self.state = State::Idle;
                    ScanResult::Prompt(detection)
                } else {
                    ScanResult::Partial
                }
            }
        }
    }

    fn scan_partial(&mut self, partial: &str) -> ScanResult {
        // Claude Code often prints "Allow? (y/n)" without a trailing newline
        if self.is_allow_prompt(partial) {
            match &self.state {
                State::Accumulating { tool, lines } => {
                    let mut all_lines = lines.clone();
                    all_lines.push(partial.to_string());
                    let detection = self.build_detection(tool, &all_lines);
                    self.state = State::Idle;
                    ScanResult::Prompt(detection)
                }
                State::Idle => ScanResult::Uncertain(partial.to_string()),
            }
        } else {
            ScanResult::None
        }
    }

    fn reset(&mut self) {
        self.state = State::Idle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bash_prompt() {
        let mut adapter = ClaudeCodeAdapter::new();

        assert_eq!(adapter.scan_line("Claude wants to use Bash"), ScanResult::Partial);
        assert_eq!(adapter.scan_line("  Command: ls -la /tmp"), ScanResult::Partial);

        match adapter.scan_line("Allow? (y/n)") {
            ScanResult::Prompt(det) => {
                assert_eq!(det.approve_response, "y");
                assert_eq!(det.deny_response, "n");
                match &det.action {
                    ActionKind::ProcessSpawn { command, args } => {
                        assert_eq!(command, "ls");
                        assert_eq!(args, &vec!["-la /tmp".to_string()]);
                    }
                    other => panic!("expected ProcessSpawn, got {other:?}"),
                }
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn detects_read_prompt() {
        let mut adapter = ClaudeCodeAdapter::new();

        adapter.scan_line("Claude wants to use Read");
        adapter.scan_line("  File: /etc/passwd");

        match adapter.scan_line("Allow? (y/n)") {
            ScanResult::Prompt(det) => {
                match &det.action {
                    ActionKind::FileRead { path } => {
                        assert_eq!(path, &PathBuf::from("/etc/passwd"));
                    }
                    other => panic!("expected FileRead, got {other:?}"),
                }
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn detects_write_prompt() {
        let mut adapter = ClaudeCodeAdapter::new();

        adapter.scan_line("Claude wants to use Write");
        adapter.scan_line("  File: /tmp/output.txt");

        match adapter.scan_line("Allow? (y/n)") {
            ScanResult::Prompt(det) => {
                match &det.action {
                    ActionKind::FileWrite { path } => {
                        assert_eq!(path, &PathBuf::from("/tmp/output.txt"));
                    }
                    other => panic!("expected FileWrite, got {other:?}"),
                }
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn detects_edit_prompt() {
        let mut adapter = ClaudeCodeAdapter::new();

        adapter.scan_line("Claude wants to use Edit");
        adapter.scan_line("  File: /src/main.rs");

        match adapter.scan_line("Allow? (y/n)") {
            ScanResult::Prompt(det) => {
                assert!(matches!(det.action, ActionKind::FileWrite { .. }));
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn detects_webfetch_prompt() {
        let mut adapter = ClaudeCodeAdapter::new();

        adapter.scan_line("Claude wants to use WebFetch");
        adapter.scan_line("  URL: https://example.com/api");

        match adapter.scan_line("Allow? (y/n)") {
            ScanResult::Prompt(det) => {
                match &det.action {
                    ActionKind::NetRequest { method, url } => {
                        assert_eq!(method, "GET");
                        assert_eq!(url, "https://example.com/api");
                    }
                    other => panic!("expected NetRequest, got {other:?}"),
                }
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn detects_unknown_tool() {
        let mut adapter = ClaudeCodeAdapter::new();

        adapter.scan_line("Claude wants to use Glob");

        match adapter.scan_line("Allow? (y/n)") {
            ScanResult::Prompt(det) => {
                match &det.action {
                    ActionKind::ToolCall { tool, .. } => {
                        assert_eq!(tool, "Glob");
                    }
                    other => panic!("expected ToolCall, got {other:?}"),
                }
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn ignores_normal_output() {
        let mut adapter = ClaudeCodeAdapter::new();
        assert_eq!(adapter.scan_line("Compiling aegis-pilot v0.1.0"), ScanResult::None);
        assert_eq!(adapter.scan_line("test result: ok. 5 passed"), ScanResult::None);
        assert_eq!(adapter.scan_line(""), ScanResult::None);
    }

    #[test]
    fn partial_line_detection() {
        let mut adapter = ClaudeCodeAdapter::new();

        adapter.scan_line("Claude wants to use Bash");
        adapter.scan_line("  Command: echo hello");

        // The Allow prompt comes as a partial (no trailing newline)
        match adapter.scan_partial("Allow? (y/n) ") {
            ScanResult::Prompt(det) => {
                assert!(matches!(det.action, ActionKind::ProcessSpawn { .. }));
            }
            other => panic!("expected Prompt from partial, got {other:?}"),
        }
    }

    #[test]
    fn reset_clears_state() {
        let mut adapter = ClaudeCodeAdapter::new();

        adapter.scan_line("Claude wants to use Bash");
        adapter.reset();

        // After reset, should not detect a prompt
        assert_eq!(adapter.scan_line("Allow? (y/n)"), ScanResult::Uncertain("Allow? (y/n)".into()));
    }

    #[test]
    fn bare_allow_returns_uncertain() {
        let mut adapter = ClaudeCodeAdapter::new();
        match adapter.scan_line("Allow? (y/n)") {
            ScanResult::Uncertain(_) => {}
            other => panic!("expected Uncertain, got {other:?}"),
        }
    }

    #[test]
    fn case_insensitive_trigger() {
        let mut adapter = ClaudeCodeAdapter::new();
        // Should still detect even with different casing
        assert_eq!(adapter.scan_line("claude Wants To Use bash"), ScanResult::Partial);
    }
}
