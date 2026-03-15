//! Codex adapter for detecting permission prompts.
//!
//! Codex CLI proposes shell commands and file edits, then asks for approval.
//! In interactive mode, it displays blocks like:
//!
//! ```text
//! Shell command:
//!   $ npm install express
//!
//! Do you want to proceed? [y/n]
//! ```
//!
//! Or file edits:
//!
//! ```text
//! File edit:
//!   src/main.rs
//!   + fn new_function() {
//!   +     // ...
//!   + }
//!
//! Do you want to proceed? [y/n]
//! ```
//!
//! The adapter is stateful: it accumulates lines after seeing a trigger
//! ("Shell command:" or "File edit:") and completes on the approval prompt.

use std::path::PathBuf;

use regex::Regex;

use aegis_types::ActionKind;

use crate::adapter::{AgentAdapter, PromptDetection, ScanResult};

/// States for the Codex multi-line prompt detection state machine.
#[derive(Debug, Clone)]
enum State {
    /// Waiting for a trigger line.
    Idle,
    /// Accumulating details after a shell command trigger.
    ShellCommand { lines: Vec<String> },
    /// Accumulating details after a file edit trigger.
    FileEdit { lines: Vec<String> },
}

/// Adapter for Codex CLI's permission prompt format.
pub struct CodexAdapter {
    state: State,
    re_shell_command: Regex,
    re_file_edit: Regex,
    re_dollar_command: Regex,
    re_file_path: Regex,
    re_proceed: Regex,
}

impl Default for CodexAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexAdapter {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            re_shell_command: Regex::new(r"(?i)^\s*shell\s+command:?\s*$")
                .expect("hardcoded regex"),
            re_file_edit: Regex::new(r"(?i)^\s*file\s+edit:?\s*$").expect("hardcoded regex"),
            re_dollar_command: Regex::new(r"^\s*\$\s*(.+)$").expect("hardcoded regex"),
            re_file_path: Regex::new(r"^\s{2,}(\S+\.\w+)").expect("hardcoded regex"),
            re_proceed: Regex::new(r"(?i)(?:proceed|approve|accept)\?\s*\[y")
                .expect("hardcoded regex"),
        }
    }

    /// Extract the shell command from accumulated lines (looks for "$ command").
    fn extract_shell_command(&self, lines: &[String]) -> String {
        for line in lines {
            if let Some(caps) = self.re_dollar_command.captures(line) {
                if let Some(m) = caps.get(1) {
                    return m.as_str().trim().to_string();
                }
            }
        }
        String::new()
    }

    /// Extract the file path from accumulated lines (first indented path-like line).
    fn extract_file_path(&self, lines: &[String]) -> String {
        for line in lines {
            if let Some(caps) = self.re_file_path.captures(line) {
                if let Some(m) = caps.get(1) {
                    return m.as_str().trim().to_string();
                }
            }
        }
        String::new()
    }

    /// Build a PromptDetection for a shell command.
    fn build_shell_detection(&self, lines: &[String]) -> PromptDetection {
        let command = self.extract_shell_command(lines);
        let parts: Vec<&str> = command.splitn(2, char::is_whitespace).collect();
        let program = parts.first().unwrap_or(&"").to_string();
        let args = parts
            .get(1)
            .map(|a| vec![a.to_string()])
            .unwrap_or_default();

        PromptDetection {
            action: ActionKind::ProcessSpawn {
                command: program,
                args,
            },
            raw_prompt: lines.join("\n"),
            approve_response: "y".into(),
            deny_response: "n".into(),
        }
    }

    /// Build a PromptDetection for a file edit.
    fn build_file_edit_detection(&self, lines: &[String]) -> PromptDetection {
        let path = self.extract_file_path(lines);
        PromptDetection {
            action: ActionKind::FileWrite {
                path: PathBuf::from(path),
            },
            raw_prompt: lines.join("\n"),
            approve_response: "y".into(),
            deny_response: "n".into(),
        }
    }

    /// Check if a line contains the proceed/approval prompt.
    fn is_proceed_prompt(&self, text: &str) -> bool {
        self.re_proceed.is_match(text)
    }
}

impl AgentAdapter for CodexAdapter {
    fn name(&self) -> &str {
        "Codex"
    }

    fn scan_line(&mut self, line: &str) -> ScanResult {
        let has_proceed = self.re_proceed.is_match(line);
        let is_shell = self.re_shell_command.is_match(line);
        let is_file_edit = self.re_file_edit.is_match(line);

        match &mut self.state {
            State::Idle => {
                if is_shell {
                    self.state = State::ShellCommand {
                        lines: vec![line.to_string()],
                    };
                    ScanResult::Partial
                } else if is_file_edit {
                    self.state = State::FileEdit {
                        lines: vec![line.to_string()],
                    };
                    ScanResult::Partial
                } else if has_proceed {
                    ScanResult::Uncertain(line.to_string())
                } else {
                    ScanResult::None
                }
            }
            State::ShellCommand { lines } => {
                lines.push(line.to_string());
                if has_proceed {
                    let lines = lines.clone();
                    let detection = self.build_shell_detection(&lines);
                    self.state = State::Idle;
                    ScanResult::Prompt(detection)
                } else {
                    ScanResult::Partial
                }
            }
            State::FileEdit { lines } => {
                lines.push(line.to_string());
                if has_proceed {
                    let lines = lines.clone();
                    let detection = self.build_file_edit_detection(&lines);
                    self.state = State::Idle;
                    ScanResult::Prompt(detection)
                } else {
                    ScanResult::Partial
                }
            }
        }
    }

    fn scan_partial(&mut self, partial: &str) -> ScanResult {
        if self.is_proceed_prompt(partial) {
            match &self.state {
                State::ShellCommand { lines } => {
                    let mut all_lines = lines.clone();
                    all_lines.push(partial.to_string());
                    let detection = self.build_shell_detection(&all_lines);
                    self.state = State::Idle;
                    ScanResult::Prompt(detection)
                }
                State::FileEdit { lines } => {
                    let mut all_lines = lines.clone();
                    all_lines.push(partial.to_string());
                    let detection = self.build_file_edit_detection(&all_lines);
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
    fn detects_shell_command_prompt() {
        let mut adapter = CodexAdapter::new();

        assert_eq!(adapter.scan_line("Shell command:"), ScanResult::Partial);
        assert_eq!(
            adapter.scan_line("  $ npm install express"),
            ScanResult::Partial
        );
        assert_eq!(adapter.scan_line(""), ScanResult::Partial);

        match adapter.scan_line("Do you want to proceed? [y/n]") {
            ScanResult::Prompt(det) => {
                assert_eq!(det.approve_response, "y");
                assert_eq!(det.deny_response, "n");
                match &det.action {
                    ActionKind::ProcessSpawn { command, args } => {
                        assert_eq!(command, "npm");
                        assert_eq!(args, &vec!["install express".to_string()]);
                    }
                    other => panic!("expected ProcessSpawn, got {other:?}"),
                }
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn detects_file_edit_prompt() {
        let mut adapter = CodexAdapter::new();

        assert_eq!(adapter.scan_line("File edit:"), ScanResult::Partial);
        assert_eq!(adapter.scan_line("  src/main.rs"), ScanResult::Partial);
        assert_eq!(adapter.scan_line("  + fn hello() {}"), ScanResult::Partial);

        match adapter.scan_line("Do you want to proceed? [y/n]") {
            ScanResult::Prompt(det) => match &det.action {
                ActionKind::FileWrite { path } => {
                    assert_eq!(path, &PathBuf::from("src/main.rs"));
                }
                other => panic!("expected FileWrite, got {other:?}"),
            },
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn ignores_normal_output() {
        let mut adapter = CodexAdapter::new();
        assert_eq!(adapter.scan_line("Compiling project..."), ScanResult::None);
        assert_eq!(adapter.scan_line("test result: ok"), ScanResult::None);
        assert_eq!(adapter.scan_line(""), ScanResult::None);
    }

    #[test]
    fn partial_line_detection() {
        let mut adapter = CodexAdapter::new();

        adapter.scan_line("Shell command:");
        adapter.scan_line("  $ echo hello");

        match adapter.scan_partial("Do you want to proceed? [y/n] ") {
            ScanResult::Prompt(det) => {
                assert!(matches!(det.action, ActionKind::ProcessSpawn { .. }));
            }
            other => panic!("expected Prompt from partial, got {other:?}"),
        }
    }

    #[test]
    fn reset_clears_state() {
        let mut adapter = CodexAdapter::new();

        adapter.scan_line("Shell command:");
        adapter.reset();

        // After reset, proceed prompt should be uncertain
        match adapter.scan_line("Do you want to proceed? [y/n]") {
            ScanResult::Uncertain(_) => {}
            other => panic!("expected Uncertain, got {other:?}"),
        }
    }

    #[test]
    fn bare_proceed_returns_uncertain() {
        let mut adapter = CodexAdapter::new();
        match adapter.scan_line("Do you want to proceed? [y/n]") {
            ScanResult::Uncertain(_) => {}
            other => panic!("expected Uncertain, got {other:?}"),
        }
    }
}
