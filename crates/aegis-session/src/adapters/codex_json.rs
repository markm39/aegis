//! Codex JSON adapter for detecting approval prompts from JSONL events.

use crate::adapter::{AgentAdapter, ScanResult};
use crate::json_events::detect_json_prompt;
use crate::session::ToolKind;

/// Adapter for Codex JSONL events.
pub struct CodexJsonAdapter;

impl CodexJsonAdapter {
    pub fn new() -> Self {
        Self
    }

    fn scan(&self, line: &str) -> ScanResult {
        match detect_json_prompt(ToolKind::Codex, line) {
            Some(detection) => ScanResult::Prompt(detection),
            None => ScanResult::None,
        }
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
        self.scan(line)
    }

    fn scan_partial(&mut self, partial: &str) -> ScanResult {
        self.scan(partial)
    }

    fn reset(&mut self) {}
}
