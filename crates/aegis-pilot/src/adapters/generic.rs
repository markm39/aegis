//! Regex-based generic agent adapter.
//!
//! Matches permission prompts using user-configured regex patterns from
//! `PromptPatternConfig`. Supports named capture groups `tool` and `args`
//! for extracting action details.

use regex::Regex;

use aegis_types::PromptPatternConfig;

use crate::adapter::{AgentAdapter, PromptDetection, ScanResult};

/// A compiled prompt pattern with its response strings.
struct CompiledPattern {
    regex: Regex,
    approve: String,
    deny: String,
}

/// Regex-based adapter configurable via `PromptPatternConfig` entries.
pub struct GenericAdapter {
    patterns: Vec<CompiledPattern>,
}

impl GenericAdapter {
    /// Create a new generic adapter from configuration patterns.
    ///
    /// Invalid regex patterns are logged and skipped rather than causing a panic.
    pub fn new(configs: &[PromptPatternConfig]) -> Self {
        let patterns = configs
            .iter()
            .filter_map(|c| match Regex::new(&c.regex) {
                Ok(regex) => Some(CompiledPattern {
                    regex,
                    approve: c.approve.clone(),
                    deny: c.deny.clone(),
                }),
                Err(e) => {
                    tracing::warn!("skipping invalid prompt pattern {:?}: {e}", c.regex);
                    None
                }
            })
            .collect();

        Self { patterns }
    }

    fn try_match(&self, line: &str) -> Option<PromptDetection> {
        for pattern in &self.patterns {
            if let Some(caps) = pattern.regex.captures(line) {
                let tool = caps
                    .name("tool")
                    .map(|m| m.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".into());
                let args = caps
                    .name("args")
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                let action = aegis_types::ActionKind::ToolCall {
                    tool: tool.clone(),
                    args: serde_json::json!({ "raw": args }),
                };

                return Some(PromptDetection {
                    action,
                    raw_prompt: line.to_string(),
                    approve_response: pattern.approve.clone(),
                    deny_response: pattern.deny.clone(),
                });
            }
        }
        None
    }
}

impl AgentAdapter for GenericAdapter {
    fn name(&self) -> &str {
        "Generic"
    }

    fn scan_line(&mut self, line: &str) -> ScanResult {
        match self.try_match(line) {
            Some(detection) => ScanResult::Prompt(detection),
            None => ScanResult::None,
        }
    }

    fn scan_partial(&mut self, partial: &str) -> ScanResult {
        match self.try_match(partial) {
            Some(detection) => ScanResult::Prompt(detection),
            None => ScanResult::None,
        }
    }

    fn reset(&mut self) {
        // Stateless -- nothing to reset.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_patterns() -> Vec<PromptPatternConfig> {
        vec![PromptPatternConfig {
            regex: r"Execute (?P<tool>\w+)\((?P<args>.*)\)\?".into(),
            approve: "yes".into(),
            deny: "no".into(),
        }]
    }

    #[test]
    fn matches_configured_pattern() {
        let mut adapter = GenericAdapter::new(&sample_patterns());

        match adapter.scan_line("Execute shell(ls -la)?") {
            ScanResult::Prompt(det) => {
                assert_eq!(det.approve_response, "yes");
                assert_eq!(det.deny_response, "no");
                match &det.action {
                    aegis_types::ActionKind::ToolCall { tool, .. } => {
                        assert_eq!(tool, "shell");
                    }
                    other => panic!("expected ToolCall, got {other:?}"),
                }
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn no_match_returns_none() {
        let mut adapter = GenericAdapter::new(&sample_patterns());
        assert_eq!(adapter.scan_line("just normal output"), ScanResult::None);
    }

    #[test]
    fn invalid_regex_is_skipped() {
        let patterns = vec![
            PromptPatternConfig {
                regex: "[invalid".into(),
                approve: "y".into(),
                deny: "n".into(),
            },
            PromptPatternConfig {
                regex: r"Allow\?".into(),
                approve: "y".into(),
                deny: "n".into(),
            },
        ];
        let mut adapter = GenericAdapter::new(&patterns);
        // Should still work with the valid pattern
        match adapter.scan_line("Allow?") {
            ScanResult::Prompt(_) => {}
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn empty_patterns() {
        let mut adapter = GenericAdapter::new(&[]);
        assert_eq!(adapter.scan_line("anything"), ScanResult::None);
    }

    #[test]
    fn empty_tool_capture_defaults_to_unknown() {
        // A regex where the tool capture group can match empty string
        let patterns = vec![PromptPatternConfig {
            regex: r"Run (?P<tool>\w*)\?".into(),
            approve: "y".into(),
            deny: "n".into(),
        }];
        let mut adapter = GenericAdapter::new(&patterns);

        match adapter.scan_line("Run ?") {
            ScanResult::Prompt(det) => match &det.action {
                aegis_types::ActionKind::ToolCall { tool, .. } => {
                    assert_eq!(
                        tool, "unknown",
                        "empty tool capture should default to 'unknown'"
                    );
                }
                other => panic!("expected ToolCall, got {other:?}"),
            },
            other => panic!("expected Prompt, got {other:?}"),
        }
    }
}
