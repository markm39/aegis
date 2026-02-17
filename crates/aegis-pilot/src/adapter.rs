//! Agent adapter trait for detecting permission prompts in terminal output.
//!
//! Each AI agent (Claude Code, Cursor, etc.) has its own prompt format.
//! Adapters parse ANSI-stripped output lines and detect when the agent is
//! asking for permission, extracting the action being requested and the
//! response strings needed to approve or deny it.

use aegis_types::ActionKind;

/// Result of scanning a line of agent output for permission prompts.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanResult {
    /// No prompt detected in this line.
    None,
    /// Accumulating a multi-line prompt (e.g., tool details span several lines).
    Partial,
    /// A complete permission prompt was detected.
    Prompt(PromptDetection),
    /// Something prompt-like was seen but couldn't be fully parsed.
    Uncertain(String),
}

/// A fully detected permission prompt with extracted action and response strings.
#[derive(Debug, Clone, PartialEq)]
pub struct PromptDetection {
    /// The action kind extracted from the prompt, for Cedar policy evaluation.
    pub action: ActionKind,
    /// The raw prompt text as displayed to the user (for audit logging).
    pub raw_prompt: String,
    /// String to send to the agent's stdin to approve the action (e.g., "y").
    pub approve_response: String,
    /// String to send to the agent's stdin to deny the action (e.g., "n").
    pub deny_response: String,
}

/// Trait for detecting permission prompts in agent terminal output.
///
/// Implementations are stateful -- they may accumulate context across
/// multiple `scan_line` calls to handle multi-line prompts. Call `reset()`
/// to clear accumulated state (e.g., after a prompt is handled).
pub trait AgentAdapter: Send {
    /// Human-readable name for this adapter (e.g., "ClaudeCode").
    fn name(&self) -> &str;

    /// Scan a single ANSI-stripped line of output.
    ///
    /// Returns `ScanResult::Prompt` when a complete prompt is detected,
    /// `ScanResult::Partial` when accumulating a multi-line prompt, or
    /// `ScanResult::None` when the line is not prompt-related.
    fn scan_line(&mut self, line: &str) -> ScanResult;

    /// Check the current partial line (text without a trailing newline).
    ///
    /// Some agents print the "Allow? (y/n)" prompt without a final newline.
    /// This method lets the supervisor check the partial buffer periodically.
    /// Default implementation returns `ScanResult::None`.
    fn scan_partial(&mut self, partial: &str) -> ScanResult {
        let _ = partial;
        ScanResult::None
    }

    /// Reset internal state (clear accumulated multi-line context).
    fn reset(&mut self);
}
