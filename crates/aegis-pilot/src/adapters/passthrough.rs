//! No-op adapter that never detects permission prompts.
//!
//! Used as a fallback when no specific adapter matches the agent command.
//! All output passes through without intervention.

use crate::adapter::{AgentAdapter, ScanResult};

/// A no-op adapter that never detects prompts.
pub struct PassthroughAdapter;

impl AgentAdapter for PassthroughAdapter {
    fn name(&self) -> &str {
        "Passthrough"
    }

    fn scan_line(&mut self, _line: &str) -> ScanResult {
        ScanResult::None
    }

    fn reset(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_returns_none() {
        let mut adapter = PassthroughAdapter;
        assert_eq!(
            adapter.scan_line("Claude wants to use Bash"),
            ScanResult::None
        );
        assert_eq!(adapter.scan_line("Allow? (y/n)"), ScanResult::None);
        assert_eq!(adapter.scan_line(""), ScanResult::None);
    }
}
