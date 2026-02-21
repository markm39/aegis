//! Built-in agent adapters for various AI tools.
//!
//! - [`claude::ClaudeCodeAdapter`]: detects Claude Code permission prompts
//! - [`generic::GenericAdapter`]: regex-based configurable adapter
//! - [`passthrough::PassthroughAdapter`]: no-op adapter that detects nothing

pub mod claude;
pub mod codex;
pub mod codex_json;
pub mod generic;
pub mod passthrough;

use aegis_types::AdapterConfig;

use crate::adapter::AgentAdapter;

/// Create an adapter from configuration, optionally auto-detecting from the command name.
pub fn create_adapter(config: &AdapterConfig, command: &str) -> Box<dyn AgentAdapter> {
    match config {
        AdapterConfig::ClaudeCode => Box::new(claude::ClaudeCodeAdapter::new()),
        AdapterConfig::Codex => Box::new(codex::CodexAdapter::new()),
        AdapterConfig::Generic { patterns } => Box::new(generic::GenericAdapter::new(patterns)),
        AdapterConfig::Passthrough => Box::new(passthrough::PassthroughAdapter),
        AdapterConfig::Auto => auto_detect(command),
    }
}

/// Auto-detect the appropriate adapter based on the command name.
fn auto_detect(command: &str) -> Box<dyn AgentAdapter> {
    // Extract the base command name (strip path, handle common wrappers)
    let base = command.rsplit('/').next().unwrap_or(command);

    if base == "claude" || base.starts_with("claude-") || base.contains("claude") {
        tracing::info!("auto-detected Claude Code adapter for command: {command}");
        Box::new(claude::ClaudeCodeAdapter::new())
    } else if base == "codex" || base.starts_with("codex-") || base.contains("codex") {
        tracing::info!("auto-detected Codex adapter for command: {command}");
        Box::new(codex::CodexAdapter::new())
    } else {
        tracing::info!("no specific adapter for command: {command}, using passthrough");
        Box::new(passthrough::PassthroughAdapter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_detect_claude() {
        let adapter = auto_detect("claude");
        assert_eq!(adapter.name(), "ClaudeCode");
    }

    #[test]
    fn auto_detect_claude_path() {
        let adapter = auto_detect("/usr/local/bin/claude");
        assert_eq!(adapter.name(), "ClaudeCode");
    }

    #[test]
    fn auto_detect_unknown() {
        let adapter = auto_detect("vim");
        assert_eq!(adapter.name(), "Passthrough");
    }

    #[test]
    fn create_from_config_claude() {
        let adapter = create_adapter(&AdapterConfig::ClaudeCode, "anything");
        assert_eq!(adapter.name(), "ClaudeCode");
    }

    #[test]
    fn create_from_config_auto() {
        let adapter = create_adapter(&AdapterConfig::Auto, "claude");
        assert_eq!(adapter.name(), "ClaudeCode");
    }
}
