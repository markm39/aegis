//! Per-tool driver implementations.
//!
//! Each module implements [`AgentDriver`](crate::driver::AgentDriver) for a
//! specific AI tool, handling spawn commands, adapter selection, and task
//! injection strategies.

pub mod claude_code;
pub mod codex;
pub mod cursor;
pub mod custom;
pub mod openclaw;

use aegis_types::AgentToolConfig;

use crate::driver::AgentDriver;

/// Create the appropriate driver for an agent tool configuration.
///
/// The optional `agent_name` is passed as `AEGIS_AGENT_NAME` to the spawned
/// process so that PreToolUse hooks can identify the agent when querying
/// the daemon for Cedar policy evaluation.
pub fn create_driver(config: &AgentToolConfig, agent_name: Option<&str>) -> Box<dyn AgentDriver> {
    match config {
        AgentToolConfig::ClaudeCode { one_shot, extra_args, .. } => {
            Box::new(claude_code::ClaudeCodeDriver {
                agent_name: agent_name.map(|s| s.to_string()),
                one_shot: *one_shot,
                extra_args: extra_args.clone(),
            })
        }
        AgentToolConfig::Codex { approval_mode, one_shot, extra_args } => {
            Box::new(codex::CodexDriver {
                approval_mode: approval_mode.clone(),
                one_shot: *one_shot,
                extra_args: extra_args.clone(),
            })
        }
        AgentToolConfig::OpenClaw { agent_name, extra_args } => {
            Box::new(openclaw::OpenClawDriver {
                agent_name: agent_name.clone(),
                extra_args: extra_args.clone(),
            })
        }
        AgentToolConfig::Cursor { assume_running } => {
            Box::new(cursor::CursorDriver {
                assume_running: *assume_running,
            })
        }
        AgentToolConfig::Custom { command, args, adapter, env } => {
            Box::new(custom::CustomDriver {
                command: command.clone(),
                args: args.clone(),
                adapter: adapter.clone(),
                env: env.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_claude_code_driver() {
        let config = AgentToolConfig::ClaudeCode {
            skip_permissions: true,
            one_shot: false,
            extra_args: vec![],
        };
        let driver = create_driver(&config, Some("test-agent"));
        assert_eq!(driver.name(), "ClaudeCode");
        assert!(driver.supports_headless());
    }

    #[test]
    fn create_codex_driver() {
        let config = AgentToolConfig::Codex {
            approval_mode: "full-auto".into(),
            one_shot: false,
            extra_args: vec![],
        };
        let driver = create_driver(&config, None);
        assert_eq!(driver.name(), "Codex");
        assert!(driver.supports_headless());
    }

    #[test]
    fn create_openclaw_driver() {
        let config = AgentToolConfig::OpenClaw {
            agent_name: None,
            extra_args: vec![],
        };
        let driver = create_driver(&config, None);
        assert_eq!(driver.name(), "OpenClaw");
    }

    #[test]
    fn create_cursor_driver() {
        let config = AgentToolConfig::Cursor { assume_running: true };
        let driver = create_driver(&config, None);
        assert_eq!(driver.name(), "Cursor");
        assert!(!driver.supports_headless());
    }

    #[test]
    fn create_custom_driver() {
        let config = AgentToolConfig::Custom {
            command: "my-agent".into(),
            args: vec!["--auto".into()],
            adapter: aegis_types::AdapterConfig::Auto,
            env: vec![],
        };
        let driver = create_driver(&config, None);
        assert_eq!(driver.name(), "Custom");
    }
}
