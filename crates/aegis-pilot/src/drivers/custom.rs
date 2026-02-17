//! Custom command driver.
//!
//! Runs an arbitrary command in a PTY with a configurable adapter.
//! Used for tools not specifically supported by Aegis.

use std::path::Path;

use aegis_types::AdapterConfig;

use crate::adapter::AgentAdapter;
use crate::adapters;
use crate::driver::{AgentDriver, SpawnStrategy, TaskInjection};

/// Driver for custom/arbitrary commands.
pub struct CustomDriver {
    pub command: String,
    pub args: Vec<String>,
    pub adapter: AdapterConfig,
    pub env: Vec<(String, String)>,
}

impl AgentDriver for CustomDriver {
    fn name(&self) -> &str {
        "Custom"
    }

    fn spawn_strategy(&self, _working_dir: &Path) -> SpawnStrategy {
        SpawnStrategy::Pty {
            command: self.command.clone(),
            args: self.args.clone(),
            env: self.env.clone(),
        }
    }

    fn create_adapter(&self) -> Option<Box<dyn AgentAdapter>> {
        Some(adapters::create_adapter(&self.adapter, &self.command))
    }

    fn task_injection(&self, task: &str) -> TaskInjection {
        TaskInjection::Stdin {
            text: task.to_string(),
        }
    }

    fn supports_headless(&self) -> bool {
        // Unknown -- depends on the command
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn spawn_strategy() {
        let driver = CustomDriver {
            command: "my-agent".into(),
            args: vec!["--auto".into()],
            adapter: AdapterConfig::Auto,
            env: vec![("KEY".into(), "val".into())],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { command, args, env } => {
                assert_eq!(command, "my-agent");
                assert_eq!(args, vec!["--auto"]);
                assert_eq!(env, vec![("KEY".into(), "val".into())]);
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn adapter_auto_detect() {
        let driver = CustomDriver {
            command: "claude".into(),
            args: vec![],
            adapter: AdapterConfig::Auto,
            env: vec![],
        };
        let adapter = driver.create_adapter().unwrap();
        assert_eq!(adapter.name(), "ClaudeCode");
    }

    #[test]
    fn task_via_stdin() {
        let driver = CustomDriver {
            command: "agent".into(),
            args: vec![],
            adapter: AdapterConfig::Auto,
            env: vec![],
        };
        match driver.task_injection("do something") {
            TaskInjection::Stdin { text } => assert_eq!(text, "do something"),
            other => panic!("expected Stdin, got {other:?}"),
        }
    }
}
