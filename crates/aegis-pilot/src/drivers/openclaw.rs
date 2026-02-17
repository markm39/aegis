//! OpenClaw driver.
//!
//! Spawns `openclaw agent` in a PTY. OpenClaw is an autonomous agent with
//! its own heartbeat daemon, so Aegis uses a PassthroughAdapter (observe-only).
//! Task injection is via `--message` flag or stdin.

use std::path::Path;

use crate::adapter::AgentAdapter;
use crate::adapters::passthrough::PassthroughAdapter;
use crate::driver::{AgentDriver, SpawnStrategy, TaskInjection};

/// Driver for OpenClaw autonomous agent.
pub struct OpenClawDriver {
    pub agent_name: Option<String>,
    pub extra_args: Vec<String>,
}

impl AgentDriver for OpenClawDriver {
    fn name(&self) -> &str {
        "OpenClaw"
    }

    fn spawn_strategy(&self, _working_dir: &Path) -> SpawnStrategy {
        let mut args = vec!["agent".to_string()];

        if let Some(name) = &self.agent_name {
            args.push("--name".to_string());
            args.push(name.clone());
        }

        args.extend(self.extra_args.iter().cloned());

        SpawnStrategy::Pty {
            command: "openclaw".to_string(),
            args,
            env: vec![],
        }
    }

    fn create_adapter(&self) -> Option<Box<dyn AgentAdapter>> {
        // OpenClaw handles its own approval flow; Aegis just observes
        Some(Box::new(PassthroughAdapter))
    }

    fn task_injection(&self, task: &str) -> TaskInjection {
        TaskInjection::CliArg {
            flag: "--message".to_string(),
            value: task.to_string(),
        }
    }

    fn supports_headless(&self) -> bool {
        // OpenClaw's agent mode is inherently headless
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn spawn_strategy_basic() {
        let driver = OpenClawDriver {
            agent_name: None,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { command, args, .. } => {
                assert_eq!(command, "openclaw");
                assert_eq!(args, vec!["agent"]);
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn spawn_strategy_with_name() {
        let driver = OpenClawDriver {
            agent_name: Some("builder".into()),
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { args, .. } => {
                assert!(args.contains(&"--name".to_string()));
                assert!(args.contains(&"builder".to_string()));
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn adapter_is_passthrough() {
        let driver = OpenClawDriver {
            agent_name: None,
            extra_args: vec![],
        };
        let adapter = driver.create_adapter().unwrap();
        assert_eq!(adapter.name(), "Passthrough");
    }

    #[test]
    fn task_injection_via_flag() {
        let driver = OpenClawDriver {
            agent_name: None,
            extra_args: vec![],
        };
        match driver.task_injection("build the API") {
            TaskInjection::CliArg { flag, value } => {
                assert_eq!(flag, "--message");
                assert_eq!(value, "build the API");
            }
            other => panic!("expected CliArg, got {other:?}"),
        }
    }
}
