//! Claude Code driver.
//!
//! Spawns `claude` in a PTY with optional `--dangerously-skip-permissions`
//! for headless operation. Tasks are injected via `-p "prompt"` (one-shot)
//! or by writing to stdin after the interactive session starts.

use std::path::Path;

use crate::adapter::AgentAdapter;
use crate::adapters::claude::ClaudeCodeAdapter;
use crate::driver::{AgentDriver, SpawnStrategy, TaskInjection};

/// Driver for Claude Code CLI.
pub struct ClaudeCodeDriver {
    pub skip_permissions: bool,
    pub one_shot: bool,
    pub extra_args: Vec<String>,
}

impl AgentDriver for ClaudeCodeDriver {
    fn name(&self) -> &str {
        "ClaudeCode"
    }

    fn spawn_strategy(&self, _working_dir: &Path) -> SpawnStrategy {
        let mut args = Vec::new();

        if self.skip_permissions {
            args.push("--dangerously-skip-permissions".to_string());
        }

        args.extend(self.extra_args.iter().cloned());

        SpawnStrategy::Pty {
            command: "claude".to_string(),
            args,
            env: vec![],
        }
    }

    fn create_adapter(&self) -> Option<Box<dyn AgentAdapter>> {
        if self.skip_permissions {
            // No permission prompts to detect when permissions are skipped
            None
        } else {
            Some(Box::new(ClaudeCodeAdapter::new()))
        }
    }

    fn task_injection(&self, task: &str) -> TaskInjection {
        if self.one_shot {
            // Pass as CLI argument: claude -p "task"
            TaskInjection::CliArg {
                flag: "-p".to_string(),
                value: task.to_string(),
            }
        } else {
            // Write to stdin after the interactive session starts
            TaskInjection::Stdin {
                text: task.to_string(),
            }
        }
    }

    fn supports_headless(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn spawn_strategy_basic() {
        let driver = ClaudeCodeDriver {
            skip_permissions: false,
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { command, args, .. } => {
                assert_eq!(command, "claude");
                assert!(args.is_empty());
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn spawn_strategy_skip_permissions() {
        let driver = ClaudeCodeDriver {
            skip_permissions: true,
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { args, .. } => {
                assert!(args.contains(&"--dangerously-skip-permissions".to_string()));
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn task_injection_stdin() {
        let driver = ClaudeCodeDriver {
            skip_permissions: false,
            one_shot: false,
            extra_args: vec![],
        };
        match driver.task_injection("build the login page") {
            TaskInjection::Stdin { text } => assert_eq!(text, "build the login page"),
            other => panic!("expected Stdin, got {other:?}"),
        }
    }

    #[test]
    fn task_injection_one_shot() {
        let driver = ClaudeCodeDriver {
            skip_permissions: true,
            one_shot: true,
            extra_args: vec![],
        };
        match driver.task_injection("fix the bug") {
            TaskInjection::CliArg { flag, value } => {
                assert_eq!(flag, "-p");
                assert_eq!(value, "fix the bug");
            }
            other => panic!("expected CliArg, got {other:?}"),
        }
    }

    #[test]
    fn adapter_with_permissions() {
        let driver = ClaudeCodeDriver {
            skip_permissions: false,
            one_shot: false,
            extra_args: vec![],
        };
        assert!(driver.create_adapter().is_some());
    }

    #[test]
    fn adapter_without_permissions() {
        let driver = ClaudeCodeDriver {
            skip_permissions: true,
            one_shot: false,
            extra_args: vec![],
        };
        assert!(driver.create_adapter().is_none());
    }
}
