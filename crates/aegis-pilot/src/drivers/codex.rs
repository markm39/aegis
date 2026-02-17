//! Codex driver.
//!
//! Spawns `codex` in a PTY. In headless mode, uses
//! `--approval-mode full-auto`. One-shot mode uses `codex exec -q "prompt"`.

use std::path::Path;

use crate::adapter::AgentAdapter;
use crate::adapters::codex::CodexAdapter;
use crate::driver::{AgentDriver, SpawnStrategy, TaskInjection};

/// Driver for OpenAI Codex CLI.
pub struct CodexDriver {
    pub approval_mode: String,
    pub one_shot: bool,
    pub extra_args: Vec<String>,
}

impl AgentDriver for CodexDriver {
    fn name(&self) -> &str {
        "Codex"
    }

    fn spawn_strategy(&self, _working_dir: &Path) -> SpawnStrategy {
        let mut args = Vec::new();

        if self.one_shot {
            args.push("exec".to_string());
        }

        // Approval mode: "suggest" (default), "auto-edit", or "full-auto"
        match self.approval_mode.as_str() {
            "full-auto" => {
                args.push("--approval-mode".to_string());
                args.push("full-auto".to_string());
            }
            "auto-edit" => {
                args.push("--approval-mode".to_string());
                args.push("auto-edit".to_string());
            }
            _ => {
                // "suggest" is the default, no flag needed
            }
        }

        args.extend(self.extra_args.iter().cloned());

        SpawnStrategy::Pty {
            command: "codex".to_string(),
            args,
            env: vec![],
        }
    }

    fn create_adapter(&self) -> Option<Box<dyn AgentAdapter>> {
        if self.approval_mode == "full-auto" {
            // No prompts in full-auto mode
            None
        } else {
            Some(Box::new(CodexAdapter::new()))
        }
    }

    fn task_injection(&self, task: &str) -> TaskInjection {
        if self.one_shot {
            TaskInjection::CliArg {
                flag: "-q".to_string(),
                value: task.to_string(),
            }
        } else {
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
    fn spawn_strategy_suggest() {
        let driver = CodexDriver {
            approval_mode: "suggest".into(),
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { command, args, .. } => {
                assert_eq!(command, "codex");
                assert!(args.is_empty());
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn spawn_strategy_full_auto() {
        let driver = CodexDriver {
            approval_mode: "full-auto".into(),
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { args, .. } => {
                assert!(args.contains(&"--approval-mode".to_string()));
                assert!(args.contains(&"full-auto".to_string()));
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn one_shot_includes_subcommand() {
        let driver = CodexDriver {
            approval_mode: "suggest".into(),
            one_shot: true,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { args, .. } => {
                assert_eq!(args[0], "exec");
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn adapter_in_suggest_mode() {
        let driver = CodexDriver {
            approval_mode: "suggest".into(),
            one_shot: false,
            extra_args: vec![],
        };
        assert!(driver.create_adapter().is_some());
    }

    #[test]
    fn no_adapter_in_full_auto() {
        let driver = CodexDriver {
            approval_mode: "full-auto".into(),
            one_shot: false,
            extra_args: vec![],
        };
        assert!(driver.create_adapter().is_none());
    }
}
