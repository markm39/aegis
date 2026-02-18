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
    /// Aegis agent name, set as AEGIS_AGENT_NAME env var so hooks can
    /// identify which agent is making the tool call.
    pub aegis_agent_name: Option<String>,
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

        let mut env = Vec::new();
        if let Some(ref name) = self.aegis_agent_name {
            env.push(("AEGIS_AGENT_NAME".to_string(), name.clone()));
        }
        let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");
        env.push((
            "AEGIS_SOCKET_PATH".to_string(),
            socket_path.to_string_lossy().into_owned(),
        ));

        SpawnStrategy::Pty {
            command: "codex".to_string(),
            args,
            env,
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
            aegis_agent_name: None,
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
            aegis_agent_name: None,
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
            aegis_agent_name: None,
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
    fn spawn_strategy_sets_aegis_env() {
        let driver = CodexDriver {
            aegis_agent_name: Some("codex-1".to_string()),
            approval_mode: "full-auto".into(),
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { env, .. } => {
                assert!(env.contains(&("AEGIS_AGENT_NAME".to_string(), "codex-1".to_string())));
                assert!(env.iter().any(|(k, _)| k == "AEGIS_SOCKET_PATH"));
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn adapter_in_suggest_mode() {
        let driver = CodexDriver {
            aegis_agent_name: None,
            approval_mode: "suggest".into(),
            one_shot: false,
            extra_args: vec![],
        };
        assert!(driver.create_adapter().is_some());
    }

    #[test]
    fn no_adapter_in_full_auto() {
        let driver = CodexDriver {
            aegis_agent_name: None,
            approval_mode: "full-auto".into(),
            one_shot: false,
            extra_args: vec![],
        };
        assert!(driver.create_adapter().is_none());
    }
}
