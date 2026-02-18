//! Claude Code driver.
//!
//! Spawns `claude` in a PTY with `--dangerously-skip-permissions` for headless
//! operation. Policy enforcement is handled externally via Claude Code's
//! `PreToolUse` hook system rather than PTY-based prompt detection (Claude Code
//! is a full-screen Ink/React TUI that cannot be reliably parsed line-by-line).
//!
//! Tasks are injected via `-p "prompt"` (one-shot) or by writing to stdin after
//! the interactive session starts.

use std::path::Path;

use crate::adapter::AgentAdapter;
use crate::driver::{AgentDriver, SpawnStrategy, TaskInjection};

/// Driver for Claude Code CLI.
pub struct ClaudeCodeDriver {
    /// Agent name, set as AEGIS_AGENT_NAME env var so the PreToolUse hook
    /// can identify which agent is making the tool call.
    pub agent_name: Option<String>,
    pub one_shot: bool,
    pub extra_args: Vec<String>,
}

impl AgentDriver for ClaudeCodeDriver {
    fn name(&self) -> &str {
        "ClaudeCode"
    }

    fn spawn_strategy(&self, _working_dir: &Path) -> SpawnStrategy {
        let mut args = vec!["--dangerously-skip-permissions".to_string()];
        args.extend(self.extra_args.iter().cloned());

        let mut env = Vec::new();
        if let Some(ref name) = self.agent_name {
            env.push(("AEGIS_AGENT_NAME".to_string(), name.clone()));
        }
        // Point the PreToolUse hook at the daemon's control socket.
        let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");
        env.push((
            "AEGIS_SOCKET_PATH".to_string(),
            socket_path.to_string_lossy().into_owned(),
        ));

        SpawnStrategy::Pty {
            command: "claude".to_string(),
            args,
            env,
        }
    }

    fn create_adapter(&self) -> Option<Box<dyn AgentAdapter>> {
        // Policy enforcement is via PreToolUse hooks, not PTY output parsing.
        // Claude Code is a full-screen Ink TUI -- its output cannot be reliably
        // parsed with line-by-line regex matching.
        None
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
    fn spawn_strategy_always_skips_permissions() {
        let driver = ClaudeCodeDriver {
            agent_name: None,
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { command, args, .. } => {
                assert_eq!(command, "claude");
                assert!(args.contains(&"--dangerously-skip-permissions".to_string()));
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn spawn_strategy_sets_agent_name_env() {
        let driver = ClaudeCodeDriver {
            agent_name: Some("claude-1".to_string()),
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { env, .. } => {
                assert!(env.contains(&("AEGIS_AGENT_NAME".to_string(), "claude-1".to_string())));
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn spawn_strategy_extra_args() {
        let driver = ClaudeCodeDriver {
            agent_name: None,
            one_shot: false,
            extra_args: vec!["--verbose".to_string()],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { args, .. } => {
                assert!(args.contains(&"--dangerously-skip-permissions".to_string()));
                assert!(args.contains(&"--verbose".to_string()));
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn task_injection_stdin() {
        let driver = ClaudeCodeDriver {
            agent_name: None,
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
            agent_name: None,
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
    fn no_adapter_hooks_handle_policy() {
        let driver = ClaudeCodeDriver {
            agent_name: None,
            one_shot: false,
            extra_args: vec![],
        };
        assert!(driver.create_adapter().is_none());
    }
}
