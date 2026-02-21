//! Claude Code driver.
//!
//! Spawns `claude` in print mode with `--output-format stream-json` for
//! reliable programmatic communication. The prompt is passed as `-p "prompt"`
//! on the command line. Output is structured NDJSON on stdout.
//!
//! Follow-up messages use `--resume <session-id>` to continue the conversation.
//! The user can `:pop` into the full interactive TUI via `claude --resume <id>`.
//!
//! Policy enforcement is handled externally via Claude Code's `PreToolUse` hook
//! system rather than output parsing.

use std::path::Path;

use crate::adapter::AgentAdapter;
use crate::driver::{AgentDriver, ProcessKind, SpawnStrategy, TaskInjection};
use crate::session::ToolKind;

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

        // Use Process (not Pty) -- the lifecycle layer spawns via JsonStreamSession
        // which handles --output-format stream-json, --session-id, etc.
        SpawnStrategy::Process {
            command: "claude".to_string(),
            args,
            env,
            kind: ProcessKind::Json {
                tool: ToolKind::ClaudeCode,
                global_args: Vec::new(),
            },
        }
    }

    fn create_adapter(&self) -> Option<Box<dyn AgentAdapter>> {
        // Policy enforcement is via PreToolUse hooks, not PTY output parsing.
        // Claude Code is a full-screen Ink TUI -- its output cannot be reliably
        // parsed with line-by-line regex matching.
        None
    }

    fn task_injection(&self, task: &str) -> TaskInjection {
        // Always use -p (print mode) for reliable prompt delivery.
        // Stdin injection into Claude Code's Ink TUI is unreliable --
        // bracketed paste often fails and the Enter keypress gets lost.
        // In -p mode, Claude Code runs the full agentic loop (tool calls,
        // file edits, etc.) and exits when done.
        TaskInjection::CliArg {
            flag: "-p".to_string(),
            value: task.to_string(),
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
            SpawnStrategy::Process { command, args, .. } => {
                assert_eq!(command, "claude");
                assert!(args.contains(&"--dangerously-skip-permissions".to_string()));
            }
            _ => panic!("expected Process strategy"),
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
            SpawnStrategy::Process { env, .. } => {
                assert!(env.contains(&("AEGIS_AGENT_NAME".to_string(), "claude-1".to_string())));
            }
            _ => panic!("expected Process strategy"),
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
            SpawnStrategy::Process { args, .. } => {
                assert!(args.contains(&"--dangerously-skip-permissions".to_string()));
                assert!(args.contains(&"--verbose".to_string()));
            }
            _ => panic!("expected Process strategy"),
        }
    }

    #[test]
    fn task_injection_always_uses_print_mode() {
        // Even with one_shot=false, -p is always used for reliable delivery
        let driver = ClaudeCodeDriver {
            agent_name: None,
            one_shot: false,
            extra_args: vec![],
        };
        match driver.task_injection("build the login page") {
            TaskInjection::CliArg { flag, value } => {
                assert_eq!(flag, "-p");
                assert_eq!(value, "build the login page");
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
