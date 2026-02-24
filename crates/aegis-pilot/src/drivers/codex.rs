//! Codex driver.
//!
//! Spawns `codex` in JSON exec mode for structured output and resume support.

use std::path::Path;

use crate::adapter::AgentAdapter;
use crate::adapters::codex_json::CodexJsonAdapter;
use crate::driver::{AgentDriver, ProcessKind, SpawnStrategy, TaskInjection};
use crate::session::ToolKind;

/// Driver for OpenAI Codex CLI.
pub struct CodexDriver {
    /// Aegis agent name, set as AEGIS_AGENT_NAME env var so hooks can
    /// identify which agent is making the tool call.
    pub aegis_agent_name: Option<String>,
    pub runtime_engine: String,
    pub approval_mode: String,
    pub one_shot: bool,
    pub extra_args: Vec<String>,
}

fn native_wrapper_path() -> Option<String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent()?.parent()?;
    let wrapper = repo_root.join("scripts").join("coding-runtime-codex.sh");
    if wrapper.exists() {
        Some(wrapper.to_string_lossy().into_owned())
    } else {
        None
    }
}

impl AgentDriver for CodexDriver {
    fn name(&self) -> &str {
        "Codex"
    }

    fn spawn_strategy(&self, _working_dir: &Path) -> SpawnStrategy {
        let mut args = Vec::new();
        // JSON exec uses a dedicated protocol; only keep relevant exec flags here.
        if self.approval_mode == "full-auto" {
            args.push("--full-auto".to_string());
        }
        args.extend(self.extra_args.iter().cloned());

        let global_args = if self.approval_mode == "full-auto" {
            Vec::new()
        } else {
            vec!["--ask-for-approval".to_string(), "on-request".to_string()]
        };

        let mut env = Vec::new();
        let command = if self.runtime_engine != "external" {
            if let Some(wrapper) = native_wrapper_path() {
                env.push(("AEGIS_CODEX_RUNTIME".to_string(), "native".to_string()));
                wrapper
            } else {
                env.push((
                    "AEGIS_CODEX_RUNTIME".to_string(),
                    "external-fallback".to_string(),
                ));
                "codex".to_string()
            }
        } else {
            env.push(("AEGIS_CODEX_RUNTIME".to_string(), "external".to_string()));
            "codex".to_string()
        };
        if let Some(ref name) = self.aegis_agent_name {
            env.push(("AEGIS_AGENT_NAME".to_string(), name.clone()));
        }
        let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");
        env.push((
            "AEGIS_SOCKET_PATH".to_string(),
            socket_path.to_string_lossy().into_owned(),
        ));

        SpawnStrategy::Process {
            command,
            args,
            env,
            kind: ProcessKind::Json {
                tool: ToolKind::Codex,
                global_args,
            },
        }
    }

    fn create_adapter(&self) -> Option<Box<dyn AgentAdapter>> {
        if self.approval_mode == "full-auto" {
            None
        } else {
            Some(Box::new(CodexJsonAdapter::new()))
        }
    }

    fn task_injection(&self, task: &str) -> TaskInjection {
        // JSON exec reads the initial prompt from arguments; the lifecycle
        // extracts the value to pass to the JSON session spawn.
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
    fn spawn_strategy_suggest() {
        let driver = CodexDriver {
            aegis_agent_name: None,
            runtime_engine: "external".into(),
            approval_mode: "suggest".into(),
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Process { command, args, .. } => {
                assert_eq!(command, "codex");
                assert!(args.is_empty());
            }
            _ => panic!("expected Process strategy"),
        }
    }

    #[test]
    fn spawn_strategy_full_auto() {
        let driver = CodexDriver {
            aegis_agent_name: None,
            runtime_engine: "external".into(),
            approval_mode: "full-auto".into(),
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Process { args, .. } => {
                assert!(args.contains(&"--full-auto".to_string()));
            }
            _ => panic!("expected Process strategy"),
        }
    }

    #[test]
    fn one_shot_includes_subcommand() {
        let driver = CodexDriver {
            aegis_agent_name: None,
            runtime_engine: "external".into(),
            approval_mode: "suggest".into(),
            one_shot: true,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Process { args, .. } => {
                assert!(args.is_empty());
            }
            _ => panic!("expected Process strategy"),
        }
    }

    #[test]
    fn spawn_strategy_sets_aegis_env() {
        let driver = CodexDriver {
            aegis_agent_name: Some("codex-1".to_string()),
            runtime_engine: "external".into(),
            approval_mode: "full-auto".into(),
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Process { env, .. } => {
                assert!(env.contains(&("AEGIS_AGENT_NAME".to_string(), "codex-1".to_string())));
                assert!(env.iter().any(|(k, _)| k == "AEGIS_SOCKET_PATH"));
            }
            _ => panic!("expected Process strategy"),
        }
    }

    #[test]
    fn adapter_in_suggest_mode() {
        let driver = CodexDriver {
            aegis_agent_name: None,
            runtime_engine: "external".into(),
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
            runtime_engine: "external".into(),
            approval_mode: "full-auto".into(),
            one_shot: false,
            extra_args: vec![],
        };
        assert!(driver.create_adapter().is_none());
    }

    #[test]
    fn native_runtime_uses_wrapper_when_available() {
        let driver = CodexDriver {
            aegis_agent_name: None,
            runtime_engine: "native".into(),
            approval_mode: "suggest".into(),
            one_shot: false,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Process { command, env, .. } => {
                if command == "codex" {
                    assert!(
                        env.contains(&(
                            "AEGIS_CODEX_RUNTIME".to_string(),
                            "external-fallback".to_string()
                        )),
                        "native mode must mark external fallback when wrapper is unavailable"
                    );
                } else {
                    assert!(command.ends_with("scripts/coding-runtime-codex.sh"));
                    assert!(
                        env.contains(&("AEGIS_CODEX_RUNTIME".to_string(), "native".to_string()))
                    );
                }
            }
            _ => panic!("expected Process strategy"),
        }
    }
}
