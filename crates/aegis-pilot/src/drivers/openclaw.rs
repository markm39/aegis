//! OpenClaw driver.
//!
//! Spawns `openclaw agent` in a PTY with daemon-managed bridge env vars.
//! Task injection is via `--message` flag or stdin.

use std::path::Path;

use crate::adapter::AgentAdapter;
use crate::adapters::passthrough::PassthroughAdapter;
use crate::driver::{AgentDriver, SpawnStrategy, TaskInjection};

/// Driver for OpenClaw autonomous agent.
pub struct OpenClawDriver {
    /// Aegis agent name, set as AEGIS_AGENT_NAME env var so hooks can
    /// identify which agent is making the tool call.
    pub aegis_agent_name: Option<String>,
    /// OpenClaw's own `--name` agent name (distinct from Aegis agent name).
    pub agent_name: Option<String>,
    pub extra_args: Vec<String>,
}

impl AgentDriver for OpenClawDriver {
    fn name(&self) -> &str {
        "OpenClaw"
    }

    fn spawn_strategy(&self, working_dir: &Path) -> SpawnStrategy {
        let mut args = vec!["agent".to_string()];

        if let Some(name) = &self.agent_name {
            args.push("--name".to_string());
            args.push(name.clone());
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
        let bridge_config = working_dir
            .join(".aegis")
            .join("openclaw")
            .join("openclaw.json");
        let bridge_marker = working_dir
            .join(".aegis")
            .join("openclaw")
            .join("bridge.json");
        env.push((
            "OPENCLAW_CONFIG_PATH".to_string(),
            bridge_config.to_string_lossy().into_owned(),
        ));
        env.push((
            "AEGIS_OPENCLAW_BRIDGE_REQUIRED".to_string(),
            "1".to_string(),
        ));
        env.push((
            "AEGIS_OPENCLAW_BRIDGE_MARKER".to_string(),
            bridge_marker.to_string_lossy().into_owned(),
        ));

        SpawnStrategy::Pty {
            command: "openclaw".to_string(),
            args,
            env,
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
            aegis_agent_name: None,
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
            aegis_agent_name: None,
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
    fn spawn_sets_aegis_env() {
        let driver = OpenClawDriver {
            aegis_agent_name: Some("oc-1".to_string()),
            agent_name: None,
            extra_args: vec![],
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Pty { env, .. } => {
                assert!(env.contains(&("AEGIS_AGENT_NAME".to_string(), "oc-1".to_string())));
                assert!(env.iter().any(|(k, _)| k == "AEGIS_SOCKET_PATH"));
            }
            _ => panic!("expected Pty strategy"),
        }
    }

    #[test]
    fn adapter_is_passthrough() {
        let driver = OpenClawDriver {
            aegis_agent_name: None,
            agent_name: None,
            extra_args: vec![],
        };
        let adapter = driver.create_adapter().unwrap();
        assert_eq!(adapter.name(), "Passthrough");
    }

    #[test]
    fn task_injection_via_flag() {
        let driver = OpenClawDriver {
            aegis_agent_name: None,
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

    #[test]
    fn spawn_sets_openclaw_bridge_env() {
        let driver = OpenClawDriver {
            aegis_agent_name: Some("oc-2".to_string()),
            agent_name: Some("builder".to_string()),
            extra_args: vec![],
        };
        let workdir = PathBuf::from("/tmp/workspace");
        let strategy = driver.spawn_strategy(&workdir);
        match strategy {
            SpawnStrategy::Pty { env, .. } => {
                assert!(env.iter().any(|(k, _)| k == "OPENCLAW_CONFIG_PATH"));
                assert!(env
                    .iter()
                    .any(|(k, v)| k == "AEGIS_OPENCLAW_BRIDGE_REQUIRED" && v == "1"));
                assert!(env.iter().any(|(k, _)| k == "AEGIS_OPENCLAW_BRIDGE_MARKER"));
            }
            _ => panic!("expected Pty strategy"),
        }
    }
}
