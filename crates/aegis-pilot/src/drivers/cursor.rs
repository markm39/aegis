//! Cursor driver.
//!
//! Cursor is a GUI-based editor. When `assume_running` is true, Aegis
//! does not spawn anything -- it just observes the filesystem via the
//! observer. When false, it launches the Cursor application.
//!
//! Cursor's beta CLI (`cursor-agent`) has limited programmatic control,
//! so this driver is primarily observe-only.

use std::path::Path;

use crate::adapter::AgentAdapter;
use crate::driver::{AgentDriver, ProcessKind, SpawnStrategy, TaskInjection};

/// Driver for Cursor editor.
///
/// When `assume_running` is true, Aegis does not spawn anything -- it just
/// observes the filesystem. When false, it launches the Cursor application.
/// In both cases, hook settings are installed for policy enforcement.
pub struct CursorDriver {
    /// Aegis agent name, set as AEGIS_AGENT_NAME env var so hooks can
    /// identify which agent is making the tool call.
    pub aegis_agent_name: Option<String>,
    pub assume_running: bool,
}

impl AgentDriver for CursorDriver {
    fn name(&self) -> &str {
        "Cursor"
    }

    fn spawn_strategy(&self, working_dir: &Path) -> SpawnStrategy {
        let mut env = Vec::new();
        if let Some(ref name) = self.aegis_agent_name {
            env.push(("AEGIS_AGENT_NAME".to_string(), name.clone()));
        }
        let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");
        env.push((
            "AEGIS_SOCKET_PATH".to_string(),
            socket_path.to_string_lossy().into_owned(),
        ));

        if self.assume_running {
            SpawnStrategy::External
        } else {
            SpawnStrategy::Process {
                command: "cursor".to_string(),
                args: vec![working_dir.to_string_lossy().to_string()],
                env,
                kind: ProcessKind::Detached,
            }
        }
    }

    fn create_adapter(&self) -> Option<Box<dyn AgentAdapter>> {
        // No PTY prompt detection for Cursor (GUI-based)
        None
    }

    fn task_injection(&self, _task: &str) -> TaskInjection {
        // Cursor is GUI-based; task injection is manual
        TaskInjection::None
    }

    fn supports_headless(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn spawn_external_when_assumed_running() {
        let driver = CursorDriver { aegis_agent_name: None, assume_running: true };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        assert!(matches!(strategy, SpawnStrategy::External));
    }

    #[test]
    fn spawn_process_when_not_running() {
        let driver = CursorDriver { aegis_agent_name: None, assume_running: false };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp/project"));
        match strategy {
            SpawnStrategy::Process { command, args, .. } => {
                assert_eq!(command, "cursor");
                assert!(args[0].contains("project"));
            }
            _ => panic!("expected Process strategy"),
        }
    }

    #[test]
    fn spawn_sets_aegis_env() {
        let driver = CursorDriver {
            aegis_agent_name: Some("cursor-1".to_string()),
            assume_running: false,
        };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        match strategy {
            SpawnStrategy::Process { env, .. } => {
                assert!(env.contains(&("AEGIS_AGENT_NAME".to_string(), "cursor-1".to_string())));
                assert!(env.iter().any(|(k, _)| k == "AEGIS_SOCKET_PATH"));
            }
            _ => panic!("expected Process strategy"),
        }
    }

    #[test]
    fn no_adapter() {
        let driver = CursorDriver { aegis_agent_name: None, assume_running: true };
        assert!(driver.create_adapter().is_none());
    }

    #[test]
    fn no_task_injection() {
        let driver = CursorDriver { aegis_agent_name: None, assume_running: true };
        assert!(matches!(driver.task_injection("anything"), TaskInjection::None));
    }

    #[test]
    fn not_headless() {
        let driver = CursorDriver { aegis_agent_name: None, assume_running: true };
        assert!(!driver.supports_headless());
    }
}
