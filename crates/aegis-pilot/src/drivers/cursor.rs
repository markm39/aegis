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
use crate::driver::{AgentDriver, SpawnStrategy, TaskInjection};

/// Driver for Cursor editor (observe-only).
pub struct CursorDriver {
    pub assume_running: bool,
}

impl AgentDriver for CursorDriver {
    fn name(&self) -> &str {
        "Cursor"
    }

    fn spawn_strategy(&self, working_dir: &Path) -> SpawnStrategy {
        if self.assume_running {
            SpawnStrategy::External
        } else {
            SpawnStrategy::Process {
                command: "cursor".to_string(),
                args: vec![working_dir.to_string_lossy().to_string()],
                env: vec![],
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
        let driver = CursorDriver { assume_running: true };
        let strategy = driver.spawn_strategy(&PathBuf::from("/tmp"));
        assert!(matches!(strategy, SpawnStrategy::External));
    }

    #[test]
    fn spawn_process_when_not_running() {
        let driver = CursorDriver { assume_running: false };
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
    fn no_adapter() {
        let driver = CursorDriver { assume_running: true };
        assert!(driver.create_adapter().is_none());
    }

    #[test]
    fn no_task_injection() {
        let driver = CursorDriver { assume_running: true };
        assert!(matches!(driver.task_injection("anything"), TaskInjection::None));
    }

    #[test]
    fn not_headless() {
        let driver = CursorDriver { assume_running: true };
        assert!(!driver.supports_headless());
    }
}
