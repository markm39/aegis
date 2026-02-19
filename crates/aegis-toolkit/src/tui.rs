//! Terminal/TUI capture and input interfaces.

use crate::{ToolkitError, ToolkitResult};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TuiSnapshot {
    pub text: String,
    pub cursor: (u16, u16),
    pub size: (u16, u16),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TuiInput {
    pub text: String,
}

pub trait TuiProvider: Send + Sync {
    fn snapshot(&self, _session_id: &str) -> ToolkitResult<TuiSnapshot>;
    fn send_input(&self, _session_id: &str, _input: &TuiInput) -> ToolkitResult<()>;
}

/// Stub implementation for non-macOS builds.
pub struct UnavailableTui;

impl TuiProvider for UnavailableTui {
    fn snapshot(&self, _session_id: &str) -> ToolkitResult<TuiSnapshot> {
        Err(ToolkitError::Unavailable(
            "tui capture not supported".into(),
        ))
    }

    fn send_input(&self, _session_id: &str, _input: &TuiInput) -> ToolkitResult<()> {
        Err(ToolkitError::Unavailable("tui input not supported".into()))
    }
}
