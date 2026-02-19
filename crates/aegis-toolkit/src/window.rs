//! Window/app focus control interfaces.

use crate::{ToolkitError, ToolkitResult};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WindowRef {
    pub app_id: String,
    pub window_id: Option<u64>,
}

pub trait WindowProvider: Send + Sync {
    fn focus(&self, _req: &WindowRef) -> ToolkitResult<()>;
}

/// Stub implementation for non-macOS builds.
pub struct UnavailableWindow;

impl WindowProvider for UnavailableWindow {
    fn focus(&self, _req: &WindowRef) -> ToolkitResult<()> {
        Err(ToolkitError::Unavailable(
            "window control not supported".into(),
        ))
    }
}
