//! Input injection interfaces (mouse/keyboard).

use crate::{InputLatency, ToolkitError, ToolkitResult};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MouseMove {
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MouseClick {
    pub x: i32,
    pub y: i32,
    pub button: MouseButton,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyPress {
    pub key: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TypeText {
    pub text: String,
}

pub trait InputProvider: Send + Sync {
    fn move_mouse(&self, _req: &MouseMove) -> ToolkitResult<InputLatency>;
    fn click_mouse(&self, _req: &MouseClick) -> ToolkitResult<InputLatency>;
    fn key_press(&self, _req: &KeyPress) -> ToolkitResult<InputLatency>;
    fn type_text(&self, _req: &TypeText) -> ToolkitResult<InputLatency>;
}

/// Stub implementation for non-macOS builds.
pub struct UnavailableInput;

impl InputProvider for UnavailableInput {
    fn move_mouse(&self, _req: &MouseMove) -> ToolkitResult<InputLatency> {
        Err(ToolkitError::Unavailable("input not supported".into()))
    }

    fn click_mouse(&self, _req: &MouseClick) -> ToolkitResult<InputLatency> {
        Err(ToolkitError::Unavailable("input not supported".into()))
    }

    fn key_press(&self, _req: &KeyPress) -> ToolkitResult<InputLatency> {
        Err(ToolkitError::Unavailable("input not supported".into()))
    }

    fn type_text(&self, _req: &TypeText) -> ToolkitResult<InputLatency> {
        Err(ToolkitError::Unavailable("input not supported".into()))
    }
}
