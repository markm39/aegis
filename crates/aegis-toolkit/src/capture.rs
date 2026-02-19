//! Screen/window capture interfaces.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{CaptureFrame, FrameMetadata, ToolkitError, ToolkitResult};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaptureRequest {
    pub target_fps: u32,
    pub region: Option<Region>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Region {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

pub trait CaptureProvider: Send + Sync {
    fn start(&self, _request: &CaptureRequest) -> ToolkitResult<()>;
    fn next_frame(&self) -> ToolkitResult<CaptureFrame>;
    fn stop(&self) -> ToolkitResult<()>;
}

/// Stub implementation for non-macOS builds.
pub struct UnavailableCapture;

impl CaptureProvider for UnavailableCapture {
    fn start(&self, _request: &CaptureRequest) -> ToolkitResult<()> {
        Err(ToolkitError::Unavailable("capture not supported".into()))
    }

    fn next_frame(&self) -> ToolkitResult<CaptureFrame> {
        Err(ToolkitError::Unavailable("capture not supported".into()))
    }

    fn stop(&self) -> ToolkitResult<()> {
        Ok(())
    }
}

/// Helper for creating a placeholder frame (useful in tests/mocks).
pub fn make_placeholder_frame(width: u32, height: u32) -> CaptureFrame {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    CaptureFrame {
        metadata: FrameMetadata {
            width,
            height,
            timestamp_ms: ts.as_millis(),
            frame_id: ts.as_millis() as u64,
        },
        rgba: vec![0; (width * height * 4) as usize],
    }
}
