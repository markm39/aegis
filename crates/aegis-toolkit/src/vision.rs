//! Vision utilities (OCR/template match stubs).

use crate::{ToolkitError, ToolkitResult};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OcrResult {
    pub text: String,
}

pub trait VisionProvider: Send + Sync {
    fn ocr(&self, _rgba: &[u8], _width: u32, _height: u32) -> ToolkitResult<OcrResult>;
}

/// Stub implementation for non-macOS builds.
pub struct UnavailableVision;

impl VisionProvider for UnavailableVision {
    fn ocr(&self, _rgba: &[u8], _width: u32, _height: u32) -> ToolkitResult<OcrResult> {
        Err(ToolkitError::Unavailable("vision not supported".into()))
    }
}
