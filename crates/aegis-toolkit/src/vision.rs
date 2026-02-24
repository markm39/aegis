//! Vision utilities for image analysis (OCR, object recognition stubs).

use crate::{ToolkitError, ToolkitResult};
use serde::{Deserialize, Serialize};

/// Result from OCR processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcrResult {
    pub text: String,
}

/// Result from image analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageAnalysisResult {
    /// Description of what was found in the image.
    pub description: String,
    /// Detected objects or regions of interest.
    pub objects: Vec<DetectedObject>,
    /// Whether the analysis was performed by a real backend or is a stub.
    pub is_stub: bool,
}

/// A detected object/region in an image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedObject {
    pub label: String,
    pub confidence: f32,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Trait for vision capabilities (OCR, image analysis).
pub trait VisionProvider: Send + Sync {
    /// Perform OCR on an RGBA image buffer.
    fn ocr(&self, rgba: &[u8], width: u32, height: u32) -> ToolkitResult<OcrResult>;

    /// Analyze an image for objects and content description.
    fn analyze_image(
        &self,
        rgba: &[u8],
        width: u32,
        height: u32,
    ) -> ToolkitResult<ImageAnalysisResult>;
}

/// Stub implementation that returns unavailable errors.
pub struct UnavailableVision;

impl VisionProvider for UnavailableVision {
    fn ocr(&self, _rgba: &[u8], _width: u32, _height: u32) -> ToolkitResult<OcrResult> {
        Err(ToolkitError::Unavailable("vision not supported".into()))
    }

    fn analyze_image(
        &self,
        _rgba: &[u8],
        _width: u32,
        _height: u32,
    ) -> ToolkitResult<ImageAnalysisResult> {
        Err(ToolkitError::Unavailable(
            "image analysis requires a vision backend (configure toolkit.vision in daemon.toml)"
                .into(),
        ))
    }
}

/// Stub implementation that returns placeholder results (for testing/development).
pub struct StubVision;

impl VisionProvider for StubVision {
    fn ocr(&self, _rgba: &[u8], _width: u32, _height: u32) -> ToolkitResult<OcrResult> {
        Ok(OcrResult {
            text: "[stub OCR result]".to_string(),
        })
    }

    fn analyze_image(
        &self,
        _rgba: &[u8],
        width: u32,
        height: u32,
    ) -> ToolkitResult<ImageAnalysisResult> {
        Ok(ImageAnalysisResult {
            description: format!("Stub analysis of {width}x{height} image"),
            objects: vec![],
            is_stub: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_vision_returns_error() {
        let v = UnavailableVision;
        assert!(v.ocr(&[], 0, 0).is_err());
        assert!(v.analyze_image(&[], 0, 0).is_err());
    }

    #[test]
    fn stub_vision_returns_placeholder() {
        let v = StubVision;
        let ocr = v.ocr(&[], 100, 100).unwrap();
        assert!(ocr.text.contains("stub"));

        let analysis = v.analyze_image(&[], 640, 480).unwrap();
        assert!(analysis.is_stub);
        assert!(analysis.description.contains("640x480"));
        assert!(analysis.objects.is_empty());
    }

    #[test]
    fn image_analysis_result_serialization() {
        let result = ImageAnalysisResult {
            description: "test".to_string(),
            objects: vec![DetectedObject {
                label: "button".to_string(),
                confidence: 0.95,
                x: 10,
                y: 20,
                width: 100,
                height: 50,
            }],
            is_stub: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ImageAnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.objects.len(), 1);
        assert_eq!(back.objects[0].label, "button");
    }
}
