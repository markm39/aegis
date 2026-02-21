//! Element-level screenshot support with CSS selector targeting and configurable format.
//!
//! Builds CDP `Page.captureScreenshot` parameters and validates inputs. Does NOT
//! perform actual CDP communication -- that is the caller's responsibility.
//!
//! Security properties:
//! - CSS selectors validated against injection attacks
//! - Screenshot data size limited (50 MB raw)
//! - Dimension limits enforced (max 4096x4096)
//! - Only png/jpeg formats accepted
//! - JPEG quality range validated (1-100)

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum raw screenshot data size: 50 MB.
const MAX_SCREENSHOT_BYTES: usize = 50 * 1024 * 1024;

/// Maximum dimension in either axis.
const MAX_DIMENSION: u32 = 4096;

/// Maximum CSS selector length.
const MAX_SELECTOR_LEN: usize = 1000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned during screenshot parameter building or validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScreenshotError {
    #[error("invalid screenshot format: {0}")]
    InvalidFormat(String),

    #[error("JPEG quality must be 1-100, got {0}")]
    InvalidJpegQuality(u8),

    #[error("selector too long: {len} chars (max {MAX_SELECTOR_LEN})")]
    SelectorTooLong { len: usize },

    #[error("selector contains forbidden pattern: {pattern}")]
    SelectorInjection { pattern: String },

    #[error("selector contains control characters")]
    SelectorControlChars,

    #[error("screenshot data exceeds {MAX_SCREENSHOT_BYTES} byte limit: {size} bytes")]
    DataTooLarge { size: usize },

    #[error("dimension {axis} = {value} exceeds max {MAX_DIMENSION}")]
    DimensionTooLarge { axis: &'static str, value: u32 },
}

// ---------------------------------------------------------------------------
// Format
// ---------------------------------------------------------------------------

/// Supported screenshot image formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ScreenshotFormat {
    Png,
    Jpeg { quality: u8 },
}

impl ScreenshotFormat {
    /// MIME type for this format.
    pub fn mime_type(&self) -> &str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg { .. } => "image/jpeg",
        }
    }

    /// File extension (without leading dot).
    pub fn extension(&self) -> &str {
        match self {
            Self::Png => "png",
            Self::Jpeg { .. } => "jpg",
        }
    }

    /// Parse from a string like "png", "jpeg", or "jpg".
    ///
    /// For JPEG, defaults to quality 80 when parsed from a bare string.
    /// Use `ScreenshotFormat::Jpeg { quality }` directly when you need a
    /// specific quality value.
    pub fn parse(s: &str) -> Result<Self, ScreenshotError> {
        match s.to_ascii_lowercase().as_str() {
            "png" => Ok(Self::Png),
            "jpeg" | "jpg" => Ok(Self::Jpeg { quality: 80 }),
            other => Err(ScreenshotError::InvalidFormat(other.to_string())),
        }
    }

    /// Validate the format parameters. Returns an error if JPEG quality is
    /// outside the 1-100 range.
    pub fn validate(&self) -> Result<(), ScreenshotError> {
        if let Self::Jpeg { quality } = self {
            if *quality == 0 || *quality > 100 {
                return Err(ScreenshotError::InvalidJpegQuality(*quality));
            }
        }
        Ok(())
    }
}

impl std::str::FromStr for ScreenshotFormat {
    type Err = ScreenshotError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Default for ScreenshotFormat {
    fn default() -> Self {
        Self::Png
    }
}

// ---------------------------------------------------------------------------
// Bounding box
// ---------------------------------------------------------------------------

/// A rectangle in CSS pixels, used for element-level clipping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundingBox {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

// ---------------------------------------------------------------------------
// Config / Request / Result
// ---------------------------------------------------------------------------

/// High-level screenshot configuration with sensible defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotConfig {
    pub format: ScreenshotFormat,
    pub max_width: u32,
    pub max_height: u32,
    pub clip_to_element: bool,
}

impl Default for ScreenshotConfig {
    fn default() -> Self {
        Self {
            format: ScreenshotFormat::Png,
            max_width: 1920,
            max_height: 1080,
            clip_to_element: true,
        }
    }
}

/// A validated screenshot request ready for CDP parameter building.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotRequest {
    pub selector: Option<String>,
    pub format: ScreenshotFormat,
    pub full_page: bool,
}

/// The result of a screenshot capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotResult {
    /// Raw image bytes.
    pub data: Vec<u8>,
    /// Format of the image.
    pub format: ScreenshotFormat,
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Whether the targeted element was found (true when no selector was used).
    pub element_found: bool,
    /// Base64-encoded image data.
    pub data_base64: String,
}

// ---------------------------------------------------------------------------
// Selector validation
// ---------------------------------------------------------------------------

/// Validate a CSS selector string for safety.
///
/// Rejects:
/// - Selectors longer than 1000 characters
/// - Selectors containing `javascript:` or `expression(` (case-insensitive)
/// - Selectors containing `url(` (can reference external resources)
/// - Selectors containing backslash escapes (used in injection attacks)
/// - Selectors containing control characters (U+0000..U+001F, U+007F)
///
/// This is a defense-in-depth measure. The selector is passed to
/// `document.querySelector()` in the browser, which itself only accepts CSS
/// selectors, but we strip obviously malicious payloads before they reach the
/// browser.
pub fn validate_selector(selector: &str) -> Result<String, ScreenshotError> {
    // Strip control characters first.
    let cleaned: String = selector
        .chars()
        .filter(|c| !c.is_control())
        .collect();

    if cleaned.len() != selector.len() {
        return Err(ScreenshotError::SelectorControlChars);
    }

    // Length check.
    if selector.len() > MAX_SELECTOR_LEN {
        return Err(ScreenshotError::SelectorTooLong {
            len: selector.len(),
        });
    }

    let lower = selector.to_ascii_lowercase();

    // Reject javascript: protocol in any position.
    if lower.contains("javascript:") {
        return Err(ScreenshotError::SelectorInjection {
            pattern: "javascript:".to_string(),
        });
    }

    // Reject CSS expression() -- IE legacy, but still a vector.
    if lower.contains("expression(") {
        return Err(ScreenshotError::SelectorInjection {
            pattern: "expression(".to_string(),
        });
    }

    // Reject url() references.
    if lower.contains("url(") {
        return Err(ScreenshotError::SelectorInjection {
            pattern: "url(".to_string(),
        });
    }

    // Reject backslash escapes (used to smuggle characters).
    if selector.contains('\\') {
        return Err(ScreenshotError::SelectorInjection {
            pattern: "backslash escape".to_string(),
        });
    }

    // Reject `<` -- never valid in CSS selectors, indicates HTML injection.
    // Note: `>` is a valid CSS child combinator (e.g., `div > p`), so we only
    // block the opening angle bracket.
    if selector.contains('<') {
        return Err(ScreenshotError::SelectorInjection {
            pattern: "HTML angle bracket".to_string(),
        });
    }

    Ok(selector.to_string())
}

// ---------------------------------------------------------------------------
// Dimension / size validation
// ---------------------------------------------------------------------------

/// Validate that dimensions are within allowed limits.
pub fn validate_dimensions(width: u32, height: u32) -> Result<(), ScreenshotError> {
    if width > MAX_DIMENSION {
        return Err(ScreenshotError::DimensionTooLarge {
            axis: "width",
            value: width,
        });
    }
    if height > MAX_DIMENSION {
        return Err(ScreenshotError::DimensionTooLarge {
            axis: "height",
            value: height,
        });
    }
    Ok(())
}

/// Validate that raw screenshot data does not exceed the size limit.
pub fn validate_data_size(data: &[u8]) -> Result<(), ScreenshotError> {
    if data.len() > MAX_SCREENSHOT_BYTES {
        return Err(ScreenshotError::DataTooLarge { size: data.len() });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CDP parameter building
// ---------------------------------------------------------------------------

/// Build CDP `Page.captureScreenshot` parameters from a request and optional
/// bounding box.
///
/// The returned JSON object can be sent directly as the `params` field of the
/// CDP command. Structure:
///
/// ```json
/// {
///   "format": "png" | "jpeg",
///   "quality": 80,           // only for jpeg
///   "clip": { ... }          // only when bounding_box is provided
/// }
/// ```
pub fn build_capture_params(
    request: &ScreenshotRequest,
    bounding_box: Option<BoundingBox>,
) -> Result<serde_json::Value, ScreenshotError> {
    // Validate format.
    request.format.validate()?;

    // Validate selector if present.
    if let Some(ref sel) = request.selector {
        validate_selector(sel)?;
    }

    let mut params = serde_json::Map::new();

    // Format.
    match &request.format {
        ScreenshotFormat::Png => {
            params.insert("format".into(), serde_json::Value::String("png".into()));
        }
        ScreenshotFormat::Jpeg { quality } => {
            params.insert("format".into(), serde_json::Value::String("jpeg".into()));
            params.insert("quality".into(), serde_json::Value::Number((*quality).into()));
        }
    }

    // Clip region from bounding box.
    if let Some(bbox) = bounding_box {
        let clip = serde_json::json!({
            "x": bbox.x,
            "y": bbox.y,
            "width": bbox.width,
            "height": bbox.height,
            "scale": 1.0
        });
        params.insert("clip".into(), clip);
    } else if request.full_page {
        // For full-page screenshots, CDP uses captureBeyondViewport.
        params.insert(
            "captureBeyondViewport".into(),
            serde_json::Value::Bool(true),
        );
    }

    Ok(serde_json::Value::Object(params))
}

// ---------------------------------------------------------------------------
// Result encoding
// ---------------------------------------------------------------------------

/// Encode raw screenshot bytes into a [`ScreenshotResult`].
///
/// Validates data size and dimensions before encoding. The `width` and `height`
/// parameters are caller-provided (e.g., from CDP response metadata or image
/// header parsing).
pub fn encode_screenshot(
    data: &[u8],
    format: &ScreenshotFormat,
    width: u32,
    height: u32,
    element_found: bool,
) -> Result<ScreenshotResult, ScreenshotError> {
    validate_data_size(data)?;
    validate_dimensions(width, height)?;
    format.validate()?;

    let data_base64 = B64.encode(data);

    Ok(ScreenshotResult {
        data: data.to_vec(),
        format: format.clone(),
        width,
        height,
        element_found,
        data_base64,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CDP parameter building --

    #[test]
    fn test_build_capture_params_png() {
        let request = ScreenshotRequest {
            selector: None,
            format: ScreenshotFormat::Png,
            full_page: false,
        };
        let params = build_capture_params(&request, None).unwrap();
        assert_eq!(params["format"], "png");
        assert!(params.get("quality").is_none());
        assert!(params.get("clip").is_none());
    }

    #[test]
    fn test_build_capture_params_jpeg_with_quality() {
        let request = ScreenshotRequest {
            selector: None,
            format: ScreenshotFormat::Jpeg { quality: 90 },
            full_page: false,
        };
        let params = build_capture_params(&request, None).unwrap();
        assert_eq!(params["format"], "jpeg");
        assert_eq!(params["quality"], 90);
    }

    #[test]
    fn test_build_capture_params_with_clip() {
        let request = ScreenshotRequest {
            selector: Some("#main-content".to_string()),
            format: ScreenshotFormat::Png,
            full_page: false,
        };
        let bbox = BoundingBox {
            x: 10.0,
            y: 20.0,
            width: 800.0,
            height: 600.0,
        };
        let params = build_capture_params(&request, Some(bbox)).unwrap();
        assert_eq!(params["format"], "png");
        let clip = &params["clip"];
        assert_eq!(clip["x"], 10.0);
        assert_eq!(clip["y"], 20.0);
        assert_eq!(clip["width"], 800.0);
        assert_eq!(clip["height"], 600.0);
        assert_eq!(clip["scale"], 1.0);
    }

    #[test]
    fn test_build_capture_params_full_page() {
        let request = ScreenshotRequest {
            selector: None,
            format: ScreenshotFormat::Png,
            full_page: true,
        };
        let params = build_capture_params(&request, None).unwrap();
        assert_eq!(params["captureBeyondViewport"], true);
    }

    #[test]
    fn test_build_capture_params_clip_overrides_full_page() {
        // When a bounding box is provided, clip takes precedence over full_page.
        let request = ScreenshotRequest {
            selector: Some("div.hero".to_string()),
            format: ScreenshotFormat::Jpeg { quality: 75 },
            full_page: true,
        };
        let bbox = BoundingBox {
            x: 0.0,
            y: 0.0,
            width: 500.0,
            height: 300.0,
        };
        let params = build_capture_params(&request, Some(bbox)).unwrap();
        assert!(params.get("clip").is_some());
        assert!(params.get("captureBeyondViewport").is_none());
    }

    // -- Format parsing --

    #[test]
    fn test_screenshot_format_from_str() {
        assert_eq!(ScreenshotFormat::parse("png").unwrap(), ScreenshotFormat::Png);
        assert_eq!(
            ScreenshotFormat::parse("jpeg").unwrap(),
            ScreenshotFormat::Jpeg { quality: 80 }
        );
        assert_eq!(
            ScreenshotFormat::parse("jpg").unwrap(),
            ScreenshotFormat::Jpeg { quality: 80 }
        );
        assert_eq!(
            ScreenshotFormat::parse("PNG").unwrap(),
            ScreenshotFormat::Png
        );
        assert!(ScreenshotFormat::parse("gif").is_err());
        assert!(ScreenshotFormat::parse("webp").is_err());
        assert!(ScreenshotFormat::parse("").is_err());

        // Also verify std::str::FromStr works.
        assert_eq!("png".parse::<ScreenshotFormat>().unwrap(), ScreenshotFormat::Png);
        assert!("bmp".parse::<ScreenshotFormat>().is_err());
    }

    #[test]
    fn test_screenshot_format_mime_type() {
        assert_eq!(ScreenshotFormat::Png.mime_type(), "image/png");
        assert_eq!(
            ScreenshotFormat::Jpeg { quality: 80 }.mime_type(),
            "image/jpeg"
        );
    }

    #[test]
    fn test_screenshot_format_extension() {
        assert_eq!(ScreenshotFormat::Png.extension(), "png");
        assert_eq!(ScreenshotFormat::Jpeg { quality: 80 }.extension(), "jpg");
    }

    // -- JPEG quality validation --

    #[test]
    fn test_jpeg_quality_validation() {
        // Valid range.
        assert!(ScreenshotFormat::Jpeg { quality: 1 }.validate().is_ok());
        assert!(ScreenshotFormat::Jpeg { quality: 50 }.validate().is_ok());
        assert!(ScreenshotFormat::Jpeg { quality: 100 }.validate().is_ok());

        // Invalid: 0.
        assert!(matches!(
            ScreenshotFormat::Jpeg { quality: 0 }.validate(),
            Err(ScreenshotError::InvalidJpegQuality(0))
        ));

        // PNG always valid.
        assert!(ScreenshotFormat::Png.validate().is_ok());
    }

    #[test]
    fn test_jpeg_quality_zero_rejected_in_params() {
        let request = ScreenshotRequest {
            selector: None,
            format: ScreenshotFormat::Jpeg { quality: 0 },
            full_page: false,
        };
        assert!(build_capture_params(&request, None).is_err());
    }

    // -- Selector validation --

    #[test]
    fn test_selector_validation_accepts_valid() {
        // Simple selectors.
        assert!(validate_selector("#my-element").is_ok());
        assert!(validate_selector(".class-name").is_ok());
        assert!(validate_selector("div").is_ok());
        assert!(validate_selector("div > p.intro").is_ok());
        assert!(validate_selector("[data-testid=\"main\"]").is_ok());
        assert!(validate_selector("ul li:nth-child(2)").is_ok());
        assert!(validate_selector("h1, h2, h3").is_ok());
        assert!(validate_selector("div.container > section:first-child").is_ok());
    }

    #[test]
    fn test_selector_validation_rejects_injection() {
        // javascript: protocol injection.
        assert!(matches!(
            validate_selector("javascript:alert(1)"),
            Err(ScreenshotError::SelectorInjection { pattern }) if pattern == "javascript:"
        ));

        // Case-insensitive javascript: detection.
        assert!(validate_selector("JAVASCRIPT:void(0)").is_err());
        assert!(validate_selector("JaVaScRiPt:alert(1)").is_err());

        // expression() injection (IE legacy).
        assert!(matches!(
            validate_selector("div{expression(alert(1))}"),
            Err(ScreenshotError::SelectorInjection { pattern }) if pattern == "expression("
        ));

        // url() reference.
        assert!(validate_selector("div{background:url(http://evil.com/img.png)}").is_err());

        // Backslash escapes.
        assert!(validate_selector("div\\{color:red\\}").is_err());

        // HTML angle brackets (< is never valid in CSS selectors).
        assert!(validate_selector("<script>alert(1)</script>").is_err());
        assert!(validate_selector("<img src=x onerror=alert(1)>").is_err());
    }

    #[test]
    fn test_selector_validation_rejects_too_long() {
        let long = "a".repeat(1001);
        assert!(matches!(
            validate_selector(&long),
            Err(ScreenshotError::SelectorTooLong { len: 1001 })
        ));

        // Exactly at limit is fine.
        let at_limit = "a".repeat(1000);
        assert!(validate_selector(&at_limit).is_ok());
    }

    // -- Security: dimensions --

    #[test]
    fn security_test_max_dimensions_enforced() {
        // At limit: OK.
        assert!(validate_dimensions(4096, 4096).is_ok());

        // Over limit: rejected.
        assert!(matches!(
            validate_dimensions(4097, 1080),
            Err(ScreenshotError::DimensionTooLarge { axis: "width", value: 4097 })
        ));
        assert!(matches!(
            validate_dimensions(1920, 4097),
            Err(ScreenshotError::DimensionTooLarge { axis: "height", value: 4097 })
        ));

        // Both over.
        assert!(validate_dimensions(5000, 5000).is_err());
    }

    #[test]
    fn security_test_max_data_size_enforced() {
        // Exactly at limit: OK.
        let data = vec![0u8; MAX_SCREENSHOT_BYTES];
        assert!(validate_data_size(&data).is_ok());

        // Over limit: rejected.
        let big = vec![0u8; MAX_SCREENSHOT_BYTES + 1];
        assert!(matches!(
            validate_data_size(&big),
            Err(ScreenshotError::DataTooLarge { .. })
        ));
    }

    // -- Security: control characters --

    #[test]
    fn security_test_control_chars_stripped() {
        // Null byte.
        assert!(matches!(
            validate_selector("div\0.class"),
            Err(ScreenshotError::SelectorControlChars)
        ));

        // Tab.
        assert!(matches!(
            validate_selector("div\t.class"),
            Err(ScreenshotError::SelectorControlChars)
        ));

        // Newline.
        assert!(matches!(
            validate_selector("div\n.class"),
            Err(ScreenshotError::SelectorControlChars)
        ));

        // Carriage return.
        assert!(matches!(
            validate_selector("div\r.class"),
            Err(ScreenshotError::SelectorControlChars)
        ));

        // DEL (U+007F).
        assert!(matches!(
            validate_selector("div\x7f.class"),
            Err(ScreenshotError::SelectorControlChars)
        ));
    }

    // -- Result encoding --

    #[test]
    fn test_encode_screenshot_basic() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = encode_screenshot(&data, &ScreenshotFormat::Png, 100, 100, true).unwrap();
        assert_eq!(result.data, data);
        assert_eq!(result.width, 100);
        assert_eq!(result.height, 100);
        assert!(result.element_found);
        assert_eq!(result.format, ScreenshotFormat::Png);
        // Verify base64 round-trips.
        let decoded = B64.decode(&result.data_base64).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_screenshot_rejects_oversized() {
        let data = vec![0u8; MAX_SCREENSHOT_BYTES + 1];
        assert!(encode_screenshot(&data, &ScreenshotFormat::Png, 100, 100, true).is_err());
    }

    #[test]
    fn test_encode_screenshot_rejects_bad_dimensions() {
        let data = vec![0u8; 100];
        assert!(encode_screenshot(&data, &ScreenshotFormat::Png, 5000, 100, true).is_err());
    }

    #[test]
    fn test_encode_screenshot_rejects_bad_quality() {
        let data = vec![0u8; 100];
        assert!(
            encode_screenshot(&data, &ScreenshotFormat::Jpeg { quality: 0 }, 100, 100, true)
                .is_err()
        );
    }
}
