//! Image understanding with format validation and security scanning.
//!
//! Provides image processing capabilities for images received through messaging
//! channels. All processing enforces strict security invariants:
//!
//! - **Size limits** are checked before any parsing or processing.
//! - **Magic byte detection** verifies actual format (never trusts extensions).
//! - **SVG is always rejected** (can embed scripts and XSS payloads).
//! - **SHA-256 hashing** provides an audit trail; raw pixel data is never logged.
//! - **Cedar policy evaluation** gates processing via `ImageProcess` action.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// ImageFormat
// ---------------------------------------------------------------------------

/// Recognized image formats, detected by magic byte inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// PNG: 8-byte signature starting with `\x89PNG`.
    Png,
    /// JPEG: starts with `\xFF\xD8\xFF`.
    Jpeg,
    /// GIF: starts with `GIF87a` or `GIF89a`.
    Gif,
    /// WebP: RIFF container with `WEBP` chunk.
    Webp,
    /// Format not recognized -- will be rejected by validation.
    Unknown,
}

impl ImageFormat {
    /// Human-readable lowercase name suitable for audit logs.
    pub fn as_str(self) -> &'static str {
        match self {
            ImageFormat::Png => "png",
            ImageFormat::Jpeg => "jpeg",
            ImageFormat::Gif => "gif",
            ImageFormat::Webp => "webp",
            ImageFormat::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ImageConfig
// ---------------------------------------------------------------------------

/// Configuration for the image processor.
///
/// Controls size limits, allowed formats, and optional OCR/vision features.
#[derive(Debug, Clone)]
pub struct ImageConfig {
    /// Maximum allowed image size in bytes. Data exceeding this limit is
    /// rejected before any processing occurs. Default: 10 MB.
    pub max_size_bytes: u64,
    /// Set of formats that are permitted. Default: PNG, JPEG, GIF, WebP.
    pub allowed_formats: Vec<ImageFormat>,
    /// Whether OCR text extraction is enabled. Default: false.
    pub enable_ocr: bool,
    /// Vision model identifier for `describe_image`. Default: empty string
    /// (placeholder -- no external API is called).
    pub vision_model: String,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 10 * 1024 * 1024, // 10 MB
            allowed_formats: vec![
                ImageFormat::Png,
                ImageFormat::Jpeg,
                ImageFormat::Gif,
                ImageFormat::Webp,
            ],
            enable_ocr: false,
            vision_model: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ImageMetadata
// ---------------------------------------------------------------------------

/// Metadata extracted from a validated image.
///
/// This struct is safe to log and store in the audit trail -- it contains
/// no raw image data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageMetadata {
    /// Detected image format.
    pub format: ImageFormat,
    /// Image width in pixels (0 if not determinable from header).
    pub width: u32,
    /// Image height in pixels (0 if not determinable from header).
    pub height: u32,
    /// Size of the raw image data in bytes.
    pub size_bytes: u64,
    /// SHA-256 hex digest of the raw image data.
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// ImageProcessor
// ---------------------------------------------------------------------------

/// Validates, hashes, and processes image data.
///
/// All public methods enforce the configured security invariants before
/// performing any work.
pub struct ImageProcessor {
    config: ImageConfig,
}

impl ImageProcessor {
    /// Create a new processor with the given configuration.
    pub fn new(config: ImageConfig) -> Self {
        Self { config }
    }

    /// Detect the image format by inspecting magic bytes.
    ///
    /// This never trusts file extensions. The detection is performed on the
    /// first few bytes of the data and is safe to call on untrusted input.
    pub fn detect_content_type(&self, data: &[u8]) -> Result<ImageFormat, String> {
        if data.is_empty() {
            return Err("image data is empty".to_string());
        }
        Ok(detect_format_from_magic_bytes(data))
    }

    /// Validate image data against configured limits and format restrictions.
    ///
    /// Checks (in order):
    /// 1. Data is non-empty.
    /// 2. Size does not exceed `max_size_bytes`.
    /// 3. SVG content is rejected (checks both magic bytes and XML markers).
    /// 4. Format is recognized (not `Unknown`).
    /// 5. Format is in the `allowed_formats` list.
    ///
    /// On success, returns [`ImageMetadata`] including a SHA-256 content hash.
    pub fn validate_image(&self, data: &[u8]) -> Result<ImageMetadata, String> {
        // 1. Reject empty data.
        if data.is_empty() {
            return Err("image data is empty".to_string());
        }

        // 2. Enforce size limit BEFORE any further processing.
        let size = data.len() as u64;
        if size > self.config.max_size_bytes {
            return Err(format!(
                "image size {} bytes exceeds maximum {} bytes",
                size, self.config.max_size_bytes
            ));
        }

        // 3. Reject SVG unconditionally (can contain embedded scripts/XSS).
        if is_svg(data) {
            return Err(
                "SVG format is rejected for security reasons (may contain embedded scripts)"
                    .to_string(),
            );
        }

        // 4. Detect format from magic bytes.
        let format = detect_format_from_magic_bytes(data);
        if format == ImageFormat::Unknown {
            return Err(
                "unrecognized image format (magic bytes do not match any supported format)"
                    .to_string(),
            );
        }

        // 5. Check format is allowed.
        if !self.config.allowed_formats.contains(&format) {
            return Err(format!(
                "image format '{}' is not in the allowed formats list",
                format
            ));
        }

        // Compute SHA-256 hash for audit trail.
        let content_hash = compute_sha256(data);

        // Extract dimensions from header (best-effort, returns 0x0 if unreadable).
        let (width, height) = extract_dimensions(data, format);

        Ok(ImageMetadata {
            format,
            width,
            height,
            size_bytes: size,
            content_hash,
        })
    }

    /// Extract text from an image via OCR (placeholder).
    ///
    /// Returns `Ok(None)` unless an external OCR backend is configured.
    /// When OCR is enabled, the returned text is sanitized to remove
    /// control characters.
    pub fn extract_text(&self, data: &[u8]) -> Result<Option<String>, String> {
        // Validate first -- ensures size/format checks are enforced.
        let _meta = self.validate_image(data)?;

        if !self.config.enable_ocr {
            return Ok(None);
        }

        // Placeholder: no external OCR backend wired yet.
        // When implemented, sanitize extracted text before returning:
        // Ok(Some(sanitize_extracted_text(&raw_text)))
        Ok(None)
    }

    /// Describe an image using a vision model (placeholder).
    ///
    /// Returns a structured description string. Currently returns a
    /// placeholder response since no external vision API is wired.
    pub fn describe_image(&self, data: &[u8], prompt: &str) -> Result<String, String> {
        let meta = self.validate_image(data)?;

        // Placeholder: no external vision API call.
        Ok(format!(
            "Image description placeholder: format={}, size={} bytes, hash={}, prompt='{}'",
            meta.format,
            meta.size_bytes,
            meta.content_hash,
            sanitize_prompt(prompt),
        ))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Detect image format from the first bytes of data (magic bytes).
fn detect_format_from_magic_bytes(data: &[u8]) -> ImageFormat {
    if data.len() >= 8 && data[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        ImageFormat::Png
    } else if data.len() >= 3 && data[..3] == [0xFF, 0xD8, 0xFF] {
        ImageFormat::Jpeg
    } else if data.len() >= 6 && (data[..6] == *b"GIF87a" || data[..6] == *b"GIF89a") {
        ImageFormat::Gif
    } else if data.len() >= 12 && data[..4] == *b"RIFF" && data[8..12] == *b"WEBP" {
        ImageFormat::Webp
    } else {
        ImageFormat::Unknown
    }
}

/// Check whether data looks like SVG content.
///
/// SVG files can contain embedded JavaScript and are an XSS vector.
/// We check for both XML-based SVG markers and the `<svg` tag with
/// optional whitespace/BOM prefixes.
fn is_svg(data: &[u8]) -> bool {
    // Work on at most the first 1024 bytes to avoid scanning large buffers.
    let prefix_len = data.len().min(1024);
    let prefix = &data[..prefix_len];

    // Convert to lowercase string for matching (SVG is text-based).
    let text = String::from_utf8_lossy(prefix).to_lowercase();

    // Check for SVG indicators.
    text.contains("<svg")
        || text.contains("<!doctype svg")
        || text.contains("xmlns=\"http://www.w3.org/2000/svg\"")
}

/// Compute the SHA-256 hex digest of a byte slice.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Best-effort dimension extraction from image headers.
///
/// Returns (0, 0) if the header cannot be parsed.
fn extract_dimensions(data: &[u8], format: ImageFormat) -> (u32, u32) {
    match format {
        ImageFormat::Png => extract_png_dimensions(data),
        ImageFormat::Jpeg => extract_jpeg_dimensions(data),
        ImageFormat::Gif => extract_gif_dimensions(data),
        ImageFormat::Webp => extract_webp_dimensions(data),
        ImageFormat::Unknown => (0, 0),
    }
}

/// Extract width/height from a PNG IHDR chunk.
///
/// PNG structure: 8-byte signature, then IHDR chunk at offset 8.
/// IHDR data starts at offset 16: 4 bytes width (BE), 4 bytes height (BE).
fn extract_png_dimensions(data: &[u8]) -> (u32, u32) {
    if data.len() < 24 {
        return (0, 0);
    }
    let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
    (width, height)
}

/// Extract width/height from a JPEG SOF marker.
///
/// Scans for SOF0 (0xFFC0) or SOF2 (0xFFC2) markers. Height is at
/// marker+5, width at marker+7 (both 2-byte big-endian).
fn extract_jpeg_dimensions(data: &[u8]) -> (u32, u32) {
    let mut i = 2; // skip SOI marker
    while i + 9 < data.len() {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = data[i + 1];
        // SOF0 or SOF2
        if marker == 0xC0 || marker == 0xC2 {
            let height = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
            let width = u16::from_be_bytes([data[i + 7], data[i + 8]]) as u32;
            return (width, height);
        }
        // Skip to next marker using segment length.
        if i + 3 < data.len() {
            let seg_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            i += 2 + seg_len;
        } else {
            break;
        }
    }
    (0, 0)
}

/// Extract width/height from a GIF logical screen descriptor.
///
/// GIF structure: 6-byte signature, then 2-byte width (LE), 2-byte height (LE).
fn extract_gif_dimensions(data: &[u8]) -> (u32, u32) {
    if data.len() < 10 {
        return (0, 0);
    }
    let width = u16::from_le_bytes([data[6], data[7]]) as u32;
    let height = u16::from_le_bytes([data[8], data[9]]) as u32;
    (width, height)
}

/// Extract width/height from a WebP VP8 header.
///
/// Only handles VP8 (lossy) bitstream for simplicity. VP8L and VP8X
/// would need additional parsing.
fn extract_webp_dimensions(data: &[u8]) -> (u32, u32) {
    // RIFF header: 12 bytes, then VP8 chunk header: 8 bytes, then VP8 bitstream.
    // VP8 bitstream: 3-byte frame tag, then 7 bytes, then 2-byte width, 2-byte height.
    if data.len() < 30 {
        return (0, 0);
    }
    // Check for VP8 chunk (lossy).
    if &data[12..16] == b"VP8 " {
        // VP8 bitstream starts at offset 20. Frame tag is 3 bytes.
        // After the frame tag: bytes 3..6 are a start code (0x9D012A),
        // then 2 bytes width (LE, lower 14 bits), 2 bytes height (LE, lower 14 bits).
        let offset = 20;
        if data.len() >= offset + 10 {
            let width = u16::from_le_bytes([data[offset + 6], data[offset + 7]]) & 0x3FFF;
            let height = u16::from_le_bytes([data[offset + 8], data[offset + 9]]) & 0x3FFF;
            return (width as u32, height as u32);
        }
    }
    (0, 0)
}

/// Sanitize a user-provided prompt string by removing control characters.
fn sanitize_prompt(prompt: &str) -> String {
    prompt
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Sanitize text extracted via OCR by removing control characters.
#[allow(dead_code)]
fn sanitize_extracted_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t' || *c == '\r')
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Minimal valid headers for each format --

    /// Minimal PNG: 8-byte signature + IHDR chunk (4-byte length, 4-byte type, 13 bytes data, 4-byte CRC).
    fn minimal_png() -> Vec<u8> {
        let mut data = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        // IHDR chunk length (13 bytes)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
        // IHDR chunk type
        data.extend_from_slice(b"IHDR");
        // Width: 100 (big-endian)
        data.extend_from_slice(&100u32.to_be_bytes());
        // Height: 200 (big-endian)
        data.extend_from_slice(&200u32.to_be_bytes());
        // Bit depth, color type, compression, filter, interlace
        data.extend_from_slice(&[8, 6, 0, 0, 0]);
        // CRC (dummy)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data
    }

    /// Minimal JPEG: SOI + SOF0 marker.
    fn minimal_jpeg() -> Vec<u8> {
        let mut data = vec![0xFF, 0xD8]; // SOI
                                         // SOF0 marker
        data.push(0xFF);
        data.push(0xC0);
        // Segment length (11 bytes)
        data.extend_from_slice(&11u16.to_be_bytes());
        // Precision
        data.push(8);
        // Height: 480 (big-endian)
        data.extend_from_slice(&480u16.to_be_bytes());
        // Width: 640 (big-endian)
        data.extend_from_slice(&640u16.to_be_bytes());
        // Number of components
        data.push(3);
        // Component data (3 * 3 bytes)
        data.extend_from_slice(&[1, 0x22, 0]);
        data.extend_from_slice(&[2, 0x11, 1]);
        data.extend_from_slice(&[3, 0x11, 1]);
        data
    }

    /// Minimal GIF89a header.
    fn minimal_gif() -> Vec<u8> {
        let mut data = b"GIF89a".to_vec();
        // Logical screen width: 320 (little-endian)
        data.extend_from_slice(&320u16.to_le_bytes());
        // Logical screen height: 240 (little-endian)
        data.extend_from_slice(&240u16.to_le_bytes());
        // Packed byte, bg color, pixel aspect ratio
        data.extend_from_slice(&[0x00, 0x00, 0x00]);
        data
    }

    /// Minimal WebP with VP8 lossy chunk.
    fn minimal_webp() -> Vec<u8> {
        let mut data = Vec::new();
        // RIFF header
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // file size (dummy)
        data.extend_from_slice(b"WEBP");
        // VP8 chunk
        data.extend_from_slice(b"VP8 ");
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // chunk size (dummy)
                                                           // VP8 bitstream: frame tag (3 bytes) + start code + dimensions
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // frame tag
        data.extend_from_slice(&[0x9D, 0x01, 0x2A]); // start code
                                                     // Width: 800 (little-endian, lower 14 bits)
        data.extend_from_slice(&800u16.to_le_bytes());
        // Height: 600 (little-endian, lower 14 bits)
        data.extend_from_slice(&600u16.to_le_bytes());
        data
    }

    // == test_config_defaults ==

    #[test]
    fn test_config_defaults() {
        let config = ImageConfig::default();
        assert_eq!(config.max_size_bytes, 10 * 1024 * 1024);
        assert_eq!(config.allowed_formats.len(), 4);
        assert!(config.allowed_formats.contains(&ImageFormat::Png));
        assert!(config.allowed_formats.contains(&ImageFormat::Jpeg));
        assert!(config.allowed_formats.contains(&ImageFormat::Gif));
        assert!(config.allowed_formats.contains(&ImageFormat::Webp));
        assert!(!config.enable_ocr);
        assert!(config.vision_model.is_empty());
    }

    // == test_magic_byte_detection ==

    #[test]
    fn test_magic_byte_detection() {
        let processor = ImageProcessor::new(ImageConfig::default());

        assert_eq!(
            processor.detect_content_type(&minimal_png()).unwrap(),
            ImageFormat::Png
        );
        assert_eq!(
            processor.detect_content_type(&minimal_jpeg()).unwrap(),
            ImageFormat::Jpeg
        );
        assert_eq!(
            processor.detect_content_type(&minimal_gif()).unwrap(),
            ImageFormat::Gif
        );
        assert_eq!(
            processor.detect_content_type(&minimal_webp()).unwrap(),
            ImageFormat::Webp
        );
    }

    // == test_size_limit_enforced ==

    #[test]
    fn test_size_limit_enforced() {
        let config = ImageConfig {
            max_size_bytes: 100,
            ..ImageConfig::default()
        };
        let processor = ImageProcessor::new(config);

        // Build a PNG header followed by enough padding to exceed the limit.
        let mut data = minimal_png();
        data.resize(200, 0x00);

        let result = processor.validate_image(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("exceeds maximum"),
            "error should mention size limit: {err}"
        );
    }

    // == test_svg_rejected ==

    #[test]
    fn test_svg_rejected() {
        let processor = ImageProcessor::new(ImageConfig::default());

        // Plain SVG tag.
        let svg1 = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
        let result = processor.validate_image(svg1);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("SVG"),
            "error should mention SVG"
        );

        // SVG with XML declaration.
        let svg2 = b"<?xml version=\"1.0\"?><svg width=\"100\" height=\"100\"></svg>";
        let result2 = processor.validate_image(svg2);
        assert!(result2.is_err());

        // SVG with DOCTYPE.
        let svg3 = b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\"><svg></svg>";
        let result3 = processor.validate_image(svg3);
        assert!(result3.is_err());

        // Case-insensitive detection.
        let svg4 = b"<SVG><rect/></SVG>";
        let result4 = processor.validate_image(svg4);
        assert!(result4.is_err());
    }

    // == test_content_hash ==

    #[test]
    fn test_content_hash() {
        let processor = ImageProcessor::new(ImageConfig::default());
        let data = minimal_png();

        let meta = processor.validate_image(&data).unwrap();

        // Verify independently.
        let expected = compute_sha256(&data);
        assert_eq!(meta.content_hash, expected);
        assert!(!meta.content_hash.is_empty());
        assert_eq!(meta.content_hash.len(), 64); // 256 bits = 64 hex chars
    }

    // == test_empty_data_rejected ==

    #[test]
    fn test_empty_data_rejected() {
        let processor = ImageProcessor::new(ImageConfig::default());
        let result = processor.validate_image(b"");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("empty"),
            "error should mention empty data"
        );
    }

    // == test_unknown_format_rejected ==

    #[test]
    fn test_unknown_format_rejected() {
        let processor = ImageProcessor::new(ImageConfig::default());

        // Random bytes that do not match any known format.
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let result = processor.validate_image(&data);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("unrecognized"),
            "error should mention unrecognized format"
        );
    }

    // == test_cedar_action_name ==

    #[test]
    fn test_cedar_action_name() {
        // Verify that the ImageProcess ActionKind maps to the expected Cedar
        // action name. This test ensures the policy integration is wired.
        let kind = aegis_types::ActionKind::ImageProcess {
            content_hash: "abc123".into(),
            format: "png".into(),
            size_bytes: 1024,
        };
        let display = kind.to_string();
        assert!(
            display.contains("ImageProcess"),
            "Display should contain ImageProcess: {display}"
        );
    }

    // == Additional security tests ==

    #[test]
    fn test_validate_returns_correct_format() {
        let processor = ImageProcessor::new(ImageConfig::default());

        let meta = processor.validate_image(&minimal_png()).unwrap();
        assert_eq!(meta.format, ImageFormat::Png);

        let meta = processor.validate_image(&minimal_jpeg()).unwrap();
        assert_eq!(meta.format, ImageFormat::Jpeg);

        let meta = processor.validate_image(&minimal_gif()).unwrap();
        assert_eq!(meta.format, ImageFormat::Gif);

        let meta = processor.validate_image(&minimal_webp()).unwrap();
        assert_eq!(meta.format, ImageFormat::Webp);
    }

    #[test]
    fn test_validate_returns_correct_dimensions() {
        let processor = ImageProcessor::new(ImageConfig::default());

        let meta = processor.validate_image(&minimal_png()).unwrap();
        assert_eq!(meta.width, 100);
        assert_eq!(meta.height, 200);

        let meta = processor.validate_image(&minimal_jpeg()).unwrap();
        assert_eq!(meta.width, 640);
        assert_eq!(meta.height, 480);

        let meta = processor.validate_image(&minimal_gif()).unwrap();
        assert_eq!(meta.width, 320);
        assert_eq!(meta.height, 240);
    }

    #[test]
    fn test_extract_text_returns_none_when_ocr_disabled() {
        let config = ImageConfig {
            enable_ocr: false,
            ..ImageConfig::default()
        };
        let processor = ImageProcessor::new(config);
        let result = processor.extract_text(&minimal_png()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_describe_image_returns_placeholder() {
        let processor = ImageProcessor::new(ImageConfig::default());
        let desc = processor
            .describe_image(&minimal_png(), "What is in this image?")
            .unwrap();
        assert!(desc.contains("placeholder"));
        assert!(desc.contains("png"));
    }

    #[test]
    fn test_format_not_in_allowed_list_rejected() {
        let config = ImageConfig {
            allowed_formats: vec![ImageFormat::Png], // only PNG allowed
            ..ImageConfig::default()
        };
        let processor = ImageProcessor::new(config);

        let result = processor.validate_image(&minimal_jpeg());
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("not in the allowed"),
            "error should mention allowed formats"
        );
    }

    #[test]
    fn test_sanitize_prompt_removes_control_chars() {
        let dirty = "Describe\x00this\x07image\nplease";
        let clean = sanitize_prompt(dirty);
        assert_eq!(clean, "Describethisimage\nplease");
    }

    #[test]
    fn test_sanitize_extracted_text() {
        let dirty = "Hello\x00World\nLine2\r\nLine3\x07end";
        let clean = sanitize_extracted_text(dirty);
        assert_eq!(clean, "HelloWorld\nLine2\r\nLine3end");
    }
}
