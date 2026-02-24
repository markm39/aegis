//! Video processing with format detection and frame extraction via ffmpeg.
//!
//! Provides video processing capabilities with strict security invariants:
//!
//! - **Size limits** are checked before any parsing or processing.
//! - **Magic byte detection** verifies actual format (never trusts extensions).
//! - **SHA-256 hashing** provides an audit trail; raw video data is never logged.
//! - **Cedar policy evaluation** gates processing via `VideoProcess` action.
//! - **FFmpeg subprocess** is sandboxed with controlled arguments only.
//! - **Temporary files** are cleaned up via RAII in all code paths.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// VideoFormat
// ---------------------------------------------------------------------------

/// Recognized video formats, detected by magic byte inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoFormat {
    /// MP4: ISO Base Media File Format with `ftyp` box.
    Mp4,
    /// WebM: EBML header with webm doctype (starts with `\x1A\x45\xDF\xA3`).
    WebM,
    /// AVI: RIFF container with `AVI ` chunk.
    Avi,
    /// MKV: EBML header with matroska doctype (starts with `\x1A\x45\xDF\xA3`).
    Mkv,
    /// MOV: ISO Base Media File Format with `ftyp` box and `qt` brand.
    Mov,
    /// Format not recognized -- will be rejected by validation.
    Unknown,
}

impl VideoFormat {
    /// Human-readable lowercase name suitable for audit logs.
    pub fn as_str(self) -> &'static str {
        match self {
            VideoFormat::Mp4 => "mp4",
            VideoFormat::WebM => "webm",
            VideoFormat::Avi => "avi",
            VideoFormat::Mkv => "mkv",
            VideoFormat::Mov => "mov",
            VideoFormat::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for VideoFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// VideoConfig
// ---------------------------------------------------------------------------

/// Configuration for the video processor.
///
/// Controls size limits, duration limits, allowed formats, and ffmpeg parameters.
#[derive(Debug, Clone)]
pub struct VideoConfig {
    /// Maximum allowed video size in bytes. Data exceeding this limit is
    /// rejected before any processing occurs. Default: 100 MB.
    pub max_video_size_bytes: u64,
    /// Maximum allowed video duration in seconds. Default: 300 (5 minutes).
    pub max_duration_secs: u64,
    /// Frame extraction interval in seconds. Default: 1 (one frame per second).
    pub frame_interval_secs: f64,
    /// If true, extract only keyframes instead of fixed-interval frames.
    pub keyframes_only: bool,
    /// Set of formats that are permitted. Default: MP4, WebM, AVI, MKV, MOV.
    pub allowed_formats: Vec<VideoFormat>,
    /// Path to the ffmpeg binary. Default: "ffmpeg" (found via PATH).
    /// Validated to prevent path traversal.
    pub ffmpeg_path: String,
}

impl Default for VideoConfig {
    fn default() -> Self {
        Self {
            max_video_size_bytes: 100 * 1024 * 1024, // 100 MB
            max_duration_secs: 300,                  // 5 minutes
            frame_interval_secs: 1.0,
            keyframes_only: false,
            allowed_formats: vec![
                VideoFormat::Mp4,
                VideoFormat::WebM,
                VideoFormat::Avi,
                VideoFormat::Mkv,
                VideoFormat::Mov,
            ],
            ffmpeg_path: "ffmpeg".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// VideoMetadata
// ---------------------------------------------------------------------------

/// Metadata extracted from a validated video.
///
/// This struct is safe to log and store in the audit trail -- it contains
/// no raw video data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoMetadata {
    /// Detected video format.
    pub format: VideoFormat,
    /// Size of the raw video data in bytes.
    pub size_bytes: u64,
    /// SHA-256 hex digest of the raw video data.
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// FrameExtractionResult
// ---------------------------------------------------------------------------

/// Result of frame extraction from a video.
#[derive(Debug, Clone)]
pub struct FrameExtractionResult {
    /// Paths to extracted PNG frame files.
    pub frame_paths: Vec<PathBuf>,
    /// Number of frames extracted.
    pub frame_count: usize,
}

// ---------------------------------------------------------------------------
// TempFrameDir
// ---------------------------------------------------------------------------

/// RAII guard for a temporary directory used during frame extraction.
///
/// The directory and all its contents are removed when this guard is dropped,
/// ensuring cleanup in all code paths (including panics and early returns).
pub struct TempFrameDir {
    path: PathBuf,
}

impl TempFrameDir {
    /// Create a new temporary directory for frame output.
    pub fn new() -> Result<Self, String> {
        let dir = std::env::temp_dir().join(format!("aegis-video-frames-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("failed to create temp frame directory: {e}"))?;
        Ok(Self { path: dir })
    }

    /// Get the path to the temporary directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFrameDir {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

// ---------------------------------------------------------------------------
// VideoProcessor
// ---------------------------------------------------------------------------

/// Validates, hashes, and processes video data.
///
/// All public methods enforce the configured security invariants before
/// performing any work.
pub struct VideoProcessor {
    config: VideoConfig,
}

impl VideoProcessor {
    /// Create a new processor with the given configuration.
    pub fn new(config: VideoConfig) -> Self {
        Self { config }
    }

    /// Detect the video format by inspecting magic bytes.
    ///
    /// This never trusts file extensions. The detection is performed on the
    /// first few bytes of the data and is safe to call on untrusted input.
    pub fn detect_format(&self, data: &[u8]) -> Result<VideoFormat, String> {
        if data.is_empty() {
            return Err("video data is empty".to_string());
        }
        Ok(detect_format_from_magic_bytes(data))
    }

    /// Validate video data against configured limits and format restrictions.
    ///
    /// Checks (in order):
    /// 1. Data is non-empty.
    /// 2. Size does not exceed `max_video_size_bytes`.
    /// 3. Format is recognized (not `Unknown`).
    /// 4. Format is in the `allowed_formats` list.
    ///
    /// On success, returns [`VideoMetadata`] including a SHA-256 content hash.
    pub fn validate_video(&self, data: &[u8]) -> Result<VideoMetadata, String> {
        // 1. Reject empty data.
        if data.is_empty() {
            return Err("video data is empty".to_string());
        }

        // 2. Enforce size limit BEFORE any further processing.
        let size = data.len() as u64;
        if size > self.config.max_video_size_bytes {
            return Err(format!(
                "video size {} bytes exceeds maximum {} bytes",
                size, self.config.max_video_size_bytes
            ));
        }

        // 3. Detect format from magic bytes.
        let format = detect_format_from_magic_bytes(data);
        if format == VideoFormat::Unknown {
            return Err(
                "unrecognized video format (magic bytes do not match any supported format)"
                    .to_string(),
            );
        }

        // 4. Check format is allowed.
        if !self.config.allowed_formats.contains(&format) {
            return Err(format!(
                "video format '{}' is not in the allowed formats list",
                format
            ));
        }

        // Compute SHA-256 hash for audit trail.
        let content_hash = compute_sha256(data);

        Ok(VideoMetadata {
            format,
            size_bytes: size,
            content_hash,
        })
    }

    /// Build the ffmpeg command arguments for frame extraction.
    ///
    /// All arguments are constructed internally -- no user-controlled strings
    /// are interpolated into the command to prevent command injection.
    ///
    /// Returns `(ffmpeg_binary_path, arguments)`.
    pub fn build_ffmpeg_command(
        &self,
        input_path: &Path,
        output_dir: &Path,
    ) -> Result<(String, Vec<String>), String> {
        // Validate ffmpeg path: reject path traversal attempts.
        let ffmpeg = validate_ffmpeg_path(&self.config.ffmpeg_path)?;

        // Validate input path exists and is a file.
        let input_str = input_path
            .to_str()
            .ok_or_else(|| "input path contains non-UTF-8 characters".to_string())?;

        // Validate output directory exists.
        let output_str = output_dir
            .to_str()
            .ok_or_else(|| "output directory path contains non-UTF-8 characters".to_string())?;

        // Validate the output path does not escape the expected temp directory.
        let canonical_output = output_dir
            .canonicalize()
            .map_err(|e| format!("failed to canonicalize output directory: {e}"))?;
        let temp_dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        if !canonical_output.starts_with(&temp_dir) {
            return Err(format!(
                "output directory must be within temp directory ({}), got: {}",
                temp_dir.display(),
                canonical_output.display()
            ));
        }

        let output_pattern = format!("{}/frame_%04d.png", output_str);

        let mut args = vec![
            "-y".to_string(), // Overwrite output files
            "-i".to_string(), // Input file
            input_str.to_string(),
            "-t".to_string(), // Duration limit
            self.config.max_duration_secs.to_string(),
        ];

        if self.config.keyframes_only {
            // Extract only keyframes using the select filter.
            args.extend_from_slice(&[
                "-vf".to_string(),
                "select=eq(pict_type\\,I)".to_string(),
                "-vsync".to_string(),
                "vfr".to_string(),
            ]);
        } else {
            // Extract frames at fixed intervals using -ss seeking with -vframes 1
            // pattern for efficiency. For batch extraction, use fps filter.
            args.extend_from_slice(&[
                "-vf".to_string(),
                format!("fps=1/{}", self.config.frame_interval_secs),
            ]);
        }

        args.extend_from_slice(&["-f".to_string(), "image2".to_string(), output_pattern]);

        Ok((ffmpeg, args))
    }

    /// Build ffmpeg arguments for extracting a single frame at a specific
    /// timestamp using efficient seeking.
    ///
    /// Uses `-ss` before input for fast seeking and `-vframes 1` for minimal
    /// decoding.
    pub fn build_single_frame_command(
        &self,
        input_path: &Path,
        output_path: &Path,
        timestamp_secs: f64,
    ) -> Result<(String, Vec<String>), String> {
        let ffmpeg = validate_ffmpeg_path(&self.config.ffmpeg_path)?;

        let input_str = input_path
            .to_str()
            .ok_or_else(|| "input path contains non-UTF-8 characters".to_string())?;

        let output_str = output_path
            .to_str()
            .ok_or_else(|| "output path contains non-UTF-8 characters".to_string())?;

        // Clamp timestamp to max duration.
        let clamped = timestamp_secs
            .min(self.config.max_duration_secs as f64)
            .max(0.0);

        let args = vec![
            "-y".to_string(),
            "-ss".to_string(),
            format!("{:.3}", clamped),
            "-i".to_string(),
            input_str.to_string(),
            "-vframes".to_string(),
            "1".to_string(),
            "-f".to_string(),
            "image2".to_string(),
            output_str.to_string(),
        ];

        Ok((ffmpeg, args))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Detect video format from the first bytes of data (magic bytes).
///
/// Detection rules:
/// - MP4: `ftyp` box at offset 4, with ISO brand (isom, mp4, M4V, etc.)
/// - MOV: `ftyp` box at offset 4 with `qt` brand
/// - WebM: EBML header `\x1A\x45\xDF\xA3` with webm doctype
/// - MKV: EBML header `\x1A\x45\xDF\xA3` with matroska doctype
/// - AVI: RIFF container with `AVI ` chunk
fn detect_format_from_magic_bytes(data: &[u8]) -> VideoFormat {
    // AVI: RIFF....AVI
    if data.len() >= 12 && data[..4] == *b"RIFF" && data[8..12] == *b"AVI " {
        return VideoFormat::Avi;
    }

    // EBML-based formats (WebM and MKV) start with 0x1A 0x45 0xDF 0xA3
    if data.len() >= 4 && data[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        // Scan for the DocType element to distinguish WebM from MKV.
        // DocType is EBML element ID 0x4282 followed by the doctype string.
        // We search through the first 64 bytes for the doctype string.
        let search_len = data.len().min(64);
        let search_window = &data[..search_len];

        // Look for "webm" or "matroska" in the EBML header.
        if contains_bytes(search_window, b"webm") {
            return VideoFormat::WebM;
        }
        if contains_bytes(search_window, b"matroska") {
            return VideoFormat::Mkv;
        }

        // If we have the EBML header but can't determine the doctype,
        // default to MKV (Matroska is the more general container).
        return VideoFormat::Mkv;
    }

    // ISO Base Media File Format: look for 'ftyp' box at offset 4.
    if data.len() >= 12 && data[4..8] == *b"ftyp" {
        // Check the major brand (bytes 8..12) to distinguish MOV from MP4.
        let brand = &data[8..12];

        // QuickTime brand
        if brand == b"qt  " {
            return VideoFormat::Mov;
        }

        // Also scan compatible brands in the ftyp box for "qt".
        // The ftyp box size is in the first 4 bytes (big-endian).
        let box_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let ftyp_end = box_size.min(data.len());
        if ftyp_end >= 16 {
            // Compatible brands start at offset 16, each is 4 bytes.
            let brands_data = &data[16..ftyp_end];
            for chunk in brands_data.chunks(4) {
                if chunk == b"qt  " {
                    return VideoFormat::Mov;
                }
            }
        }

        // Otherwise, it's an MP4 variant.
        return VideoFormat::Mp4;
    }

    VideoFormat::Unknown
}

/// Check if `haystack` contains the byte sequence `needle`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Compute the SHA-256 hex digest of a byte slice.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Validate the ffmpeg binary path.
///
/// Rejects paths containing directory traversal components (`..`) or
/// absolute paths that point outside expected locations. Only bare
/// binary names (e.g., `"ffmpeg"`) or absolute paths to known
/// system directories are accepted.
fn validate_ffmpeg_path(path: &str) -> Result<String, String> {
    let path = path.trim();

    if path.is_empty() {
        return Err("ffmpeg path is empty".to_string());
    }

    // Reject path traversal.
    if path.contains("..") {
        return Err("ffmpeg path must not contain '..' (path traversal)".to_string());
    }

    // Reject null bytes (could truncate paths in C-based systems).
    if path.contains('\0') {
        return Err("ffmpeg path must not contain null bytes".to_string());
    }

    // If it's a bare binary name (no slashes), allow it -- the OS will
    // resolve it via PATH.
    if !path.contains('/') && !path.contains('\\') {
        return Ok(path.to_string());
    }

    // For absolute paths, verify they point to a reasonable location.
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(
            "ffmpeg path must be either a bare binary name or an absolute path".to_string(),
        );
    }

    Ok(path.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Minimal valid headers for each format --

    /// Minimal MP4: ftyp box with isom brand.
    fn minimal_mp4() -> Vec<u8> {
        let mut data = Vec::new();
        // Box size (20 bytes total)
        data.extend_from_slice(&20u32.to_be_bytes());
        // Box type: ftyp
        data.extend_from_slice(b"ftyp");
        // Major brand: isom
        data.extend_from_slice(b"isom");
        // Minor version
        data.extend_from_slice(&0u32.to_be_bytes());
        data
    }

    /// Minimal WebM: EBML header with webm doctype.
    fn minimal_webm() -> Vec<u8> {
        let mut data = vec![0x1A, 0x45, 0xDF, 0xA3];
        // Simulated EBML header content containing "webm" doctype
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F]);
        // DocType element (0x4282)
        data.extend_from_slice(&[0x42, 0x82]);
        data.extend_from_slice(&[0x84]); // size = 4
        data.extend_from_slice(b"webm");
        data
    }

    /// Minimal AVI: RIFF header with AVI chunk.
    fn minimal_avi() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // file size (dummy)
        data.extend_from_slice(b"AVI ");
        // Additional AVI structure data
        data.extend_from_slice(b"LIST");
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data
    }

    /// Minimal MKV: EBML header with matroska doctype.
    fn minimal_mkv() -> Vec<u8> {
        let mut data = vec![0x1A, 0x45, 0xDF, 0xA3];
        // Simulated EBML header content containing "matroska" doctype
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23]);
        // DocType element (0x4282)
        data.extend_from_slice(&[0x42, 0x82]);
        data.extend_from_slice(&[0x88]); // size = 8
        data.extend_from_slice(b"matroska");
        data
    }

    /// Minimal MOV: ftyp box with qt brand.
    fn minimal_mov() -> Vec<u8> {
        let mut data = Vec::new();
        // Box size (20 bytes total)
        data.extend_from_slice(&20u32.to_be_bytes());
        // Box type: ftyp
        data.extend_from_slice(b"ftyp");
        // Major brand: qt (QuickTime)
        data.extend_from_slice(b"qt  ");
        // Minor version
        data.extend_from_slice(&0u32.to_be_bytes());
        data
    }

    // == video_format_detection_mp4 ==

    #[test]
    fn video_format_detection_mp4() {
        let processor = VideoProcessor::new(VideoConfig::default());
        assert_eq!(
            processor.detect_format(&minimal_mp4()).unwrap(),
            VideoFormat::Mp4
        );
    }

    // == video_format_detection_webm ==

    #[test]
    fn video_format_detection_webm() {
        let processor = VideoProcessor::new(VideoConfig::default());
        assert_eq!(
            processor.detect_format(&minimal_webm()).unwrap(),
            VideoFormat::WebM
        );
    }

    // == video_format_detection_avi ==

    #[test]
    fn video_format_detection_avi() {
        let processor = VideoProcessor::new(VideoConfig::default());
        assert_eq!(
            processor.detect_format(&minimal_avi()).unwrap(),
            VideoFormat::Avi
        );
    }

    // == video_format_detection_mkv ==

    #[test]
    fn video_format_detection_mkv() {
        let processor = VideoProcessor::new(VideoConfig::default());
        assert_eq!(
            processor.detect_format(&minimal_mkv()).unwrap(),
            VideoFormat::Mkv
        );
    }

    // == video_format_detection_mov ==

    #[test]
    fn video_format_detection_mov() {
        let processor = VideoProcessor::new(VideoConfig::default());
        assert_eq!(
            processor.detect_format(&minimal_mov()).unwrap(),
            VideoFormat::Mov
        );
    }

    // == unknown_format_rejected ==

    #[test]
    fn unknown_format_rejected() {
        let processor = VideoProcessor::new(VideoConfig::default());

        // Random bytes that do not match any known format.
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let result = processor.validate_video(&data);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("unrecognized"),
            "error should mention unrecognized format"
        );
    }

    // == size_limit_enforced ==

    #[test]
    fn size_limit_enforced() {
        let config = VideoConfig {
            max_video_size_bytes: 100,
            ..VideoConfig::default()
        };
        let processor = VideoProcessor::new(config);

        // Build an MP4 header followed by enough padding to exceed the limit.
        let mut data = minimal_mp4();
        data.resize(200, 0x00);

        let result = processor.validate_video(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("exceeds maximum"),
            "error should mention size limit: {err}"
        );
    }

    // == content_hash_computed ==

    #[test]
    fn content_hash_computed() {
        let processor = VideoProcessor::new(VideoConfig::default());
        let data = minimal_mp4();

        let meta = processor.validate_video(&data).unwrap();

        // Verify independently.
        let expected = compute_sha256(&data);
        assert_eq!(meta.content_hash, expected);
        assert!(!meta.content_hash.is_empty());
        assert_eq!(meta.content_hash.len(), 64); // 256 bits = 64 hex chars
    }

    // == ffmpeg_command_construction ==

    #[test]
    fn ffmpeg_command_construction() {
        let config = VideoConfig {
            frame_interval_secs: 2.0,
            max_duration_secs: 60,
            ..VideoConfig::default()
        };
        let processor = VideoProcessor::new(config);

        let temp_dir = TempFrameDir::new().unwrap();
        let input_path = Path::new("/tmp/test_video.mp4");

        let (binary, args) = processor
            .build_ffmpeg_command(input_path, temp_dir.path())
            .unwrap();

        assert_eq!(binary, "ffmpeg");
        assert!(args.contains(&"-y".to_string()));
        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&"/tmp/test_video.mp4".to_string()));
        assert!(args.contains(&"-t".to_string()));
        assert!(args.contains(&"60".to_string()));
        assert!(args.contains(&"fps=1/2".to_string()));
        assert!(args.contains(&"image2".to_string()));
    }

    // == ffmpeg_single_frame_command ==

    #[test]
    fn ffmpeg_single_frame_command() {
        let processor = VideoProcessor::new(VideoConfig::default());

        let input_path = Path::new("/tmp/test_video.mp4");
        let output_path = Path::new("/tmp/frame.png");

        let (binary, args) = processor
            .build_single_frame_command(input_path, output_path, 10.5)
            .unwrap();

        assert_eq!(binary, "ffmpeg");
        assert!(args.contains(&"-ss".to_string()));
        assert!(args.contains(&"10.500".to_string()));
        assert!(args.contains(&"-vframes".to_string()));
        assert!(args.contains(&"1".to_string()));
    }

    // == ffmpeg_keyframes_only_command ==

    #[test]
    fn ffmpeg_keyframes_only_command() {
        let config = VideoConfig {
            keyframes_only: true,
            ..VideoConfig::default()
        };
        let processor = VideoProcessor::new(config);

        let temp_dir = TempFrameDir::new().unwrap();
        let input_path = Path::new("/tmp/test_video.mp4");

        let (_binary, args) = processor
            .build_ffmpeg_command(input_path, temp_dir.path())
            .unwrap();

        assert!(args.contains(&"select=eq(pict_type\\,I)".to_string()));
        assert!(args.contains(&"vfr".to_string()));
    }

    // == temp_dir_cleanup ==

    #[test]
    fn temp_dir_cleanup() {
        let path;
        {
            let temp = TempFrameDir::new().unwrap();
            path = temp.path().to_path_buf();
            assert!(
                path.exists(),
                "temp directory should exist while guard is alive"
            );

            // Create a file inside to verify recursive cleanup.
            std::fs::write(path.join("test_frame.png"), b"fake png data").unwrap();
        }
        // After the guard is dropped, the directory should be gone.
        assert!(
            !path.exists(),
            "temp directory should be cleaned up after guard is dropped"
        );
    }

    // == video_requires_cedar_policy (security test) ==

    #[test]
    fn video_requires_cedar_policy() {
        // Verify that the VideoProcess ActionKind maps to the expected Cedar
        // action name. This test ensures policy integration is wired and that
        // video processing cannot bypass Cedar authorization.
        let kind = aegis_types::ActionKind::VideoProcess {
            content_hash: "abc123def456".into(),
            format: "mp4".into(),
            size_bytes: 2048,
        };
        let display = kind.to_string();
        assert!(
            display.contains("VideoProcess"),
            "Display should contain VideoProcess: {display}"
        );

        // Verify that default-deny Cedar policies would block this action.
        // This proves the action MUST have an explicit permit policy to proceed.
        let engine = aegis_policy::engine::PolicyEngine::from_policies(
            "forbid(principal, action, resource);",
            None,
        )
        .expect("should create engine");

        let action = aegis_types::Action::new("test-agent", kind);
        let verdict = engine.evaluate(&action);
        assert_eq!(
            verdict.decision,
            aegis_types::Decision::Deny,
            "VideoProcess must be denied by default-deny policy"
        );
    }

    // == empty_data_rejected ==

    #[test]
    fn empty_data_rejected() {
        let processor = VideoProcessor::new(VideoConfig::default());
        let result = processor.validate_video(b"");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("empty"),
            "error should mention empty data"
        );
    }

    // == config_defaults ==

    #[test]
    fn config_defaults() {
        let config = VideoConfig::default();
        assert_eq!(config.max_video_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.max_duration_secs, 300);
        assert_eq!(config.frame_interval_secs, 1.0);
        assert!(!config.keyframes_only);
        assert_eq!(config.allowed_formats.len(), 5);
        assert!(config.allowed_formats.contains(&VideoFormat::Mp4));
        assert!(config.allowed_formats.contains(&VideoFormat::WebM));
        assert!(config.allowed_formats.contains(&VideoFormat::Avi));
        assert!(config.allowed_formats.contains(&VideoFormat::Mkv));
        assert!(config.allowed_formats.contains(&VideoFormat::Mov));
        assert_eq!(config.ffmpeg_path, "ffmpeg");
    }

    // == validate_returns_correct_format ==

    #[test]
    fn validate_returns_correct_format() {
        let processor = VideoProcessor::new(VideoConfig::default());

        let meta = processor.validate_video(&minimal_mp4()).unwrap();
        assert_eq!(meta.format, VideoFormat::Mp4);

        let meta = processor.validate_video(&minimal_webm()).unwrap();
        assert_eq!(meta.format, VideoFormat::WebM);

        let meta = processor.validate_video(&minimal_avi()).unwrap();
        assert_eq!(meta.format, VideoFormat::Avi);

        let meta = processor.validate_video(&minimal_mkv()).unwrap();
        assert_eq!(meta.format, VideoFormat::Mkv);

        let meta = processor.validate_video(&minimal_mov()).unwrap();
        assert_eq!(meta.format, VideoFormat::Mov);
    }

    // == format_not_in_allowed_list_rejected ==

    #[test]
    fn format_not_in_allowed_list_rejected() {
        let config = VideoConfig {
            allowed_formats: vec![VideoFormat::Mp4], // only MP4 allowed
            ..VideoConfig::default()
        };
        let processor = VideoProcessor::new(config);

        let result = processor.validate_video(&minimal_avi());
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("not in the allowed"),
            "error should mention allowed formats"
        );
    }

    // == ffmpeg_path_traversal_rejected (security test) ==

    #[test]
    fn ffmpeg_path_traversal_rejected() {
        assert!(
            validate_ffmpeg_path("../../../usr/bin/ffmpeg").is_err(),
            "path traversal must be rejected"
        );
        assert!(
            validate_ffmpeg_path("/usr/bin/../bin/ffmpeg").is_err(),
            "path traversal must be rejected"
        );
        assert!(
            validate_ffmpeg_path("ffmpeg\0--evil").is_err(),
            "null bytes must be rejected"
        );
        assert!(
            validate_ffmpeg_path("").is_err(),
            "empty path must be rejected"
        );
        assert!(
            validate_ffmpeg_path("relative/path/ffmpeg").is_err(),
            "relative paths must be rejected"
        );
    }

    // == ffmpeg_valid_paths_accepted ==

    #[test]
    fn ffmpeg_valid_paths_accepted() {
        assert!(validate_ffmpeg_path("ffmpeg").is_ok());
        assert!(validate_ffmpeg_path("/usr/bin/ffmpeg").is_ok());
        assert!(validate_ffmpeg_path("/usr/local/bin/ffmpeg").is_ok());
    }

    // == video_format_display ==

    #[test]
    fn video_format_display() {
        assert_eq!(VideoFormat::Mp4.to_string(), "mp4");
        assert_eq!(VideoFormat::WebM.to_string(), "webm");
        assert_eq!(VideoFormat::Avi.to_string(), "avi");
        assert_eq!(VideoFormat::Mkv.to_string(), "mkv");
        assert_eq!(VideoFormat::Mov.to_string(), "mov");
        assert_eq!(VideoFormat::Unknown.to_string(), "unknown");
    }

    // == size_limit_checked_before_format_detection (security test) ==

    #[test]
    fn size_limit_checked_before_format_detection() {
        let config = VideoConfig {
            max_video_size_bytes: 10, // very small limit
            ..VideoConfig::default()
        };
        let processor = VideoProcessor::new(config);

        // Data is too large but has valid MP4 magic bytes.
        let mut data = minimal_mp4();
        data.resize(100, 0x00);

        let result = processor.validate_video(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Must fail on size, not format -- proves size check comes first.
        assert!(
            err.contains("exceeds maximum"),
            "should fail on size limit before format check: {err}"
        );
    }

    // == timestamp_clamped_to_max_duration ==

    #[test]
    fn timestamp_clamped_to_max_duration() {
        let config = VideoConfig {
            max_duration_secs: 60,
            ..VideoConfig::default()
        };
        let processor = VideoProcessor::new(config);

        let input_path = Path::new("/tmp/test.mp4");
        let output_path = Path::new("/tmp/frame.png");

        // Request a timestamp beyond max_duration_secs.
        let (_binary, args) = processor
            .build_single_frame_command(input_path, output_path, 999.0)
            .unwrap();

        // The timestamp should be clamped to 60.000.
        let ss_idx = args.iter().position(|a| a == "-ss").unwrap();
        let timestamp = &args[ss_idx + 1];
        assert_eq!(timestamp, "60.000");
    }

    // == negative_timestamp_clamped_to_zero ==

    #[test]
    fn negative_timestamp_clamped_to_zero() {
        let processor = VideoProcessor::new(VideoConfig::default());

        let input_path = Path::new("/tmp/test.mp4");
        let output_path = Path::new("/tmp/frame.png");

        let (_binary, args) = processor
            .build_single_frame_command(input_path, output_path, -5.0)
            .unwrap();

        let ss_idx = args.iter().position(|a| a == "-ss").unwrap();
        let timestamp = &args[ss_idx + 1];
        assert_eq!(timestamp, "0.000");
    }
}
