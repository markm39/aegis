//! Unified media handling pipeline for channel attachments.
//!
//! Provides a common abstraction for uploading, downloading, and validating
//! media attachments across all channel backends. Each channel type can
//! register its own size limits and supported MIME types.
//!
//! # Architecture
//!
//! - [`MediaAttachment`]: metadata for a media file (MIME type, size, URL,
//!   optional thumbnail).
//! - [`MediaLimits`]: per-channel constraints on file size and allowed types.
//! - [`MediaPipeline`]: orchestrates upload/download with validation, caching
//!   metadata in a registry keyed by attachment ID.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum filename length.
const MAX_FILENAME_LEN: usize = 255;

/// Maximum number of attachments in the registry.
const MAX_REGISTRY_SIZE: usize = 10_000;

/// Default maximum file size (25 MB).
const DEFAULT_MAX_FILE_SIZE: u64 = 25 * 1024 * 1024;

/// Maximum thumbnail size (256 KB).
const MAX_THUMBNAIL_SIZE: u64 = 256 * 1024;

/// Default TTL for cached attachment metadata.
const DEFAULT_METADATA_TTL: Duration = Duration::from_secs(3600); // 1 hour

// ---------------------------------------------------------------------------
// MIME types
// ---------------------------------------------------------------------------

/// Common MIME type groups for media validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaType {
    /// Images (png, jpg, gif, webp, bmp, svg).
    Image,
    /// Videos (mp4, webm, mov).
    Video,
    /// Audio files (mp3, ogg, wav, flac, opus).
    Audio,
    /// Documents (pdf, txt, csv, json, xml).
    Document,
    /// Archives (zip, tar, gz, 7z).
    Archive,
    /// Any other type.
    Other,
}

impl MediaType {
    /// Infer the media type from a MIME type string.
    pub fn from_mime(mime: &str) -> Self {
        let lower = mime.to_ascii_lowercase();
        if lower.starts_with("image/") {
            Self::Image
        } else if lower.starts_with("video/") {
            Self::Video
        } else if lower.starts_with("audio/") {
            Self::Audio
        } else if lower.starts_with("application/pdf")
            || lower.starts_with("text/")
            || lower.starts_with("application/json")
            || lower.starts_with("application/xml")
        {
            Self::Document
        } else if lower.starts_with("application/zip")
            || lower.starts_with("application/gzip")
            || lower.starts_with("application/x-tar")
            || lower.starts_with("application/x-7z")
        {
            Self::Archive
        } else {
            Self::Other
        }
    }

    /// Common file extensions for this media type.
    pub fn common_extensions(&self) -> &'static [&'static str] {
        match self {
            Self::Image => &["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg"],
            Self::Video => &["mp4", "webm", "mov", "avi", "mkv"],
            Self::Audio => &["mp3", "ogg", "wav", "flac", "opus", "m4a"],
            Self::Document => &["pdf", "txt", "csv", "json", "xml", "html", "md"],
            Self::Archive => &["zip", "tar", "gz", "7z", "rar"],
            Self::Other => &[],
        }
    }
}

impl std::fmt::Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Image => write!(f, "image"),
            Self::Video => write!(f, "video"),
            Self::Audio => write!(f, "audio"),
            Self::Document => write!(f, "document"),
            Self::Archive => write!(f, "archive"),
            Self::Other => write!(f, "other"),
        }
    }
}

// ---------------------------------------------------------------------------
// MediaAttachment
// ---------------------------------------------------------------------------

/// Metadata for a media attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaAttachment {
    /// Unique attachment ID.
    pub id: String,
    /// Original filename.
    pub filename: String,
    /// MIME type string (e.g., "image/png").
    pub mime_type: String,
    /// Classified media type.
    pub media_type: MediaType,
    /// File size in bytes.
    pub size_bytes: u64,
    /// URL where the file can be downloaded.
    pub url: Option<String>,
    /// URL of a thumbnail/preview image.
    pub thumbnail_url: Option<String>,
    /// Thumbnail size in bytes (if known).
    pub thumbnail_size: Option<u64>,
    /// Width in pixels (for images/videos).
    pub width: Option<u32>,
    /// Height in pixels (for images/videos).
    pub height: Option<u32>,
    /// Duration in seconds (for audio/video).
    pub duration_secs: Option<f64>,
}

impl MediaAttachment {
    /// Create a new attachment with required fields.
    pub fn new(
        filename: impl Into<String>,
        mime_type: impl Into<String>,
        size_bytes: u64,
    ) -> Self {
        let mime = mime_type.into();
        let media_type = MediaType::from_mime(&mime);
        Self {
            id: Uuid::new_v4().to_string(),
            filename: filename.into(),
            mime_type: mime,
            media_type,
            size_bytes,
            url: None,
            thumbnail_url: None,
            thumbnail_size: None,
            width: None,
            height: None,
            duration_secs: None,
        }
    }

    /// Set the download URL.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the thumbnail URL and optional size.
    pub fn with_thumbnail(mut self, url: impl Into<String>, size: Option<u64>) -> Self {
        self.thumbnail_url = Some(url.into());
        self.thumbnail_size = size;
        self
    }

    /// Set pixel dimensions (for images/videos).
    pub fn with_dimensions(mut self, width: u32, height: u32) -> Self {
        self.width = Some(width);
        self.height = Some(height);
        self
    }

    /// Set duration in seconds (for audio/video).
    pub fn with_duration(mut self, secs: f64) -> Self {
        self.duration_secs = Some(secs);
        self
    }
}

// ---------------------------------------------------------------------------
// MediaLimits
// ---------------------------------------------------------------------------

/// Per-channel constraints on media attachments.
#[derive(Debug, Clone)]
pub struct MediaLimits {
    /// Channel name for error messages.
    pub channel_name: String,
    /// Maximum file size in bytes.
    pub max_file_size: u64,
    /// Allowed media types (empty = all allowed).
    pub allowed_types: Vec<MediaType>,
    /// Blocked MIME type strings (exact match).
    pub blocked_mimes: Vec<String>,
    /// Maximum pixel dimensions for images (width * height).
    pub max_image_pixels: Option<u64>,
    /// Maximum thumbnail size in bytes.
    pub max_thumbnail_size: u64,
}

impl MediaLimits {
    /// Create limits for a channel with sensible defaults.
    pub fn new(channel_name: impl Into<String>) -> Self {
        Self {
            channel_name: channel_name.into(),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            allowed_types: Vec::new(), // empty = all allowed
            blocked_mimes: Vec::new(),
            max_image_pixels: None,
            max_thumbnail_size: MAX_THUMBNAIL_SIZE,
        }
    }

    /// Set the maximum file size.
    pub fn with_max_size(mut self, max_bytes: u64) -> Self {
        self.max_file_size = max_bytes;
        self
    }

    /// Restrict to specific media types only.
    pub fn with_allowed_types(mut self, types: Vec<MediaType>) -> Self {
        self.allowed_types = types;
        self
    }

    /// Block specific MIME type strings.
    pub fn with_blocked_mimes(mut self, mimes: Vec<String>) -> Self {
        self.blocked_mimes = mimes;
        self
    }

    /// Validate an attachment against these limits.
    pub fn validate(&self, attachment: &MediaAttachment) -> Result<(), MediaError> {
        // Check file size
        if attachment.size_bytes > self.max_file_size {
            return Err(MediaError::FileTooLarge {
                size: attachment.size_bytes,
                limit: self.max_file_size,
                channel: self.channel_name.clone(),
            });
        }

        // Check allowed types
        if !self.allowed_types.is_empty()
            && !self.allowed_types.contains(&attachment.media_type)
        {
            return Err(MediaError::TypeNotAllowed {
                media_type: attachment.media_type,
                channel: self.channel_name.clone(),
            });
        }

        // Check blocked MIME types
        let lower_mime = attachment.mime_type.to_ascii_lowercase();
        if self.blocked_mimes.iter().any(|b| b.to_ascii_lowercase() == lower_mime) {
            return Err(MediaError::MimeBlocked {
                mime: attachment.mime_type.clone(),
                channel: self.channel_name.clone(),
            });
        }

        // Check image pixel limit
        if let (Some(max_px), Some(w), Some(h)) =
            (self.max_image_pixels, attachment.width, attachment.height)
        {
            let pixels = u64::from(w) * u64::from(h);
            if pixels > max_px {
                return Err(MediaError::ImageTooLarge {
                    pixels,
                    limit: max_px,
                    channel: self.channel_name.clone(),
                });
            }
        }

        // Check thumbnail size
        if let Some(thumb_size) = attachment.thumbnail_size {
            if thumb_size > self.max_thumbnail_size {
                return Err(MediaError::ThumbnailTooLarge {
                    size: thumb_size,
                    limit: self.max_thumbnail_size,
                });
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from media pipeline operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    /// File exceeds size limit.
    FileTooLarge { size: u64, limit: u64, channel: String },
    /// Media type not allowed for this channel.
    TypeNotAllowed { media_type: MediaType, channel: String },
    /// MIME type is explicitly blocked.
    MimeBlocked { mime: String, channel: String },
    /// Image exceeds pixel limit.
    ImageTooLarge { pixels: u64, limit: u64, channel: String },
    /// Thumbnail exceeds size limit.
    ThumbnailTooLarge { size: u64, limit: u64 },
    /// Attachment not found in registry.
    NotFound { id: String },
    /// Registry is full.
    RegistryFull { limit: usize },
    /// Invalid attachment data.
    Invalid { reason: String },
}

impl std::fmt::Display for MediaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileTooLarge {
                size,
                limit,
                channel,
            } => {
                write!(
                    f,
                    "file size {size} bytes exceeds {channel} limit of {limit} bytes"
                )
            }
            Self::TypeNotAllowed {
                media_type,
                channel,
            } => {
                write!(f, "{media_type} files not allowed on {channel}")
            }
            Self::MimeBlocked { mime, channel } => {
                write!(f, "MIME type {mime:?} is blocked on {channel}")
            }
            Self::ImageTooLarge {
                pixels,
                limit,
                channel,
            } => {
                write!(
                    f,
                    "image has {pixels} pixels, exceeding {channel} limit of {limit}"
                )
            }
            Self::ThumbnailTooLarge { size, limit } => {
                write!(
                    f,
                    "thumbnail size {size} bytes exceeds limit of {limit} bytes"
                )
            }
            Self::NotFound { id } => write!(f, "attachment {id:?} not found"),
            Self::RegistryFull { limit } => {
                write!(f, "attachment registry limit of {limit} exceeded")
            }
            Self::Invalid { reason } => write!(f, "invalid attachment: {reason}"),
        }
    }
}

impl std::error::Error for MediaError {}

// ---------------------------------------------------------------------------
// MediaPipeline
// ---------------------------------------------------------------------------

/// Cached attachment metadata with expiry.
#[derive(Debug)]
struct CachedAttachment {
    attachment: MediaAttachment,
    cached_at: Instant,
}

/// Orchestrates media upload/download with validation and metadata caching.
///
/// The pipeline does not perform actual network I/O -- it validates
/// attachments against channel limits and maintains a metadata registry.
/// Actual upload/download is delegated to the channel backends.
#[derive(Debug)]
pub struct MediaPipeline {
    /// Per-channel limits.
    channel_limits: HashMap<String, MediaLimits>,
    /// Attachment metadata cache.
    registry: HashMap<String, CachedAttachment>,
    /// TTL for cached metadata.
    metadata_ttl: Duration,
}

impl MediaPipeline {
    /// Create a new media pipeline.
    pub fn new() -> Self {
        Self {
            channel_limits: HashMap::new(),
            registry: HashMap::new(),
            metadata_ttl: DEFAULT_METADATA_TTL,
        }
    }

    /// Create a pipeline with a custom metadata TTL.
    pub fn with_ttl(metadata_ttl: Duration) -> Self {
        Self {
            channel_limits: HashMap::new(),
            registry: HashMap::new(),
            metadata_ttl,
        }
    }

    /// Register limits for a channel.
    pub fn register_channel(&mut self, limits: MediaLimits) {
        debug!(channel = %limits.channel_name, "registered media limits");
        self.channel_limits
            .insert(limits.channel_name.clone(), limits);
    }

    /// Get the limits for a channel.
    pub fn get_limits(&self, channel_name: &str) -> Option<&MediaLimits> {
        self.channel_limits.get(channel_name)
    }

    /// Validate an attachment against a channel's limits.
    ///
    /// If no limits are registered for the channel, validation passes
    /// (permissive by default).
    pub fn validate(
        &self,
        channel_name: &str,
        attachment: &MediaAttachment,
    ) -> Result<(), MediaError> {
        if let Some(limits) = self.channel_limits.get(channel_name) {
            limits.validate(attachment)
        } else {
            Ok(()) // no limits registered = permissive
        }
    }

    /// Register an attachment in the metadata cache.
    ///
    /// Returns the attachment ID for later retrieval.
    pub fn register_attachment(
        &mut self,
        attachment: MediaAttachment,
    ) -> Result<String, MediaError> {
        if self.registry.len() >= MAX_REGISTRY_SIZE {
            return Err(MediaError::RegistryFull {
                limit: MAX_REGISTRY_SIZE,
            });
        }

        if attachment.filename.is_empty() {
            return Err(MediaError::Invalid {
                reason: "filename cannot be empty".to_string(),
            });
        }
        if attachment.filename.len() > MAX_FILENAME_LEN {
            return Err(MediaError::Invalid {
                reason: format!("filename exceeds {MAX_FILENAME_LEN} characters"),
            });
        }

        let id = attachment.id.clone();
        self.registry.insert(
            id.clone(),
            CachedAttachment {
                attachment,
                cached_at: Instant::now(),
            },
        );
        Ok(id)
    }

    /// Look up an attachment by ID.
    pub fn get_attachment(&self, id: &str) -> Result<&MediaAttachment, MediaError> {
        self.registry
            .get(id)
            .map(|c| &c.attachment)
            .ok_or_else(|| MediaError::NotFound {
                id: id.to_string(),
            })
    }

    /// Remove an attachment from the cache.
    pub fn remove_attachment(&mut self, id: &str) -> Result<MediaAttachment, MediaError> {
        self.registry
            .remove(id)
            .map(|c| c.attachment)
            .ok_or_else(|| MediaError::NotFound {
                id: id.to_string(),
            })
    }

    /// Number of cached attachments.
    pub fn cached_count(&self) -> usize {
        self.registry.len()
    }

    /// Expire old cached metadata and return the number removed.
    pub fn expire_cache(&mut self) -> usize {
        let before = self.registry.len();
        self.registry
            .retain(|_, cached| cached.cached_at.elapsed() < self.metadata_ttl);
        before - self.registry.len()
    }

    /// Clear all cached metadata.
    pub fn clear_cache(&mut self) {
        self.registry.clear();
    }

    /// List all registered channel names.
    pub fn registered_channels(&self) -> Vec<&str> {
        self.channel_limits.keys().map(|k| k.as_str()).collect()
    }
}

impl Default for MediaPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- MediaType --

    #[test]
    fn media_type_from_mime() {
        assert_eq!(MediaType::from_mime("image/png"), MediaType::Image);
        assert_eq!(MediaType::from_mime("image/jpeg"), MediaType::Image);
        assert_eq!(MediaType::from_mime("video/mp4"), MediaType::Video);
        assert_eq!(MediaType::from_mime("audio/ogg"), MediaType::Audio);
        assert_eq!(MediaType::from_mime("application/pdf"), MediaType::Document);
        assert_eq!(MediaType::from_mime("text/plain"), MediaType::Document);
        assert_eq!(MediaType::from_mime("application/json"), MediaType::Document);
        assert_eq!(MediaType::from_mime("application/zip"), MediaType::Archive);
        assert_eq!(
            MediaType::from_mime("application/octet-stream"),
            MediaType::Other
        );
    }

    #[test]
    fn media_type_from_mime_case_insensitive() {
        assert_eq!(MediaType::from_mime("IMAGE/PNG"), MediaType::Image);
        assert_eq!(MediaType::from_mime("Video/MP4"), MediaType::Video);
    }

    #[test]
    fn media_type_display() {
        assert_eq!(MediaType::Image.to_string(), "image");
        assert_eq!(MediaType::Video.to_string(), "video");
        assert_eq!(MediaType::Audio.to_string(), "audio");
        assert_eq!(MediaType::Document.to_string(), "document");
        assert_eq!(MediaType::Archive.to_string(), "archive");
        assert_eq!(MediaType::Other.to_string(), "other");
    }

    #[test]
    fn media_type_common_extensions() {
        assert!(MediaType::Image.common_extensions().contains(&"png"));
        assert!(MediaType::Video.common_extensions().contains(&"mp4"));
        assert!(MediaType::Audio.common_extensions().contains(&"mp3"));
        assert!(MediaType::Document.common_extensions().contains(&"pdf"));
        assert!(MediaType::Archive.common_extensions().contains(&"zip"));
        assert!(MediaType::Other.common_extensions().is_empty());
    }

    #[test]
    fn media_type_serde_roundtrip() {
        let json = serde_json::to_string(&MediaType::Image).unwrap();
        assert_eq!(json, "\"image\"");
        let back: MediaType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, MediaType::Image);
    }

    // -- MediaAttachment --

    #[test]
    fn attachment_new() {
        let att = MediaAttachment::new("photo.png", "image/png", 1024);
        assert_eq!(att.filename, "photo.png");
        assert_eq!(att.mime_type, "image/png");
        assert_eq!(att.media_type, MediaType::Image);
        assert_eq!(att.size_bytes, 1024);
        assert!(att.url.is_none());
        assert!(att.thumbnail_url.is_none());
        assert!(!att.id.is_empty());
    }

    #[test]
    fn attachment_builder_chain() {
        let att = MediaAttachment::new("video.mp4", "video/mp4", 50_000)
            .with_url("https://cdn.example.com/video.mp4")
            .with_thumbnail("https://cdn.example.com/thumb.jpg", Some(10_000))
            .with_dimensions(1920, 1080)
            .with_duration(120.5);

        assert_eq!(att.url.as_deref(), Some("https://cdn.example.com/video.mp4"));
        assert_eq!(
            att.thumbnail_url.as_deref(),
            Some("https://cdn.example.com/thumb.jpg")
        );
        assert_eq!(att.thumbnail_size, Some(10_000));
        assert_eq!(att.width, Some(1920));
        assert_eq!(att.height, Some(1080));
        assert_eq!(att.duration_secs, Some(120.5));
    }

    #[test]
    fn attachment_serde_roundtrip() {
        let att = MediaAttachment::new("test.pdf", "application/pdf", 5000)
            .with_url("https://example.com/test.pdf");
        let json = serde_json::to_string(&att).unwrap();
        let back: MediaAttachment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, att.id);
        assert_eq!(back.filename, att.filename);
        assert_eq!(back.size_bytes, att.size_bytes);
    }

    // -- MediaLimits --

    #[test]
    fn limits_default() {
        let limits = MediaLimits::new("telegram");
        assert_eq!(limits.channel_name, "telegram");
        assert_eq!(limits.max_file_size, DEFAULT_MAX_FILE_SIZE);
        assert!(limits.allowed_types.is_empty());
        assert!(limits.blocked_mimes.is_empty());
    }

    #[test]
    fn limits_validate_size() {
        let limits = MediaLimits::new("test").with_max_size(1000);
        let small = MediaAttachment::new("f.txt", "text/plain", 500);
        assert!(limits.validate(&small).is_ok());

        let big = MediaAttachment::new("f.txt", "text/plain", 1500);
        let err = limits.validate(&big).unwrap_err();
        assert!(matches!(err, MediaError::FileTooLarge { .. }));
    }

    #[test]
    fn limits_validate_allowed_types() {
        let limits =
            MediaLimits::new("test").with_allowed_types(vec![MediaType::Image, MediaType::Document]);

        let img = MediaAttachment::new("photo.png", "image/png", 100);
        assert!(limits.validate(&img).is_ok());

        let video = MediaAttachment::new("vid.mp4", "video/mp4", 100);
        let err = limits.validate(&video).unwrap_err();
        assert!(matches!(err, MediaError::TypeNotAllowed { .. }));
    }

    #[test]
    fn limits_validate_empty_allowed_permits_all() {
        let limits = MediaLimits::new("test"); // allowed_types is empty
        let video = MediaAttachment::new("vid.mp4", "video/mp4", 100);
        assert!(limits.validate(&video).is_ok());
    }

    #[test]
    fn limits_validate_blocked_mimes() {
        let limits =
            MediaLimits::new("test").with_blocked_mimes(vec!["application/x-executable".to_string()]);

        let exe = MediaAttachment::new("bad.exe", "application/x-executable", 100);
        let err = limits.validate(&exe).unwrap_err();
        assert!(matches!(err, MediaError::MimeBlocked { .. }));
    }

    #[test]
    fn limits_validate_image_pixels() {
        let mut limits = MediaLimits::new("test");
        limits.max_image_pixels = Some(1_000_000);

        let small = MediaAttachment::new("s.png", "image/png", 100).with_dimensions(800, 600);
        assert!(limits.validate(&small).is_ok());

        let huge = MediaAttachment::new("h.png", "image/png", 100).with_dimensions(2000, 2000);
        let err = limits.validate(&huge).unwrap_err();
        assert!(matches!(err, MediaError::ImageTooLarge { .. }));
    }

    #[test]
    fn limits_validate_thumbnail_size() {
        let limits = MediaLimits::new("test");
        let att = MediaAttachment::new("f.png", "image/png", 100)
            .with_thumbnail("https://x.com/t.jpg", Some(MAX_THUMBNAIL_SIZE + 1));
        let err = limits.validate(&att).unwrap_err();
        assert!(matches!(err, MediaError::ThumbnailTooLarge { .. }));
    }

    // -- MediaPipeline --

    #[test]
    fn pipeline_register_and_validate() {
        let mut pipeline = MediaPipeline::new();
        pipeline.register_channel(MediaLimits::new("telegram").with_max_size(10_000));

        let small = MediaAttachment::new("f.txt", "text/plain", 500);
        assert!(pipeline.validate("telegram", &small).is_ok());

        let big = MediaAttachment::new("f.txt", "text/plain", 50_000);
        assert!(pipeline.validate("telegram", &big).is_err());
    }

    #[test]
    fn pipeline_no_limits_permissive() {
        let pipeline = MediaPipeline::new();
        let att = MediaAttachment::new("f.txt", "text/plain", 999_999_999);
        assert!(pipeline.validate("unknown_channel", &att).is_ok());
    }

    #[test]
    fn pipeline_register_and_lookup_attachment() {
        let mut pipeline = MediaPipeline::new();
        let att = MediaAttachment::new("photo.png", "image/png", 1024);
        let id = pipeline.register_attachment(att).unwrap();

        let found = pipeline.get_attachment(&id).unwrap();
        assert_eq!(found.filename, "photo.png");
    }

    #[test]
    fn pipeline_lookup_nonexistent() {
        let pipeline = MediaPipeline::new();
        let err = pipeline.get_attachment("ghost").unwrap_err();
        assert!(matches!(err, MediaError::NotFound { .. }));
    }

    #[test]
    fn pipeline_remove_attachment() {
        let mut pipeline = MediaPipeline::new();
        let att = MediaAttachment::new("f.txt", "text/plain", 100);
        let id = pipeline.register_attachment(att).unwrap();

        let removed = pipeline.remove_attachment(&id).unwrap();
        assert_eq!(removed.filename, "f.txt");
        assert!(pipeline.get_attachment(&id).is_err());
    }

    #[test]
    fn pipeline_register_empty_filename_rejected() {
        let mut pipeline = MediaPipeline::new();
        let att = MediaAttachment::new("", "text/plain", 100);
        let err = pipeline.register_attachment(att).unwrap_err();
        assert!(matches!(err, MediaError::Invalid { .. }));
    }

    #[test]
    fn pipeline_register_long_filename_rejected() {
        let mut pipeline = MediaPipeline::new();
        let long_name = "a".repeat(MAX_FILENAME_LEN + 1);
        let att = MediaAttachment::new(long_name, "text/plain", 100);
        let err = pipeline.register_attachment(att).unwrap_err();
        assert!(matches!(err, MediaError::Invalid { .. }));
    }

    #[test]
    fn pipeline_cached_count() {
        let mut pipeline = MediaPipeline::new();
        assert_eq!(pipeline.cached_count(), 0);

        pipeline
            .register_attachment(MediaAttachment::new("a.txt", "text/plain", 10))
            .unwrap();
        assert_eq!(pipeline.cached_count(), 1);
    }

    #[test]
    fn pipeline_clear_cache() {
        let mut pipeline = MediaPipeline::new();
        pipeline
            .register_attachment(MediaAttachment::new("a.txt", "text/plain", 10))
            .unwrap();
        pipeline.clear_cache();
        assert_eq!(pipeline.cached_count(), 0);
    }

    #[test]
    fn pipeline_expire_cache() {
        let mut pipeline = MediaPipeline::with_ttl(Duration::from_millis(0));
        pipeline
            .register_attachment(MediaAttachment::new("a.txt", "text/plain", 10))
            .unwrap();
        std::thread::sleep(Duration::from_millis(1));
        let expired = pipeline.expire_cache();
        assert_eq!(expired, 1);
        assert_eq!(pipeline.cached_count(), 0);
    }

    #[test]
    fn pipeline_registered_channels() {
        let mut pipeline = MediaPipeline::new();
        pipeline.register_channel(MediaLimits::new("telegram"));
        pipeline.register_channel(MediaLimits::new("discord"));

        let mut channels = pipeline.registered_channels();
        channels.sort();
        assert_eq!(channels, vec!["discord", "telegram"]);
    }

    #[test]
    fn pipeline_get_limits() {
        let mut pipeline = MediaPipeline::new();
        pipeline.register_channel(MediaLimits::new("telegram").with_max_size(5000));

        let limits = pipeline.get_limits("telegram").unwrap();
        assert_eq!(limits.max_file_size, 5000);
        assert!(pipeline.get_limits("unknown").is_none());
    }

    #[test]
    fn pipeline_default() {
        let pipeline = MediaPipeline::default();
        assert_eq!(pipeline.cached_count(), 0);
    }

    // -- Error Display --

    #[test]
    fn error_display() {
        assert_eq!(
            MediaError::FileTooLarge {
                size: 100,
                limit: 50,
                channel: "tg".to_string()
            }
            .to_string(),
            "file size 100 bytes exceeds tg limit of 50 bytes"
        );
        assert_eq!(
            MediaError::TypeNotAllowed {
                media_type: MediaType::Video,
                channel: "slack".to_string()
            }
            .to_string(),
            "video files not allowed on slack"
        );
        assert_eq!(
            MediaError::NotFound {
                id: "abc".to_string()
            }
            .to_string(),
            "attachment \"abc\" not found"
        );
        assert_eq!(
            MediaError::RegistryFull { limit: 10 }.to_string(),
            "attachment registry limit of 10 exceeded"
        );
    }
}
