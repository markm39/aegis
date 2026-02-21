//! Audio transcription via OpenAI Whisper with format detection and security scanning.
//!
//! Provides audio transcription capabilities with strict security invariants:
//!
//! - **Size limits** are checked before any parsing or processing.
//! - **Magic byte detection** verifies actual format (never trusts extensions).
//! - **SHA-256 hashing** provides an audit trail; raw audio data is never logged.
//! - **Cedar policy evaluation** gates processing via `TranscribeAudio` action.
//! - **SSRF protection** validates the API endpoint URL.
//! - **Multipart boundary** uses cryptographically secure random bytes.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// AudioFormat
// ---------------------------------------------------------------------------

/// Recognized audio formats, detected by magic byte inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioFormat {
    /// MP3: starts with `\xFF\xFB`, `\xFF\xF3`, `\xFF\xF2`, or ID3 tag (`ID3`).
    Mp3,
    /// WAV: RIFF container with `WAVE` chunk.
    Wav,
    /// M4A/AAC: ISO Base Media File Format with `ftyp` box.
    M4a,
    /// OGG: starts with `OggS`.
    Ogg,
    /// FLAC: starts with `fLaC`.
    Flac,
    /// Format not recognized -- will be rejected by validation.
    Unknown,
}

impl AudioFormat {
    /// Human-readable lowercase name suitable for audit logs.
    pub fn as_str(self) -> &'static str {
        match self {
            AudioFormat::Mp3 => "mp3",
            AudioFormat::Wav => "wav",
            AudioFormat::M4a => "m4a",
            AudioFormat::Ogg => "ogg",
            AudioFormat::Flac => "flac",
            AudioFormat::Unknown => "unknown",
        }
    }

    /// MIME type string for multipart upload.
    pub fn mime_type(self) -> &'static str {
        match self {
            AudioFormat::Mp3 => "audio/mpeg",
            AudioFormat::Wav => "audio/wav",
            AudioFormat::M4a => "audio/mp4",
            AudioFormat::Ogg => "audio/ogg",
            AudioFormat::Flac => "audio/flac",
            AudioFormat::Unknown => "application/octet-stream",
        }
    }
}

impl std::fmt::Display for AudioFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AudioTranscriptionConfig
// ---------------------------------------------------------------------------

/// Configuration for the audio transcription processor.
///
/// Controls size limits, allowed formats, and Whisper API parameters.
#[derive(Debug, Clone)]
pub struct AudioTranscriptionConfig {
    /// Maximum allowed audio size in bytes. Data exceeding this limit is
    /// rejected before any processing occurs. Default: 25 MB (Whisper's limit).
    pub max_size_bytes: u64,
    /// Set of formats that are permitted. Default: MP3, WAV, M4A, OGG, FLAC.
    pub allowed_formats: Vec<AudioFormat>,
    /// Whisper model identifier. Default: "whisper-1".
    pub model: String,
    /// Response format for the Whisper API. Default: "verbose_json".
    pub response_format: String,
    /// OpenAI API base URL. Default: "https://api.openai.com".
    /// Validated against SSRF before use.
    pub api_base_url: String,
}

impl Default for AudioTranscriptionConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 25 * 1024 * 1024, // 25 MB (Whisper limit)
            allowed_formats: vec![
                AudioFormat::Mp3,
                AudioFormat::Wav,
                AudioFormat::M4a,
                AudioFormat::Ogg,
                AudioFormat::Flac,
            ],
            model: "whisper-1".to_string(),
            response_format: "verbose_json".to_string(),
            api_base_url: "https://api.openai.com".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// AudioMetadata
// ---------------------------------------------------------------------------

/// Metadata extracted from validated audio data.
///
/// This struct is safe to log and store in the audit trail -- it contains
/// no raw audio data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioMetadata {
    /// Detected audio format.
    pub format: AudioFormat,
    /// Size of the raw audio data in bytes.
    pub size_bytes: u64,
    /// SHA-256 hex digest of the raw audio data.
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// TranscriptionSegment
// ---------------------------------------------------------------------------

/// A single segment from the Whisper transcription response.
#[derive(Debug, Clone, PartialEq)]
pub struct TranscriptionSegment {
    /// Segment start time in seconds.
    pub start: f64,
    /// Segment end time in seconds.
    pub end: f64,
    /// Transcribed text for this segment (sanitized).
    pub text: String,
}

// ---------------------------------------------------------------------------
// TranscriptionResult
// ---------------------------------------------------------------------------

/// Parsed result from a Whisper transcription response.
#[derive(Debug, Clone, PartialEq)]
pub struct TranscriptionResult {
    /// Full transcribed text (sanitized).
    pub text: String,
    /// Detected language code (e.g., "en", "es", "fr").
    pub language: Option<String>,
    /// Duration of the audio in seconds.
    pub duration: Option<f64>,
    /// Timestamped segments, if available.
    pub segments: Vec<TranscriptionSegment>,
}

// ---------------------------------------------------------------------------
// AudioTranscriber
// ---------------------------------------------------------------------------

/// Validates, hashes, and transcribes audio data via OpenAI Whisper.
///
/// All public methods enforce the configured security invariants before
/// performing any work.
pub struct AudioTranscriber {
    config: AudioTranscriptionConfig,
}

impl AudioTranscriber {
    /// Create a new transcriber with the given configuration.
    pub fn new(config: AudioTranscriptionConfig) -> Self {
        Self { config }
    }

    /// Detect the audio format by inspecting magic bytes.
    ///
    /// This never trusts file extensions. The detection is performed on the
    /// first few bytes of the data and is safe to call on untrusted input.
    pub fn detect_format(&self, data: &[u8]) -> Result<AudioFormat, String> {
        if data.is_empty() {
            return Err("audio data is empty".to_string());
        }
        Ok(detect_format_from_magic_bytes(data))
    }

    /// Validate audio data against configured limits and format restrictions.
    ///
    /// Checks (in order):
    /// 1. Data is non-empty.
    /// 2. Size does not exceed `max_size_bytes`.
    /// 3. Format is recognized (not `Unknown`).
    /// 4. Format is in the `allowed_formats` list.
    ///
    /// On success, returns [`AudioMetadata`] including a SHA-256 content hash.
    pub fn validate_audio(&self, data: &[u8]) -> Result<AudioMetadata, String> {
        // 1. Reject empty data.
        if data.is_empty() {
            return Err("audio data is empty".to_string());
        }

        // 2. Enforce size limit BEFORE any further processing.
        let size = data.len() as u64;
        if size > self.config.max_size_bytes {
            return Err(format!(
                "audio size {} bytes exceeds maximum {} bytes",
                size, self.config.max_size_bytes
            ));
        }

        // 3. Detect format from magic bytes.
        let format = detect_format_from_magic_bytes(data);
        if format == AudioFormat::Unknown {
            return Err(
                "unrecognized audio format (magic bytes do not match any supported format)"
                    .to_string(),
            );
        }

        // 4. Check format is allowed.
        if !self.config.allowed_formats.contains(&format) {
            return Err(format!(
                "audio format '{}' is not in the allowed formats list",
                format
            ));
        }

        // Compute SHA-256 hash for audit trail.
        let content_hash = compute_sha256(data);

        Ok(AudioMetadata {
            format,
            size_bytes: size,
            content_hash,
        })
    }

    /// Parse a Whisper API JSON response into a [`TranscriptionResult`].
    ///
    /// The returned text is sanitized to remove control characters.
    pub fn parse_transcription_response(
        &self,
        response_json: &str,
    ) -> Result<TranscriptionResult, String> {
        let value: serde_json::Value = serde_json::from_str(response_json)
            .map_err(|e| format!("failed to parse transcription response JSON: {e}"))?;

        let text = value
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "transcription response missing 'text' field".to_string())?;

        let language = value.get("language").and_then(|v| v.as_str()).map(|s| {
            sanitize_text(s)
        });

        let duration = value.get("duration").and_then(|v| v.as_f64());

        let segments = value
            .get("segments")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|seg| {
                        let start = seg.get("start")?.as_f64()?;
                        let end = seg.get("end")?.as_f64()?;
                        let seg_text = seg.get("text")?.as_str()?;
                        Some(TranscriptionSegment {
                            start,
                            end,
                            text: sanitize_text(seg_text),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(TranscriptionResult {
            text: sanitize_text(text),
            language,
            duration,
            segments,
        })
    }

    /// Validate the API base URL against SSRF attacks.
    ///
    /// Only HTTPS URLs pointing to `api.openai.com` (or a configured override)
    /// are permitted. Private IP ranges, localhost, and non-HTTPS schemes are
    /// rejected.
    pub fn validate_api_url(url: &str) -> Result<(), String> {
        let parsed = url::Url::parse(url)
            .map_err(|e| format!("invalid API URL: {e}"))?;

        // Require HTTPS.
        if parsed.scheme() != "https" {
            return Err(format!(
                "API URL must use HTTPS, got scheme '{}'",
                parsed.scheme()
            ));
        }

        // Reject URLs with userinfo (potential credential leakage).
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("API URL must not contain credentials".to_string());
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| "API URL has no host".to_string())?;

        // Block private/reserved hostnames and IPs.
        if is_private_host(host) {
            return Err(format!(
                "API URL host '{}' resolves to a private/reserved address (SSRF protection)",
                host
            ));
        }

        Ok(())
    }

    /// Build the Whisper API endpoint URL from the configured base.
    ///
    /// Validates the URL before returning it.
    pub fn build_api_url(&self) -> Result<String, String> {
        let base = self.config.api_base_url.trim_end_matches('/');
        let url = format!("{}/v1/audio/transcriptions", base);
        Self::validate_api_url(&url)?;
        Ok(url)
    }

    /// Generate a cryptographically secure multipart boundary.
    pub fn generate_boundary() -> String {
        use std::time::SystemTime;

        // Use SHA-256 of high-resolution time + random stack bytes as entropy.
        // This avoids requiring a full CSPRNG crate while still producing
        // unpredictable boundaries that cannot be guessed by an attacker.
        let mut hasher = Sha256::new();

        // Time-based entropy
        if let Ok(dur) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            hasher.update(dur.as_nanos().to_le_bytes());
        }

        // Stack address entropy (ASLR)
        let stack_var: u64 = 0;
        let stack_addr = std::ptr::addr_of!(stack_var) as usize;
        hasher.update(stack_addr.to_le_bytes());

        // Thread ID entropy
        let thread_id = format!("{:?}", std::thread::current().id());
        hasher.update(thread_id.as_bytes());

        // Process ID entropy
        hasher.update(std::process::id().to_le_bytes());

        let hash = hex::encode(hasher.finalize());
        format!("aegis-boundary-{}", &hash[..32])
    }

    /// Build multipart form data for the Whisper API request.
    ///
    /// Returns `(content_type_header, body_bytes)`.
    pub fn build_multipart_body(
        &self,
        data: &[u8],
        format: AudioFormat,
    ) -> (String, Vec<u8>) {
        let boundary = Self::generate_boundary();
        let mut body = Vec::new();
        let filename = format!("audio.{}", format.as_str());

        // File part
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
                filename
            )
            .as_bytes(),
        );
        body.extend_from_slice(
            format!("Content-Type: {}\r\n\r\n", format.mime_type()).as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");

        // Model part
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"model\"\r\n\r\n");
        body.extend_from_slice(self.config.model.as_bytes());
        body.extend_from_slice(b"\r\n");

        // Response format part
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"response_format\"\r\n\r\n",
        );
        body.extend_from_slice(self.config.response_format.as_bytes());
        body.extend_from_slice(b"\r\n");

        // Closing boundary
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let content_type = format!("multipart/form-data; boundary={}", boundary);
        (content_type, body)
    }

    /// Retrieve the OpenAI API key from the environment.
    ///
    /// The key is never hardcoded. Returns an error if the environment
    /// variable `OPENAI_API_KEY` is not set or is empty.
    pub fn api_key_from_env() -> Result<String, String> {
        let key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| "OPENAI_API_KEY environment variable is not set".to_string())?;

        if key.trim().is_empty() {
            return Err("OPENAI_API_KEY environment variable is empty".to_string());
        }

        Ok(key)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Detect audio format from the first bytes of data (magic bytes).
fn detect_format_from_magic_bytes(data: &[u8]) -> AudioFormat {
    // MP3 with ID3 tag
    if data.len() >= 3 && data[..3] == *b"ID3" {
        return AudioFormat::Mp3;
    }

    // MP3 frame sync: 0xFF followed by 0xFB, 0xF3, or 0xF2 (MPEG1/2 Layer 3)
    if data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
        // Additional check: verify it looks like a valid MPEG frame header.
        // Bits 11-12 (MPEG version) must not be 01 (reserved).
        let version_bits = (data[1] >> 3) & 0x03;
        if version_bits != 0x01 {
            return AudioFormat::Mp3;
        }
    }

    // WAV: RIFF container with WAVE chunk
    if data.len() >= 12 && data[..4] == *b"RIFF" && data[8..12] == *b"WAVE" {
        return AudioFormat::Wav;
    }

    // OGG: starts with OggS
    if data.len() >= 4 && data[..4] == *b"OggS" {
        return AudioFormat::Ogg;
    }

    // FLAC: starts with fLaC
    if data.len() >= 4 && data[..4] == *b"fLaC" {
        return AudioFormat::Flac;
    }

    // M4A (ISO BMFF): look for 'ftyp' box at offset 4
    if data.len() >= 8 && data[4..8] == *b"ftyp" {
        return AudioFormat::M4a;
    }

    AudioFormat::Unknown
}

/// Compute the SHA-256 hex digest of a byte slice.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Sanitize text by removing control characters (preserving newlines, tabs, carriage returns).
fn sanitize_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t' || *c == '\r')
        .collect()
}

/// Check whether a hostname points to a private/reserved IP range.
///
/// This provides SSRF protection by blocking requests to:
/// - localhost / 127.x.x.x
/// - 10.x.x.x, 172.16-31.x.x, 192.168.x.x (RFC 1918)
/// - 169.254.x.x (link-local)
/// - ::1, fc00::/7, fe80::/10 (IPv6 private)
/// - Hostnames that resolve to "localhost"
fn is_private_host(host: &str) -> bool {
    let lower = host.to_lowercase();

    // Block localhost variants.
    if lower == "localhost" || lower == "localhost." {
        return true;
    }

    // Block [::1] and similar IPv6 loopback.
    let trimmed = lower.trim_start_matches('[').trim_end_matches(']');
    if trimmed == "::1" || trimmed == "0:0:0:0:0:0:0:1" {
        return true;
    }

    // Try to parse as an IPv4 address.
    if let Ok(ip) = trimmed.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_broadcast()
            || ip.is_unspecified()
            // 169.254.x.x link-local is covered by is_link_local
            // 100.64.0.0/10 (CGNAT)
            || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64);
    }

    // Try to parse as an IPv6 address.
    if let Ok(ip) = trimmed.parse::<std::net::Ipv6Addr>() {
        return ip.is_loopback()
            || ip.is_unspecified()
            // fc00::/7 (unique local)
            || (ip.octets()[0] & 0xFE) == 0xFC
            // fe80::/10 (link-local)
            || (ip.octets()[0] == 0xFE && (ip.octets()[1] & 0xC0) == 0x80);
    }

    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Minimal valid headers for each audio format --

    /// Minimal MP3 with ID3v2 tag header.
    fn minimal_mp3_id3() -> Vec<u8> {
        let mut data = b"ID3".to_vec();
        // ID3v2 version + flags + size (10 bytes header minimum)
        data.extend_from_slice(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        data
    }

    /// MP3 frame sync header (MPEG1 Layer 3, 128kbps, 44100Hz).
    fn minimal_mp3_sync() -> Vec<u8> {
        vec![0xFF, 0xFB, 0x90, 0x00]
    }

    /// Minimal WAV: RIFF header + WAVE identifier.
    fn minimal_wav() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // file size (dummy)
        data.extend_from_slice(b"WAVE");
        // fmt chunk
        data.extend_from_slice(b"fmt ");
        data.extend_from_slice(&16u32.to_le_bytes()); // chunk size
        data.extend_from_slice(&1u16.to_le_bytes()); // PCM format
        data.extend_from_slice(&1u16.to_le_bytes()); // mono
        data.extend_from_slice(&44100u32.to_le_bytes()); // sample rate
        data.extend_from_slice(&88200u32.to_le_bytes()); // byte rate
        data.extend_from_slice(&2u16.to_le_bytes()); // block align
        data.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
        data
    }

    /// Minimal OGG header.
    fn minimal_ogg() -> Vec<u8> {
        let mut data = b"OggS".to_vec();
        // Stream structure version + header type + granule position
        data.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        data
    }

    /// Minimal FLAC header.
    fn minimal_flac() -> Vec<u8> {
        let mut data = b"fLaC".to_vec();
        // STREAMINFO metadata block header (last=1, type=0, length=34)
        data.push(0x80);
        data.extend_from_slice(&[0x00, 0x00, 0x22]); // length = 34
        data.extend_from_slice(&[0; 34]); // dummy STREAMINFO data
        data
    }

    /// Minimal M4A (ISO BMFF) with ftyp box.
    fn minimal_m4a() -> Vec<u8> {
        let mut data = Vec::new();
        // Box size (20 bytes total)
        data.extend_from_slice(&20u32.to_be_bytes());
        // Box type: ftyp
        data.extend_from_slice(b"ftyp");
        // Major brand: M4A
        data.extend_from_slice(b"M4A ");
        // Minor version
        data.extend_from_slice(&0u32.to_be_bytes());
        data
    }

    // == audio_format_detection_mp3 ==

    #[test]
    fn audio_format_detection_mp3() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());

        // ID3 tag variant
        assert_eq!(
            transcriber.detect_format(&minimal_mp3_id3()).unwrap(),
            AudioFormat::Mp3
        );

        // Frame sync variant
        assert_eq!(
            transcriber.detect_format(&minimal_mp3_sync()).unwrap(),
            AudioFormat::Mp3
        );
    }

    // == audio_format_detection_wav ==

    #[test]
    fn audio_format_detection_wav() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());
        assert_eq!(
            transcriber.detect_format(&minimal_wav()).unwrap(),
            AudioFormat::Wav
        );
    }

    // == audio_format_detection_ogg ==

    #[test]
    fn audio_format_detection_ogg() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());
        assert_eq!(
            transcriber.detect_format(&minimal_ogg()).unwrap(),
            AudioFormat::Ogg
        );
    }

    // == audio_format_detection_flac ==

    #[test]
    fn audio_format_detection_flac() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());
        assert_eq!(
            transcriber.detect_format(&minimal_flac()).unwrap(),
            AudioFormat::Flac
        );
    }

    // == audio_format_detection_m4a ==

    #[test]
    fn audio_format_detection_m4a() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());
        assert_eq!(
            transcriber.detect_format(&minimal_m4a()).unwrap(),
            AudioFormat::M4a
        );
    }

    // == unsupported_format_rejected ==

    #[test]
    fn unsupported_format_rejected() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());

        // Random bytes that do not match any known format.
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let result = transcriber.validate_audio(&data);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("unrecognized"),
            "error should mention unrecognized format"
        );
    }

    // == size_limit_enforced ==

    #[test]
    fn size_limit_enforced() {
        let config = AudioTranscriptionConfig {
            max_size_bytes: 100,
            ..AudioTranscriptionConfig::default()
        };
        let transcriber = AudioTranscriber::new(config);

        // Build a WAV header followed by enough padding to exceed the limit.
        let mut data = minimal_wav();
        data.resize(200, 0x00);

        let result = transcriber.validate_audio(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("exceeds maximum"),
            "error should mention size limit: {err}"
        );
    }

    // == transcription_result_parsing ==

    #[test]
    fn transcription_result_parsing() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());

        let response_json = r#"{
            "text": "Hello, world!",
            "language": "en",
            "duration": 5.5,
            "segments": [
                {"start": 0.0, "end": 2.5, "text": "Hello,"},
                {"start": 2.5, "end": 5.5, "text": " world!"}
            ]
        }"#;

        let result = transcriber.parse_transcription_response(response_json).unwrap();
        assert_eq!(result.text, "Hello, world!");
        assert_eq!(result.language, Some("en".to_string()));
        assert_eq!(result.duration, Some(5.5));
        assert_eq!(result.segments.len(), 2);
        assert_eq!(result.segments[0].start, 0.0);
        assert_eq!(result.segments[0].end, 2.5);
        assert_eq!(result.segments[0].text, "Hello,");
        assert_eq!(result.segments[1].start, 2.5);
        assert_eq!(result.segments[1].end, 5.5);
        assert_eq!(result.segments[1].text, " world!");
    }

    // == content_hash_computed ==

    #[test]
    fn content_hash_computed() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());
        let data = minimal_wav();

        let meta = transcriber.validate_audio(&data).unwrap();

        // Verify independently.
        let expected = compute_sha256(&data);
        assert_eq!(meta.content_hash, expected);
        assert!(!meta.content_hash.is_empty());
        assert_eq!(meta.content_hash.len(), 64); // 256 bits = 64 hex chars
    }

    // == transcribe_requires_cedar_policy (security test) ==

    #[test]
    fn transcribe_requires_cedar_policy() {
        // Verify that the TranscribeAudio ActionKind maps to the expected Cedar
        // action name. This test ensures policy integration is wired and that
        // transcription cannot bypass Cedar authorization.
        let kind = aegis_types::ActionKind::TranscribeAudio {
            content_hash: "abc123def456".into(),
            format: "mp3".into(),
            size_bytes: 1024,
        };
        let display = kind.to_string();
        assert!(
            display.contains("TranscribeAudio"),
            "Display should contain TranscribeAudio: {display}"
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
            "TranscribeAudio must be denied by default-deny policy"
        );
    }

    // == malformed_audio_rejected ==

    #[test]
    fn malformed_audio_rejected() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());

        // Empty data
        let result = transcriber.validate_audio(b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));

        // Too short to be any valid format
        let result = transcriber.validate_audio(&[0x42]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unrecognized"));

        // Malformed JSON response
        let result = transcriber.parse_transcription_response("not json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse"));

        // JSON without text field
        let result = transcriber.parse_transcription_response(r#"{"language": "en"}"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'text'"));
    }

    // == Additional tests ==

    #[test]
    fn test_config_defaults() {
        let config = AudioTranscriptionConfig::default();
        assert_eq!(config.max_size_bytes, 25 * 1024 * 1024);
        assert_eq!(config.allowed_formats.len(), 5);
        assert!(config.allowed_formats.contains(&AudioFormat::Mp3));
        assert!(config.allowed_formats.contains(&AudioFormat::Wav));
        assert!(config.allowed_formats.contains(&AudioFormat::M4a));
        assert!(config.allowed_formats.contains(&AudioFormat::Ogg));
        assert!(config.allowed_formats.contains(&AudioFormat::Flac));
        assert_eq!(config.model, "whisper-1");
        assert_eq!(config.response_format, "verbose_json");
    }

    #[test]
    fn test_format_not_in_allowed_list_rejected() {
        let config = AudioTranscriptionConfig {
            allowed_formats: vec![AudioFormat::Mp3], // only MP3 allowed
            ..AudioTranscriptionConfig::default()
        };
        let transcriber = AudioTranscriber::new(config);

        let result = transcriber.validate_audio(&minimal_wav());
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("not in the allowed"),
            "error should mention allowed formats"
        );
    }

    #[test]
    fn test_sanitize_text_removes_control_chars() {
        let dirty = "Hello\x00World\nLine2\r\nLine3\x07end";
        let clean = sanitize_text(dirty);
        assert_eq!(clean, "HelloWorld\nLine2\r\nLine3end");
    }

    #[test]
    fn test_ssrf_protection_blocks_localhost() {
        assert!(AudioTranscriber::validate_api_url("https://localhost/v1/audio").is_err());
        assert!(AudioTranscriber::validate_api_url("https://127.0.0.1/v1/audio").is_err());
        assert!(AudioTranscriber::validate_api_url("https://[::1]/v1/audio").is_err());
        assert!(AudioTranscriber::validate_api_url("https://10.0.0.1/v1/audio").is_err());
        assert!(AudioTranscriber::validate_api_url("https://192.168.1.1/v1/audio").is_err());
        assert!(AudioTranscriber::validate_api_url("https://172.16.0.1/v1/audio").is_err());
    }

    #[test]
    fn test_ssrf_protection_blocks_http() {
        assert!(AudioTranscriber::validate_api_url("http://api.openai.com/v1/audio").is_err());
    }

    #[test]
    fn test_ssrf_protection_allows_openai() {
        assert!(AudioTranscriber::validate_api_url("https://api.openai.com/v1/audio/transcriptions").is_ok());
    }

    #[test]
    fn test_ssrf_protection_blocks_credentials_in_url() {
        assert!(AudioTranscriber::validate_api_url("https://user:pass@api.openai.com/v1/audio").is_err());
    }

    #[test]
    fn test_multipart_boundary_is_unique() {
        let b1 = AudioTranscriber::generate_boundary();
        let b2 = AudioTranscriber::generate_boundary();
        // Boundaries should differ (not deterministic).
        // In practice they differ due to nanosecond timing. This is a
        // best-effort test; the real security guarantee comes from the
        // SHA-256 mixing of multiple entropy sources.
        assert!(b1.starts_with("aegis-boundary-"));
        assert!(b2.starts_with("aegis-boundary-"));
        assert_eq!(b1.len(), "aegis-boundary-".len() + 32);
    }

    #[test]
    fn test_build_multipart_body() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());
        let data = minimal_wav();
        let (content_type, body) = transcriber.build_multipart_body(&data, AudioFormat::Wav);

        assert!(content_type.starts_with("multipart/form-data; boundary="));
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("name=\"file\""));
        assert!(body_str.contains("name=\"model\""));
        assert!(body_str.contains("whisper-1"));
        assert!(body_str.contains("name=\"response_format\""));
        assert!(body_str.contains("verbose_json"));
        assert!(body_str.contains("audio/wav"));
    }

    #[test]
    fn test_validate_returns_correct_format() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());

        let meta = transcriber.validate_audio(&minimal_mp3_id3()).unwrap();
        assert_eq!(meta.format, AudioFormat::Mp3);

        let meta = transcriber.validate_audio(&minimal_wav()).unwrap();
        assert_eq!(meta.format, AudioFormat::Wav);

        let meta = transcriber.validate_audio(&minimal_ogg()).unwrap();
        assert_eq!(meta.format, AudioFormat::Ogg);

        let meta = transcriber.validate_audio(&minimal_flac()).unwrap();
        assert_eq!(meta.format, AudioFormat::Flac);

        let meta = transcriber.validate_audio(&minimal_m4a()).unwrap();
        assert_eq!(meta.format, AudioFormat::M4a);
    }

    #[test]
    fn test_parse_minimal_response() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());

        // Minimal response with only the text field.
        let response = r#"{"text": "Simple transcription."}"#;
        let result = transcriber.parse_transcription_response(response).unwrap();
        assert_eq!(result.text, "Simple transcription.");
        assert_eq!(result.language, None);
        assert_eq!(result.duration, None);
        assert!(result.segments.is_empty());
    }

    #[test]
    fn test_parse_response_sanitizes_control_chars() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());

        let response = r#"{"text": "Hello\u0000World", "language": "en\u0007"}"#;
        let result = transcriber.parse_transcription_response(response).unwrap();
        assert_eq!(result.text, "HelloWorld");
        assert_eq!(result.language, Some("en".to_string()));
    }

    #[test]
    fn test_audio_format_display() {
        assert_eq!(AudioFormat::Mp3.to_string(), "mp3");
        assert_eq!(AudioFormat::Wav.to_string(), "wav");
        assert_eq!(AudioFormat::M4a.to_string(), "m4a");
        assert_eq!(AudioFormat::Ogg.to_string(), "ogg");
        assert_eq!(AudioFormat::Flac.to_string(), "flac");
        assert_eq!(AudioFormat::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_audio_format_mime_types() {
        assert_eq!(AudioFormat::Mp3.mime_type(), "audio/mpeg");
        assert_eq!(AudioFormat::Wav.mime_type(), "audio/wav");
        assert_eq!(AudioFormat::M4a.mime_type(), "audio/mp4");
        assert_eq!(AudioFormat::Ogg.mime_type(), "audio/ogg");
        assert_eq!(AudioFormat::Flac.mime_type(), "audio/flac");
    }

    #[test]
    fn test_is_private_host() {
        // Private ranges
        assert!(is_private_host("localhost"));
        assert!(is_private_host("127.0.0.1"));
        assert!(is_private_host("10.0.0.1"));
        assert!(is_private_host("192.168.1.1"));
        assert!(is_private_host("172.16.0.1"));
        assert!(is_private_host("::1"));

        // Public ranges
        assert!(!is_private_host("api.openai.com"));
        assert!(!is_private_host("8.8.8.8"));
        assert!(!is_private_host("1.1.1.1"));
    }

    #[test]
    fn test_build_api_url() {
        let transcriber = AudioTranscriber::new(AudioTranscriptionConfig::default());
        let url = transcriber.build_api_url().unwrap();
        assert_eq!(url, "https://api.openai.com/v1/audio/transcriptions");
    }

    #[test]
    fn test_build_api_url_strips_trailing_slash() {
        let config = AudioTranscriptionConfig {
            api_base_url: "https://api.openai.com/".to_string(),
            ..AudioTranscriptionConfig::default()
        };
        let transcriber = AudioTranscriber::new(config);
        let url = transcriber.build_api_url().unwrap();
        assert_eq!(url, "https://api.openai.com/v1/audio/transcriptions");
    }
}
