//! Text-to-speech engine for Aegis with Cedar policy enforcement.
//!
//! Provides a [`TtsProvider`] trait for pluggable TTS backends, with an
//! [`OpenAiTtsProvider`] implementation. All synthesis requests are gated
//! by Cedar policy (via [`ActionKind::TtsSynthesize`]) and text inputs
//! are sanitized before reaching any external API.
//!
//! # Security
//!
//! - API keys come from environment variables, never config files.
//! - Text input is sanitized: control characters stripped, max 4096 chars.
//! - SSRF protection: API endpoint URLs are validated against private IP ranges.
//! - Every TTS request is logged with a text hash (not raw text) for auditability.

pub mod openai;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use url::Url;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during TTS operations.
#[derive(Debug, thiserror::Error)]
pub enum TtsError {
    /// Input text exceeded the maximum allowed length.
    #[error("text exceeds maximum length of {max} characters (got {actual})")]
    TextTooLong { max: usize, actual: usize },

    /// Input text was empty after sanitization.
    #[error("text is empty after sanitization")]
    EmptyText,

    /// The TTS provider API returned an error.
    #[error("provider error: {0}")]
    ProviderError(String),

    /// HTTP request failed.
    #[error("http error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// API key was not found in environment variables.
    #[error("missing API key: environment variable {0} is not set")]
    MissingApiKey(String),

    /// URL validation failed (e.g., SSRF protection).
    #[error("invalid endpoint URL: {0}")]
    InvalidEndpoint(String),

    /// Cedar policy denied the TTS request.
    #[error("policy denied TTS request: {0}")]
    PolicyDenied(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    ConfigError(String),
}

/// Convenience alias for TTS results.
pub type TtsResult<T> = Result<T, TtsError>;

// ---------------------------------------------------------------------------
// Audio format
// ---------------------------------------------------------------------------

/// Supported audio output formats for TTS synthesis.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AudioFormat {
    /// MPEG Audio Layer 3 format.
    #[default]
    Mp3,
    /// Waveform Audio File Format (uncompressed PCM).
    Wav,
    /// Ogg Vorbis container format.
    Ogg,
}

impl AudioFormat {
    /// Return the MIME type string for this audio format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            AudioFormat::Mp3 => "audio/mpeg",
            AudioFormat::Wav => "audio/wav",
            AudioFormat::Ogg => "audio/ogg",
        }
    }

    /// Return the format string used by API providers.
    pub fn api_format_str(&self) -> &'static str {
        match self {
            AudioFormat::Mp3 => "mp3",
            AudioFormat::Wav => "wav",
            AudioFormat::Ogg => "opus",
        }
    }

    /// Return the file extension for this format (without the leading dot).
    pub fn extension(&self) -> &'static str {
        match self {
            AudioFormat::Mp3 => "mp3",
            AudioFormat::Wav => "wav",
            AudioFormat::Ogg => "ogg",
        }
    }
}

impl std::fmt::Display for AudioFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.api_format_str())
    }
}

// ---------------------------------------------------------------------------
// Voice info
// ---------------------------------------------------------------------------

/// Metadata describing a TTS voice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoiceInfo {
    /// Provider-specific voice identifier (e.g., "alloy", "echo").
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Provider that offers this voice (e.g., "openai").
    pub provider: String,
    /// BCP-47 language tag (e.g., "en-US"), if known.
    pub language: Option<String>,
    /// Voice gender, if specified by the provider.
    pub gender: Option<String>,
    /// Voice style description (e.g., "warm", "authoritative"), if available.
    pub style: Option<String>,
    /// URL for a sample audio preview, if available.
    pub preview_url: Option<String>,
}

// ---------------------------------------------------------------------------
// TtsProvider trait
// ---------------------------------------------------------------------------

/// Trait for pluggable text-to-speech backends.
///
/// Each implementation handles communication with a specific TTS API.
/// Callers are responsible for running Cedar policy checks before invoking
/// [`synthesize`](TtsProvider::synthesize).
#[async_trait]
pub trait TtsProvider: Send + Sync {
    /// Synthesize text into audio bytes.
    ///
    /// The `text` should already be sanitized via [`sanitize_text`].
    /// The `voice` is a provider-specific voice ID. If `None`, the
    /// provider's default voice is used.
    /// The `format` selects the output audio encoding.
    async fn synthesize(
        &self,
        text: &str,
        voice: Option<&str>,
        format: AudioFormat,
    ) -> TtsResult<Vec<u8>>;

    /// List all voices available from this provider.
    fn list_voices(&self) -> Vec<VoiceInfo>;

    /// Return the provider name (e.g., "openai", "elevenlabs").
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// TTS configuration
// ---------------------------------------------------------------------------

/// Configuration for the TTS engine.
///
/// API keys are resolved from environment variables at runtime, never stored
/// in the config itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtsConfig {
    /// Which provider to use (e.g., "openai").
    #[serde(default = "default_provider")]
    pub provider: String,

    /// Environment variable name holding the API key.
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,

    /// Default voice ID to use when none is specified.
    #[serde(default = "default_voice")]
    pub default_voice: String,

    /// Default audio output format.
    #[serde(default)]
    pub default_format: AudioFormat,

    /// Maximum text length in characters (hard cap: 4096).
    #[serde(default = "default_max_text_length")]
    pub max_text_length: usize,

    /// Rate limit: maximum requests per minute. 0 means unlimited.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_rpm: u32,

    /// Custom API endpoint URL override (must pass SSRF validation).
    pub endpoint_url: Option<String>,
}

fn default_provider() -> String {
    "openai".to_string()
}

fn default_api_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}

fn default_voice() -> String {
    "alloy".to_string()
}

fn default_max_text_length() -> usize {
    4096
}

fn default_rate_limit() -> u32 {
    60
}

impl Default for TtsConfig {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            api_key_env: default_api_key_env(),
            default_voice: default_voice(),
            default_format: AudioFormat::default(),
            max_text_length: default_max_text_length(),
            rate_limit_rpm: default_rate_limit(),
            endpoint_url: None,
        }
    }
}

impl TtsConfig {
    /// Resolve the API key from the configured environment variable.
    ///
    /// Returns an error if the variable is not set or is empty.
    pub fn resolve_api_key(&self) -> TtsResult<String> {
        std::env::var(&self.api_key_env)
            .map_err(|_| TtsError::MissingApiKey(self.api_key_env.clone()))
            .and_then(|key| {
                if key.is_empty() {
                    Err(TtsError::MissingApiKey(self.api_key_env.clone()))
                } else {
                    Ok(key)
                }
            })
    }
}

// ---------------------------------------------------------------------------
// Text sanitization
// ---------------------------------------------------------------------------

/// Maximum allowed text length for TTS synthesis.
pub const MAX_TEXT_LENGTH: usize = 4096;

/// Sanitize text input for TTS synthesis.
///
/// Strips control characters (except newline, tab, and carriage return),
/// trims leading/trailing whitespace, and enforces the maximum text length.
///
/// Returns the sanitized text or an error if the result is empty or too long.
pub fn sanitize_text(text: &str, max_length: usize) -> TtsResult<String> {
    // Cap the effective max length at the absolute maximum.
    let effective_max = max_length.min(MAX_TEXT_LENGTH);

    // Strip control characters, preserving newlines, tabs, and carriage returns
    // for natural paragraph breaks.
    let sanitized: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t' || *c == '\r')
        .collect();

    let sanitized = sanitized.trim().to_string();

    if sanitized.is_empty() {
        return Err(TtsError::EmptyText);
    }

    if sanitized.len() > effective_max {
        return Err(TtsError::TextTooLong {
            max: effective_max,
            actual: sanitized.len(),
        });
    }

    Ok(sanitized)
}

/// Compute a SHA-256 hex digest of the text for audit logging.
///
/// The raw text is never stored in audit logs -- only this hash is recorded,
/// providing traceability without exposing sensitive content.
pub fn text_hash(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

/// Validate that a URL is safe to use as an API endpoint.
///
/// Rejects:
/// - Non-HTTPS schemes (except for localhost/loopback in tests)
/// - URLs resolving to private/link-local IP ranges (not loopback)
/// - URLs with no host or empty host
pub fn validate_endpoint_url(url_str: &str) -> TtsResult<Url> {
    let url = Url::parse(url_str)
        .map_err(|e| TtsError::InvalidEndpoint(format!("failed to parse URL: {e}")))?;

    let host = url.host_str().unwrap_or("");
    if host.is_empty() {
        return Err(TtsError::InvalidEndpoint(
            "URL has no host".to_string(),
        ));
    }

    let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";

    // Require HTTPS for non-localhost URLs.
    match url.scheme() {
        "https" => {}
        "http" if is_localhost => {}
        "http" => {
            return Err(TtsError::InvalidEndpoint(
                "only HTTPS is allowed for non-localhost endpoints".to_string(),
            ));
        }
        scheme => {
            return Err(TtsError::InvalidEndpoint(format!(
                "unsupported scheme: {scheme}"
            )));
        }
    }

    // Skip SSRF checks for localhost/loopback (needed for local dev and tests).
    // For all other hosts, reject private/reserved IP addresses.
    if !is_localhost {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_ip(&ip) {
                return Err(TtsError::InvalidEndpoint(format!(
                    "endpoint resolves to private IP: {ip}"
                )));
            }
        }
    }

    Ok(url)
}

/// Check if an IP address is in a private, loopback, or link-local range.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()        // 127.0.0.0/8
                || v4.is_private()   // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local() // 169.254.0.0/16
                || v4.is_broadcast() // 255.255.255.255
                || v4.is_unspecified() // 0.0.0.0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()         // ::1
                || v6.is_unspecified() // ::
                // ULA: fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local: fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Text sanitization tests --

    #[test]
    fn text_sanitization_strips_control_chars() {
        // Input with null bytes, bell, backspace, escape sequences
        let input = "Hello\x00World\x07!\x08Test\x1BEnd";
        let result = sanitize_text(input, MAX_TEXT_LENGTH).unwrap();
        assert_eq!(result, "HelloWorld!TestEnd");
    }

    #[test]
    fn text_sanitization_preserves_whitespace() {
        let input = "Hello\nWorld\tGoodbye\r\n";
        let result = sanitize_text(input, MAX_TEXT_LENGTH).unwrap();
        assert_eq!(result, "Hello\nWorld\tGoodbye");
    }

    #[test]
    fn text_sanitization_trims_whitespace() {
        let input = "   Hello World   ";
        let result = sanitize_text(input, MAX_TEXT_LENGTH).unwrap();
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn text_sanitization_rejects_empty() {
        let result = sanitize_text("", MAX_TEXT_LENGTH);
        assert!(matches!(result, Err(TtsError::EmptyText)));
    }

    #[test]
    fn text_sanitization_rejects_only_control_chars() {
        let result = sanitize_text("\x00\x01\x02\x03", MAX_TEXT_LENGTH);
        assert!(matches!(result, Err(TtsError::EmptyText)));
    }

    #[test]
    fn text_length_limit_enforced() {
        let long_text = "a".repeat(4097);
        let result = sanitize_text(&long_text, MAX_TEXT_LENGTH);
        assert!(matches!(
            result,
            Err(TtsError::TextTooLong {
                max: 4096,
                actual: 4097
            })
        ));
    }

    #[test]
    fn text_length_custom_limit() {
        let text = "a".repeat(100);
        let result = sanitize_text(&text, 50);
        assert!(matches!(
            result,
            Err(TtsError::TextTooLong {
                max: 50,
                actual: 100
            })
        ));
    }

    #[test]
    fn text_length_exactly_at_limit() {
        let text = "a".repeat(4096);
        let result = sanitize_text(&text, MAX_TEXT_LENGTH);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 4096);
    }

    #[test]
    fn text_length_custom_limit_capped_at_max() {
        // Even if you pass a higher limit, it caps at MAX_TEXT_LENGTH.
        let text = "a".repeat(5000);
        let result = sanitize_text(&text, 10000);
        assert!(matches!(result, Err(TtsError::TextTooLong { max: 4096, .. })));
    }

    // -- Text hash tests --

    #[test]
    fn text_hash_deterministic() {
        let h1 = text_hash("Hello, world!");
        let h2 = text_hash("Hello, world!");
        assert_eq!(h1, h2);
    }

    #[test]
    fn text_hash_different_inputs() {
        let h1 = text_hash("Hello");
        let h2 = text_hash("World");
        assert_ne!(h1, h2);
    }

    #[test]
    fn text_hash_is_hex_sha256() {
        let h = text_hash("test");
        assert_eq!(h.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- Audio format tests --

    #[test]
    fn audio_format_selection() {
        assert_eq!(AudioFormat::Mp3.api_format_str(), "mp3");
        assert_eq!(AudioFormat::Wav.api_format_str(), "wav");
        assert_eq!(AudioFormat::Ogg.api_format_str(), "opus");

        assert_eq!(AudioFormat::Mp3.mime_type(), "audio/mpeg");
        assert_eq!(AudioFormat::Wav.mime_type(), "audio/wav");
        assert_eq!(AudioFormat::Ogg.mime_type(), "audio/ogg");

        assert_eq!(AudioFormat::Mp3.extension(), "mp3");
        assert_eq!(AudioFormat::Wav.extension(), "wav");
        assert_eq!(AudioFormat::Ogg.extension(), "ogg");
    }

    #[test]
    fn audio_format_default_is_mp3() {
        assert_eq!(AudioFormat::default(), AudioFormat::Mp3);
    }

    #[test]
    fn audio_format_serialization_roundtrip() {
        for format in [AudioFormat::Mp3, AudioFormat::Wav, AudioFormat::Ogg] {
            let json = serde_json::to_string(&format).unwrap();
            let back: AudioFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(back, format);
        }
    }

    // -- Config tests --

    #[test]
    fn tts_config_from_env() {
        // Set a test API key
        std::env::set_var("TEST_TTS_API_KEY_12345", "sk-test-key-value");

        let config = TtsConfig {
            api_key_env: "TEST_TTS_API_KEY_12345".to_string(),
            ..TtsConfig::default()
        };

        let key = config.resolve_api_key().unwrap();
        assert_eq!(key, "sk-test-key-value");

        // Clean up
        std::env::remove_var("TEST_TTS_API_KEY_12345");
    }

    #[test]
    fn tts_config_missing_env_var() {
        let config = TtsConfig {
            api_key_env: "DEFINITELY_NOT_SET_TTS_KEY_XYZ".to_string(),
            ..TtsConfig::default()
        };
        let result = config.resolve_api_key();
        assert!(matches!(result, Err(TtsError::MissingApiKey(_))));
    }

    #[test]
    fn tts_config_empty_env_var() {
        std::env::set_var("EMPTY_TTS_KEY_TEST", "");
        let config = TtsConfig {
            api_key_env: "EMPTY_TTS_KEY_TEST".to_string(),
            ..TtsConfig::default()
        };
        let result = config.resolve_api_key();
        assert!(matches!(result, Err(TtsError::MissingApiKey(_))));
        std::env::remove_var("EMPTY_TTS_KEY_TEST");
    }

    #[test]
    fn tts_config_defaults() {
        let config = TtsConfig::default();
        assert_eq!(config.provider, "openai");
        assert_eq!(config.api_key_env, "OPENAI_API_KEY");
        assert_eq!(config.default_voice, "alloy");
        assert_eq!(config.default_format, AudioFormat::Mp3);
        assert_eq!(config.max_text_length, 4096);
        assert_eq!(config.rate_limit_rpm, 60);
        assert!(config.endpoint_url.is_none());
    }

    #[test]
    fn tts_config_serialization_roundtrip() {
        let config = TtsConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: TtsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider, config.provider);
        assert_eq!(back.default_voice, config.default_voice);
    }

    // -- SSRF protection tests --

    #[test]
    fn validate_endpoint_rejects_private_ips() {
        // Private RFC1918 ranges must be blocked (SSRF protection).
        assert!(validate_endpoint_url("https://10.0.0.1/v1/audio").is_err());
        assert!(validate_endpoint_url("https://192.168.1.1/v1/audio").is_err());
        assert!(validate_endpoint_url("https://172.16.0.1/v1/audio").is_err());
        // Loopback (127.0.0.1) is intentionally allowed for local dev/testing.
        assert!(validate_endpoint_url("https://127.0.0.1/v1/audio").is_ok());
    }

    #[test]
    fn validate_endpoint_rejects_http_non_localhost() {
        assert!(validate_endpoint_url("http://api.openai.com/v1/audio").is_err());
    }

    #[test]
    fn validate_endpoint_allows_https() {
        assert!(validate_endpoint_url("https://api.openai.com/v1/audio/speech").is_ok());
    }

    #[test]
    fn validate_endpoint_allows_http_localhost() {
        assert!(validate_endpoint_url("http://localhost:8080/v1/audio").is_ok());
        assert!(validate_endpoint_url("http://127.0.0.1:8080/v1/audio").is_ok());
    }

    #[test]
    fn validate_endpoint_rejects_ftp() {
        assert!(validate_endpoint_url("ftp://files.example.com/audio").is_err());
    }

    #[test]
    fn validate_endpoint_rejects_invalid_urls() {
        // Completely invalid URLs should be rejected.
        assert!(validate_endpoint_url("not-a-url").is_err());
        // File URIs are not allowed.
        assert!(validate_endpoint_url("file:///etc/passwd").is_err());
        // Data URIs are not allowed.
        assert!(validate_endpoint_url("data:text/plain,hello").is_err());
    }

    // -- Voice info tests --

    #[test]
    fn voice_info_serialization_roundtrip() {
        let voice = VoiceInfo {
            id: "alloy".to_string(),
            name: "Alloy".to_string(),
            provider: "openai".to_string(),
            language: Some("en-US".to_string()),
            gender: Some("neutral".to_string()),
            style: Some("warm".to_string()),
            preview_url: None,
        };
        let json = serde_json::to_string(&voice).unwrap();
        let back: VoiceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, voice);
    }

    // -- Security test: Cedar policy integration --

    /// MANDATORY SECURITY TEST: TtsSynthesize action is denied by default-deny
    /// Cedar policy. This verifies that TTS requests cannot bypass policy enforcement.
    #[test]
    fn tts_requires_cedar_policy() {
        use aegis_policy::engine::PolicyEngine;
        use aegis_types::{Action, ActionKind, Decision};

        // Default-deny policy: no explicit permit for TtsSynthesize.
        let engine = PolicyEngine::from_policies(
            r#"forbid(principal, action, resource);"#,
            None,
        )
        .expect("should create engine");

        let action = Action::new(
            "test-agent",
            ActionKind::TtsSynthesize {
                provider: "openai".to_string(),
                text_hash: text_hash("Hello, world!"),
                voice: "alloy".to_string(),
                format: "mp3".to_string(),
                text_length: 13,
            },
        );

        let verdict = engine.evaluate(&action);
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "TtsSynthesize MUST be denied by default-deny policy"
        );

        // Now verify it CAN be allowed with an explicit permit.
        let permissive_engine = PolicyEngine::from_policies(
            r#"permit(principal, action == Aegis::Action::"TtsSynthesize", resource);"#,
            None,
        )
        .expect("should create engine");

        let verdict = permissive_engine.evaluate(&action);
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "TtsSynthesize should be allowed with explicit permit"
        );
    }
}
