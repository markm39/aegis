//! Edge TTS provider implementation.
//!
//! Uses Microsoft's free Edge TTS service for text-to-speech synthesis.
//! No API key is required. The provider constructs SSML payloads and sends
//! them to the Edge speech synthesis endpoint.
//!
//! # Security
//!
//! - Voice IDs are validated to prevent injection (alphanumeric, hyphens, and
//!   dots only, matching BCP-47 style voice names like "en-US-AriaNeural").
//! - Text is expected to be pre-sanitized via [`sanitize_text`](crate::sanitize_text).
//! - SSML content is XML-escaped to prevent injection attacks.

use async_trait::async_trait;
use reqwest::Client;

use crate::{AudioFormat, TtsError, TtsProvider, TtsResult, VoiceInfo};

/// Default Edge TTS API endpoint for speech synthesis.
const EDGE_TTS_ENDPOINT: &str =
    "https://speech.platform.bing.com/consumer/speech/synthesize/readaloud";

/// Default Edge TTS voice.
const DEFAULT_EDGE_VOICE: &str = "en-US-AriaNeural";

/// Maximum allowed length for an Edge TTS voice name.
const MAX_VOICE_NAME_LEN: usize = 128;

/// Edge TTS provider.
///
/// Sends POST requests with SSML payloads to Microsoft's free Edge TTS
/// endpoint. No API key is required -- this service is available without
/// authentication.
pub struct EdgeTtsProvider {
    client: Client,
    voice: String,
}

impl Default for EdgeTtsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl EdgeTtsProvider {
    /// Create a new Edge TTS provider with the default voice ("en-US-AriaNeural").
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            voice: DEFAULT_EDGE_VOICE.to_string(),
        }
    }

    /// Create a new Edge TTS provider with a specific voice.
    ///
    /// The voice name is validated before use. Valid voices follow the pattern
    /// `en-US-AriaNeural` (BCP-47 locale + neural voice name).
    pub fn with_voice(voice: &str) -> TtsResult<Self> {
        validate_edge_voice(voice)?;
        Ok(Self {
            client: Client::new(),
            voice: voice.to_string(),
        })
    }

    /// Return the currently configured voice name.
    pub fn voice(&self) -> &str {
        &self.voice
    }

    /// Build an SSML payload for the given text and voice.
    ///
    /// The text is XML-escaped to prevent SSML injection.
    pub fn build_ssml(text: &str, voice: &str) -> String {
        let escaped_text = xml_escape(text);
        format!(
            r#"<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xml:lang="en-US"><voice name="{voice}">{escaped_text}</voice></speak>"#
        )
    }

    /// Map an [`AudioFormat`] to the Edge TTS output format header value.
    fn edge_output_format(format: AudioFormat) -> &'static str {
        match format {
            AudioFormat::Mp3 => "audio-24khz-48kbitrate-mono-mp3",
            AudioFormat::Wav => "riff-24khz-16bit-mono-pcm",
            AudioFormat::Ogg => "ogg-24khz-16bit-mono-opus",
        }
    }
}

#[async_trait]
impl TtsProvider for EdgeTtsProvider {
    async fn synthesize(
        &self,
        text: &str,
        voice: Option<&str>,
        format: AudioFormat,
    ) -> TtsResult<Vec<u8>> {
        let voice = voice.unwrap_or(&self.voice);
        validate_edge_voice(voice)?;

        let ssml = Self::build_ssml(text, voice);
        let output_format = Self::edge_output_format(format);

        tracing::debug!(
            voice = voice,
            format = %format,
            output_format = output_format,
            text_len = text.len(),
            "sending TTS request to Edge TTS"
        );

        let response = self
            .client
            .post(EDGE_TTS_ENDPOINT)
            .header("Content-Type", "application/ssml+xml")
            .header("X-Microsoft-OutputFormat", output_format)
            .header("User-Agent", "Aegis-TTS/0.1")
            .body(ssml)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read error body".to_string());
            return Err(TtsError::ProviderError(format!(
                "Edge TTS returned {status}: {error_body}"
            )));
        }

        let audio_bytes = response.bytes().await?.to_vec();

        tracing::debug!(
            bytes = audio_bytes.len(),
            "received TTS audio response from Edge TTS"
        );

        Ok(audio_bytes)
    }

    fn list_voices(&self) -> Vec<VoiceInfo> {
        vec![
            VoiceInfo {
                id: "en-US-AriaNeural".to_string(),
                name: "Aria".to_string(),
                provider: "edge".to_string(),
                language: Some("en-US".to_string()),
                gender: Some("female".to_string()),
                style: Some("friendly and conversational".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "en-US-GuyNeural".to_string(),
                name: "Guy".to_string(),
                provider: "edge".to_string(),
                language: Some("en-US".to_string()),
                gender: Some("male".to_string()),
                style: Some("clear and professional".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "en-US-JennyNeural".to_string(),
                name: "Jenny".to_string(),
                provider: "edge".to_string(),
                language: Some("en-US".to_string()),
                gender: Some("female".to_string()),
                style: Some("warm and natural".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "en-GB-SoniaNeural".to_string(),
                name: "Sonia".to_string(),
                provider: "edge".to_string(),
                language: Some("en-GB".to_string()),
                gender: Some("female".to_string()),
                style: Some("clear British accent".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "en-GB-RyanNeural".to_string(),
                name: "Ryan".to_string(),
                provider: "edge".to_string(),
                language: Some("en-GB".to_string()),
                gender: Some("male".to_string()),
                style: Some("professional British accent".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "en-AU-NatashaNeural".to_string(),
                name: "Natasha".to_string(),
                provider: "edge".to_string(),
                language: Some("en-AU".to_string()),
                gender: Some("female".to_string()),
                style: Some("warm Australian accent".to_string()),
                preview_url: None,
            },
        ]
    }

    fn name(&self) -> &str {
        "edge"
    }
}

/// Validate an Edge TTS voice name.
///
/// Voice names follow the BCP-47 pattern (e.g., "en-US-AriaNeural") and may
/// contain only ASCII alphanumeric characters, hyphens, and dots.
fn validate_edge_voice(voice: &str) -> TtsResult<()> {
    if voice.is_empty() {
        return Err(TtsError::ConfigError(
            "Edge TTS voice name must not be empty".to_string(),
        ));
    }
    if voice.len() > MAX_VOICE_NAME_LEN {
        return Err(TtsError::ConfigError(format!(
            "Edge TTS voice name exceeds maximum length of {MAX_VOICE_NAME_LEN} characters"
        )));
    }
    if !voice
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(TtsError::ConfigError(format!(
            "Edge TTS voice name contains invalid characters (only alphanumeric, hyphens, and dots allowed): {voice}"
        )));
    }
    Ok(())
}

/// Escape special XML characters in text to prevent SSML injection.
fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn edge_provider_default_voice() {
        let provider = EdgeTtsProvider::new();
        assert_eq!(provider.voice(), "en-US-AriaNeural");
        assert_eq!(provider.name(), "edge");
    }

    #[test]
    fn edge_provider_custom_voice() {
        let provider = EdgeTtsProvider::with_voice("en-GB-SoniaNeural").unwrap();
        assert_eq!(provider.voice(), "en-GB-SoniaNeural");
    }

    #[test]
    fn edge_provider_rejects_invalid_voice() {
        // Empty voice.
        assert!(EdgeTtsProvider::with_voice("").is_err());

        // Special characters that could cause injection.
        assert!(EdgeTtsProvider::with_voice("<script>alert(1)</script>").is_err());
        assert!(EdgeTtsProvider::with_voice("voice;rm -rf /").is_err());
        assert!(EdgeTtsProvider::with_voice("../etc/passwd").is_err());
        assert!(EdgeTtsProvider::with_voice("voice name").is_err());

        // Too long.
        let long_name = "a".repeat(129);
        assert!(EdgeTtsProvider::with_voice(&long_name).is_err());
    }

    #[test]
    fn edge_voice_validation() {
        // Valid voices.
        assert!(validate_edge_voice("en-US-AriaNeural").is_ok());
        assert!(validate_edge_voice("en-GB-SoniaNeural").is_ok());
        assert!(validate_edge_voice("zh-CN-XiaoxiaoNeural").is_ok());

        // Invalid voices.
        assert!(validate_edge_voice("").is_err());
        assert!(validate_edge_voice("bad voice").is_err());
        assert!(validate_edge_voice("bad/voice").is_err());
        assert!(validate_edge_voice("bad&voice").is_err());
    }

    #[test]
    fn edge_ssml_construction() {
        let ssml = EdgeTtsProvider::build_ssml("Hello, world!", "en-US-AriaNeural");
        assert!(ssml.contains("en-US-AriaNeural"));
        assert!(ssml.contains("Hello, world!"));
        assert!(ssml.starts_with("<speak"));
        assert!(ssml.ends_with("</speak>"));
    }

    #[test]
    fn edge_ssml_escapes_xml() {
        let ssml = EdgeTtsProvider::build_ssml("Hello <world> & \"friends\"", "en-US-AriaNeural");
        assert!(ssml.contains("Hello &lt;world&gt; &amp; &quot;friends&quot;"));
        assert!(!ssml.contains("<world>"));
    }

    #[test]
    fn xml_escape_all_special_chars() {
        assert_eq!(xml_escape("&"), "&amp;");
        assert_eq!(xml_escape("<"), "&lt;");
        assert_eq!(xml_escape(">"), "&gt;");
        assert_eq!(xml_escape("\""), "&quot;");
        assert_eq!(xml_escape("'"), "&apos;");
        assert_eq!(xml_escape("normal text"), "normal text");
        assert_eq!(
            xml_escape("a<b>c&d\"e'f"),
            "a&lt;b&gt;c&amp;d&quot;e&apos;f"
        );
    }

    #[test]
    fn edge_voice_listing() {
        let provider = EdgeTtsProvider::new();
        let voices = provider.list_voices();
        assert_eq!(voices.len(), 6);

        for voice in &voices {
            assert_eq!(voice.provider, "edge");
        }

        let voice_ids: Vec<&str> = voices.iter().map(|v| v.id.as_str()).collect();
        assert!(voice_ids.contains(&"en-US-AriaNeural"));
        assert!(voice_ids.contains(&"en-US-GuyNeural"));
        assert!(voice_ids.contains(&"en-US-JennyNeural"));
        assert!(voice_ids.contains(&"en-GB-SoniaNeural"));
        assert!(voice_ids.contains(&"en-GB-RyanNeural"));
        assert!(voice_ids.contains(&"en-AU-NatashaNeural"));
    }

    #[test]
    fn edge_output_format_mapping() {
        assert_eq!(
            EdgeTtsProvider::edge_output_format(AudioFormat::Mp3),
            "audio-24khz-48kbitrate-mono-mp3"
        );
        assert_eq!(
            EdgeTtsProvider::edge_output_format(AudioFormat::Wav),
            "riff-24khz-16bit-mono-pcm"
        );
        assert_eq!(
            EdgeTtsProvider::edge_output_format(AudioFormat::Ogg),
            "ogg-24khz-16bit-mono-opus"
        );
    }

    #[tokio::test]
    async fn edge_synthesize_sends_correct_request() {
        let mock_server = MockServer::start().await;

        let audio_bytes = vec![0xFF, 0xFB, 0x90, 0x00]; // Fake MP3 header

        Mock::given(method("POST"))
            .and(header("Content-Type", "application/ssml+xml"))
            .and(header(
                "X-Microsoft-OutputFormat",
                "audio-24khz-48kbitrate-mono-mp3",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(audio_bytes.clone())
                    .insert_header("content-type", "audio/mpeg"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        // We need to create a provider that points to the mock server.
        // Since the endpoint is hardcoded, we construct manually for this test.
        let provider = EdgeTtsProviderTestable {
            client: Client::new(),
            voice: DEFAULT_EDGE_VOICE.to_string(),
            endpoint: mock_server.uri(),
        };

        let result = provider
            .synthesize("Hello, world!", None, AudioFormat::Mp3)
            .await
            .unwrap();

        assert_eq!(result, audio_bytes);
    }

    #[tokio::test]
    async fn edge_synthesize_handles_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = EdgeTtsProviderTestable {
            client: Client::new(),
            voice: DEFAULT_EDGE_VOICE.to_string(),
            endpoint: mock_server.uri(),
        };

        let result = provider.synthesize("Hello", None, AudioFormat::Mp3).await;

        assert!(matches!(result, Err(TtsError::ProviderError(_))));
        if let Err(TtsError::ProviderError(msg)) = result {
            assert!(msg.contains("429"));
        }
    }

    /// A testable version of EdgeTtsProvider with configurable endpoint.
    struct EdgeTtsProviderTestable {
        client: Client,
        voice: String,
        endpoint: String,
    }

    #[async_trait]
    impl TtsProvider for EdgeTtsProviderTestable {
        async fn synthesize(
            &self,
            text: &str,
            voice: Option<&str>,
            format: AudioFormat,
        ) -> TtsResult<Vec<u8>> {
            let voice = voice.unwrap_or(&self.voice);
            validate_edge_voice(voice)?;

            let ssml = EdgeTtsProvider::build_ssml(text, voice);
            let output_format = EdgeTtsProvider::edge_output_format(format);

            let response = self
                .client
                .post(&self.endpoint)
                .header("Content-Type", "application/ssml+xml")
                .header("X-Microsoft-OutputFormat", output_format)
                .header("User-Agent", "Aegis-TTS/0.1")
                .body(ssml)
                .send()
                .await?;

            let status = response.status();
            if !status.is_success() {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "failed to read error body".to_string());
                return Err(TtsError::ProviderError(format!(
                    "Edge TTS returned {status}: {error_body}"
                )));
            }

            Ok(response.bytes().await?.to_vec())
        }

        fn list_voices(&self) -> Vec<VoiceInfo> {
            EdgeTtsProvider::new().list_voices()
        }

        fn name(&self) -> &str {
            "edge"
        }
    }
}
