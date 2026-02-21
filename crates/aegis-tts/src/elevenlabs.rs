//! ElevenLabs TTS provider implementation.
//!
//! Sends POST requests to `/v1/text-to-speech/{voice_id}` with streaming
//! response and returns the raw audio bytes. The API key is resolved from
//! the `ELEVENLABS_API_KEY` environment variable.
//!
//! # Security
//!
//! - Voice IDs are validated to prevent path traversal (alphanumeric + hyphens only).
//! - API endpoint is SSRF-validated before use.
//! - Text is expected to be pre-sanitized via [`sanitize_text`](crate::sanitize_text).

use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;

use crate::{
    validate_endpoint_url, AudioFormat, TtsConfig, TtsError, TtsProvider, TtsResult, VoiceInfo,
};

/// Default ElevenLabs TTS API base URL.
const DEFAULT_ELEVENLABS_BASE_URL: &str = "https://api.elevenlabs.io";

/// Default ElevenLabs voice ID (Rachel -- a general-purpose voice).
const DEFAULT_VOICE_ID: &str = "21m00Tcm4TlvDq8ikWAM";

/// Default ElevenLabs model ID.
const DEFAULT_MODEL_ID: &str = "eleven_monolingual_v1";

/// Environment variable name for the ElevenLabs API key.
pub const ELEVENLABS_API_KEY_ENV: &str = "ELEVENLABS_API_KEY";

/// Regex-like validation: voice ID must be alphanumeric plus hyphens only.
/// This prevents path traversal attacks (e.g., `../../etc/passwd`).
fn validate_voice_id(voice_id: &str) -> TtsResult<()> {
    if voice_id.is_empty() {
        return Err(TtsError::ConfigError(
            "voice ID must not be empty".to_string(),
        ));
    }
    if voice_id.len() > 128 {
        return Err(TtsError::ConfigError(
            "voice ID exceeds maximum length of 128 characters".to_string(),
        ));
    }
    if !voice_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(TtsError::ConfigError(format!(
            "voice ID contains invalid characters (only alphanumeric and hyphens allowed): {voice_id}"
        )));
    }
    Ok(())
}

/// ElevenLabs TTS provider.
///
/// Sends POST requests to the ElevenLabs `/v1/text-to-speech/{voice_id}`
/// endpoint. The API key is resolved from the configured environment variable.
pub struct ElevenLabsProvider {
    client: Client,
    api_key: String,
    base_url: String,
    model_id: String,
    default_voice: String,
}

/// Request body for the ElevenLabs TTS API.
#[derive(Debug, Serialize)]
struct ElevenLabsRequest<'a> {
    text: &'a str,
    model_id: &'a str,
    voice_settings: VoiceSettings,
}

/// Voice tuning parameters for ElevenLabs.
#[derive(Debug, Serialize)]
struct VoiceSettings {
    stability: f32,
    similarity_boost: f32,
}

impl Default for VoiceSettings {
    fn default() -> Self {
        Self {
            stability: 0.5,
            similarity_boost: 0.75,
        }
    }
}

impl ElevenLabsProvider {
    /// Create a new ElevenLabs TTS provider from a [`TtsConfig`].
    ///
    /// Resolves the API key from the environment immediately. Returns an error
    /// if the key is missing or the endpoint URL is invalid.
    pub fn from_config(config: &TtsConfig) -> TtsResult<Self> {
        let api_key = config.resolve_api_key()?;

        let base_url = match &config.endpoint_url {
            Some(url) => {
                let validated = validate_endpoint_url(url)?;
                validated.to_string().trim_end_matches('/').to_string()
            }
            None => DEFAULT_ELEVENLABS_BASE_URL.to_string(),
        };

        let default_voice = if config.default_voice.is_empty() {
            DEFAULT_VOICE_ID.to_string()
        } else {
            validate_voice_id(&config.default_voice)?;
            config.default_voice.clone()
        };

        Ok(Self {
            client: Client::new(),
            api_key,
            base_url,
            model_id: DEFAULT_MODEL_ID.to_string(),
            default_voice,
        })
    }

    /// Create from explicit parameters (useful for testing).
    ///
    /// The `api_key` is passed directly -- callers are responsible for
    /// sourcing it from an environment variable.
    pub fn new(
        api_key: String,
        endpoint: Option<String>,
        default_voice: Option<String>,
    ) -> TtsResult<Self> {
        let base_url = match endpoint {
            Some(url) => {
                let validated = validate_endpoint_url(&url)?;
                validated.to_string().trim_end_matches('/').to_string()
            }
            None => DEFAULT_ELEVENLABS_BASE_URL.to_string(),
        };

        let default_voice = match default_voice {
            Some(v) => {
                validate_voice_id(&v)?;
                v
            }
            None => DEFAULT_VOICE_ID.to_string(),
        };

        Ok(Self {
            client: Client::new(),
            api_key,
            base_url,
            model_id: DEFAULT_MODEL_ID.to_string(),
            default_voice,
        })
    }

    /// Build the full API URL for a given voice ID.
    ///
    /// The voice ID is validated before being interpolated into the URL path
    /// to prevent path traversal.
    fn build_url(&self, voice_id: &str) -> TtsResult<String> {
        validate_voice_id(voice_id)?;
        Ok(format!(
            "{}/v1/text-to-speech/{}",
            self.base_url, voice_id
        ))
    }

    /// Build the request body for the ElevenLabs TTS API.
    fn build_request_body<'a>(&'a self, text: &'a str) -> ElevenLabsRequest<'a> {
        ElevenLabsRequest {
            text,
            model_id: &self.model_id,
            voice_settings: VoiceSettings::default(),
        }
    }

    /// Map an [`AudioFormat`] to the ElevenLabs `output_format` query parameter.
    ///
    /// ElevenLabs uses specific format identifiers that differ from OpenAI.
    fn elevenlabs_output_format(format: AudioFormat) -> &'static str {
        match format {
            AudioFormat::Mp3 => "mp3_44100_128",
            AudioFormat::Wav => "pcm_44100",
            AudioFormat::Ogg => "mp3_44100_128", // ElevenLabs doesn't natively support OGG; fall back to MP3
        }
    }
}

#[async_trait]
impl TtsProvider for ElevenLabsProvider {
    async fn synthesize(
        &self,
        text: &str,
        voice: Option<&str>,
        format: AudioFormat,
    ) -> TtsResult<Vec<u8>> {
        let voice_id = voice.unwrap_or(&self.default_voice);
        let url = self.build_url(voice_id)?;
        let body = self.build_request_body(text);
        let output_format = Self::elevenlabs_output_format(format);

        tracing::debug!(
            endpoint = %url,
            voice = voice_id,
            format = %format,
            output_format = output_format,
            text_len = text.len(),
            "sending TTS request to ElevenLabs"
        );

        let response = self
            .client
            .post(&url)
            .query(&[("output_format", output_format)])
            .header("xi-api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read error body".to_string());
            return Err(TtsError::ProviderError(format!(
                "ElevenLabs API returned {status}: {error_body}"
            )));
        }

        let audio_bytes = response.bytes().await?.to_vec();

        tracing::debug!(
            bytes = audio_bytes.len(),
            "received TTS audio response from ElevenLabs"
        );

        Ok(audio_bytes)
    }

    fn list_voices(&self) -> Vec<VoiceInfo> {
        // ElevenLabs has a dynamic voice library, but we list the well-known
        // pre-made voices for offline/static usage. Real voice discovery would
        // require an API call to GET /v1/voices.
        vec![
            VoiceInfo {
                id: "21m00Tcm4TlvDq8ikWAM".to_string(),
                name: "Rachel".to_string(),
                provider: "elevenlabs".to_string(),
                language: Some("en".to_string()),
                gender: Some("female".to_string()),
                style: Some("calm and conversational".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "29vD33N1CtxCmqQRPOHJ".to_string(),
                name: "Drew".to_string(),
                provider: "elevenlabs".to_string(),
                language: Some("en".to_string()),
                gender: Some("male".to_string()),
                style: Some("well-rounded and informative".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "EXAVITQu4vr4xnSDxMaL".to_string(),
                name: "Bella".to_string(),
                provider: "elevenlabs".to_string(),
                language: Some("en".to_string()),
                gender: Some("female".to_string()),
                style: Some("soft and pleasant".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "ErXwobaYiN019PkySvjV".to_string(),
                name: "Antoni".to_string(),
                provider: "elevenlabs".to_string(),
                language: Some("en".to_string()),
                gender: Some("male".to_string()),
                style: Some("well-rounded and expressive".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "MF3mGyEYCl7XYWbV9V6O".to_string(),
                name: "Elli".to_string(),
                provider: "elevenlabs".to_string(),
                language: Some("en".to_string()),
                gender: Some("female".to_string()),
                style: Some("emotional and expressive".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "TxGEqnHWrfWFTfGW9XjX".to_string(),
                name: "Josh".to_string(),
                provider: "elevenlabs".to_string(),
                language: Some("en".to_string()),
                gender: Some("male".to_string()),
                style: Some("deep and narrative".to_string()),
                preview_url: None,
            },
        ]
    }

    fn name(&self) -> &str {
        "elevenlabs"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn elevenlabs_voice_listing() {
        let provider = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .unwrap();

        let voices = provider.list_voices();
        assert_eq!(voices.len(), 6);

        // All voices should report elevenlabs as provider.
        for voice in &voices {
            assert_eq!(voice.provider, "elevenlabs");
        }

        // Check that known voices are present.
        let voice_names: Vec<&str> = voices.iter().map(|v| v.name.as_str()).collect();
        assert!(voice_names.contains(&"Rachel"));
        assert!(voice_names.contains(&"Drew"));
        assert!(voice_names.contains(&"Josh"));
    }

    #[test]
    fn provider_name() {
        let provider = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(provider.name(), "elevenlabs");
    }

    #[test]
    fn elevenlabs_provider_synthesize_request() {
        let provider = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("http://localhost:9999".to_string()),
            Some("21m00Tcm4TlvDq8ikWAM".to_string()),
        )
        .unwrap();

        let body = provider.build_request_body("Hello, world!");

        assert_eq!(body.text, "Hello, world!");
        assert_eq!(body.model_id, "eleven_monolingual_v1");

        // Verify it serializes to proper JSON.
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["text"], "Hello, world!");
        assert_eq!(json["model_id"], "eleven_monolingual_v1");
        assert!(json["voice_settings"]["stability"].is_number());
        assert!(json["voice_settings"]["similarity_boost"].is_number());
    }

    #[test]
    fn build_url_validates_voice_id() {
        let provider = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .unwrap();

        // Valid voice ID.
        let url = provider.build_url("21m00Tcm4TlvDq8ikWAM");
        assert!(url.is_ok());
        assert!(url.unwrap().ends_with("/v1/text-to-speech/21m00Tcm4TlvDq8ikWAM"));

        // Path traversal attempt must be rejected.
        let result = provider.build_url("../../etc/passwd");
        assert!(matches!(result, Err(TtsError::ConfigError(_))));

        // Empty voice ID must be rejected.
        let result = provider.build_url("");
        assert!(matches!(result, Err(TtsError::ConfigError(_))));
    }

    #[test]
    fn voice_id_validation_rejects_path_traversal() {
        assert!(validate_voice_id("valid-voice-id-123").is_ok());
        assert!(validate_voice_id("21m00Tcm4TlvDq8ikWAM").is_ok());

        // Path traversal characters.
        assert!(validate_voice_id("../etc/passwd").is_err());
        assert!(validate_voice_id("voice/../../secret").is_err());
        assert!(validate_voice_id("voice%00id").is_err());

        // Spaces, special characters.
        assert!(validate_voice_id("voice id").is_err());
        assert!(validate_voice_id("voice;rm -rf /").is_err());

        // Empty.
        assert!(validate_voice_id("").is_err());

        // Too long.
        let long_id = "a".repeat(129);
        assert!(validate_voice_id(&long_id).is_err());
    }

    #[test]
    fn from_config_requires_api_key() {
        std::env::remove_var("AEGIS_ELEVENLABS_TEST_MISSING_KEY");
        let config = TtsConfig {
            api_key_env: "AEGIS_ELEVENLABS_TEST_MISSING_KEY".to_string(),
            ..TtsConfig::default()
        };
        let result = ElevenLabsProvider::from_config(&config);
        assert!(matches!(result, Err(TtsError::MissingApiKey(_))));
    }

    #[test]
    fn from_config_validates_endpoint() {
        std::env::set_var("AEGIS_ELEVENLABS_ENDPOINT_TEST_KEY", "xi-test-key");
        let config = TtsConfig {
            api_key_env: "AEGIS_ELEVENLABS_ENDPOINT_TEST_KEY".to_string(),
            endpoint_url: Some("http://10.0.0.1/v1".to_string()),
            ..TtsConfig::default()
        };
        let result = ElevenLabsProvider::from_config(&config);
        assert!(matches!(result, Err(TtsError::InvalidEndpoint(_))));
        std::env::remove_var("AEGIS_ELEVENLABS_ENDPOINT_TEST_KEY");
    }

    /// MANDATORY SECURITY TEST: ElevenLabs provider must reject endpoints
    /// pointing to private IP ranges (SSRF protection).
    #[test]
    fn elevenlabs_ssrf_protection() {
        // Private RFC1918 ranges must be blocked.
        let result = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("https://10.0.0.1/v1".to_string()),
            None,
        );
        assert!(
            matches!(result, Err(TtsError::InvalidEndpoint(_))),
            "must reject private IP endpoints to prevent SSRF"
        );

        let result = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("https://192.168.1.1/v1".to_string()),
            None,
        );
        assert!(
            matches!(result, Err(TtsError::InvalidEndpoint(_))),
            "must reject 192.168.x.x endpoints"
        );

        let result = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("https://172.16.0.1/v1".to_string()),
            None,
        );
        assert!(
            matches!(result, Err(TtsError::InvalidEndpoint(_))),
            "must reject 172.16.x.x endpoints"
        );

        // Non-HTTPS must be blocked for non-localhost.
        let result = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("http://api.elevenlabs.io/v1".to_string()),
            None,
        );
        assert!(
            matches!(result, Err(TtsError::InvalidEndpoint(_))),
            "must reject non-HTTPS for non-localhost"
        );

        // File URI must be blocked.
        let result = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("file:///etc/passwd".to_string()),
            None,
        );
        assert!(
            matches!(result, Err(TtsError::InvalidEndpoint(_))),
            "must reject file:// URIs"
        );

        // Path traversal in voice ID must be blocked when building URL.
        let provider = ElevenLabsProvider::new(
            "xi-test-key".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .unwrap();
        let result = provider.build_url("../../etc/passwd");
        assert!(
            matches!(result, Err(TtsError::ConfigError(_))),
            "must reject path traversal in voice ID"
        );
    }

    #[test]
    fn output_format_mapping() {
        assert_eq!(
            ElevenLabsProvider::elevenlabs_output_format(AudioFormat::Mp3),
            "mp3_44100_128"
        );
        assert_eq!(
            ElevenLabsProvider::elevenlabs_output_format(AudioFormat::Wav),
            "pcm_44100"
        );
        // OGG falls back to MP3 since ElevenLabs doesn't support it natively.
        assert_eq!(
            ElevenLabsProvider::elevenlabs_output_format(AudioFormat::Ogg),
            "mp3_44100_128"
        );
    }

    #[tokio::test]
    async fn synthesize_sends_correct_request() {
        let mock_server = MockServer::start().await;

        let audio_bytes = vec![0xFF, 0xFB, 0x90, 0x00]; // Fake MP3 header bytes

        Mock::given(method("POST"))
            .and(path("/v1/text-to-speech/21m00Tcm4TlvDq8ikWAM"))
            .and(header("xi-api-key", "xi-mock-key"))
            .and(header("Content-Type", "application/json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(audio_bytes.clone())
                    .insert_header("content-type", "audio/mpeg"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = ElevenLabsProvider::new(
            "xi-mock-key".to_string(),
            Some(mock_server.uri()),
            None,
        )
        .unwrap();

        let result = provider
            .synthesize("Hello, world!", None, AudioFormat::Mp3)
            .await
            .unwrap();

        assert_eq!(result, audio_bytes);
    }

    #[tokio::test]
    async fn synthesize_handles_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/text-to-speech/21m00Tcm4TlvDq8ikWAM"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_string(r#"{"detail":{"status":"invalid_api_key"}}"#),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = ElevenLabsProvider::new(
            "xi-bad-key".to_string(),
            Some(mock_server.uri()),
            None,
        )
        .unwrap();

        let result = provider
            .synthesize("Hello", None, AudioFormat::Mp3)
            .await;

        assert!(matches!(result, Err(TtsError::ProviderError(_))));
        if let Err(TtsError::ProviderError(msg)) = result {
            assert!(msg.contains("401"));
        }
    }

    #[tokio::test]
    async fn synthesize_uses_specified_voice() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/text-to-speech/TxGEqnHWrfWFTfGW9XjX"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![0x00]),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = ElevenLabsProvider::new(
            "xi-mock-key".to_string(),
            Some(mock_server.uri()),
            None,
        )
        .unwrap();

        let result = provider
            .synthesize("Test", Some("TxGEqnHWrfWFTfGW9XjX"), AudioFormat::Mp3)
            .await;

        assert!(result.is_ok());
    }
}
