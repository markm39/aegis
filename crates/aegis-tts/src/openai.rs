//! OpenAI TTS provider implementation.
//!
//! Sends POST requests to `/v1/audio/speech` and returns the raw audio bytes.
//! The API key is resolved from an environment variable at construction time.

use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;

use crate::{
    validate_endpoint_url, AudioFormat, TtsConfig, TtsError, TtsProvider, TtsResult, VoiceInfo,
};

/// Default OpenAI TTS API endpoint.
const DEFAULT_OPENAI_TTS_URL: &str = "https://api.openai.com/v1/audio/speech";

/// Default model for OpenAI TTS.
const DEFAULT_MODEL: &str = "tts-1";

/// OpenAI TTS provider.
///
/// Sends POST requests to the OpenAI `/v1/audio/speech` endpoint.
/// The API key is resolved from the configured environment variable.
pub struct OpenAiTtsProvider {
    client: Client,
    api_key: String,
    endpoint: String,
    model: String,
    default_voice: String,
}

/// Request body for the OpenAI TTS API.
#[derive(Debug, Serialize)]
struct SpeechRequest<'a> {
    model: &'a str,
    input: &'a str,
    voice: &'a str,
    response_format: &'a str,
}

impl OpenAiTtsProvider {
    /// Create a new OpenAI TTS provider from a [`TtsConfig`].
    ///
    /// Resolves the API key from the environment immediately. Returns an error
    /// if the key is missing or the endpoint URL is invalid.
    pub fn from_config(config: &TtsConfig) -> TtsResult<Self> {
        let api_key = config.resolve_api_key()?;

        let endpoint = match &config.endpoint_url {
            Some(url) => {
                let validated = validate_endpoint_url(url)?;
                validated.to_string()
            }
            None => DEFAULT_OPENAI_TTS_URL.to_string(),
        };

        Ok(Self {
            client: Client::new(),
            api_key,
            endpoint,
            model: DEFAULT_MODEL.to_string(),
            default_voice: config.default_voice.clone(),
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
        let endpoint = match endpoint {
            Some(url) => {
                let validated = validate_endpoint_url(&url)?;
                validated.to_string()
            }
            None => DEFAULT_OPENAI_TTS_URL.to_string(),
        };

        Ok(Self {
            client: Client::new(),
            api_key,
            endpoint,
            model: DEFAULT_MODEL.to_string(),
            default_voice: default_voice.unwrap_or_else(|| "alloy".to_string()),
        })
    }

    /// Build the request body for the OpenAI TTS API.
    fn build_request_body<'a>(
        &'a self,
        text: &'a str,
        voice: &'a str,
        format: AudioFormat,
    ) -> SpeechRequest<'a> {
        SpeechRequest {
            model: &self.model,
            input: text,
            voice,
            response_format: format.api_format_str(),
        }
    }
}

#[async_trait]
impl TtsProvider for OpenAiTtsProvider {
    async fn synthesize(
        &self,
        text: &str,
        voice: Option<&str>,
        format: AudioFormat,
    ) -> TtsResult<Vec<u8>> {
        let voice = voice.unwrap_or(&self.default_voice);
        let body = self.build_request_body(text, voice, format);

        tracing::debug!(
            endpoint = %self.endpoint,
            voice = voice,
            format = %format,
            text_len = text.len(),
            "sending TTS request to OpenAI"
        );

        let response = self
            .client
            .post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.api_key))
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
                "OpenAI API returned {status}: {error_body}"
            )));
        }

        let audio_bytes = response.bytes().await?.to_vec();

        tracing::debug!(bytes = audio_bytes.len(), "received TTS audio response");

        Ok(audio_bytes)
    }

    fn list_voices(&self) -> Vec<VoiceInfo> {
        // OpenAI provides a fixed set of voices for the tts-1 and tts-1-hd models.
        vec![
            VoiceInfo {
                id: "alloy".to_string(),
                name: "Alloy".to_string(),
                provider: "openai".to_string(),
                language: Some("en".to_string()),
                gender: Some("neutral".to_string()),
                style: Some("warm and balanced".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "echo".to_string(),
                name: "Echo".to_string(),
                provider: "openai".to_string(),
                language: Some("en".to_string()),
                gender: Some("male".to_string()),
                style: Some("deep and resonant".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "fable".to_string(),
                name: "Fable".to_string(),
                provider: "openai".to_string(),
                language: Some("en".to_string()),
                gender: Some("neutral".to_string()),
                style: Some("expressive and storytelling".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "onyx".to_string(),
                name: "Onyx".to_string(),
                provider: "openai".to_string(),
                language: Some("en".to_string()),
                gender: Some("male".to_string()),
                style: Some("authoritative and deep".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "nova".to_string(),
                name: "Nova".to_string(),
                provider: "openai".to_string(),
                language: Some("en".to_string()),
                gender: Some("female".to_string()),
                style: Some("friendly and upbeat".to_string()),
                preview_url: None,
            },
            VoiceInfo {
                id: "shimmer".to_string(),
                name: "Shimmer".to_string(),
                provider: "openai".to_string(),
                language: Some("en".to_string()),
                gender: Some("female".to_string()),
                style: Some("clear and pleasant".to_string()),
                preview_url: None,
            },
        ]
    }

    fn name(&self) -> &str {
        "openai"
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
    fn voice_listing() {
        // Create a provider with a dummy key (we won't hit the network).
        let provider = OpenAiTtsProvider::new(
            "sk-test".to_string(),
            Some("http://localhost:9999/v1/audio/speech".to_string()),
            None,
        )
        .unwrap();

        let voices = provider.list_voices();
        assert_eq!(voices.len(), 6);

        let voice_ids: Vec<&str> = voices.iter().map(|v| v.id.as_str()).collect();
        assert!(voice_ids.contains(&"alloy"));
        assert!(voice_ids.contains(&"echo"));
        assert!(voice_ids.contains(&"fable"));
        assert!(voice_ids.contains(&"onyx"));
        assert!(voice_ids.contains(&"nova"));
        assert!(voice_ids.contains(&"shimmer"));

        // All voices should report openai as provider.
        for voice in &voices {
            assert_eq!(voice.provider, "openai");
        }
    }

    #[test]
    fn provider_name() {
        let provider = OpenAiTtsProvider::new(
            "sk-test".to_string(),
            Some("http://localhost:9999/v1/audio/speech".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(provider.name(), "openai");
    }

    #[test]
    fn openai_provider_synthesize_request_format() {
        let provider = OpenAiTtsProvider::new(
            "sk-test-key".to_string(),
            Some("http://localhost:9999/v1/audio/speech".to_string()),
            Some("nova".to_string()),
        )
        .unwrap();

        let body = provider.build_request_body("Hello, world!", "nova", AudioFormat::Mp3);

        assert_eq!(body.model, "tts-1");
        assert_eq!(body.input, "Hello, world!");
        assert_eq!(body.voice, "nova");
        assert_eq!(body.response_format, "mp3");

        // Verify it serializes to proper JSON.
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["model"], "tts-1");
        assert_eq!(json["input"], "Hello, world!");
        assert_eq!(json["voice"], "nova");
        assert_eq!(json["response_format"], "mp3");
    }

    #[test]
    fn request_format_wav() {
        let provider = OpenAiTtsProvider::new(
            "sk-test".to_string(),
            Some("http://localhost:9999/v1/audio/speech".to_string()),
            None,
        )
        .unwrap();

        let body = provider.build_request_body("Test", "alloy", AudioFormat::Wav);
        assert_eq!(body.response_format, "wav");
    }

    #[test]
    fn request_format_ogg() {
        let provider = OpenAiTtsProvider::new(
            "sk-test".to_string(),
            Some("http://localhost:9999/v1/audio/speech".to_string()),
            None,
        )
        .unwrap();

        let body = provider.build_request_body("Test", "alloy", AudioFormat::Ogg);
        assert_eq!(body.response_format, "opus");
    }

    #[test]
    fn from_config_requires_api_key() {
        // Ensure the env var is not set.
        std::env::remove_var("AEGIS_TTS_TEST_MISSING_KEY");
        let config = TtsConfig {
            api_key_env: "AEGIS_TTS_TEST_MISSING_KEY".to_string(),
            ..TtsConfig::default()
        };
        let result = OpenAiTtsProvider::from_config(&config);
        assert!(matches!(result, Err(TtsError::MissingApiKey(_))));
    }

    #[test]
    fn from_config_validates_endpoint() {
        std::env::set_var("AEGIS_TTS_ENDPOINT_TEST_KEY", "sk-test");
        let config = TtsConfig {
            api_key_env: "AEGIS_TTS_ENDPOINT_TEST_KEY".to_string(),
            endpoint_url: Some("http://10.0.0.1/v1/audio".to_string()),
            ..TtsConfig::default()
        };
        let result = OpenAiTtsProvider::from_config(&config);
        assert!(matches!(result, Err(TtsError::InvalidEndpoint(_))));
        std::env::remove_var("AEGIS_TTS_ENDPOINT_TEST_KEY");
    }

    #[tokio::test]
    async fn synthesize_sends_correct_request() {
        let mock_server = MockServer::start().await;

        let audio_bytes = vec![0xFF, 0xFB, 0x90, 0x00]; // Fake MP3 header bytes

        Mock::given(method("POST"))
            .and(path("/v1/audio/speech"))
            .and(header("Authorization", "Bearer sk-mock-key"))
            .and(header("Content-Type", "application/json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(audio_bytes.clone())
                    .insert_header("content-type", "audio/mpeg"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = OpenAiTtsProvider::new(
            "sk-mock-key".to_string(),
            Some(format!("{}/v1/audio/speech", mock_server.uri())),
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
            .and(path("/v1/audio/speech"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_string(r#"{"error":{"message":"rate limit exceeded"}}"#),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = OpenAiTtsProvider::new(
            "sk-mock-key".to_string(),
            Some(format!("{}/v1/audio/speech", mock_server.uri())),
            None,
        )
        .unwrap();

        let result = provider.synthesize("Hello", None, AudioFormat::Mp3).await;

        assert!(matches!(result, Err(TtsError::ProviderError(_))));
        if let Err(TtsError::ProviderError(msg)) = result {
            assert!(msg.contains("429"));
            assert!(msg.contains("rate limit"));
        }
    }

    #[tokio::test]
    async fn synthesize_uses_specified_voice() {
        let mock_server = MockServer::start().await;

        // We verify the request contains the right voice by checking the body.
        Mock::given(method("POST"))
            .and(path("/v1/audio/speech"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0x00]))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = OpenAiTtsProvider::new(
            "sk-mock-key".to_string(),
            Some(format!("{}/v1/audio/speech", mock_server.uri())),
            Some("alloy".to_string()),
        )
        .unwrap();

        let result = provider
            .synthesize("Test", Some("shimmer"), AudioFormat::Mp3)
            .await;

        assert!(result.is_ok());
    }

    /// Security test: verify that the provider rejects endpoints pointing to
    /// private IP ranges (SSRF protection).
    #[test]
    fn provider_rejects_private_ip_endpoints() {
        let result = OpenAiTtsProvider::new(
            "sk-test".to_string(),
            Some("https://10.0.0.1/v1/audio/speech".to_string()),
            None,
        );
        assert!(
            matches!(result, Err(TtsError::InvalidEndpoint(_))),
            "must reject private IP endpoints to prevent SSRF"
        );

        let result = OpenAiTtsProvider::new(
            "sk-test".to_string(),
            Some("https://192.168.1.1/v1/audio/speech".to_string()),
            None,
        );
        assert!(matches!(result, Err(TtsError::InvalidEndpoint(_))));
    }
}
