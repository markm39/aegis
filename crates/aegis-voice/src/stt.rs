//! Speech-to-text (STT) provider trait and implementations.
//!
//! Provides a pluggable [`SttProvider`] trait for converting audio to text,
//! with three implementations:
//!
//! - [`WhisperStt`]: OpenAI Whisper API (cloud-based, high accuracy).
//! - [`DeepgramStt`]: Deepgram API (cloud-based, low latency).
//! - [`LocalStt`]: Local whisper.cpp via command line (offline, private).
//!
//! # Security
//!
//! - API keys are resolved from environment variables, never stored in config.
//! - Audio data is sent over HTTPS only (enforced by provider implementations).
//! - Local STT keeps all data on-device.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::process::Command;

use crate::{VoiceError, VoiceResult};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for speech-to-text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SttConfig {
    /// Which STT provider to use.
    #[serde(default)]
    pub provider: SttProviderKind,

    /// Environment variable name holding the API key (for cloud providers).
    #[serde(default = "default_stt_api_key_env")]
    pub api_key_env: String,

    /// Language hint for transcription (BCP-47 tag, e.g., "en").
    #[serde(default = "default_language")]
    pub language: String,

    /// Model name override (provider-specific).
    pub model: Option<String>,

    /// Path to local whisper.cpp binary (for `LocalStt`).
    pub whisper_bin: Option<String>,

    /// Path to local whisper model file (for `LocalStt`).
    pub whisper_model: Option<String>,
}

/// Available STT provider types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SttProviderKind {
    /// OpenAI Whisper API.
    #[default]
    Whisper,
    /// Deepgram API.
    Deepgram,
    /// Local whisper.cpp binary.
    Local,
}

impl std::fmt::Display for SttProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SttProviderKind::Whisper => write!(f, "whisper"),
            SttProviderKind::Deepgram => write!(f, "deepgram"),
            SttProviderKind::Local => write!(f, "local"),
        }
    }
}

fn default_stt_api_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}

fn default_language() -> String {
    "en".to_string()
}

impl Default for SttConfig {
    fn default() -> Self {
        Self {
            provider: SttProviderKind::default(),
            api_key_env: default_stt_api_key_env(),
            language: default_language(),
            model: None,
            whisper_bin: None,
            whisper_model: None,
        }
    }
}

impl SttConfig {
    /// Resolve the API key from the configured environment variable.
    ///
    /// Returns an error if the variable is not set or is empty.
    pub fn resolve_api_key(&self) -> VoiceResult<String> {
        std::env::var(&self.api_key_env)
            .map_err(|_| {
                VoiceError::ConfigError(format!(
                    "missing API key: environment variable {} is not set",
                    self.api_key_env
                ))
            })
            .and_then(|key| {
                if key.is_empty() {
                    Err(VoiceError::ConfigError(format!(
                        "API key is empty: environment variable {}",
                        self.api_key_env
                    )))
                } else {
                    Ok(key)
                }
            })
    }
}

// ---------------------------------------------------------------------------
// SttProvider trait
// ---------------------------------------------------------------------------

/// Trait for pluggable speech-to-text backends.
///
/// Each implementation handles communication with a specific STT service.
/// Implementations must be `Send + Sync` for use in async contexts.
#[async_trait]
pub trait SttProvider: Send + Sync {
    /// Transcribe audio data to text.
    ///
    /// The `audio` parameter should contain WAV-formatted audio data
    /// (16-bit PCM, mono, at the capture sample rate).
    ///
    /// Returns the transcribed text, which may be empty if no speech
    /// was detected.
    async fn transcribe(&self, audio: &[u8]) -> VoiceResult<String>;

    /// Return the provider name.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// WhisperStt
// ---------------------------------------------------------------------------

/// OpenAI Whisper API speech-to-text provider.
///
/// Sends audio to the OpenAI `/v1/audio/transcriptions` endpoint and
/// returns the transcribed text. Requires an OpenAI API key.
pub struct WhisperStt {
    client: reqwest::Client,
    api_key: String,
    model: String,
    language: String,
}

/// Default Whisper model.
const DEFAULT_WHISPER_MODEL: &str = "whisper-1";

/// OpenAI Whisper API endpoint.
const WHISPER_API_URL: &str = "https://api.openai.com/v1/audio/transcriptions";

impl WhisperStt {
    /// Create a new Whisper STT provider from configuration.
    ///
    /// Resolves the API key from the environment immediately.
    pub fn from_config(config: &SttConfig) -> VoiceResult<Self> {
        let api_key = config.resolve_api_key()?;
        let model = config
            .model
            .clone()
            .unwrap_or_else(|| DEFAULT_WHISPER_MODEL.to_string());

        Ok(Self {
            client: reqwest::Client::new(),
            api_key,
            model,
            language: config.language.clone(),
        })
    }

    /// Create from explicit parameters (useful for testing).
    pub fn new(api_key: String, model: Option<String>, language: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            model: model.unwrap_or_else(|| DEFAULT_WHISPER_MODEL.to_string()),
            language: language.unwrap_or_else(|| "en".to_string()),
        }
    }
}

#[async_trait]
impl SttProvider for WhisperStt {
    async fn transcribe(&self, audio: &[u8]) -> VoiceResult<String> {
        tracing::debug!(
            model = %self.model,
            language = %self.language,
            audio_bytes = audio.len(),
            "sending audio to Whisper API"
        );

        let file_part = reqwest::multipart::Part::bytes(audio.to_vec())
            .file_name("audio.wav")
            .mime_str("audio/wav")
            .map_err(|e| VoiceError::SttError(format!("failed to create multipart: {e}")))?;

        let form = reqwest::multipart::Form::new()
            .part("file", file_part)
            .text("model", self.model.clone())
            .text("language", self.language.clone())
            .text("response_format", "text");

        let response = self
            .client
            .post(WHISPER_API_URL)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .multipart(form)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read error body".to_string());
            return Err(VoiceError::SttError(format!(
                "Whisper API returned {status}: {error_body}"
            )));
        }

        let text = response.text().await.map_err(|e| {
            VoiceError::SttError(format!("failed to read response: {e}"))
        })?;

        Ok(text.trim().to_string())
    }

    fn name(&self) -> &str {
        "whisper"
    }
}

// ---------------------------------------------------------------------------
// DeepgramStt
// ---------------------------------------------------------------------------

/// Deepgram API speech-to-text provider.
///
/// Sends audio to the Deepgram `/v1/listen` endpoint and returns the
/// transcribed text. Requires a Deepgram API key.
pub struct DeepgramStt {
    client: reqwest::Client,
    api_key: String,
    model: String,
    language: String,
}

/// Default Deepgram model.
const DEFAULT_DEEPGRAM_MODEL: &str = "nova-2";

/// Deepgram API endpoint.
const DEEPGRAM_API_URL: &str = "https://api.deepgram.com/v1/listen";

impl DeepgramStt {
    /// Create a new Deepgram STT provider from configuration.
    pub fn from_config(config: &SttConfig) -> VoiceResult<Self> {
        let api_key = config.resolve_api_key()?;
        let model = config
            .model
            .clone()
            .unwrap_or_else(|| DEFAULT_DEEPGRAM_MODEL.to_string());

        Ok(Self {
            client: reqwest::Client::new(),
            api_key,
            model,
            language: config.language.clone(),
        })
    }

    /// Create from explicit parameters.
    pub fn new(api_key: String, model: Option<String>, language: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            model: model.unwrap_or_else(|| DEFAULT_DEEPGRAM_MODEL.to_string()),
            language: language.unwrap_or_else(|| "en".to_string()),
        }
    }
}

/// Deepgram API response structure.
#[derive(Debug, Deserialize)]
struct DeepgramResponse {
    results: Option<DeepgramResults>,
}

#[derive(Debug, Deserialize)]
struct DeepgramResults {
    channels: Vec<DeepgramChannel>,
}

#[derive(Debug, Deserialize)]
struct DeepgramChannel {
    alternatives: Vec<DeepgramAlternative>,
}

#[derive(Debug, Deserialize)]
struct DeepgramAlternative {
    transcript: String,
}

#[async_trait]
impl SttProvider for DeepgramStt {
    async fn transcribe(&self, audio: &[u8]) -> VoiceResult<String> {
        tracing::debug!(
            model = %self.model,
            language = %self.language,
            audio_bytes = audio.len(),
            "sending audio to Deepgram API"
        );

        let url = format!(
            "{}?model={}&language={}",
            DEEPGRAM_API_URL, self.model, self.language
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Token {}", self.api_key))
            .header("Content-Type", "audio/wav")
            .body(audio.to_vec())
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read error body".to_string());
            return Err(VoiceError::SttError(format!(
                "Deepgram API returned {status}: {error_body}"
            )));
        }

        let body: DeepgramResponse = response.json().await.map_err(|e| {
            VoiceError::SttError(format!("failed to parse Deepgram response: {e}"))
        })?;

        let transcript = body
            .results
            .and_then(|r| r.channels.into_iter().next())
            .and_then(|c| c.alternatives.into_iter().next())
            .map(|a| a.transcript)
            .unwrap_or_default();

        Ok(transcript.trim().to_string())
    }

    fn name(&self) -> &str {
        "deepgram"
    }
}

// ---------------------------------------------------------------------------
// LocalStt
// ---------------------------------------------------------------------------

/// Local whisper.cpp speech-to-text provider.
///
/// Runs whisper.cpp as a subprocess to transcribe audio entirely on-device.
/// Requires the whisper.cpp binary (`main` or `whisper-cpp`) and a model
/// file to be present on the system.
pub struct LocalStt {
    /// Path to the whisper.cpp binary.
    whisper_bin: String,
    /// Path to the GGML model file.
    model_path: String,
    /// Language hint.
    language: String,
}

impl LocalStt {
    /// Create a new local STT provider from configuration.
    pub fn from_config(config: &SttConfig) -> VoiceResult<Self> {
        let whisper_bin = config.whisper_bin.clone().unwrap_or_else(|| {
            "whisper-cpp".to_string()
        });
        let model_path = config.whisper_model.clone().ok_or_else(|| {
            VoiceError::ConfigError(
                "whisper_model path is required for local STT provider".to_string(),
            )
        })?;

        Ok(Self {
            whisper_bin,
            model_path,
            language: config.language.clone(),
        })
    }

    /// Create from explicit parameters.
    pub fn new(whisper_bin: String, model_path: String, language: Option<String>) -> Self {
        Self {
            whisper_bin,
            model_path,
            language: language.unwrap_or_else(|| "en".to_string()),
        }
    }
}

#[async_trait]
impl SttProvider for LocalStt {
    async fn transcribe(&self, audio: &[u8]) -> VoiceResult<String> {
        // Write audio to a temporary file (whisper.cpp reads from files).
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!("aegis_stt_{}.wav", std::process::id()));

        tokio::fs::write(&temp_path, audio).await.map_err(|e| {
            VoiceError::SttError(format!("failed to write temp audio file: {e}"))
        })?;

        tracing::debug!(
            bin = %self.whisper_bin,
            model = %self.model_path,
            language = %self.language,
            audio_bytes = audio.len(),
            "transcribing audio with local whisper.cpp"
        );

        let output = Command::new(&self.whisper_bin)
            .arg("-m")
            .arg(&self.model_path)
            .arg("-l")
            .arg(&self.language)
            .arg("-f")
            .arg(temp_path.to_string_lossy().as_ref())
            .arg("--no-timestamps")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                VoiceError::SttError(format!("failed to run {}: {e}", self.whisper_bin))
            })?;

        // Clean up temp file (best-effort).
        let _ = tokio::fs::remove_file(&temp_path).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(VoiceError::SttError(format!(
                "whisper.cpp exited with status {}: {stderr}",
                output.status
            )));
        }

        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(text)
    }

    fn name(&self) -> &str {
        "local"
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Create an STT provider from configuration.
///
/// Returns the appropriate provider based on `config.provider`.
pub fn create_stt_provider(config: &SttConfig) -> VoiceResult<Box<dyn SttProvider>> {
    match config.provider {
        SttProviderKind::Whisper => {
            let provider = WhisperStt::from_config(config)?;
            Ok(Box::new(provider))
        }
        SttProviderKind::Deepgram => {
            let provider = DeepgramStt::from_config(config)?;
            Ok(Box::new(provider))
        }
        SttProviderKind::Local => {
            let provider = LocalStt::from_config(config)?;
            Ok(Box::new(provider))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SttConfig tests --

    #[test]
    fn stt_config_defaults() {
        let config = SttConfig::default();
        assert_eq!(config.provider, SttProviderKind::Whisper);
        assert_eq!(config.api_key_env, "OPENAI_API_KEY");
        assert_eq!(config.language, "en");
        assert!(config.model.is_none());
        assert!(config.whisper_bin.is_none());
        assert!(config.whisper_model.is_none());
    }

    #[test]
    fn stt_config_serialization_roundtrip() {
        let config = SttConfig {
            provider: SttProviderKind::Deepgram,
            api_key_env: "DEEPGRAM_API_KEY".to_string(),
            language: "es".to_string(),
            model: Some("nova-2".to_string()),
            whisper_bin: None,
            whisper_model: None,
        };

        let json = serde_json::to_string(&config).unwrap();
        let back: SttConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider, SttProviderKind::Deepgram);
        assert_eq!(back.api_key_env, "DEEPGRAM_API_KEY");
        assert_eq!(back.language, "es");
        assert_eq!(back.model.as_deref(), Some("nova-2"));
    }

    #[test]
    fn stt_config_deserialize_defaults() {
        let json = "{}";
        let config: SttConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.provider, SttProviderKind::Whisper);
        assert_eq!(config.language, "en");
    }

    // -- SttProviderKind tests --

    #[test]
    fn stt_provider_kind_display() {
        assert_eq!(SttProviderKind::Whisper.to_string(), "whisper");
        assert_eq!(SttProviderKind::Deepgram.to_string(), "deepgram");
        assert_eq!(SttProviderKind::Local.to_string(), "local");
    }

    #[test]
    fn stt_provider_kind_serialization() {
        for kind in [
            SttProviderKind::Whisper,
            SttProviderKind::Deepgram,
            SttProviderKind::Local,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: SttProviderKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn stt_provider_kind_default() {
        assert_eq!(SttProviderKind::default(), SttProviderKind::Whisper);
    }

    // -- API key resolution tests --

    #[test]
    fn stt_config_resolve_api_key_missing() {
        std::env::remove_var("AEGIS_STT_TEST_MISSING_KEY_XYZ");
        let config = SttConfig {
            api_key_env: "AEGIS_STT_TEST_MISSING_KEY_XYZ".to_string(),
            ..SttConfig::default()
        };
        let result = config.resolve_api_key();
        assert!(result.is_err());
    }

    #[test]
    fn stt_config_resolve_api_key_empty() {
        std::env::set_var("AEGIS_STT_TEST_EMPTY_KEY", "");
        let config = SttConfig {
            api_key_env: "AEGIS_STT_TEST_EMPTY_KEY".to_string(),
            ..SttConfig::default()
        };
        let result = config.resolve_api_key();
        assert!(result.is_err());
        std::env::remove_var("AEGIS_STT_TEST_EMPTY_KEY");
    }

    #[test]
    fn stt_config_resolve_api_key_present() {
        std::env::set_var("AEGIS_STT_TEST_PRESENT_KEY", "sk-test-value");
        let config = SttConfig {
            api_key_env: "AEGIS_STT_TEST_PRESENT_KEY".to_string(),
            ..SttConfig::default()
        };
        let key = config.resolve_api_key().unwrap();
        assert_eq!(key, "sk-test-value");
        std::env::remove_var("AEGIS_STT_TEST_PRESENT_KEY");
    }

    // -- Provider construction tests --

    #[test]
    fn whisper_stt_new() {
        let provider = WhisperStt::new("sk-test".to_string(), None, None);
        assert_eq!(provider.name(), "whisper");
        assert_eq!(provider.model, "whisper-1");
        assert_eq!(provider.language, "en");
    }

    #[test]
    fn whisper_stt_custom_model() {
        let provider = WhisperStt::new(
            "sk-test".to_string(),
            Some("whisper-large-v3".to_string()),
            Some("fr".to_string()),
        );
        assert_eq!(provider.model, "whisper-large-v3");
        assert_eq!(provider.language, "fr");
    }

    #[test]
    fn deepgram_stt_new() {
        let provider = DeepgramStt::new("dg-test".to_string(), None, None);
        assert_eq!(provider.name(), "deepgram");
        assert_eq!(provider.model, "nova-2");
        assert_eq!(provider.language, "en");
    }

    #[test]
    fn local_stt_new() {
        let provider = LocalStt::new(
            "/usr/local/bin/whisper-cpp".to_string(),
            "/models/ggml-base.bin".to_string(),
            None,
        );
        assert_eq!(provider.name(), "local");
        assert_eq!(provider.whisper_bin, "/usr/local/bin/whisper-cpp");
        assert_eq!(provider.model_path, "/models/ggml-base.bin");
    }

    #[test]
    fn local_stt_from_config_requires_model() {
        let config = SttConfig {
            provider: SttProviderKind::Local,
            whisper_model: None,
            ..SttConfig::default()
        };
        let result = LocalStt::from_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn local_stt_from_config_with_model() {
        let config = SttConfig {
            provider: SttProviderKind::Local,
            whisper_bin: Some("/opt/whisper".to_string()),
            whisper_model: Some("/models/base.bin".to_string()),
            ..SttConfig::default()
        };
        let provider = LocalStt::from_config(&config).unwrap();
        assert_eq!(provider.whisper_bin, "/opt/whisper");
        assert_eq!(provider.model_path, "/models/base.bin");
    }

    // -- Factory tests --

    #[test]
    fn create_stt_provider_whisper_requires_key() {
        std::env::remove_var("AEGIS_STT_FACTORY_TEST_KEY");
        let config = SttConfig {
            provider: SttProviderKind::Whisper,
            api_key_env: "AEGIS_STT_FACTORY_TEST_KEY".to_string(),
            ..SttConfig::default()
        };
        let result = create_stt_provider(&config);
        assert!(result.is_err());
    }

    #[test]
    fn create_stt_provider_local_requires_model() {
        let config = SttConfig {
            provider: SttProviderKind::Local,
            whisper_model: None,
            ..SttConfig::default()
        };
        let result = create_stt_provider(&config);
        assert!(result.is_err());
    }

    // -- Deepgram response parsing tests --

    #[test]
    fn deepgram_response_parse() {
        let json = r#"{
            "results": {
                "channels": [{
                    "alternatives": [{
                        "transcript": "hello world"
                    }]
                }]
            }
        }"#;

        let response: DeepgramResponse = serde_json::from_str(json).unwrap();
        let transcript = response
            .results
            .unwrap()
            .channels
            .into_iter()
            .next()
            .unwrap()
            .alternatives
            .into_iter()
            .next()
            .unwrap()
            .transcript;
        assert_eq!(transcript, "hello world");
    }

    #[test]
    fn deepgram_response_empty() {
        let json = r#"{"results": null}"#;
        let response: DeepgramResponse = serde_json::from_str(json).unwrap();
        let transcript = response
            .results
            .and_then(|r| r.channels.into_iter().next())
            .and_then(|c| c.alternatives.into_iter().next())
            .map(|a| a.transcript)
            .unwrap_or_default();
        assert_eq!(transcript, "");
    }
}
