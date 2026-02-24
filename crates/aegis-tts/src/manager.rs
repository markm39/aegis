//! TTS manager that routes requests to the configured provider with rate limiting.
//!
//! The [`TtsManager`] wraps one or more [`TtsProvider`] implementations and
//! routes synthesis requests to the active provider. It enforces a configurable
//! rate limit (requests per minute) to prevent abuse and runaway costs.
//!
//! # Security
//!
//! - Rate limiting is enforced before any provider call.
//! - Text is sanitized via [`sanitize_text`](crate::sanitize_text) before synthesis.
//! - Provider selection is validated at construction time.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{sanitize_text, AudioFormat, TtsConfig, TtsError, TtsProvider, TtsResult, VoiceInfo};

/// A sliding-window rate limiter based on request timestamps.
///
/// Tracks timestamps of recent requests and rejects new ones when the
/// window is full. The window size is 60 seconds (one minute).
struct RateLimiter {
    /// Maximum requests allowed per minute. 0 means unlimited.
    max_rpm: u32,
    /// Timestamps of requests within the current window.
    timestamps: Vec<std::time::Instant>,
}

impl RateLimiter {
    fn new(max_rpm: u32) -> Self {
        Self {
            max_rpm,
            timestamps: Vec::new(),
        }
    }

    /// Check if a request is allowed under the rate limit.
    ///
    /// If allowed, records the timestamp and returns `Ok(())`.
    /// If the rate limit is exceeded, returns an error.
    fn check(&mut self) -> TtsResult<()> {
        if self.max_rpm == 0 {
            return Ok(()); // Unlimited.
        }

        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(60);

        // Evict expired timestamps.
        self.timestamps
            .retain(|ts| now.duration_since(*ts) < window);

        if self.timestamps.len() >= self.max_rpm as usize {
            return Err(TtsError::ProviderError(format!(
                "rate limit exceeded: {} requests per minute (current: {})",
                self.max_rpm,
                self.timestamps.len()
            )));
        }

        self.timestamps.push(now);
        Ok(())
    }

    /// Return the number of requests in the current window.
    #[cfg(test)]
    fn current_count(&mut self) -> usize {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(60);
        self.timestamps
            .retain(|ts| now.duration_since(*ts) < window);
        self.timestamps.len()
    }
}

/// TTS manager that routes requests to providers with rate limiting.
///
/// Holds multiple named providers and routes to the active one based on
/// the configured provider name. Rate limiting is applied globally across
/// all providers.
pub struct TtsManager {
    /// Named providers keyed by provider name.
    providers: HashMap<String, Box<dyn TtsProvider>>,
    /// Name of the active provider.
    active_provider: String,
    /// Shared rate limiter (behind a mutex for async safety).
    rate_limiter: Arc<Mutex<RateLimiter>>,
    /// Maximum text length from config.
    max_text_length: usize,
    /// Default voice for the active provider.
    default_voice: String,
    /// Default audio format.
    default_format: AudioFormat,
}

impl TtsManager {
    /// Create a new TTS manager from a [`TtsConfig`].
    ///
    /// This does NOT automatically create providers -- use [`add_provider`]
    /// to register providers after construction.
    pub fn new(config: &TtsConfig) -> Self {
        Self {
            providers: HashMap::new(),
            active_provider: config.provider.clone(),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(config.rate_limit_rpm))),
            max_text_length: config.max_text_length,
            default_voice: config.default_voice.clone(),
            default_format: config.default_format,
        }
    }

    /// Register a provider under a given name.
    pub fn add_provider(&mut self, name: impl Into<String>, provider: Box<dyn TtsProvider>) {
        self.providers.insert(name.into(), provider);
    }

    /// Set the active provider by name.
    ///
    /// Returns an error if the provider is not registered.
    pub fn set_active_provider(&mut self, name: &str) -> TtsResult<()> {
        if !self.providers.contains_key(name) {
            return Err(TtsError::ConfigError(format!(
                "unknown provider: {name} (available: {})",
                self.providers
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        self.active_provider = name.to_string();
        Ok(())
    }

    /// Get a reference to the active provider.
    fn active(&self) -> TtsResult<&dyn TtsProvider> {
        self.providers
            .get(&self.active_provider)
            .map(|p| p.as_ref())
            .ok_or_else(|| {
                TtsError::ConfigError(format!(
                    "active provider '{}' is not registered",
                    self.active_provider
                ))
            })
    }

    /// Synthesize text to audio using the active provider.
    ///
    /// Performs text sanitization and rate limit checks before calling the
    /// provider. If `voice` is `None`, the manager's default voice is used.
    /// If `format` is `None`, the manager's default format is used.
    pub async fn synthesize(
        &self,
        text: &str,
        voice: Option<&str>,
        format: Option<AudioFormat>,
    ) -> TtsResult<Vec<u8>> {
        // Sanitize text input.
        let sanitized = sanitize_text(text, self.max_text_length)?;

        // Enforce rate limit.
        {
            let mut limiter = self.rate_limiter.lock().await;
            limiter.check()?;
        }

        let format = format.unwrap_or(self.default_format);
        let voice = voice.unwrap_or(&self.default_voice);
        let voice_opt = if voice.is_empty() { None } else { Some(voice) };

        let provider = self.active()?;

        tracing::info!(
            provider = provider.name(),
            voice = voice,
            format = %format,
            text_len = sanitized.len(),
            "TtsManager: routing synthesis request"
        );

        provider.synthesize(&sanitized, voice_opt, format).await
    }

    /// List all voices from the active provider.
    pub fn list_voices(&self) -> TtsResult<Vec<VoiceInfo>> {
        let provider = self.active()?;
        Ok(provider.list_voices())
    }

    /// List all voices from all registered providers.
    pub fn list_all_voices(&self) -> Vec<VoiceInfo> {
        self.providers
            .values()
            .flat_map(|p| p.list_voices())
            .collect()
    }

    /// Return the name of the active provider.
    pub fn active_provider_name(&self) -> &str {
        &self.active_provider
    }

    /// Return the names of all registered providers.
    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.keys().map(|k| k.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    /// A mock TTS provider for testing the manager.
    struct MockProvider {
        provider_name: String,
        /// Audio bytes to return from synthesize.
        response_bytes: Vec<u8>,
    }

    impl MockProvider {
        fn new(name: &str, response: Vec<u8>) -> Self {
            Self {
                provider_name: name.to_string(),
                response_bytes: response,
            }
        }
    }

    #[async_trait]
    impl TtsProvider for MockProvider {
        async fn synthesize(
            &self,
            _text: &str,
            _voice: Option<&str>,
            _format: AudioFormat,
        ) -> TtsResult<Vec<u8>> {
            Ok(self.response_bytes.clone())
        }

        fn list_voices(&self) -> Vec<VoiceInfo> {
            vec![VoiceInfo {
                id: "mock-voice".to_string(),
                name: "Mock Voice".to_string(),
                provider: self.provider_name.clone(),
                language: Some("en".to_string()),
                gender: Some("neutral".to_string()),
                style: None,
                preview_url: None,
            }]
        }

        fn name(&self) -> &str {
            &self.provider_name
        }
    }

    #[tokio::test]
    async fn tts_manager_routes_to_provider() {
        let config = TtsConfig {
            provider: "mock-a".to_string(),
            rate_limit_rpm: 0, // Unlimited for testing.
            ..TtsConfig::default()
        };

        let mut manager = TtsManager::new(&config);
        manager.add_provider(
            "mock-a",
            Box::new(MockProvider::new("mock-a", vec![0xAA, 0xBB])),
        );
        manager.add_provider(
            "mock-b",
            Box::new(MockProvider::new("mock-b", vec![0xCC, 0xDD])),
        );

        // Should route to mock-a.
        let result = manager.synthesize("Hello", None, None).await.unwrap();
        assert_eq!(result, vec![0xAA, 0xBB]);

        // Switch to mock-b.
        manager.set_active_provider("mock-b").unwrap();
        let result = manager.synthesize("Hello", None, None).await.unwrap();
        assert_eq!(result, vec![0xCC, 0xDD]);
    }

    #[tokio::test]
    async fn tts_manager_rate_limiting() {
        let config = TtsConfig {
            provider: "mock".to_string(),
            rate_limit_rpm: 3, // Allow only 3 requests per minute.
            ..TtsConfig::default()
        };

        let mut manager = TtsManager::new(&config);
        manager.add_provider("mock", Box::new(MockProvider::new("mock", vec![0x00])));

        // First 3 requests should succeed.
        for _ in 0..3 {
            let result = manager.synthesize("Hello", None, None).await;
            assert!(result.is_ok(), "request should succeed within rate limit");
        }

        // 4th request should be rate limited.
        let result = manager.synthesize("Hello", None, None).await;
        assert!(
            matches!(result, Err(TtsError::ProviderError(ref msg)) if msg.contains("rate limit")),
            "4th request should be rate limited, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn tts_manager_sanitizes_text() {
        let config = TtsConfig {
            provider: "mock".to_string(),
            rate_limit_rpm: 0,
            max_text_length: 10,
            ..TtsConfig::default()
        };

        let mut manager = TtsManager::new(&config);
        manager.add_provider("mock", Box::new(MockProvider::new("mock", vec![0x00])));

        // Text too long should be rejected.
        let long_text = "a".repeat(11);
        let result = manager.synthesize(&long_text, None, None).await;
        assert!(matches!(result, Err(TtsError::TextTooLong { .. })));

        // Empty text should be rejected.
        let result = manager.synthesize("", None, None).await;
        assert!(matches!(result, Err(TtsError::EmptyText)));
    }

    #[tokio::test]
    async fn tts_manager_unknown_provider_error() {
        let config = TtsConfig {
            provider: "nonexistent".to_string(),
            rate_limit_rpm: 0,
            ..TtsConfig::default()
        };

        let manager = TtsManager::new(&config);

        let result = manager.synthesize("Hello", None, None).await;
        assert!(matches!(result, Err(TtsError::ConfigError(_))));
    }

    #[test]
    fn tts_manager_list_voices() {
        let config = TtsConfig {
            provider: "mock-a".to_string(),
            rate_limit_rpm: 0,
            ..TtsConfig::default()
        };

        let mut manager = TtsManager::new(&config);
        manager.add_provider("mock-a", Box::new(MockProvider::new("mock-a", vec![])));
        manager.add_provider("mock-b", Box::new(MockProvider::new("mock-b", vec![])));

        // list_voices returns only the active provider's voices.
        let voices = manager.list_voices().unwrap();
        assert_eq!(voices.len(), 1);
        assert_eq!(voices[0].provider, "mock-a");

        // list_all_voices returns voices from all providers.
        let all_voices = manager.list_all_voices();
        assert_eq!(all_voices.len(), 2);
    }

    #[test]
    fn tts_manager_set_active_provider_validation() {
        let config = TtsConfig {
            provider: "mock".to_string(),
            rate_limit_rpm: 0,
            ..TtsConfig::default()
        };

        let mut manager = TtsManager::new(&config);
        manager.add_provider("mock", Box::new(MockProvider::new("mock", vec![])));

        // Setting to registered provider should succeed.
        assert!(manager.set_active_provider("mock").is_ok());

        // Setting to unregistered provider should fail.
        let result = manager.set_active_provider("unknown");
        assert!(matches!(result, Err(TtsError::ConfigError(_))));
    }

    #[test]
    fn rate_limiter_sliding_window() {
        let mut limiter = RateLimiter::new(5);

        // Should allow 5 requests.
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }
        assert_eq!(limiter.current_count(), 5);

        // 6th should fail.
        assert!(limiter.check().is_err());
    }

    #[test]
    fn rate_limiter_unlimited() {
        let mut limiter = RateLimiter::new(0);

        // Should allow any number of requests.
        for _ in 0..1000 {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn tts_manager_provider_names() {
        let config = TtsConfig {
            provider: "mock-a".to_string(),
            rate_limit_rpm: 0,
            ..TtsConfig::default()
        };

        let mut manager = TtsManager::new(&config);
        manager.add_provider("mock-a", Box::new(MockProvider::new("mock-a", vec![])));
        manager.add_provider("mock-b", Box::new(MockProvider::new("mock-b", vec![])));

        let mut names = manager.provider_names();
        names.sort();
        assert_eq!(names, vec!["mock-a", "mock-b"]);
        assert_eq!(manager.active_provider_name(), "mock-a");
    }
}
