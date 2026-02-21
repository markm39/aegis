//! Embedding providers for vector memory search.
//!
//! Provides an async trait for generating text embeddings and an OpenAI
//! implementation that calls the embeddings API. API keys are read
//! exclusively from environment variables -- never from config files.

use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Async trait for generating vector embeddings from text.
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// Generate embeddings for a batch of texts.
    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>>;

    /// Maximum number of texts per single API call.
    fn max_batch_size(&self) -> usize;

    /// Human-readable provider name for logging.
    fn provider_name(&self) -> &str;

    /// Dimensionality of the returned embedding vectors.
    fn dimension(&self) -> usize;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for embedding generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingConfig {
    /// Provider identifier (currently only "openai").
    #[serde(default = "default_provider")]
    pub provider: String,

    /// Model name passed to the API.
    #[serde(default = "default_model")]
    pub model: String,

    /// Name of the environment variable holding the API key.
    /// The key itself is NEVER stored in config.
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,

    /// Number of texts to send per API request.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Expected embedding dimension.
    #[serde(default = "default_dimension")]
    pub dimension: usize,

    /// Rate limit in requests per minute.
    #[serde(default = "default_rate_limit_rpm")]
    pub rate_limit_rpm: u32,
}

fn default_provider() -> String {
    "openai".into()
}
fn default_model() -> String {
    "text-embedding-3-small".into()
}
fn default_api_key_env() -> String {
    "OPENAI_API_KEY".into()
}
fn default_batch_size() -> usize {
    100
}
fn default_dimension() -> usize {
    1536
}
fn default_rate_limit_rpm() -> u32 {
    60
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            model: default_model(),
            api_key_env: default_api_key_env(),
            batch_size: default_batch_size(),
            dimension: default_dimension(),
            rate_limit_rpm: default_rate_limit_rpm(),
        }
    }
}

// ---------------------------------------------------------------------------
// OpenAI provider
// ---------------------------------------------------------------------------

/// Maximum character length for a single input text (~8191 tokens).
const MAX_INPUT_CHARS: usize = 32_768;

/// OpenAI-compatible embedding provider.
#[derive(Debug)]
pub struct OpenAiEmbeddingProvider {
    api_key: String,
    model: String,
    dimension: usize,
    max_batch: usize,
    client: reqwest::Client,
    rate_limiter: Mutex<TokenBucket>,
}

/// Simple token-bucket rate limiter.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(requests_per_minute: u32) -> Self {
        let max = requests_per_minute as f64;
        Self {
            tokens: max,
            max_tokens: max,
            refill_rate: max / 60.0,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl OpenAiEmbeddingProvider {
    /// Create a new OpenAI embedding provider.
    ///
    /// The API key is read from the environment variable specified by
    /// `api_key_env`. Construction fails if the variable is unset or empty.
    pub fn new(config: &EmbeddingConfig) -> Result<Self> {
        let api_key = std::env::var(&config.api_key_env).with_context(|| {
            format!(
                "embedding API key not found: set the {} environment variable",
                config.api_key_env
            )
        })?;

        ensure!(
            !api_key.is_empty(),
            "embedding API key in {} is empty",
            config.api_key_env
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("build HTTP client for embeddings")?;

        Ok(Self {
            api_key,
            model: config.model.clone(),
            dimension: config.dimension,
            max_batch: config.batch_size.min(2048),
            client,
            rate_limiter: Mutex::new(TokenBucket::new(config.rate_limit_rpm)),
        })
    }

    /// Wait until the rate limiter allows a request.
    async fn wait_for_rate_limit(&self) {
        loop {
            {
                let mut limiter = self.rate_limiter.lock().expect("rate limiter poisoned");
                if limiter.try_consume() {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

#[async_trait]
impl EmbeddingProvider for OpenAiEmbeddingProvider {
    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
        ensure!(!texts.is_empty(), "embed called with empty text list");

        for (i, text) in texts.iter().enumerate() {
            ensure!(
                !text.is_empty(),
                "embed input at index {i} is empty"
            );
            ensure!(
                text.len() <= MAX_INPUT_CHARS,
                "embed input at index {i} exceeds maximum length ({} > {MAX_INPUT_CHARS})",
                text.len()
            );
        }

        self.wait_for_rate_limit().await;

        let body = serde_json::json!({
            "model": self.model,
            "input": texts,
        });

        let resp = self
            .client
            .post("https://api.openai.com/v1/embeddings")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .context("send embedding request to OpenAI")?;

        let status = resp.status();
        if !status.is_success() {
            let err_body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".into());
            bail!("OpenAI embeddings API returned {status}: {err_body}");
        }

        let response: OpenAiEmbeddingResponse = resp
            .json()
            .await
            .context("parse OpenAI embedding response")?;

        ensure!(
            response.data.len() == texts.len(),
            "expected {} embeddings, got {}",
            texts.len(),
            response.data.len()
        );

        let mut embeddings = Vec::with_capacity(response.data.len());
        for item in response.data {
            ensure!(
                item.embedding.len() == self.dimension,
                "expected embedding dimension {}, got {}",
                self.dimension,
                item.embedding.len()
            );
            embeddings.push(item.embedding);
        }

        Ok(embeddings)
    }

    fn max_batch_size(&self) -> usize {
        self.max_batch
    }

    fn provider_name(&self) -> &str {
        "openai"
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}

/// Response from the OpenAI embeddings endpoint.
#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingResponse {
    data: Vec<OpenAiEmbeddingData>,
}

/// Single embedding entry in the OpenAI response.
#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingData {
    embedding: Vec<f32>,
}

// ---------------------------------------------------------------------------
// Batch helper
// ---------------------------------------------------------------------------

/// Embed a large list of texts by chunking into provider-sized batches.
///
/// Batches are processed sequentially to respect rate limits.
pub async fn batch_embed(
    provider: &dyn EmbeddingProvider,
    texts: &[String],
) -> Result<Vec<Vec<f32>>> {
    if texts.is_empty() {
        return Ok(Vec::new());
    }

    let batch_size = provider.max_batch_size();
    let mut all_embeddings = Vec::with_capacity(texts.len());

    for chunk in texts.chunks(batch_size) {
        let results = provider.embed(chunk).await?;
        all_embeddings.extend(results);
    }

    Ok(all_embeddings)
}

// ---------------------------------------------------------------------------
// Cosine similarity
// ---------------------------------------------------------------------------

/// Compute cosine similarity between two vectors.
///
/// Returns a value in [-1.0, 1.0]. Identical vectors yield 1.0,
/// orthogonal vectors yield 0.0, and opposite vectors yield -1.0.
///
/// Returns 0.0 if either vector has zero magnitude.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    assert_eq!(a.len(), b.len(), "vectors must have equal length");

    let mut dot = 0.0_f64;
    let mut norm_a = 0.0_f64;
    let mut norm_b = 0.0_f64;

    for (ai, bi) in a.iter().zip(b.iter()) {
        let ai = *ai as f64;
        let bi = *bi as f64;
        dot += ai * bi;
        norm_a += ai * ai;
        norm_b += bi * bi;
    }

    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        return 0.0;
    }

    (dot / denom) as f32
}

// ---------------------------------------------------------------------------
// Blob conversion helpers
// ---------------------------------------------------------------------------

/// Serialize an embedding vector to a little-endian byte blob.
pub fn embedding_to_blob(embedding: &[f32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(embedding.len() * 4);
    for &val in embedding {
        buf.extend_from_slice(&val.to_le_bytes());
    }
    buf
}

/// Deserialize a little-endian byte blob back to an embedding vector.
pub fn blob_to_embedding(blob: &[u8]) -> Vec<f32> {
    assert!(
        blob.len().is_multiple_of(4),
        "blob length must be a multiple of 4 bytes"
    );
    blob.chunks_exact(4)
        .map(|chunk| {
            let bytes: [u8; 4] = chunk.try_into().expect("chunk is exactly 4 bytes");
            f32::from_le_bytes(bytes)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -- Mock provider -------------------------------------------------------

    /// Deterministic mock provider for testing.
    struct MockEmbeddingProvider {
        dim: usize,
        max_batch: usize,
        call_count: AtomicUsize,
    }

    impl MockEmbeddingProvider {
        fn new(dim: usize, max_batch: usize) -> Self {
            Self {
                dim,
                max_batch,
                call_count: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl EmbeddingProvider for MockEmbeddingProvider {
        async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let mut results = Vec::with_capacity(texts.len());
            for (i, _text) in texts.iter().enumerate() {
                // Generate a deterministic vector based on index.
                let mut vec = vec![0.0_f32; self.dim];
                if !vec.is_empty() {
                    vec[i % self.dim] = 1.0;
                }
                results.push(vec);
            }
            Ok(results)
        }

        fn max_batch_size(&self) -> usize {
            self.max_batch
        }

        fn provider_name(&self) -> &str {
            "mock"
        }

        fn dimension(&self) -> usize {
            self.dim
        }
    }

    // -- Config tests --------------------------------------------------------

    #[test]
    fn test_embedding_config_defaults() {
        let config = EmbeddingConfig::default();
        assert_eq!(config.provider, "openai");
        assert_eq!(config.model, "text-embedding-3-small");
        assert_eq!(config.api_key_env, "OPENAI_API_KEY");
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.dimension, 1536);
        assert_eq!(config.rate_limit_rpm, 60);
    }

    // -- Cosine similarity tests ---------------------------------------------

    #[test]
    fn test_cosine_similarity_identical() {
        let v = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-6, "identical vectors should yield 1.0, got {sim}");
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-6, "orthogonal vectors should yield 0.0, got {sim}");
    }

    #[test]
    fn test_cosine_similarity_opposite() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![-1.0, -2.0, -3.0];
        let sim = cosine_similarity(&a, &b);
        assert!((sim + 1.0).abs() < 1e-6, "opposite vectors should yield -1.0, got {sim}");
    }

    // -- Blob roundtrip test -------------------------------------------------

    #[test]
    fn test_embedding_to_blob_roundtrip() {
        let original = vec![1.0_f32, -0.5, 0.0, 3.14, f32::MIN, f32::MAX];
        let blob = embedding_to_blob(&original);
        assert_eq!(blob.len(), original.len() * 4);
        let recovered = blob_to_embedding(&blob);
        assert_eq!(original, recovered);
    }

    // -- Batch chunking test -------------------------------------------------

    #[tokio::test]
    async fn test_batch_chunking() {
        let provider = MockEmbeddingProvider::new(4, 100);
        let texts: Vec<String> = (0..250).map(|i| format!("text {i}")).collect();

        let results = batch_embed(&provider, &texts).await.unwrap();
        assert_eq!(results.len(), 250);
        // 250 / 100 = 3 batches (100 + 100 + 50)
        assert_eq!(provider.calls(), 3);
    }

    // -- OpenAI provider construction tests ----------------------------------

    #[test]
    fn test_openai_provider_rejects_missing_api_key() {
        // Ensure the env var is unset for this test.
        let unique_var = "AEGIS_TEST_MISSING_KEY_12345";
        std::env::remove_var(unique_var);

        let config = EmbeddingConfig {
            api_key_env: unique_var.into(),
            ..Default::default()
        };

        let result = OpenAiEmbeddingProvider::new(&config);
        assert!(result.is_err(), "should fail when API key env var is missing");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains(unique_var),
            "error should mention the env var name: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_openai_provider_rejects_empty_text() {
        // Set a dummy key so construction succeeds.
        let unique_var = "AEGIS_TEST_EMPTY_TEXT_KEY";
        std::env::set_var(unique_var, "sk-test-dummy");

        let config = EmbeddingConfig {
            api_key_env: unique_var.into(),
            ..Default::default()
        };

        let provider = OpenAiEmbeddingProvider::new(&config).unwrap();
        let result = provider.embed(&[String::new()]).await;
        assert!(result.is_err(), "should reject empty text input");

        // Clean up.
        std::env::remove_var(unique_var);
    }

    // -- Security test -------------------------------------------------------

    #[test]
    fn test_api_key_from_env_only() {
        // Verify that EmbeddingConfig only stores the env var NAME, not a key.
        let config = EmbeddingConfig::default();

        // The config should only contain the env var name, not an actual key.
        assert_eq!(config.api_key_env, "OPENAI_API_KEY");

        // Serialize to JSON and verify no field resembles an API key.
        let json = serde_json::to_string(&config).unwrap();
        assert!(
            !json.contains("sk-"),
            "config JSON must not contain an API key: {json}"
        );

        // The struct has no field for storing the actual key value.
        // This is enforced by the struct definition: only `api_key_env` exists,
        // which holds the environment variable name.
        let deserialized: EmbeddingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.api_key_env, "OPENAI_API_KEY");

        // Attempting to construct a provider without the env var fails.
        let unique_var = "AEGIS_TEST_NO_KEY_SECURITY";
        std::env::remove_var(unique_var);
        let cfg = EmbeddingConfig {
            api_key_env: unique_var.into(),
            ..Default::default()
        };
        assert!(
            OpenAiEmbeddingProvider::new(&cfg).is_err(),
            "provider must not be constructible without an env var set"
        );
    }
}
