//! Semantic search engine combining embedding generation with vector retrieval.
//!
//! Wraps [`MemoryStore`] and an [`EmbeddingProvider`] to provide a high-level
//! API for storing text with auto-generated embeddings and querying by semantic
//! similarity.
//!
//! All text is sanitized before embedding to strip potential secrets (API keys,
//! tokens, credentials) so they never leak into embedding vectors.

use std::sync::Arc;

use anyhow::{Context, Result};
use regex::Regex;

use crate::embeddings::{batch_embed, EmbeddingProvider};
use crate::memory::MemoryStore;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the semantic search engine.
#[derive(Debug, Clone)]
pub struct SemanticSearchConfig {
    /// Minimum cosine similarity threshold. Results below this are discarded.
    pub min_similarity: f32,
    /// Maximum number of results to return from a search.
    pub max_results: usize,
    /// Whether to automatically generate and store embeddings on `store()`.
    pub embed_on_store: bool,
    /// Namespace isolation. All operations are scoped to this namespace.
    pub namespace: String,
}

impl Default for SemanticSearchConfig {
    fn default() -> Self {
        Self {
            min_similarity: 0.5,
            max_results: 10,
            embed_on_store: true,
            namespace: "default".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Search result
// ---------------------------------------------------------------------------

/// A single search result with similarity score.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The key of the matched entry.
    pub key: String,
    /// The stored value text.
    pub value: String,
    /// Cosine similarity between the query and this entry's embedding.
    pub similarity: f32,
}

// ---------------------------------------------------------------------------
// Secret stripping
// ---------------------------------------------------------------------------

/// Strip content that looks like secrets from text before embedding.
///
/// Matches common credential patterns and replaces them with a placeholder.
/// This prevents secrets from leaking into embedding vectors.
fn strip_secrets(text: &str) -> String {
    // Patterns for common secret formats:
    // - OpenAI keys: sk-... (20+ alphanumeric chars)
    // - GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_ followed by 36+ chars
    // - AWS access key IDs: AKIA followed by 16 uppercase alphanumeric chars
    // - Generic long hex/base64 tokens: 40+ contiguous alphanumeric chars that
    //   look like tokens (heuristic: no spaces, mostly not dictionary words)
    // - Bearer tokens in headers
    // - Basic auth credentials
    let patterns = [
        // OpenAI-style keys
        r"sk-[A-Za-z0-9_-]{20,}",
        // GitHub tokens
        r"gh[pousr]_[A-Za-z0-9_]{36,}",
        // AWS access key IDs
        r"AKIA[A-Z0-9]{16}",
        // AWS secret access keys (40 char base64-ish)
        r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"]?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}"#,
        // Generic long tokens (50+ alphanumeric without spaces, likely a key)
        r"\b[A-Za-z0-9_\-]{50,}\b",
        // Bearer token values
        r"(?i)bearer\s+[A-Za-z0-9_\-.~+/]+=*",
        // Basic auth in URLs
        r"://[^@\s]+:[^@\s]+@",
    ];

    let mut result = text.to_string();
    for pat in &patterns {
        let re = Regex::new(pat).expect("secret pattern regex should compile");
        result = re.replace_all(&result, "[REDACTED]").to_string();
    }
    result
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// High-level semantic search engine combining embedding generation with
/// vector retrieval from a [`MemoryStore`].
pub struct SemanticSearchEngine {
    memory: MemoryStore,
    provider: Arc<dyn EmbeddingProvider>,
    config: SemanticSearchConfig,
}

impl SemanticSearchEngine {
    /// Create a new semantic search engine.
    pub fn new(
        memory: MemoryStore,
        provider: Arc<dyn EmbeddingProvider>,
        config: SemanticSearchConfig,
    ) -> Self {
        Self {
            memory,
            provider,
            config,
        }
    }

    /// Store a key-value pair, optionally generating and storing its embedding.
    ///
    /// If `embed_on_store` is enabled in the config, the value text is
    /// sanitized (secrets stripped) and embedded before storage.
    pub async fn store(&self, key: &str, value: &str) -> Result<()> {
        let ns = &self.config.namespace;

        if self.config.embed_on_store {
            let sanitized = strip_secrets(value);
            let embeddings = self
                .provider
                .embed(&[sanitized])
                .await
                .context("generate embedding for store")?;
            let embedding = embeddings
                .into_iter()
                .next()
                .context("embedding provider returned empty result")?;
            self.memory
                .set_with_embedding(ns, key, value, &embedding)
                .context("store value with embedding")?;
        } else {
            self.memory
                .set(ns, key, value)
                .context("store value without embedding")?;
        }

        Ok(())
    }

    /// Search for entries semantically similar to the query text.
    ///
    /// The query is sanitized, embedded, and compared against stored embeddings.
    /// Results are filtered by `min_similarity` and limited to `max_results`,
    /// returned in descending order of similarity.
    pub async fn search(&self, query: &str) -> Result<Vec<SearchResult>> {
        let sanitized = strip_secrets(query);
        let embeddings = self
            .provider
            .embed(&[sanitized])
            .await
            .context("generate embedding for search query")?;
        let query_embedding = embeddings
            .into_iter()
            .next()
            .context("embedding provider returned empty result for query")?;

        // Fetch more than max_results since we filter by min_similarity after.
        // Use a generous limit to avoid missing results.
        let raw_limit = self.config.max_results * 10;
        let results = self
            .memory
            .search_similar(&self.config.namespace, &query_embedding, raw_limit, None)
            .context("search similar embeddings")?;

        let filtered: Vec<SearchResult> = results
            .into_iter()
            .filter(|(_, _, sim)| *sim >= self.config.min_similarity)
            .take(self.config.max_results)
            .map(|(key, value, similarity)| SearchResult {
                key,
                value,
                similarity,
            })
            .collect();

        Ok(filtered)
    }

    /// Store multiple key-value pairs, batch-embedding their values.
    ///
    /// Values are sanitized before embedding. The batch is processed
    /// through the embedding provider in provider-sized chunks.
    pub async fn store_batch(&self, entries: &[(String, String)]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let ns = &self.config.namespace;

        if self.config.embed_on_store {
            let sanitized: Vec<String> = entries
                .iter()
                .map(|(_, value)| strip_secrets(value))
                .collect();

            let embeddings = batch_embed(self.provider.as_ref(), &sanitized)
                .await
                .context("batch embed values")?;

            for ((key, value), embedding) in entries.iter().zip(embeddings.iter()) {
                self.memory
                    .set_with_embedding(ns, key, value, embedding)
                    .context("store batch entry with embedding")?;
            }
        } else {
            for (key, value) in entries {
                self.memory
                    .set(ns, key, value)
                    .context("store batch entry without embedding")?;
            }
        }

        Ok(())
    }

    /// Delete an entry from the memory store.
    pub fn delete(&self, key: &str) -> Result<()> {
        self.memory
            .delete(&self.config.namespace, key)
            .context("delete from memory store")?;
        Ok(())
    }

    /// List all keys in the configured namespace.
    pub fn list_keys(&self) -> Result<Vec<String>> {
        // Use a generous limit; the memory store list returns (key, value) pairs.
        let entries = self
            .memory
            .list(&self.config.namespace, usize::MAX)
            .context("list memory store keys")?;
        Ok(entries.into_iter().map(|(key, _)| key).collect())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use tempfile::TempDir;

    // -- Mock embedding provider ---------------------------------------------

    /// Deterministic mock embedding provider for testing.
    ///
    /// Generates embeddings by hashing the input text to produce stable,
    /// reproducible vectors. Optionally records all inputs for inspection.
    struct MockEmbeddingProvider {
        dim: usize,
        recorded_inputs: Mutex<Vec<String>>,
    }

    impl MockEmbeddingProvider {
        fn new(dim: usize) -> Self {
            Self {
                dim,
                recorded_inputs: Mutex::new(Vec::new()),
            }
        }

        /// Return all texts that were passed to `embed()`, in order.
        fn recorded_inputs(&self) -> Vec<String> {
            self.recorded_inputs.lock().unwrap().clone()
        }

        /// Simple hash-based vector generation for deterministic results.
        /// Different texts produce different vectors; similar prefixes share
        /// some components.
        fn hash_to_vector(&self, text: &str) -> Vec<f32> {
            let mut vec = vec![0.0_f32; self.dim];
            // Use a simple hash spread across dimensions.
            for (i, byte) in text.bytes().enumerate() {
                let idx = i % self.dim;
                // Accumulate byte values, scaled down to keep magnitudes reasonable.
                vec[idx] += (byte as f32) / 256.0;
            }
            // Normalize to unit vector so cosine similarity is meaningful.
            let magnitude: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
            if magnitude > 0.0 {
                for v in &mut vec {
                    *v /= magnitude;
                }
            }
            vec
        }
    }

    #[async_trait]
    impl EmbeddingProvider for MockEmbeddingProvider {
        async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
            {
                let mut inputs = self.recorded_inputs.lock().unwrap();
                for t in texts {
                    inputs.push(t.clone());
                }
            }
            Ok(texts.iter().map(|t| self.hash_to_vector(t)).collect())
        }

        fn max_batch_size(&self) -> usize {
            100
        }

        fn provider_name(&self) -> &str {
            "mock"
        }

        fn dimension(&self) -> usize {
            self.dim
        }
    }

    // -- Helpers --------------------------------------------------------------

    fn test_engine(config: SemanticSearchConfig) -> (SemanticSearchEngine, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = MemoryStore::new(&dir.path().join("memory.db")).unwrap();
        let provider = Arc::new(MockEmbeddingProvider::new(32));
        let engine = SemanticSearchEngine::new(store, provider, config);
        (engine, dir)
    }

    fn test_engine_with_provider(
        config: SemanticSearchConfig,
        provider: Arc<MockEmbeddingProvider>,
    ) -> (SemanticSearchEngine, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = MemoryStore::new(&dir.path().join("memory.db")).unwrap();
        let engine = SemanticSearchEngine::new(store, provider, config);
        (engine, dir)
    }

    // -- Tests ----------------------------------------------------------------

    #[test]
    fn test_search_config_defaults() {
        let config = SemanticSearchConfig::default();
        assert!(
            (config.min_similarity - 0.5).abs() < f32::EPSILON,
            "default min_similarity should be 0.5"
        );
        assert_eq!(config.max_results, 10, "default max_results should be 10");
        assert!(config.embed_on_store, "default embed_on_store should be true");
        assert_eq!(
            config.namespace, "default",
            "default namespace should be 'default'"
        );
    }

    #[tokio::test]
    async fn test_store_and_search() {
        let (engine, _dir) = test_engine(SemanticSearchConfig {
            min_similarity: 0.0,
            ..Default::default()
        });

        engine.store("doc1", "rust programming language").await.unwrap();
        engine.store("doc2", "python programming language").await.unwrap();
        engine.store("doc3", "cooking recipes for dinner").await.unwrap();

        // Search for something close to the first two entries.
        let results = engine.search("rust programming").await.unwrap();
        assert!(!results.is_empty(), "should return at least one result");

        // The top result should be "doc1" since the query matches its content most.
        assert_eq!(results[0].key, "doc1");
        assert!(
            results[0].similarity > 0.0,
            "similarity should be positive for a match"
        );
    }

    #[tokio::test]
    async fn test_search_respects_min_similarity() {
        let (engine, _dir) = test_engine(SemanticSearchConfig {
            min_similarity: 0.99,
            ..Default::default()
        });

        engine.store("doc1", "the quick brown fox").await.unwrap();
        engine.store("doc2", "jumps over the lazy dog").await.unwrap();

        // A vague query unlikely to have 0.99+ similarity with either.
        let results = engine.search("unrelated quantum physics topic").await.unwrap();
        assert!(
            results.is_empty(),
            "no results should pass min_similarity=0.99 for unrelated query, got {} results",
            results.len()
        );
    }

    #[tokio::test]
    async fn test_search_respects_max_results() {
        let (engine, _dir) = test_engine(SemanticSearchConfig {
            min_similarity: 0.0,
            max_results: 3,
            ..Default::default()
        });

        for i in 0..10 {
            engine
                .store(&format!("item{i}"), &format!("document number {i} about testing"))
                .await
                .unwrap();
        }

        let results = engine.search("document about testing").await.unwrap();
        assert!(
            results.len() <= 3,
            "should return at most 3 results, got {}",
            results.len()
        );
    }

    #[tokio::test]
    async fn test_search_results_sorted_by_similarity() {
        let (engine, _dir) = test_engine(SemanticSearchConfig {
            min_similarity: 0.0,
            max_results: 100,
            ..Default::default()
        });

        engine.store("a", "alpha beta gamma delta").await.unwrap();
        engine.store("b", "epsilon zeta eta theta").await.unwrap();
        engine.store("c", "iota kappa lambda mu").await.unwrap();
        engine.store("d", "nu xi omicron pi").await.unwrap();

        let results = engine.search("alpha beta gamma").await.unwrap();
        assert!(
            results.len() >= 2,
            "should have at least 2 results for sorting check"
        );

        for window in results.windows(2) {
            assert!(
                window[0].similarity >= window[1].similarity,
                "results should be sorted descending by similarity: {} >= {} failed",
                window[0].similarity,
                window[1].similarity
            );
        }
    }

    #[tokio::test]
    async fn test_store_batch() {
        let (engine, _dir) = test_engine(SemanticSearchConfig {
            min_similarity: 0.0,
            ..Default::default()
        });

        let entries: Vec<(String, String)> = (0..5)
            .map(|i| (format!("batch{i}"), format!("batch item number {i} content")))
            .collect();

        engine.store_batch(&entries).await.unwrap();

        // Verify all items are searchable.
        for (key, _) in &entries {
            let keys = engine.list_keys().unwrap();
            assert!(
                keys.contains(key),
                "batch-stored key '{key}' should be listed"
            );
        }

        // Search should find batch items.
        let results = engine.search("batch item content").await.unwrap();
        assert!(!results.is_empty(), "should find batch-stored items via search");
    }

    #[tokio::test]
    async fn test_delete_removes_from_search() {
        let (engine, _dir) = test_engine(SemanticSearchConfig {
            min_similarity: 0.0,
            ..Default::default()
        });

        engine.store("target", "unique searchable text xyz").await.unwrap();

        // Confirm it's findable.
        let results = engine.search("unique searchable text xyz").await.unwrap();
        assert!(!results.is_empty(), "should find the stored item before delete");

        // Delete and re-search.
        engine.delete("target").unwrap();
        let results = engine.search("unique searchable text xyz").await.unwrap();
        assert!(
            results.is_empty(),
            "should not find deleted item, got {} results",
            results.len()
        );
    }

    #[tokio::test]
    async fn test_list_keys() {
        let (engine, _dir) = test_engine(Default::default());

        engine.store("alpha", "first value").await.unwrap();
        engine.store("beta", "second value").await.unwrap();
        engine.store("gamma", "third value").await.unwrap();

        let mut keys = engine.list_keys().unwrap();
        keys.sort();

        assert_eq!(keys, vec!["alpha", "beta", "gamma"]);
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("memory.db");

        // Engine in namespace "ns1".
        let store1 = MemoryStore::new(&db_path).unwrap();
        let provider: Arc<MockEmbeddingProvider> = Arc::new(MockEmbeddingProvider::new(32));
        let engine1 = SemanticSearchEngine::new(
            store1,
            provider.clone(),
            SemanticSearchConfig {
                namespace: "ns1".into(),
                min_similarity: 0.0,
                ..Default::default()
            },
        );

        // Engine in namespace "ns2", sharing the same database.
        let store2 = MemoryStore::new(&db_path).unwrap();
        let engine2 = SemanticSearchEngine::new(
            store2,
            provider,
            SemanticSearchConfig {
                namespace: "ns2".into(),
                min_similarity: 0.0,
                ..Default::default()
            },
        );

        engine1.store("shared_key", "namespace one value").await.unwrap();
        engine2.store("shared_key", "namespace two value").await.unwrap();

        // ns1 should only see its own entries.
        let keys1 = engine1.list_keys().unwrap();
        assert_eq!(keys1.len(), 1);

        let results1 = engine1.search("namespace one value").await.unwrap();
        assert!(!results1.is_empty(), "ns1 should find its own entry");
        assert_eq!(results1[0].value, "namespace one value");

        // ns2 should only see its own entries.
        let keys2 = engine2.list_keys().unwrap();
        assert_eq!(keys2.len(), 1);

        let results2 = engine2.search("namespace two value").await.unwrap();
        assert!(!results2.is_empty(), "ns2 should find its own entry");
        assert_eq!(results2[0].value, "namespace two value");

        // Cross-namespace search should not leak.
        let cross = engine1.search("namespace two value").await.unwrap();
        // The result, if any, should be from ns1, not ns2.
        for r in &cross {
            assert_eq!(
                r.value, "namespace one value",
                "ns1 search should never return ns2 values"
            );
        }
    }

    #[tokio::test]
    async fn test_secret_stripping_before_embed() {
        let provider = Arc::new(MockEmbeddingProvider::new(32));
        let (engine, _dir) = test_engine_with_provider(
            SemanticSearchConfig {
                min_similarity: 0.0,
                ..Default::default()
            },
            provider.clone(),
        );

        // Store text containing various secret patterns.
        let text_with_secrets = concat!(
            "Configure the API with key sk-abc123xyz456789012345 ",
            "and GitHub token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn ",
            "and AWS key AKIAIOSFODNN7EXAMPLE ",
            "using bearer token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        );

        engine.store("secrets_doc", text_with_secrets).await.unwrap();

        // Check what the provider actually received for embedding.
        let inputs = provider.recorded_inputs();
        assert!(!inputs.is_empty(), "provider should have received input");

        let embedded_text = &inputs[0];

        // The sk- key should be stripped.
        assert!(
            !embedded_text.contains("sk-abc123xyz456789012345"),
            "OpenAI-style key should be stripped from embedded text, got: {embedded_text}"
        );

        // The GitHub token should be stripped.
        assert!(
            !embedded_text.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            "GitHub token should be stripped from embedded text, got: {embedded_text}"
        );

        // The AWS key should be stripped.
        assert!(
            !embedded_text.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS access key should be stripped from embedded text, got: {embedded_text}"
        );

        // The bearer token should be stripped.
        assert!(
            !embedded_text.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            "Bearer token should be stripped from embedded text, got: {embedded_text}"
        );

        // The non-secret context words should still be present.
        assert!(
            embedded_text.contains("Configure"),
            "non-secret text should be preserved, got: {embedded_text}"
        );

        // Also verify search queries get sanitized.
        let _ = engine
            .search("find sk-secretkey12345678901234 info")
            .await
            .unwrap();
        let all_inputs = provider.recorded_inputs();
        let search_input = &all_inputs[all_inputs.len() - 1];
        assert!(
            !search_input.contains("sk-secretkey12345678901234"),
            "search query secrets should also be stripped, got: {search_input}"
        );
    }

    // -- Unit tests for strip_secrets -----------------------------------------

    #[test]
    fn test_strip_secrets_openai_key() {
        let input = "Use key sk-proj-abc123def456ghi789";
        let output = strip_secrets(input);
        assert!(!output.contains("sk-proj-abc123def456ghi789"));
        assert!(output.contains("Use key"));
    }

    #[test]
    fn test_strip_secrets_github_token() {
        let input = "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";
        let output = strip_secrets(input);
        assert!(!output.contains("ghp_ABCDEF"));
    }

    #[test]
    fn test_strip_secrets_aws_key() {
        let input = "access key AKIAIOSFODNN7EXAMPLE";
        let output = strip_secrets(input);
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_strip_secrets_preserves_normal_text() {
        let input = "This is normal text with no secrets at all.";
        let output = strip_secrets(input);
        assert_eq!(input, output);
    }

    #[test]
    fn test_strip_secrets_basic_auth_url() {
        let input = "Connect to https://user:password@example.com/api";
        let output = strip_secrets(input);
        assert!(!output.contains("user:password@"));
    }
}
