//! QMD Hybrid Search: BM25 full-text search combined with vector similarity.
//!
//! Enhances the existing semantic search with a hybrid retrieval approach
//! that combines:
//!
//! - **BM25 full-text search**: Keyword-based relevance scoring using the
//!   existing FTS5 index in [`MemoryStore`].
//! - **Vector similarity**: Cosine similarity between embedding vectors.
//! - **Score fusion**: Reciprocal rank fusion (RRF) or weighted linear
//!   combination to merge results from both sources.
//!
//! ## Score Fusion Methods
//!
//! **Reciprocal Rank Fusion (RRF)**: Combines rankings from multiple
//! retrievers by computing `1 / (k + rank)` for each result in each
//! list, then summing. This method is robust to score scale differences.
//!
//! **Weighted Linear Combination**: Directly combines normalized scores
//! with configurable weights: `w_bm25 * bm25_score + w_vector * vector_score`.

use anyhow::{Context, Result};

use crate::memory::MemoryStore;

/// Configuration for hybrid search.
#[derive(Debug, Clone)]
pub struct HybridSearchConfig {
    /// Weight for BM25 (full-text) scores in [0.0, 1.0].
    /// The vector weight is `1.0 - bm25_weight`.
    pub bm25_weight: f64,
    /// RRF constant `k` (higher values dampen the effect of top ranks).
    /// Default: 60.0 (standard value from the RRF paper).
    pub rrf_k: f64,
    /// Score fusion method.
    pub fusion_method: FusionMethod,
    /// Maximum number of results to return.
    pub max_results: usize,
    /// Minimum fused score to include in results.
    pub min_score: f64,
}

impl Default for HybridSearchConfig {
    fn default() -> Self {
        Self {
            bm25_weight: 0.4,
            rrf_k: 60.0,
            fusion_method: FusionMethod::ReciprocalRankFusion,
            max_results: 10,
            min_score: 0.0,
        }
    }
}

/// Method used to fuse BM25 and vector search scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusionMethod {
    /// Reciprocal Rank Fusion: score = sum(1 / (k + rank_i)).
    ReciprocalRankFusion,
    /// Weighted linear combination of normalized scores.
    WeightedLinear,
}

/// A single hybrid search result with fused score.
#[derive(Debug, Clone)]
pub struct HybridSearchResult {
    /// The key of the matched entry.
    pub key: String,
    /// The stored value text.
    pub value: String,
    /// Fused score combining BM25 and vector similarity.
    pub fused_score: f64,
    /// The BM25 component score (if available).
    pub bm25_score: Option<f64>,
    /// The vector similarity component score (if available).
    pub vector_score: Option<f64>,
}

/// Hybrid search engine combining BM25 and vector similarity retrieval.
pub struct HybridSearchEngine<'a> {
    store: &'a MemoryStore,
    config: HybridSearchConfig,
}

impl<'a> HybridSearchEngine<'a> {
    /// Create a new hybrid search engine.
    pub fn new(store: &'a MemoryStore, config: HybridSearchConfig) -> Self {
        Self { store, config }
    }

    /// Perform a hybrid search combining BM25 and vector similarity.
    ///
    /// - `namespace`: the memory namespace to search in.
    /// - `query`: the text query for BM25 search.
    /// - `query_embedding`: optional embedding vector for similarity search.
    ///   If `None`, only BM25 results are used.
    /// - `half_life_hours`: optional temporal decay parameter.
    pub fn search(
        &self,
        namespace: &str,
        query: &str,
        query_embedding: Option<&[f32]>,
        half_life_hours: Option<f64>,
    ) -> Result<Vec<HybridSearchResult>> {
        let fetch_limit = self.config.max_results * 5;

        // 1. BM25 search via FTS5.
        let bm25_results = self
            .store
            .search_safe(namespace, query, fetch_limit, half_life_hours)
            .context("BM25 search")?;

        // 2. Vector similarity search (if embeddings available).
        let vector_results = match query_embedding {
            Some(emb) => self
                .store
                .search_similar_safe(namespace, emb, fetch_limit, half_life_hours)
                .context("vector similarity search")?,
            None => Vec::new(),
        };

        // 3. Fuse results.
        match self.config.fusion_method {
            FusionMethod::ReciprocalRankFusion => self.fuse_rrf(&bm25_results, &vector_results),
            FusionMethod::WeightedLinear => {
                self.fuse_weighted_linear(&bm25_results, &vector_results)
            }
        }
    }

    /// BM25-only search (no vector component).
    pub fn search_bm25_only(
        &self,
        namespace: &str,
        query: &str,
        half_life_hours: Option<f64>,
    ) -> Result<Vec<HybridSearchResult>> {
        self.search(namespace, query, None, half_life_hours)
    }

    /// Fuse results using Reciprocal Rank Fusion.
    fn fuse_rrf(
        &self,
        bm25_results: &[(String, String, f64, String)],
        vector_results: &[(String, String, f32, String)],
    ) -> Result<Vec<HybridSearchResult>> {
        let mut scores: std::collections::HashMap<String, RrfEntry> =
            std::collections::HashMap::new();

        let k = self.config.rrf_k;
        let bm25_w = self.config.bm25_weight;
        let vec_w = 1.0 - bm25_w;

        // Score BM25 results by rank.
        for (rank, (key, value, score, _ts)) in bm25_results.iter().enumerate() {
            let rrf_score = bm25_w / (k + (rank + 1) as f64);
            let entry = scores.entry(key.clone()).or_insert_with(|| RrfEntry {
                key: key.clone(),
                value: value.clone(),
                fused_score: 0.0,
                bm25_score: None,
                vector_score: None,
            });
            entry.fused_score += rrf_score;
            entry.bm25_score = Some(*score);
        }

        // Score vector results by rank.
        for (rank, (key, value, sim, _ts)) in vector_results.iter().enumerate() {
            let rrf_score = vec_w / (k + (rank + 1) as f64);
            let entry = scores.entry(key.clone()).or_insert_with(|| RrfEntry {
                key: key.clone(),
                value: value.clone(),
                fused_score: 0.0,
                bm25_score: None,
                vector_score: None,
            });
            entry.fused_score += rrf_score;
            entry.vector_score = Some(*sim as f64);
        }

        let mut results: Vec<HybridSearchResult> = scores
            .into_values()
            .filter(|e| e.fused_score >= self.config.min_score)
            .map(|e| HybridSearchResult {
                key: e.key,
                value: e.value,
                fused_score: e.fused_score,
                bm25_score: e.bm25_score,
                vector_score: e.vector_score,
            })
            .collect();

        results.sort_by(|a, b| {
            b.fused_score
                .partial_cmp(&a.fused_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(self.config.max_results);

        Ok(results)
    }

    /// Fuse results using weighted linear combination of normalized scores.
    fn fuse_weighted_linear(
        &self,
        bm25_results: &[(String, String, f64, String)],
        vector_results: &[(String, String, f32, String)],
    ) -> Result<Vec<HybridSearchResult>> {
        let mut scores: std::collections::HashMap<String, RrfEntry> =
            std::collections::HashMap::new();

        let bm25_w = self.config.bm25_weight;
        let vec_w = 1.0 - bm25_w;

        // Normalize BM25 scores to [0, 1].
        let bm25_max = bm25_results
            .iter()
            .map(|(_, _, s, _)| *s)
            .fold(0.0_f64, f64::max);

        for (key, value, score, _ts) in bm25_results {
            let normalized = if bm25_max > 0.0 {
                *score / bm25_max
            } else {
                0.0
            };

            let entry = scores.entry(key.clone()).or_insert_with(|| RrfEntry {
                key: key.clone(),
                value: value.clone(),
                fused_score: 0.0,
                bm25_score: None,
                vector_score: None,
            });
            entry.fused_score += bm25_w * normalized;
            entry.bm25_score = Some(*score);
        }

        // Normalize vector scores to [0, 1] (cosine similarity is already in [-1, 1]).
        let vec_max = vector_results
            .iter()
            .map(|(_, _, s, _)| *s)
            .fold(0.0_f32, f32::max);

        for (key, value, sim, _ts) in vector_results {
            let normalized = if vec_max > 0.0 {
                *sim as f64 / vec_max as f64
            } else {
                0.0
            };

            let entry = scores.entry(key.clone()).or_insert_with(|| RrfEntry {
                key: key.clone(),
                value: value.clone(),
                fused_score: 0.0,
                bm25_score: None,
                vector_score: None,
            });
            entry.fused_score += vec_w * normalized;
            entry.vector_score = Some(*sim as f64);
        }

        let mut results: Vec<HybridSearchResult> = scores
            .into_values()
            .filter(|e| e.fused_score >= self.config.min_score)
            .map(|e| HybridSearchResult {
                key: e.key,
                value: e.value,
                fused_score: e.fused_score,
                bm25_score: e.bm25_score,
                vector_score: e.vector_score,
            })
            .collect();

        results.sort_by(|a, b| {
            b.fused_score
                .partial_cmp(&a.fused_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(self.config.max_results);

        Ok(results)
    }
}

/// Internal struct for accumulating fused scores.
struct RrfEntry {
    key: String,
    value: String,
    fused_score: f64,
    bm25_score: Option<f64>,
    vector_score: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_store() -> (MemoryStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = MemoryStore::new(&dir.path().join("memory.db")).unwrap();
        (store, dir)
    }

    fn populate_store(store: &MemoryStore) {
        store
            .set(
                "ns1",
                "rust_intro",
                "Rust is a systems programming language focused on safety",
            )
            .unwrap();
        store
            .set(
                "ns1",
                "python_intro",
                "Python is a dynamic programming language for data science",
            )
            .unwrap();
        store
            .set(
                "ns1",
                "go_intro",
                "Go is a programming language by Google for cloud services",
            )
            .unwrap();
        store
            .set(
                "ns1",
                "cooking",
                "How to make pasta carbonara with bacon and eggs",
            )
            .unwrap();
    }

    #[test]
    fn test_bm25_only_search() {
        let (store, _dir) = test_store();
        populate_store(&store);

        let engine = HybridSearchEngine::new(
            &store,
            HybridSearchConfig {
                max_results: 10,
                min_score: 0.0,
                ..Default::default()
            },
        );

        let results = engine
            .search_bm25_only("ns1", "programming language", None)
            .unwrap();

        assert!(
            !results.is_empty(),
            "should find results for 'programming language'"
        );

        // Programming-related entries should rank higher than cooking.
        let keys: Vec<&str> = results.iter().map(|r| r.key.as_str()).collect();
        assert!(
            !keys.contains(&"cooking"),
            "cooking should not match 'programming language'"
        );
    }

    #[test]
    fn test_hybrid_rrf_search() {
        let (store, _dir) = test_store();
        populate_store(&store);

        // Store with embeddings for vector search.
        let emb_rust = vec![1.0_f32, 0.0, 0.0, 0.0];
        let emb_python = vec![0.8_f32, 0.2, 0.0, 0.0];
        let emb_go = vec![0.7_f32, 0.3, 0.0, 0.0];
        let emb_cooking = vec![0.0_f32, 0.0, 1.0, 0.0];

        store
            .set_with_embedding(
                "ns1",
                "rust_intro",
                "Rust is a systems programming language focused on safety",
                &emb_rust,
            )
            .unwrap();
        store
            .set_with_embedding(
                "ns1",
                "python_intro",
                "Python is a dynamic programming language for data science",
                &emb_python,
            )
            .unwrap();
        store
            .set_with_embedding(
                "ns1",
                "go_intro",
                "Go is a programming language by Google for cloud services",
                &emb_go,
            )
            .unwrap();
        store
            .set_with_embedding(
                "ns1",
                "cooking",
                "How to make pasta carbonara with bacon and eggs",
                &emb_cooking,
            )
            .unwrap();

        let engine = HybridSearchEngine::new(
            &store,
            HybridSearchConfig {
                bm25_weight: 0.4,
                fusion_method: FusionMethod::ReciprocalRankFusion,
                max_results: 10,
                min_score: 0.0,
                ..Default::default()
            },
        );

        // Search with a query embedding close to Rust.
        let query_emb = vec![0.95_f32, 0.05, 0.0, 0.0];
        let results = engine
            .search("ns1", "Rust programming", Some(&query_emb), None)
            .unwrap();

        assert!(!results.is_empty(), "hybrid search should return results");

        // Results should be sorted by fused score descending.
        for window in results.windows(2) {
            assert!(
                window[0].fused_score >= window[1].fused_score,
                "results should be sorted by fused_score descending"
            );
        }
    }

    #[test]
    fn test_hybrid_weighted_linear() {
        let (store, _dir) = test_store();
        populate_store(&store);

        let engine = HybridSearchEngine::new(
            &store,
            HybridSearchConfig {
                bm25_weight: 0.5,
                fusion_method: FusionMethod::WeightedLinear,
                max_results: 10,
                min_score: 0.0,
                ..Default::default()
            },
        );

        let results = engine
            .search_bm25_only("ns1", "programming language", None)
            .unwrap();

        // Should still work with only BM25 in weighted linear mode.
        assert!(!results.is_empty());

        // All results should have non-negative fused scores.
        for r in &results {
            assert!(
                r.fused_score >= 0.0,
                "fused_score should be non-negative, got {}",
                r.fused_score
            );
        }
    }

    #[test]
    fn test_hybrid_respects_max_results() {
        let (store, _dir) = test_store();
        populate_store(&store);

        let engine = HybridSearchEngine::new(
            &store,
            HybridSearchConfig {
                max_results: 2,
                min_score: 0.0,
                ..Default::default()
            },
        );

        let results = engine.search_bm25_only("ns1", "programming", None).unwrap();

        assert!(
            results.len() <= 2,
            "should return at most 2 results, got {}",
            results.len()
        );
    }

    #[test]
    fn test_hybrid_respects_min_score() {
        let (store, _dir) = test_store();
        populate_store(&store);

        let engine = HybridSearchEngine::new(
            &store,
            HybridSearchConfig {
                min_score: 999.0, // impossibly high
                max_results: 10,
                ..Default::default()
            },
        );

        let results = engine.search_bm25_only("ns1", "programming", None).unwrap();

        assert!(results.is_empty(), "no results should pass min_score=999.0");
    }

    #[test]
    fn test_hybrid_empty_namespace() {
        let (store, _dir) = test_store();

        let engine = HybridSearchEngine::new(&store, Default::default());

        let results = engine
            .search_bm25_only("empty_ns", "anything", None)
            .unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_config_defaults() {
        let config = HybridSearchConfig::default();
        assert!((config.bm25_weight - 0.4).abs() < f64::EPSILON);
        assert!((config.rrf_k - 60.0).abs() < f64::EPSILON);
        assert_eq!(config.fusion_method, FusionMethod::ReciprocalRankFusion);
        assert_eq!(config.max_results, 10);
        assert!((config.min_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rrf_results_have_scores() {
        let (store, _dir) = test_store();
        populate_store(&store);

        let engine = HybridSearchEngine::new(
            &store,
            HybridSearchConfig {
                min_score: 0.0,
                max_results: 10,
                ..Default::default()
            },
        );

        let results = engine.search_bm25_only("ns1", "programming", None).unwrap();

        for r in &results {
            assert!(
                r.bm25_score.is_some(),
                "BM25-only search results should have bm25_score"
            );
            assert!(
                r.fused_score > 0.0,
                "fused_score should be positive, got {}",
                r.fused_score
            );
        }
    }

    #[test]
    fn test_weighted_linear_weights_sum_to_one() {
        let config = HybridSearchConfig {
            bm25_weight: 0.3,
            ..Default::default()
        };
        let vec_weight = 1.0 - config.bm25_weight;
        assert!(
            (config.bm25_weight + vec_weight - 1.0).abs() < f64::EPSILON,
            "weights should sum to 1.0"
        );
    }
}
