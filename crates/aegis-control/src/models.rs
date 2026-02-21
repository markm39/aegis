//! Model catalog, metadata, and allowlisting.
//!
//! Provides:
//! - [`ModelInfo`]: metadata about a model (context window, capabilities, etc.)
//! - [`ModelCatalog`]: a registry of known models with TTL-based refresh tracking
//! - [`ModelAllowlist`]: glob-pattern-based allowlisting that fails closed (empty = deny all)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metadata about a single model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelInfo {
    /// Provider name (e.g. "anthropic", "openai").
    pub provider: String,
    /// Canonical model identifier (e.g. "claude-sonnet-4-5").
    pub model_id: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Maximum context window size in tokens.
    pub context_window: u32,
    /// Maximum output tokens per response.
    pub max_output_tokens: u32,
    /// Whether the model supports vision/image inputs.
    pub supports_vision: bool,
    /// Whether the model supports tool use.
    pub supports_tools: bool,
    /// Whether the model supports streaming responses.
    pub supports_streaming: bool,
    /// Whether the model supports extended thinking.
    pub supports_extended_thinking: bool,
}

/// A registry of known models with TTL-based refresh tracking.
///
/// Use [`ModelCatalog::with_defaults()`] to get a catalog pre-populated with
/// known Anthropic and OpenAI models. The catalog supports prefix-based lookup
/// so that dated model identifiers (e.g. `"claude-sonnet-4-5-20250929"`) resolve
/// to their base model entry.
pub struct ModelCatalog {
    models: Vec<ModelInfo>,
    last_refreshed: Option<DateTime<Utc>>,
    /// TTL in seconds before the catalog should be refreshed. Default: 21600 (6 hours).
    ttl_secs: u64,
}

impl ModelCatalog {
    /// Create an empty catalog.
    pub fn new() -> Self {
        Self {
            models: Vec::new(),
            last_refreshed: None,
            ttl_secs: 21600,
        }
    }

    /// Create a catalog pre-populated with known Anthropic and OpenAI models.
    pub fn with_defaults() -> Self {
        let models = vec![
            ModelInfo {
                provider: "anthropic".into(),
                model_id: "claude-opus-4".into(),
                display_name: "Claude Opus 4".into(),
                context_window: 200_000,
                max_output_tokens: 32_000,
                supports_vision: true,
                supports_tools: true,
                supports_streaming: true,
                supports_extended_thinking: true,
            },
            ModelInfo {
                provider: "anthropic".into(),
                model_id: "claude-sonnet-4-5".into(),
                display_name: "Claude Sonnet 4.5".into(),
                context_window: 200_000,
                max_output_tokens: 64_000,
                supports_vision: true,
                supports_tools: true,
                supports_streaming: true,
                supports_extended_thinking: true,
            },
            ModelInfo {
                provider: "anthropic".into(),
                model_id: "claude-haiku-4-5".into(),
                display_name: "Claude Haiku 4.5".into(),
                context_window: 200_000,
                max_output_tokens: 8_000,
                supports_vision: true,
                supports_tools: true,
                supports_streaming: true,
                supports_extended_thinking: false,
            },
            ModelInfo {
                provider: "openai".into(),
                model_id: "gpt-4o".into(),
                display_name: "GPT-4o".into(),
                context_window: 128_000,
                max_output_tokens: 16_000,
                supports_vision: true,
                supports_tools: true,
                supports_streaming: true,
                supports_extended_thinking: false,
            },
            ModelInfo {
                provider: "openai".into(),
                model_id: "gpt-4o-mini".into(),
                display_name: "GPT-4o Mini".into(),
                context_window: 128_000,
                max_output_tokens: 16_000,
                supports_vision: true,
                supports_tools: true,
                supports_streaming: true,
                supports_extended_thinking: false,
            },
        ];

        Self {
            models,
            last_refreshed: None,
            ttl_secs: 21600,
        }
    }

    /// Look up a model by exact or prefix match.
    ///
    /// First tries an exact match on `model_id`. If none is found, checks
    /// whether the queried id starts with any catalog entry's `model_id`
    /// (prefix matching for versioned models like `"claude-sonnet-4-5-20250929"`).
    pub fn lookup(&self, model_id: &str) -> Option<&ModelInfo> {
        // Exact match first.
        if let Some(info) = self.models.iter().find(|m| m.model_id == model_id) {
            return Some(info);
        }

        // Prefix match: the queried id starts with a catalog entry's model_id
        // followed by a separator character (hyphen or end-of-string).
        // We pick the longest matching prefix to avoid ambiguity.
        self.models
            .iter()
            .filter(|m| {
                model_id.starts_with(&m.model_id)
                    && model_id
                        .as_bytes()
                        .get(m.model_id.len())
                        .is_none_or(|&b| b == b'-')
            })
            .max_by_key(|m| m.model_id.len())
    }

    /// Return all models in the catalog.
    pub fn list(&self) -> &[ModelInfo] {
        &self.models
    }

    /// Add or update a model in the catalog.
    ///
    /// If an entry with the same `model_id` already exists, it is replaced.
    pub fn add(&mut self, model: ModelInfo) {
        if let Some(existing) = self.models.iter_mut().find(|m| m.model_id == model.model_id) {
            *existing = model;
        } else {
            self.models.push(model);
        }
    }

    /// Returns `true` if the catalog has never been refreshed or if the TTL
    /// has expired.
    pub fn needs_refresh(&self) -> bool {
        match self.last_refreshed {
            None => true,
            Some(last) => {
                let elapsed = Utc::now().signed_duration_since(last);
                elapsed.num_seconds() as u64 >= self.ttl_secs
            }
        }
    }

    /// Mark the catalog as freshly refreshed (sets `last_refreshed` to now).
    pub fn mark_refreshed(&mut self) {
        self.last_refreshed = Some(Utc::now());
    }
}

impl Default for ModelCatalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Glob-pattern-based model allowlist.
///
/// **Security property: fail-closed.** An empty pattern list rejects every
/// model. Use [`ModelAllowlist::allow_all()`] to explicitly permit everything.
pub struct ModelAllowlist {
    patterns: Vec<String>,
}

impl ModelAllowlist {
    /// Create an allowlist from a set of glob patterns.
    ///
    /// Patterns use standard glob syntax: `"claude-*"` matches any model whose
    /// name starts with `"claude-"`. An empty list rejects all models
    /// (fail-closed).
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    /// Create an allowlist that permits any model.
    pub fn allow_all() -> Self {
        Self {
            patterns: vec!["*".into()],
        }
    }

    /// Check whether a model id is permitted by this allowlist.
    ///
    /// Returns `true` if the model matches at least one pattern.
    /// Returns `false` if no patterns match (including when the list is empty).
    pub fn is_allowed(&self, model_id: &str) -> bool {
        self.patterns.iter().any(|p| {
            glob::Pattern::new(p)
                .map(|pat| pat.matches(model_id))
                .unwrap_or_else(|_| p == model_id)
        })
    }

    /// Filter a slice of models, returning only those permitted by this
    /// allowlist.
    pub fn filter(&self, models: &[ModelInfo]) -> Vec<ModelInfo> {
        models
            .iter()
            .filter(|m| self.is_allowed(&m.model_id))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_catalog_defaults() {
        let catalog = ModelCatalog::with_defaults();
        let models = catalog.list();

        let has_sonnet = models.iter().any(|m| m.model_id == "claude-sonnet-4-5");
        assert!(has_sonnet, "defaults should include claude-sonnet-4-5");

        let has_gpt4o = models.iter().any(|m| m.model_id == "gpt-4o");
        assert!(has_gpt4o, "defaults should include gpt-4o");
    }

    #[test]
    fn test_model_catalog_lookup() {
        let catalog = ModelCatalog::with_defaults();
        let info = catalog
            .lookup("claude-sonnet-4-5")
            .expect("should find claude-sonnet-4-5 by exact id");
        assert_eq!(info.provider, "anthropic");
        assert_eq!(info.context_window, 200_000);
        assert_eq!(info.max_output_tokens, 64_000);
    }

    #[test]
    fn test_model_catalog_lookup_prefix() {
        let catalog = ModelCatalog::with_defaults();
        let info = catalog
            .lookup("claude-sonnet-4-5-20250929")
            .expect("dated variant should match via prefix");
        assert_eq!(info.model_id, "claude-sonnet-4-5");
        assert!(info.supports_extended_thinking);
    }

    #[test]
    fn test_model_catalog_add_and_lookup() {
        let mut catalog = ModelCatalog::new();
        catalog.add(ModelInfo {
            provider: "custom".into(),
            model_id: "my-model-v1".into(),
            display_name: "My Model v1".into(),
            context_window: 32_000,
            max_output_tokens: 4_000,
            supports_vision: false,
            supports_tools: true,
            supports_streaming: true,
            supports_extended_thinking: false,
        });

        let info = catalog
            .lookup("my-model-v1")
            .expect("should find custom model after add");
        assert_eq!(info.provider, "custom");
        assert_eq!(info.context_window, 32_000);
    }

    #[test]
    fn test_model_catalog_needs_refresh() {
        let mut catalog = ModelCatalog::new();

        // A fresh catalog with no last_refreshed should need refresh.
        assert!(
            catalog.needs_refresh(),
            "new catalog should need refresh"
        );

        // After marking refreshed, should no longer need refresh (ttl=6h).
        catalog.mark_refreshed();
        assert!(
            !catalog.needs_refresh(),
            "just-refreshed catalog should not need refresh"
        );
    }

    #[test]
    fn test_model_allowlist_pattern_match() {
        let allowlist = ModelAllowlist::new(vec!["claude-*".into()]);
        assert!(
            allowlist.is_allowed("claude-sonnet-4-5"),
            "'claude-*' should allow 'claude-sonnet-4-5'"
        );
    }

    #[test]
    fn test_model_allowlist_rejects_unmatched() {
        let allowlist = ModelAllowlist::new(vec!["claude-*".into()]);
        assert!(
            !allowlist.is_allowed("gpt-4o"),
            "'claude-*' should reject 'gpt-4o'"
        );
    }

    #[test]
    fn test_model_allowlist_allow_all() {
        let allowlist = ModelAllowlist::allow_all();
        assert!(allowlist.is_allowed("claude-sonnet-4-5"));
        assert!(allowlist.is_allowed("gpt-4o"));
        assert!(allowlist.is_allowed("some-unknown-model"));
    }

    #[test]
    fn test_model_allowlist_filter() {
        let catalog = ModelCatalog::with_defaults();
        let allowlist = ModelAllowlist::new(vec!["claude-*".into()]);
        let filtered = allowlist.filter(catalog.list());

        assert!(
            filtered.iter().all(|m| m.provider == "anthropic"),
            "filtered list should only contain Anthropic models"
        );
        assert!(
            !filtered.is_empty(),
            "filtered list should not be empty"
        );
        assert!(
            filtered.iter().all(|m| m.model_id.starts_with("claude-")),
            "all filtered models should start with 'claude-'"
        );
    }

    #[test]
    fn test_model_info_serialization() {
        let info = ModelInfo {
            provider: "anthropic".into(),
            model_id: "claude-sonnet-4-5".into(),
            display_name: "Claude Sonnet 4.5".into(),
            context_window: 200_000,
            max_output_tokens: 64_000,
            supports_vision: true,
            supports_tools: true,
            supports_streaming: true,
            supports_extended_thinking: true,
        };

        let json = serde_json::to_string(&info).expect("should serialize");
        let back: ModelInfo = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(info, back);
    }

    #[test]
    fn test_model_allowlist_multiple_patterns() {
        let allowlist = ModelAllowlist::new(vec!["claude-*".into(), "gpt-4o*".into()]);
        assert!(
            allowlist.is_allowed("claude-opus-4"),
            "should allow claude family"
        );
        assert!(
            allowlist.is_allowed("gpt-4o"),
            "should allow gpt-4o"
        );
        assert!(
            allowlist.is_allowed("gpt-4o-mini"),
            "should allow gpt-4o-mini"
        );
        assert!(
            !allowlist.is_allowed("llama-3"),
            "should reject llama-3"
        );
    }

    /// SECURITY: An empty allowlist must reject everything (fail-closed).
    #[test]
    fn test_model_allowlist_empty_rejects_all() {
        let allowlist = ModelAllowlist::new(vec![]);
        assert!(
            !allowlist.is_allowed("claude-sonnet-4-5"),
            "empty allowlist must reject claude-sonnet-4-5 (fail-closed)"
        );
        assert!(
            !allowlist.is_allowed("gpt-4o"),
            "empty allowlist must reject gpt-4o (fail-closed)"
        );
        assert!(
            !allowlist.is_allowed(""),
            "empty allowlist must reject empty string (fail-closed)"
        );
    }
}
