//! Model pricing tables and cost calculation.
//!
//! Provides a [`PricingTable`] that maps model names (via glob patterns) to
//! per-million-token costs for input, output, cache read, and cache write.
//! The table ships with sensible defaults for current Anthropic and OpenAI
//! models and can be extended or overridden via TOML configuration.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Per-model pricing specification.
///
/// `model_pattern` supports simple glob matching (e.g. `"claude-sonnet-4-5-*"`)
/// so that dated model identifiers like `"claude-sonnet-4-5-20250929"` match
/// without requiring exact strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    /// Glob or exact model name (e.g. `"claude-sonnet-4-5-*"`).
    pub model_pattern: String,
    /// Cost per million input tokens in USD.
    pub input_cost_per_mtok: f64,
    /// Cost per million output tokens in USD.
    pub output_cost_per_mtok: f64,
    /// Cost per million cache-read tokens in USD.
    pub cache_read_cost_per_mtok: f64,
    /// Cost per million cache-write (creation) tokens in USD.
    pub cache_write_cost_per_mtok: f64,
    /// Provider name (e.g. `"anthropic"`, `"openai"`, `"google"`, `"ollama"`).
    #[serde(default)]
    pub provider: String,
}

/// A table of model pricing entries, searched in order.
///
/// The first entry whose `model_pattern` matches the queried model name wins,
/// so more-specific patterns should appear before broader ones.
#[derive(Debug, Clone)]
pub struct PricingTable {
    models: Vec<ModelPricing>,
}

impl PricingTable {
    /// Create an empty pricing table.
    pub fn new() -> Self {
        Self { models: Vec::new() }
    }

    /// Create a pricing table pre-populated with current Anthropic, OpenAI,
    /// Google, and Ollama model pricing.
    pub fn with_defaults() -> Self {
        let models = default_pricing();
        Self { models }
    }

    /// Look up pricing for a model by name (glob-matched against patterns).
    ///
    /// Returns the first matching entry, or `None` if no pattern matches.
    pub fn lookup(&self, model: &str) -> Option<&ModelPricing> {
        self.models.iter().find(|p| {
            glob::Pattern::new(&p.model_pattern)
                .map(|pat| pat.matches(model))
                .unwrap_or_else(|_| p.model_pattern == model)
        })
    }

    /// Calculate the total cost in USD for a single API call.
    ///
    /// Returns `None` if the model is not found in the table.
    pub fn calculate_cost(
        &self,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        cache_read_tokens: u64,
        cache_write_tokens: u64,
    ) -> Option<f64> {
        let pricing = self.lookup(model)?;
        let cost = (input_tokens as f64 * pricing.input_cost_per_mtok
            + output_tokens as f64 * pricing.output_cost_per_mtok
            + cache_read_tokens as f64 * pricing.cache_read_cost_per_mtok
            + cache_write_tokens as f64 * pricing.cache_write_cost_per_mtok)
            / 1_000_000.0;
        Some(cost)
    }

    /// Resolve the provider name for a model by matching against pricing patterns.
    ///
    /// Returns `None` if no pattern matches.
    pub fn provider_for_model(&self, model: &str) -> Option<&str> {
        self.lookup(model).map(|p| p.provider.as_str())
    }

    /// Add or override a model pricing entry.
    ///
    /// If an entry with the same `model_pattern` already exists, it is replaced.
    pub fn add_model(&mut self, pricing: ModelPricing) {
        if let Some(existing) = self
            .models
            .iter_mut()
            .find(|p| p.model_pattern == pricing.model_pattern)
        {
            *existing = pricing;
        } else {
            self.models.push(pricing);
        }
    }
}

impl Default for PricingTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Return the built-in default pricing entries for common LLM providers.
///
/// Includes Anthropic, OpenAI, Google, and Ollama (local/free) models.
/// More-specific patterns (e.g. `gpt-4o-mini*`) appear before broader
/// ones (e.g. `gpt-4o*`) so that the first match wins correctly.
pub fn default_pricing() -> Vec<ModelPricing> {
    vec![
        // -- Anthropic --
        ModelPricing {
            model_pattern: "claude-opus-4*".into(),
            input_cost_per_mtok: 15.0,
            output_cost_per_mtok: 75.0,
            cache_read_cost_per_mtok: 1.875,
            cache_write_cost_per_mtok: 18.75,
            provider: "anthropic".into(),
        },
        ModelPricing {
            model_pattern: "claude-sonnet-4*".into(),
            input_cost_per_mtok: 3.0,
            output_cost_per_mtok: 15.0,
            cache_read_cost_per_mtok: 0.375,
            cache_write_cost_per_mtok: 3.75,
            provider: "anthropic".into(),
        },
        ModelPricing {
            model_pattern: "claude-haiku-4*".into(),
            input_cost_per_mtok: 0.80,
            output_cost_per_mtok: 4.0,
            cache_read_cost_per_mtok: 0.08,
            cache_write_cost_per_mtok: 1.0,
            provider: "anthropic".into(),
        },
        // -- OpenAI (specific patterns before broader ones) --
        ModelPricing {
            model_pattern: "gpt-4o-mini*".into(),
            input_cost_per_mtok: 0.15,
            output_cost_per_mtok: 0.60,
            cache_read_cost_per_mtok: 0.075,
            cache_write_cost_per_mtok: 0.0,
            provider: "openai".into(),
        },
        ModelPricing {
            model_pattern: "gpt-4o*".into(),
            input_cost_per_mtok: 2.50,
            output_cost_per_mtok: 10.0,
            cache_read_cost_per_mtok: 1.25,
            cache_write_cost_per_mtok: 0.0,
            provider: "openai".into(),
        },
        ModelPricing {
            model_pattern: "o1*".into(),
            input_cost_per_mtok: 15.0,
            output_cost_per_mtok: 60.0,
            cache_read_cost_per_mtok: 0.0,
            cache_write_cost_per_mtok: 0.0,
            provider: "openai".into(),
        },
        // -- Google --
        ModelPricing {
            model_pattern: "gemini-2*".into(),
            input_cost_per_mtok: 0.075,
            output_cost_per_mtok: 0.30,
            cache_read_cost_per_mtok: 0.0,
            cache_write_cost_per_mtok: 0.0,
            provider: "google".into(),
        },
        ModelPricing {
            model_pattern: "gemini-1.5-pro*".into(),
            input_cost_per_mtok: 1.25,
            output_cost_per_mtok: 5.0,
            cache_read_cost_per_mtok: 0.0,
            cache_write_cost_per_mtok: 0.0,
            provider: "google".into(),
        },
        // -- MiniMax --
        ModelPricing {
            model_pattern: "MiniMax-M2.5-Lightning*".into(),
            input_cost_per_mtok: 0.30,
            output_cost_per_mtok: 2.40,
            cache_read_cost_per_mtok: 0.0,
            cache_write_cost_per_mtok: 0.0,
            provider: "minimax".into(),
        },
        ModelPricing {
            model_pattern: "MiniMax-M2*".into(),
            input_cost_per_mtok: 0.30,
            output_cost_per_mtok: 1.20,
            cache_read_cost_per_mtok: 0.0,
            cache_write_cost_per_mtok: 0.0,
            provider: "minimax".into(),
        },
        ModelPricing {
            model_pattern: "MiniMax-VL*".into(),
            input_cost_per_mtok: 0.30,
            output_cost_per_mtok: 1.20,
            cache_read_cost_per_mtok: 0.0,
            cache_write_cost_per_mtok: 0.0,
            provider: "minimax".into(),
        },
        // -- Ollama (local, free) --
        ModelPricing {
            model_pattern: "llama*".into(),
            input_cost_per_mtok: 0.0,
            output_cost_per_mtok: 0.0,
            cache_read_cost_per_mtok: 0.0,
            cache_write_cost_per_mtok: 0.0,
            provider: "ollama".into(),
        },
    ]
}

/// Intermediate TOML representation for deserialization.
#[derive(Deserialize)]
struct PricingToml {
    #[serde(default)]
    models: Vec<ModelPricing>,
}

/// Parse a TOML string into a [`PricingTable`].
///
/// Expected format:
/// ```toml
/// [[models]]
/// model_pattern = "claude-sonnet-4-5-*"
/// input_cost_per_mtok = 3.0
/// output_cost_per_mtok = 15.0
/// cache_read_cost_per_mtok = 0.375
/// cache_write_cost_per_mtok = 3.75
/// ```
pub fn parse_pricing_toml(toml_str: &str) -> Result<PricingTable> {
    let parsed: PricingToml = toml::from_str(toml_str).context("failed to parse pricing TOML")?;
    Ok(PricingTable {
        models: parsed.models,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pricing_table_defaults_have_anthropic() {
        let table = PricingTable::with_defaults();
        let pricing = table
            .lookup("claude-sonnet-4-5-20250929")
            .expect("should find claude-sonnet-4-5 pricing");
        assert!(
            (pricing.input_cost_per_mtok - 3.0).abs() < f64::EPSILON,
            "input cost should be $3/Mtok"
        );
    }

    #[test]
    fn test_pricing_table_defaults_have_openai() {
        let table = PricingTable::with_defaults();
        let pricing = table.lookup("gpt-4o").expect("should find gpt-4o pricing");
        assert!(
            (pricing.input_cost_per_mtok - 2.5).abs() < f64::EPSILON,
            "gpt-4o input cost should be $2.50/Mtok"
        );
    }

    #[test]
    fn test_cost_calculation_basic() {
        let table = PricingTable::with_defaults();
        // 1M input tokens of claude-sonnet-4-5 should cost $3
        let cost = table
            .calculate_cost("claude-sonnet-4-5-20250929", 1_000_000, 0, 0, 0)
            .expect("should calculate cost");
        assert!(
            (cost - 3.0).abs() < 1e-9,
            "1M input tokens of sonnet should cost $3, got {cost}"
        );
    }

    #[test]
    fn test_cost_calculation_with_cache() {
        let table = PricingTable::with_defaults();
        // 500k input + 200k output + 100k cache read + 50k cache write
        let cost = table
            .calculate_cost(
                "claude-sonnet-4-5-20250929",
                500_000,
                200_000,
                100_000,
                50_000,
            )
            .expect("should calculate cost");
        // Expected: (500k * 3 + 200k * 15 + 100k * 0.375 + 50k * 3.75) / 1M
        //         = (1_500_000 + 3_000_000 + 37_500 + 187_500) / 1_000_000
        //         = 4_725_000 / 1_000_000 = 4.725
        assert!((cost - 4.725).abs() < 1e-9, "expected $4.725, got {cost}");
    }

    #[test]
    fn test_cost_calculation_unknown_model() {
        let table = PricingTable::with_defaults();
        let cost = table.calculate_cost("unknown-model-xyz", 1_000_000, 0, 0, 0);
        assert!(cost.is_none(), "unknown model should return None");
    }

    #[test]
    fn test_pricing_glob_match() {
        let table = PricingTable::with_defaults();
        // Dated variant should match the glob pattern
        let pricing = table.lookup("claude-sonnet-4-5-20250929");
        assert!(pricing.is_some(), "dated model should match glob pattern");

        // Base pattern should also match (exact match via glob)
        let pricing = table.lookup("claude-opus-4-20250929");
        assert!(pricing.is_some(), "claude-opus-4 variant should match glob");
    }

    #[test]
    fn test_pricing_toml_parse() {
        let toml_str = r#"
[[models]]
model_pattern = "my-custom-model-*"
input_cost_per_mtok = 1.0
output_cost_per_mtok = 2.0
cache_read_cost_per_mtok = 0.5
cache_write_cost_per_mtok = 0.75

[[models]]
model_pattern = "another-model"
input_cost_per_mtok = 0.1
output_cost_per_mtok = 0.2
cache_read_cost_per_mtok = 0.0
cache_write_cost_per_mtok = 0.0
"#;
        let table = parse_pricing_toml(toml_str).expect("should parse TOML");
        let pricing = table
            .lookup("my-custom-model-v2")
            .expect("should find custom model via glob");
        assert!((pricing.input_cost_per_mtok - 1.0).abs() < f64::EPSILON);
        assert!((pricing.output_cost_per_mtok - 2.0).abs() < f64::EPSILON);
        let exact = table
            .lookup("another-model")
            .expect("should find exact match");
        assert!((exact.input_cost_per_mtok - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_add_model_override() {
        let mut table = PricingTable::with_defaults();
        // Override gpt-4o pricing
        table.add_model(ModelPricing {
            model_pattern: "gpt-4o*".into(),
            input_cost_per_mtok: 99.0,
            output_cost_per_mtok: 99.0,
            cache_read_cost_per_mtok: 0.0,
            cache_write_cost_per_mtok: 0.0,
            provider: "openai".into(),
        });
        let pricing = table.lookup("gpt-4o").unwrap();
        assert!(
            (pricing.input_cost_per_mtok - 99.0).abs() < f64::EPSILON,
            "override should replace existing entry"
        );
    }

    #[test]
    fn test_default_pricing_has_all_providers() {
        let pricing = default_pricing();
        let providers: std::collections::HashSet<&str> =
            pricing.iter().map(|p| p.provider.as_str()).collect();
        assert!(providers.contains("anthropic"));
        assert!(providers.contains("openai"));
        assert!(providers.contains("google"));
        assert!(providers.contains("ollama"));
    }

    #[test]
    fn test_provider_for_model() {
        let table = PricingTable::with_defaults();
        assert_eq!(
            table.provider_for_model("claude-opus-4-20250929"),
            Some("anthropic")
        );
        assert_eq!(table.provider_for_model("gpt-4o"), Some("openai"));
        assert_eq!(table.provider_for_model("gemini-2-flash"), Some("google"));
        assert_eq!(table.provider_for_model("llama-3-70b"), Some("ollama"));
        assert_eq!(table.provider_for_model("unknown-model"), None);
    }

    #[test]
    fn test_gpt_4o_mini_matches_before_gpt_4o() {
        let table = PricingTable::with_defaults();
        let mini = table.lookup("gpt-4o-mini").unwrap();
        assert!(
            (mini.input_cost_per_mtok - 0.15).abs() < f64::EPSILON,
            "gpt-4o-mini should match the mini pricing, not gpt-4o"
        );
        let full = table.lookup("gpt-4o").unwrap();
        assert!(
            (full.input_cost_per_mtok - 2.50).abs() < f64::EPSILON,
            "gpt-4o should match the full pricing"
        );
    }

    #[test]
    fn test_o1_model_pricing() {
        let table = PricingTable::with_defaults();
        let pricing = table.lookup("o1-preview").expect("should find o1 pricing");
        assert!((pricing.input_cost_per_mtok - 15.0).abs() < f64::EPSILON);
        assert!((pricing.output_cost_per_mtok - 60.0).abs() < f64::EPSILON);
        assert_eq!(pricing.provider, "openai");
    }

    #[test]
    fn test_ollama_free_pricing() {
        let table = PricingTable::with_defaults();
        let cost = table
            .calculate_cost("llama-3-70b", 1_000_000, 1_000_000, 0, 0)
            .expect("should calculate cost for ollama model");
        assert!(
            cost.abs() < f64::EPSILON,
            "ollama models should be free, got {cost}"
        );
    }

    #[test]
    fn test_gemini_pricing() {
        let table = PricingTable::with_defaults();
        let pricing = table
            .lookup("gemini-2-flash")
            .expect("should find gemini-2 pricing");
        assert!((pricing.input_cost_per_mtok - 0.075).abs() < f64::EPSILON);
        assert_eq!(pricing.provider, "google");
    }
}
