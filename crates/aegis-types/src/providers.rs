//! AI provider registry with model catalogs and detection.
//!
//! Central source of truth for all supported LLM providers, their models,
//! authentication requirements, and availability detection. Used by the
//! onboarding wizard, daemon configuration, and fleet TUI.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// API compatibility mode for a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiType {
    /// Anthropic Messages API format.
    AnthropicMessages,
    /// OpenAI Chat Completions API format.
    OpenaiCompletions,
    /// Google Generative AI format.
    GoogleGenerativeAi,
    /// AWS Bedrock Converse Stream format.
    BedrockConverseStream,
    /// Ollama native API format.
    Ollama,
    /// GitHub Copilot (uses OpenAI responses format internally).
    GithubCopilot,
}

/// How a provider authenticates requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    /// Bearer token via API key.
    ApiKey,
    /// OAuth2 flow.
    OAuth,
    /// AWS SDK credentials (IAM/STS).
    AwsSdk,
    /// GitHub token (PAT or Copilot token).
    GithubToken,
    /// No authentication required (local services).
    None,
}

/// Tier grouping for display in the wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderTier {
    /// Major cloud AI providers.
    Primary,
    /// Model aggregation / routing services.
    Aggregator,
    /// Specialized coding / development providers.
    CodeFocused,
    /// Region-specific providers.
    Regional,
    /// Locally hosted models.
    Local,
    /// User-defined custom endpoint.
    Custom,
}

/// A model offered by a provider.
#[derive(Debug, Clone, Serialize)]
pub struct ModelInfo {
    /// Model identifier used in API calls.
    pub id: &'static str,
    /// Human-readable display name.
    pub display_name: &'static str,
    /// Maximum context window in tokens (0 = unknown).
    pub context_window: u64,
    /// Maximum output tokens (0 = unknown).
    pub max_output_tokens: u64,
    /// Whether this model supports vision/image input.
    pub supports_vision: bool,
    /// Whether this model supports extended thinking / reasoning.
    pub supports_thinking: bool,
}

/// An LLM provider with its configuration and model catalog.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    /// Unique provider identifier (e.g., "anthropic", "openai").
    pub id: &'static str,
    /// Human-readable display name (e.g., "Anthropic (Claude)").
    pub display_name: &'static str,
    /// Provider tier for grouping in the wizard.
    pub tier: ProviderTier,
    /// Primary environment variable for API key.
    pub env_var: &'static str,
    /// Additional environment variables that can provide auth.
    pub alt_env_vars: &'static [&'static str],
    /// Default API base URL.
    pub base_url: &'static str,
    /// API compatibility type.
    pub api_type: ApiType,
    /// Authentication method.
    pub auth_method: AuthMethod,
    /// Default model ID.
    pub default_model: &'static str,
    /// Available models.
    pub models: &'static [ModelInfo],
    /// Whether models are discovered dynamically (Ollama, vLLM, Bedrock).
    pub dynamic_discovery: bool,
    /// TCP address to probe for local service availability (Ollama, vLLM).
    /// Empty string means no probe (use env var detection instead).
    pub probe_addr: &'static str,
}

/// Detection result for a provider.
#[derive(Debug, Clone)]
pub struct DetectedProvider {
    /// Reference to the provider info.
    pub info: &'static ProviderInfo,
    /// Whether the provider is available (key set, service running, etc.).
    pub available: bool,
    /// Status label for display: "[API Key Set]", "[Running]", "[--]".
    pub status_label: String,
    /// Dynamically discovered models (for Ollama, vLLM, etc.).
    pub discovered_models: Vec<String>,
}

// ---------------------------------------------------------------------------
// Provider registry
// ---------------------------------------------------------------------------

/// Scan all providers and return detection results.
pub fn scan_providers() -> Vec<DetectedProvider> {
    ALL_PROVIDERS
        .iter()
        .map(detect_provider)
        .collect()
}

/// Detect availability of a single provider.
pub fn detect_provider(info: &'static ProviderInfo) -> DetectedProvider {
    // Check environment variable
    let key_set = has_env_var(info.env_var)
        || info.alt_env_vars.iter().any(|v| has_env_var(v));

    // Check TCP probe for local services
    let probe_ok = if !info.probe_addr.is_empty() {
        probe_tcp(info.probe_addr)
    } else {
        false
    };

    let available = key_set || probe_ok;

    let status_label = if key_set {
        "[API Key Set]".to_string()
    } else if probe_ok {
        "[Running]".to_string()
    } else {
        "[--]".to_string()
    };

    DetectedProvider {
        info,
        available,
        status_label,
        discovered_models: Vec::new(),
    }
}

/// Look up a provider by its ID.
pub fn provider_by_id(id: &str) -> Option<&'static ProviderInfo> {
    ALL_PROVIDERS.iter().find(|p| p.id == id)
}

/// Get all providers in a given tier.
pub fn providers_by_tier(tier: ProviderTier) -> Vec<&'static ProviderInfo> {
    ALL_PROVIDERS.iter().filter(|p| p.tier == tier).collect()
}

fn has_env_var(name: &str) -> bool {
    std::env::var(name).map(|v| !v.is_empty()).unwrap_or(false)
}

fn probe_tcp(addr: &str) -> bool {
    addr.parse::<SocketAddr>()
        .ok()
        .and_then(|a| TcpStream::connect_timeout(&a, Duration::from_millis(300)).ok())
        .is_some()
}

// ---------------------------------------------------------------------------
// Static provider catalog
// ---------------------------------------------------------------------------

/// All supported providers.
pub static ALL_PROVIDERS: &[ProviderInfo] = &[
    // ── Primary ──────────────────────────────────────────────────────
    ProviderInfo {
        id: "anthropic",
        display_name: "Anthropic (Claude)",
        tier: ProviderTier::Primary,
        env_var: "ANTHROPIC_API_KEY",
        alt_env_vars: &["ANTHROPIC_OAUTH_TOKEN"],
        base_url: "https://api.anthropic.com",
        api_type: ApiType::AnthropicMessages,
        auth_method: AuthMethod::ApiKey,
        default_model: "claude-opus-4-6",
        models: &[
            ModelInfo {
                id: "claude-opus-4-6",
                display_name: "Claude Opus 4.6",
                context_window: 1_000_000,
                max_output_tokens: 128_000,
                supports_vision: true,
                supports_thinking: true,
            },
            ModelInfo {
                id: "claude-sonnet-4-5",
                display_name: "Claude Sonnet 4.5",
                context_window: 200_000,
                max_output_tokens: 64_000,
                supports_vision: true,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "openai",
        display_name: "OpenAI",
        tier: ProviderTier::Primary,
        env_var: "OPENAI_API_KEY",
        alt_env_vars: &[],
        base_url: "https://api.openai.com",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "gpt-5.3-codex",
        models: &[
            ModelInfo {
                id: "gpt-5.3-codex",
                display_name: "GPT-5.3 Codex",
                context_window: 400_000,
                max_output_tokens: 128_000,
                supports_vision: true,
                supports_thinking: false,
            },
            ModelInfo {
                id: "gpt-5.3-codex-spark",
                display_name: "GPT-5.3 Codex Spark",
                context_window: 400_000,
                max_output_tokens: 128_000,
                supports_vision: true,
                supports_thinking: false,
            },
            ModelInfo {
                id: "gpt-5.2",
                display_name: "GPT-5.2",
                context_window: 400_000,
                max_output_tokens: 128_000,
                supports_vision: true,
                supports_thinking: false,
            },
            ModelInfo {
                id: "gpt-5.1",
                display_name: "GPT-5.1",
                context_window: 400_000,
                max_output_tokens: 128_000,
                supports_vision: true,
                supports_thinking: false,
            },
            ModelInfo {
                id: "gpt-4.1",
                display_name: "GPT-4.1",
                context_window: 1_047_576,
                max_output_tokens: 32_768,
                supports_vision: true,
                supports_thinking: false,
            },
            ModelInfo {
                id: "gpt-4.1-mini",
                display_name: "GPT-4.1 Mini",
                context_window: 1_047_576,
                max_output_tokens: 32_768,
                supports_vision: true,
                supports_thinking: false,
            },
            ModelInfo {
                id: "gpt-4.1-nano",
                display_name: "GPT-4.1 Nano",
                context_window: 1_047_576,
                max_output_tokens: 32_768,
                supports_vision: true,
                supports_thinking: false,
            },
            ModelInfo {
                id: "o3-mini",
                display_name: "o3 Mini",
                context_window: 200_000,
                max_output_tokens: 100_000,
                supports_vision: false,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "google",
        display_name: "Google (Gemini)",
        tier: ProviderTier::Primary,
        env_var: "GOOGLE_API_KEY",
        alt_env_vars: &["GEMINI_API_KEY"],
        base_url: "https://generativelanguage.googleapis.com",
        api_type: ApiType::GoogleGenerativeAi,
        auth_method: AuthMethod::ApiKey,
        default_model: "gemini-3-pro",
        models: &[
            ModelInfo {
                id: "gemini-3-pro",
                display_name: "Gemini 3 Pro",
                context_window: 1_000_000,
                max_output_tokens: 65_536,
                supports_vision: true,
                supports_thinking: true,
            },
            ModelInfo {
                id: "gemini-3-flash",
                display_name: "Gemini 3 Flash",
                context_window: 1_000_000,
                max_output_tokens: 65_536,
                supports_vision: true,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "xai",
        display_name: "xAI (Grok)",
        tier: ProviderTier::Primary,
        env_var: "XAI_API_KEY",
        alt_env_vars: &[],
        base_url: "https://api.x.ai",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "grok-4",
        models: &[
            ModelInfo {
                id: "grok-4",
                display_name: "Grok 4",
                context_window: 256_000,
                max_output_tokens: 32_768,
                supports_vision: true,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    // ── Aggregators ──────────────────────────────────────────────────
    ProviderInfo {
        id: "openrouter",
        display_name: "OpenRouter",
        tier: ProviderTier::Aggregator,
        env_var: "OPENROUTER_API_KEY",
        alt_env_vars: &[],
        base_url: "https://openrouter.ai/api/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "auto",
        models: &[
            ModelInfo {
                id: "auto",
                display_name: "OpenRouter Auto",
                context_window: 0,
                max_output_tokens: 0,
                supports_vision: true,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "together",
        display_name: "Together AI",
        tier: ProviderTier::Aggregator,
        env_var: "TOGETHER_API_KEY",
        alt_env_vars: &[],
        base_url: "https://api.together.xyz/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "deepseek-ai/DeepSeek-V3.1",
        models: &[
            ModelInfo {
                id: "zai-org/GLM-4.7",
                display_name: "GLM 4.7",
                context_window: 204_800,
                max_output_tokens: 131_000,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "moonshotai/Kimi-K2.5",
                display_name: "Kimi K2.5",
                context_window: 256_000,
                max_output_tokens: 65_536,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
                display_name: "Llama 3.3 70B Turbo",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "meta-llama/Llama-4-Scout-17B-16E-Instruct",
                display_name: "Llama 4 Scout 17B",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
                display_name: "Llama 4 Maverick 17B",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "deepseek-ai/DeepSeek-V3.1",
                display_name: "DeepSeek V3.1",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "deepseek-ai/DeepSeek-R1",
                display_name: "DeepSeek R1",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "moonshotai/Kimi-K2-Instruct-0905",
                display_name: "Kimi K2 Instruct",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "huggingface",
        display_name: "HuggingFace Inference",
        tier: ProviderTier::Aggregator,
        env_var: "HUGGINGFACE_HUB_TOKEN",
        alt_env_vars: &["HF_TOKEN"],
        base_url: "https://router.huggingface.co/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "deepseek-ai/DeepSeek-V3.1",
        models: &[
            ModelInfo {
                id: "deepseek-ai/DeepSeek-R1",
                display_name: "DeepSeek R1",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "deepseek-ai/DeepSeek-V3.1",
                display_name: "DeepSeek V3.1",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
                display_name: "Llama 3.3 70B Turbo",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "openai/gpt-oss-120b",
                display_name: "GPT OSS 120B",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: true,
        probe_addr: "",
    },
    ProviderInfo {
        id: "venice",
        display_name: "Venice AI",
        tier: ProviderTier::Aggregator,
        env_var: "VENICE_API_KEY",
        alt_env_vars: &[],
        base_url: "https://api.venice.ai/api/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "llama-3.3-70b",
        models: &[
            ModelInfo {
                id: "llama-3.3-70b",
                display_name: "Llama 3.3 70B",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "deepseek-v3.2",
                display_name: "DeepSeek V3.2",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "qwen3-235b-a22b-thinking-2507",
                display_name: "Qwen3 235B Thinking",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "qwen3-235b-a22b-instruct-2507",
                display_name: "Qwen3 235B Instruct",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "qwen3-coder-480b-a35b-instruct",
                display_name: "Qwen3 Coder 480B",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "vercel-ai-gateway",
        display_name: "Vercel AI Gateway",
        tier: ProviderTier::Aggregator,
        env_var: "VERCEL_AI_GATEWAY_API_KEY",
        alt_env_vars: &["AI_GATEWAY_API_KEY"],
        base_url: "https://gateway.vercel.ai/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "claude-sonnet-4-5",
        models: &[
            ModelInfo {
                id: "claude-sonnet-4-5",
                display_name: "Claude Sonnet 4.5 (via Vercel)",
                context_window: 200_000,
                max_output_tokens: 64_000,
                supports_vision: true,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "cloudflare-ai-gateway",
        display_name: "Cloudflare AI Gateway",
        tier: ProviderTier::Aggregator,
        env_var: "CLOUDFLARE_AI_GATEWAY_API_KEY",
        alt_env_vars: &[],
        base_url: "https://gateway.ai.cloudflare.com",
        api_type: ApiType::AnthropicMessages,
        auth_method: AuthMethod::ApiKey,
        default_model: "claude-sonnet-4-5",
        models: &[
            ModelInfo {
                id: "claude-sonnet-4-5",
                display_name: "Claude Sonnet 4.5 (via Cloudflare)",
                context_window: 200_000,
                max_output_tokens: 64_000,
                supports_vision: true,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "bedrock",
        display_name: "Amazon Bedrock",
        tier: ProviderTier::Aggregator,
        env_var: "AWS_BEARER_TOKEN_BEDROCK",
        alt_env_vars: &["AWS_ACCESS_KEY_ID", "AWS_PROFILE"],
        base_url: "https://bedrock-runtime.us-east-1.amazonaws.com",
        api_type: ApiType::BedrockConverseStream,
        auth_method: AuthMethod::AwsSdk,
        default_model: "anthropic.claude-opus-4-6-v1:0",
        models: &[
            ModelInfo {
                id: "anthropic.claude-opus-4-6-v1:0",
                display_name: "Claude Opus 4.6 (Bedrock)",
                context_window: 1_000_000,
                max_output_tokens: 128_000,
                supports_vision: true,
                supports_thinking: true,
            },
            ModelInfo {
                id: "anthropic.claude-sonnet-4-5-v1:0",
                display_name: "Claude Sonnet 4.5 (Bedrock)",
                context_window: 200_000,
                max_output_tokens: 64_000,
                supports_vision: true,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: true,
        probe_addr: "",
    },
    ProviderInfo {
        id: "litellm",
        display_name: "LiteLLM",
        tier: ProviderTier::Aggregator,
        env_var: "LITELLM_API_KEY",
        alt_env_vars: &[],
        base_url: "http://localhost:4000",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "gpt-4o",
        models: &[
            ModelInfo {
                id: "gpt-4o",
                display_name: "GPT-4o (via LiteLLM)",
                context_window: 128_000,
                max_output_tokens: 16_384,
                supports_vision: true,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: true,
        probe_addr: "127.0.0.1:4000",
    },
    // ── Code-focused ─────────────────────────────────────────────────
    ProviderInfo {
        id: "github-copilot",
        display_name: "GitHub Copilot",
        tier: ProviderTier::CodeFocused,
        env_var: "COPILOT_GITHUB_TOKEN",
        alt_env_vars: &["GH_TOKEN", "GITHUB_TOKEN"],
        base_url: "https://api.github.com/copilot",
        api_type: ApiType::GithubCopilot,
        auth_method: AuthMethod::GithubToken,
        default_model: "claude-sonnet-4.6",
        models: &[
            ModelInfo {
                id: "claude-sonnet-4.6",
                display_name: "Claude Sonnet 4.6 (Copilot)",
                context_window: 200_000,
                max_output_tokens: 64_000,
                supports_vision: true,
                supports_thinking: true,
            },
            ModelInfo {
                id: "claude-sonnet-4.5",
                display_name: "Claude Sonnet 4.5 (Copilot)",
                context_window: 200_000,
                max_output_tokens: 64_000,
                supports_vision: true,
                supports_thinking: true,
            },
            ModelInfo {
                id: "gpt-4o",
                display_name: "GPT-4o (Copilot)",
                context_window: 128_000,
                max_output_tokens: 16_384,
                supports_vision: true,
                supports_thinking: false,
            },
            ModelInfo {
                id: "gpt-4.1",
                display_name: "GPT-4.1 (Copilot)",
                context_window: 1_047_576,
                max_output_tokens: 32_768,
                supports_vision: true,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "opencode-zen",
        display_name: "OpenCode Zen",
        tier: ProviderTier::CodeFocused,
        env_var: "OPENCODE_API_KEY",
        alt_env_vars: &["OPENCODE_ZEN_API_KEY"],
        base_url: "https://opencode.ai/zen/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "claude-opus-4-6",
        models: &[
            ModelInfo {
                id: "claude-opus-4-6",
                display_name: "Claude Opus 4.6 (Zen)",
                context_window: 1_000_000,
                max_output_tokens: 128_000,
                supports_vision: true,
                supports_thinking: true,
            },
            ModelInfo {
                id: "gpt-5.1-codex",
                display_name: "GPT-5.1 Codex (Zen)",
                context_window: 400_000,
                max_output_tokens: 128_000,
                supports_vision: true,
                supports_thinking: false,
            },
            ModelInfo {
                id: "gemini-3-pro",
                display_name: "Gemini 3 Pro (Zen)",
                context_window: 1_000_000,
                max_output_tokens: 65_536,
                supports_vision: true,
                supports_thinking: true,
            },
            ModelInfo {
                id: "glm-4.7",
                display_name: "GLM 4.7 (Zen)",
                context_window: 204_800,
                max_output_tokens: 131_000,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "synthetic",
        display_name: "Synthetic",
        tier: ProviderTier::CodeFocused,
        env_var: "SYNTHETIC_API_KEY",
        alt_env_vars: &[],
        base_url: "https://api.synthetic.new/anthropic",
        api_type: ApiType::AnthropicMessages,
        auth_method: AuthMethod::ApiKey,
        default_model: "hf:MiniMaxAI/MiniMax-M2.1",
        models: &[
            ModelInfo {
                id: "hf:MiniMaxAI/MiniMax-M2.1",
                display_name: "MiniMax M2.1 (Synthetic)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "hf:moonshotai/Kimi-K2-Thinking",
                display_name: "Kimi K2 Thinking (Synthetic)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "hf:zai-org/GLM-4.7",
                display_name: "GLM 4.7 (Synthetic)",
                context_window: 204_800,
                max_output_tokens: 131_000,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "hf:zai-org/GLM-5",
                display_name: "GLM 5 (Synthetic)",
                context_window: 204_800,
                max_output_tokens: 131_000,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "hf:deepseek-ai/DeepSeek-V3.2",
                display_name: "DeepSeek V3.2 (Synthetic)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "hf:deepseek-ai/DeepSeek-R1-0528",
                display_name: "DeepSeek R1 (Synthetic)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "hf:Qwen/Qwen3-235B-A22B-Instruct-2507",
                display_name: "Qwen3 235B Instruct (Synthetic)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "hf:Qwen/Qwen3-Coder-480B-A35B-Instruct",
                display_name: "Qwen3 Coder 480B (Synthetic)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "hf:meta-llama/Llama-3.3-70B-Instruct",
                display_name: "Llama 3.3 70B (Synthetic)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    // ── Regional ─────────────────────────────────────────────────────
    ProviderInfo {
        id: "minimax",
        display_name: "MiniMax",
        tier: ProviderTier::Regional,
        env_var: "MINIMAX_API_KEY",
        alt_env_vars: &["MINIMAX_OAUTH_TOKEN"],
        base_url: "https://api.minimax.io/anthropic",
        api_type: ApiType::AnthropicMessages,
        auth_method: AuthMethod::ApiKey,
        default_model: "MiniMax-M2.5",
        models: &[
            ModelInfo {
                id: "MiniMax-M2.5",
                display_name: "MiniMax M2.5",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "MiniMax-M2.5-Lightning",
                display_name: "MiniMax M2.5 Lightning",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "MiniMax-M2.1",
                display_name: "MiniMax M2.1",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "MiniMax-VL-01",
                display_name: "MiniMax VL 01",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: true,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "moonshot",
        display_name: "Moonshot (Kimi)",
        tier: ProviderTier::Regional,
        env_var: "MOONSHOT_API_KEY",
        alt_env_vars: &[],
        base_url: "https://api.moonshot.ai/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "kimi-k2.5",
        models: &[
            ModelInfo {
                id: "kimi-k2.5",
                display_name: "Kimi K2.5",
                context_window: 256_000,
                max_output_tokens: 65_536,
                supports_vision: false,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "kimi-coding",
        display_name: "Kimi Coding",
        tier: ProviderTier::Regional,
        env_var: "KIMI_API_KEY",
        alt_env_vars: &["KIMICODE_API_KEY"],
        base_url: "https://api.kimi.com/coding/",
        api_type: ApiType::AnthropicMessages,
        auth_method: AuthMethod::ApiKey,
        default_model: "k2p5",
        models: &[
            ModelInfo {
                id: "k2p5",
                display_name: "Kimi K2.5 for Coding",
                context_window: 262_000,
                max_output_tokens: 65_536,
                supports_vision: true,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "qwen",
        display_name: "Qwen Portal (Alibaba)",
        tier: ProviderTier::Regional,
        env_var: "QWEN_PORTAL_API_KEY",
        alt_env_vars: &["QWEN_OAUTH_TOKEN"],
        base_url: "https://portal.qwen.ai/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "coder-model",
        models: &[
            ModelInfo {
                id: "coder-model",
                display_name: "Qwen Coder",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "vision-model",
                display_name: "Qwen Vision",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: true,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "zhipu",
        display_name: "Z.AI (GLM)",
        tier: ProviderTier::Regional,
        env_var: "ZHIPU_API_KEY",
        alt_env_vars: &[],
        base_url: "https://open.bigmodel.cn/api/paas/v4",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "glm-4.7",
        models: &[
            ModelInfo {
                id: "glm-4.7",
                display_name: "GLM 4.7",
                context_window: 204_800,
                max_output_tokens: 131_000,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "glm-5",
                display_name: "GLM 5",
                context_window: 204_800,
                max_output_tokens: 131_000,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "volcano",
        display_name: "Volcano Engine (Doubao)",
        tier: ProviderTier::Regional,
        env_var: "VOLCANO_ENGINE_API_KEY",
        alt_env_vars: &[],
        base_url: "https://ark.cn-beijing.volces.com/api/v3",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "doubao-seed-1-8-251228",
        models: &[
            ModelInfo {
                id: "doubao-seed-1-8-251228",
                display_name: "Doubao Seed 1.8",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "doubao-seed-code-preview-251028",
                display_name: "Doubao Seed Code",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "glm-4-7-251222",
                display_name: "GLM 4.7 (Volcano)",
                context_window: 204_800,
                max_output_tokens: 131_000,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "kimi-k2-5-260127",
                display_name: "Kimi K2.5 (Volcano)",
                context_window: 256_000,
                max_output_tokens: 65_536,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "deepseek-v3-2-251201",
                display_name: "DeepSeek V3.2 (Volcano)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "byteplus",
        display_name: "BytePlus",
        tier: ProviderTier::Regional,
        env_var: "BYTEPLUS_API_KEY",
        alt_env_vars: &[],
        base_url: "https://ark.ap-southeast.bytepluses.com/api/v3",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "seed-1-8-251228",
        models: &[
            ModelInfo {
                id: "seed-1-8-251228",
                display_name: "Seed 1.8 (BytePlus)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "kimi-k2-5-260127",
                display_name: "Kimi K2.5 (BytePlus)",
                context_window: 256_000,
                max_output_tokens: 65_536,
                supports_vision: false,
                supports_thinking: true,
            },
            ModelInfo {
                id: "glm-4-7-251222",
                display_name: "GLM 4.7 (BytePlus)",
                context_window: 204_800,
                max_output_tokens: 131_000,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "xiaomi",
        display_name: "Xiaomi MiMo",
        tier: ProviderTier::Regional,
        env_var: "XIAOMI_API_KEY",
        alt_env_vars: &[],
        base_url: "https://api.xiaomimimo.com/anthropic",
        api_type: ApiType::AnthropicMessages,
        auth_method: AuthMethod::ApiKey,
        default_model: "mimo-v2-flash",
        models: &[
            ModelInfo {
                id: "mimo-v2-flash",
                display_name: "MiMo V2 Flash",
                context_window: 262_000,
                max_output_tokens: 65_536,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "qianfan",
        display_name: "Baidu QianFan",
        tier: ProviderTier::Regional,
        env_var: "QIANFAN_API_KEY",
        alt_env_vars: &[],
        base_url: "https://qianfan.baidubce.com/v2",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "deepseek-v3.2",
        models: &[
            ModelInfo {
                id: "deepseek-v3.2",
                display_name: "DeepSeek V3.2 (QianFan)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "ernie-5.0-thinking-preview",
                display_name: "ERNIE 5.0 Thinking",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: true,
                supports_thinking: true,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    ProviderInfo {
        id: "nvidia",
        display_name: "NVIDIA NIM",
        tier: ProviderTier::Regional,
        env_var: "NVIDIA_API_KEY",
        alt_env_vars: &[],
        base_url: "https://integrate.api.nvidia.com/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::ApiKey,
        default_model: "nvidia/llama-3.1-nemotron-70b-instruct",
        models: &[
            ModelInfo {
                id: "nvidia/llama-3.1-nemotron-70b-instruct",
                display_name: "Llama 3.1 Nemotron 70B",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
            ModelInfo {
                id: "meta/llama-3.3-70b-instruct",
                display_name: "Llama 3.3 70B (NVIDIA)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: false,
        probe_addr: "",
    },
    // ── Local ────────────────────────────────────────────────────────
    ProviderInfo {
        id: "ollama",
        display_name: "Ollama (Local)",
        tier: ProviderTier::Local,
        env_var: "OLLAMA_API_KEY",
        alt_env_vars: &[],
        base_url: "http://127.0.0.1:11434",
        api_type: ApiType::Ollama,
        auth_method: AuthMethod::None,
        default_model: "llama3.2",
        models: &[
            ModelInfo {
                id: "llama3.2",
                display_name: "Llama 3.2 (placeholder -- use dynamic discovery)",
                context_window: 131_072,
                max_output_tokens: 32_768,
                supports_vision: false,
                supports_thinking: false,
            },
        ],
        dynamic_discovery: true,
        probe_addr: "127.0.0.1:11434",
    },
    ProviderInfo {
        id: "vllm",
        display_name: "vLLM (Local)",
        tier: ProviderTier::Local,
        env_var: "VLLM_API_KEY",
        alt_env_vars: &[],
        base_url: "http://127.0.0.1:8000/v1",
        api_type: ApiType::OpenaiCompletions,
        auth_method: AuthMethod::None,
        default_model: "",
        models: &[],
        dynamic_discovery: true,
        probe_addr: "127.0.0.1:8000",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_providers_have_unique_ids() {
        let mut ids: Vec<&str> = ALL_PROVIDERS.iter().map(|p| p.id).collect();
        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate provider IDs found");
    }

    #[test]
    fn primary_providers_have_models() {
        for p in ALL_PROVIDERS.iter().filter(|p| p.tier == ProviderTier::Primary) {
            assert!(
                !p.models.is_empty(),
                "primary provider {} has no models",
                p.id
            );
            assert!(
                !p.default_model.is_empty(),
                "primary provider {} has no default model",
                p.id
            );
        }
    }

    #[test]
    fn default_model_exists_in_catalog() {
        for p in ALL_PROVIDERS {
            if p.default_model.is_empty() || p.dynamic_discovery {
                continue;
            }
            assert!(
                p.models.iter().any(|m| m.id == p.default_model),
                "provider {} default model '{}' not in its model list",
                p.id,
                p.default_model
            );
        }
    }

    #[test]
    fn provider_lookup_works() {
        assert!(provider_by_id("anthropic").is_some());
        assert!(provider_by_id("nonexistent").is_none());
    }

    #[test]
    fn tier_filtering_works() {
        let primaries = providers_by_tier(ProviderTier::Primary);
        assert_eq!(primaries.len(), 4);
        for p in &primaries {
            assert_eq!(p.tier, ProviderTier::Primary);
        }
    }

    #[test]
    fn provider_count() {
        // Ensure we have all 25+ providers.
        assert!(
            ALL_PROVIDERS.len() >= 25,
            "expected 25+ providers, got {}",
            ALL_PROVIDERS.len()
        );
    }
}
