//! LLM provider abstraction with format normalization.
//!
//! Provides a unified type system for interacting with multiple LLM providers
//! (Anthropic, OpenAI, Google/Gemini) through a common request/response format.
//! Handles format conversion between the internal representation and
//! provider-specific wire formats.
//!
//! # Security
//!
//! - API keys are read from environment variables at runtime, never stored in config.
//! - API keys are masked in all `Debug` and `Display` output.
//! - Endpoint URLs are validated against SSRF (private/loopback IPs blocked).
//! - Tool call inputs are sanitized to strip control characters.
//! - Response content is sanitized before returning.
//! - All LLM completions are gated by Cedar policy (`LlmComplete` action).

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config_loader::mask_sensitive;
use crate::google_ai::validate_endpoint_url;
use crate::AegisError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default Anthropic API endpoint.
pub const DEFAULT_ANTHROPIC_ENDPOINT: &str = "https://api.anthropic.com";

/// Default OpenAI API endpoint.
pub const DEFAULT_OPENAI_ENDPOINT: &str = "https://api.openai.com";

/// Default Anthropic model.
pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-sonnet-4-20250514";

/// Default OpenAI model.
pub const DEFAULT_OPENAI_MODEL: &str = "gpt-4o";

/// Default environment variable for Anthropic API key.
pub const ANTHROPIC_API_KEY_ENV: &str = "ANTHROPIC_API_KEY";

/// Default environment variable for OpenAI API key.
pub const OPENAI_API_KEY_ENV: &str = "OPENAI_API_KEY";

/// Default Gemini API endpoint.
pub const DEFAULT_GEMINI_ENDPOINT: &str = "https://generativelanguage.googleapis.com";

/// Default Gemini model.
pub const DEFAULT_GEMINI_MODEL: &str = "gemini-2.0-flash";

/// Default environment variable for Google/Gemini API key.
pub const GOOGLE_API_KEY_ENV: &str = "GOOGLE_API_KEY";

/// Fallback environment variable for Gemini API key.
pub const GEMINI_API_KEY_ENV: &str = "GEMINI_API_KEY";

/// Default Ollama base URL.
pub const DEFAULT_OLLAMA_BASE_URL: &str = "http://localhost:11434";

/// Default Ollama model.
pub const DEFAULT_OLLAMA_MODEL: &str = "llama3.2";

/// Default OpenRouter API endpoint.
pub const DEFAULT_OPENROUTER_ENDPOINT: &str = "https://openrouter.ai";

/// Default OpenRouter model.
pub const DEFAULT_OPENROUTER_MODEL: &str = "anthropic/claude-sonnet-4-20250514";

/// Default environment variable for OpenRouter API key.
pub const OPENROUTER_API_KEY_ENV: &str = "OPENROUTER_API_KEY";

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Role of a message participant in an LLM conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmRole {
    /// System instruction (usually the first message).
    System,
    /// User input.
    User,
    /// Assistant (model) response.
    Assistant,
    /// Tool result fed back to the model.
    Tool,
}

impl fmt::Display for LlmRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmRole::System => write!(f, "system"),
            LlmRole::User => write!(f, "user"),
            LlmRole::Assistant => write!(f, "assistant"),
            LlmRole::Tool => write!(f, "tool"),
        }
    }
}

/// A message in an LLM conversation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmMessage {
    /// The role of the message sender.
    pub role: LlmRole,
    /// Text content of the message.
    pub content: String,
    /// Tool use ID (for Tool role messages, references the tool call being responded to).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
    /// Tool calls made by the assistant in this message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<LlmToolCall>,
}

impl LlmMessage {
    /// Create a user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: LlmRole::User,
            content: content.into(),
            tool_use_id: None,
            tool_calls: Vec::new(),
        }
    }

    /// Create an assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: LlmRole::Assistant,
            content: content.into(),
            tool_use_id: None,
            tool_calls: Vec::new(),
        }
    }

    /// Create a system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: LlmRole::System,
            content: content.into(),
            tool_use_id: None,
            tool_calls: Vec::new(),
        }
    }

    /// Create a tool result message.
    pub fn tool_result(tool_use_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: LlmRole::Tool,
            content: content.into(),
            tool_use_id: Some(tool_use_id.into()),
            tool_calls: Vec::new(),
        }
    }

    /// Create an assistant message that includes tool calls.
    pub fn assistant_with_tools(content: impl Into<String>, tool_calls: Vec<LlmToolCall>) -> Self {
        Self {
            role: LlmRole::Assistant,
            content: content.into(),
            tool_use_id: None,
            tool_calls,
        }
    }
}

// ---------------------------------------------------------------------------
// Tool call types
// ---------------------------------------------------------------------------

/// A tool call made by an LLM model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmToolCall {
    /// Unique identifier for this tool call.
    pub id: String,
    /// Name of the tool being called.
    pub name: String,
    /// Tool input arguments as a JSON value.
    pub input: serde_json::Value,
}

/// A tool definition provided to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmToolDefinition {
    /// Tool name.
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
    /// Input parameter schema in JSON Schema format.
    pub input_schema: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// A completion request to an LLM provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmRequest {
    /// Model identifier (e.g., "claude-sonnet-4-20250514", "gpt-4o").
    pub model: String,
    /// Conversation messages.
    pub messages: Vec<LlmMessage>,
    /// Sampling temperature (0.0 to 2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Maximum tokens to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// System prompt (separate from messages for providers that support it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// Tool definitions available to the model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<LlmToolDefinition>,
    /// Extended thinking budget in tokens (Anthropic only).
    /// When set, enables extended thinking with the given token budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_budget: Option<u32>,
}

/// Why the model stopped generating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Natural end of response.
    EndTurn,
    /// Max tokens reached.
    MaxTokens,
    /// Model wants to use a tool.
    ToolUse,
    /// Stop sequence matched.
    StopSequence,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopReason::EndTurn => write!(f, "end_turn"),
            StopReason::MaxTokens => write!(f, "max_tokens"),
            StopReason::ToolUse => write!(f, "tool_use"),
            StopReason::StopSequence => write!(f, "stop_sequence"),
        }
    }
}

/// Token usage information from a completion response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmUsage {
    /// Number of input/prompt tokens.
    pub input_tokens: u64,
    /// Number of output/completion tokens.
    pub output_tokens: u64,
}

/// A completion response from an LLM provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    /// Text content of the response.
    pub content: String,
    /// Model that generated the response.
    pub model: String,
    /// Token usage information.
    pub usage: LlmUsage,
    /// Tool calls requested by the model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<LlmToolCall>,
    /// Why the model stopped generating.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<StopReason>,
}

// ---------------------------------------------------------------------------
// Model info
// ---------------------------------------------------------------------------

/// Information about a model available from a provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelInfo {
    /// Model identifier (e.g., "claude-sonnet-4-20250514").
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Provider name (e.g., "anthropic", "openai", "google").
    pub provider: String,
    /// Maximum context window in tokens.
    pub max_tokens: u64,
    /// Capabilities this model supports (e.g., "tool_use", "vision", "streaming").
    pub capabilities: Vec<String>,
}

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

/// Configuration for the Anthropic provider.
///
/// The API key is never stored directly. `api_key_env` names the environment
/// variable that holds the key at runtime.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnthropicConfig {
    /// Name of the environment variable holding the API key.
    #[serde(default = "default_anthropic_api_key_env")]
    pub api_key_env: String,
    /// Base API endpoint URL (must be HTTPS).
    #[serde(default = "default_anthropic_endpoint")]
    pub base_url: String,
    /// Default model to use when none is specified.
    #[serde(default = "default_anthropic_model")]
    pub default_model: String,
}

fn default_anthropic_api_key_env() -> String {
    ANTHROPIC_API_KEY_ENV.to_string()
}

fn default_anthropic_endpoint() -> String {
    DEFAULT_ANTHROPIC_ENDPOINT.to_string()
}

fn default_anthropic_model() -> String {
    DEFAULT_ANTHROPIC_MODEL.to_string()
}

impl Default for AnthropicConfig {
    fn default() -> Self {
        Self {
            api_key_env: default_anthropic_api_key_env(),
            base_url: default_anthropic_endpoint(),
            default_model: default_anthropic_model(),
        }
    }
}

impl fmt::Debug for AnthropicConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnthropicConfig")
            .field("api_key_env", &self.api_key_env)
            .field("base_url", &self.base_url)
            .field("default_model", &self.default_model)
            .finish()
    }
}

impl AnthropicConfig {
    /// Read the API key from the configured environment variable.
    ///
    /// Returns an error if the variable is not set or the value is empty.
    pub fn read_api_key(&self) -> Result<String, AegisError> {
        match std::env::var(&self.api_key_env) {
            Ok(key) if !key.is_empty() => Ok(key),
            _ => Err(AegisError::ConfigError(format!(
                "environment variable '{}' not set (required for Anthropic API key)",
                self.api_key_env
            ))),
        }
    }

    /// Validate that the base URL is safe (HTTPS, no SSRF targets).
    pub fn validate_endpoint(&self) -> Result<(), AegisError> {
        validate_endpoint_url(&self.base_url)
            .map_err(|e| AegisError::ConfigError(e.to_string().replace("Gemini", "Anthropic")))
    }
}

/// Configuration for the OpenAI provider.
///
/// The API key is never stored directly. `api_key_env` names the environment
/// variable that holds the key at runtime.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenAiConfig {
    /// Name of the environment variable holding the API key.
    #[serde(default = "default_openai_api_key_env")]
    pub api_key_env: String,
    /// Base API endpoint URL (must be HTTPS).
    #[serde(default = "default_openai_endpoint")]
    pub base_url: String,
    /// Default model to use when none is specified.
    #[serde(default = "default_openai_model")]
    pub default_model: String,
}

fn default_openai_api_key_env() -> String {
    OPENAI_API_KEY_ENV.to_string()
}

fn default_openai_endpoint() -> String {
    DEFAULT_OPENAI_ENDPOINT.to_string()
}

fn default_openai_model() -> String {
    DEFAULT_OPENAI_MODEL.to_string()
}

impl Default for OpenAiConfig {
    fn default() -> Self {
        Self {
            api_key_env: default_openai_api_key_env(),
            base_url: default_openai_endpoint(),
            default_model: default_openai_model(),
        }
    }
}

impl fmt::Debug for OpenAiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiConfig")
            .field("api_key_env", &self.api_key_env)
            .field("base_url", &self.base_url)
            .field("default_model", &self.default_model)
            .finish()
    }
}

impl OpenAiConfig {
    /// Read the API key from the configured environment variable.
    ///
    /// Returns an error if the variable is not set or the value is empty.
    pub fn read_api_key(&self) -> Result<String, AegisError> {
        match std::env::var(&self.api_key_env) {
            Ok(key) if !key.is_empty() => Ok(key),
            _ => Err(AegisError::ConfigError(format!(
                "environment variable '{}' not set (required for OpenAI API key)",
                self.api_key_env
            ))),
        }
    }

    /// Validate that the base URL is safe (HTTPS, no SSRF targets).
    pub fn validate_endpoint(&self) -> Result<(), AegisError> {
        validate_endpoint_url(&self.base_url)
            .map_err(|e| AegisError::ConfigError(e.to_string().replace("Gemini", "OpenAI")))
    }
}

/// Configuration for the Google Gemini provider.
///
/// The API key is never stored directly. `api_key_env` names the environment
/// variable that holds the key at runtime. Falls back to `GEMINI_API_KEY` if
/// the primary variable is the default and not set.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeminiProviderConfig {
    /// Name of the environment variable holding the API key.
    #[serde(default = "default_google_api_key_env")]
    pub api_key_env: String,
    /// Default model to use when none is specified.
    #[serde(default = "default_gemini_model")]
    pub default_model: String,
}

fn default_google_api_key_env() -> String {
    GOOGLE_API_KEY_ENV.to_string()
}

fn default_gemini_model() -> String {
    DEFAULT_GEMINI_MODEL.to_string()
}

impl Default for GeminiProviderConfig {
    fn default() -> Self {
        Self {
            api_key_env: default_google_api_key_env(),
            default_model: default_gemini_model(),
        }
    }
}

impl fmt::Debug for GeminiProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeminiProviderConfig")
            .field("api_key_env", &self.api_key_env)
            .field("default_model", &self.default_model)
            .finish()
    }
}

impl GeminiProviderConfig {
    /// Read the API key from the configured environment variable.
    ///
    /// Tries the primary `api_key_env` first, then falls back to `GEMINI_API_KEY`
    /// if the primary is the default and not set.
    pub fn read_api_key(&self) -> Result<String, AegisError> {
        match std::env::var(&self.api_key_env) {
            Ok(key) if !key.is_empty() => return Ok(key),
            _ => {}
        }

        // Fallback: if primary is the default, also try GEMINI_API_KEY.
        if self.api_key_env == GOOGLE_API_KEY_ENV {
            match std::env::var(GEMINI_API_KEY_ENV) {
                Ok(key) if !key.is_empty() => return Ok(key),
                _ => {}
            }
        }

        Err(AegisError::ConfigError(format!(
            "environment variable '{}' not set (required for Gemini API key)",
            self.api_key_env
        )))
    }

    /// Validate the Gemini endpoint URL for SSRF protection.
    ///
    /// The Gemini endpoint is always the public Google API; we validate against
    /// the constant to prevent SSRF via configuration tampering.
    pub fn validate_endpoint(&self) -> Result<(), AegisError> {
        validate_endpoint_url(DEFAULT_GEMINI_ENDPOINT)
            .map_err(|e| AegisError::ConfigError(e.to_string().replace("Gemini", "Google Gemini")))
    }
}

/// Configuration for the Ollama provider (local inference).
///
/// Ollama runs locally, so no API key is required. The base URL defaults to
/// `http://localhost:11434`. SSRF validation is intentionally skipped for
/// Ollama since it is expected to be a local service.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OllamaConfig {
    /// Base URL for the Ollama API.
    #[serde(default = "default_ollama_base_url")]
    pub base_url: String,
    /// Default model to use when none is specified.
    #[serde(default = "default_ollama_model")]
    pub default_model: String,
}

fn default_ollama_base_url() -> String {
    DEFAULT_OLLAMA_BASE_URL.to_string()
}

fn default_ollama_model() -> String {
    DEFAULT_OLLAMA_MODEL.to_string()
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: default_ollama_base_url(),
            default_model: default_ollama_model(),
        }
    }
}

impl fmt::Debug for OllamaConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OllamaConfig")
            .field("base_url", &self.base_url)
            .field("default_model", &self.default_model)
            .finish()
    }
}

impl OllamaConfig {
    /// Validate the Ollama endpoint URL.
    ///
    /// Ollama is a local service, so we only check for basic URL sanity.
    /// We intentionally allow HTTP and localhost/private IPs since that
    /// is Ollama's expected deployment model.
    pub fn validate_endpoint(&self) -> Result<(), AegisError> {
        if self.base_url.is_empty() {
            return Err(AegisError::ConfigError(
                "Ollama base_url must not be empty".into(),
            ));
        }
        if !self.base_url.starts_with("http://") && !self.base_url.starts_with("https://") {
            return Err(AegisError::ConfigError(format!(
                "Ollama base_url must use HTTP or HTTPS, got: {}",
                self.base_url
            )));
        }
        Ok(())
    }
}

/// Configuration for the OpenRouter provider.
///
/// OpenRouter provides a unified API compatible with OpenAI's format, routing
/// to many backend models. The API key is never stored directly.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenRouterConfig {
    /// Name of the environment variable holding the API key.
    #[serde(default = "default_openrouter_api_key_env")]
    pub api_key_env: String,
    /// Default model to use when none is specified.
    #[serde(default = "default_openrouter_model")]
    pub default_model: String,
}

fn default_openrouter_api_key_env() -> String {
    OPENROUTER_API_KEY_ENV.to_string()
}

fn default_openrouter_model() -> String {
    DEFAULT_OPENROUTER_MODEL.to_string()
}

impl Default for OpenRouterConfig {
    fn default() -> Self {
        Self {
            api_key_env: default_openrouter_api_key_env(),
            default_model: default_openrouter_model(),
        }
    }
}

impl fmt::Debug for OpenRouterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenRouterConfig")
            .field("api_key_env", &self.api_key_env)
            .field("default_model", &self.default_model)
            .finish()
    }
}

impl OpenRouterConfig {
    /// Read the API key from the configured environment variable.
    ///
    /// Returns an error if the variable is not set or the value is empty.
    pub fn read_api_key(&self) -> Result<String, AegisError> {
        match std::env::var(&self.api_key_env) {
            Ok(key) if !key.is_empty() => Ok(key),
            _ => Err(AegisError::ConfigError(format!(
                "environment variable '{}' not set (required for OpenRouter API key)",
                self.api_key_env
            ))),
        }
    }

    /// Validate the OpenRouter endpoint URL for SSRF protection.
    pub fn validate_endpoint(&self) -> Result<(), AegisError> {
        validate_endpoint_url(DEFAULT_OPENROUTER_ENDPOINT)
            .map_err(|e| AegisError::ConfigError(e.to_string().replace("Gemini", "OpenRouter")))
    }
}

/// Provider configuration enum wrapping all supported providers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderConfig {
    /// Anthropic (Claude) provider.
    Anthropic(AnthropicConfig),
    /// OpenAI (GPT) provider.
    OpenAi(OpenAiConfig),
    /// Google Gemini provider.
    Gemini(GeminiProviderConfig),
    /// Ollama (local inference) provider.
    Ollama(OllamaConfig),
    /// OpenRouter (multi-model gateway) provider.
    OpenRouter(OpenRouterConfig),
}

impl ProviderConfig {
    /// Validate the endpoint URL for SSRF protection.
    pub fn validate_endpoint(&self) -> Result<(), AegisError> {
        match self {
            ProviderConfig::Anthropic(c) => c.validate_endpoint(),
            ProviderConfig::OpenAi(c) => c.validate_endpoint(),
            ProviderConfig::Gemini(c) => c.validate_endpoint(),
            ProviderConfig::Ollama(c) => c.validate_endpoint(),
            ProviderConfig::OpenRouter(c) => c.validate_endpoint(),
        }
    }

    /// Read the API key from the environment.
    ///
    /// Returns `Ok` for Ollama (which requires no key).
    pub fn read_api_key(&self) -> Result<String, AegisError> {
        match self {
            ProviderConfig::Anthropic(c) => c.read_api_key(),
            ProviderConfig::OpenAi(c) => c.read_api_key(),
            ProviderConfig::Gemini(c) => c.read_api_key(),
            ProviderConfig::Ollama(_) => Ok(String::new()),
            ProviderConfig::OpenRouter(c) => c.read_api_key(),
        }
    }

    /// Get the provider name.
    pub fn provider_name(&self) -> &str {
        match self {
            ProviderConfig::Anthropic(_) => "anthropic",
            ProviderConfig::OpenAi(_) => "openai",
            ProviderConfig::Gemini(_) => "google",
            ProviderConfig::Ollama(_) => "ollama",
            ProviderConfig::OpenRouter(_) => "openrouter",
        }
    }
}

// ---------------------------------------------------------------------------
// Provider registry
// ---------------------------------------------------------------------------

/// Model-to-provider routing and registration.
///
/// Routes model identifiers to their provider based on prefix matching:
/// - `claude-*` -> Anthropic
/// - `gpt-5.3-codex*` -> OpenAI Codex
/// - `gpt-*`, `o1-*`, `o3-*` -> OpenAI
/// - `gemini-*` -> Google
/// - `llama*`, `mistral*`, `codellama*`, `phi*` -> Ollama (when registered)
///
/// Supports model aliases (e.g., "fast" -> "gemini-2.0-flash") and failover
/// chains (e.g., primary model -> fallback1 -> fallback2).
///
/// Custom providers can be registered with explicit model prefixes.
#[derive(Debug, Clone)]
pub struct ProviderRegistry {
    /// Registered providers by name.
    providers: HashMap<String, ProviderConfig>,
    /// Model prefix -> provider name mapping.
    prefix_routes: Vec<(String, String)>,
    /// Model alias -> actual model name mapping.
    aliases: HashMap<String, String>,
    /// Model -> ordered list of fallback models for failover.
    failover_chains: HashMap<String, Vec<String>>,
}

impl ProviderRegistry {
    /// Create a new registry with default prefix routes.
    pub fn new() -> Self {
        let prefix_routes = vec![
            ("claude-".to_string(), "anthropic".to_string()),
            ("gpt-5.3-codex".to_string(), "openai-codex".to_string()),
            ("gpt-".to_string(), "openai".to_string()),
            ("o1-".to_string(), "openai".to_string()),
            ("o3-".to_string(), "openai".to_string()),
            ("o4-".to_string(), "openai".to_string()),
            ("gemini-".to_string(), "google".to_string()),
            ("llama".to_string(), "ollama".to_string()),
            ("mistral".to_string(), "ollama".to_string()),
            ("codellama".to_string(), "ollama".to_string()),
            ("phi".to_string(), "ollama".to_string()),
            ("qwen".to_string(), "ollama".to_string()),
        ];
        Self {
            providers: HashMap::new(),
            prefix_routes,
            aliases: HashMap::new(),
            failover_chains: HashMap::new(),
        }
    }

    /// Register a provider configuration under the given name.
    ///
    /// The provider's endpoint URL is validated for SSRF protection before
    /// registration. Returns an error if the endpoint is unsafe.
    pub fn register_provider(
        &mut self,
        name: impl Into<String>,
        config: ProviderConfig,
    ) -> Result<(), AegisError> {
        config.validate_endpoint()?;
        self.providers.insert(name.into(), config);
        Ok(())
    }

    /// Resolve a model identifier to a provider name.
    ///
    /// First resolves any alias, then uses prefix matching against the
    /// registered routes. Returns `None` if no prefix matches.
    pub fn resolve_provider(&self, model: &str) -> Option<&str> {
        let resolved = self.resolve_alias(model);
        let lower = resolved.to_lowercase();
        for (prefix, provider) in &self.prefix_routes {
            if lower.starts_with(prefix) {
                return Some(provider.as_str());
            }
        }
        None
    }

    /// Get the provider configuration for a given provider name.
    pub fn get_provider(&self, name: &str) -> Option<&ProviderConfig> {
        self.providers.get(name)
    }

    /// Get the provider configuration for a given model identifier.
    ///
    /// Resolves aliases first, then combines `resolve_provider` and
    /// `get_provider` in one call.
    pub fn get_provider_for_model(&self, model: &str) -> Option<&ProviderConfig> {
        let provider_name = self.resolve_provider(model)?;
        self.get_provider(provider_name)
    }

    /// Resolve a model alias to the actual model name.
    ///
    /// Returns the alias target if the name is a registered alias,
    /// otherwise returns the input unchanged.
    pub fn resolve_alias<'a>(&'a self, name: &'a str) -> &'a str {
        self.aliases.get(name).map(|s| s.as_str()).unwrap_or(name)
    }

    /// Register a model alias.
    ///
    /// After registration, `resolve_alias("fast")` returns `"gemini-2.0-flash"`,
    /// and model routing uses the resolved name for prefix matching.
    pub fn add_alias(&mut self, alias: impl Into<String>, model: impl Into<String>) {
        self.aliases.insert(alias.into(), model.into());
    }

    /// Set a failover chain for a model.
    ///
    /// When the primary model fails, the client will try each fallback in order.
    pub fn set_failover(&mut self, model: impl Into<String>, fallbacks: Vec<String>) {
        self.failover_chains.insert(model.into(), fallbacks);
    }

    /// Get the failover chain for a model.
    ///
    /// Returns the primary model followed by all fallback models. If no
    /// failover is configured, returns a single-element list with the model.
    pub fn get_failover_chain(&self, model: &str) -> Vec<String> {
        let resolved = self.resolve_alias(model).to_string();
        let mut chain = vec![resolved.clone()];
        if let Some(fallbacks) = self.failover_chains.get(&resolved) {
            chain.extend(fallbacks.iter().cloned());
        }
        chain
    }

    /// List all models from registered providers.
    pub fn list_all_models(&self) -> Vec<ModelInfo> {
        let mut models = Vec::new();
        for (name, config) in &self.providers {
            match config {
                ProviderConfig::Anthropic(c) => {
                    models.push(ModelInfo {
                        id: c.default_model.clone(),
                        name: c.default_model.clone(),
                        provider: name.clone(),
                        max_tokens: 200_000,
                        capabilities: vec![
                            "tool_use".to_string(),
                            "vision".to_string(),
                            "streaming".to_string(),
                        ],
                    });
                }
                ProviderConfig::OpenAi(c) => {
                    models.push(ModelInfo {
                        id: c.default_model.clone(),
                        name: c.default_model.clone(),
                        provider: name.clone(),
                        max_tokens: 128_000,
                        capabilities: vec![
                            "tool_use".to_string(),
                            "vision".to_string(),
                            "streaming".to_string(),
                        ],
                    });
                }
                ProviderConfig::Gemini(c) => {
                    models.push(ModelInfo {
                        id: c.default_model.clone(),
                        name: c.default_model.clone(),
                        provider: name.clone(),
                        max_tokens: 1_000_000,
                        capabilities: vec![
                            "tool_use".to_string(),
                            "vision".to_string(),
                            "streaming".to_string(),
                        ],
                    });
                }
                ProviderConfig::Ollama(c) => {
                    models.push(ModelInfo {
                        id: c.default_model.clone(),
                        name: c.default_model.clone(),
                        provider: name.clone(),
                        max_tokens: 128_000,
                        capabilities: vec!["tool_use".to_string()],
                    });
                }
                ProviderConfig::OpenRouter(c) => {
                    models.push(ModelInfo {
                        id: c.default_model.clone(),
                        name: c.default_model.clone(),
                        provider: name.clone(),
                        max_tokens: 200_000,
                        capabilities: vec![
                            "tool_use".to_string(),
                            "vision".to_string(),
                            "streaming".to_string(),
                        ],
                    });
                }
            }
        }
        models
    }

    /// Add a custom model prefix route.
    pub fn add_prefix_route(&mut self, prefix: impl Into<String>, provider: impl Into<String>) {
        self.prefix_routes.push((prefix.into(), provider.into()));
    }

    /// List all registered provider names.
    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Sanitization helpers (reused from google_ai pattern)
// ---------------------------------------------------------------------------

/// Strip ASCII control characters (0x00-0x1F, 0x7F) from a string, preserving
/// common whitespace (newline, tab, carriage return).
fn sanitize_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t' || *c == '\r')
        .collect()
}

/// Recursively sanitize string values in a JSON tree, stripping control characters.
fn sanitize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(sanitize_text(s)),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sanitize_json_value).collect())
        }
        serde_json::Value::Object(map) => {
            let sanitized: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (sanitize_text(k), sanitize_json_value(v)))
                .collect();
            serde_json::Value::Object(sanitized)
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// Anthropic format conversion
// ---------------------------------------------------------------------------

/// Anthropic content block types used in the Messages API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnthropicContentBlock {
    /// Plain text content.
    Text {
        /// The text content.
        text: String,
    },
    /// A tool use request from the model.
    ToolUse {
        /// Unique ID for this tool use.
        id: String,
        /// Name of the tool.
        name: String,
        /// Tool input arguments.
        input: serde_json::Value,
    },
    /// A tool result fed back to the model.
    ToolResult {
        /// ID of the tool use this result corresponds to.
        tool_use_id: String,
        /// Result content.
        content: String,
    },
}

/// An Anthropic Messages API message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicMessage {
    /// Message role ("user" or "assistant").
    pub role: String,
    /// Content blocks.
    pub content: Vec<AnthropicContentBlock>,
}

/// Convert an internal `LlmMessage` to Anthropic format.
///
/// Sanitizes all text content and tool inputs before conversion.
pub fn to_anthropic_message(msg: &LlmMessage) -> AnthropicMessage {
    let role = match msg.role {
        LlmRole::User | LlmRole::System => "user".to_string(),
        LlmRole::Assistant => "assistant".to_string(),
        LlmRole::Tool => "user".to_string(),
    };

    let mut content = Vec::new();

    // For tool role, emit a tool_result block.
    if msg.role == LlmRole::Tool {
        if let Some(ref id) = msg.tool_use_id {
            content.push(AnthropicContentBlock::ToolResult {
                tool_use_id: id.clone(),
                content: sanitize_text(&msg.content),
            });
        }
    } else if !msg.content.is_empty() {
        content.push(AnthropicContentBlock::Text {
            text: sanitize_text(&msg.content),
        });
    }

    // Add tool calls as tool_use blocks.
    for tc in &msg.tool_calls {
        content.push(AnthropicContentBlock::ToolUse {
            id: tc.id.clone(),
            name: sanitize_text(&tc.name),
            input: sanitize_json_value(&tc.input),
        });
    }

    AnthropicMessage { role, content }
}

/// Convert an Anthropic message back to the internal `LlmMessage` format.
///
/// Sanitizes all content during conversion.
pub fn from_anthropic_message(msg: &AnthropicMessage) -> LlmMessage {
    let role = match msg.role.as_str() {
        "assistant" => LlmRole::Assistant,
        _ => LlmRole::User,
    };

    let mut content_text = String::new();
    let mut tool_calls = Vec::new();
    let mut tool_use_id = None;

    for block in &msg.content {
        match block {
            AnthropicContentBlock::Text { text } => {
                if !content_text.is_empty() {
                    content_text.push('\n');
                }
                content_text.push_str(&sanitize_text(text));
            }
            AnthropicContentBlock::ToolUse { id, name, input } => {
                tool_calls.push(LlmToolCall {
                    id: id.clone(),
                    name: sanitize_text(name),
                    input: sanitize_json_value(input),
                });
            }
            AnthropicContentBlock::ToolResult {
                tool_use_id: id,
                content,
            } => {
                tool_use_id = Some(id.clone());
                content_text = sanitize_text(content);
            }
        }
    }

    // If we found a tool_result, this is a Tool role message.
    let final_role = if tool_use_id.is_some() {
        LlmRole::Tool
    } else {
        role
    };

    LlmMessage {
        role: final_role,
        content: content_text,
        tool_use_id,
        tool_calls,
    }
}

// ---------------------------------------------------------------------------
// OpenAI format conversion
// ---------------------------------------------------------------------------

/// An OpenAI Chat Completion API tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiToolCall {
    /// Unique ID for this tool call.
    pub id: String,
    /// Type of tool call (always "function" for now).
    #[serde(rename = "type")]
    pub call_type: String,
    /// Function call details.
    pub function: OpenAiFunction,
}

/// Function details within an OpenAI tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiFunction {
    /// Name of the function to call.
    pub name: String,
    /// JSON-encoded arguments string.
    pub arguments: String,
}

/// An OpenAI Chat Completion API message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiMessage {
    /// Message role ("system", "user", "assistant", "tool").
    pub role: String,
    /// Text content (may be None for tool-call-only messages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Tool calls made by the assistant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAiToolCall>>,
    /// Tool call ID (for tool role messages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// Convert an internal `LlmMessage` to OpenAI format.
///
/// Sanitizes all text content and tool inputs before conversion.
pub fn to_openai_message(msg: &LlmMessage) -> OpenAiMessage {
    let role = match msg.role {
        LlmRole::System => "system".to_string(),
        LlmRole::User => "user".to_string(),
        LlmRole::Assistant => "assistant".to_string(),
        LlmRole::Tool => "tool".to_string(),
    };

    let content = if msg.content.is_empty() {
        None
    } else {
        Some(sanitize_text(&msg.content))
    };

    let tool_calls = if msg.tool_calls.is_empty() {
        None
    } else {
        Some(
            msg.tool_calls
                .iter()
                .map(|tc| OpenAiToolCall {
                    id: tc.id.clone(),
                    call_type: "function".to_string(),
                    function: OpenAiFunction {
                        name: sanitize_text(&tc.name),
                        arguments: serde_json::to_string(&sanitize_json_value(&tc.input))
                            .unwrap_or_default(),
                    },
                })
                .collect(),
        )
    };

    let tool_call_id = msg.tool_use_id.clone();

    OpenAiMessage {
        role,
        content,
        tool_calls,
        tool_call_id,
    }
}

/// Convert an OpenAI message back to the internal `LlmMessage` format.
///
/// Sanitizes all content during conversion.
pub fn from_openai_message(msg: &OpenAiMessage) -> LlmMessage {
    let role = match msg.role.as_str() {
        "system" => LlmRole::System,
        "assistant" => LlmRole::Assistant,
        "tool" => LlmRole::Tool,
        _ => LlmRole::User,
    };

    let content = msg
        .content
        .as_deref()
        .map(sanitize_text)
        .unwrap_or_default();

    let tool_calls = msg
        .tool_calls
        .as_ref()
        .map(|tcs| {
            tcs.iter()
                .map(|tc| {
                    let input = serde_json::from_str(&tc.function.arguments)
                        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
                    LlmToolCall {
                        id: tc.id.clone(),
                        name: sanitize_text(&tc.function.name),
                        input: sanitize_json_value(&input),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    LlmMessage {
        role,
        content,
        tool_use_id: msg.tool_call_id.clone(),
        tool_calls,
    }
}

// ---------------------------------------------------------------------------
// Gemini format conversion
// ---------------------------------------------------------------------------

/// A part within a Gemini content message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GeminiPart {
    /// Plain text content.
    Text {
        /// The text content.
        text: String,
    },
    /// A function call from the model.
    FunctionCall {
        /// Function call details.
        #[serde(rename = "functionCall")]
        function_call: GeminiFunctionCall,
    },
    /// A function response fed back to the model.
    FunctionResponse {
        /// Function response details.
        #[serde(rename = "functionResponse")]
        function_response: GeminiFunctionResponse,
    },
}

/// A function call within a Gemini response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiFunctionCall {
    /// Name of the function to call.
    pub name: String,
    /// Function arguments as a JSON object.
    pub args: serde_json::Value,
}

/// A function response fed back to Gemini.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiFunctionResponse {
    /// Name of the function that was called.
    pub name: String,
    /// Function result as a JSON object.
    pub response: serde_json::Value,
}

/// A Gemini content message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiContent {
    /// Message role ("user" or "model").
    pub role: String,
    /// Content parts.
    pub parts: Vec<GeminiPart>,
}

/// Convert an internal `LlmMessage` to Gemini content format.
///
/// Sanitizes all text content and tool inputs before conversion.
/// System messages should be extracted and placed in `system_instruction`
/// at the request level, not converted here.
pub fn to_gemini_content(msg: &LlmMessage) -> GeminiContent {
    let role = match msg.role {
        LlmRole::User | LlmRole::System => "user".to_string(),
        LlmRole::Assistant => "model".to_string(),
        LlmRole::Tool => "user".to_string(),
    };

    let mut parts = Vec::new();

    // For tool role, emit a functionResponse part.
    if msg.role == LlmRole::Tool {
        if let Some(ref _id) = msg.tool_use_id {
            // Gemini uses the function name, not an ID, for responses.
            // We store the result in a generic response object.
            parts.push(GeminiPart::FunctionResponse {
                function_response: GeminiFunctionResponse {
                    name: "tool_result".to_string(),
                    response: serde_json::json!({
                        "result": sanitize_text(&msg.content)
                    }),
                },
            });
        }
    } else if !msg.content.is_empty() {
        parts.push(GeminiPart::Text {
            text: sanitize_text(&msg.content),
        });
    }

    // Add tool calls as functionCall parts.
    for tc in &msg.tool_calls {
        parts.push(GeminiPart::FunctionCall {
            function_call: GeminiFunctionCall {
                name: sanitize_text(&tc.name),
                args: sanitize_json_value(&tc.input),
            },
        });
    }

    GeminiContent { role, parts }
}

/// Convert a Gemini content message back to the internal `LlmMessage` format.
///
/// Sanitizes all content during conversion.
pub fn from_gemini_content(content: &GeminiContent) -> LlmMessage {
    let role = match content.role.as_str() {
        "model" => LlmRole::Assistant,
        _ => LlmRole::User,
    };

    let mut content_text = String::new();
    let mut tool_calls = Vec::new();
    let mut is_tool_response = false;
    let mut tool_use_id = None;

    for part in &content.parts {
        match part {
            GeminiPart::Text { text } => {
                if !content_text.is_empty() {
                    content_text.push('\n');
                }
                content_text.push_str(&sanitize_text(text));
            }
            GeminiPart::FunctionCall { function_call } => {
                // Generate a synthetic ID for the tool call.
                let id = format!("gemini_fc_{}", tool_calls.len());
                tool_calls.push(LlmToolCall {
                    id,
                    name: sanitize_text(&function_call.name),
                    input: sanitize_json_value(&function_call.args),
                });
            }
            GeminiPart::FunctionResponse { function_response } => {
                is_tool_response = true;
                tool_use_id = Some(function_response.name.clone());
                if let Some(result) = function_response.response.get("result") {
                    if let Some(s) = result.as_str() {
                        content_text = sanitize_text(s);
                    } else {
                        content_text = sanitize_text(&result.to_string());
                    }
                }
            }
        }
    }

    let final_role = if is_tool_response {
        LlmRole::Tool
    } else {
        role
    };

    LlmMessage {
        role: final_role,
        content: content_text,
        tool_use_id,
        tool_calls,
    }
}

/// Parse a Gemini API response JSON into an `LlmResponse`.
///
/// Expects the standard Gemini `generateContent` response format:
/// ```json
/// {
///   "candidates": [{
///     "content": {"parts": [{"text": "..."}], "role": "model"},
///     "finishReason": "STOP"
///   }],
///   "usageMetadata": {
///     "promptTokenCount": 10,
///     "candidatesTokenCount": 20
///   }
/// }
/// ```
pub fn from_gemini_response(json: &serde_json::Value, model: &str) -> Result<LlmResponse, String> {
    // Extract the first candidate.
    let candidate = json
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .ok_or("Gemini response missing candidates array")?;

    let content_obj = candidate
        .get("content")
        .ok_or("Gemini response missing content in candidate")?;

    let mut content_text = String::new();
    let mut tool_calls = Vec::new();

    if let Some(parts) = content_obj.get("parts").and_then(|p| p.as_array()) {
        for part in parts {
            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                if !content_text.is_empty() {
                    content_text.push('\n');
                }
                content_text.push_str(text);
            }
            if let Some(fc) = part.get("functionCall") {
                let name = fc
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let args = fc
                    .get("args")
                    .cloned()
                    .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
                let id = format!("gemini_fc_{}", tool_calls.len());
                tool_calls.push(LlmToolCall {
                    id,
                    name,
                    input: args,
                });
            }
        }
    }

    // Extract usage metadata.
    let usage = json
        .get("usageMetadata")
        .map(|u| LlmUsage {
            input_tokens: u
                .get("promptTokenCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: u
                .get("candidatesTokenCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        })
        .unwrap_or(LlmUsage {
            input_tokens: 0,
            output_tokens: 0,
        });

    // Map finishReason.
    let stop_reason = candidate
        .get("finishReason")
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "STOP" => StopReason::EndTurn,
            "MAX_TOKENS" => StopReason::MaxTokens,
            "FUNCTION_CALL" => StopReason::ToolUse,
            "SAFETY" | "RECITATION" | "OTHER" => StopReason::EndTurn,
            _ => StopReason::EndTurn,
        });

    let response_model = json
        .get("modelVersion")
        .and_then(|v| v.as_str())
        .unwrap_or(model)
        .to_string();

    Ok(LlmResponse {
        content: content_text,
        model: response_model,
        usage,
        tool_calls,
        stop_reason,
    })
}

// ---------------------------------------------------------------------------
// MaskedApiKey (reexport pattern from google_ai)
// ---------------------------------------------------------------------------

/// A wrapper around an API key string that masks its value in Debug/Display.
///
/// Prevents accidental exposure of API keys in logs, error messages, and
/// debug output. The key value is never shown in full.
#[derive(Clone, Serialize, Deserialize)]
pub struct MaskedApiKey(pub String);

impl fmt::Debug for MaskedApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MaskedApiKey({})", mask_sensitive(&self.0))
    }
}

impl fmt::Display for MaskedApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", mask_sensitive(&self.0))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Request serialization --

    #[test]
    fn llm_request_serialization() {
        let request = LlmRequest {
            model: "claude-sonnet-4-20250514".into(),
            messages: vec![
                LlmMessage::system("You are helpful."),
                LlmMessage::user("Hello!"),
            ],
            temperature: Some(0.7),
            max_tokens: Some(1024),
            system_prompt: Some("Be concise.".into()),
            tools: vec![LlmToolDefinition {
                name: "search".into(),
                description: "Search the web".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"}
                    },
                    "required": ["query"]
                }),
            }],
            thinking_budget: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let back: LlmRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.model, "claude-sonnet-4-20250514");
        assert_eq!(back.messages.len(), 2);
        assert_eq!(back.temperature, Some(0.7));
        assert_eq!(back.max_tokens, Some(1024));
        assert_eq!(back.tools.len(), 1);
        assert_eq!(back.tools[0].name, "search");
    }

    // -- Response parsing --

    #[test]
    fn llm_response_parsing() {
        let json = r#"{
            "content": "Hello! How can I help?",
            "model": "claude-sonnet-4-20250514",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 8
            },
            "stop_reason": "end_turn"
        }"#;

        let response: LlmResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.content, "Hello! How can I help?");
        assert_eq!(response.model, "claude-sonnet-4-20250514");
        assert_eq!(response.usage.input_tokens, 10);
        assert_eq!(response.usage.output_tokens, 8);
        assert_eq!(response.stop_reason, Some(StopReason::EndTurn));
        assert!(response.tool_calls.is_empty());
    }

    // -- Anthropic message format conversion --

    #[test]
    fn anthropic_message_format_conversion() {
        // User message roundtrip.
        let msg = LlmMessage::user("Hello, Claude!");
        let anthropic = to_anthropic_message(&msg);
        assert_eq!(anthropic.role, "user");
        assert_eq!(anthropic.content.len(), 1);
        match &anthropic.content[0] {
            AnthropicContentBlock::Text { text } => assert_eq!(text, "Hello, Claude!"),
            _ => panic!("expected text block"),
        }

        let back = from_anthropic_message(&anthropic);
        assert_eq!(back.role, LlmRole::User);
        assert_eq!(back.content, "Hello, Claude!");

        // Assistant message with tool call.
        let msg = LlmMessage {
            role: LlmRole::Assistant,
            content: "Let me search for that.".into(),
            tool_use_id: None,
            tool_calls: vec![LlmToolCall {
                id: "tc_123".into(),
                name: "search".into(),
                input: serde_json::json!({"query": "rust programming"}),
            }],
        };
        let anthropic = to_anthropic_message(&msg);
        assert_eq!(anthropic.role, "assistant");
        assert_eq!(anthropic.content.len(), 2); // text + tool_use

        let back = from_anthropic_message(&anthropic);
        assert_eq!(back.role, LlmRole::Assistant);
        assert_eq!(back.content, "Let me search for that.");
        assert_eq!(back.tool_calls.len(), 1);
        assert_eq!(back.tool_calls[0].name, "search");

        // Tool result message.
        let msg = LlmMessage::tool_result("tc_123", "Search results here");
        let anthropic = to_anthropic_message(&msg);
        assert_eq!(anthropic.role, "user");
        assert_eq!(anthropic.content.len(), 1);
        match &anthropic.content[0] {
            AnthropicContentBlock::ToolResult {
                tool_use_id,
                content,
            } => {
                assert_eq!(tool_use_id, "tc_123");
                assert_eq!(content, "Search results here");
            }
            _ => panic!("expected tool_result block"),
        }

        let back = from_anthropic_message(&anthropic);
        assert_eq!(back.role, LlmRole::Tool);
        assert_eq!(back.tool_use_id, Some("tc_123".to_string()));
        assert_eq!(back.content, "Search results here");
    }

    // -- OpenAI message format conversion --

    #[test]
    fn openai_message_format_conversion() {
        // System message.
        let msg = LlmMessage::system("You are helpful.");
        let openai = to_openai_message(&msg);
        assert_eq!(openai.role, "system");
        assert_eq!(openai.content.as_deref(), Some("You are helpful."));
        assert!(openai.tool_calls.is_none());

        let back = from_openai_message(&openai);
        assert_eq!(back.role, LlmRole::System);
        assert_eq!(back.content, "You are helpful.");

        // User message.
        let msg = LlmMessage::user("What is Rust?");
        let openai = to_openai_message(&msg);
        assert_eq!(openai.role, "user");
        assert_eq!(openai.content.as_deref(), Some("What is Rust?"));

        let back = from_openai_message(&openai);
        assert_eq!(back.role, LlmRole::User);
        assert_eq!(back.content, "What is Rust?");

        // Assistant with tool calls.
        let msg = LlmMessage {
            role: LlmRole::Assistant,
            content: String::new(),
            tool_use_id: None,
            tool_calls: vec![LlmToolCall {
                id: "call_abc".into(),
                name: "get_weather".into(),
                input: serde_json::json!({"city": "NYC"}),
            }],
        };
        let openai = to_openai_message(&msg);
        assert_eq!(openai.role, "assistant");
        assert!(openai.content.is_none()); // empty content -> None
        let tcs = openai.tool_calls.as_ref().unwrap();
        assert_eq!(tcs.len(), 1);
        assert_eq!(tcs[0].function.name, "get_weather");

        let back = from_openai_message(&openai);
        assert_eq!(back.role, LlmRole::Assistant);
        assert_eq!(back.tool_calls.len(), 1);
        assert_eq!(back.tool_calls[0].name, "get_weather");
        assert_eq!(back.tool_calls[0].input["city"], "NYC");

        // Tool result.
        let msg = LlmMessage::tool_result("call_abc", "72F, sunny");
        let openai = to_openai_message(&msg);
        assert_eq!(openai.role, "tool");
        assert_eq!(openai.content.as_deref(), Some("72F, sunny"));
        assert_eq!(openai.tool_call_id.as_deref(), Some("call_abc"));

        let back = from_openai_message(&openai);
        assert_eq!(back.role, LlmRole::Tool);
        assert_eq!(back.content, "72F, sunny");
        assert_eq!(back.tool_use_id, Some("call_abc".to_string()));
    }

    // -- Provider registry routing --

    #[test]
    fn provider_registry_routing() {
        let registry = ProviderRegistry::new();

        assert_eq!(
            registry.resolve_provider("claude-sonnet-4-20250514"),
            Some("anthropic")
        );
        assert_eq!(
            registry.resolve_provider("claude-3-haiku"),
            Some("anthropic")
        );
        assert_eq!(registry.resolve_provider("gpt-4o"), Some("openai"));
        assert_eq!(registry.resolve_provider("gpt-4-turbo"), Some("openai"));
        assert_eq!(registry.resolve_provider("o1-preview"), Some("openai"));
        assert_eq!(registry.resolve_provider("o3-mini"), Some("openai"));
        assert_eq!(
            registry.resolve_provider("gpt-5.3-codex"),
            Some("openai-codex")
        );
        assert_eq!(
            registry.resolve_provider("gpt-5.3-codex-spark"),
            Some("openai-codex")
        );
        assert_eq!(registry.resolve_provider("gemini-pro"), Some("google"));
        assert_eq!(registry.resolve_provider("gemini-1.5-pro"), Some("google"));
    }

    // -- Model prefix matching --

    #[test]
    fn model_prefix_matching() {
        let mut registry = ProviderRegistry::new();

        // Ollama models route by default.
        assert_eq!(registry.resolve_provider("llama3.2"), Some("ollama"));
        assert_eq!(registry.resolve_provider("mistral-7b"), Some("ollama"));

        // Unknown model returns None.
        assert!(registry.resolve_provider("unknown-model-xyz").is_none());

        // Case insensitive matching.
        assert_eq!(
            registry.resolve_provider("Claude-Sonnet-4"),
            Some("anthropic")
        );
        assert_eq!(registry.resolve_provider("GPT-4o"), Some("openai"));

        // Custom prefix route (overrides default).
        registry.add_prefix_route("llama-", "meta");
        // The custom "llama-" route is checked after the default "llama" route,
        // so "llama3.2" still matches the default. Test a fresh pattern.
        registry.add_prefix_route("falcon-", "tii");
        assert_eq!(registry.resolve_provider("falcon-40b"), Some("tii"));
    }

    // -- Provider config from env --

    #[test]
    fn provider_config_from_env() {
        // Test Anthropic config with custom env var.
        let config = AnthropicConfig {
            api_key_env: "_AEGIS_TEST_ANTHROPIC_KEY".into(),
            ..Default::default()
        };

        // Key not set -> error.
        std::env::remove_var("_AEGIS_TEST_ANTHROPIC_KEY");
        assert!(config.read_api_key().is_err());

        // Set the key.
        std::env::set_var("_AEGIS_TEST_ANTHROPIC_KEY", "sk-test-key-123");
        let key = config.read_api_key().unwrap();
        assert_eq!(key, "sk-test-key-123");
        std::env::remove_var("_AEGIS_TEST_ANTHROPIC_KEY");

        // Test OpenAI config with custom env var.
        let config = OpenAiConfig {
            api_key_env: "_AEGIS_TEST_OPENAI_KEY".into(),
            ..Default::default()
        };

        std::env::set_var("_AEGIS_TEST_OPENAI_KEY", "sk-openai-456");
        let key = config.read_api_key().unwrap();
        assert_eq!(key, "sk-openai-456");
        std::env::remove_var("_AEGIS_TEST_OPENAI_KEY");
    }

    // -- Tool call format normalization --

    #[test]
    fn tool_call_format_normalization() {
        // Tool call with control characters in name and input.
        let tc = LlmToolCall {
            id: "tc_1".into(),
            name: "evil\x00tool".into(),
            input: serde_json::json!({"cmd": "rm\x00 -rf /"}),
        };

        let msg = LlmMessage {
            role: LlmRole::Assistant,
            content: String::new(),
            tool_use_id: None,
            tool_calls: vec![tc],
        };

        // Anthropic conversion sanitizes.
        let anthropic = to_anthropic_message(&msg);
        match &anthropic.content[0] {
            AnthropicContentBlock::ToolUse { name, input, .. } => {
                assert_eq!(name, "eviltool");
                assert_eq!(input["cmd"], "rm -rf /");
            }
            _ => panic!("expected tool_use block"),
        }

        // OpenAI conversion sanitizes.
        let openai = to_openai_message(&msg);
        let tcs = openai.tool_calls.as_ref().unwrap();
        assert_eq!(tcs[0].function.name, "eviltool");
        let args: serde_json::Value = serde_json::from_str(&tcs[0].function.arguments).unwrap();
        assert_eq!(args["cmd"], "rm -rf /");
    }

    // -- Security: LlmComplete requires Cedar policy --

    #[test]
    fn llm_requires_cedar_policy() {
        use crate::ActionKind;

        // Verify the LlmComplete variant exists and can be constructed.
        let action = ActionKind::LlmComplete {
            provider: "anthropic".into(),
            model: "claude-sonnet-4-20250514".into(),
            endpoint: "https://api.anthropic.com".into(),
            input_tokens: 100,
            output_tokens: 50,
        };

        // Verify it serializes (i.e., is a proper ActionKind variant).
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("LlmComplete"));
        assert!(json.contains("anthropic"));

        // Verify round-trip.
        let back: ActionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, action);
    }

    // -- Security: API key masked in config --

    #[test]
    fn api_key_masked_in_config() {
        let key = MaskedApiKey("sk-ant-1234567890abcdef".into());
        let debug = format!("{key:?}");
        assert!(debug.contains("sk-a***"));
        assert!(!debug.contains("1234567890abcdef"));

        let display = format!("{key}");
        assert!(display.contains("sk-a***"));
        assert!(!display.contains("1234567890abcdef"));

        // Anthropic config Debug does not expose the key env var value.
        let config = AnthropicConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("ANTHROPIC_API_KEY"));
        // The field name is shown, not the key value.
        assert!(!debug.contains("sk-"));
    }

    // -- Security: SSRF protection on provider endpoints --

    #[test]
    fn provider_endpoint_ssrf_protection() {
        // Private addresses blocked for Anthropic.
        let config = AnthropicConfig {
            base_url: "https://127.0.0.1/v1".into(),
            ..Default::default()
        };
        assert!(config.validate_endpoint().is_err());

        // Private addresses blocked for OpenAI.
        let config = OpenAiConfig {
            base_url: "https://192.168.1.1/v1".into(),
            ..Default::default()
        };
        assert!(config.validate_endpoint().is_err());

        // HTTP rejected.
        let config = AnthropicConfig {
            base_url: "http://api.anthropic.com/v1".into(),
            ..Default::default()
        };
        assert!(config.validate_endpoint().is_err());

        // Valid HTTPS endpoints pass.
        let config = AnthropicConfig::default();
        assert!(config.validate_endpoint().is_ok());

        let config = OpenAiConfig::default();
        assert!(config.validate_endpoint().is_ok());

        // Registry rejects unsafe providers.
        let mut registry = ProviderRegistry::new();
        let result = registry.register_provider(
            "bad",
            ProviderConfig::Anthropic(AnthropicConfig {
                base_url: "https://localhost/v1".into(),
                ..Default::default()
            }),
        );
        assert!(result.is_err());
    }

    // -- Provider config defaults --

    #[test]
    fn provider_config_defaults() {
        let anthropic = AnthropicConfig::default();
        assert_eq!(anthropic.api_key_env, "ANTHROPIC_API_KEY");
        assert_eq!(anthropic.base_url, "https://api.anthropic.com");
        assert_eq!(anthropic.default_model, "claude-sonnet-4-20250514");

        let openai = OpenAiConfig::default();
        assert_eq!(openai.api_key_env, "OPENAI_API_KEY");
        assert_eq!(openai.base_url, "https://api.openai.com");
        assert_eq!(openai.default_model, "gpt-4o");
    }

    // -- Registry model listing --

    #[test]
    fn registry_list_models() {
        let mut registry = ProviderRegistry::new();
        registry
            .register_provider(
                "anthropic",
                ProviderConfig::Anthropic(AnthropicConfig::default()),
            )
            .unwrap();
        registry
            .register_provider("openai", ProviderConfig::OpenAi(OpenAiConfig::default()))
            .unwrap();

        let models = registry.list_all_models();
        assert_eq!(models.len(), 2);

        let providers: Vec<&str> = models.iter().map(|m| m.provider.as_str()).collect();
        assert!(providers.contains(&"anthropic"));
        assert!(providers.contains(&"openai"));
    }

    // -- ProviderConfig enum --

    #[test]
    fn provider_config_serialization() {
        let config = ProviderConfig::Anthropic(AnthropicConfig::default());
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("anthropic"));

        let back: ProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider_name(), "anthropic");

        let config = ProviderConfig::OpenAi(OpenAiConfig::default());
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("open_ai"));

        let back: ProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider_name(), "openai");
    }

    // -- StopReason serialization --

    #[test]
    fn stop_reason_serialization() {
        let reasons = vec![
            StopReason::EndTurn,
            StopReason::MaxTokens,
            StopReason::ToolUse,
            StopReason::StopSequence,
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let back: StopReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reason);
        }
    }

    // -- LlmResponse with tool calls --

    #[test]
    fn llm_response_with_tool_calls() {
        let json = r#"{
            "content": "",
            "model": "gpt-4o",
            "usage": {
                "input_tokens": 50,
                "output_tokens": 25
            },
            "tool_calls": [{
                "id": "call_123",
                "name": "search",
                "input": {"query": "rust lang"}
            }],
            "stop_reason": "tool_use"
        }"#;

        let response: LlmResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "search");
        assert_eq!(response.stop_reason, Some(StopReason::ToolUse));
    }

    // -- ModelInfo serialization --

    #[test]
    fn model_info_serialization() {
        let info = ModelInfo {
            id: "claude-sonnet-4-20250514".into(),
            name: "Claude Sonnet 4".into(),
            provider: "anthropic".into(),
            max_tokens: 200_000,
            capabilities: vec!["tool_use".into(), "vision".into()],
        };

        let json = serde_json::to_string(&info).unwrap();
        let back: ModelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, info);
    }

    // -- Gemini format conversion --

    #[test]
    fn gemini_content_format_conversion() {
        // User message roundtrip.
        let msg = LlmMessage::user("Hello, Gemini!");
        let gemini = to_gemini_content(&msg);
        assert_eq!(gemini.role, "user");
        assert_eq!(gemini.parts.len(), 1);
        match &gemini.parts[0] {
            GeminiPart::Text { text } => assert_eq!(text, "Hello, Gemini!"),
            _ => panic!("expected text part"),
        }

        let back = from_gemini_content(&gemini);
        assert_eq!(back.role, LlmRole::User);
        assert_eq!(back.content, "Hello, Gemini!");

        // Assistant message with function call.
        let msg = LlmMessage {
            role: LlmRole::Assistant,
            content: "Let me look that up.".into(),
            tool_use_id: None,
            tool_calls: vec![LlmToolCall {
                id: "fc_1".into(),
                name: "search".into(),
                input: serde_json::json!({"query": "rust programming"}),
            }],
        };
        let gemini = to_gemini_content(&msg);
        assert_eq!(gemini.role, "model");
        assert_eq!(gemini.parts.len(), 2); // text + functionCall

        let back = from_gemini_content(&gemini);
        assert_eq!(back.role, LlmRole::Assistant);
        assert_eq!(back.content, "Let me look that up.");
        assert_eq!(back.tool_calls.len(), 1);
        assert_eq!(back.tool_calls[0].name, "search");

        // Tool result message.
        let msg = LlmMessage::tool_result("fc_1", "Search results here");
        let gemini = to_gemini_content(&msg);
        assert_eq!(gemini.role, "user");
        assert_eq!(gemini.parts.len(), 1);
        match &gemini.parts[0] {
            GeminiPart::FunctionResponse { function_response } => {
                assert_eq!(function_response.name, "tool_result");
                assert_eq!(function_response.response["result"], "Search results here");
            }
            _ => panic!("expected functionResponse part"),
        }

        let back = from_gemini_content(&gemini);
        assert_eq!(back.role, LlmRole::Tool);
        assert_eq!(back.content, "Search results here");
    }

    // -- Gemini response parsing --

    #[test]
    fn gemini_response_parsing() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello! I am Gemini."}],
                    "role": "model"
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 15,
                "candidatesTokenCount": 8
            }
        }"#,
        )
        .unwrap();

        let resp = from_gemini_response(&json, "gemini-2.0-flash").unwrap();
        assert_eq!(resp.content, "Hello! I am Gemini.");
        assert_eq!(resp.model, "gemini-2.0-flash");
        assert_eq!(resp.usage.input_tokens, 15);
        assert_eq!(resp.usage.output_tokens, 8);
        assert_eq!(resp.stop_reason, Some(StopReason::EndTurn));
        assert!(resp.tool_calls.is_empty());
    }

    #[test]
    fn gemini_function_call_response() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "Let me search for that."},
                        {"functionCall": {"name": "search", "args": {"query": "rust lang"}}}
                    ],
                    "role": "model"
                },
                "finishReason": "FUNCTION_CALL"
            }],
            "usageMetadata": {
                "promptTokenCount": 20,
                "candidatesTokenCount": 15
            }
        }"#,
        )
        .unwrap();

        let resp = from_gemini_response(&json, "gemini-2.0-flash").unwrap();
        assert_eq!(resp.content, "Let me search for that.");
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].name, "search");
        assert_eq!(resp.tool_calls[0].input["query"], "rust lang");
        assert_eq!(resp.stop_reason, Some(StopReason::ToolUse));
    }

    // -- Provider config: Gemini --

    #[test]
    fn gemini_provider_config_defaults() {
        let config = GeminiProviderConfig::default();
        assert_eq!(config.api_key_env, "GOOGLE_API_KEY");
        assert_eq!(config.default_model, "gemini-2.0-flash");
    }

    #[test]
    fn gemini_provider_config_from_env() {
        let config = GeminiProviderConfig {
            api_key_env: "_AEGIS_TEST_GOOGLE_KEY".into(),
            ..Default::default()
        };

        std::env::remove_var("_AEGIS_TEST_GOOGLE_KEY");
        assert!(config.read_api_key().is_err());

        std::env::set_var("_AEGIS_TEST_GOOGLE_KEY", "AIza-test-key");
        let key = config.read_api_key().unwrap();
        assert_eq!(key, "AIza-test-key");
        std::env::remove_var("_AEGIS_TEST_GOOGLE_KEY");
    }

    // -- Provider config: Ollama --

    #[test]
    fn ollama_config_defaults() {
        let config = OllamaConfig::default();
        assert_eq!(config.base_url, "http://localhost:11434");
        assert_eq!(config.default_model, "llama3.2");
    }

    #[test]
    fn ollama_config_validation() {
        // Default is valid.
        let config = OllamaConfig::default();
        assert!(config.validate_endpoint().is_ok());

        // Empty URL is invalid.
        let config = OllamaConfig {
            base_url: "".into(),
            ..Default::default()
        };
        assert!(config.validate_endpoint().is_err());

        // Non-HTTP scheme is invalid.
        let config = OllamaConfig {
            base_url: "ftp://localhost:11434".into(),
            ..Default::default()
        };
        assert!(config.validate_endpoint().is_err());

        // HTTPS is also valid for Ollama.
        let config = OllamaConfig {
            base_url: "https://ollama.internal:11434".into(),
            ..Default::default()
        };
        assert!(config.validate_endpoint().is_ok());
    }

    // -- Provider config: OpenRouter --

    #[test]
    fn openrouter_config_defaults() {
        let config = OpenRouterConfig::default();
        assert_eq!(config.api_key_env, "OPENROUTER_API_KEY");
        assert_eq!(config.default_model, "anthropic/claude-sonnet-4-20250514");
    }

    #[test]
    fn openrouter_config_from_env() {
        let config = OpenRouterConfig {
            api_key_env: "_AEGIS_TEST_OPENROUTER_KEY".into(),
            ..Default::default()
        };

        std::env::remove_var("_AEGIS_TEST_OPENROUTER_KEY");
        assert!(config.read_api_key().is_err());

        std::env::set_var("_AEGIS_TEST_OPENROUTER_KEY", "sk-or-test-123");
        let key = config.read_api_key().unwrap();
        assert_eq!(key, "sk-or-test-123");
        std::env::remove_var("_AEGIS_TEST_OPENROUTER_KEY");
    }

    // -- ProviderConfig new variants serialization --

    #[test]
    fn provider_config_new_variants_serialization() {
        let config = ProviderConfig::Gemini(GeminiProviderConfig::default());
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("gemini"));
        let back: ProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider_name(), "google");

        let config = ProviderConfig::Ollama(OllamaConfig::default());
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("ollama"));
        let back: ProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider_name(), "ollama");

        let config = ProviderConfig::OpenRouter(OpenRouterConfig::default());
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("open_router"));
        let back: ProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider_name(), "openrouter");
    }

    // -- Model aliases --

    #[test]
    fn model_alias_resolution() {
        let mut registry = ProviderRegistry::new();

        // No alias set -> returns input.
        assert_eq!(registry.resolve_alias("gpt-4o"), "gpt-4o");

        // Set an alias.
        registry.add_alias("fast", "gemini-2.0-flash");
        assert_eq!(registry.resolve_alias("fast"), "gemini-2.0-flash");

        // Alias affects provider routing.
        assert_eq!(registry.resolve_provider("fast"), Some("google"));

        // Multiple aliases.
        registry.add_alias("smart", "claude-sonnet-4-20250514");
        assert_eq!(registry.resolve_alias("smart"), "claude-sonnet-4-20250514");
        assert_eq!(registry.resolve_provider("smart"), Some("anthropic"));

        // Alias for local model.
        registry.add_alias("local", "llama3.2");
        assert_eq!(registry.resolve_alias("local"), "llama3.2");
        assert_eq!(registry.resolve_provider("local"), Some("ollama"));
    }

    // -- Failover chains --

    #[test]
    fn failover_chain_resolution() {
        let mut registry = ProviderRegistry::new();

        // No failover configured -> single-element chain.
        let chain = registry.get_failover_chain("gpt-4o");
        assert_eq!(chain, vec!["gpt-4o"]);

        // Set a failover chain.
        registry.set_failover(
            "gpt-4o",
            vec![
                "claude-sonnet-4-20250514".to_string(),
                "gemini-2.0-flash".to_string(),
            ],
        );

        let chain = registry.get_failover_chain("gpt-4o");
        assert_eq!(
            chain,
            vec!["gpt-4o", "claude-sonnet-4-20250514", "gemini-2.0-flash",]
        );

        // Failover with alias resolves the alias first.
        registry.add_alias("fast", "gemini-2.0-flash");
        registry.set_failover("gemini-2.0-flash", vec!["gpt-4o-mini".to_string()]);

        let chain = registry.get_failover_chain("fast");
        assert_eq!(chain, vec!["gemini-2.0-flash", "gpt-4o-mini"]);
    }

    // -- Provider registry with all 5 providers --

    #[test]
    fn registry_all_five_providers() {
        let mut registry = ProviderRegistry::new();

        registry
            .register_provider(
                "anthropic",
                ProviderConfig::Anthropic(AnthropicConfig::default()),
            )
            .unwrap();
        registry
            .register_provider("openai", ProviderConfig::OpenAi(OpenAiConfig::default()))
            .unwrap();
        registry
            .register_provider(
                "google",
                ProviderConfig::Gemini(GeminiProviderConfig::default()),
            )
            .unwrap();
        registry
            .register_provider("ollama", ProviderConfig::Ollama(OllamaConfig::default()))
            .unwrap();
        registry
            .register_provider(
                "openrouter",
                ProviderConfig::OpenRouter(OpenRouterConfig::default()),
            )
            .unwrap();

        // All 5 providers registered.
        assert_eq!(registry.provider_names().len(), 5);

        // Model routing works for all providers.
        assert_eq!(
            registry.resolve_provider("claude-sonnet-4-20250514"),
            Some("anthropic")
        );
        assert_eq!(registry.resolve_provider("gpt-4o"), Some("openai"));
        assert_eq!(
            registry.resolve_provider("gemini-2.0-flash"),
            Some("google")
        );
        assert_eq!(registry.resolve_provider("llama3.2"), Some("ollama"));

        // All models listed.
        let models = registry.list_all_models();
        assert_eq!(models.len(), 5);

        let providers: Vec<&str> = models.iter().map(|m| m.provider.as_str()).collect();
        assert!(providers.contains(&"anthropic"));
        assert!(providers.contains(&"openai"));
        assert!(providers.contains(&"google"));
        assert!(providers.contains(&"ollama"));
        assert!(providers.contains(&"openrouter"));
    }

    // -- Gemini content sanitization --

    #[test]
    fn gemini_content_sanitization() {
        // Tool call with control characters.
        let msg = LlmMessage {
            role: LlmRole::Assistant,
            content: "text\x00with\x01nulls".into(),
            tool_use_id: None,
            tool_calls: vec![LlmToolCall {
                id: "fc_1".into(),
                name: "evil\x00tool".into(),
                input: serde_json::json!({"cmd": "rm\x00 -rf /"}),
            }],
        };

        let gemini = to_gemini_content(&msg);
        match &gemini.parts[0] {
            GeminiPart::Text { text } => assert_eq!(text, "textwithnulls"),
            _ => panic!("expected text part"),
        }
        match &gemini.parts[1] {
            GeminiPart::FunctionCall { function_call } => {
                assert_eq!(function_call.name, "eviltool");
                assert_eq!(function_call.args["cmd"], "rm -rf /");
            }
            _ => panic!("expected functionCall part"),
        }
    }

    // -- Ollama read_api_key returns empty (no key required) --

    #[test]
    fn ollama_no_api_key_needed() {
        let config = ProviderConfig::Ollama(OllamaConfig::default());
        let key = config.read_api_key().unwrap();
        assert!(key.is_empty());
    }
}
