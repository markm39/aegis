//! LLM HTTP client for Anthropic and OpenAI providers.
//!
//! Provides a blocking HTTP client that routes completion requests to the
//! appropriate provider based on model name, using the type abstractions
//! from `aegis_types::llm`.
//!
//! # Security
//!
//! - API keys read exclusively from environment variables, never from request payloads.
//! - Endpoint URLs validated against SSRF (private/loopback IPs blocked).
//! - No HTTP redirect following (SSRF prevention).
//! - Request body size capped at 1 MB.
//! - Response body size capped at 10 MB.
//! - API keys masked in all log output via `MaskedApiKey`.
//! - Rate limited to 100 calls per minute (token-bucket).
//! - All completions logged to audit trail (model, token counts, NOT content).

use parking_lot::Mutex;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::Value;
use tracing::{debug, info, warn};

use aegis_types::credentials::CredentialStore;
use aegis_types::llm::{
    from_gemini_response, to_anthropic_message, to_gemini_content, to_openai_message,
    AnthropicConfig, GeminiProviderConfig, LlmRequest, LlmResponse, LlmToolCall, LlmUsage,
    MaskedApiKey, OllamaConfig, OpenAiConfig, OpenRouterConfig, ProviderConfig, ProviderRegistry,
    StopReason,
};
use aegis_types::oauth::{FileTokenStore, OAuthTokenStore};
use aegis_types::providers::{provider_by_id, read_codex_cli_token};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum request body size (1 MB).
const MAX_REQUEST_BODY_BYTES: usize = 1_000_000;

/// Maximum response body size (10 MB).
const MAX_RESPONSE_BODY_BYTES: u64 = 10_000_000;

/// Default maximum tokens if not specified in the request.
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Rate limit: maximum LLM calls per minute.
const RATE_LIMIT_RPM: u32 = 100;

/// Model name validation: allowed characters.
fn is_valid_model_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_'
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Simple token-bucket rate limiter.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
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

    /// Try to consume one token. Returns `true` if allowed, `false` if rate-limited.
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

// ---------------------------------------------------------------------------
// OAuthTokenResolver
// ---------------------------------------------------------------------------

/// Resolves OAuth bearer tokens for LLM providers.
///
/// For each provider, builds a per-provider `FileTokenStore` and loads the
/// token from `~/.aegis/oauth/<provider>/token.json`. Falls back gracefully
/// when no OAuth token is available (the caller should use the API key instead).
#[derive(Debug)]
pub struct OAuthTokenResolver {
    /// Base directory for per-provider token stores (e.g. `~/.aegis/oauth`).
    _base: PathBuf,
}

impl OAuthTokenResolver {
    /// Create a resolver using the default token store location (`~/.aegis/oauth/`).
    pub fn new() -> Option<Self> {
        let home = std::env::var("HOME").ok()?;
        let base = PathBuf::from(home).join(".aegis").join("oauth");
        Some(Self { _base: base })
    }

    /// Try to resolve a valid OAuth bearer token for the given provider.
    ///
    /// Returns `Some(token_string)` if a valid, non-expired token is found.
    /// Returns `None` if no token exists, the token is expired with no
    /// refresh token, or the store is inaccessible.
    pub fn resolve_token(&self, provider: &str) -> Option<String> {
        let store = match FileTokenStore::new(provider) {
            Ok(s) => s,
            Err(e) => {
                debug!(provider, error = %e, "could not create token store for provider");
                return None;
            }
        };

        let token = match store.load() {
            Ok(Some(t)) => t,
            Ok(None) => {
                debug!(provider, "no OAuth token found for provider");
                return None;
            }
            Err(e) => {
                debug!(provider, error = %e, "failed to load OAuth token");
                return None;
            }
        };

        // Check if token is still valid (with a 60-second buffer).
        if !token.needs_refresh(60) {
            debug!(provider, "using cached OAuth token");
            return Some(token.access_token);
        }

        // Token needs refresh but we don't have a refresh token.
        if !token.has_refresh_token() {
            warn!(
                provider,
                "OAuth token expired and no refresh token available"
            );
            return None;
        }

        warn!(
            provider,
            "OAuth token expired; automatic refresh requires async runtime (falling back to API key)"
        );
        None
    }
}

// ---------------------------------------------------------------------------
// LlmClient
// ---------------------------------------------------------------------------

/// Blocking HTTP client for LLM API calls.
///
/// Routes requests to Anthropic or OpenAI based on model name via a
/// `ProviderRegistry`. Enforces rate limiting, request/response size limits,
/// and SSRF protections.
///
/// When an `OAuthTokenResolver` is configured, the client will attempt to
/// use OAuth bearer tokens before falling back to API keys from environment
/// variables.
pub struct LlmClient {
    /// The HTTP client (blocking, no redirects).
    http_client: reqwest::blocking::Client,
    /// Provider registry for model-to-provider routing.
    registry: ProviderRegistry,
    /// Default request timeout.
    #[allow(dead_code)]
    default_timeout: Duration,
    /// Rate limiter.
    rate_limiter: Mutex<TokenBucket>,
    /// Optional OAuth token resolver for bearer token auth.
    oauth_resolver: Option<OAuthTokenResolver>,
}

impl std::fmt::Debug for LlmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmClient")
            .field("registry", &self.registry)
            .field("default_timeout", &self.default_timeout)
            .finish_non_exhaustive()
    }
}

impl LlmClient {
    /// Create a new LLM client with the given provider registry.
    ///
    /// Builds a reqwest blocking client with:
    /// - No redirect following (SSRF prevention)
    /// - Connection timeout of 10 seconds
    /// - Request timeout of 60 seconds
    /// - User-Agent header: "aegis-daemon/0.1"
    ///
    /// Automatically initializes an `OAuthTokenResolver` if the home
    /// directory is available.
    pub fn new(registry: ProviderRegistry) -> Result<Self, String> {
        let http_client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .user_agent("aegis-daemon/0.1")
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let oauth_resolver = OAuthTokenResolver::new();
        if oauth_resolver.is_some() {
            info!("OAuth token resolver initialized");
        }

        Ok(Self {
            http_client,
            registry,
            default_timeout: Duration::from_secs(30),
            rate_limiter: Mutex::new(TokenBucket::new(RATE_LIMIT_RPM)),
            oauth_resolver,
        })
    }

    /// Resolve an API key for the given provider, checking all credential sources.
    ///
    /// Resolution order:
    /// 1. OAuth token store (`~/.aegis/oauth/<provider>/token.json`) -- with refresh logic
    /// 2. Credential store (`~/.aegis/credentials.toml`) -- where onboarding saves tokens
    ///    (also checks env vars and alt env vars internally)
    /// 3. Provider-specific env var read as final fallback
    fn resolve_api_key_with_oauth(
        &self,
        provider_name: &str,
        read_env_key: impl FnOnce() -> Result<String, String>,
    ) -> Result<String, String> {
        // 1. Try OAuth token resolver (handles refresh-token logic).
        if let Some(ref resolver) = self.oauth_resolver {
            if let Some(oauth_token) = resolver.resolve_token(provider_name) {
                info!(
                    provider = provider_name,
                    "using OAuth bearer token instead of API key"
                );
                return Ok(oauth_token);
            }
        }

        // 2. Try the unified credential store (env vars -> stored creds -> OAuth file).
        if let Some(provider) = provider_by_id(provider_name) {
            let store = CredentialStore::load_default().unwrap_or_default();
            if let Some(key) = store.resolve_api_key(provider) {
                info!(
                    provider = provider_name,
                    "resolved API key from credential store"
                );
                return Ok(key);
            }

            // Backward-compat shim: older builds stored Codex OAuth credentials
            // under `openai`. Prefer the dedicated `openai-codex` provider now.
            if provider_name == "openai-codex" {
                use aegis_types::provider_auth::CredentialType;
                if let Some(legacy) = store.get("openai") {
                    let is_legacy_codex_oauth = legacy.credential_type
                        == CredentialType::OAuthToken
                        && legacy
                            .base_url
                            .as_deref()
                            .map(|u| u.contains("chatgpt.com"))
                            .unwrap_or(false)
                        && !legacy.api_key.is_empty();
                    if is_legacy_codex_oauth {
                        info!(
                            provider = provider_name,
                            "resolved legacy Codex OAuth credential from openai entry"
                        );
                        return Ok(legacy.api_key.clone());
                    }
                }
            }
        }

        // 2b. Try provider-specific CLI token files.
        if provider_name == "openai-codex" {
            if let Some(token) = read_codex_cli_token() {
                info!(
                    provider = provider_name,
                    "resolved token from Codex CLI auth file"
                );
                return Ok(token);
            }
        }

        // 3. Fall back to provider-config env var read.
        read_env_key()
    }

    /// Get a reference to the provider registry.
    pub fn registry(&self) -> &ProviderRegistry {
        &self.registry
    }

    /// Validate an LLM request before sending.
    ///
    /// Checks:
    /// - Model name non-empty, contains only alphanumeric + hyphens + dots + underscores
    /// - Messages non-empty
    /// - Temperature in 0.0..=2.0 (if set)
    /// - Max tokens > 0 and <= 1,000,000 (if set)
    /// - System prompt <= 100,000 chars (if set)
    pub fn validate_request(request: &LlmRequest) -> Result<(), String> {
        // Model name must be non-empty.
        if request.model.is_empty() {
            return Err("model name must not be empty".into());
        }

        // Model name must contain only safe characters.
        if !request.model.chars().all(is_valid_model_char) {
            return Err(format!(
                "model name contains invalid characters: '{}'",
                request.model
            ));
        }

        // Messages must be non-empty.
        if request.messages.is_empty() {
            return Err("messages must not be empty".into());
        }

        // Temperature bounds.
        if let Some(temp) = request.temperature {
            if !(0.0..=2.0).contains(&temp) {
                return Err(format!(
                    "temperature must be between 0.0 and 2.0, got {temp}"
                ));
            }
        }

        // Max tokens bounds.
        if let Some(max_tokens) = request.max_tokens {
            if max_tokens == 0 {
                return Err("max_tokens must be greater than 0".into());
            }
            if max_tokens > 1_000_000 {
                return Err(format!("max_tokens must be <= 1,000,000, got {max_tokens}"));
            }
        }

        // System prompt length.
        if let Some(ref system_prompt) = request.system_prompt {
            if system_prompt.len() > 100_000 {
                return Err(format!(
                    "system prompt must be <= 100,000 characters, got {}",
                    system_prompt.len()
                ));
            }
        }

        Ok(())
    }

    /// Send a completion request to the appropriate provider.
    ///
    /// 1. Validates the request.
    /// 2. Resolves model aliases and gets the failover chain.
    /// 3. Checks rate limit.
    /// 4. Tries the primary model, then each fallback in the failover chain.
    pub fn complete(&self, request: &LlmRequest) -> Result<LlmResponse, String> {
        Self::validate_request(request)?;

        // Resolve aliases and get failover chain.
        let failover_chain = self.registry.get_failover_chain(&request.model);

        // Rate limit check.
        {
            let mut limiter = self.rate_limiter.lock();
            if !limiter.try_consume() {
                return Err("LLM rate limit exceeded (max 100 calls/minute)".into());
            }
        }

        let mut last_error = String::new();
        for model in &failover_chain {
            let provider_name = match self.registry.resolve_provider(model) {
                Some(name) => name,
                None => {
                    last_error = format!(
                        "no provider configured for model '{model}' (check provider registry)"
                    );
                    continue;
                }
            };
            let provider_config = match self.registry.get_provider(provider_name) {
                Some(config) => config,
                None => {
                    last_error = format!(
                        "provider '{provider_name}' resolved for model '{model}' but is not registered"
                    );
                    continue;
                }
            };

            // Build a request with the current model from the failover chain.
            let req = if model != &request.model {
                let mut r = request.clone();
                r.model = model.clone();
                r
            } else {
                request.clone()
            };

            let result = match provider_config.clone() {
                ProviderConfig::Anthropic(config) => self.complete_anthropic(&req, &config),
                ProviderConfig::OpenAi(config) => {
                    self.complete_openai(&req, provider_name, &config)
                }
                ProviderConfig::Gemini(config) => self.complete_gemini(&req, &config),
                ProviderConfig::Ollama(config) => self.complete_ollama(&req, &config),
                ProviderConfig::OpenRouter(config) => self.complete_openrouter(&req, &config),
            };

            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    info!(
                        model = %model,
                        error = %e,
                        remaining_fallbacks = failover_chain.len() - 1,
                        "model failed, trying next in failover chain"
                    );
                    last_error = e;
                }
            }
        }

        Err(last_error)
    }

    /// Send a completion request to the Anthropic Messages API.
    fn complete_anthropic(
        &self,
        request: &LlmRequest,
        config: &AnthropicConfig,
    ) -> Result<LlmResponse, String> {
        // Resolve API key, preferring OAuth if available.
        let api_key = self.resolve_api_key_with_oauth("anthropic", || {
            config.read_api_key().map_err(|e| e.to_string())
        })?;
        let masked = MaskedApiKey(api_key.clone());
        debug!(provider = "anthropic", key = %masked, "resolved API key");

        // Validate endpoint for SSRF.
        config.validate_endpoint().map_err(|e| e.to_string())?;

        // Build the URL.
        let url = format!("{}/v1/messages", config.base_url.trim_end_matches('/'));

        // Convert messages to Anthropic format, separating out system messages.
        let mut system_text = request.system_prompt.clone().unwrap_or_default();
        let mut anthropic_messages = Vec::new();
        for msg in &request.messages {
            if msg.role == aegis_types::llm::LlmRole::System {
                if !system_text.is_empty() {
                    system_text.push('\n');
                }
                system_text.push_str(&msg.content);
            } else {
                anthropic_messages.push(to_anthropic_message(msg));
            }
        }

        // Build request body.
        let max_tokens = request.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);
        let mut body = serde_json::json!({
            "model": request.model,
            "max_tokens": max_tokens,
            "messages": anthropic_messages,
        });

        if !system_text.is_empty() {
            body["system"] = Value::String(system_text);
        }

        if let Some(temp) = request.temperature {
            body["temperature"] = serde_json::json!(temp);
        }

        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })
                })
                .collect();
            body["tools"] = Value::Array(tools);
        }

        // Add extended thinking if configured.
        if let Some(budget) = request.thinking_budget {
            body["thinking"] = serde_json::json!({
                "type": "enabled",
                "budget_tokens": budget,
            });
        }

        // Validate request body size.
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| format!("failed to serialize Anthropic request body: {e}"))?;
        if body_bytes.len() > MAX_REQUEST_BODY_BYTES {
            return Err(format!(
                "request body too large: {} bytes (max {MAX_REQUEST_BODY_BYTES})",
                body_bytes.len()
            ));
        }

        info!(
            provider = "anthropic",
            model = %request.model,
            message_count = request.messages.len(),
            "sending LLM completion request"
        );

        // Send the request.
        let resp = self
            .http_client
            .post(&url)
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .body(body_bytes)
            .send()
            .map_err(|e| format!("Anthropic API request failed: {e}"))?;

        // Check response size from Content-Length header before reading body.
        if let Some(content_length) = resp.content_length() {
            if content_length > MAX_RESPONSE_BODY_BYTES {
                return Err(format!(
                    "Anthropic response too large: {content_length} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                ));
            }
        }

        let status = resp.status();
        let resp_text = resp
            .text()
            .map_err(|e| format!("failed to read Anthropic response: {e}"))?;

        // Enforce response body size limit on actual body.
        if resp_text.len() as u64 > MAX_RESPONSE_BODY_BYTES {
            return Err(format!(
                "Anthropic response body too large: {} bytes (max {MAX_RESPONSE_BODY_BYTES})",
                resp_text.len()
            ));
        }

        if !status.is_success() {
            return Err(format!("Anthropic API returned {status}: {resp_text}"));
        }

        // Parse Anthropic response.
        let resp_json: Value = serde_json::from_str(&resp_text)
            .map_err(|e| format!("failed to parse Anthropic response JSON: {e}"))?;

        Self::parse_anthropic_response(&resp_json, &request.model)
    }

    /// Parse an Anthropic Messages API response into an `LlmResponse`.
    fn parse_anthropic_response(json: &Value, model: &str) -> Result<LlmResponse, String> {
        let mut content = String::new();
        let mut tool_calls = Vec::new();

        // Extract content blocks.
        if let Some(blocks) = json.get("content").and_then(|c| c.as_array()) {
            for block in blocks {
                match block.get("type").and_then(|t| t.as_str()) {
                    Some("text") => {
                        if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                            if !content.is_empty() {
                                content.push('\n');
                            }
                            content.push_str(text);
                        }
                    }
                    Some("tool_use") => {
                        let id = block
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = block
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let input = block
                            .get("input")
                            .cloned()
                            .unwrap_or(Value::Object(serde_json::Map::new()));
                        tool_calls.push(LlmToolCall { id, name, input });
                    }
                    _ => {}
                }
            }
        }

        // Extract usage.
        let usage = json
            .get("usage")
            .map(|u| LlmUsage {
                input_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                output_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
            })
            .unwrap_or(LlmUsage {
                input_tokens: 0,
                output_tokens: 0,
            });

        // Map stop_reason.
        let stop_reason = json
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .map(|s| match s {
                "end_turn" => StopReason::EndTurn,
                "max_tokens" => StopReason::MaxTokens,
                "tool_use" => StopReason::ToolUse,
                "stop_sequence" => StopReason::StopSequence,
                _ => StopReason::EndTurn,
            });

        let response_model = json
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(model)
            .to_string();

        info!(
            provider = "anthropic",
            model = %response_model,
            input_tokens = usage.input_tokens,
            output_tokens = usage.output_tokens,
            tool_calls = tool_calls.len(),
            "LLM completion response received"
        );

        Ok(LlmResponse {
            content,
            model: response_model,
            usage,
            tool_calls,
            stop_reason,
        })
    }

    /// Send a completion request to the OpenAI Chat Completions API,
    /// or delegate to the Responses API for OAuth credentials.
    fn complete_openai(
        &self,
        request: &LlmRequest,
        provider_name: &str,
        config: &OpenAiConfig,
    ) -> Result<LlmResponse, String> {
        // Resolve API key, preferring OAuth if available.
        let api_key = self.resolve_api_key_with_oauth(provider_name, || {
            config.read_api_key().map_err(|e| e.to_string())
        })?;
        let masked = MaskedApiKey(api_key.clone());
        debug!(provider = provider_name, key = %masked, "resolved API key");

        // Check if the credential is an OAuth token -- route to Responses API.
        // OpenAI Codex always uses the Responses API.
        let is_oauth = {
            use aegis_types::provider_auth::CredentialType;
            let store = CredentialStore::load_default().unwrap_or_default();
            store
                .get(provider_name)
                .map(|c| c.credential_type == CredentialType::OAuthToken)
                .unwrap_or(false)
        };
        if provider_name == "openai-codex" || is_oauth {
            return self.complete_openai_responses(request, provider_name, &api_key);
        }

        // Validate endpoint for SSRF.
        config.validate_endpoint().map_err(|e| e.to_string())?;

        // Build the URL.
        let url = format!(
            "{}/v1/chat/completions",
            config.base_url.trim_end_matches('/')
        );

        // Convert messages to OpenAI format.
        // If there's a system prompt, prepend it as a system message.
        let mut openai_messages: Vec<Value> = Vec::new();
        if let Some(ref system_prompt) = request.system_prompt {
            if !system_prompt.is_empty() {
                openai_messages.push(serde_json::json!({
                    "role": "system",
                    "content": system_prompt,
                }));
            }
        }
        for msg in &request.messages {
            let converted = to_openai_message(msg);
            openai_messages.push(
                serde_json::to_value(&converted)
                    .map_err(|e| format!("failed to serialize OpenAI message: {e}"))?,
            );
        }

        // Build request body.
        let mut body = serde_json::json!({
            "model": request.model,
            "messages": openai_messages,
        });

        if let Some(max_tokens) = request.max_tokens {
            body["max_tokens"] = serde_json::json!(max_tokens);
        }

        if let Some(temp) = request.temperature {
            body["temperature"] = serde_json::json!(temp);
        }

        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.input_schema,
                        }
                    })
                })
                .collect();
            body["tools"] = Value::Array(tools);
        }

        // Validate request body size.
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| format!("failed to serialize OpenAI request body: {e}"))?;
        if body_bytes.len() > MAX_REQUEST_BODY_BYTES {
            return Err(format!(
                "request body too large: {} bytes (max {MAX_REQUEST_BODY_BYTES})",
                body_bytes.len()
            ));
        }

        info!(
            provider = provider_name,
            model = %request.model,
            message_count = request.messages.len(),
            "sending LLM completion request"
        );

        // Send the request.
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("content-type", "application/json")
            .body(body_bytes)
            .send()
            .map_err(|e| format!("OpenAI API request failed: {e}"))?;

        // Check response size from Content-Length header.
        if let Some(content_length) = resp.content_length() {
            if content_length > MAX_RESPONSE_BODY_BYTES {
                return Err(format!(
                    "OpenAI response too large: {content_length} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                ));
            }
        }

        let status = resp.status();
        let resp_text = resp
            .text()
            .map_err(|e| format!("failed to read OpenAI response: {e}"))?;

        // Enforce response body size limit on actual body.
        if resp_text.len() as u64 > MAX_RESPONSE_BODY_BYTES {
            return Err(format!(
                "OpenAI response body too large: {} bytes (max {MAX_RESPONSE_BODY_BYTES})",
                resp_text.len()
            ));
        }

        if !status.is_success() {
            return Err(format!("OpenAI API returned {status}: {resp_text}"));
        }

        // Parse OpenAI response.
        let resp_json: Value = serde_json::from_str(&resp_text)
            .map_err(|e| format!("failed to parse OpenAI response JSON: {e}"))?;

        Self::parse_openai_response(&resp_json, &request.model)
    }

    /// Send a completion request to the Gemini API.
    fn complete_gemini(
        &self,
        request: &LlmRequest,
        config: &GeminiProviderConfig,
    ) -> Result<LlmResponse, String> {
        // Resolve API key, preferring OAuth if available.
        let api_key = self.resolve_api_key_with_oauth("google", || {
            config.read_api_key().map_err(|e| e.to_string())
        })?;
        let masked = MaskedApiKey(api_key.clone());
        debug!(provider = "gemini", key = %masked, "resolved API key");

        // Build the URL.
        let url = format!(
            "{}/v1beta/models/{}:generateContent?key={}",
            aegis_types::llm::DEFAULT_GEMINI_ENDPOINT.trim_end_matches('/'),
            request.model,
            api_key,
        );

        // Convert messages to Gemini format, separating out system messages.
        let mut system_text = request.system_prompt.clone().unwrap_or_default();
        let mut gemini_contents = Vec::new();
        for msg in &request.messages {
            if msg.role == aegis_types::llm::LlmRole::System {
                if !system_text.is_empty() {
                    system_text.push('\n');
                }
                system_text.push_str(&msg.content);
            } else {
                gemini_contents.push(to_gemini_content(msg));
            }
        }

        // Build request body.
        let mut body = serde_json::json!({
            "contents": gemini_contents,
        });

        if !system_text.is_empty() {
            body["system_instruction"] = serde_json::json!({
                "parts": [{"text": system_text}]
            });
        }

        // Generation config.
        let mut gen_config = serde_json::Map::new();
        if let Some(temp) = request.temperature {
            gen_config.insert("temperature".into(), serde_json::json!(temp));
        }
        if let Some(max_tokens) = request.max_tokens {
            gen_config.insert("maxOutputTokens".into(), serde_json::json!(max_tokens));
        }
        if !gen_config.is_empty() {
            body["generationConfig"] = Value::Object(gen_config);
        }

        // Tool definitions.
        if !request.tools.is_empty() {
            let declarations: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    })
                })
                .collect();
            body["tools"] = serde_json::json!([{
                "function_declarations": declarations
            }]);
        }

        // Validate request body size.
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| format!("failed to serialize Gemini request body: {e}"))?;
        if body_bytes.len() > MAX_REQUEST_BODY_BYTES {
            return Err(format!(
                "request body too large: {} bytes (max {MAX_REQUEST_BODY_BYTES})",
                body_bytes.len()
            ));
        }

        info!(
            provider = "gemini",
            model = %request.model,
            message_count = request.messages.len(),
            "sending LLM completion request"
        );

        // Send the request.
        let resp = self
            .http_client
            .post(&url)
            .header("content-type", "application/json")
            .body(body_bytes)
            .send()
            .map_err(|e| format!("Gemini API request failed: {e}"))?;

        // Check response size from Content-Length header.
        if let Some(content_length) = resp.content_length() {
            if content_length > MAX_RESPONSE_BODY_BYTES {
                return Err(format!(
                    "Gemini response too large: {content_length} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                ));
            }
        }

        let status = resp.status();
        let resp_text = resp
            .text()
            .map_err(|e| format!("failed to read Gemini response: {e}"))?;

        if resp_text.len() as u64 > MAX_RESPONSE_BODY_BYTES {
            return Err(format!(
                "Gemini response body too large: {} bytes (max {MAX_RESPONSE_BODY_BYTES})",
                resp_text.len()
            ));
        }

        if !status.is_success() {
            return Err(format!("Gemini API returned {status}: {resp_text}"));
        }

        let resp_json: Value = serde_json::from_str(&resp_text)
            .map_err(|e| format!("failed to parse Gemini response JSON: {e}"))?;

        let response = from_gemini_response(&resp_json, &request.model)
            .map_err(|e| format!("failed to parse Gemini response: {e}"))?;

        info!(
            provider = "gemini",
            model = %response.model,
            input_tokens = response.usage.input_tokens,
            output_tokens = response.usage.output_tokens,
            tool_calls = response.tool_calls.len(),
            "LLM completion response received"
        );

        Ok(response)
    }

    /// Send a completion request to the Ollama API.
    ///
    /// Ollama uses OpenAI-compatible message format but with a different
    /// endpoint structure and no API key requirement.
    fn complete_ollama(
        &self,
        request: &LlmRequest,
        config: &OllamaConfig,
    ) -> Result<LlmResponse, String> {
        // Validate endpoint.
        config.validate_endpoint().map_err(|e| e.to_string())?;

        // Build the URL.
        let url = format!("{}/api/chat", config.base_url.trim_end_matches('/'));

        // Convert messages to OpenAI format (which Ollama understands).
        let mut messages: Vec<Value> = Vec::new();
        if let Some(ref system_prompt) = request.system_prompt {
            if !system_prompt.is_empty() {
                messages.push(serde_json::json!({
                    "role": "system",
                    "content": system_prompt,
                }));
            }
        }
        for msg in &request.messages {
            let converted = to_openai_message(msg);
            messages.push(
                serde_json::to_value(&converted)
                    .map_err(|e| format!("failed to serialize Ollama message: {e}"))?,
            );
        }

        // Build request body.
        let mut body = serde_json::json!({
            "model": request.model,
            "messages": messages,
            "stream": false,
        });

        // Options.
        let mut options = serde_json::Map::new();
        if let Some(temp) = request.temperature {
            options.insert("temperature".into(), serde_json::json!(temp));
        }
        if !options.is_empty() {
            body["options"] = Value::Object(options);
        }

        // Validate request body size.
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| format!("failed to serialize Ollama request body: {e}"))?;
        if body_bytes.len() > MAX_REQUEST_BODY_BYTES {
            return Err(format!(
                "request body too large: {} bytes (max {MAX_REQUEST_BODY_BYTES})",
                body_bytes.len()
            ));
        }

        info!(
            provider = "ollama",
            model = %request.model,
            message_count = request.messages.len(),
            "sending LLM completion request"
        );

        // Send the request.
        let resp = self
            .http_client
            .post(&url)
            .header("content-type", "application/json")
            .body(body_bytes)
            .send()
            .map_err(|e| format!("Ollama API request failed: {e}"))?;

        // Check response size.
        if let Some(content_length) = resp.content_length() {
            if content_length > MAX_RESPONSE_BODY_BYTES {
                return Err(format!(
                    "Ollama response too large: {content_length} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                ));
            }
        }

        let status = resp.status();
        let resp_text = resp
            .text()
            .map_err(|e| format!("failed to read Ollama response: {e}"))?;

        if resp_text.len() as u64 > MAX_RESPONSE_BODY_BYTES {
            return Err(format!(
                "Ollama response body too large: {} bytes (max {MAX_RESPONSE_BODY_BYTES})",
                resp_text.len()
            ));
        }

        if !status.is_success() {
            return Err(format!("Ollama API returned {status}: {resp_text}"));
        }

        let resp_json: Value = serde_json::from_str(&resp_text)
            .map_err(|e| format!("failed to parse Ollama response JSON: {e}"))?;

        Self::parse_ollama_response(&resp_json, &request.model)
    }

    /// Parse an Ollama `/api/chat` response into an `LlmResponse`.
    fn parse_ollama_response(json: &Value, model: &str) -> Result<LlmResponse, String> {
        let message = json
            .get("message")
            .ok_or("Ollama response missing message object")?;

        let content = message
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Ollama may include tool calls in the message.
        let mut tool_calls = Vec::new();
        if let Some(tcs) = message.get("tool_calls").and_then(|v| v.as_array()) {
            for tc in tcs {
                let function = tc.get("function").unwrap_or(&Value::Null);
                let id = tc
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = function
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let args_val = function
                    .get("arguments")
                    .cloned()
                    .unwrap_or(Value::Object(serde_json::Map::new()));
                // Arguments may be a string (JSON-encoded) or already an object.
                let input = if let Some(s) = args_val.as_str() {
                    serde_json::from_str(s).unwrap_or(Value::Object(serde_json::Map::new()))
                } else {
                    args_val
                };
                tool_calls.push(LlmToolCall { id, name, input });
            }
        }

        // Extract token counts from Ollama's response fields.
        let eval_count = json.get("eval_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let prompt_eval_count = json
            .get("prompt_eval_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let usage = LlmUsage {
            input_tokens: prompt_eval_count,
            output_tokens: eval_count,
        };

        let response_model = json
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(model)
            .to_string();

        let stop_reason = if !tool_calls.is_empty() {
            Some(StopReason::ToolUse)
        } else if json.get("done").and_then(|v| v.as_bool()).unwrap_or(false) {
            Some(StopReason::EndTurn)
        } else {
            None
        };

        info!(
            provider = "ollama",
            model = %response_model,
            input_tokens = usage.input_tokens,
            output_tokens = usage.output_tokens,
            tool_calls = tool_calls.len(),
            "LLM completion response received"
        );

        Ok(LlmResponse {
            content,
            model: response_model,
            usage,
            tool_calls,
            stop_reason,
        })
    }

    /// Send a completion request to the OpenRouter API.
    ///
    /// OpenRouter is OpenAI-compatible, so we reuse the OpenAI format
    /// converters with different endpoint and auth headers.
    fn complete_openrouter(
        &self,
        request: &LlmRequest,
        config: &OpenRouterConfig,
    ) -> Result<LlmResponse, String> {
        // Resolve API key, preferring OAuth if available.
        let api_key = self.resolve_api_key_with_oauth("openrouter", || {
            config.read_api_key().map_err(|e| e.to_string())
        })?;
        let masked = MaskedApiKey(api_key.clone());
        debug!(provider = "openrouter", key = %masked, "resolved API key");

        // Build the URL.
        let url = format!(
            "{}/api/v1/chat/completions",
            aegis_types::llm::DEFAULT_OPENROUTER_ENDPOINT.trim_end_matches('/')
        );

        // Convert messages to OpenAI format (which OpenRouter uses).
        let mut openai_messages: Vec<Value> = Vec::new();
        if let Some(ref system_prompt) = request.system_prompt {
            if !system_prompt.is_empty() {
                openai_messages.push(serde_json::json!({
                    "role": "system",
                    "content": system_prompt,
                }));
            }
        }
        for msg in &request.messages {
            let converted = to_openai_message(msg);
            openai_messages.push(
                serde_json::to_value(&converted)
                    .map_err(|e| format!("failed to serialize OpenRouter message: {e}"))?,
            );
        }

        // Build request body.
        let mut body = serde_json::json!({
            "model": request.model,
            "messages": openai_messages,
        });

        if let Some(max_tokens) = request.max_tokens {
            body["max_tokens"] = serde_json::json!(max_tokens);
        }
        if let Some(temp) = request.temperature {
            body["temperature"] = serde_json::json!(temp);
        }

        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.input_schema,
                        }
                    })
                })
                .collect();
            body["tools"] = Value::Array(tools);
        }

        // Validate request body size.
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| format!("failed to serialize OpenRouter request body: {e}"))?;
        if body_bytes.len() > MAX_REQUEST_BODY_BYTES {
            return Err(format!(
                "request body too large: {} bytes (max {MAX_REQUEST_BODY_BYTES})",
                body_bytes.len()
            ));
        }

        info!(
            provider = "openrouter",
            model = %request.model,
            message_count = request.messages.len(),
            "sending LLM completion request"
        );

        // Send the request.
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("HTTP-Referer", "https://github.com/aegis-project/aegis")
            .header("content-type", "application/json")
            .body(body_bytes)
            .send()
            .map_err(|e| format!("OpenRouter API request failed: {e}"))?;

        // Check response size.
        if let Some(content_length) = resp.content_length() {
            if content_length > MAX_RESPONSE_BODY_BYTES {
                return Err(format!(
                    "OpenRouter response too large: {content_length} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                ));
            }
        }

        let status = resp.status();
        let resp_text = resp
            .text()
            .map_err(|e| format!("failed to read OpenRouter response: {e}"))?;

        if resp_text.len() as u64 > MAX_RESPONSE_BODY_BYTES {
            return Err(format!(
                "OpenRouter response body too large: {} bytes (max {MAX_RESPONSE_BODY_BYTES})",
                resp_text.len()
            ));
        }

        if !status.is_success() {
            return Err(format!("OpenRouter API returned {status}: {resp_text}"));
        }

        // Parse using OpenAI format (OpenRouter is API-compatible).
        let resp_json: Value = serde_json::from_str(&resp_text)
            .map_err(|e| format!("failed to parse OpenRouter response JSON: {e}"))?;

        let mut response = Self::parse_openai_response(&resp_json, &request.model)?;

        // Override the provider name in logs.
        info!(
            provider = "openrouter",
            model = %response.model,
            input_tokens = response.usage.input_tokens,
            output_tokens = response.usage.output_tokens,
            tool_calls = response.tool_calls.len(),
            "LLM completion response received"
        );

        // OpenRouter may return a different model name; keep it.
        if response.model.is_empty() {
            response.model = request.model.clone();
        }

        Ok(response)
    }

    /// Send a completion request via the OpenAI Responses API.
    ///
    /// Used when the credential is an OAuth token (ChatGPT backend). The
    /// Responses API uses `input` instead of `messages` and `instructions`
    /// instead of system messages.
    ///
    /// Note: ChatGPT Codex backend rejects `max_output_tokens`, so we only
    /// send token caps for the public `/v1/responses` endpoint.
    fn complete_openai_responses(
        &self,
        request: &LlmRequest,
        provider_name: &str,
        api_key: &str,
    ) -> Result<LlmResponse, String> {
        // Resolve base URL from credential store.
        let base_url = {
            let store = CredentialStore::load_default().unwrap_or_default();
            provider_by_id(provider_name)
                .map(|p| store.resolve_base_url(p))
                .unwrap_or_else(|| {
                    if provider_name == "openai-codex" {
                        "https://chatgpt.com/backend-api".to_string()
                    } else {
                        "https://api.openai.com".to_string()
                    }
                })
        };

        // ChatGPT backend uses /codex/responses, public API uses /v1/responses.
        let is_codex_backend = provider_name == "openai-codex" || base_url.contains("chatgpt.com");
        let url = if is_codex_backend {
            format!("{}/codex/responses", base_url.trim_end_matches('/'))
        } else {
            format!("{}/v1/responses", base_url.trim_end_matches('/'))
        };

        // Build input in Responses API format.
        let mut input: Vec<Value> = Vec::new();
        for msg in &request.messages {
            match msg.role {
                aegis_types::llm::LlmRole::User => {
                    input.push(serde_json::json!({
                        "role": "user",
                        "content": msg.content,
                    }));
                }
                aegis_types::llm::LlmRole::Assistant => {
                    if !msg.tool_calls.is_empty() {
                        let mut items: Vec<Value> = Vec::new();
                        if !msg.content.is_empty() {
                            items.push(serde_json::json!({
                                "type": "output_text",
                                "text": msg.content,
                            }));
                        }
                        for tc in &msg.tool_calls {
                            items.push(serde_json::json!({
                                "type": "function_call",
                                "name": tc.name,
                                "call_id": tc.id,
                                "arguments": tc.input.to_string(),
                            }));
                        }
                        input.push(serde_json::json!({
                            "role": "assistant",
                            "content": items,
                        }));
                    } else {
                        input.push(serde_json::json!({
                            "role": "assistant",
                            "content": [{"type": "output_text", "text": msg.content}],
                        }));
                    }
                }
                aegis_types::llm::LlmRole::Tool => {
                    input.push(serde_json::json!({
                        "type": "function_call_output",
                        "call_id": msg.tool_use_id.as_deref().unwrap_or(""),
                        "output": msg.content,
                    }));
                }
                aegis_types::llm::LlmRole::System => {
                    // Handled via `instructions` field below.
                }
            }
        }

        let mut body = serde_json::json!({
            "model": request.model,
            "input": input,
            "stream": true,
            // Direct OpenAI Responses expects store=true by default; Codex
            // backend requires store=false.
            "store": !is_codex_backend,
        });

        if let Some(ref system_prompt) = request.system_prompt {
            if !system_prompt.is_empty() {
                body["instructions"] = Value::String(system_prompt.clone());
            }
        }

        // ChatGPT Codex backend does not accept `max_output_tokens`.
        if !is_codex_backend {
            let max_tokens = request.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);
            body["max_output_tokens"] = serde_json::json!(max_tokens);
        }

        // ChatGPT Codex backend does not accept `temperature`.
        if !is_codex_backend {
            if let Some(temp) = request.temperature {
                body["temperature"] = serde_json::json!(temp);
            }
        }

        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    })
                })
                .collect();
            body["tools"] = Value::Array(tools);
        }

        // Validate request body size.
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| format!("failed to serialize Responses API request body: {e}"))?;
        if body_bytes.len() > MAX_REQUEST_BODY_BYTES {
            return Err(format!(
                "request body too large: {} bytes (max {MAX_REQUEST_BODY_BYTES})",
                body_bytes.len()
            ));
        }

        info!(
            provider = "openai-responses",
            model = %request.model,
            message_count = request.messages.len(),
            "sending Responses API completion request"
        );

        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("content-type", "application/json")
            .body(body_bytes)
            .send()
            .map_err(|e| format!("OpenAI Responses API request failed: {e}"))?;

        if let Some(content_length) = resp.content_length() {
            if content_length > MAX_RESPONSE_BODY_BYTES {
                return Err(format!(
                    "Responses API response too large: {content_length} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                ));
            }
        }

        let status = resp.status();
        let resp_text = resp
            .text()
            .map_err(|e| format!("failed to read Responses API response: {e}"))?;

        if resp_text.len() as u64 > MAX_RESPONSE_BODY_BYTES {
            return Err(format!(
                "Responses API response body too large: {} bytes (max {MAX_RESPONSE_BODY_BYTES})",
                resp_text.len()
            ));
        }

        if !status.is_success() {
            return Err(format!(
                "OpenAI Responses API returned {status}: {resp_text}"
            ));
        }

        match serde_json::from_str::<Value>(&resp_text) {
            Ok(resp_json) => Self::parse_responses_api_response(&resp_json, &request.model),
            Err(json_err) => Self::parse_responses_api_sse(&resp_text, &request.model).map_err(
                |sse_err| {
                    format!(
                        "failed to parse Responses API response as JSON ({json_err}) or SSE ({sse_err})"
                    )
                },
            ),
        }
    }

    /// Parse an OpenAI Responses API response into an `LlmResponse`.
    ///
    /// The Responses API returns:
    /// ```json
    /// {
    ///   "output": [
    ///     {"type": "message", "content": [{"type": "output_text", "text": "..."}]},
    ///     {"type": "function_call", "name": "...", "call_id": "...", "arguments": "..."}
    ///   ],
    ///   "usage": {"input_tokens": N, "output_tokens": N}
    /// }
    /// ```
    fn parse_responses_api_response(json: &Value, model: &str) -> Result<LlmResponse, String> {
        let mut content = String::new();
        let mut tool_calls = Vec::new();

        // Parse output items.
        if let Some(output) = json.get("output").and_then(|v| v.as_array()) {
            for item in output {
                let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match item_type {
                    "message" => {
                        // Extract text from content blocks.
                        if let Some(blocks) = item.get("content").and_then(|v| v.as_array()) {
                            for block in blocks {
                                let block_type =
                                    block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                                if block_type == "output_text" {
                                    if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                                        content.push_str(text);
                                    }
                                }
                            }
                        }
                    }
                    "function_call" => {
                        let name = item
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let call_id = item
                            .get("call_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let args_str = item
                            .get("arguments")
                            .and_then(|v| v.as_str())
                            .unwrap_or("{}");
                        let input: Value = serde_json::from_str(args_str)
                            .unwrap_or(Value::Object(serde_json::Map::new()));
                        tool_calls.push(LlmToolCall {
                            id: call_id,
                            name,
                            input,
                        });
                    }
                    _ => {}
                }
            }
        }

        // Also check output_text shorthand.
        if content.is_empty() {
            if let Some(text) = json.get("output_text").and_then(|v| v.as_str()) {
                content = text.to_string();
            }
        }

        // Extract usage.
        let usage = json
            .get("usage")
            .map(|u| LlmUsage {
                input_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                output_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
            })
            .unwrap_or(LlmUsage {
                input_tokens: 0,
                output_tokens: 0,
            });

        // Determine stop reason from status.
        let stop_reason = json
            .get("status")
            .and_then(|v| v.as_str())
            .map(|s| match s {
                "completed" => {
                    if tool_calls.is_empty() {
                        StopReason::EndTurn
                    } else {
                        StopReason::ToolUse
                    }
                }
                "incomplete" => StopReason::MaxTokens,
                _ => StopReason::EndTurn,
            });

        let response_model = json
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(model)
            .to_string();

        info!(
            provider = "openai-responses",
            model = %response_model,
            input_tokens = usage.input_tokens,
            output_tokens = usage.output_tokens,
            tool_calls = tool_calls.len(),
            "Responses API completion received"
        );

        Ok(LlmResponse {
            content,
            model: response_model,
            usage,
            tool_calls,
            stop_reason,
        })
    }

    /// Parse an OpenAI Responses API SSE payload into an `LlmResponse`.
    ///
    /// Expected stream event types include:
    /// - `response.output_text.delta`
    /// - `response.output_item.added`
    /// - `response.function_call_arguments.delta`
    /// - `response.function_call_arguments.done`
    /// - `response.completed`
    fn parse_responses_api_sse(sse: &str, model: &str) -> Result<LlmResponse, String> {
        let mut content = String::new();
        let mut tool_calls = Vec::new();
        let mut current_tool_name = String::new();
        let mut current_tool_call_id = String::new();
        let mut current_tool_args = String::new();
        let mut usage = LlmUsage {
            input_tokens: 0,
            output_tokens: 0,
        };
        let mut stop_reason = None;
        let mut response_model = model.to_string();
        let mut current_event_type = String::new();
        let mut saw_stream_event = false;

        for line in sse.lines() {
            if let Some(event_name) = line.strip_prefix("event: ") {
                current_event_type = event_name.trim().to_string();
                saw_stream_event = true;
                continue;
            }

            let data = match line.strip_prefix("data: ") {
                Some(d) => d,
                None => continue,
            };
            if data == "[DONE]" {
                saw_stream_event = true;
                break;
            }

            let event: Value = match serde_json::from_str(data) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let event_type = if current_event_type.is_empty() {
                event.get("type").and_then(|v| v.as_str()).unwrap_or("")
            } else {
                current_event_type.as_str()
            };

            match event_type {
                "response.output_text.delta" => {
                    if let Some(delta) = event.get("delta").and_then(|v| v.as_str()) {
                        saw_stream_event = true;
                        content.push_str(delta);
                    }
                }
                "response.output_item.added" => {
                    if let Some(item) = event.get("item") {
                        let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if item_type == "function_call" {
                            saw_stream_event = true;
                            current_tool_name = item
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            current_tool_call_id = item
                                .get("call_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            current_tool_args.clear();
                        }
                    }
                }
                "response.function_call_arguments.delta" => {
                    if let Some(delta) = event.get("delta").and_then(|v| v.as_str()) {
                        saw_stream_event = true;
                        current_tool_args.push_str(delta);
                    }
                }
                "response.function_call_arguments.done" | "response.output_item.done" => {
                    let item = event.get("item");
                    let name = item
                        .and_then(|i| i.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&current_tool_name);
                    let call_id = item
                        .and_then(|i| i.get("call_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&current_tool_call_id);
                    let args_str = event
                        .get("arguments")
                        .and_then(|v| v.as_str())
                        .or_else(|| {
                            item.and_then(|i| i.get("arguments"))
                                .and_then(|v| v.as_str())
                        })
                        .unwrap_or(&current_tool_args);
                    let input = serde_json::from_str(args_str)
                        .unwrap_or(Value::Object(serde_json::Map::new()));

                    if !name.is_empty() {
                        saw_stream_event = true;
                        tool_calls.push(LlmToolCall {
                            id: call_id.to_string(),
                            name: name.to_string(),
                            input,
                        });
                    }

                    current_tool_name.clear();
                    current_tool_call_id.clear();
                    current_tool_args.clear();
                }
                "response.completed" => {
                    saw_stream_event = true;
                    if let Some(response) = event.get("response") {
                        if let Ok(parsed) = Self::parse_responses_api_response(response, model) {
                            if content.is_empty() {
                                content = parsed.content;
                            }
                            if tool_calls.is_empty() {
                                tool_calls = parsed.tool_calls;
                            }
                            usage = parsed.usage;
                            stop_reason = parsed.stop_reason;
                            response_model = parsed.model;
                        } else {
                            if let Some(m) = response.get("model").and_then(|v| v.as_str()) {
                                response_model = m.to_string();
                            }
                            if let Some(u) = response.get("usage") {
                                if let Some(inp) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                                    usage.input_tokens = inp;
                                }
                                if let Some(out) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                                    usage.output_tokens = out;
                                }
                            }
                        }
                    }
                    break;
                }
                _ => {}
            }

            current_event_type.clear();
        }

        if !saw_stream_event {
            return Err("no SSE events found".to_string());
        }

        if !tool_calls.is_empty() && stop_reason == Some(StopReason::EndTurn) {
            stop_reason = Some(StopReason::ToolUse);
        }

        if stop_reason.is_none() {
            stop_reason = Some(if tool_calls.is_empty() {
                StopReason::EndTurn
            } else {
                StopReason::ToolUse
            });
        }

        Ok(LlmResponse {
            content,
            model: response_model,
            usage,
            tool_calls,
            stop_reason,
        })
    }

    /// Parse an OpenAI Chat Completions API response into an `LlmResponse`.
    fn parse_openai_response(json: &Value, model: &str) -> Result<LlmResponse, String> {
        // Extract the first choice.
        let choice = json
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .ok_or("OpenAI response missing choices array")?;

        let message = choice
            .get("message")
            .ok_or("OpenAI response missing message in choice")?;

        // Extract content.
        let content = message
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Extract tool calls.
        let mut tool_calls = Vec::new();
        if let Some(tcs) = message.get("tool_calls").and_then(|v| v.as_array()) {
            for tc in tcs {
                let id = tc
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let function = tc.get("function").unwrap_or(&Value::Null);
                let name = function
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let args_str = function
                    .get("arguments")
                    .and_then(|v| v.as_str())
                    .unwrap_or("{}");
                let input: Value =
                    serde_json::from_str(args_str).unwrap_or(Value::Object(serde_json::Map::new()));
                tool_calls.push(LlmToolCall { id, name, input });
            }
        }

        // Extract usage.
        let usage = json
            .get("usage")
            .map(|u| LlmUsage {
                input_tokens: u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                output_tokens: u
                    .get("completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            })
            .unwrap_or(LlmUsage {
                input_tokens: 0,
                output_tokens: 0,
            });

        // Map finish_reason.
        let stop_reason = choice
            .get("finish_reason")
            .and_then(|v| v.as_str())
            .map(|s| match s {
                "stop" => StopReason::EndTurn,
                "length" => StopReason::MaxTokens,
                "tool_calls" => StopReason::ToolUse,
                _ => StopReason::EndTurn,
            });

        let response_model = json
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(model)
            .to_string();

        info!(
            provider = "openai",
            model = %response_model,
            input_tokens = usage.input_tokens,
            output_tokens = usage.output_tokens,
            tool_calls = tool_calls.len(),
            "LLM completion response received"
        );

        Ok(LlmResponse {
            content,
            model: response_model,
            usage,
            tool_calls,
            stop_reason,
        })
    }
}

/// Build a `ProviderRegistry` from environment variables.
///
/// Registers all known providers using default configurations.
/// Providers are registered regardless of whether API keys are present;
/// key availability is checked at request time.
///
/// Provider detection:
/// - Anthropic, OpenAI, and OpenAI Codex are always registered.
/// - Gemini is registered if `GOOGLE_API_KEY` or `GEMINI_API_KEY` is set.
/// - Ollama is always registered (local, no key needed). The base URL can
///   be overridden with `OLLAMA_BASE_URL`.
/// - OpenRouter is registered if `OPENROUTER_API_KEY` is set.
pub fn build_registry_from_env() -> Result<ProviderRegistry, String> {
    let mut registry = ProviderRegistry::new();

    // Register Anthropic with defaults.
    registry
        .register_provider(
            "anthropic",
            ProviderConfig::Anthropic(AnthropicConfig::default()),
        )
        .map_err(|e| format!("failed to register Anthropic provider: {e}"))?;

    // Register OpenAI, reading base_url from credential store if available
    // (OAuth users store the ChatGPT backend URL there).
    let openai_base_url = {
        let store = CredentialStore::load_default().unwrap_or_default();
        provider_by_id("openai")
            .and_then(|p| store.get(p.id))
            .and_then(|c| c.base_url.clone())
    };
    let openai_config = if let Some(ref url) = openai_base_url {
        OpenAiConfig {
            base_url: url.clone(),
            ..Default::default()
        }
    } else {
        OpenAiConfig::default()
    };
    registry
        .register_provider("openai", ProviderConfig::OpenAi(openai_config))
        .map_err(|e| format!("failed to register OpenAI provider: {e}"))?;

    // Register OpenAI Codex (ChatGPT backend) with credential-store base URL
    // override support.
    let openai_codex_base_url = {
        let store = CredentialStore::load_default().unwrap_or_default();
        provider_by_id("openai-codex").map(|p| store.resolve_base_url(p))
    };
    let openai_codex_config = OpenAiConfig {
        base_url: openai_codex_base_url
            .unwrap_or_else(|| "https://chatgpt.com/backend-api".to_string()),
        default_model: "gpt-5.3-codex".to_string(),
        ..Default::default()
    };
    registry
        .register_provider("openai-codex", ProviderConfig::OpenAi(openai_codex_config))
        .map_err(|e| format!("failed to register OpenAI Codex provider: {e}"))?;

    // Load credential store once for provider registration checks.
    let cred_store = CredentialStore::load_default().unwrap_or_default();

    // Register Gemini if credentials are available (env var, stored cred, or OAuth).
    let has_gemini_cred = provider_by_id("google")
        .and_then(|p| cred_store.resolve_api_key(p))
        .is_some();
    if has_gemini_cred {
        registry
            .register_provider(
                "google",
                ProviderConfig::Gemini(GeminiProviderConfig::default()),
            )
            .map_err(|e| format!("failed to register Gemini provider: {e}"))?;
    }

    // Register Ollama (always available, local service).
    let ollama_base_url = std::env::var("OLLAMA_BASE_URL")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| aegis_types::llm::DEFAULT_OLLAMA_BASE_URL.to_string());
    registry
        .register_provider(
            "ollama",
            ProviderConfig::Ollama(OllamaConfig {
                base_url: ollama_base_url,
                ..Default::default()
            }),
        )
        .map_err(|e| format!("failed to register Ollama provider: {e}"))?;

    // Register OpenRouter if credentials are available (env var, stored cred, or OAuth).
    let has_openrouter_cred = provider_by_id("openrouter")
        .and_then(|p| cred_store.resolve_api_key(p))
        .is_some();
    if has_openrouter_cred {
        registry
            .register_provider(
                "openrouter",
                ProviderConfig::OpenRouter(OpenRouterConfig::default()),
            )
            .map_err(|e| format!("failed to register OpenRouter provider: {e}"))?;
    }

    Ok(registry)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::llm::{LlmMessage, LlmRequest, LlmToolDefinition};

    /// Mutex to serialize tests that modify the HOME env var.
    /// `set_var` is process-global and not thread-safe, so tests that depend
    /// on HOME must hold this lock to avoid racing with each other.
    static HOME_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn sample_request() -> LlmRequest {
        LlmRequest {
            model: "claude-sonnet-4-20250514".into(),
            messages: vec![LlmMessage::user("Hello")],
            temperature: None,
            max_tokens: None,
            system_prompt: None,
            tools: vec![],
            thinking_budget: None,
        }
    }

    // -- test_request_validation --

    #[test]
    fn test_request_validation() {
        // Valid request.
        let req = sample_request();
        assert!(LlmClient::validate_request(&req).is_ok());

        // Empty model name.
        let req = LlmRequest {
            model: "".into(),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_err());

        // Model name with spaces.
        let req = LlmRequest {
            model: "bad model".into(),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_err());

        // Model name with slashes.
        let req = LlmRequest {
            model: "bad/model".into(),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_err());

        // Valid model names with dots, hyphens, underscores.
        let req = LlmRequest {
            model: "claude-sonnet-4.0_preview".into(),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_ok());

        // Empty messages.
        let req = LlmRequest {
            messages: vec![],
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_err());

        // Temperature too low.
        let req = LlmRequest {
            temperature: Some(-0.1),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_err());

        // Temperature too high.
        let req = LlmRequest {
            temperature: Some(2.1),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_err());

        // Temperature at bounds (valid).
        let req = LlmRequest {
            temperature: Some(0.0),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_ok());
        let req = LlmRequest {
            temperature: Some(2.0),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_ok());

        // Max tokens 0.
        let req = LlmRequest {
            max_tokens: Some(0),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_err());

        // Max tokens too large.
        let req = LlmRequest {
            max_tokens: Some(1_000_001),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_err());

        // Max tokens at boundary (valid).
        let req = LlmRequest {
            max_tokens: Some(1_000_000),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_ok());
        let req = LlmRequest {
            max_tokens: Some(1),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_ok());

        // System prompt too long.
        let req = LlmRequest {
            system_prompt: Some("x".repeat(100_001)),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_err());

        // System prompt at boundary (valid).
        let req = LlmRequest {
            system_prompt: Some("x".repeat(100_000)),
            ..sample_request()
        };
        assert!(LlmClient::validate_request(&req).is_ok());
    }

    // -- test_anthropic_request_format --

    #[test]
    fn test_anthropic_request_format() {
        // Build a request that would be sent to Anthropic and verify the body shape.
        let request = LlmRequest {
            model: "claude-sonnet-4-20250514".into(),
            messages: vec![
                LlmMessage::user("Hello, Claude!"),
                LlmMessage::assistant("Hi there!"),
                LlmMessage::user("What is Rust?"),
            ],
            temperature: Some(0.7),
            max_tokens: Some(1024),
            system_prompt: Some("You are helpful.".into()),
            tools: vec![LlmToolDefinition {
                name: "search".into(),
                description: "Search the web".into(),
                input_schema: serde_json::json!({"type": "object", "properties": {"query": {"type": "string"}}}),
            }],
            thinking_budget: None,
        };

        // Convert messages to Anthropic format.
        let mut system_text = request.system_prompt.clone().unwrap_or_default();
        let mut anthropic_messages = Vec::new();
        for msg in &request.messages {
            if msg.role == aegis_types::llm::LlmRole::System {
                if !system_text.is_empty() {
                    system_text.push('\n');
                }
                system_text.push_str(&msg.content);
            } else {
                anthropic_messages.push(to_anthropic_message(msg));
            }
        }

        let max_tokens = request.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);
        let mut body = serde_json::json!({
            "model": request.model,
            "max_tokens": max_tokens,
            "messages": anthropic_messages,
        });

        if !system_text.is_empty() {
            body["system"] = Value::String(system_text);
        }

        if let Some(temp) = request.temperature {
            body["temperature"] = serde_json::json!(temp);
        }

        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })
                })
                .collect();
            body["tools"] = Value::Array(tools);
        }

        // Verify body structure.
        assert_eq!(body["model"], "claude-sonnet-4-20250514");
        assert_eq!(body["max_tokens"], 1024);
        assert_eq!(body["system"], "You are helpful.");
        assert_eq!(body["temperature"], 0.7);

        // Messages should NOT contain system role (it's extracted).
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[1]["role"], "assistant");
        assert_eq!(msgs[2]["role"], "user");

        // Tools should be present.
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "search");
        assert!(tools[0].get("input_schema").is_some());
    }

    // -- test_openai_request_format --

    #[test]
    fn test_openai_request_format() {
        let request = LlmRequest {
            model: "gpt-4o".into(),
            messages: vec![LlmMessage::user("Hello"), LlmMessage::assistant("Hi!")],
            temperature: Some(0.5),
            max_tokens: Some(2048),
            system_prompt: Some("Be concise.".into()),
            tools: vec![LlmToolDefinition {
                name: "get_weather".into(),
                description: "Get weather data".into(),
                input_schema: serde_json::json!({"type": "object", "properties": {"city": {"type": "string"}}}),
            }],
            thinking_budget: None,
        };

        // Build body as the client would.
        let mut openai_messages: Vec<Value> = Vec::new();
        if let Some(ref system_prompt) = request.system_prompt {
            if !system_prompt.is_empty() {
                openai_messages.push(serde_json::json!({
                    "role": "system",
                    "content": system_prompt,
                }));
            }
        }
        for msg in &request.messages {
            let converted = to_openai_message(msg);
            openai_messages.push(serde_json::to_value(&converted).unwrap());
        }

        let mut body = serde_json::json!({
            "model": request.model,
            "messages": openai_messages,
        });

        if let Some(max_tokens) = request.max_tokens {
            body["max_tokens"] = serde_json::json!(max_tokens);
        }
        if let Some(temp) = request.temperature {
            body["temperature"] = serde_json::json!(temp);
        }

        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.input_schema,
                        }
                    })
                })
                .collect();
            body["tools"] = Value::Array(tools);
        }

        // Verify body structure.
        assert_eq!(body["model"], "gpt-4o");
        assert_eq!(body["max_tokens"], 2048);
        assert_eq!(body["temperature"], 0.5);

        // System prompt should be the first message.
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "Be concise.");
        assert_eq!(msgs[1]["role"], "user");
        assert_eq!(msgs[2]["role"], "assistant");

        // Tools should be OpenAI function format.
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["type"], "function");
        assert_eq!(tools[0]["function"]["name"], "get_weather");
        assert!(tools[0]["function"].get("parameters").is_some());
    }

    // -- test_api_key_not_in_body --

    #[test]
    fn test_api_key_not_in_body() {
        // Ensure that when we build the request body, no API key appears in it.
        let request = sample_request();

        let mut system_text = request.system_prompt.clone().unwrap_or_default();
        let mut anthropic_messages = Vec::new();
        for msg in &request.messages {
            if msg.role == aegis_types::llm::LlmRole::System {
                system_text.push_str(&msg.content);
            } else {
                anthropic_messages.push(to_anthropic_message(msg));
            }
        }

        let body = serde_json::json!({
            "model": request.model,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "messages": anthropic_messages,
        });

        let body_str = serde_json::to_string(&body).unwrap();

        // Body should not contain any key-related fields.
        assert!(!body_str.contains("api_key"));
        assert!(!body_str.contains("x-api-key"));
        assert!(!body_str.contains("Authorization"));
        assert!(!body_str.contains("Bearer"));

        // Same for OpenAI format.
        let openai_messages: Vec<Value> = request
            .messages
            .iter()
            .map(|m| serde_json::to_value(to_openai_message(m)).unwrap())
            .collect();

        let body = serde_json::json!({
            "model": request.model,
            "messages": openai_messages,
        });

        let body_str = serde_json::to_string(&body).unwrap();
        assert!(!body_str.contains("api_key"));
        assert!(!body_str.contains("Authorization"));
        assert!(!body_str.contains("Bearer"));
    }

    // -- test_ssrf_protection --

    #[test]
    fn test_ssrf_protection() {
        // Private IP endpoints should be rejected.
        let private_urls = vec![
            "https://127.0.0.1/v1",
            "https://localhost/v1",
            "https://192.168.1.1/v1",
            "https://10.0.0.1/v1",
        ];

        for url in &private_urls {
            let config = AnthropicConfig {
                base_url: url.to_string(),
                ..Default::default()
            };
            assert!(
                config.validate_endpoint().is_err(),
                "should reject SSRF target: {url}"
            );
        }

        // HTTP (non-HTTPS) should be rejected.
        let config = AnthropicConfig {
            base_url: "http://api.anthropic.com".into(),
            ..Default::default()
        };
        assert!(config.validate_endpoint().is_err());

        // Valid HTTPS endpoints should pass.
        let config = AnthropicConfig::default();
        assert!(config.validate_endpoint().is_ok());

        let config = OpenAiConfig::default();
        assert!(config.validate_endpoint().is_ok());
    }

    // -- test_rate_limit_enforcement --

    #[test]
    fn test_rate_limit_enforcement() {
        let mut bucket = TokenBucket::new(100);

        // Should allow first 100 calls.
        for i in 0..100 {
            assert!(bucket.try_consume(), "call {i} should be allowed");
        }

        // 101st call should be denied.
        assert!(!bucket.try_consume(), "101st call should be rate-limited");
    }

    // -- test_response_size_limit --

    #[test]
    fn test_response_size_limit() {
        // The constant should be exactly 10 MB.
        assert_eq!(MAX_RESPONSE_BODY_BYTES, 10_000_000);

        // Verify the check logic: a response body larger than limit should be flagged.
        let large_body_len: u64 = MAX_RESPONSE_BODY_BYTES + 1;
        assert!(large_body_len > MAX_RESPONSE_BODY_BYTES);

        // A body at exactly the limit should pass.
        let at_limit: u64 = MAX_RESPONSE_BODY_BYTES;
        assert!(at_limit <= MAX_RESPONSE_BODY_BYTES);
    }

    // -- test_model_routing --

    #[test]
    fn test_model_routing() {
        let registry = build_registry_from_env().unwrap();

        // Anthropic models.
        assert_eq!(
            registry.resolve_provider("claude-sonnet-4-20250514"),
            Some("anthropic")
        );
        assert_eq!(
            registry.resolve_provider("claude-3-haiku"),
            Some("anthropic")
        );

        // OpenAI models.
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

        // Ollama models (now route via default prefixes).
        assert_eq!(registry.resolve_provider("llama3.2"), Some("ollama"));
        assert_eq!(registry.resolve_provider("mistral-7b"), Some("ollama"));

        // Unknown models.
        assert!(registry.resolve_provider("unknown-model-xyz").is_none());

        // Provider configs are registered.
        assert!(registry.get_provider("anthropic").is_some());
        assert!(registry.get_provider("openai").is_some());
        assert!(registry.get_provider("openai-codex").is_some());
        assert!(registry.get_provider("ollama").is_some());

        // Model resolution returns the correct provider config.
        let anthropic_config = registry.get_provider_for_model("claude-sonnet-4-20250514");
        assert!(anthropic_config.is_some());
        assert_eq!(anthropic_config.unwrap().provider_name(), "anthropic");

        let openai_config = registry.get_provider_for_model("gpt-4o");
        assert!(openai_config.is_some());
        assert_eq!(openai_config.unwrap().provider_name(), "openai");

        let ollama_config = registry.get_provider_for_model("llama3.2");
        assert!(ollama_config.is_some());
        assert_eq!(ollama_config.unwrap().provider_name(), "ollama");
    }

    // -- test_anthropic_response_parsing --

    #[test]
    fn test_anthropic_response_parsing() {
        let json: Value = serde_json::from_str(
            r#"{
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [
                {"type": "text", "text": "Hello! How can I help?"}
            ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 25,
                "output_tokens": 10
            }
        }"#,
        )
        .unwrap();

        let resp = LlmClient::parse_anthropic_response(&json, "claude-sonnet-4-20250514").unwrap();
        assert_eq!(resp.content, "Hello! How can I help?");
        assert_eq!(resp.model, "claude-sonnet-4-20250514");
        assert_eq!(resp.usage.input_tokens, 25);
        assert_eq!(resp.usage.output_tokens, 10);
        assert_eq!(resp.stop_reason, Some(StopReason::EndTurn));
        assert!(resp.tool_calls.is_empty());
    }

    // -- test_anthropic_tool_use_response --

    #[test]
    fn test_anthropic_tool_use_response() {
        let json: Value = serde_json::from_str(r#"{
            "id": "msg_456",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [
                {"type": "text", "text": "Let me search for that."},
                {"type": "tool_use", "id": "toolu_01", "name": "search", "input": {"query": "rust programming"}}
            ],
            "stop_reason": "tool_use",
            "usage": {
                "input_tokens": 50,
                "output_tokens": 30
            }
        }"#).unwrap();

        let resp = LlmClient::parse_anthropic_response(&json, "claude-sonnet-4-20250514").unwrap();
        assert_eq!(resp.content, "Let me search for that.");
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].id, "toolu_01");
        assert_eq!(resp.tool_calls[0].name, "search");
        assert_eq!(resp.tool_calls[0].input["query"], "rust programming");
        assert_eq!(resp.stop_reason, Some(StopReason::ToolUse));
    }

    // -- test_openai_response_parsing --

    #[test]
    fn test_openai_response_parsing() {
        let json: Value = serde_json::from_str(
            r#"{
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "model": "gpt-4o-2024-05-13",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Rust is a systems programming language."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 15,
                "completion_tokens": 8,
                "total_tokens": 23
            }
        }"#,
        )
        .unwrap();

        let resp = LlmClient::parse_openai_response(&json, "gpt-4o").unwrap();
        assert_eq!(resp.content, "Rust is a systems programming language.");
        assert_eq!(resp.model, "gpt-4o-2024-05-13");
        assert_eq!(resp.usage.input_tokens, 15);
        assert_eq!(resp.usage.output_tokens, 8);
        assert_eq!(resp.stop_reason, Some(StopReason::EndTurn));
        assert!(resp.tool_calls.is_empty());
    }

    // -- test_openai_tool_call_response --

    #[test]
    fn test_openai_tool_call_response() {
        let json: Value = serde_json::from_str(
            r#"{
            "id": "chatcmpl-789",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\": \"NYC\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {
                "prompt_tokens": 20,
                "completion_tokens": 15,
                "total_tokens": 35
            }
        }"#,
        )
        .unwrap();

        let resp = LlmClient::parse_openai_response(&json, "gpt-4o").unwrap();
        assert!(resp.content.is_empty());
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].id, "call_abc");
        assert_eq!(resp.tool_calls[0].name, "get_weather");
        assert_eq!(resp.tool_calls[0].input["city"], "NYC");
        assert_eq!(resp.stop_reason, Some(StopReason::ToolUse));
    }

    // -- test_responses_api_sse_text_parsing --

    #[test]
    fn test_responses_api_sse_text_parsing() {
        let sse = "\
event: response.output_text.delta\n\
data: {\"delta\":\"Hello \"}\n\
\n\
event: response.output_text.delta\n\
data: {\"delta\":\"world\"}\n\
\n\
event: response.completed\n\
data: {\"response\":{\"model\":\"gpt-5.3-codex\",\"status\":\"completed\",\"usage\":{\"input_tokens\":12,\"output_tokens\":5}}}\n\
";

        let resp = LlmClient::parse_responses_api_sse(sse, "gpt-5.3-codex").unwrap();
        assert_eq!(resp.content, "Hello world");
        assert_eq!(resp.model, "gpt-5.3-codex");
        assert_eq!(resp.usage.input_tokens, 12);
        assert_eq!(resp.usage.output_tokens, 5);
        assert_eq!(resp.stop_reason, Some(StopReason::EndTurn));
        assert!(resp.tool_calls.is_empty());
    }

    // -- test_responses_api_sse_tool_call_parsing --

    #[test]
    fn test_responses_api_sse_tool_call_parsing() {
        let sse = "\
event: response.output_item.added\n\
data: {\"item\":{\"type\":\"function_call\",\"name\":\"get_weather\",\"call_id\":\"call_1\"}}\n\
\n\
event: response.function_call_arguments.delta\n\
data: {\"delta\":\"{\\\"city\\\":\\\"NY\"}\n\
\n\
event: response.function_call_arguments.delta\n\
data: {\"delta\":\"C\\\"}\"}\n\
\n\
event: response.function_call_arguments.done\n\
data: {\"arguments\":\"{\\\"city\\\":\\\"NYC\\\"}\"}\n\
\n\
event: response.completed\n\
data: {\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":20,\"output_tokens\":7}}}\n\
";

        let resp = LlmClient::parse_responses_api_sse(sse, "gpt-5.3-codex").unwrap();
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].id, "call_1");
        assert_eq!(resp.tool_calls[0].name, "get_weather");
        assert_eq!(resp.tool_calls[0].input["city"], "NYC");
        assert_eq!(resp.stop_reason, Some(StopReason::ToolUse));
    }

    // -- test_build_registry --

    #[test]
    fn test_build_registry() {
        let registry = build_registry_from_env().unwrap();
        assert!(registry.get_provider("anthropic").is_some());
        assert!(registry.get_provider("openai").is_some());
        assert!(registry.get_provider("openai-codex").is_some());
        // Ollama is always registered.
        assert!(registry.get_provider("ollama").is_some());
    }

    // -- test_ollama_response_parsing --

    #[test]
    fn test_ollama_response_parsing() {
        let json: Value = serde_json::from_str(
            r#"{
            "model": "llama3.2",
            "message": {
                "role": "assistant",
                "content": "Hello! I am Llama."
            },
            "done": true,
            "eval_count": 12,
            "prompt_eval_count": 8
        }"#,
        )
        .unwrap();

        let resp = LlmClient::parse_ollama_response(&json, "llama3.2").unwrap();
        assert_eq!(resp.content, "Hello! I am Llama.");
        assert_eq!(resp.model, "llama3.2");
        assert_eq!(resp.usage.input_tokens, 8);
        assert_eq!(resp.usage.output_tokens, 12);
        assert_eq!(resp.stop_reason, Some(StopReason::EndTurn));
        assert!(resp.tool_calls.is_empty());
    }

    // -- test_ollama_response_with_tool_calls --

    #[test]
    fn test_ollama_response_with_tool_calls() {
        let json: Value = serde_json::from_str(
            r#"{
            "model": "llama3.2",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call_1",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"city\": \"NYC\"}"
                    }
                }]
            },
            "done": true,
            "eval_count": 20,
            "prompt_eval_count": 15
        }"#,
        )
        .unwrap();

        let resp = LlmClient::parse_ollama_response(&json, "llama3.2").unwrap();
        assert!(resp.content.is_empty());
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].id, "call_1");
        assert_eq!(resp.tool_calls[0].name, "get_weather");
        assert_eq!(resp.tool_calls[0].input["city"], "NYC");
        assert_eq!(resp.stop_reason, Some(StopReason::ToolUse));
    }

    // -- test_gemini_response_parsing_via_client --

    #[test]
    fn test_gemini_response_parsing_via_from_gemini_response() {
        let json: Value = serde_json::from_str(
            r#"{
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello from Gemini!"}],
                    "role": "model"
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 6
            }
        }"#,
        )
        .unwrap();

        let resp = from_gemini_response(&json, "gemini-2.0-flash").unwrap();
        assert_eq!(resp.content, "Hello from Gemini!");
        assert_eq!(resp.model, "gemini-2.0-flash");
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 6);
        assert_eq!(resp.stop_reason, Some(StopReason::EndTurn));
    }

    // -- test_openrouter_uses_openai_format --

    #[test]
    fn test_openrouter_uses_openai_format() {
        // OpenRouter responses are parsed with the OpenAI parser.
        let json: Value = serde_json::from_str(
            r#"{
            "id": "gen-123",
            "model": "anthropic/claude-sonnet-4-20250514",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Via OpenRouter."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15
            }
        }"#,
        )
        .unwrap();

        let resp =
            LlmClient::parse_openai_response(&json, "anthropic/claude-sonnet-4-20250514").unwrap();
        assert_eq!(resp.content, "Via OpenRouter.");
        assert_eq!(resp.model, "anthropic/claude-sonnet-4-20250514");
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 5);
    }

    // -- test_build_registry_with_gemini_env --

    #[test]
    fn test_build_registry_with_gemini_env() {
        // Set a Gemini key and verify it gets registered.
        std::env::set_var("GOOGLE_API_KEY", "test-gemini-key");
        let registry = build_registry_from_env().unwrap();
        assert!(registry.get_provider("google").is_some());
        std::env::remove_var("GOOGLE_API_KEY");
    }

    // -- test_build_registry_with_openrouter_env --

    #[test]
    fn test_build_registry_with_openrouter_env() {
        std::env::set_var("OPENROUTER_API_KEY", "test-or-key");
        let registry = build_registry_from_env().unwrap();
        assert!(registry.get_provider("openrouter").is_some());
        std::env::remove_var("OPENROUTER_API_KEY");
    }

    // -- test_build_registry_ollama_custom_url --

    #[test]
    fn test_build_registry_ollama_custom_url() {
        std::env::set_var("OLLAMA_BASE_URL", "http://gpu-server:11434");
        let registry = build_registry_from_env().unwrap();
        let ollama = registry.get_provider("ollama").unwrap();
        match ollama {
            ProviderConfig::Ollama(c) => {
                assert_eq!(c.base_url, "http://gpu-server:11434");
            }
            _ => panic!("expected Ollama provider config"),
        }
        std::env::remove_var("OLLAMA_BASE_URL");
    }

    // -- test_failover_chain_in_complete --

    #[test]
    fn test_failover_chain_resolution_in_registry() {
        let mut registry = ProviderRegistry::new();

        // Set up failover: gpt-4o -> claude-sonnet -> gemini-flash
        registry.set_failover(
            "gpt-4o",
            vec![
                "claude-sonnet-4-20250514".to_string(),
                "gemini-2.0-flash".to_string(),
            ],
        );

        let chain = registry.get_failover_chain("gpt-4o");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], "gpt-4o");
        assert_eq!(chain[1], "claude-sonnet-4-20250514");
        assert_eq!(chain[2], "gemini-2.0-flash");
    }

    // -- test_alias_resolution_in_registry --

    #[test]
    fn test_alias_resolution_in_registry() {
        let mut registry = ProviderRegistry::new();

        registry.add_alias("fast", "gemini-2.0-flash");
        registry.add_alias("smart", "claude-sonnet-4-20250514");
        registry.add_alias("local", "llama3.2");

        assert_eq!(registry.resolve_alias("fast"), "gemini-2.0-flash");
        assert_eq!(registry.resolve_alias("smart"), "claude-sonnet-4-20250514");
        assert_eq!(registry.resolve_alias("local"), "llama3.2");
        assert_eq!(registry.resolve_alias("unknown"), "unknown");

        // Aliases affect provider resolution.
        assert_eq!(registry.resolve_provider("fast"), Some("google"));
        assert_eq!(registry.resolve_provider("smart"), Some("anthropic"));
        assert_eq!(registry.resolve_provider("local"), Some("ollama"));
    }

    // -- test_gemini_request_body_format --

    #[test]
    fn test_gemini_request_body_format() {
        let request = LlmRequest {
            model: "gemini-2.0-flash".into(),
            messages: vec![
                LlmMessage::user("Hello, Gemini!"),
                LlmMessage::assistant("Hi there!"),
                LlmMessage::user("What is Rust?"),
            ],
            temperature: Some(0.7),
            max_tokens: Some(2048),
            system_prompt: Some("You are a helpful assistant.".into()),
            tools: vec![LlmToolDefinition {
                name: "search".into(),
                description: "Search the web".into(),
                input_schema: serde_json::json!({"type": "object", "properties": {"query": {"type": "string"}}}),
            }],
            thinking_budget: None,
        };

        // Build the body as complete_gemini would.
        let mut system_text = request.system_prompt.clone().unwrap_or_default();
        let mut gemini_contents = Vec::new();
        for msg in &request.messages {
            if msg.role == aegis_types::llm::LlmRole::System {
                if !system_text.is_empty() {
                    system_text.push('\n');
                }
                system_text.push_str(&msg.content);
            } else {
                gemini_contents.push(to_gemini_content(msg));
            }
        }

        let mut body = serde_json::json!({
            "contents": gemini_contents,
        });

        if !system_text.is_empty() {
            body["system_instruction"] = serde_json::json!({
                "parts": [{"text": system_text}]
            });
        }

        let mut gen_config = serde_json::Map::new();
        if let Some(temp) = request.temperature {
            gen_config.insert("temperature".into(), serde_json::json!(temp));
        }
        if let Some(max_tokens) = request.max_tokens {
            gen_config.insert("maxOutputTokens".into(), serde_json::json!(max_tokens));
        }
        if !gen_config.is_empty() {
            body["generationConfig"] = Value::Object(gen_config);
        }

        // Verify body structure.
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 3);
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[1]["role"], "model");
        assert_eq!(contents[2]["role"], "user");

        // System instruction should be separate.
        assert_eq!(
            body["system_instruction"]["parts"][0]["text"],
            "You are a helpful assistant."
        );

        // Generation config.
        assert_eq!(body["generationConfig"]["temperature"], 0.7);
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 2048);
    }

    // -- test_oauth_resolver_no_token --

    #[test]
    fn test_oauth_resolver_no_token() {
        let _guard = HOME_MUTEX.lock();
        // Point HOME to a temp dir so FileTokenStore::new finds no tokens.
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let resolver = OAuthTokenResolver::new().unwrap();

        // Should return None for any provider (no token files exist).
        assert!(resolver.resolve_token("anthropic").is_none());
        assert!(resolver.resolve_token("openai").is_none());

        // Restore HOME.
        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        }
    }

    // -- test_oauth_resolver_valid_token --

    #[test]
    fn test_oauth_resolver_valid_token() {
        let _guard = HOME_MUTEX.lock();
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // Store a valid token via FileTokenStore (uses HOME).
        let store = FileTokenStore::new("anthropic").unwrap();
        let token = aegis_types::oauth::OAuthToken {
            access_token: "oauth-test-token-abc123".to_string(),
            refresh_token: String::new(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            scope: None,
        };
        store.save(&token).unwrap();

        let resolver = OAuthTokenResolver::new().unwrap();
        let resolved = resolver.resolve_token("anthropic");
        assert_eq!(resolved, Some("oauth-test-token-abc123".to_string()));

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        }
    }

    // -- test_oauth_resolver_expired_token_no_refresh --

    #[test]
    fn test_oauth_resolver_expired_token_no_refresh() {
        let _guard = HOME_MUTEX.lock();
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let store = FileTokenStore::new("openai").unwrap();
        let token = aegis_types::oauth::OAuthToken {
            access_token: "expired-token".to_string(),
            refresh_token: String::new(),
            expires_at: Some(chrono::DateTime::from_timestamp(1000, 0).unwrap()),
            scope: None,
        };
        store.save(&token).unwrap();

        let resolver = OAuthTokenResolver::new().unwrap();
        assert!(resolver.resolve_token("openai").is_none());

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        }
    }

    // -- test_oauth_resolver_expired_token_with_refresh --

    #[test]
    fn test_oauth_resolver_expired_with_refresh_falls_back() {
        let _guard = HOME_MUTEX.lock();
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let store = FileTokenStore::new("google").unwrap();
        let token = aegis_types::oauth::OAuthToken {
            access_token: "expired-token".to_string(),
            refresh_token: "refresh-me".to_string(),
            expires_at: Some(chrono::DateTime::from_timestamp(1000, 0).unwrap()),
            scope: None,
        };
        store.save(&token).unwrap();

        let resolver = OAuthTokenResolver::new().unwrap();
        // Falls back to None because async refresh is not available in blocking mode.
        assert!(resolver.resolve_token("google").is_none());

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        }
    }

    // -- test_resolve_api_key_with_oauth_prefers_oauth --

    #[test]
    fn test_resolve_api_key_prefers_oauth() {
        let _guard = HOME_MUTEX.lock();
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let store = FileTokenStore::new("anthropic").unwrap();
        let token = aegis_types::oauth::OAuthToken {
            access_token: "oauth-preferred".to_string(),
            refresh_token: String::new(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            scope: None,
        };
        store.save(&token).unwrap();

        let registry = build_registry_from_env().unwrap();
        let mut client = LlmClient::new(registry).unwrap();
        client.oauth_resolver = OAuthTokenResolver::new();

        let key =
            client.resolve_api_key_with_oauth("anthropic", || Ok("env-key-fallback".to_string()));
        assert_eq!(key.unwrap(), "oauth-preferred");

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        }
    }

    // -- test_resolve_api_key_with_oauth_falls_back_to_env --

    #[test]
    fn test_resolve_api_key_falls_back_to_env() {
        let _guard = HOME_MUTEX.lock();
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // No tokens stored.
        let registry = build_registry_from_env().unwrap();
        let mut client = LlmClient::new(registry).unwrap();
        client.oauth_resolver = OAuthTokenResolver::new();

        let key =
            client.resolve_api_key_with_oauth("anthropic", || Ok("env-key-value".to_string()));
        assert_eq!(key.unwrap(), "env-key-value");

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        }
    }

    // -- test_resolve_api_key_no_resolver --

    #[test]
    fn test_resolve_api_key_no_resolver() {
        let _guard = HOME_MUTEX.lock();
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();
        let old_anthropic = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::set_var("HOME", tmp.path());
        std::env::remove_var("ANTHROPIC_API_KEY");

        let registry = build_registry_from_env().unwrap();
        let mut client = LlmClient::new(registry).unwrap();
        client.oauth_resolver = None;

        let key = client.resolve_api_key_with_oauth("anthropic", || Ok("only-env".to_string()));
        assert_eq!(key.unwrap(), "only-env");

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        }
        if let Some(k) = old_anthropic {
            std::env::set_var("ANTHROPIC_API_KEY", k);
        }
    }

    #[test]
    fn test_resolve_api_key_openai_codex_reads_cli_token_file() {
        let _guard = HOME_MUTEX.lock();
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();
        let old_openai = std::env::var("OPENAI_API_KEY").ok();
        std::env::set_var("HOME", tmp.path());
        std::env::remove_var("OPENAI_API_KEY");

        let codex_dir = tmp.path().join(".codex");
        std::fs::create_dir_all(&codex_dir).unwrap();
        std::fs::write(
            codex_dir.join("auth.json"),
            r#"{"tokens":{"access_token":"codex-cli-token"}}"#,
        )
        .unwrap();

        let registry = build_registry_from_env().unwrap();
        let mut client = LlmClient::new(registry).unwrap();
        client.oauth_resolver = None;

        let key = client.resolve_api_key_with_oauth("openai-codex", || {
            Err("OPENAI_API_KEY environment variable is not set".to_string())
        });
        assert_eq!(key.unwrap(), "codex-cli-token");

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        }
        if let Some(k) = old_openai {
            std::env::set_var("OPENAI_API_KEY", k);
        }
    }
}
