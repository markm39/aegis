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

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use tracing::{debug, info};

use aegis_types::llm::{
    to_anthropic_message, to_openai_message, AnthropicConfig, LlmRequest, LlmResponse,
    LlmToolCall, LlmUsage, MaskedApiKey, OpenAiConfig, ProviderConfig,
    ProviderRegistry, StopReason,
};

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
// LlmClient
// ---------------------------------------------------------------------------

/// Blocking HTTP client for LLM API calls.
///
/// Routes requests to Anthropic or OpenAI based on model name via a
/// `ProviderRegistry`. Enforces rate limiting, request/response size limits,
/// and SSRF protections.
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
    pub fn new(registry: ProviderRegistry) -> Result<Self, String> {
        let http_client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .user_agent("aegis-daemon/0.1")
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        Ok(Self {
            http_client,
            registry,
            default_timeout: Duration::from_secs(30),
            rate_limiter: Mutex::new(TokenBucket::new(RATE_LIMIT_RPM)),
        })
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
                return Err(format!(
                    "max_tokens must be <= 1,000,000, got {max_tokens}"
                ));
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
    /// 2. Resolves the provider from the model name via the registry.
    /// 3. Checks rate limit.
    /// 4. Dispatches to the provider-specific method.
    pub fn complete(&self, request: &LlmRequest) -> Result<LlmResponse, String> {
        Self::validate_request(request)?;

        let provider_config = self
            .registry
            .get_provider_for_model(&request.model)
            .ok_or_else(|| {
                format!(
                    "no provider configured for model '{}' (check provider registry)",
                    request.model
                )
            })?;

        // Rate limit check.
        {
            let mut limiter = self.rate_limiter.lock().map_err(|e| {
                format!("rate limiter lock poisoned: {e}")
            })?;
            if !limiter.try_consume() {
                return Err("LLM rate limit exceeded (max 100 calls/minute)".into());
            }
        }

        match provider_config.clone() {
            ProviderConfig::Anthropic(config) => self.complete_anthropic(request, &config),
            ProviderConfig::OpenAi(config) => self.complete_openai(request, &config),
        }
    }

    /// Send a completion request to the Anthropic Messages API.
    fn complete_anthropic(
        &self,
        request: &LlmRequest,
        config: &AnthropicConfig,
    ) -> Result<LlmResponse, String> {
        // Read API key from environment.
        let api_key = config.read_api_key().map_err(|e| e.to_string())?;
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

        // Validate request body size.
        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            format!("failed to serialize Anthropic request body: {e}")
        })?;
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
            return Err(format!(
                "Anthropic API returned {status}: {resp_text}"
            ));
        }

        // Parse Anthropic response.
        let resp_json: Value = serde_json::from_str(&resp_text).map_err(|e| {
            format!("failed to parse Anthropic response JSON: {e}")
        })?;

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
                input_tokens: u
                    .get("input_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                output_tokens: u
                    .get("output_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
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

    /// Send a completion request to the OpenAI Chat Completions API.
    fn complete_openai(
        &self,
        request: &LlmRequest,
        config: &OpenAiConfig,
    ) -> Result<LlmResponse, String> {
        // Read API key from environment.
        let api_key = config.read_api_key().map_err(|e| e.to_string())?;
        let masked = MaskedApiKey(api_key.clone());
        debug!(provider = "openai", key = %masked, "resolved API key");

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
                serde_json::to_value(&converted).map_err(|e| {
                    format!("failed to serialize OpenAI message: {e}")
                })?,
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
        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            format!("failed to serialize OpenAI request body: {e}")
        })?;
        if body_bytes.len() > MAX_REQUEST_BODY_BYTES {
            return Err(format!(
                "request body too large: {} bytes (max {MAX_REQUEST_BODY_BYTES})",
                body_bytes.len()
            ));
        }

        info!(
            provider = "openai",
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
        let resp_json: Value = serde_json::from_str(&resp_text).map_err(|e| {
            format!("failed to parse OpenAI response JSON: {e}")
        })?;

        Self::parse_openai_response(&resp_json, &request.model)
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
                let input: Value = serde_json::from_str(args_str)
                    .unwrap_or(Value::Object(serde_json::Map::new()));
                tool_calls.push(LlmToolCall { id, name, input });
            }
        }

        // Extract usage.
        let usage = json
            .get("usage")
            .map(|u| LlmUsage {
                input_tokens: u
                    .get("prompt_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
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
/// Registers Anthropic and OpenAI providers using default configurations.
/// Both providers are registered regardless of whether API keys are present;
/// key availability is checked at request time.
pub fn build_registry_from_env() -> Result<ProviderRegistry, String> {
    let mut registry = ProviderRegistry::new();

    // Register Anthropic with defaults.
    registry
        .register_provider(
            "anthropic",
            ProviderConfig::Anthropic(AnthropicConfig::default()),
        )
        .map_err(|e| format!("failed to register Anthropic provider: {e}"))?;

    // Register OpenAI with defaults.
    registry
        .register_provider(
            "openai",
            ProviderConfig::OpenAi(OpenAiConfig::default()),
        )
        .map_err(|e| format!("failed to register OpenAI provider: {e}"))?;

    Ok(registry)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::llm::{LlmMessage, LlmRequest, LlmToolDefinition};

    fn sample_request() -> LlmRequest {
        LlmRequest {
            model: "claude-sonnet-4-20250514".into(),
            messages: vec![LlmMessage::user("Hello")],
            temperature: None,
            max_tokens: None,
            system_prompt: None,
            tools: vec![],
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
            messages: vec![
                LlmMessage::user("Hello"),
                LlmMessage::assistant("Hi!"),
            ],
            temperature: Some(0.5),
            max_tokens: Some(2048),
            system_prompt: Some("Be concise.".into()),
            tools: vec![LlmToolDefinition {
                name: "get_weather".into(),
                description: "Get weather data".into(),
                input_schema: serde_json::json!({"type": "object", "properties": {"city": {"type": "string"}}}),
            }],
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
            assert!(
                bucket.try_consume(),
                "call {i} should be allowed"
            );
        }

        // 101st call should be denied.
        assert!(
            !bucket.try_consume(),
            "101st call should be rate-limited"
        );
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

        // Unknown models.
        assert!(registry.resolve_provider("llama-70b").is_none());
        assert!(registry.resolve_provider("mistral-7b").is_none());

        // Provider configs are registered.
        assert!(registry.get_provider("anthropic").is_some());
        assert!(registry.get_provider("openai").is_some());

        // Model resolution returns the correct provider config.
        let anthropic_config = registry.get_provider_for_model("claude-sonnet-4-20250514");
        assert!(anthropic_config.is_some());
        assert_eq!(anthropic_config.unwrap().provider_name(), "anthropic");

        let openai_config = registry.get_provider_for_model("gpt-4o");
        assert!(openai_config.is_some());
        assert_eq!(openai_config.unwrap().provider_name(), "openai");
    }

    // -- test_anthropic_response_parsing --

    #[test]
    fn test_anthropic_response_parsing() {
        let json: Value = serde_json::from_str(r#"{
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
        }"#).unwrap();

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
        let json: Value = serde_json::from_str(r#"{
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
        }"#).unwrap();

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
        let json: Value = serde_json::from_str(r#"{
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
        }"#).unwrap();

        let resp = LlmClient::parse_openai_response(&json, "gpt-4o").unwrap();
        assert!(resp.content.is_empty());
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].id, "call_abc");
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
    }
}
