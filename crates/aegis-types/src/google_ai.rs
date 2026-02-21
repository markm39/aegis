//! Google AI (Gemini) provider types and function calling translation.
//!
//! Provides request/response types for the Gemini API, format translation
//! between Anthropic/OpenAI tool_use format and Gemini's native functionCall
//! format, and streaming chunk parsing.
//!
//! # Security
//!
//! - API keys are read from environment variables at runtime, never hardcoded.
//! - API keys are masked in all `Debug` and `Display` output.
//! - Endpoint URLs are validated against SSRF (private/loopback IPs blocked).
//! - Function call arguments are sanitized to strip control characters.
//! - Response content is sanitized before returning.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config_loader::mask_sensitive;
use crate::AegisError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default Gemini model name.
pub const DEFAULT_GEMINI_MODEL: &str = "gemini-pro";

/// Default Gemini API endpoint.
pub const DEFAULT_GEMINI_ENDPOINT: &str = "https://generativelanguage.googleapis.com";

/// Primary environment variable for the Gemini API key.
pub const DEFAULT_API_KEY_ENV: &str = "GOOGLE_AI_API_KEY";

/// Fallback environment variable for the Gemini API key.
pub const FALLBACK_API_KEY_ENV: &str = "GEMINI_API_KEY";

// ---------------------------------------------------------------------------
// GeminiConfig
// ---------------------------------------------------------------------------

/// Configuration for connecting to the Google AI Gemini API.
///
/// The API key is never stored directly. Instead, `api_key_env` names the
/// environment variable that holds the key at runtime. The actual key is
/// read via [`GeminiConfig::read_api_key`].
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeminiConfig {
    /// Name of the environment variable holding the API key.
    /// Defaults to `GOOGLE_AI_API_KEY`; falls back to `GEMINI_API_KEY`.
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,

    /// Gemini model name (e.g., "gemini-pro", "gemini-1.5-pro").
    #[serde(default = "default_model")]
    pub model: String,

    /// Base endpoint URL (must be HTTPS for non-test environments).
    #[serde(default = "default_endpoint")]
    pub endpoint_url: String,
}

fn default_api_key_env() -> String {
    DEFAULT_API_KEY_ENV.to_string()
}

fn default_model() -> String {
    DEFAULT_GEMINI_MODEL.to_string()
}

fn default_endpoint() -> String {
    DEFAULT_GEMINI_ENDPOINT.to_string()
}

impl Default for GeminiConfig {
    fn default() -> Self {
        Self {
            api_key_env: default_api_key_env(),
            model: default_model(),
            endpoint_url: default_endpoint(),
        }
    }
}

impl fmt::Debug for GeminiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeminiConfig")
            .field("api_key_env", &self.api_key_env)
            .field("model", &self.model)
            .field("endpoint_url", &self.endpoint_url)
            .finish()
    }
}

impl GeminiConfig {
    /// Read the API key from the configured environment variable.
    ///
    /// Tries the primary `api_key_env` first, then falls back to
    /// `GEMINI_API_KEY` if the primary is the default and not set.
    /// Returns an error if neither variable is set or the value is empty.
    pub fn read_api_key(&self) -> Result<String, AegisError> {
        // Try the primary env var.
        match std::env::var(&self.api_key_env) {
            Ok(key) if !key.is_empty() => return Ok(key),
            _ => {}
        }

        // If the primary is the default, try the fallback.
        if self.api_key_env == DEFAULT_API_KEY_ENV {
            match std::env::var(FALLBACK_API_KEY_ENV) {
                Ok(key) if !key.is_empty() => return Ok(key),
                _ => {}
            }
        }

        Err(AegisError::ConfigError(format!(
            "environment variable '{}' not set (required for Gemini API key)",
            self.api_key_env
        )))
    }

    /// Validate that the endpoint URL is safe (HTTPS, no SSRF targets).
    pub fn validate_endpoint(&self) -> Result<(), AegisError> {
        validate_endpoint_url(&self.endpoint_url)
    }
}

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

/// Validate that a URL uses HTTPS and does not point to a private/loopback address.
///
/// This blocks SSRF attacks where a malicious config might redirect API
/// requests to internal services.
pub fn validate_endpoint_url(url: &str) -> Result<(), AegisError> {
    if !url.starts_with("https://") {
        return Err(AegisError::ConfigError(format!(
            "Gemini endpoint URL must use HTTPS, got: {url}"
        )));
    }

    let host = extract_host(url).ok_or_else(|| {
        AegisError::ConfigError(format!(
            "cannot parse host from Gemini endpoint URL: {url}"
        ))
    })?;

    if is_private_or_loopback(&host) {
        return Err(AegisError::ConfigError(format!(
            "Gemini endpoint URL points to private/loopback address (SSRF blocked): {host}"
        )));
    }

    Ok(())
}

/// Extract the host portion from a URL string.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host = after_scheme.split(['/', '?', '#']).next()?;
    // Strip port if present (but not IPv6 bracket notation).
    let host = if let Some((h, port)) = host.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host
        }
    } else {
        host
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Check if a hostname or IP address is private, loopback, or link-local.
fn is_private_or_loopback(host: &str) -> bool {
    if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        return addr.is_loopback()
            || addr.is_private()
            || addr.is_link_local()
            || addr.is_unspecified()
            || (addr.octets()[0] == 100 && addr.octets()[1] >= 64 && addr.octets()[1] <= 127);
    }

    if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
        return addr.is_loopback() || addr.is_unspecified();
    }

    let lower = host.to_lowercase();
    lower == "localhost"
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".localhost")
}

// ---------------------------------------------------------------------------
// Sanitization helpers
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
// Gemini API request types
// ---------------------------------------------------------------------------

/// A request to the Gemini generateContent or streamGenerateContent endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiRequest {
    /// Conversation contents (messages with parts).
    pub contents: Vec<GeminiContent>,

    /// Optional generation parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_config: Option<GeminiGenerationConfig>,

    /// Optional tool declarations (function calling).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<GeminiTool>>,
}

/// A content block in a Gemini conversation (role + parts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiContent {
    /// The role: "user" or "model".
    pub role: String,
    /// Content parts (text, function calls, function responses).
    pub parts: Vec<GeminiPart>,
}

/// A single part within a Gemini content block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GeminiPart {
    /// Plain text content.
    #[serde(rename = "text")]
    Text(String),

    /// A function call made by the model.
    FunctionCall(GeminiFunctionCall),

    /// A function response provided back to the model.
    FunctionResponse(GeminiFunctionResponse),
}

/// A function call from the Gemini model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiFunctionCall {
    /// Name of the function to call.
    pub name: String,
    /// Arguments as a JSON object.
    pub args: serde_json::Value,
}

/// A function response sent back to the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiFunctionResponse {
    /// Name of the function that was called.
    pub name: String,
    /// The response content.
    pub response: serde_json::Value,
}

/// Generation configuration for a Gemini request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiGenerationConfig {
    /// Maximum number of tokens to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,

    /// Sampling temperature (0.0 to 2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,

    /// Top-p nucleus sampling threshold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,

    /// Top-k sampling parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,

    /// Stop sequences.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
}

/// A tool declaration for Gemini function calling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiTool {
    /// Function declarations available to the model.
    pub function_declarations: Vec<GeminiFunctionDeclaration>,
}

/// A function declaration describing a callable function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiFunctionDeclaration {
    /// Function name.
    pub name: String,
    /// Human-readable description of what the function does.
    pub description: String,
    /// Parameter schema in JSON Schema format.
    pub parameters: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Gemini API response types
// ---------------------------------------------------------------------------

/// Response from the Gemini generateContent endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiResponse {
    /// Generated candidates.
    #[serde(default)]
    pub candidates: Vec<GeminiCandidate>,

    /// Token usage metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_metadata: Option<GeminiUsageMetadata>,
}

/// A single candidate response from Gemini.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiCandidate {
    /// The generated content.
    pub content: GeminiContent,

    /// Why generation stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,

    /// Safety ratings for the content.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safety_ratings: Vec<GeminiSafetyRating>,
}

/// Safety rating for generated content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiSafetyRating {
    /// Safety category.
    pub category: String,
    /// Probability assessment.
    pub probability: String,
}

/// Token usage metadata from a Gemini response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiUsageMetadata {
    /// Number of tokens in the prompt.
    #[serde(default)]
    pub prompt_token_count: u64,
    /// Number of tokens in the generated candidates.
    #[serde(default)]
    pub candidates_token_count: u64,
    /// Total token count (prompt + candidates).
    #[serde(default)]
    pub total_token_count: u64,
}

// ---------------------------------------------------------------------------
// Streaming types
// ---------------------------------------------------------------------------

/// A streaming chunk from the Gemini streamGenerateContent endpoint.
///
/// Gemini uses a JSON array SSE format: the stream begins with `[`, each
/// chunk is a JSON object (optionally preceded by `,`), and ends with `]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiStreamChunk {
    /// Candidates in this chunk (may contain partial content).
    #[serde(default)]
    pub candidates: Vec<GeminiCandidate>,

    /// Usage metadata (typically only present in the final chunk).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_metadata: Option<GeminiUsageMetadata>,
}

/// Parse a raw SSE line from Gemini streaming into a stream chunk.
///
/// Gemini streams as a JSON array: `[\n{chunk1},\n{chunk2},\n...\n]`.
/// This function strips the leading `[`, trailing `]`, and commas
/// to extract individual JSON objects.
pub fn parse_stream_chunk(line: &str) -> Option<GeminiStreamChunk> {
    let trimmed = line.trim();

    // Skip empty lines, array delimiters, and bare commas.
    if trimmed.is_empty() || trimmed == "[" || trimmed == "]" || trimmed == "," {
        return None;
    }

    // Strip leading comma if present (from array continuation).
    let json_str = trimmed.strip_prefix(',').unwrap_or(trimmed).trim();

    // Skip if still an array delimiter after stripping.
    if json_str.is_empty() || json_str == "[" || json_str == "]" {
        return None;
    }

    serde_json::from_str(json_str).ok()
}

// ---------------------------------------------------------------------------
// Response extraction
// ---------------------------------------------------------------------------

impl GeminiResponse {
    /// Extract all text content from the first candidate, sanitized.
    pub fn text_content(&self) -> Option<String> {
        let candidate = self.candidates.first()?;
        let texts: Vec<&str> = candidate
            .content
            .parts
            .iter()
            .filter_map(|part| match part {
                GeminiPart::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();

        if texts.is_empty() {
            None
        } else {
            Some(sanitize_text(&texts.join("")))
        }
    }

    /// Extract all function calls from the first candidate, with sanitized args.
    pub fn function_calls(&self) -> Vec<GeminiFunctionCall> {
        let Some(candidate) = self.candidates.first() else {
            return Vec::new();
        };
        candidate
            .content
            .parts
            .iter()
            .filter_map(|part| match part {
                GeminiPart::FunctionCall(fc) => Some(GeminiFunctionCall {
                    name: sanitize_text(&fc.name),
                    args: sanitize_json_value(&fc.args),
                }),
                _ => None,
            })
            .collect()
    }

    /// Extract usage metadata, returning zeros if not present.
    pub fn usage(&self) -> GeminiUsageMetadata {
        self.usage_metadata.clone().unwrap_or(GeminiUsageMetadata {
            prompt_token_count: 0,
            candidates_token_count: 0,
            total_token_count: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Format translation: Anthropic/OpenAI -> Gemini
// ---------------------------------------------------------------------------

/// An Anthropic/OpenAI-style tool definition for format translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// Input schema (JSON Schema format).
    pub input_schema: serde_json::Value,
}

/// An Anthropic/OpenAI-style tool_use block for format translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUseBlock {
    /// Tool use ID.
    pub id: String,
    /// Tool name.
    pub name: String,
    /// Tool input arguments.
    pub input: serde_json::Value,
}

/// Convert an Anthropic/OpenAI tool definition to a Gemini function declaration.
pub fn tool_to_gemini_declaration(tool: &ToolDefinition) -> GeminiFunctionDeclaration {
    GeminiFunctionDeclaration {
        name: sanitize_text(&tool.name),
        description: sanitize_text(&tool.description),
        parameters: sanitize_json_value(&tool.input_schema),
    }
}

/// Convert a list of Anthropic/OpenAI tool definitions to a Gemini tools array.
pub fn tools_to_gemini(tools: &[ToolDefinition]) -> Vec<GeminiTool> {
    if tools.is_empty() {
        return Vec::new();
    }
    vec![GeminiTool {
        function_declarations: tools.iter().map(tool_to_gemini_declaration).collect(),
    }]
}

/// Convert an Anthropic/OpenAI tool_use block to a Gemini function call.
pub fn tool_use_to_gemini_function_call(tool_use: &ToolUseBlock) -> GeminiFunctionCall {
    GeminiFunctionCall {
        name: sanitize_text(&tool_use.name),
        args: sanitize_json_value(&tool_use.input),
    }
}

/// Convert a Gemini function call back to an Anthropic/OpenAI tool_use block.
///
/// Generates a deterministic ID from the function name since Gemini does
/// not provide tool_use IDs.
pub fn gemini_function_call_to_tool_use(fc: &GeminiFunctionCall, id: &str) -> ToolUseBlock {
    ToolUseBlock {
        id: id.to_string(),
        name: sanitize_text(&fc.name),
        input: sanitize_json_value(&fc.args),
    }
}

// ---------------------------------------------------------------------------
// MaskedApiKey: Display wrapper that hides the key value
// ---------------------------------------------------------------------------

/// A wrapper around an API key string that masks its value in Debug/Display.
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

    // -- Config defaults --

    #[test]
    fn config_defaults() {
        let config = GeminiConfig::default();
        assert_eq!(config.api_key_env, "GOOGLE_AI_API_KEY");
        assert_eq!(config.model, "gemini-pro");
        assert_eq!(
            config.endpoint_url,
            "https://generativelanguage.googleapis.com"
        );
    }

    // -- Request serialization --

    #[test]
    fn gemini_request_serialization() {
        let request = GeminiRequest {
            contents: vec![GeminiContent {
                role: "user".into(),
                parts: vec![GeminiPart::Text("Hello, Gemini!".into())],
            }],
            generation_config: Some(GeminiGenerationConfig {
                max_output_tokens: Some(1024),
                temperature: Some(0.7),
                top_p: None,
                top_k: None,
                stop_sequences: None,
            }),
            tools: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify camelCase serialization.
        assert!(parsed.get("contents").is_some());
        assert!(parsed.get("generationConfig").is_some());
        let gen_config = parsed.get("generationConfig").unwrap();
        assert_eq!(gen_config.get("maxOutputTokens").unwrap(), 1024);

        // Roundtrip.
        let deserialized: GeminiRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.contents.len(), 1);
        assert_eq!(deserialized.contents[0].role, "user");
    }

    // -- Response parsing --

    #[test]
    fn gemini_response_parsing() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"text": "Hello! How can I help?"}]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 8,
                "totalTokenCount": 18
            }
        }"#;

        let response: GeminiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.candidates.len(), 1);
        assert_eq!(
            response.candidates[0].finish_reason.as_deref(),
            Some("STOP")
        );
        assert_eq!(response.text_content().unwrap(), "Hello! How can I help?");
    }

    // -- Function call format translation --

    #[test]
    fn function_call_format_translation() {
        let tool_use = ToolUseBlock {
            id: "tu_123".into(),
            name: "get_weather".into(),
            input: serde_json::json!({"city": "San Francisco"}),
        };

        let fc = tool_use_to_gemini_function_call(&tool_use);
        assert_eq!(fc.name, "get_weather");
        assert_eq!(fc.args["city"], "San Francisco");

        // Round-trip back.
        let back = gemini_function_call_to_tool_use(&fc, "tu_456");
        assert_eq!(back.id, "tu_456");
        assert_eq!(back.name, "get_weather");
        assert_eq!(back.input["city"], "San Francisco");
    }

    // -- Function declaration translation --

    #[test]
    fn function_declaration_to_gemini() {
        let tool = ToolDefinition {
            name: "search".into(),
            description: "Search the web".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                },
                "required": ["query"]
            }),
        };

        let declarations = tools_to_gemini(&[tool]);
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].function_declarations.len(), 1);
        assert_eq!(declarations[0].function_declarations[0].name, "search");
        assert_eq!(
            declarations[0].function_declarations[0].description,
            "Search the web"
        );
        assert!(declarations[0].function_declarations[0]
            .parameters
            .get("properties")
            .is_some());
    }

    // -- Usage metadata extraction --

    #[test]
    fn usage_metadata_extraction() {
        let response = GeminiResponse {
            candidates: vec![],
            usage_metadata: Some(GeminiUsageMetadata {
                prompt_token_count: 42,
                candidates_token_count: 17,
                total_token_count: 59,
            }),
        };

        let usage = response.usage();
        assert_eq!(usage.prompt_token_count, 42);
        assert_eq!(usage.candidates_token_count, 17);
        assert_eq!(usage.total_token_count, 59);
    }

    #[test]
    fn usage_metadata_defaults_to_zeros() {
        let response = GeminiResponse {
            candidates: vec![],
            usage_metadata: None,
        };

        let usage = response.usage();
        assert_eq!(usage.prompt_token_count, 0);
        assert_eq!(usage.candidates_token_count, 0);
        assert_eq!(usage.total_token_count, 0);
    }

    // -- Streaming chunk parsing --

    #[test]
    fn streaming_chunk_parsing() {
        let chunk_json = r#"{
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"text": "Hi"}]
                }
            }]
        }"#;

        // Direct JSON parse.
        let chunk = parse_stream_chunk(chunk_json).unwrap();
        assert_eq!(chunk.candidates.len(), 1);

        // With leading comma (array continuation).
        let with_comma = format!(",{chunk_json}");
        let chunk2 = parse_stream_chunk(&with_comma).unwrap();
        assert_eq!(chunk2.candidates.len(), 1);

        // Array delimiters should be skipped.
        assert!(parse_stream_chunk("[").is_none());
        assert!(parse_stream_chunk("]").is_none());
        assert!(parse_stream_chunk(",").is_none());
        assert!(parse_stream_chunk("").is_none());
    }

    // -- API key from env --

    #[test]
    fn api_key_from_env() {
        // Set the env var for this test.
        let key = "test-api-key-abc123";
        std::env::set_var("_AEGIS_TEST_GEMINI_KEY", key);

        let config = GeminiConfig {
            api_key_env: "_AEGIS_TEST_GEMINI_KEY".into(),
            ..Default::default()
        };
        let result = config.read_api_key().unwrap();
        assert_eq!(result, key);

        std::env::remove_var("_AEGIS_TEST_GEMINI_KEY");
    }

    #[test]
    fn api_key_missing_env_errors() {
        let config = GeminiConfig {
            api_key_env: "_AEGIS_TEST_NONEXISTENT_KEY".into(),
            ..Default::default()
        };
        let result = config.read_api_key();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("_AEGIS_TEST_NONEXISTENT_KEY"));
    }

    #[test]
    fn api_key_fallback_env() {
        // Remove primary, set fallback.
        std::env::remove_var("GOOGLE_AI_API_KEY");
        std::env::set_var("GEMINI_API_KEY", "fallback-key-xyz");

        let config = GeminiConfig::default();
        let result = config.read_api_key().unwrap();
        assert_eq!(result, "fallback-key-xyz");

        std::env::remove_var("GEMINI_API_KEY");
    }

    // -- SSRF protection (security test) --

    #[test]
    fn endpoint_ssrf_protection() {
        // Loopback IPv4.
        assert!(validate_endpoint_url("https://127.0.0.1/v1").is_err());
        assert!(validate_endpoint_url("https://127.0.0.2/v1").is_err());

        // Localhost hostname.
        assert!(validate_endpoint_url("https://localhost/v1").is_err());
        assert!(validate_endpoint_url("https://something.localhost/v1").is_err());

        // Private ranges.
        assert!(validate_endpoint_url("https://10.0.0.1/v1").is_err());
        assert!(validate_endpoint_url("https://192.168.1.1/v1").is_err());
        assert!(validate_endpoint_url("https://172.16.0.1/v1").is_err());

        // Link-local (AWS metadata endpoint).
        assert!(validate_endpoint_url("https://169.254.169.254/v1").is_err());

        // .internal and .local.
        assert!(validate_endpoint_url("https://metadata.internal/v1").is_err());
        assert!(validate_endpoint_url("https://myhost.local/v1").is_err());

        // Unspecified.
        assert!(validate_endpoint_url("https://0.0.0.0/v1").is_err());

        // HTTP (not HTTPS) should be rejected.
        assert!(validate_endpoint_url("http://generativelanguage.googleapis.com/v1").is_err());

        // Valid HTTPS to public hosts should pass.
        assert!(
            validate_endpoint_url("https://generativelanguage.googleapis.com/v1").is_ok()
        );
        assert!(validate_endpoint_url("https://us-central1-aiplatform.googleapis.com").is_ok());
    }

    // -- Config validates endpoint --

    #[test]
    fn config_validate_endpoint_default_ok() {
        let config = GeminiConfig::default();
        assert!(config.validate_endpoint().is_ok());
    }

    #[test]
    fn config_validate_endpoint_private_blocked() {
        let config = GeminiConfig {
            endpoint_url: "https://192.168.1.1/v1".into(),
            ..Default::default()
        };
        assert!(config.validate_endpoint().is_err());
    }

    // -- API key masking --

    #[test]
    fn api_key_masked_in_debug() {
        let key = MaskedApiKey("AIzaSyB1234567890abcdef".into());
        let debug = format!("{key:?}");
        assert!(debug.contains("AIza***"));
        assert!(!debug.contains("1234567890abcdef"));
    }

    #[test]
    fn api_key_masked_in_display() {
        let key = MaskedApiKey("AIzaSyB1234567890abcdef".into());
        let display = format!("{key}");
        assert!(display.contains("AIza***"));
        assert!(!display.contains("1234567890abcdef"));
    }

    // -- Sanitization --

    #[test]
    fn sanitize_strips_control_chars() {
        let dirty = "hello\x00world\x01\x02\x1F";
        let clean = sanitize_text(dirty);
        assert_eq!(clean, "helloworld");
    }

    #[test]
    fn sanitize_preserves_whitespace() {
        let text = "hello\nworld\ttab\r\n";
        let clean = sanitize_text(text);
        assert_eq!(clean, text);
    }

    #[test]
    fn sanitize_json_value_recursion() {
        let dirty = serde_json::json!({
            "clean": "normal",
            "dirty\x00key": "value\x01",
            "nested": {
                "deep": "control\x02char"
            },
            "array": ["ok", "bad\x03value"]
        });

        let clean = sanitize_json_value(&dirty);
        assert_eq!(clean["clean"], "normal");
        assert_eq!(clean["dirtykey"], "value");
        assert_eq!(clean["nested"]["deep"], "controlchar");
        assert_eq!(clean["array"][1], "badvalue");
    }

    // -- Function call with control chars in args (security test) --

    #[test]
    fn function_call_args_sanitized() {
        let fc = GeminiFunctionCall {
            name: "eval\x00code".into(),
            args: serde_json::json!({"code": "rm -rf /\x00"}),
        };

        let response = GeminiResponse {
            candidates: vec![GeminiCandidate {
                content: GeminiContent {
                    role: "model".into(),
                    parts: vec![GeminiPart::FunctionCall(fc)],
                },
                finish_reason: Some("STOP".into()),
                safety_ratings: vec![],
            }],
            usage_metadata: None,
        };

        let calls = response.function_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "evalcode");
        assert_eq!(calls[0].args["code"], "rm -rf /");
    }

    // -- Response content sanitized --

    #[test]
    fn response_text_sanitized() {
        let response = GeminiResponse {
            candidates: vec![GeminiCandidate {
                content: GeminiContent {
                    role: "model".into(),
                    parts: vec![GeminiPart::Text("safe text\x00hidden".into())],
                },
                finish_reason: None,
                safety_ratings: vec![],
            }],
            usage_metadata: None,
        };

        let text = response.text_content().unwrap();
        assert_eq!(text, "safe texthidden");
        assert!(!text.contains('\x00'));
    }

    // -- GeminiResponse with function call parsing from JSON --

    #[test]
    fn gemini_response_function_call_from_json() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "functionCall": {
                            "name": "get_weather",
                            "args": {"location": "NYC", "unit": "celsius"}
                        }
                    }]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 20,
                "candidatesTokenCount": 5,
                "totalTokenCount": 25
            }
        }"#;

        let response: GeminiResponse = serde_json::from_str(json).unwrap();
        let calls = response.function_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "get_weather");
        assert_eq!(calls[0].args["location"], "NYC");
        assert_eq!(calls[0].args["unit"], "celsius");

        let usage = response.usage();
        assert_eq!(usage.prompt_token_count, 20);
        assert_eq!(usage.candidates_token_count, 5);
        assert_eq!(usage.total_token_count, 25);
    }

    // -- Empty tools list produces empty vec --

    #[test]
    fn empty_tools_produces_empty_vec() {
        let result = tools_to_gemini(&[]);
        assert!(result.is_empty());
    }

    // -- Config serialization roundtrip --

    #[test]
    fn config_serialization_roundtrip() {
        let config = GeminiConfig {
            api_key_env: "MY_KEY_VAR".into(),
            model: "gemini-1.5-pro".into(),
            endpoint_url: "https://custom.example.com/v1".into(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let back: GeminiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);

        // Verify no raw secret in serialized output.
        assert!(json.contains("MY_KEY_VAR"));
        assert!(!json.contains("api_key\""));
    }

    // -- Security: Cedar action required (tests that GeminiApiCall ActionKind exists) --

    #[test]
    fn gemini_requires_cedar_policy() {
        use crate::ActionKind;

        // Verify the GeminiApiCall variant exists and can be constructed.
        let action = ActionKind::GeminiApiCall {
            model: "gemini-pro".into(),
            endpoint: "https://generativelanguage.googleapis.com".into(),
            input_tokens: 100,
            output_tokens: 50,
        };

        // Verify it serializes (i.e., is a proper ActionKind variant).
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("GeminiApiCall"));
        assert!(json.contains("gemini-pro"));

        // Verify round-trip.
        let back: ActionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, action);
    }
}
