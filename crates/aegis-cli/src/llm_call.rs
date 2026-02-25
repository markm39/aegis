//! Minimal blocking LLM client for use outside the streaming chat TUI.
//!
//! Used by the onboarding wizard to call the LLM before the daemon starts.
//! Makes a single non-streaming HTTP request and returns the full reply.

use aegis_types::CredentialStore;
use aegis_types::providers::{ApiType, provider_by_id};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single message in a conversation.
#[derive(Debug, Clone)]
pub struct SimpleLlmMessage {
    pub role: String,
    pub content: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Call the LLM synchronously and return the assistant's reply.
///
/// Detects the provider from the model name using the same heuristics as the
/// streaming module. Resolves credentials from the credential store, then
/// env vars. Blocks the calling thread (intended to be called from a
/// `std::thread::spawn` background thread).
pub fn call_llm_simple(
    model: &str,
    system: &str,
    messages: &[SimpleLlmMessage],
    credential_store: &CredentialStore,
) -> Result<String, String> {
    let (provider_id, api_type) = resolve_model_provider(model);

    let key = resolve_key(provider_id, credential_store)?;

    match api_type {
        ApiType::AnthropicMessages => call_anthropic(model, system, messages, &key),
        ApiType::OpenaiCompletions | ApiType::OpenaiResponses | ApiType::GithubCopilot => {
            call_openai(model, system, messages, &key, provider_id)
        }
        _ => Err(format!(
            "provider '{}' is not supported by the simple LLM client",
            provider_id
        )),
    }
}

// ---------------------------------------------------------------------------
// Provider detection (mirrors streaming.rs logic)
// ---------------------------------------------------------------------------

fn resolve_model_provider(model: &str) -> (&'static str, ApiType) {
    let lower = model.to_lowercase();

    // Check ALL_PROVIDERS catalog first.
    use aegis_types::providers::ALL_PROVIDERS;
    for provider in ALL_PROVIDERS.iter() {
        for m in provider.models {
            if lower == m.id.to_lowercase()
                || lower.starts_with(&format!("{}-", m.id.to_lowercase()))
            {
                return (provider.id, provider.api_type);
            }
        }
        if !provider.default_model.is_empty()
            && lower == provider.default_model.to_lowercase()
        {
            return (provider.id, provider.api_type);
        }
    }

    // Legacy prefix fallbacks.
    if lower.starts_with("claude-") {
        return ("anthropic", ApiType::AnthropicMessages);
    }
    if lower.starts_with("gpt-")
        || lower.starts_with("o1-")
        || lower.starts_with("o3-")
        || lower.starts_with("o4-")
    {
        return ("openai", ApiType::OpenaiCompletions);
    }

    // Default to Anthropic for unknown models (most likely claude-* aliases).
    ("anthropic", ApiType::AnthropicMessages)
}

// ---------------------------------------------------------------------------
// Credential resolution
// ---------------------------------------------------------------------------

fn resolve_key(provider_id: &str, store: &CredentialStore) -> Result<String, String> {
    if let Some(provider) = provider_by_id(provider_id) {
        if let Some(resolved) = store.resolve_api_key(provider) {
            return Ok(resolved.key);
        }
    }
    Err(format!(
        "No API key found for provider '{provider_id}'. \
         Set the environment variable or run `aegis` to authenticate."
    ))
}

// ---------------------------------------------------------------------------
// Anthropic Messages API
// ---------------------------------------------------------------------------

fn call_anthropic(
    model: &str,
    system: &str,
    messages: &[SimpleLlmMessage],
    api_key: &str,
) -> Result<String, String> {
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": messages.iter().map(|m| serde_json::json!({
            "role": m.role,
            "content": m.content,
        })).collect::<Vec<_>>(),
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("HTTP error: {e}"))?;

    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("failed to read response: {e}"))?;

    if !status.is_success() {
        return Err(format!("Anthropic API error {status}: {text}"));
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("JSON parse error: {e}"))?;

    parsed["content"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("unexpected response shape: {text}"))
}

// ---------------------------------------------------------------------------
// OpenAI Chat Completions API
// ---------------------------------------------------------------------------

fn call_openai(
    model: &str,
    system: &str,
    messages: &[SimpleLlmMessage],
    api_key: &str,
    provider_id: &str,
) -> Result<String, String> {
    let mut all_messages = vec![serde_json::json!({
        "role": "system",
        "content": system,
    })];
    all_messages.extend(messages.iter().map(|m| {
        serde_json::json!({
            "role": m.role,
            "content": m.content,
        })
    }));

    let body = serde_json::json!({
        "model": model,
        "max_tokens": 1024,
        "messages": all_messages,
    });

    let base_url = resolve_openai_base_url(provider_id);
    let url = format!("{base_url}/v1/chat/completions");

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("HTTP error: {e}"))?;

    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("failed to read response: {e}"))?;

    if !status.is_success() {
        return Err(format!("OpenAI API error {status}: {text}"));
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("JSON parse error: {e}"))?;

    parsed["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("unexpected response shape: {text}"))
}

fn resolve_openai_base_url(provider_id: &str) -> String {
    provider_by_id(provider_id)
        .map(|p| p.base_url.trim_end_matches('/').to_string())
        .unwrap_or_else(|| "https://api.openai.com".to_string())
}
