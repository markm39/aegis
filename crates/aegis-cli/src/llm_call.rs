//! Minimal blocking LLM client for use outside the streaming chat TUI.
//!
//! Used by the onboarding wizard to call the LLM before the daemon starts.
//! Makes a single non-streaming HTTP request and returns the full reply.
//!
//! Provider detection, credential resolution, base-URL resolution, and
//! auth-header selection all mirror the logic in `chat_tui/streaming.rs`
//! exactly so every provider that works in the chat TUI also works here.

use aegis_types::credentials::{CredentialStore, ResolvedKey};
use aegis_types::providers::{ApiType, ALL_PROVIDERS, provider_by_id};

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
/// streaming module. Resolves credentials and base URL from the credential
/// store (including any custom base URL override the user stored). Blocks the
/// calling thread (intended for `std::thread::spawn` background threads).
pub fn call_llm_simple(
    model: &str,
    system: &str,
    messages: &[SimpleLlmMessage],
    credential_store: &CredentialStore,
) -> Result<String, String> {
    let (provider_id, api_type) = resolve_model_provider(model)?;

    let provider = provider_by_id(provider_id)
        .ok_or_else(|| format!("unknown provider: {provider_id}"))?;

    let cred = credential_store
        .resolve_api_key(provider)
        .ok_or_else(|| {
            format!(
                "No API key found for provider '{provider_id}'. \
                 Set {} or run `aegis` to authenticate.",
                provider.env_var
            )
        })?;

    let base_url = resolve_base_url(provider_id, credential_store);

    match api_type {
        ApiType::AnthropicMessages => {
            call_anthropic(model, system, messages, &cred, &base_url, provider_id)
        }
        ApiType::OpenaiCompletions | ApiType::OpenaiResponses | ApiType::GithubCopilot => {
            call_openai(model, system, messages, &cred, &base_url, provider_id)
        }
        _ => Err(format!(
            "provider '{provider_id}' uses an API type not supported by the simple LLM client"
        )),
    }
}

// ---------------------------------------------------------------------------
// Provider detection — mirrors streaming.rs exactly
// ---------------------------------------------------------------------------

fn resolve_model_provider(model: &str) -> Result<(&'static str, ApiType), String> {
    let lower = model.to_lowercase();

    for provider in ALL_PROVIDERS.iter() {
        for m in provider.models {
            if lower == m.id.to_lowercase()
                || lower.starts_with(&format!("{}-", m.id.to_lowercase()))
            {
                return Ok((provider.id, provider.api_type));
            }
        }
        if !provider.default_model.is_empty()
            && lower == provider.default_model.to_lowercase()
        {
            return Ok((provider.id, provider.api_type));
        }
    }

    // Legacy prefix fallbacks (same order as streaming.rs).
    if lower.starts_with("claude-") {
        return Ok(("anthropic", ApiType::AnthropicMessages));
    }
    if lower.starts_with("gpt-")
        || lower.starts_with("o1-")
        || lower.starts_with("o3-")
        || lower.starts_with("o4-")
    {
        return Ok(("openai", ApiType::OpenaiCompletions));
    }

    Err(format!(
        "Cannot determine LLM provider for model '{model}'. \
         Please select a provider in the wizard."
    ))
}

// ---------------------------------------------------------------------------
// Base URL resolution — mirrors streaming.rs resolve_provider_base_url
// ---------------------------------------------------------------------------

fn resolve_base_url(provider_id: &str, store: &CredentialStore) -> String {
    let provider = match provider_by_id(provider_id) {
        Some(p) => p,
        None => return String::new(),
    };
    // Environment variable override takes precedence (same as streaming.rs).
    let env_key = format!("{}_BASE_URL", provider_id.to_uppercase().replace('-', "_"));
    if let Ok(url) = std::env::var(&env_key) {
        if !url.is_empty() {
            return url;
        }
    }
    store.resolve_base_url(provider)
}

// ---------------------------------------------------------------------------
// Anthropic Messages API
// ---------------------------------------------------------------------------

fn call_anthropic(
    model: &str,
    system: &str,
    messages: &[SimpleLlmMessage],
    cred: &ResolvedKey,
    base_url: &str,
    provider_id: &str,
) -> Result<String, String> {
    let url = format!("{}/v1/messages", base_url.trim_end_matches('/'));

    let body = serde_json::json!({
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": messages.iter().map(|m| serde_json::json!({
            "role": m.role,
            "content": m.content,
        })).collect::<Vec<_>>(),
    });

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    // Mirror streaming.rs: Bearer token for OAuth/CLI credentials, x-api-key otherwise.
    let mut req = client.post(&url);
    if cred.is_bearer() {
        req = req.header("Authorization", format!("Bearer {}", cred.key));
    } else {
        req = req.header("x-api-key", &cred.key);
    }
    let resp = req
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("{provider_id} request failed: {e}"))?;

    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("failed to read response: {e}"))?;

    if !status.is_success() {
        return Err(format!("{provider_id} API error {status}: {text}"));
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("JSON parse error: {e}"))?;

    // Anthropic content is an array of typed blocks. Providers that support
    // extended thinking (e.g. MiniMax) prepend a {"type":"thinking",...} block
    // before the {"type":"text",...} block, so we must scan the array rather
    // than assuming [0] is the text block.
    if let Some(blocks) = parsed["content"].as_array() {
        for block in blocks {
            if block["type"].as_str() == Some("text") {
                if let Some(s) = block["text"].as_str() {
                    return Ok(s.to_string());
                }
            }
        }
    }

    Err(format!("unexpected response shape from {provider_id}: {text}"))
}

// ---------------------------------------------------------------------------
// OpenAI Chat Completions API
// ---------------------------------------------------------------------------

fn call_openai(
    model: &str,
    system: &str,
    messages: &[SimpleLlmMessage],
    cred: &ResolvedKey,
    base_url: &str,
    provider_id: &str,
) -> Result<String, String> {
    let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));

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

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", cred.key))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("{provider_id} request failed: {e}"))?;

    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("failed to read response: {e}"))?;

    if !status.is_success() {
        return Err(format!("{provider_id} API error {status}: {text}"));
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("JSON parse error: {e}"))?;

    parsed["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("unexpected response shape: {text}"))
}
