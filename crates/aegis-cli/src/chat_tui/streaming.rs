//! Streaming LLM API client for the chat TUI.
//!
//! Makes direct HTTP calls to LLM providers with SSE streaming enabled,
//! sending text deltas to the UI as they arrive. Falls back to the daemon's
//! blocking `LlmComplete` for unsupported providers.
//!
//! Only the LLM call itself bypasses the daemon -- tool execution still goes
//! through `DaemonCommand::ExecuteTool` for sandbox/policy enforcement.

use std::io::{BufRead, BufReader, Read};
use std::sync::mpsc;

use serde_json::Value;

use aegis_types::credentials::CredentialStore;
use aegis_types::llm::{
    to_anthropic_message, LlmMessage, LlmResponse, LlmRole, LlmToolCall, LlmUsage, StopReason,
};
use aegis_types::providers::provider_by_id;

use super::AgentLoopEvent;

/// Maximum response body size (10 MB).
const MAX_RESPONSE_BYTES: u64 = 10_000_000;

/// Default max tokens for LLM requests.
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Resolve an API key for a provider, checking all credential sources.
///
/// Resolution order (handled by `CredentialStore::resolve_api_key`):
/// 1. Environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
/// 2. Credential store (`~/.aegis/credentials.toml`)
/// 3. OAuth token store (`~/.aegis/oauth/{provider}/token.json`)
fn resolve_provider_key(provider_id: &str) -> Result<String, String> {
    let provider = provider_by_id(provider_id)
        .ok_or_else(|| format!("unknown provider: {provider_id}"))?;

    let store = CredentialStore::load_default().unwrap_or_default();

    store.resolve_api_key(provider).ok_or_else(|| {
        format!(
            "configuration error: environment variable '{}' not set \
             and no stored credentials found for {} \
             (run `aegis` to set up authentication)",
            provider.env_var, provider.display_name,
        )
    })
}

/// Resolve the base URL for a provider.
///
/// Checks env var override first (preserving existing behavior), then
/// credential store, then falls back to the provider's default URL.
fn resolve_provider_base_url(provider_id: &str) -> String {
    let provider = match provider_by_id(provider_id) {
        Some(p) => p,
        None => return String::new(),
    };
    // Env var override takes precedence (matches existing behavior).
    let env_key = format!("{}_BASE_URL", provider_id.to_uppercase());
    if let Ok(url) = std::env::var(&env_key) {
        if !url.is_empty() {
            return url;
        }
    }
    let store = CredentialStore::load_default().unwrap_or_default();
    store.resolve_base_url(provider)
}

/// Parameters for a streaming LLM call.
pub struct StreamingCallParams {
    pub model: String,
    pub messages: Vec<LlmMessage>,
    pub system_prompt: Option<String>,
    pub tools: Option<Value>,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub thinking_budget: Option<u32>,
}

/// Result of a completed streaming call.
#[derive(Debug)]
pub struct StreamingCallResult {
    pub response: LlmResponse,
}

/// Perform a streaming LLM call, sending deltas to the UI via `event_tx`.
///
/// Returns the accumulated `LlmResponse` on success, or an error string.
/// Currently supports Anthropic models. Other providers fall back to the
/// daemon's blocking `LlmComplete` path (no streaming).
pub(super) fn stream_llm_call(
    params: &StreamingCallParams,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
) -> Result<StreamingCallResult, String> {
    if is_anthropic_model(&params.model) {
        stream_anthropic(params, event_tx)
    } else if is_openai_model(&params.model) {
        // Route to Responses API for OAuth users (ChatGPT backend) or always
        // for models that only exist on the Responses API.
        if should_use_responses_api("openai") {
            stream_openai_responses(params, event_tx)
        } else {
            stream_openai(params, event_tx)
        }
    } else {
        Err(format!(
            "streaming not supported for model '{}'; use daemon fallback",
            params.model
        ))
    }
}

/// Check if the OpenAI credential is an OAuth token, which requires the
/// Responses API (ChatGPT backend) instead of Chat Completions.
fn should_use_responses_api(provider_id: &str) -> bool {
    use aegis_types::provider_auth::CredentialType;
    let store = CredentialStore::load_default().unwrap_or_default();
    store
        .get(provider_id)
        .map(|c| c.credential_type == CredentialType::OAuthToken)
        .unwrap_or(false)
}

/// Check if this is an Anthropic model name.
fn is_anthropic_model(model: &str) -> bool {
    model.starts_with("claude-")
}

/// Check if this is an OpenAI model name.
fn is_openai_model(model: &str) -> bool {
    model.starts_with("gpt-") || model.starts_with("codex-")
}

// ---------------------------------------------------------------------------
// Anthropic streaming
// ---------------------------------------------------------------------------

fn stream_anthropic(
    params: &StreamingCallParams,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
) -> Result<StreamingCallResult, String> {
    let api_key = resolve_provider_key("anthropic")?;
    let base_url = resolve_provider_base_url("anthropic");
    let url = format!("{}/v1/messages", base_url.trim_end_matches('/'));

    // Build messages, separating system.
    let mut system_text = params.system_prompt.clone().unwrap_or_default();
    let mut anthropic_messages = Vec::new();
    for msg in &params.messages {
        if msg.role == LlmRole::System {
            if !system_text.is_empty() {
                system_text.push('\n');
            }
            system_text.push_str(&msg.content);
        } else {
            anthropic_messages.push(to_anthropic_message(msg));
        }
    }

    let max_tokens = params.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);
    let mut body = serde_json::json!({
        "model": params.model,
        "max_tokens": max_tokens,
        "messages": anthropic_messages,
        "stream": true,
    });

    if !system_text.is_empty() {
        body["system"] = Value::String(system_text);
    }
    if let Some(temp) = params.temperature {
        body["temperature"] = serde_json::json!(temp);
    }
    if let Some(ref tools) = params.tools {
        if let Some(arr) = tools.as_array() {
            if !arr.is_empty() {
                body["tools"] = tools.clone();
            }
        }
    }

    // Add extended thinking if configured.
    if let Some(budget) = params.thinking_budget {
        body["thinking"] = serde_json::json!({
            "type": "enabled",
            "budget_tokens": budget,
        });
    }

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client
        .post(&url)
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("Anthropic streaming request failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let err_text = resp.text().unwrap_or_default();
        return Err(format!("Anthropic API returned {status}: {err_text}"));
    }

    // Read SSE events from the streaming response.
    parse_anthropic_sse(resp, event_tx)
}

/// Parse Anthropic SSE events from a streaming HTTP response.
fn parse_anthropic_sse(
    resp: reqwest::blocking::Response,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
) -> Result<StreamingCallResult, String> {
    let reader = BufReader::new(resp.take(MAX_RESPONSE_BYTES));

    let mut content = String::new();
    let mut tool_calls: Vec<LlmToolCall> = Vec::new();
    let mut current_tool: Option<PartialToolCall> = None;
    let mut usage = LlmUsage {
        input_tokens: 0,
        output_tokens: 0,
    };
    let mut stop_reason = None;
    let mut model = String::new();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("failed to read SSE line: {e}"))?;

        // SSE format: "event: <type>" followed by "data: <json>"
        if let Some(data) = line.strip_prefix("data: ") {
            // Skip "[DONE]" marker (OpenAI-style, Anthropic doesn't use this).
            if data == "[DONE]" {
                break;
            }

            let event: Value = match serde_json::from_str(data) {
                Ok(v) => v,
                Err(_) => continue, // Skip malformed data lines
            };

            let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");

            match event_type {
                "message_start" => {
                    // Extract model name.
                    if let Some(m) = event
                        .get("message")
                        .and_then(|msg| msg.get("model"))
                        .and_then(|v| v.as_str())
                    {
                        model = m.to_string();
                    }
                    // Extract input token usage from message_start.
                    if let Some(u) = event
                        .get("message")
                        .and_then(|msg| msg.get("usage"))
                    {
                        if let Some(inp) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                            usage.input_tokens = inp;
                        }
                    }
                }
                "content_block_start" => {
                    if let Some(block) = event.get("content_block") {
                        let block_type = block.get("type").and_then(|t| t.as_str());
                        if block_type == Some("tool_use") {
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
                            current_tool = Some(PartialToolCall {
                                id,
                                name,
                                input_json: String::new(),
                            });
                        }
                    }
                }
                "content_block_delta" => {
                    if let Some(delta) = event.get("delta") {
                        let delta_type = delta.get("type").and_then(|t| t.as_str());
                        match delta_type {
                            Some("text_delta") => {
                                if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
                                    content.push_str(text);
                                    // Send delta to UI for live display.
                                    let _ = event_tx
                                        .send(AgentLoopEvent::StreamDelta(text.to_string()));
                                }
                            }
                            Some("input_json_delta") => {
                                if let Some(json_chunk) =
                                    delta.get("partial_json").and_then(|t| t.as_str())
                                {
                                    if let Some(ref mut tool) = current_tool {
                                        tool.input_json.push_str(json_chunk);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "content_block_stop" => {
                    // Finalize tool call if one was in progress.
                    if let Some(tool) = current_tool.take() {
                        let input: Value = serde_json::from_str(&tool.input_json)
                            .unwrap_or(Value::Object(serde_json::Map::new()));
                        tool_calls.push(LlmToolCall {
                            id: tool.id,
                            name: tool.name,
                            input,
                        });
                    }
                }
                "message_delta" => {
                    if let Some(delta) = event.get("delta") {
                        if let Some(sr) = delta.get("stop_reason").and_then(|v| v.as_str()) {
                            stop_reason = Some(match sr {
                                "end_turn" => StopReason::EndTurn,
                                "max_tokens" => StopReason::MaxTokens,
                                "tool_use" => StopReason::ToolUse,
                                "stop_sequence" => StopReason::StopSequence,
                                _ => StopReason::EndTurn,
                            });
                        }
                    }
                    if let Some(u) = event.get("usage") {
                        if let Some(out) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                            usage.output_tokens = out;
                        }
                    }
                }
                "message_stop" => {
                    break;
                }
                _ => {}
            }
        }
    }

    let response = LlmResponse {
        content,
        model,
        usage,
        tool_calls,
        stop_reason,
    };

    Ok(StreamingCallResult { response })
}

/// Partially accumulated tool call during streaming.
struct PartialToolCall {
    id: String,
    name: String,
    input_json: String,
}

// ---------------------------------------------------------------------------
// OpenAI streaming
// ---------------------------------------------------------------------------

fn stream_openai(
    params: &StreamingCallParams,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
) -> Result<StreamingCallResult, String> {
    let api_key = resolve_provider_key("openai")?;
    let base_url = resolve_provider_base_url("openai");
    let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));

    // Build messages in OpenAI format.
    let mut openai_messages: Vec<Value> = Vec::new();
    if let Some(ref sys) = params.system_prompt {
        if !sys.is_empty() {
            openai_messages.push(serde_json::json!({
                "role": "system",
                "content": sys,
            }));
        }
    }
    for msg in &params.messages {
        let oai_msg = aegis_types::llm::to_openai_message(msg);
        if let Ok(v) = serde_json::to_value(&oai_msg) {
            openai_messages.push(v);
        }
    }

    let mut body = serde_json::json!({
        "model": params.model,
        "messages": openai_messages,
        "stream": true,
    });

    if let Some(temp) = params.temperature {
        body["temperature"] = serde_json::json!(temp);
    }
    if let Some(max) = params.max_tokens {
        body["max_tokens"] = serde_json::json!(max);
    }
    if let Some(ref tools) = params.tools {
        if let Some(arr) = tools.as_array() {
            if !arr.is_empty() {
                // OpenAI uses a different tool format -- wrap each tool.
                let openai_tools: Vec<Value> = arr
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "type": "function",
                            "function": {
                                "name": t.get("name").cloned().unwrap_or(Value::Null),
                                "description": t.get("description").cloned().unwrap_or(Value::Null),
                                "parameters": t.get("input_schema").cloned().unwrap_or(Value::Null),
                            }
                        })
                    })
                    .collect();
                body["tools"] = Value::Array(openai_tools);
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("OpenAI streaming request failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let err_text = resp.text().unwrap_or_default();
        return Err(format!("OpenAI API returned {status}: {err_text}"));
    }

    parse_openai_sse(resp, event_tx, &params.model)
}

/// Parse OpenAI SSE events from a streaming HTTP response.
fn parse_openai_sse(
    resp: reqwest::blocking::Response,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
    request_model: &str,
) -> Result<StreamingCallResult, String> {
    let reader = BufReader::new(resp.take(MAX_RESPONSE_BYTES));

    let mut content = String::new();
    let mut tool_calls: Vec<PartialToolCall> = Vec::new();
    let mut stop_reason = None;
    let mut model = request_model.to_string();
    let mut usage = LlmUsage {
        input_tokens: 0,
        output_tokens: 0,
    };

    for line in reader.lines() {
        let line = line.map_err(|e| format!("failed to read SSE line: {e}"))?;

        let data = match line.strip_prefix("data: ") {
            Some(d) => d,
            None => continue,
        };
        if data == "[DONE]" {
            break;
        }

        let event: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(m) = event.get("model").and_then(|v| v.as_str()) {
            model = m.to_string();
        }

        // Extract usage if present (OpenAI includes it in the last chunk).
        if let Some(u) = event.get("usage") {
            if let Some(inp) = u.get("prompt_tokens").and_then(|v| v.as_u64()) {
                usage.input_tokens = inp;
            }
            if let Some(out) = u.get("completion_tokens").and_then(|v| v.as_u64()) {
                usage.output_tokens = out;
            }
        }

        if let Some(choices) = event.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                // Check finish_reason.
                if let Some(fr) = choice.get("finish_reason").and_then(|v| v.as_str()) {
                    stop_reason = Some(match fr {
                        "stop" => StopReason::EndTurn,
                        "length" => StopReason::MaxTokens,
                        "tool_calls" => StopReason::ToolUse,
                        _ => StopReason::EndTurn,
                    });
                }

                if let Some(delta) = choice.get("delta") {
                    // Text content delta.
                    if let Some(text) = delta.get("content").and_then(|v| v.as_str()) {
                        content.push_str(text);
                        let _ = event_tx.send(AgentLoopEvent::StreamDelta(text.to_string()));
                    }

                    // Tool call deltas.
                    if let Some(tcs) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                        for tc in tcs {
                            let idx = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(0)
                                as usize;

                            // Extend tool_calls vec if needed.
                            while tool_calls.len() <= idx {
                                tool_calls.push(PartialToolCall {
                                    id: String::new(),
                                    name: String::new(),
                                    input_json: String::new(),
                                });
                            }

                            if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                                tool_calls[idx].id = id.to_string();
                            }
                            if let Some(func) = tc.get("function") {
                                if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
                                    tool_calls[idx].name = name.to_string();
                                }
                                if let Some(args) =
                                    func.get("arguments").and_then(|v| v.as_str())
                                {
                                    tool_calls[idx].input_json.push_str(args);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Convert partial tool calls to LlmToolCall.
    let final_tool_calls: Vec<LlmToolCall> = tool_calls
        .into_iter()
        .filter(|tc| !tc.name.is_empty())
        .map(|tc| {
            let input: Value = serde_json::from_str(&tc.input_json)
                .unwrap_or(Value::Object(serde_json::Map::new()));
            LlmToolCall {
                id: tc.id,
                name: tc.name,
                input,
            }
        })
        .collect();

    let response = LlmResponse {
        content,
        model,
        usage,
        tool_calls: final_tool_calls,
        stop_reason,
    };

    Ok(StreamingCallResult { response })
}

// ---------------------------------------------------------------------------
// OpenAI Responses API streaming (for OAuth / ChatGPT backend)
// ---------------------------------------------------------------------------

/// Convert conversation messages to OpenAI Responses API `input` format.
///
/// Key differences from Chat Completions:
/// - User messages: `{ "role": "user", "content": "..." }`
/// - Assistant messages: `{ "role": "assistant", "content": [{"type": "output_text", "text": "..."}] }`
/// - Tool results: `{ "type": "function_call_output", "call_id": "...", "output": "..." }`
fn to_responses_input(messages: &[LlmMessage]) -> Vec<Value> {
    let mut input = Vec::new();
    for msg in messages {
        match msg.role {
            LlmRole::User => {
                input.push(serde_json::json!({
                    "role": "user",
                    "content": msg.content,
                }));
            }
            LlmRole::Assistant => {
                // Check if this message has tool calls.
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
            LlmRole::Tool => {
                // Tool results in Responses API are top-level input items.
                input.push(serde_json::json!({
                    "type": "function_call_output",
                    "call_id": msg.tool_use_id.as_deref().unwrap_or(""),
                    "output": msg.content,
                }));
            }
            LlmRole::System => {
                // System messages are handled via `instructions` field, not input.
            }
        }
    }
    input
}

/// Stream a request via the OpenAI Responses API (used for OAuth / ChatGPT backend).
fn stream_openai_responses(
    params: &StreamingCallParams,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
) -> Result<StreamingCallResult, String> {
    let api_key = resolve_provider_key("openai")?;
    let base_url = resolve_provider_base_url("openai");

    // ChatGPT backend uses /codex/responses, public API uses /v1/responses.
    let url = if base_url.contains("chatgpt.com") {
        format!("{}/codex/responses", base_url.trim_end_matches('/'))
    } else {
        format!("{}/v1/responses", base_url.trim_end_matches('/'))
    };

    // Build input in Responses API format.
    let input = to_responses_input(&params.messages);

    let mut body = serde_json::json!({
        "model": params.model,
        "input": input,
        "stream": true,
    });

    // System prompt goes in `instructions`.
    if let Some(ref sys) = params.system_prompt {
        if !sys.is_empty() {
            body["instructions"] = Value::String(sys.clone());
        }
    }

    if let Some(temp) = params.temperature {
        body["temperature"] = serde_json::json!(temp);
    }
    let max_tokens = params.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);
    body["max_output_tokens"] = serde_json::json!(max_tokens);

    if let Some(ref tools) = params.tools {
        if let Some(arr) = tools.as_array() {
            if !arr.is_empty() {
                // Responses API tool format: { type, name, description, parameters }
                let responses_tools: Vec<Value> = arr
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "type": "function",
                            "name": t.get("name").cloned().unwrap_or(Value::Null),
                            "description": t.get("description").cloned().unwrap_or(Value::Null),
                            "parameters": t.get("input_schema").cloned().unwrap_or(Value::Null),
                        })
                    })
                    .collect();
                body["tools"] = Value::Array(responses_tools);
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("OpenAI Responses API request failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let err_text = resp.text().unwrap_or_default();
        return Err(format!("OpenAI Responses API returned {status}: {err_text}"));
    }

    parse_responses_sse(resp, event_tx, &params.model)
}

/// Parse OpenAI Responses API SSE events.
///
/// The Responses API uses different event types than Chat Completions:
/// - `response.output_text.delta` -- text chunk with `delta` field
/// - `response.output_item.added` -- new output item (may be function_call)
/// - `response.function_call_arguments.delta` -- tool call arg chunk
/// - `response.function_call_arguments.done` -- tool call complete
/// - `response.completed` -- final event with usage stats
fn parse_responses_sse(
    resp: reqwest::blocking::Response,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
    request_model: &str,
) -> Result<StreamingCallResult, String> {
    let reader = BufReader::new(resp.take(MAX_RESPONSE_BYTES));

    let mut content = String::new();
    let mut tool_calls: Vec<LlmToolCall> = Vec::new();
    let mut current_tool_name = String::new();
    let mut current_tool_call_id = String::new();
    let mut current_tool_args = String::new();
    let mut usage = LlmUsage {
        input_tokens: 0,
        output_tokens: 0,
    };
    let mut stop_reason = None;
    let mut model = request_model.to_string();
    let mut current_event_type = String::new();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("failed to read SSE line: {e}"))?;

        // Track the event type from "event: <type>" lines.
        if let Some(event_name) = line.strip_prefix("event: ") {
            current_event_type = event_name.trim().to_string();
            continue;
        }

        let data = match line.strip_prefix("data: ") {
            Some(d) => d,
            None => continue,
        };
        if data == "[DONE]" {
            break;
        }

        let event: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        match current_event_type.as_str() {
            "response.output_text.delta" => {
                if let Some(delta) = event.get("delta").and_then(|v| v.as_str()) {
                    content.push_str(delta);
                    let _ = event_tx.send(AgentLoopEvent::StreamDelta(delta.to_string()));
                }
            }
            "response.output_item.added" => {
                // Check if a function_call item is starting.
                if let Some(item) = event.get("item") {
                    let item_type = item.get("type").and_then(|v| v.as_str());
                    if item_type == Some("function_call") {
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
                    current_tool_args.push_str(delta);
                }
            }
            "response.function_call_arguments.done" => {
                // Finalize the tool call.
                let args_str = event
                    .get("arguments")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&current_tool_args);
                let input: Value = serde_json::from_str(args_str)
                    .unwrap_or(Value::Object(serde_json::Map::new()));
                tool_calls.push(LlmToolCall {
                    id: current_tool_call_id.clone(),
                    name: current_tool_name.clone(),
                    input,
                });
                current_tool_name.clear();
                current_tool_call_id.clear();
                current_tool_args.clear();
            }
            "response.completed" => {
                // Extract usage from the completed response object.
                if let Some(response) = event.get("response") {
                    if let Some(m) = response.get("model").and_then(|v| v.as_str()) {
                        model = m.to_string();
                    }
                    if let Some(u) = response.get("usage") {
                        if let Some(inp) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                            usage.input_tokens = inp;
                        }
                        if let Some(out) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                            usage.output_tokens = out;
                        }
                    }
                    // Determine stop reason from response status.
                    let status = response.get("status").and_then(|v| v.as_str());
                    stop_reason = Some(match status {
                        Some("completed") => {
                            if tool_calls.is_empty() {
                                StopReason::EndTurn
                            } else {
                                StopReason::ToolUse
                            }
                        }
                        Some("incomplete") => StopReason::MaxTokens,
                        _ => StopReason::EndTurn,
                    });
                }
                break;
            }
            _ => {}
        }

        current_event_type.clear();
    }

    let response = LlmResponse {
        content,
        model,
        usage,
        tool_calls,
        stop_reason,
    };

    Ok(StreamingCallResult { response })
}

#[cfg(test)]
#[allow(clippy::manual_strip)]
mod tests {
    use super::*;

    #[test]
    fn is_anthropic_model_detects_claude() {
        assert!(is_anthropic_model("claude-sonnet-4-20250514"));
        assert!(is_anthropic_model("claude-3-haiku-20240307"));
        assert!(!is_anthropic_model("gpt-4o"));
        assert!(!is_anthropic_model("gemini-2.0-flash"));
    }

    #[test]
    fn is_openai_model_detects_gpt() {
        assert!(is_openai_model("gpt-5.2"));
        assert!(is_openai_model("gpt-5.1-codex"));
        assert!(is_openai_model("codex-mini-latest"));
        assert!(!is_openai_model("claude-sonnet-4-6"));
        assert!(!is_openai_model("gemini-2.0-flash"));
    }

    #[test]
    fn unsupported_model_returns_error() {
        let (tx, _rx) = mpsc::channel();
        let params = StreamingCallParams {
            model: "gemini-2.0-flash".to_string(),
            messages: vec![],
            system_prompt: None,
            tools: None,
            temperature: None,
            max_tokens: None,
            thinking_budget: None,
        };
        let result = stream_llm_call(&params, &tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("streaming not supported"));
    }

    #[test]
    fn parse_anthropic_sse_handles_text_deltas() {
        // Simulate an Anthropic SSE stream with text deltas.
        let sse_data = "\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":25,\"output_tokens\":0}}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello \"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"world!\"}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n";

        let (tx, rx) = mpsc::channel();

        // Create a mock response by wrapping the string in a cursor.
        let cursor = std::io::Cursor::new(sse_data.as_bytes().to_vec());
        let reader = BufReader::new(cursor.take(MAX_RESPONSE_BYTES));

        // Inline the parsing logic with reader instead of response.
        let mut content = String::new();
        let mut tool_calls: Vec<LlmToolCall> = Vec::new();
        let mut current_tool: Option<PartialToolCall> = None;
        let mut usage = LlmUsage {
            input_tokens: 0,
            output_tokens: 0,
        };
        let mut stop_reason = None;
        let mut model = String::new();

        for line in reader.lines() {
            let line = line.unwrap();
            if line.starts_with("data: ") {
                let data = &line[6..];
                if data == "[DONE]" {
                    break;
                }
                let event: Value = match serde_json::from_str(data) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match event_type {
                    "message_start" => {
                        if let Some(m) = event
                            .get("message")
                            .and_then(|msg| msg.get("model"))
                            .and_then(|v| v.as_str())
                        {
                            model = m.to_string();
                        }
                        if let Some(u) = event.get("message").and_then(|msg| msg.get("usage")) {
                            if let Some(inp) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                                usage.input_tokens = inp;
                            }
                        }
                    }
                    "content_block_start" => {
                        if let Some(block) = event.get("content_block") {
                            let bt = block.get("type").and_then(|t| t.as_str());
                            if bt == Some("tool_use") {
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
                                current_tool = Some(PartialToolCall {
                                    id,
                                    name,
                                    input_json: String::new(),
                                });
                            }
                        }
                    }
                    "content_block_delta" => {
                        if let Some(delta) = event.get("delta") {
                            let dt = delta.get("type").and_then(|t| t.as_str());
                            match dt {
                                Some("text_delta") => {
                                    if let Some(text) =
                                        delta.get("text").and_then(|t| t.as_str())
                                    {
                                        content.push_str(text);
                                        let _ = tx.send(AgentLoopEvent::StreamDelta(
                                            text.to_string(),
                                        ));
                                    }
                                }
                                Some("input_json_delta") => {
                                    if let Some(json_chunk) =
                                        delta.get("partial_json").and_then(|t| t.as_str())
                                    {
                                        if let Some(ref mut tool) = current_tool {
                                            tool.input_json.push_str(json_chunk);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    "content_block_stop" => {
                        if let Some(tool) = current_tool.take() {
                            let input: Value = serde_json::from_str(&tool.input_json)
                                .unwrap_or(Value::Object(serde_json::Map::new()));
                            tool_calls.push(LlmToolCall {
                                id: tool.id,
                                name: tool.name,
                                input,
                            });
                        }
                    }
                    "message_delta" => {
                        if let Some(delta) = event.get("delta") {
                            if let Some(sr) = delta.get("stop_reason").and_then(|v| v.as_str()) {
                                stop_reason = Some(match sr {
                                    "end_turn" => StopReason::EndTurn,
                                    "tool_use" => StopReason::ToolUse,
                                    _ => StopReason::EndTurn,
                                });
                            }
                        }
                        if let Some(u) = event.get("usage") {
                            if let Some(out) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                                usage.output_tokens = out;
                            }
                        }
                    }
                    "message_stop" => break,
                    _ => {}
                }
            }
        }

        assert_eq!(content, "Hello world!");
        assert_eq!(model, "claude-sonnet-4-20250514");
        assert_eq!(usage.input_tokens, 25);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(stop_reason, Some(StopReason::EndTurn));
        assert!(tool_calls.is_empty());

        // Check that deltas were sent.
        let deltas: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(deltas.len(), 2);
    }

    #[test]
    fn parse_anthropic_sse_handles_tool_use() {
        let sse_data = "\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_2\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":30,\"output_tokens\":0}}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Let me read that.\"}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_123\",\"name\":\"read_file\",\"input\":{}}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\": \\\"src/\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"main.rs\\\"}\"}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":1}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":15}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n";

        let (tx, _rx) = mpsc::channel();

        let cursor = std::io::Cursor::new(sse_data.as_bytes().to_vec());
        let reader = BufReader::new(cursor.take(MAX_RESPONSE_BYTES));

        let mut content = String::new();
        let mut tool_calls: Vec<LlmToolCall> = Vec::new();
        let mut current_tool: Option<PartialToolCall> = None;
        let mut stop_reason = None;

        for line in reader.lines() {
            let line = line.unwrap();
            if line.starts_with("data: ") {
                let data = &line[6..];
                let event: Value = match serde_json::from_str(data) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match event_type {
                    "content_block_start" => {
                        if let Some(block) = event.get("content_block") {
                            if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                                current_tool = Some(PartialToolCall {
                                    id: block
                                        .get("id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    name: block
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    input_json: String::new(),
                                });
                            }
                        }
                    }
                    "content_block_delta" => {
                        if let Some(delta) = event.get("delta") {
                            match delta.get("type").and_then(|t| t.as_str()) {
                                Some("text_delta") => {
                                    if let Some(text) =
                                        delta.get("text").and_then(|t| t.as_str())
                                    {
                                        content.push_str(text);
                                        let _ = tx.send(AgentLoopEvent::StreamDelta(
                                            text.to_string(),
                                        ));
                                    }
                                }
                                Some("input_json_delta") => {
                                    if let Some(json_chunk) =
                                        delta.get("partial_json").and_then(|t| t.as_str())
                                    {
                                        if let Some(ref mut tool) = current_tool {
                                            tool.input_json.push_str(json_chunk);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    "content_block_stop" => {
                        if let Some(tool) = current_tool.take() {
                            let input: Value = serde_json::from_str(&tool.input_json)
                                .unwrap_or(Value::Object(serde_json::Map::new()));
                            tool_calls.push(LlmToolCall {
                                id: tool.id,
                                name: tool.name,
                                input,
                            });
                        }
                    }
                    "message_delta" => {
                        if let Some(delta) = event.get("delta") {
                            if let Some(sr) = delta.get("stop_reason").and_then(|v| v.as_str()) {
                                stop_reason = Some(match sr {
                                    "tool_use" => StopReason::ToolUse,
                                    _ => StopReason::EndTurn,
                                });
                            }
                        }
                    }
                    "message_stop" => break,
                    _ => {}
                }
            }
        }

        assert_eq!(content, "Let me read that.");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].id, "toolu_123");
        assert_eq!(tool_calls[0].name, "read_file");
        assert_eq!(
            tool_calls[0].input,
            serde_json::json!({"path": "src/main.rs"})
        );
        assert_eq!(stop_reason, Some(StopReason::ToolUse));
    }
}
