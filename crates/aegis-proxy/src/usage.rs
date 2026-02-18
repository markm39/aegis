//! HTTP reverse proxy for API usage tracking.
//!
//! Starts a local HTTP server that intercepts AI tool API traffic,
//! forwards requests to the real upstream endpoints, and extracts
//! token/model usage data from responses (including streaming SSE).
//! Usage data is logged to the audit ledger as `ActionKind::ApiUsage`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use bytes::BytesMut;
use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use uuid::Uuid;

use aegis_ledger::AuditStore;
use aegis_types::{Action, ActionKind, Verdict};

/// Shared state for the proxy handlers.
#[derive(Clone)]
struct ProxyState {
    store: Arc<Mutex<AuditStore>>,
    principal: String,
    session_id: Option<Uuid>,
    client: reqwest::Client,
    anthropic_api_key: Option<String>,
    openai_api_key: Option<String>,
}

/// An HTTP reverse proxy for API usage tracking.
pub struct UsageProxy {
    store: Arc<Mutex<AuditStore>>,
    principal: String,
    session_id: Option<Uuid>,
    port: u16,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Result of starting the proxy.
pub struct UsageProxyHandle {
    /// The actual port the proxy bound to.
    pub port: u16,
    /// Send `true` to shut the proxy down.
    pub shutdown_tx: watch::Sender<bool>,
}

impl UsageProxy {
    /// Create a new usage proxy.
    pub fn new(
        store: Arc<Mutex<AuditStore>>,
        principal: String,
        session_id: Option<Uuid>,
        port: u16,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            store,
            principal,
            session_id,
            port,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Start the proxy. Returns a handle with the actual bound port and shutdown sender.
    ///
    /// The proxy runs as a tokio task on the current runtime.
    pub async fn start(self) -> Result<UsageProxyHandle, String> {
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], self.port));

        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("failed to bind usage proxy on {bind_addr}: {e}"))?;

        let actual_addr = listener
            .local_addr()
            .map_err(|e| format!("failed to get local addr: {e}"))?;
        let actual_port = actual_addr.port();

        info!(addr = %actual_addr, "usage proxy listening");

        let state = ProxyState {
            store: self.store,
            principal: self.principal,
            session_id: self.session_id,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            anthropic_api_key: std::env::var("ANTHROPIC_API_KEY").ok(),
            openai_api_key: std::env::var("OPENAI_API_KEY").ok(),
        };

        let app = Router::new()
            .route("/anthropic/{*path}", any(handle_anthropic))
            .route("/openai/{*path}", any(handle_openai))
            .with_state(state);

        let mut shutdown_rx = self.shutdown_rx;
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.wait_for(|v| *v).await;
                })
                .await
                .ok();
            debug!("usage proxy shut down");
        });

        Ok(UsageProxyHandle {
            port: actual_port,
            shutdown_tx: self.shutdown_tx,
        })
    }
}

/// Provider type for routing and response parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    Anthropic,
    OpenAi,
}

impl Provider {
    fn name(&self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAi => "openai",
        }
    }

    fn upstream_base(&self) -> &'static str {
        match self {
            Provider::Anthropic => "https://api.anthropic.com",
            Provider::OpenAi => "https://api.openai.com",
        }
    }
}

/// Handle requests to /anthropic/*
async fn handle_anthropic(
    State(state): State<ProxyState>,
    method: Method,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    proxy_request(&state, Provider::Anthropic, &method, &path, &headers, body).await
}

/// Handle requests to /openai/*
async fn handle_openai(
    State(state): State<ProxyState>,
    method: Method,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    proxy_request(&state, Provider::OpenAi, &method, &path, &headers, body).await
}

/// Forward a request to the upstream provider and extract usage from the response.
async fn proxy_request(
    state: &ProxyState,
    provider: Provider,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    let upstream_url = format!("{}/{path}", provider.upstream_base());

    // Read the request body
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to read request body");
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };

    // Build upstream request
    let mut req_builder = state.client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST),
        &upstream_url,
    );

    // Forward relevant headers
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        // Skip hop-by-hop and host headers
        if matches!(
            name_str.as_str(),
            "host" | "connection" | "transfer-encoding" | "keep-alive"
        ) {
            continue;
        }
        if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
            req_builder = req_builder.header(name.as_str(), v);
        }
    }

    // Inject API key if not already present
    match provider {
        Provider::Anthropic => {
            if !headers.contains_key("x-api-key") {
                if let Some(ref key) = state.anthropic_api_key {
                    req_builder = req_builder.header("x-api-key", key);
                }
            }
            // Ensure anthropic-version header
            if !headers.contains_key("anthropic-version") {
                req_builder = req_builder.header("anthropic-version", "2023-06-01");
            }
        }
        Provider::OpenAi => {
            if !headers.contains_key("authorization") {
                if let Some(ref key) = state.openai_api_key {
                    req_builder = req_builder.header("authorization", format!("Bearer {key}"));
                }
            }
        }
    }

    req_builder = req_builder.body(body_bytes.to_vec());

    // Send upstream request
    let upstream_response = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, url = upstream_url, "upstream request failed");
            return (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response();
        }
    };

    let status = upstream_response.status();
    let response_headers = upstream_response.headers().clone();

    // Check if this is a streaming response
    let is_streaming = response_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("text/event-stream"));

    let endpoint = format!("/{path}");

    if is_streaming {
        handle_streaming_response(state, provider, &endpoint, status, &response_headers, upstream_response)
            .await
    } else {
        handle_non_streaming_response(state, provider, &endpoint, status, &response_headers, upstream_response)
            .await
    }
}

/// Handle a non-streaming response: read the full body, extract usage, log, return.
async fn handle_non_streaming_response(
    state: &ProxyState,
    provider: Provider,
    endpoint: &str,
    status: reqwest::StatusCode,
    response_headers: &reqwest::header::HeaderMap,
    response: reqwest::Response,
) -> Response {
    // Limit response body to 50 MB to prevent OOM from pathological responses
    let body_bytes = match response.bytes().await {
        Ok(b) if b.len() > 50 * 1024 * 1024 => {
            warn!(size = b.len(), "upstream response body exceeds 50 MB limit");
            return (StatusCode::BAD_GATEWAY, "response too large").into_response();
        }
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to read upstream response body");
            return (StatusCode::BAD_GATEWAY, "failed to read response").into_response();
        }
    };

    // Extract usage from JSON response (only for successful responses)
    if status.is_success() {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            let usage = extract_usage_from_json(provider, &json);
            if let Some(usage) = usage {
                log_usage(state, provider, endpoint, &usage);
            }
        }
    }

    // Build axum response
    let mut builder = Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
    for (name, value) in response_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if matches!(name_str.as_str(), "transfer-encoding" | "connection") {
            continue;
        }
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            builder = builder.header(name.as_str(), v);
        }
    }

    builder.body(Body::from(body_bytes)).unwrap_or_else(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "failed to build response").into_response()
    })
}

/// Handle a streaming SSE response: pass through bytes while extracting usage.
async fn handle_streaming_response(
    state: &ProxyState,
    provider: Provider,
    endpoint: &str,
    status: reqwest::StatusCode,
    response_headers: &reqwest::header::HeaderMap,
    response: reqwest::Response,
) -> Response {
    let state = state.clone();
    let endpoint = endpoint.to_string();

    // Build response headers
    let mut builder = Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
    for (name, value) in response_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if matches!(name_str.as_str(), "transfer-encoding" | "connection") {
            continue;
        }
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            builder = builder.header(name.as_str(), v);
        }
    }

    // Create a stream that intercepts SSE events
    let upstream_stream = response.bytes_stream();
    let mut accumulator = UsageAccumulator::new(provider);
    let mut line_buf = BytesMut::new();

    let body_stream = async_stream::stream! {
        tokio::pin!(upstream_stream);
        while let Some(chunk_result) = upstream_stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    // Parse SSE events from the chunk
                    line_buf.extend_from_slice(&chunk);
                    parse_sse_lines(&mut line_buf, &mut accumulator);

                    // Forward the chunk to the client
                    yield Ok::<_, std::io::Error>(chunk);
                }
                Err(e) => {
                    warn!(error = %e, "upstream stream error");
                    break;
                }
            }
        }

        // Process any remaining data in the buffer
        if !line_buf.is_empty() {
            parse_sse_lines_final(&mut line_buf, &mut accumulator);
        }

        // Log accumulated usage
        if accumulator.has_data() {
            let usage = accumulator.into_usage_data();
            log_usage(&state, provider, &endpoint, &usage);
        }
    };

    let body = Body::from_stream(body_stream);

    builder.body(body).unwrap_or_else(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "failed to build streaming response").into_response()
    })
}

/// Extracted usage data from an API response.
#[derive(Debug, Default)]
struct UsageData {
    model: String,
    input_tokens: u64,
    output_tokens: u64,
    cache_creation_input_tokens: u64,
    cache_read_input_tokens: u64,
}

/// Accumulates usage data from SSE events across a streaming response.
#[derive(Debug)]
pub(crate) struct UsageAccumulator {
    provider: Provider,
    current_event_type: String,
    data: UsageData,
    has_any_data: bool,
}

impl UsageAccumulator {
    fn new(provider: Provider) -> Self {
        Self {
            provider,
            current_event_type: String::new(),
            data: UsageData::default(),
            has_any_data: false,
        }
    }

    fn has_data(&self) -> bool {
        self.has_any_data
    }

    fn into_usage_data(self) -> UsageData {
        self.data
    }

    /// Process an SSE event (event type + data).
    fn feed_event(&mut self, event_type: &str, data: &str) {
        if data == "[DONE]" {
            return;
        }

        let json: serde_json::Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => return,
        };

        match self.provider {
            Provider::Anthropic => self.feed_anthropic_event(event_type, &json),
            Provider::OpenAi => self.feed_openai_event(&json),
        }
    }

    fn feed_anthropic_event(&mut self, event_type: &str, json: &serde_json::Value) {
        match event_type {
            "message_start" => {
                // Extract model and input_tokens from message_start
                if let Some(message) = json.get("message") {
                    if let Some(model) = message.get("model").and_then(|v| v.as_str()) {
                        self.data.model = model.to_string();
                    }
                    if let Some(usage) = message.get("usage") {
                        self.data.input_tokens = usage
                            .get("input_tokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        self.data.cache_creation_input_tokens = usage
                            .get("cache_creation_input_tokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        self.data.cache_read_input_tokens = usage
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        self.has_any_data = true;
                    }
                }
            }
            "message_delta" => {
                // Extract output_tokens from message_delta
                if let Some(usage) = json.get("usage") {
                    self.data.output_tokens = usage
                        .get("output_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    self.has_any_data = true;
                }
            }
            _ => {}
        }
    }

    fn feed_openai_event(&mut self, json: &serde_json::Value) {
        // OpenAI includes usage in the final chunk
        if let Some(usage) = json.get("usage") {
            if !usage.is_null() {
                self.data.input_tokens = usage
                    .get("prompt_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                self.data.output_tokens = usage
                    .get("completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                self.has_any_data = true;
            }
        }
        // Extract model if present
        if let Some(model) = json.get("model").and_then(|v| v.as_str()) {
            if !model.is_empty() {
                self.data.model = model.to_string();
            }
        }
    }
}

/// Parse SSE lines from the buffer, feeding complete events to the accumulator.
fn parse_sse_lines(buf: &mut BytesMut, acc: &mut UsageAccumulator) {
    loop {
        // Find the next line ending
        let newline_pos = buf.iter().position(|&b| b == b'\n');
        let Some(pos) = newline_pos else { break };

        let line_bytes = buf.split_to(pos + 1);
        let line = String::from_utf8_lossy(&line_bytes).trim_end().to_string();

        process_sse_line(&line, acc);
    }
}

/// Process remaining buffer contents as final SSE lines.
fn parse_sse_lines_final(buf: &mut BytesMut, acc: &mut UsageAccumulator) {
    let remaining = String::from_utf8_lossy(buf).to_string();
    for line in remaining.lines() {
        process_sse_line(line, acc);
    }
    buf.clear();
}

/// Process a single SSE line, updating the accumulator state.
fn process_sse_line(line: &str, acc: &mut UsageAccumulator) {
    if let Some(rest) = line.strip_prefix("event:") {
        acc.current_event_type = rest.trim().to_string();
    } else if let Some(rest) = line.strip_prefix("data:") {
        let data = rest.trim();
        let event_type = acc.current_event_type.clone();
        acc.feed_event(&event_type, data);
    }
    // Empty lines delimit events -- reset event type after processing
    if line.is_empty() {
        acc.current_event_type.clear();
    }
}

/// Extract usage data from a non-streaming JSON response.
fn extract_usage_from_json(provider: Provider, json: &serde_json::Value) -> Option<UsageData> {
    let model = json.get("model").and_then(|v| v.as_str()).unwrap_or("unknown");
    let usage = json.get("usage")?;

    match provider {
        Provider::Anthropic => Some(UsageData {
            model: model.to_string(),
            input_tokens: usage.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
            output_tokens: usage.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
            cache_creation_input_tokens: usage
                .get("cache_creation_input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_read_input_tokens: usage
                .get("cache_read_input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        }),
        Provider::OpenAi => Some(UsageData {
            model: model.to_string(),
            input_tokens: usage.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
            output_tokens: usage.get("completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        }),
    }
}

/// Log usage data to the audit ledger.
fn log_usage(state: &ProxyState, provider: Provider, endpoint: &str, usage: &UsageData) {
    let action = Action::new(
        &state.principal,
        ActionKind::ApiUsage {
            provider: provider.name().to_string(),
            model: usage.model.clone(),
            endpoint: endpoint.to_string(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cache_creation_input_tokens: usage.cache_creation_input_tokens,
            cache_read_input_tokens: usage.cache_read_input_tokens,
        },
    );

    let verdict = Verdict::allow(action.id, "usage-tracking", None);

    match state.store.lock() {
        Ok(mut store) => {
            let result = if let Some(session_id) = state.session_id {
                store.append_with_session(&action, &verdict, &session_id)
            } else {
                store.append(&action, &verdict)
            };
            match result {
                Ok(_) => {
                    info!(
                        provider = provider.name(),
                        model = usage.model,
                        input_tokens = usage.input_tokens,
                        output_tokens = usage.output_tokens,
                        "API usage logged"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "failed to log API usage");
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "audit store lock poisoned, cannot log usage");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_anthropic_non_streaming_usage() {
        let json: serde_json::Value = serde_json::json!({
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-5-20250929",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_creation_input_tokens": 10,
                "cache_read_input_tokens": 5
            }
        });

        let usage = extract_usage_from_json(Provider::Anthropic, &json).unwrap();
        assert_eq!(usage.model, "claude-sonnet-4-5-20250929");
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
        assert_eq!(usage.cache_creation_input_tokens, 10);
        assert_eq!(usage.cache_read_input_tokens, 5);
    }

    #[test]
    fn extract_openai_non_streaming_usage() {
        let json: serde_json::Value = serde_json::json!({
            "id": "chatcmpl-123",
            "model": "gpt-4-turbo",
            "usage": {
                "prompt_tokens": 200,
                "completion_tokens": 75,
                "total_tokens": 275
            }
        });

        let usage = extract_usage_from_json(Provider::OpenAi, &json).unwrap();
        assert_eq!(usage.model, "gpt-4-turbo");
        assert_eq!(usage.input_tokens, 200);
        assert_eq!(usage.output_tokens, 75);
    }

    #[test]
    fn extract_usage_no_usage_field() {
        let json: serde_json::Value = serde_json::json!({"error": "bad request"});
        assert!(extract_usage_from_json(Provider::Anthropic, &json).is_none());
    }

    #[test]
    fn accumulator_anthropic_streaming() {
        let mut acc = UsageAccumulator::new(Provider::Anthropic);

        // message_start event
        acc.feed_event(
            "message_start",
            r#"{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":150,"cache_creation_input_tokens":0,"cache_read_input_tokens":20}}}"#,
        );

        assert!(acc.has_data());
        assert_eq!(acc.data.model, "claude-sonnet-4-5-20250929");
        assert_eq!(acc.data.input_tokens, 150);
        assert_eq!(acc.data.cache_read_input_tokens, 20);

        // message_delta event
        acc.feed_event(
            "message_delta",
            r#"{"type":"message_delta","usage":{"output_tokens":85}}"#,
        );

        assert_eq!(acc.data.output_tokens, 85);

        let usage = acc.into_usage_data();
        assert_eq!(usage.input_tokens, 150);
        assert_eq!(usage.output_tokens, 85);
    }

    #[test]
    fn accumulator_openai_streaming() {
        let mut acc = UsageAccumulator::new(Provider::OpenAi);

        // Regular chunks have null usage
        acc.feed_event(
            "",
            r#"{"id":"chatcmpl-1","model":"gpt-4-turbo","choices":[{"delta":{"content":"Hello"}}],"usage":null}"#,
        );

        assert!(!acc.has_data());
        assert_eq!(acc.data.model, "gpt-4-turbo");

        // Final chunk has usage
        acc.feed_event(
            "",
            r#"{"id":"chatcmpl-1","model":"gpt-4-turbo","choices":[],"usage":{"prompt_tokens":50,"completion_tokens":30,"total_tokens":80}}"#,
        );

        assert!(acc.has_data());
        let usage = acc.into_usage_data();
        assert_eq!(usage.input_tokens, 50);
        assert_eq!(usage.output_tokens, 30);
    }

    #[test]
    fn accumulator_ignores_done() {
        let mut acc = UsageAccumulator::new(Provider::OpenAi);
        acc.feed_event("", "[DONE]");
        assert!(!acc.has_data());
    }

    #[test]
    fn accumulator_handles_malformed_json() {
        let mut acc = UsageAccumulator::new(Provider::Anthropic);
        acc.feed_event("message_start", "not json at all");
        assert!(!acc.has_data());
    }

    #[test]
    fn sse_line_parsing() {
        let mut acc = UsageAccumulator::new(Provider::Anthropic);
        let mut buf = BytesMut::from(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-5-20250929\",\"usage\":{\"input_tokens\":42}}}\n\n"
        );

        parse_sse_lines(&mut buf, &mut acc);

        assert!(acc.has_data());
        assert_eq!(acc.data.model, "claude-sonnet-4-5-20250929");
        assert_eq!(acc.data.input_tokens, 42);
    }

    #[test]
    fn sse_line_parsing_split_across_chunks() {
        let mut acc = UsageAccumulator::new(Provider::Anthropic);

        // First chunk: partial line
        let mut buf = BytesMut::from("event: message_st");
        parse_sse_lines(&mut buf, &mut acc);
        assert!(!acc.has_data());
        // Remaining bytes stay in buffer
        assert_eq!(buf.as_ref(), b"event: message_st");

        // Second chunk completes the line
        buf.extend_from_slice(b"art\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test\",\"usage\":{\"input_tokens\":10}}}\n\n");
        parse_sse_lines(&mut buf, &mut acc);

        assert!(acc.has_data());
        assert_eq!(acc.data.input_tokens, 10);
    }

    #[test]
    fn provider_names() {
        assert_eq!(Provider::Anthropic.name(), "anthropic");
        assert_eq!(Provider::OpenAi.name(), "openai");
    }

    #[test]
    fn provider_upstream_urls() {
        assert_eq!(Provider::Anthropic.upstream_base(), "https://api.anthropic.com");
        assert_eq!(Provider::OpenAi.upstream_base(), "https://api.openai.com");
    }

    #[test]
    fn usage_data_display_via_action_kind() {
        let kind = ActionKind::ApiUsage {
            provider: "anthropic".into(),
            model: "claude-sonnet-4-5-20250929".into(),
            endpoint: "/v1/messages".into(),
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let display = kind.to_string();
        assert!(display.contains("anthropic"));
        assert!(display.contains("in=100"));
        assert!(display.contains("out=50"));
    }
}
