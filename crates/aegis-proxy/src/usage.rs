//! HTTP reverse proxy for API usage tracking.
//!
//! Starts a local HTTP server that intercepts AI tool API traffic,
//! forwards requests to the real upstream endpoints, and extracts
//! token/model usage data from responses (including streaming SSE).
//! Usage data is logged to the audit ledger as `ActionKind::ApiUsage`.

use std::collections::HashMap;
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
    rate_limiter: Option<Arc<Mutex<crate::rate_limit::ProviderRateLimiter>>>,
    budget_tracker: Option<Arc<Mutex<crate::budget::BudgetTracker>>>,
}

/// An HTTP reverse proxy for API usage tracking.
pub struct UsageProxy {
    store: Arc<Mutex<AuditStore>>,
    principal: String,
    session_id: Option<Uuid>,
    port: u16,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    rate_limiter: Option<Arc<Mutex<crate::rate_limit::ProviderRateLimiter>>>,
    budget_tracker: Option<Arc<Mutex<crate::budget::BudgetTracker>>>,
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
            rate_limiter: None,
            budget_tracker: None,
        }
    }

    /// Enable per-provider rate limiting with default provider limits.
    pub fn with_rate_limiting(mut self) -> Self {
        self.rate_limiter = Some(Arc::new(Mutex::new(
            crate::rate_limit::ProviderRateLimiter::with_defaults(),
        )));
        self
    }

    /// Enable budget enforcement with the given ceiling in USD.
    pub fn with_budget(mut self, budget_usd: f64) -> Self {
        if budget_usd > 0.0 {
            let config = crate::budget::BudgetConfig {
                budget_usd,
                warn_threshold: 0.8,
                action_on_exceed: crate::budget::BudgetAction::Warn,
            };
            self.budget_tracker = Some(Arc::new(Mutex::new(
                crate::budget::BudgetTracker::new(config),
            )));
        }
        self
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
            rate_limiter: self.rate_limiter,
            budget_tracker: self.budget_tracker,
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
    // Check rate limit before forwarding
    if let Some(ref rl) = state.rate_limiter {
        match rl.lock() {
            Ok(mut limiter) => {
                if let Err(e) = limiter.check_request(provider.name()) {
                    let retry_after_ms = match &e {
                        crate::rate_limit::RateLimitError::RequestsExceeded {
                            retry_after_ms,
                            ..
                        }
                        | crate::rate_limit::RateLimitError::TokensExceeded {
                            retry_after_ms,
                            ..
                        } => *retry_after_ms,
                    };
                    warn!(
                        provider = provider.name(),
                        error = %e,
                        "rate limit exceeded, returning 429"
                    );
                    let retry_secs = (retry_after_ms / 1000).max(1);
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(
                            "retry-after",
                            HeaderValue::from_str(&retry_secs.to_string())
                                .unwrap_or_else(|_| HeaderValue::from_static("60")),
                        )],
                        format!("Rate limit exceeded: {e}"),
                    )
                        .into_response();
                }
            }
            Err(e) => {
                warn!(error = %e, "rate limiter lock poisoned, skipping rate check");
            }
        }
    }

    let upstream_url = format!("{}/{path}", provider.upstream_base());

    // Read the request body
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to read request body");
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };

    let request_preview = extract_preview(&body_bytes, 200);

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
        handle_streaming_response(
            state,
            provider,
            &endpoint,
            status,
            &response_headers,
            upstream_response,
            &request_preview,
        )
        .await
    } else {
        handle_non_streaming_response(
            state,
            provider,
            &endpoint,
            status,
            &response_headers,
            upstream_response,
            &request_preview,
        )
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
    request_preview: &str,
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
                let response_preview = extract_preview(&body_bytes, 200);
                log_usage(
                    state,
                    provider,
                    endpoint,
                    &usage,
                    Some(request_preview),
                    Some(&response_preview),
                );
            }
        }
    }

    // Build axum response
    let mut builder =
        Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to build response",
        )
            .into_response()
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
    request_preview: &str,
) -> Response {
    let state = state.clone();
    let endpoint = endpoint.to_string();
    let request_preview = request_preview.to_string();

    // Build response headers
    let mut builder =
        Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
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
                    // Cap buffer at 10 MB to prevent unbounded growth on missing newlines
                    if line_buf.len() > 10 * 1024 * 1024 {
                        tracing::warn!("SSE line buffer exceeded 10 MB, clearing");
                        line_buf.clear();
                    }
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
            log_usage(&state, provider, &endpoint, &usage, Some(&request_preview), Some("[streaming response]"));
        }
    };

    let body = Body::from_stream(body_stream);

    builder.body(body).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to build streaming response",
        )
            .into_response()
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
///
/// Also tracks which model names have been seen across API calls,
/// enabling model discovery and fleet-wide model inventory.
#[derive(Debug)]
pub(crate) struct UsageAccumulator {
    provider: Provider,
    current_event_type: String,
    data: UsageData,
    has_any_data: bool,
    seen_models: std::collections::HashSet<String>,
}

impl UsageAccumulator {
    fn new(provider: Provider) -> Self {
        Self {
            provider,
            current_event_type: String::new(),
            data: UsageData::default(),
            has_any_data: false,
            seen_models: std::collections::HashSet::new(),
        }
    }

    fn has_data(&self) -> bool {
        self.has_any_data
    }

    fn into_usage_data(self) -> UsageData {
        self.data
    }

    /// Return a sorted list of all model names seen by this accumulator.
    #[allow(dead_code)]
    pub fn models(&self) -> Vec<String> {
        let mut models: Vec<String> = self.seen_models.iter().cloned().collect();
        models.sort();
        models
    }

    /// Return the number of distinct models seen.
    #[allow(dead_code)]
    pub fn model_count(&self) -> usize {
        self.seen_models.len()
    }

    /// Record a model name as seen.
    fn track_model(&mut self, model: &str) {
        if !model.is_empty() {
            self.seen_models.insert(model.to_string());
        }
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
                        self.track_model(model);
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
                self.track_model(model);
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
    let model = json
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let usage = json.get("usage")?;

    match provider {
        Provider::Anthropic => Some(UsageData {
            model: model.to_string(),
            input_tokens: usage
                .get("input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage
                .get("output_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
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
            input_tokens: usage
                .get("prompt_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage
                .get("completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        }),
    }
}

/// Extract a UTF-8 preview from raw bytes, truncated to `max_len` chars.
fn extract_preview(bytes: &[u8], max_len: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= max_len {
        text.to_string()
    } else {
        let mut end = max_len;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &text[..end])
    }
}

/// Log usage data to the audit ledger.
fn log_usage(
    state: &ProxyState,
    provider: Provider,
    endpoint: &str,
    usage: &UsageData,
    request_preview: Option<&str>,
    response_preview: Option<&str>,
) {
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
                        request_preview = request_preview.unwrap_or(""),
                        response_preview = response_preview.unwrap_or(""),
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

    // Record tokens for rate limiting
    let total_tokens = usage.input_tokens + usage.output_tokens;
    if let Some(ref rl) = state.rate_limiter {
        if let Ok(mut limiter) = rl.lock() {
            limiter.record_tokens(provider.name(), total_tokens);
        }
    }

    // Record cost for budget tracking
    if let Some(ref bt) = state.budget_tracker {
        let pricing = PricingTable::default();
        let cost = pricing
            .calculate_cost(
                &usage.model,
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_read_input_tokens,
                usage.cache_creation_input_tokens,
            )
            .unwrap_or(0.0);
        if cost > 0.0 {
            if let Ok(mut tracker) = bt.lock() {
                match tracker.record_cost(cost) {
                    crate::budget::BudgetStatus::Ok => {}
                    crate::budget::BudgetStatus::Warning { utilization } => {
                        warn!(
                            principal = state.principal,
                            utilization = format!("{:.0}%", utilization * 100.0),
                            spent_usd = format!("{:.4}", tracker.spent()),
                            remaining_usd = format!("{:.4}", tracker.remaining()),
                            "budget warning threshold reached"
                        );
                    }
                    crate::budget::BudgetStatus::Exceeded { overage, action } => {
                        warn!(
                            principal = state.principal,
                            overage_usd = format!("{:.4}", overage),
                            action = ?action,
                            "budget exceeded"
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session-level usage aggregation
// ---------------------------------------------------------------------------

use crate::pricing::PricingTable;

/// Per-model usage breakdown.
#[derive(Debug, Clone, Default)]
pub struct ModelUsageSummary {
    /// Total input tokens for this model.
    pub input_tokens: u64,
    /// Total output tokens for this model.
    pub output_tokens: u64,
    /// Total cache-read tokens for this model.
    pub cache_read_tokens: u64,
    /// Total cache-write (creation) tokens for this model.
    pub cache_write_tokens: u64,
    /// Estimated cost in USD for this model (if pricing is available).
    pub cost_usd: Option<f64>,
}

/// Aggregated usage summary across one or more API calls.
#[derive(Debug, Clone, Default)]
pub struct UsageSummary {
    /// Total input tokens across all models.
    pub total_input_tokens: u64,
    /// Total output tokens across all models.
    pub total_output_tokens: u64,
    /// Total cache-read tokens across all models.
    pub total_cache_read: u64,
    /// Total cache-write tokens across all models.
    pub total_cache_write: u64,
    /// Total estimated cost in USD (sum of per-model costs for known models).
    pub total_cost_usd: f64,
    /// Per-model breakdown.
    pub by_model: HashMap<String, ModelUsageSummary>,
}

/// A single API usage record, matching the fields in `ActionKind::ApiUsage`.
///
/// This is a lightweight input struct for [`calculate_session_cost`] so that
/// callers do not need to depend on `ActionKind` directly.
#[derive(Debug, Clone)]
pub struct ApiUsageRecord {
    /// Model identifier (e.g. `"claude-sonnet-4-5-20250929"`).
    pub model: String,
    /// Input / prompt tokens.
    pub input_tokens: u64,
    /// Output / completion tokens.
    pub output_tokens: u64,
    /// Cache-read input tokens.
    pub cache_read_input_tokens: u64,
    /// Cache-creation input tokens.
    pub cache_creation_input_tokens: u64,
}

/// Aggregate a list of API usage records into a [`UsageSummary`], using the
/// provided [`PricingTable`] to compute costs.
///
/// Records whose model is not found in the pricing table contribute to token
/// totals but not to `total_cost_usd`.
pub fn calculate_session_cost(records: &[ApiUsageRecord], pricing: &PricingTable) -> UsageSummary {
    let mut summary = UsageSummary::default();

    for record in records {
        summary.total_input_tokens += record.input_tokens;
        summary.total_output_tokens += record.output_tokens;
        summary.total_cache_read += record.cache_read_input_tokens;
        summary.total_cache_write += record.cache_creation_input_tokens;

        let model_summary = summary.by_model.entry(record.model.clone()).or_default();

        model_summary.input_tokens += record.input_tokens;
        model_summary.output_tokens += record.output_tokens;
        model_summary.cache_read_tokens += record.cache_read_input_tokens;
        model_summary.cache_write_tokens += record.cache_creation_input_tokens;

        if let Some(cost) = pricing.calculate_cost(
            &record.model,
            record.input_tokens,
            record.output_tokens,
            record.cache_read_input_tokens,
            record.cache_creation_input_tokens,
        ) {
            *model_summary.cost_usd.get_or_insert(0.0) += cost;
            summary.total_cost_usd += cost;
        }
    }

    summary
}

// ---------------------------------------------------------------------------
// Enhanced cost tracking
// ---------------------------------------------------------------------------

/// Cost breakdown for a single API call.
#[derive(Debug, Clone)]
pub struct UsageCost {
    /// Number of input / prompt tokens.
    pub input_tokens: u64,
    /// Number of output / completion tokens.
    pub output_tokens: u64,
    /// Cost of input tokens in USD.
    pub input_cost: f64,
    /// Cost of output tokens in USD.
    pub output_cost: f64,
    /// Total cost in USD (input + output).
    pub total_cost: f64,
    /// Model identifier (e.g. `"claude-sonnet-4-5-20250929"`).
    pub model: String,
    /// Provider name (e.g. `"anthropic"`).
    pub provider: String,
}

/// Calculate the cost for a single API call.
///
/// Looks up the model in `pricing` to determine per-token rates, then
/// computes input and output costs separately. Unknown models yield
/// zero costs but still record token counts and return `"unknown"` as
/// the provider.
pub fn calculate_cost(
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
    pricing: &[crate::pricing::ModelPricing],
) -> UsageCost {
    let matched = pricing.iter().find(|p| {
        glob::Pattern::new(&p.model_pattern)
            .map(|pat| pat.matches(model))
            .unwrap_or_else(|_| p.model_pattern == model)
    });

    let (input_cost, output_cost, provider) = match matched {
        Some(p) => (
            input_tokens as f64 * p.input_cost_per_mtok / 1_000_000.0,
            output_tokens as f64 * p.output_cost_per_mtok / 1_000_000.0,
            p.provider.clone(),
        ),
        None => (0.0, 0.0, "unknown".to_string()),
    };

    UsageCost {
        input_tokens,
        output_tokens,
        input_cost,
        output_cost,
        total_cost: input_cost + output_cost,
        model: model.to_string(),
        provider,
    }
}

/// Aggregated cost summary across multiple API calls.
#[derive(Debug, Clone)]
pub struct CostSummary {
    /// Total cost in USD across all recorded calls.
    pub total_cost: f64,
    /// Total input tokens across all recorded calls.
    pub total_input_tokens: u64,
    /// Total output tokens across all recorded calls.
    pub total_output_tokens: u64,
    /// Number of API calls recorded.
    pub calls: usize,
    /// Cost breakdown by provider name.
    pub by_provider: HashMap<String, f64>,
    /// Cost breakdown by model identifier.
    pub by_model: HashMap<String, f64>,
}

/// Tracks costs across an entire session (multiple API calls).
///
/// Records individual [`UsageCost`] entries and provides aggregation
/// methods for total cost, per-provider breakdown, and per-model breakdown.
#[derive(Debug)]
pub struct SessionCostTracker {
    entries: Vec<UsageCost>,
    pricing: Vec<crate::pricing::ModelPricing>,
}

impl SessionCostTracker {
    /// Create a new tracker using the built-in default pricing table.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            pricing: crate::pricing::default_pricing(),
        }
    }

    /// Create a new tracker with custom pricing entries.
    pub fn with_pricing(pricing: Vec<crate::pricing::ModelPricing>) -> Self {
        Self {
            entries: Vec::new(),
            pricing,
        }
    }

    /// Record an API call's token usage, computing cost from the pricing table.
    pub fn record(&mut self, model: &str, input_tokens: u64, output_tokens: u64) {
        let cost = calculate_cost(model, input_tokens, output_tokens, &self.pricing);
        self.entries.push(cost);
    }

    /// Total cost in USD across all recorded calls.
    pub fn total_cost(&self) -> f64 {
        self.entries.iter().map(|e| e.total_cost).sum()
    }

    /// Total input tokens across all recorded calls.
    pub fn total_input_tokens(&self) -> u64 {
        self.entries.iter().map(|e| e.input_tokens).sum()
    }

    /// Total output tokens across all recorded calls.
    pub fn total_output_tokens(&self) -> u64 {
        self.entries.iter().map(|e| e.output_tokens).sum()
    }

    /// Aggregate cost by provider name.
    pub fn cost_by_provider(&self) -> HashMap<String, f64> {
        let mut map = HashMap::new();
        for entry in &self.entries {
            *map.entry(entry.provider.clone()).or_insert(0.0) += entry.total_cost;
        }
        map
    }

    /// Aggregate cost by model identifier.
    pub fn cost_by_model(&self) -> HashMap<String, f64> {
        let mut map = HashMap::new();
        for entry in &self.entries {
            *map.entry(entry.model.clone()).or_insert(0.0) += entry.total_cost;
        }
        map
    }

    /// Produce a full [`CostSummary`] snapshot.
    pub fn summary(&self) -> CostSummary {
        CostSummary {
            total_cost: self.total_cost(),
            total_input_tokens: self.total_input_tokens(),
            total_output_tokens: self.total_output_tokens(),
            calls: self.entries.len(),
            by_provider: self.cost_by_provider(),
            by_model: self.cost_by_model(),
        }
    }
}

impl Default for SessionCostTracker {
    fn default() -> Self {
        Self::new()
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
        assert_eq!(
            Provider::Anthropic.upstream_base(),
            "https://api.anthropic.com"
        );
        assert_eq!(Provider::OpenAi.upstream_base(), "https://api.openai.com");
    }

    #[test]
    fn model_tracking_across_events() {
        let mut acc = UsageAccumulator::new(Provider::Anthropic);
        acc.feed_event(
            "message_start",
            r#"{"type":"message_start","message":{"model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":10}}}"#,
        );
        assert_eq!(acc.model_count(), 1);
        assert_eq!(acc.models(), vec!["claude-sonnet-4-5-20250929"]);
    }

    #[test]
    fn model_tracking_deduplication() {
        let mut acc = UsageAccumulator::new(Provider::OpenAi);
        // Same model in two events
        acc.feed_event("", r#"{"model":"gpt-4-turbo","usage":null}"#);
        acc.feed_event(
            "",
            r#"{"model":"gpt-4-turbo","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#,
        );
        assert_eq!(acc.model_count(), 1);
        assert_eq!(acc.models(), vec!["gpt-4-turbo"]);
    }

    #[test]
    fn model_tracking_multiple_models() {
        let mut acc = UsageAccumulator::new(Provider::OpenAi);
        acc.feed_event("", r#"{"model":"gpt-4-turbo","usage":null}"#);
        acc.feed_event("", r#"{"model":"gpt-3.5-turbo","usage":null}"#);
        assert_eq!(acc.model_count(), 2);
        // Sorted output
        assert_eq!(acc.models(), vec!["gpt-3.5-turbo", "gpt-4-turbo"]);
    }

    #[test]
    fn model_tracking_empty_model_ignored() {
        let mut acc = UsageAccumulator::new(Provider::OpenAi);
        acc.feed_event("", r#"{"model":"","usage":null}"#);
        assert_eq!(acc.model_count(), 0);
        assert!(acc.models().is_empty());
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

    #[test]
    fn test_usage_summary_aggregation() {
        let pricing = PricingTable::with_defaults();
        let records = vec![
            ApiUsageRecord {
                model: "claude-sonnet-4-5-20250929".into(),
                input_tokens: 1_000_000,
                output_tokens: 0,
                cache_read_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
            ApiUsageRecord {
                model: "claude-sonnet-4-5-20250929".into(),
                input_tokens: 500_000,
                output_tokens: 200_000,
                cache_read_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
            ApiUsageRecord {
                model: "gpt-4o".into(),
                input_tokens: 100_000,
                output_tokens: 50_000,
                cache_read_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        ];

        let summary = calculate_session_cost(&records, &pricing);

        // Total tokens
        assert_eq!(summary.total_input_tokens, 1_600_000);
        assert_eq!(summary.total_output_tokens, 250_000);
        assert_eq!(summary.total_cache_read, 0);
        assert_eq!(summary.total_cache_write, 0);

        // Per-model breakdown
        assert_eq!(summary.by_model.len(), 2);

        let sonnet = summary.by_model.get("claude-sonnet-4-5-20250929").unwrap();
        assert_eq!(sonnet.input_tokens, 1_500_000);
        assert_eq!(sonnet.output_tokens, 200_000);

        let gpt = summary.by_model.get("gpt-4o").unwrap();
        assert_eq!(gpt.input_tokens, 100_000);
        assert_eq!(gpt.output_tokens, 50_000);

        // Cost check: sonnet calls = (1M*3 + 0)/1M + (500k*3 + 200k*15)/1M
        //           = 3.0 + 4.5 = 7.5
        // gpt-4o call = (100k*2.5 + 50k*10)/1M = 0.75
        // Total = 8.25
        assert!(
            (summary.total_cost_usd - 8.25).abs() < 1e-9,
            "expected $8.25, got {}",
            summary.total_cost_usd
        );
    }

    // -----------------------------------------------------------------------
    // Enhanced cost tracking tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_calculate_cost_known_model() {
        let pricing = crate::pricing::default_pricing();
        let cost = calculate_cost("claude-sonnet-4-5-20250929", 1_000_000, 500_000, &pricing);
        assert_eq!(cost.input_tokens, 1_000_000);
        assert_eq!(cost.output_tokens, 500_000);
        // input: 1M * 3.0 / 1M = 3.0
        assert!((cost.input_cost - 3.0).abs() < 1e-9);
        // output: 500k * 15.0 / 1M = 7.5
        assert!((cost.output_cost - 7.5).abs() < 1e-9);
        assert!((cost.total_cost - 10.5).abs() < 1e-9);
        assert_eq!(cost.provider, "anthropic");
        assert_eq!(cost.model, "claude-sonnet-4-5-20250929");
    }

    #[test]
    fn test_calculate_cost_unknown_model() {
        let pricing = crate::pricing::default_pricing();
        let cost = calculate_cost("totally-unknown", 1_000_000, 500_000, &pricing);
        assert_eq!(cost.input_tokens, 1_000_000);
        assert_eq!(cost.output_tokens, 500_000);
        assert!((cost.input_cost).abs() < f64::EPSILON);
        assert!((cost.output_cost).abs() < f64::EPSILON);
        assert!((cost.total_cost).abs() < f64::EPSILON);
        assert_eq!(cost.provider, "unknown");
    }

    #[test]
    fn test_calculate_cost_zero_tokens() {
        let pricing = crate::pricing::default_pricing();
        let cost = calculate_cost("claude-opus-4-20250929", 0, 0, &pricing);
        assert_eq!(cost.input_tokens, 0);
        assert_eq!(cost.output_tokens, 0);
        assert!((cost.total_cost).abs() < f64::EPSILON);
        assert_eq!(cost.provider, "anthropic");
    }

    #[test]
    fn test_session_cost_tracker_empty() {
        let tracker = SessionCostTracker::new();
        assert!((tracker.total_cost()).abs() < f64::EPSILON);
        assert_eq!(tracker.total_input_tokens(), 0);
        assert_eq!(tracker.total_output_tokens(), 0);
        let summary = tracker.summary();
        assert_eq!(summary.calls, 0);
        assert!(summary.by_provider.is_empty());
        assert!(summary.by_model.is_empty());
    }

    #[test]
    fn test_session_cost_tracker_single_call() {
        let mut tracker = SessionCostTracker::new();
        tracker.record("gpt-4o", 100_000, 50_000);

        assert_eq!(tracker.total_input_tokens(), 100_000);
        assert_eq!(tracker.total_output_tokens(), 50_000);
        // input: 100k * 2.5 / 1M = 0.25
        // output: 50k * 10.0 / 1M = 0.50
        let expected_cost = 0.75;
        assert!(
            (tracker.total_cost() - expected_cost).abs() < 1e-9,
            "expected {expected_cost}, got {}",
            tracker.total_cost()
        );

        let by_provider = tracker.cost_by_provider();
        assert!((by_provider["openai"] - expected_cost).abs() < 1e-9);
    }

    #[test]
    fn test_session_cost_tracker_multi_provider() {
        let mut tracker = SessionCostTracker::new();
        // Anthropic call
        tracker.record("claude-sonnet-4-5-20250929", 1_000_000, 0);
        // OpenAI call
        tracker.record("gpt-4o", 100_000, 50_000);
        // Google call
        tracker.record("gemini-2-flash", 1_000_000, 500_000);

        // Anthropic: 1M * 3.0 / 1M = 3.0
        // OpenAI: (100k * 2.5 + 50k * 10.0) / 1M = 0.75
        // Google: (1M * 0.075 + 500k * 0.30) / 1M = 0.225
        let expected_total = 3.0 + 0.75 + 0.225;
        assert!(
            (tracker.total_cost() - expected_total).abs() < 1e-9,
            "expected {expected_total}, got {}",
            tracker.total_cost()
        );

        let by_provider = tracker.cost_by_provider();
        assert_eq!(by_provider.len(), 3);
        assert!((by_provider["anthropic"] - 3.0).abs() < 1e-9);
        assert!((by_provider["openai"] - 0.75).abs() < 1e-9);
        assert!((by_provider["google"] - 0.225).abs() < 1e-9);

        let by_model = tracker.cost_by_model();
        assert_eq!(by_model.len(), 3);

        let summary = tracker.summary();
        assert_eq!(summary.calls, 3);
        assert_eq!(summary.total_input_tokens, 2_100_000);
        assert_eq!(summary.total_output_tokens, 550_000);
    }

    #[test]
    fn test_session_cost_tracker_same_model_aggregation() {
        let mut tracker = SessionCostTracker::new();
        tracker.record("claude-sonnet-4-5-20250929", 500_000, 100_000);
        tracker.record("claude-sonnet-4-5-20250929", 500_000, 100_000);

        let by_model = tracker.cost_by_model();
        assert_eq!(by_model.len(), 1);
        // Each call: (500k * 3.0 + 100k * 15.0) / 1M = 3.0
        // Two calls = 6.0
        assert!((by_model["claude-sonnet-4-5-20250929"] - 6.0).abs() < 1e-9);
        assert_eq!(tracker.total_input_tokens(), 1_000_000);
        assert_eq!(tracker.total_output_tokens(), 200_000);
    }

    #[test]
    fn test_session_cost_tracker_ollama_free() {
        let mut tracker = SessionCostTracker::new();
        tracker.record("llama-3-70b", 1_000_000, 1_000_000);
        assert!((tracker.total_cost()).abs() < f64::EPSILON);

        let summary = tracker.summary();
        assert_eq!(summary.calls, 1);
        assert_eq!(summary.total_input_tokens, 1_000_000);
        assert_eq!(summary.total_output_tokens, 1_000_000);
        assert!((summary.total_cost).abs() < f64::EPSILON);
    }
}
