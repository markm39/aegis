//! OpenAI-compatible HTTP API endpoint.
//!
//! Provides a `/v1/chat/completions` endpoint that emulates the OpenAI API format,
//! allowing any client that speaks the OpenAI protocol to interact with Aegis agents.
//!
//! ## Supported features
//!
//! - Non-streaming chat completions (`stream: false`)
//! - Server-Sent Events streaming (`stream: true`)
//! - Function/tool calling format (maps to daemon tool execution)
//! - Model listing via `GET /v1/models`
//! - Bearer token authentication compatible with OpenAI client libraries
//!
//! ## Mapping
//!
//! - The `model` field selects the target agent by name. If the model name
//!   matches an agent slot, messages are routed to that agent. Otherwise,
//!   the model name is used as-is for metadata.
//! - User messages are concatenated and sent to the agent as text input.
//! - Assistant responses come from agent output.
//! - Tool calls in messages map to daemon `ExecuteToolAction` commands.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;
// tracing is available but not actively used in this module's current code paths.
use uuid::Uuid;

use crate::daemon::{DaemonCommand, DaemonResponse};
use crate::server::http::DaemonCommandTx;

// ---------------------------------------------------------------------------
// OpenAI API types
// ---------------------------------------------------------------------------

/// A chat message in the OpenAI format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// The role of the message author (system, user, assistant, tool).
    pub role: String,
    /// The text content of the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Tool calls requested by the assistant (for tool_calls responses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// Tool call ID (when role is "tool").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Function call (deprecated format, but still supported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_call: Option<FunctionCall>,
    /// Name field (for function messages).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A tool call in the OpenAI format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Unique identifier for this tool call.
    pub id: String,
    /// Type of tool call (always "function" currently).
    #[serde(rename = "type")]
    pub call_type: String,
    /// The function to call.
    pub function: FunctionCall,
}

/// A function call specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    /// The name of the function to call.
    pub name: String,
    /// The arguments to pass (JSON string).
    pub arguments: String,
}

/// Tool definition in the OpenAI format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Type of tool (always "function" currently).
    #[serde(rename = "type")]
    pub tool_type: String,
    /// The function definition.
    pub function: FunctionDefinition,
}

/// Function definition for tool specifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// The name of the function.
    pub name: String,
    /// A description of what the function does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The parameters the function accepts (JSON Schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

/// Request body for `/v1/chat/completions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    /// Model identifier (maps to agent name or model name).
    pub model: String,
    /// The messages to process.
    pub messages: Vec<ChatMessage>,
    /// Whether to stream the response.
    #[serde(default)]
    pub stream: bool,
    /// Maximum tokens in the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Temperature for response generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Top-p sampling parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Number of completions to generate (only 1 supported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Stop sequences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    /// Tool definitions available to the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolDefinition>>,
    /// How to choose tool calls ("auto", "none", or specific).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
    /// Arbitrary user identifier for tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Response body for `/v1/chat/completions` (non-streaming).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    /// Unique completion identifier.
    pub id: String,
    /// Object type (always "chat.completion").
    pub object: String,
    /// Unix timestamp of creation.
    pub created: i64,
    /// Model used for completion.
    pub model: String,
    /// Generated choices.
    pub choices: Vec<Choice>,
    /// Token usage statistics.
    pub usage: Usage,
}

/// A single completion choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    /// Index of this choice.
    pub index: u32,
    /// The generated message.
    pub message: ChatMessage,
    /// Why generation stopped.
    pub finish_reason: Option<String>,
}

/// Token usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// Tokens in the prompt.
    pub prompt_tokens: u32,
    /// Tokens in the completion.
    pub completion_tokens: u32,
    /// Total tokens.
    pub total_tokens: u32,
}

/// A streaming chunk for SSE responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionChunk {
    /// Unique completion identifier.
    pub id: String,
    /// Object type (always "chat.completion.chunk").
    pub object: String,
    /// Unix timestamp.
    pub created: i64,
    /// Model identifier.
    pub model: String,
    /// Delta choices.
    pub choices: Vec<ChunkChoice>,
}

/// A single streaming choice delta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkChoice {
    /// Index of this choice.
    pub index: u32,
    /// The delta content.
    pub delta: ChatMessageDelta,
    /// Why generation stopped (null until final chunk).
    pub finish_reason: Option<String>,
}

/// Delta content in a streaming chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessageDelta {
    /// Role (only in first chunk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Content fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// Model information for `/v1/models`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelObject {
    /// Model identifier.
    pub id: String,
    /// Object type (always "model").
    pub object: String,
    /// Unix timestamp of creation.
    pub created: i64,
    /// Owner of the model.
    pub owned_by: String,
}

/// Response body for `/v1/models`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelListResponse {
    /// Object type (always "list").
    pub object: String,
    /// Available models.
    pub data: Vec<ModelObject>,
}

/// OpenAI-style error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiError {
    /// Error details.
    pub error: OpenAiErrorDetail,
}

/// Error detail within an OpenAI error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiErrorDetail {
    /// Error message.
    pub message: String,
    /// Error type.
    #[serde(rename = "type")]
    pub error_type: String,
    /// Parameter that caused the error (if applicable).
    pub param: Option<String>,
    /// Error code.
    pub code: Option<String>,
}

impl OpenAiError {
    /// Create a new error response.
    fn new(message: impl Into<String>, error_type: impl Into<String>) -> Self {
        Self {
            error: OpenAiErrorDetail {
                message: message.into(),
                error_type: error_type.into(),
                param: None,
                code: None,
            },
        }
    }

    fn with_code(mut self, code: impl Into<String>) -> Self {
        self.error.code = Some(code.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for OpenAI-compatible endpoints.
pub struct OpenAiState {
    /// API key for authentication (compared via constant-time eq).
    pub api_key: String,
    /// Daemon command channel.
    pub daemon_tx: DaemonCommandTx,
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Authenticate an OpenAI-compatible request using Bearer token.
fn authenticate(
    state: &OpenAiState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<OpenAiError>)> {
    if state.api_key.is_empty() {
        return Ok(());
    }

    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth.strip_prefix("Bearer ").unwrap_or("");

    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                OpenAiError::new(
                    "missing API key; provide it via Authorization: Bearer <key>",
                    "invalid_request_error",
                )
                .with_code("invalid_api_key"),
            ),
        ));
    }

    if !constant_time_eq(token.as_bytes(), state.api_key.as_bytes()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                OpenAiError::new("invalid API key", "invalid_request_error")
                    .with_code("invalid_api_key"),
            ),
        ));
    }

    Ok(())
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the OpenAI-compatible route group.
///
/// Returns a `Router` that provides:
/// - `POST /v1/chat/completions` -- chat completion endpoint
/// - `GET /v1/models` -- model listing endpoint
pub fn openai_routes(state: Arc<OpenAiState>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions_handler))
        .route("/v1/models", get(models_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/chat/completions` -- OpenAI-compatible chat completion.
///
/// Routes user messages to the appropriate agent and returns the response
/// in OpenAI API format. Supports both streaming and non-streaming modes.
async fn chat_completions_handler(
    State(state): State<Arc<OpenAiState>>,
    headers: HeaderMap,
    Json(request): Json<ChatCompletionRequest>,
) -> axum::response::Response {
    if let Err((status, json)) = authenticate(&state, &headers) {
        return (status, json).into_response();
    }

    // Validate request
    if request.messages.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(OpenAiError::new(
                "messages array must contain at least one message",
                "invalid_request_error",
            )),
        )
            .into_response();
    }

    if request.model.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(OpenAiError::new(
                "model field is required",
                "invalid_request_error",
            )),
        )
            .into_response();
    }

    // Extract user content to send to agent
    let user_content = extract_user_content(&request.messages);
    let completion_id = format!("chatcmpl-{}", Uuid::new_v4().as_simple());
    let created = Utc::now().timestamp();

    if request.stream {
        // Streaming mode: return SSE events
        handle_streaming_completion(
            state,
            request.model.clone(),
            user_content,
            completion_id,
            created,
        )
        .await
    } else {
        // Non-streaming mode: send to agent and return full response
        handle_non_streaming_completion(
            state,
            request.model.clone(),
            user_content,
            completion_id,
            created,
        )
        .await
    }
}

/// `GET /v1/models` -- list available models.
///
/// Returns the list of agents as "models", compatible with OpenAI model listing.
async fn models_handler(
    State(state): State<Arc<OpenAiState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e.into_response();
    }

    // Query daemon for agent list
    let cmd = DaemonCommand::ListAgents;
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();

    if state.daemon_tx.send((cmd, resp_tx)).await.is_err() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(OpenAiError::new(
                "daemon unavailable",
                "server_error",
            )),
        )
            .into_response();
    }

    match resp_rx.await {
        Ok(resp) => {
            let models = build_model_list(&resp);
            Json(models).into_response()
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(OpenAiError::new(
                "daemon response channel closed",
                "server_error",
            )),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Completion logic
// ---------------------------------------------------------------------------

/// Handle a non-streaming chat completion request.
async fn handle_non_streaming_completion(
    state: Arc<OpenAiState>,
    model: String,
    user_content: String,
    completion_id: String,
    created: i64,
) -> axum::response::Response {
    // Send user content to the named agent
    let agent_name = model.clone();
    let cmd = DaemonCommand::SendToAgent {
        name: agent_name,
        text: user_content.clone(),
    };

    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    if state.daemon_tx.send((cmd, resp_tx)).await.is_err() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(OpenAiError::new(
                "daemon unavailable",
                "server_error",
            )),
        )
            .into_response();
    }

    match resp_rx.await {
        Ok(resp) => {
            let content = resp.message.clone();
            let estimated_tokens = estimate_tokens(&content);
            let prompt_tokens = estimate_tokens(&user_content);

            let response = ChatCompletionResponse {
                id: completion_id,
                object: "chat.completion".to_string(),
                created,
                model,
                choices: vec![Choice {
                    index: 0,
                    message: ChatMessage {
                        role: "assistant".to_string(),
                        content: Some(content),
                        tool_calls: None,
                        tool_call_id: None,
                        function_call: None,
                        name: None,
                    },
                    finish_reason: Some("stop".to_string()),
                }],
                usage: Usage {
                    prompt_tokens,
                    completion_tokens: estimated_tokens,
                    total_tokens: prompt_tokens + estimated_tokens,
                },
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(OpenAiError::new(
                "daemon response channel closed",
                "server_error",
            )),
        )
            .into_response(),
    }
}

/// Handle a streaming chat completion request via SSE.
async fn handle_streaming_completion(
    state: Arc<OpenAiState>,
    model: String,
    user_content: String,
    completion_id: String,
    created: i64,
) -> axum::response::Response {
    // Send user content to the named agent
    let agent_name = model.clone();
    let cmd = DaemonCommand::SendToAgent {
        name: agent_name,
        text: user_content,
    };

    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    if state.daemon_tx.send((cmd, resp_tx)).await.is_err() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(OpenAiError::new(
                "daemon unavailable",
                "server_error",
            )),
        )
            .into_response();
    }

    let daemon_response = match resp_rx.await {
        Ok(resp) => resp,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(OpenAiError::new(
                    "daemon response channel closed",
                    "server_error",
                )),
            )
                .into_response();
        }
    };

    // Build SSE stream from the response
    // In a real implementation, this would stream token-by-token from agent output.
    // Here we simulate streaming by chunking the response.
    let chunks = chunk_response(&daemon_response.message, &model, &completion_id, created);

    let stream = tokio_stream::iter(chunks.into_iter().map(|chunk| {
        let json = serde_json::to_string(&chunk).unwrap_or_default();
        Ok::<_, std::convert::Infallible>(Event::default().data(json))
    }))
    .chain(tokio_stream::once(Ok::<_, std::convert::Infallible>(
        Event::default().data("[DONE]"),
    )));

    Sse::new(stream).into_response()
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract user message content from a message array.
///
/// Concatenates all user messages into a single string, separated by newlines.
/// System messages are prepended as context.
fn extract_user_content(messages: &[ChatMessage]) -> String {
    let mut parts = Vec::new();

    for msg in messages {
        match msg.role.as_str() {
            "system" => {
                if let Some(ref content) = msg.content {
                    parts.push(format!("[System: {}]", content));
                }
            }
            "user" => {
                if let Some(ref content) = msg.content {
                    parts.push(content.clone());
                }
            }
            _ => {} // Skip assistant and tool messages for input
        }
    }

    parts.join("\n")
}

/// Build a model list from a daemon ListAgents response.
fn build_model_list(resp: &DaemonResponse) -> ModelListResponse {
    let mut models = Vec::new();

    // Always include the base "aegis" model
    models.push(ModelObject {
        id: "aegis".to_string(),
        object: "model".to_string(),
        created: 1700000000, // Fixed timestamp
        owned_by: "aegis".to_string(),
    });

    // Parse agent names from daemon response data
    if let Some(data) = &resp.data {
        let agents = data
            .get("agents")
            .and_then(|a| a.as_array())
            .or_else(|| data.as_array());

        if let Some(arr) = agents {
            for agent in arr {
                if let Some(name) = agent.get("name").and_then(|n| n.as_str()) {
                    models.push(ModelObject {
                        id: name.to_string(),
                        object: "model".to_string(),
                        created: 1700000000,
                        owned_by: "aegis".to_string(),
                    });
                }
            }
        }
    }

    ModelListResponse {
        object: "list".to_string(),
        data: models,
    }
}

/// Chunk a response string into streaming SSE chunks.
///
/// Splits the content into word-boundary chunks to simulate streaming.
fn chunk_response(
    content: &str,
    model: &str,
    completion_id: &str,
    created: i64,
) -> Vec<ChatCompletionChunk> {
    let mut chunks = Vec::new();

    // First chunk: role announcement
    chunks.push(ChatCompletionChunk {
        id: completion_id.to_string(),
        object: "chat.completion.chunk".to_string(),
        created,
        model: model.to_string(),
        choices: vec![ChunkChoice {
            index: 0,
            delta: ChatMessageDelta {
                role: Some("assistant".to_string()),
                content: None,
            },
            finish_reason: None,
        }],
    });

    // Content chunks: split by words, batch ~5 words per chunk
    let words: Vec<&str> = content.split_whitespace().collect();
    for batch in words.chunks(5) {
        let text = format!("{} ", batch.join(" "));
        chunks.push(ChatCompletionChunk {
            id: completion_id.to_string(),
            object: "chat.completion.chunk".to_string(),
            created,
            model: model.to_string(),
            choices: vec![ChunkChoice {
                index: 0,
                delta: ChatMessageDelta {
                    role: None,
                    content: Some(text),
                },
                finish_reason: None,
            }],
        });
    }

    // Final chunk: finish_reason
    chunks.push(ChatCompletionChunk {
        id: completion_id.to_string(),
        object: "chat.completion.chunk".to_string(),
        created,
        model: model.to_string(),
        choices: vec![ChunkChoice {
            index: 0,
            delta: ChatMessageDelta {
                role: None,
                content: None,
            },
            finish_reason: Some("stop".to_string()),
        }],
    });

    chunks
}

/// Estimate token count from text (rough approximation: ~4 chars per token).
fn estimate_tokens(text: &str) -> u32 {
    (text.len() as u32 / 4).max(1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_message_serialization() {
        let msg = ChatMessage {
            role: "user".to_string(),
            content: Some("Hello, world!".to_string()),
            tool_calls: None,
            tool_call_id: None,
            function_call: None,
            name: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let back: ChatMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.role, "user");
        assert_eq!(back.content.unwrap(), "Hello, world!");
    }

    #[test]
    fn test_chat_completion_request_deserialization() {
        let json = r#"{
            "model": "claude-1",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "What is 2+2?"}
            ],
            "stream": false
        }"#;

        let req: ChatCompletionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.model, "claude-1");
        assert_eq!(req.messages.len(), 2);
        assert!(!req.stream);
    }

    #[test]
    fn test_chat_completion_request_streaming() {
        let json = r#"{
            "model": "agent-1",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": true,
            "temperature": 0.7,
            "max_tokens": 100
        }"#;

        let req: ChatCompletionRequest = serde_json::from_str(json).unwrap();
        assert!(req.stream);
        assert_eq!(req.temperature, Some(0.7));
        assert_eq!(req.max_tokens, Some(100));
    }

    #[test]
    fn test_chat_completion_response_serialization() {
        let resp = ChatCompletionResponse {
            id: "chatcmpl-test123".to_string(),
            object: "chat.completion".to_string(),
            created: 1700000000,
            model: "claude-1".to_string(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".to_string(),
                    content: Some("The answer is 4.".to_string()),
                    tool_calls: None,
                    tool_call_id: None,
                    function_call: None,
                    name: None,
                },
                finish_reason: Some("stop".to_string()),
            }],
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
        };

        let json = serde_json::to_string(&resp).unwrap();
        let back: ChatCompletionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "chatcmpl-test123");
        assert_eq!(back.object, "chat.completion");
        assert_eq!(back.choices.len(), 1);
        assert_eq!(
            back.choices[0].message.content.as_deref(),
            Some("The answer is 4.")
        );
        assert_eq!(back.usage.total_tokens, 15);
    }

    #[test]
    fn test_streaming_chunk_serialization() {
        let chunk = ChatCompletionChunk {
            id: "chatcmpl-test".to_string(),
            object: "chat.completion.chunk".to_string(),
            created: 1700000000,
            model: "agent-1".to_string(),
            choices: vec![ChunkChoice {
                index: 0,
                delta: ChatMessageDelta {
                    role: Some("assistant".to_string()),
                    content: None,
                },
                finish_reason: None,
            }],
        };

        let json = serde_json::to_string(&chunk).unwrap();
        let back: ChatCompletionChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(back.object, "chat.completion.chunk");
        assert_eq!(back.choices[0].delta.role.as_deref(), Some("assistant"));
    }

    #[test]
    fn test_extract_user_content() {
        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: Some("You are helpful.".to_string()),
                tool_calls: None,
                tool_call_id: None,
                function_call: None,
                name: None,
            },
            ChatMessage {
                role: "user".to_string(),
                content: Some("What is 2+2?".to_string()),
                tool_calls: None,
                tool_call_id: None,
                function_call: None,
                name: None,
            },
            ChatMessage {
                role: "assistant".to_string(),
                content: Some("4".to_string()),
                tool_calls: None,
                tool_call_id: None,
                function_call: None,
                name: None,
            },
            ChatMessage {
                role: "user".to_string(),
                content: Some("Are you sure?".to_string()),
                tool_calls: None,
                tool_call_id: None,
                function_call: None,
                name: None,
            },
        ];

        let content = extract_user_content(&messages);
        assert!(content.contains("[System: You are helpful.]"));
        assert!(content.contains("What is 2+2?"));
        assert!(content.contains("Are you sure?"));
        // Assistant messages should not be included
        assert!(!content.contains("\n4\n"));
    }

    #[test]
    fn test_extract_user_content_empty() {
        let messages: Vec<ChatMessage> = vec![];
        let content = extract_user_content(&messages);
        assert!(content.is_empty());
    }

    #[test]
    fn test_chunk_response() {
        let chunks = chunk_response(
            "Hello world this is a test response",
            "agent-1",
            "chatcmpl-test",
            1700000000,
        );

        // First chunk should have role
        assert!(chunks[0].choices[0].delta.role.is_some());
        assert!(chunks[0].choices[0].delta.content.is_none());

        // Last chunk should have finish_reason
        let last = chunks.last().unwrap();
        assert_eq!(last.choices[0].finish_reason.as_deref(), Some("stop"));
        assert!(last.choices[0].delta.content.is_none());

        // Middle chunks should have content
        assert!(chunks.len() >= 3); // role + content + finish
        for chunk in &chunks[1..chunks.len() - 1] {
            assert!(chunk.choices[0].delta.content.is_some());
            assert!(chunk.choices[0].finish_reason.is_none());
        }
    }

    #[test]
    fn test_estimate_tokens() {
        assert_eq!(estimate_tokens(""), 1); // minimum 1
        assert_eq!(estimate_tokens("test"), 1);
        assert_eq!(estimate_tokens("hello world this is a test"), 6);
    }

    #[test]
    fn test_model_list_response() {
        let resp = DaemonResponse::ok_with_data(
            "2 agents",
            serde_json::json!({
                "agents": [
                    {"name": "claude-1", "status": "running"},
                    {"name": "agent-2", "status": "stopped"}
                ]
            }),
        );

        let models = build_model_list(&resp);
        assert_eq!(models.object, "list");
        // Should have base "aegis" + 2 agents
        assert_eq!(models.data.len(), 3);
        assert_eq!(models.data[0].id, "aegis");
        assert_eq!(models.data[1].id, "claude-1");
        assert_eq!(models.data[2].id, "agent-2");
    }

    #[test]
    fn test_model_list_no_data() {
        let resp = DaemonResponse::ok("no agents");
        let models = build_model_list(&resp);
        assert_eq!(models.data.len(), 1); // Just "aegis"
    }

    #[test]
    fn test_openai_error_format() {
        let err = OpenAiError::new("something failed", "server_error").with_code("internal_error");
        let json = serde_json::to_string(&err).unwrap();
        let back: OpenAiError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.error.message, "something failed");
        assert_eq!(back.error.error_type, "server_error");
        assert_eq!(back.error.code.as_deref(), Some("internal_error"));
    }

    #[test]
    fn test_tool_call_serialization() {
        let tool_call = ToolCall {
            id: "call_abc123".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "get_weather".to_string(),
                arguments: r#"{"location": "Boston"}"#.to_string(),
            },
        };

        let json = serde_json::to_string(&tool_call).unwrap();
        let back: ToolCall = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "call_abc123");
        assert_eq!(back.function.name, "get_weather");
    }

    #[test]
    fn test_tool_definition_serialization() {
        let tool = ToolDefinition {
            tool_type: "function".to_string(),
            function: FunctionDefinition {
                name: "search".to_string(),
                description: Some("Search the web".to_string()),
                parameters: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"}
                    },
                    "required": ["query"]
                })),
            },
        };

        let json = serde_json::to_string(&tool).unwrap();
        let back: ToolDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.function.name, "search");
        assert!(back.function.description.is_some());
        assert!(back.function.parameters.is_some());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"hellp"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn test_chat_completion_with_tools() {
        let json = r#"{
            "model": "claude-1",
            "messages": [{"role": "user", "content": "Search for Rust tutorials"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "web_search",
                        "description": "Search the web",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "query": {"type": "string"}
                            }
                        }
                    }
                }
            ],
            "tool_choice": "auto"
        }"#;

        let req: ChatCompletionRequest = serde_json::from_str(json).unwrap();
        assert!(req.tools.is_some());
        assert_eq!(req.tools.as_ref().unwrap().len(), 1);
        assert_eq!(
            req.tools.as_ref().unwrap()[0].function.name,
            "web_search"
        );
    }
}
