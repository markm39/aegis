//! Low-level CDP (Chrome DevTools Protocol) WebSocket client.
//!
//! Connects to a running Chrome/Chromium instance via its DevTools WebSocket
//! endpoint and provides JSON-RPC 2.0 command/response correlation with
//! support for asynchronous event subscriptions.
//!
//! This module handles:
//! - WebSocket connection management
//! - Command ID generation and request/response correlation
//! - Event dispatching to registered listeners
//! - Timeout handling for commands

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::error::BrowserError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

/// A CDP event received from the browser.
#[derive(Debug, Clone)]
pub struct CdpEvent {
    /// The event method name (e.g. "Page.loadEventFired").
    pub method: String,
    /// The event parameters.
    pub params: Value,
}

/// A CDP command to send to the browser.
#[derive(Debug, Clone, serde::Serialize)]
struct CdpCommand {
    id: u64,
    method: String,
    params: Value,
}

/// A CDP response from the browser.
#[derive(Debug, Clone)]
pub struct CdpResponse {
    /// The command ID this response correlates to.
    pub id: u64,
    /// The result value on success.
    pub result: Option<Value>,
    /// The error object on failure.
    pub error: Option<CdpResponseError>,
}

/// Error object in a CDP response.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CdpResponseError {
    pub code: i64,
    pub message: String,
    pub data: Option<String>,
}

// ---------------------------------------------------------------------------
// CdpClient
// ---------------------------------------------------------------------------

/// Low-level CDP client that manages a WebSocket connection to Chrome DevTools.
///
/// Commands are sent with auto-incrementing IDs and responses are correlated
/// back to the caller. Events are forwarded to a broadcast channel for
/// subscription by higher-level code.
pub struct CdpClient {
    /// Auto-incrementing command ID counter.
    next_id: Arc<AtomicU64>,
    /// Pending commands awaiting responses: id -> oneshot sender.
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<CdpResponse>>>>,
    /// WebSocket write half, wrapped in a mutex for shared access.
    writer: Arc<Mutex<WsSink>>,
    /// Channel for receiving CDP events.
    event_rx: mpsc::UnboundedReceiver<CdpEvent>,
    /// Handle to the background reader task.
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl CdpClient {
    /// Connect to a Chrome DevTools WebSocket endpoint.
    ///
    /// The `ws_url` should be of the form:
    /// `ws://localhost:{port}/devtools/page/{target_id}`
    ///
    /// This can be obtained from Chrome's `/json` HTTP endpoint or from
    /// the `aegis-toolkit` browser discovery module.
    pub async fn connect(ws_url: &str) -> Result<Self, BrowserError> {
        tracing::info!(url = ws_url, "connecting to Chrome DevTools WebSocket");

        let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url)
            .await
            .map_err(|e| BrowserError::ConnectionFailed {
                url: ws_url.to_string(),
                reason: e.to_string(),
            })?;

        let (writer, reader) = ws_stream.split();

        let next_id = Arc::new(AtomicU64::new(1));
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<CdpResponse>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let pending_clone = Arc::clone(&pending);
        let reader_handle = tokio::spawn(async move {
            Self::read_loop(reader, pending_clone, event_tx).await;
        });

        tracing::info!(url = ws_url, "CDP WebSocket connection established");

        Ok(Self {
            next_id,
            pending,
            writer: Arc::new(Mutex::new(writer)),
            event_rx,
            _reader_handle: reader_handle,
        })
    }

    /// Send a CDP command and wait for its response.
    ///
    /// Returns the result value from the CDP response. If the CDP response
    /// contains an error, it is returned as a `BrowserError::CdpError`.
    pub async fn send_command(&self, method: &str, params: Value) -> Result<Value, BrowserError> {
        self.send_command_with_timeout(method, params, Duration::from_secs(30))
            .await
    }

    /// Send a CDP command with a custom timeout.
    pub async fn send_command_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, BrowserError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let cmd = CdpCommand {
            id,
            method: method.to_string(),
            params,
        };

        let json = serde_json::to_string(&cmd).map_err(|e| BrowserError::Protocol {
            detail: format!("failed to serialize command: {e}"),
        })?;

        tracing::debug!(id = id, method = method, "sending CDP command");

        // Register the pending response before sending to avoid races.
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            pending.insert(id, tx);
        }

        // Send the command.
        {
            let mut writer = self.writer.lock().await;
            writer
                .send(Message::Text(json.into()))
                .await
                .map_err(|e| BrowserError::Protocol {
                    detail: format!("failed to send WebSocket message: {e}"),
                })?;
        }

        // Wait for the response with timeout.
        let response = tokio::time::timeout(timeout, rx)
            .await
            .map_err(|_| BrowserError::Timeout {
                method: method.to_string(),
                duration: timeout,
            })?
            .map_err(|_| BrowserError::Protocol {
                detail: "response channel closed unexpectedly".to_string(),
            })?;

        // Check for CDP-level errors.
        if let Some(err) = response.error {
            return Err(BrowserError::CdpError {
                code: err.code,
                message: err.message,
                data: err.data,
            });
        }

        Ok(response.result.unwrap_or(Value::Null))
    }

    /// Receive the next CDP event.
    ///
    /// Returns `None` if the event channel has been closed (WebSocket
    /// disconnected).
    pub async fn recv_event(&mut self) -> Option<CdpEvent> {
        self.event_rx.recv().await
    }

    /// Enable a CDP domain (e.g. "Page", "DOM", "Runtime").
    ///
    /// Many CDP domains require an explicit `enable` call before they will
    /// emit events.
    pub async fn enable_domain(&self, domain: &str) -> Result<(), BrowserError> {
        let method = format!("{domain}.enable");
        self.send_command(&method, serde_json::json!({})).await?;
        Ok(())
    }

    /// Background task that reads WebSocket messages and dispatches them.
    ///
    /// - Messages with an `id` field are responses to pending commands.
    /// - Messages with a `method` field (and no `id`) are events.
    async fn read_loop(
        mut reader: futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        pending: Arc<Mutex<HashMap<u64, oneshot::Sender<CdpResponse>>>>,
        event_tx: mpsc::UnboundedSender<CdpEvent>,
    ) {
        while let Some(msg_result) = reader.next().await {
            let msg = match msg_result {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::warn!(error = %e, "WebSocket read error, stopping reader");
                    break;
                }
            };

            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Binary(b) => match String::from_utf8(b.to_vec()) {
                    Ok(s) => s,
                    Err(_) => continue,
                },
                Message::Close(_) => {
                    tracing::info!("WebSocket closed by remote");
                    break;
                }
                _ => continue,
            };

            let json: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to parse CDP message as JSON");
                    continue;
                }
            };

            // Check if this is a response (has `id` field).
            if let Some(id) = json.get("id").and_then(|v| v.as_u64()) {
                let response = CdpResponse {
                    id,
                    result: json.get("result").cloned(),
                    error: json
                        .get("error")
                        .and_then(|e| serde_json::from_value(e.clone()).ok()),
                };

                let mut pending_guard = pending.lock().await;
                if let Some(tx) = pending_guard.remove(&id) {
                    let _ = tx.send(response);
                } else {
                    tracing::debug!(id = id, "received response for unknown command ID");
                }
            }
            // Otherwise it's an event (has `method` field, no `id`).
            else if let Some(method) = json.get("method").and_then(|v| v.as_str()) {
                let params = json.get("params").cloned().unwrap_or(Value::Null);
                let event = CdpEvent {
                    method: method.to_string(),
                    params,
                };
                // If nobody is listening, that's fine -- just drop the event.
                let _ = event_tx.send(event);
            }
        }

        // Clean up: cancel all pending commands when the connection drops.
        let mut pending_guard = pending.lock().await;
        for (id, tx) in pending_guard.drain() {
            let _ = tx.send(CdpResponse {
                id,
                result: None,
                error: Some(CdpResponseError {
                    code: -1,
                    message: "WebSocket connection closed".to_string(),
                    data: None,
                }),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// CDP protocol helpers
// ---------------------------------------------------------------------------

/// Build a CDP JSON-RPC message (used in tests for validation).
pub fn build_cdp_message(id: u64, method: &str, params: Value) -> Value {
    serde_json::json!({
        "id": id,
        "method": method,
        "params": params,
    })
}

/// Parse a CDP response JSON into its components.
pub fn parse_cdp_response(json: &Value) -> Option<CdpResponse> {
    let id = json.get("id")?.as_u64()?;
    Some(CdpResponse {
        id,
        result: json.get("result").cloned(),
        error: json
            .get("error")
            .and_then(|e| serde_json::from_value(e.clone()).ok()),
    })
}

/// Parse a CDP event JSON into its components.
pub fn parse_cdp_event(json: &Value) -> Option<CdpEvent> {
    // Events have a `method` field but no `id`.
    if json.get("id").is_some() {
        return None;
    }
    let method = json.get("method")?.as_str()?.to_string();
    let params = json.get("params").cloned().unwrap_or(Value::Null);
    Some(CdpEvent { method, params })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_cdp_message() {
        let msg = build_cdp_message(
            42,
            "Page.navigate",
            serde_json::json!({"url": "https://example.com"}),
        );
        assert_eq!(msg["id"], 42);
        assert_eq!(msg["method"], "Page.navigate");
        assert_eq!(msg["params"]["url"], "https://example.com");
    }

    #[test]
    fn test_parse_cdp_response_success() {
        let json = serde_json::json!({
            "id": 1,
            "result": {
                "frameId": "abc123",
                "loaderId": "def456"
            }
        });
        let resp = parse_cdp_response(&json).unwrap();
        assert_eq!(resp.id, 1);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["frameId"], "abc123");
    }

    #[test]
    fn test_parse_cdp_response_error() {
        let json = serde_json::json!({
            "id": 2,
            "error": {
                "code": -32602,
                "message": "Invalid params",
                "data": "missing required field 'url'"
            }
        });
        let resp = parse_cdp_response(&json).unwrap();
        assert_eq!(resp.id, 2);
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "Invalid params");
        assert_eq!(err.data.as_deref(), Some("missing required field 'url'"));
    }

    #[test]
    fn test_parse_cdp_response_missing_id() {
        let json = serde_json::json!({
            "method": "Page.loadEventFired",
            "params": {}
        });
        assert!(parse_cdp_response(&json).is_none());
    }

    #[test]
    fn test_parse_cdp_event_valid() {
        let json = serde_json::json!({
            "method": "Page.loadEventFired",
            "params": {
                "timestamp": 12345.678
            }
        });
        let event = parse_cdp_event(&json).unwrap();
        assert_eq!(event.method, "Page.loadEventFired");
        assert_eq!(event.params["timestamp"], 12345.678);
    }

    #[test]
    fn test_parse_cdp_event_rejects_response() {
        // A message with an `id` is a response, not an event.
        let json = serde_json::json!({
            "id": 1,
            "method": "Page.navigate",
            "result": {}
        });
        assert!(parse_cdp_event(&json).is_none());
    }

    #[test]
    fn test_parse_cdp_event_no_params() {
        let json = serde_json::json!({
            "method": "Page.domContentEventFired"
        });
        let event = parse_cdp_event(&json).unwrap();
        assert_eq!(event.method, "Page.domContentEventFired");
        assert_eq!(event.params, Value::Null);
    }

    #[test]
    fn test_parse_cdp_event_no_method() {
        let json = serde_json::json!({
            "params": { "foo": "bar" }
        });
        assert!(parse_cdp_event(&json).is_none());
    }

    #[test]
    fn test_cdp_command_serialization() {
        let cmd = CdpCommand {
            id: 7,
            method: "Runtime.evaluate".to_string(),
            params: serde_json::json!({
                "expression": "1 + 1",
                "returnByValue": true,
            }),
        };
        let json = serde_json::to_value(&cmd).unwrap();
        assert_eq!(json["id"], 7);
        assert_eq!(json["method"], "Runtime.evaluate");
        assert_eq!(json["params"]["expression"], "1 + 1");
        assert_eq!(json["params"]["returnByValue"], true);
    }

    #[test]
    fn test_cdp_response_error_deserialization() {
        let json_str = r#"{"code": -32601, "message": "Method not found"}"#;
        let err: CdpResponseError = serde_json::from_str(json_str).unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "Method not found");
        assert!(err.data.is_none());
    }

    #[test]
    fn test_cdp_response_error_with_data() {
        let json_str = r#"{"code": -32000, "message": "Server error", "data": "something broke"}"#;
        let err: CdpResponseError = serde_json::from_str(json_str).unwrap();
        assert_eq!(err.code, -32000);
        assert_eq!(err.message, "Server error");
        assert_eq!(err.data.as_deref(), Some("something broke"));
    }
}
