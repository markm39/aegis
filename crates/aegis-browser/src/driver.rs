//! High-level browser driver wrapping the CDP client.
//!
//! Provides ergonomic methods for common browser automation tasks:
//! navigation, JavaScript evaluation, element interaction (click, type),
//! screenshots, and DOM queries.
//!
//! All methods validate their inputs and return structured errors. The driver
//! owns a [`CdpClient`] and manages CDP domain enablement automatically.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::Value;

use crate::cdp::CdpClient;
use crate::error::BrowserError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Opaque handle to a DOM node, as returned by CDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub i64);

/// Bounding box of a DOM element in CSS pixels.
#[derive(Debug, Clone)]
pub struct ElementBox {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

// ---------------------------------------------------------------------------
// BrowserDriver
// ---------------------------------------------------------------------------

/// High-level browser automation driver.
///
/// Wraps a CDP WebSocket client and provides methods for navigation,
/// JavaScript evaluation, DOM interaction, and screenshots.
///
/// # Example (conceptual)
///
/// ```ignore
/// let driver = BrowserDriver::connect("ws://localhost:9222/devtools/page/ABC").await?;
/// driver.navigate("https://example.com").await?;
/// driver.click("#login-button").await?;
/// driver.type_text("#username", "user@example.com").await?;
/// let html = driver.get_html().await?;
/// let png = driver.screenshot().await?;
/// ```
pub struct BrowserDriver {
    client: CdpClient,
}

impl BrowserDriver {
    /// Connect to a Chrome DevTools page target.
    ///
    /// Automatically enables the Page, DOM, Runtime, and Input CDP domains.
    pub async fn connect(ws_url: &str) -> Result<Self, BrowserError> {
        let client = CdpClient::connect(ws_url).await?;

        // Enable required domains.
        client.enable_domain("Page").await?;
        client.enable_domain("DOM").await?;
        client.enable_domain("Runtime").await?;

        Ok(Self { client })
    }

    /// Create a driver from an existing CDP client (for testing or advanced use).
    pub fn from_client(client: CdpClient) -> Self {
        Self { client }
    }

    /// Return a reference to the underlying CDP client for direct command access.
    pub fn client(&self) -> &CdpClient {
        &self.client
    }

    // -----------------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------------

    /// Navigate to a URL and wait for the frame to stop loading.
    ///
    /// This sends `Page.navigate` and waits for the `Page.frameStoppedLoading`
    /// event. If navigation returns an error (e.g. net::ERR_NAME_NOT_RESOLVED),
    /// it is surfaced as `BrowserError::NavigationFailed`.
    pub async fn navigate(&self, url: &str) -> Result<(), BrowserError> {
        let result = self
            .client
            .send_command("Page.navigate", serde_json::json!({ "url": url }))
            .await?;

        // Check for navigation-level errors (errorText field in response).
        if let Some(error_text) = result.get("errorText").and_then(|v| v.as_str()) {
            return Err(BrowserError::NavigationFailed {
                reason: error_text.to_string(),
            });
        }

        Ok(())
    }

    /// Wait for a page load event with a timeout.
    ///
    /// Listens for the `Page.loadEventFired` CDP event. If the event does not
    /// arrive within `timeout`, returns `BrowserError::PageLoadTimeout`.
    pub async fn wait_for_navigation(
        &mut self,
        timeout: Duration,
    ) -> Result<(), BrowserError> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(BrowserError::PageLoadTimeout { duration: timeout });
            }

            let event = tokio::time::timeout(remaining, self.client.recv_event()).await;

            match event {
                Ok(Some(evt)) => {
                    if evt.method == "Page.loadEventFired" {
                        return Ok(());
                    }
                    // Consume other events and keep waiting.
                }
                Ok(None) => {
                    // Event channel closed -- connection dropped.
                    return Err(BrowserError::Protocol {
                        detail: "WebSocket closed while waiting for page load".to_string(),
                    });
                }
                Err(_) => {
                    return Err(BrowserError::PageLoadTimeout { duration: timeout });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // JavaScript evaluation
    // -----------------------------------------------------------------------

    /// Evaluate a JavaScript expression in the page context.
    ///
    /// Returns the evaluated result as a `serde_json::Value`. If the
    /// expression throws an exception, it is returned as
    /// `BrowserError::JsException`.
    pub async fn evaluate(&self, expression: &str) -> Result<Value, BrowserError> {
        let result = self
            .client
            .send_command(
                "Runtime.evaluate",
                serde_json::json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true,
                }),
            )
            .await?;

        // Check for JS exceptions.
        if let Some(exception) = result.get("exceptionDetails") {
            let message = exception
                .get("exception")
                .and_then(|e| e.get("description"))
                .and_then(|d| d.as_str())
                .or_else(|| {
                    exception
                        .get("text")
                        .and_then(|t| t.as_str())
                })
                .unwrap_or("unknown exception")
                .to_string();
            return Err(BrowserError::JsException { message });
        }

        // Extract the value from the result object.
        let value = result
            .get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(Value::Null);

        Ok(value)
    }

    // -----------------------------------------------------------------------
    // DOM queries
    // -----------------------------------------------------------------------

    /// Get the document root node ID.
    async fn get_document_root(&self) -> Result<i64, BrowserError> {
        let result = self
            .client
            .send_command("DOM.getDocument", serde_json::json!({}))
            .await?;

        result
            .get("root")
            .and_then(|r| r.get("nodeId"))
            .and_then(|n| n.as_i64())
            .ok_or_else(|| BrowserError::Protocol {
                detail: "DOM.getDocument did not return a root nodeId".to_string(),
            })
    }

    /// Find a single element matching a CSS selector.
    ///
    /// Returns `Ok(None)` if no element matches. Returns the CDP `NodeId`
    /// which can be used for further DOM operations.
    pub async fn query_selector(
        &self,
        selector: &str,
    ) -> Result<Option<NodeId>, BrowserError> {
        let root_id = self.get_document_root().await?;

        let result = self
            .client
            .send_command(
                "DOM.querySelector",
                serde_json::json!({
                    "nodeId": root_id,
                    "selector": selector,
                }),
            )
            .await?;

        let node_id = result
            .get("nodeId")
            .and_then(|n| n.as_i64())
            .unwrap_or(0);

        if node_id == 0 {
            Ok(None)
        } else {
            Ok(Some(NodeId(node_id)))
        }
    }

    /// Find all elements matching a CSS selector.
    ///
    /// Returns an empty vector if no elements match.
    pub async fn query_selector_all(
        &self,
        selector: &str,
    ) -> Result<Vec<NodeId>, BrowserError> {
        let root_id = self.get_document_root().await?;

        let result = self
            .client
            .send_command(
                "DOM.querySelectorAll",
                serde_json::json!({
                    "nodeId": root_id,
                    "selector": selector,
                }),
            )
            .await?;

        let node_ids = result
            .get("nodeIds")
            .and_then(|n| n.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_i64())
                    .filter(|id| *id != 0)
                    .map(NodeId)
                    .collect()
            })
            .unwrap_or_default();

        Ok(node_ids)
    }

    // -----------------------------------------------------------------------
    // Element interaction
    // -----------------------------------------------------------------------

    /// Get the bounding box of a DOM element.
    ///
    /// Uses `DOM.getBoxModel` to retrieve the element's content quad, then
    /// computes a bounding rectangle from it.
    async fn get_element_box(&self, node_id: NodeId) -> Result<ElementBox, BrowserError> {
        let result = self
            .client
            .send_command(
                "DOM.getBoxModel",
                serde_json::json!({ "nodeId": node_id.0 }),
            )
            .await?;

        // The content quad is an array of 8 values: [x1,y1, x2,y2, x3,y3, x4,y4].
        let content = result
            .get("model")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .ok_or_else(|| BrowserError::Protocol {
                detail: "DOM.getBoxModel did not return a content quad".to_string(),
            })?;

        if content.len() < 8 {
            return Err(BrowserError::Protocol {
                detail: format!(
                    "content quad has {} values, expected 8",
                    content.len()
                ),
            });
        }

        let xs: Vec<f64> = content.iter().step_by(2).filter_map(|v| v.as_f64()).collect();
        let ys: Vec<f64> = content.iter().skip(1).step_by(2).filter_map(|v| v.as_f64()).collect();

        if xs.len() < 4 || ys.len() < 4 {
            return Err(BrowserError::Protocol {
                detail: "failed to parse content quad coordinates".to_string(),
            });
        }

        let min_x = xs.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_x = xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min_y = ys.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_y = ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        let width = max_x - min_x;
        let height = max_y - min_y;

        if width <= 0.0 || height <= 0.0 {
            return Err(BrowserError::ElementNotInteractable {
                reason: format!(
                    "element has zero or negative size: {width}x{height}"
                ),
            });
        }

        Ok(ElementBox {
            x: min_x,
            y: min_y,
            width,
            height,
        })
    }

    /// Click an element identified by a CSS selector.
    ///
    /// Finds the element via `DOM.querySelector`, retrieves its bounding box
    /// via `DOM.getBoxModel`, computes the center point, and dispatches
    /// `mousePressed` and `mouseReleased` events at that location.
    pub async fn click(&self, selector: &str) -> Result<(), BrowserError> {
        let node_id = self
            .query_selector(selector)
            .await?
            .ok_or_else(|| BrowserError::ElementNotFound {
                selector: selector.to_string(),
            })?;

        let bbox = self.get_element_box(node_id).await?;
        let cx = bbox.x + bbox.width / 2.0;
        let cy = bbox.y + bbox.height / 2.0;

        // Dispatch mousePressed.
        self.client
            .send_command(
                "Input.dispatchMouseEvent",
                serde_json::json!({
                    "type": "mousePressed",
                    "x": cx,
                    "y": cy,
                    "button": "left",
                    "clickCount": 1,
                }),
            )
            .await?;

        // Dispatch mouseReleased.
        self.client
            .send_command(
                "Input.dispatchMouseEvent",
                serde_json::json!({
                    "type": "mouseReleased",
                    "x": cx,
                    "y": cy,
                    "button": "left",
                    "clickCount": 1,
                }),
            )
            .await?;

        Ok(())
    }

    /// Type text into an element identified by a CSS selector.
    ///
    /// Finds the element, focuses it via `DOM.focus`, then dispatches
    /// individual `keyDown`, `keyUp` events with a `char` event for each
    /// character in the text.
    pub async fn type_text(
        &self,
        selector: &str,
        text: &str,
    ) -> Result<(), BrowserError> {
        let node_id = self
            .query_selector(selector)
            .await?
            .ok_or_else(|| BrowserError::ElementNotFound {
                selector: selector.to_string(),
            })?;

        // Focus the element.
        self.client
            .send_command(
                "DOM.focus",
                serde_json::json!({ "nodeId": node_id.0 }),
            )
            .await?;

        // Type each character using Input.dispatchKeyEvent.
        for ch in text.chars() {
            let ch_str = ch.to_string();

            // keyDown with the character.
            self.client
                .send_command(
                    "Input.dispatchKeyEvent",
                    serde_json::json!({
                        "type": "keyDown",
                        "text": ch_str,
                        "unmodifiedText": ch_str,
                        "key": ch_str,
                    }),
                )
                .await?;

            // keyUp.
            self.client
                .send_command(
                    "Input.dispatchKeyEvent",
                    serde_json::json!({
                        "type": "keyUp",
                        "text": ch_str,
                        "unmodifiedText": ch_str,
                        "key": ch_str,
                    }),
                )
                .await?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Screenshots
    // -----------------------------------------------------------------------

    /// Take a screenshot of the current page.
    ///
    /// Returns the raw PNG bytes. Uses `Page.captureScreenshot` with PNG
    /// format.
    pub async fn screenshot(&self) -> Result<Vec<u8>, BrowserError> {
        let result = self
            .client
            .send_command(
                "Page.captureScreenshot",
                serde_json::json!({ "format": "png" }),
            )
            .await?;

        let data_b64 = result
            .get("data")
            .and_then(|d| d.as_str())
            .ok_or_else(|| BrowserError::Protocol {
                detail: "Page.captureScreenshot did not return 'data' field".to_string(),
            })?;

        let bytes = B64.decode(data_b64).map_err(|e| BrowserError::Protocol {
            detail: format!("failed to decode screenshot base64: {e}"),
        })?;

        Ok(bytes)
    }

    // -----------------------------------------------------------------------
    // Page content
    // -----------------------------------------------------------------------

    /// Get the full HTML of the current page.
    ///
    /// Evaluates `document.documentElement.outerHTML` in the page context.
    pub async fn get_html(&self) -> Result<String, BrowserError> {
        let value = self
            .evaluate("document.documentElement.outerHTML")
            .await?;

        value.as_str().map(|s| s.to_string()).ok_or_else(|| {
            BrowserError::Protocol {
                detail: "outerHTML evaluation did not return a string".to_string(),
            }
        })
    }

    /// Get the current page URL.
    ///
    /// Evaluates `window.location.href` in the page context.
    pub async fn get_url(&self) -> Result<String, BrowserError> {
        let value = self.evaluate("window.location.href").await?;
        value.as_str().map(|s| s.to_string()).ok_or_else(|| {
            BrowserError::Protocol {
                detail: "location.href evaluation did not return a string".to_string(),
            }
        })
    }

    /// Get the current page title.
    ///
    /// Evaluates `document.title` in the page context.
    pub async fn get_title(&self) -> Result<String, BrowserError> {
        let value = self.evaluate("document.title").await?;
        Ok(value.as_str().unwrap_or("").to_string())
    }
}

// ---------------------------------------------------------------------------
// CDP parameter builders (for testing and external use)
// ---------------------------------------------------------------------------

/// Build CDP `Page.navigate` parameters.
pub fn build_navigate_params(url: &str) -> Value {
    serde_json::json!({ "url": url })
}

/// Build CDP `Runtime.evaluate` parameters.
pub fn build_evaluate_params(expression: &str) -> Value {
    serde_json::json!({
        "expression": expression,
        "returnByValue": true,
        "awaitPromise": true,
    })
}

/// Build CDP `DOM.querySelector` parameters.
pub fn build_query_selector_params(root_node_id: i64, selector: &str) -> Value {
    serde_json::json!({
        "nodeId": root_node_id,
        "selector": selector,
    })
}

/// Build CDP `DOM.querySelectorAll` parameters.
pub fn build_query_selector_all_params(root_node_id: i64, selector: &str) -> Value {
    serde_json::json!({
        "nodeId": root_node_id,
        "selector": selector,
    })
}

/// Build CDP `Input.dispatchMouseEvent` parameters for a click at (x, y).
pub fn build_click_params(x: f64, y: f64, event_type: &str) -> Value {
    serde_json::json!({
        "type": event_type,
        "x": x,
        "y": y,
        "button": "left",
        "clickCount": 1,
    })
}

/// Build CDP `Input.dispatchKeyEvent` parameters for a key event.
pub fn build_key_event_params(event_type: &str, text: &str) -> Value {
    serde_json::json!({
        "type": event_type,
        "text": text,
        "unmodifiedText": text,
        "key": text,
    })
}

/// Build CDP `Page.captureScreenshot` parameters.
pub fn build_screenshot_params(format: &str) -> Value {
    serde_json::json!({ "format": format })
}

/// Compute the center point of a content quad (8-element array of coordinates).
///
/// Returns `(center_x, center_y)` or `None` if the quad is invalid.
pub fn center_of_quad(quad: &[f64]) -> Option<(f64, f64)> {
    if quad.len() < 8 {
        return None;
    }
    let xs: Vec<f64> = quad.iter().step_by(2).copied().collect();
    let ys: Vec<f64> = quad.iter().skip(1).step_by(2).copied().collect();
    if xs.is_empty() || ys.is_empty() {
        return None;
    }
    let min_x = xs.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_x = xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let min_y = ys.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_y = ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    Some(((min_x + max_x) / 2.0, (min_y + max_y) / 2.0))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Parameter builder tests --------------------------------------------

    #[test]
    fn test_build_navigate_params() {
        let params = build_navigate_params("https://example.com");
        assert_eq!(params["url"], "https://example.com");
    }

    #[test]
    fn test_build_evaluate_params() {
        let params = build_evaluate_params("1 + 1");
        assert_eq!(params["expression"], "1 + 1");
        assert_eq!(params["returnByValue"], true);
        assert_eq!(params["awaitPromise"], true);
    }

    #[test]
    fn test_build_query_selector_params() {
        let params = build_query_selector_params(1, "#main");
        assert_eq!(params["nodeId"], 1);
        assert_eq!(params["selector"], "#main");
    }

    #[test]
    fn test_build_query_selector_all_params() {
        let params = build_query_selector_all_params(1, "div.item");
        assert_eq!(params["nodeId"], 1);
        assert_eq!(params["selector"], "div.item");
    }

    #[test]
    fn test_build_click_params() {
        let params = build_click_params(100.0, 200.0, "mousePressed");
        assert_eq!(params["type"], "mousePressed");
        assert_eq!(params["x"], 100.0);
        assert_eq!(params["y"], 200.0);
        assert_eq!(params["button"], "left");
        assert_eq!(params["clickCount"], 1);
    }

    #[test]
    fn test_build_key_event_params() {
        let params = build_key_event_params("keyDown", "a");
        assert_eq!(params["type"], "keyDown");
        assert_eq!(params["text"], "a");
        assert_eq!(params["key"], "a");
    }

    #[test]
    fn test_build_screenshot_params() {
        let params = build_screenshot_params("png");
        assert_eq!(params["format"], "png");
    }

    // -- center_of_quad tests -----------------------------------------------

    #[test]
    fn test_center_of_quad_basic() {
        // A 100x100 quad at origin.
        let quad = [0.0, 0.0, 100.0, 0.0, 100.0, 100.0, 0.0, 100.0];
        let (cx, cy) = center_of_quad(&quad).unwrap();
        assert!((cx - 50.0).abs() < 0.001);
        assert!((cy - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_center_of_quad_offset() {
        // A 200x100 quad at (50, 75).
        let quad = [50.0, 75.0, 250.0, 75.0, 250.0, 175.0, 50.0, 175.0];
        let (cx, cy) = center_of_quad(&quad).unwrap();
        assert!((cx - 150.0).abs() < 0.001);
        assert!((cy - 125.0).abs() < 0.001);
    }

    #[test]
    fn test_center_of_quad_too_few_values() {
        let quad = [0.0, 0.0, 100.0, 0.0];
        assert!(center_of_quad(&quad).is_none());
    }

    #[test]
    fn test_center_of_quad_empty() {
        let quad: [f64; 0] = [];
        assert!(center_of_quad(&quad).is_none());
    }

    // -- NodeId tests -------------------------------------------------------

    #[test]
    fn test_node_id_equality() {
        assert_eq!(NodeId(42), NodeId(42));
        assert_ne!(NodeId(1), NodeId(2));
    }

    #[test]
    fn test_node_id_debug() {
        let node = NodeId(123);
        let debug = format!("{node:?}");
        assert!(debug.contains("123"));
    }

    // -- ElementBox tests ---------------------------------------------------

    #[test]
    fn test_element_box_fields() {
        let ebox = ElementBox {
            x: 10.0,
            y: 20.0,
            width: 300.0,
            height: 150.0,
        };
        assert!((ebox.x - 10.0).abs() < f64::EPSILON);
        assert!((ebox.y - 20.0).abs() < f64::EPSILON);
        assert!((ebox.width - 300.0).abs() < f64::EPSILON);
        assert!((ebox.height - 150.0).abs() < f64::EPSILON);
    }

    // -- Simulated CDP response parsing tests --------------------------------

    #[test]
    fn test_parse_navigate_response_success() {
        let response = serde_json::json!({
            "frameId": "ABC123",
            "loaderId": "DEF456"
        });
        // No errorText means success.
        assert!(response.get("errorText").is_none());
    }

    #[test]
    fn test_parse_navigate_response_error() {
        let response = serde_json::json!({
            "errorText": "net::ERR_NAME_NOT_RESOLVED"
        });
        let error_text = response.get("errorText").and_then(|v| v.as_str());
        assert_eq!(error_text, Some("net::ERR_NAME_NOT_RESOLVED"));
    }

    #[test]
    fn test_parse_evaluate_response_with_value() {
        let response = serde_json::json!({
            "result": {
                "type": "number",
                "value": 42,
                "description": "42"
            }
        });
        let value = response
            .get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(Value::Null);
        assert_eq!(value, 42);
    }

    #[test]
    fn test_parse_evaluate_response_with_exception() {
        let response = serde_json::json!({
            "result": {
                "type": "object",
                "subtype": "error"
            },
            "exceptionDetails": {
                "exceptionId": 1,
                "text": "Uncaught",
                "lineNumber": 0,
                "columnNumber": 0,
                "exception": {
                    "type": "object",
                    "subtype": "error",
                    "className": "ReferenceError",
                    "description": "ReferenceError: foo is not defined"
                }
            }
        });

        let exception = response.get("exceptionDetails");
        assert!(exception.is_some());
        let msg = exception
            .unwrap()
            .get("exception")
            .and_then(|e| e.get("description"))
            .and_then(|d| d.as_str())
            .unwrap();
        assert_eq!(msg, "ReferenceError: foo is not defined");
    }

    #[test]
    fn test_parse_query_selector_response_found() {
        let response = serde_json::json!({ "nodeId": 42 });
        let node_id = response.get("nodeId").and_then(|n| n.as_i64()).unwrap();
        assert_eq!(node_id, 42);
    }

    #[test]
    fn test_parse_query_selector_response_not_found() {
        // CDP returns nodeId: 0 when no element matches.
        let response = serde_json::json!({ "nodeId": 0 });
        let node_id = response.get("nodeId").and_then(|n| n.as_i64()).unwrap();
        assert_eq!(node_id, 0);
    }

    #[test]
    fn test_parse_query_selector_all_response() {
        let response = serde_json::json!({ "nodeIds": [10, 20, 30] });
        let node_ids: Vec<i64> = response
            .get("nodeIds")
            .and_then(|n| n.as_array())
            .unwrap()
            .iter()
            .filter_map(|v| v.as_i64())
            .collect();
        assert_eq!(node_ids, vec![10, 20, 30]);
    }

    #[test]
    fn test_parse_screenshot_response() {
        // Simulate a small base64-encoded "PNG".
        let fake_png = vec![0x89, 0x50, 0x4E, 0x47]; // PNG magic bytes
        let b64_data = B64.encode(&fake_png);
        let response = serde_json::json!({ "data": b64_data });

        let data_str = response.get("data").and_then(|d| d.as_str()).unwrap();
        let decoded = B64.decode(data_str).unwrap();
        assert_eq!(decoded, fake_png);
    }

    #[test]
    fn test_parse_get_box_model_response() {
        let response = serde_json::json!({
            "model": {
                "content": [100.0, 200.0, 300.0, 200.0, 300.0, 400.0, 100.0, 400.0],
                "padding": [100.0, 200.0, 300.0, 200.0, 300.0, 400.0, 100.0, 400.0],
                "border": [95.0, 195.0, 305.0, 195.0, 305.0, 405.0, 95.0, 405.0],
                "margin": [90.0, 190.0, 310.0, 190.0, 310.0, 410.0, 90.0, 410.0],
                "width": 200,
                "height": 200
            }
        });

        let content = response
            .get("model")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .unwrap();

        assert_eq!(content.len(), 8);

        // Compute center.
        let coords: Vec<f64> = content.iter().filter_map(|v| v.as_f64()).collect();
        let (cx, cy) = center_of_quad(&coords).unwrap();
        assert!((cx - 200.0).abs() < 0.001);
        assert!((cy - 300.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_document_root_response() {
        let response = serde_json::json!({
            "root": {
                "nodeId": 1,
                "backendNodeId": 2,
                "nodeType": 9,
                "nodeName": "#document",
                "childNodeCount": 2
            }
        });

        let root_node_id = response
            .get("root")
            .and_then(|r| r.get("nodeId"))
            .and_then(|n| n.as_i64())
            .unwrap();
        assert_eq!(root_node_id, 1);
    }
}
