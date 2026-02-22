//! Error types for the aegis-browser crate.

use std::time::Duration;

use thiserror::Error;

/// Errors that can occur during browser operations.
#[derive(Debug, Error)]
pub enum BrowserError {
    /// Failed to establish a WebSocket connection to Chrome DevTools.
    #[error("failed to connect to Chrome DevTools at {url}: {reason}")]
    ConnectionFailed { url: String, reason: String },

    /// A CDP command returned an error response.
    #[error("CDP error {code}: {message}")]
    CdpError {
        code: i64,
        message: String,
        data: Option<String>,
    },

    /// A CDP command timed out waiting for a response.
    #[error("CDP command '{method}' timed out after {duration:?}")]
    Timeout { method: String, duration: Duration },

    /// A protocol-level error (serialization, unexpected message format, etc.).
    #[error("CDP protocol error: {detail}")]
    Protocol { detail: String },

    /// The requested DOM element was not found.
    #[error("element not found: {selector}")]
    ElementNotFound { selector: String },

    /// Navigation failed.
    #[error("navigation failed: {reason}")]
    NavigationFailed { reason: String },

    /// JavaScript evaluation returned an exception.
    #[error("JavaScript exception: {message}")]
    JsException { message: String },

    /// The page did not load within the expected timeout.
    #[error("page load timed out after {duration:?}")]
    PageLoadTimeout { duration: Duration },

    /// An element could not be interacted with (e.g., not visible, zero-size).
    #[error("element not interactable: {reason}")]
    ElementNotInteractable { reason: String },
}
